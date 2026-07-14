#!/usr/bin/env python3
"""pii_redaction_re_derivation.py — stdlib constrained-Viterbi re-derivation pack.

Verifies that the bundled PII spans are reproducible from the bundled BIOES
logits tensor under the bundled transition-bias parameters.
the audit-bundle contract §C5 (auditor independence) + §C6 (re-derivation).

Reads from --bundle-dir:
  payload/bioes_logits.json     — float32 logits as list[list[float]], shape [T, 33]
  payload/tokens.json           — {"tokens": [...]}
  payload/redaction_output.json — spans, bias_vector, redacted_text

BIOES state space (33 states total):
  States 0–31: category * 4 + bioes_offset
    bioes_offset: B=0 I=1 E=2 S=3
    category 0–7: private_person/address/email/phone/url/date/account_number/secret
  State 32: O (outside / no entity)

Constrained-Viterbi transition rules (BIOES validity):
  From O   (32): may go to O, any B, any S
  From B_c (4c+0): may go to I_c (4c+1), E_c (4c+2) — must continue same category
  From I_c (4c+1): may go to I_c (4c+1), E_c (4c+2) — must continue same category
  From E_c (4c+2): may go to O, any B, any S — span ended
  From S_c (4c+3): may go to O, any B, any S — single-token span ended

Transition-bias parameters (6 floats added as log-prior to transition score):
  bias_vector[0] = background_persistence  — O→O additive log-prior
  bias_vector[1] = span_entry              — *→B or *→S additive log-prior (start a new span)
  bias_vector[2] = span_continuation       — B→I, I→I additive log-prior
  bias_vector[3] = span_closure            — B→E, I→E additive log-prior (close a multi-token span)
  bias_vector[4] = boundary_to_boundary    — E→B, E→S, S→B, S→S (end one span, start another)
  bias_vector[5] = category_switch_penalty — additive log-prior applied when the target span
                                             category differs from the source span category
                                             (relevant only for boundary_to_boundary transitions;
                                             negative value discourages rapid category switching)

Exit 0 on full match; exit 1 on any mismatch, with JSON error to stdout.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path

_NEG_INF = float("-inf")
_N_CATS = 8
_N_STATES = 33  # 8*4 + 1
_O = 32


def _tag_index(cat: int, bioes: str) -> int:
    return cat * 4 + ["B", "I", "E", "S"].index(bioes)


def _state_info(state: int) -> tuple[str, int | None]:
    """Return (bioes_letter, category_or_None) for a state index."""
    if state == _O:
        return ("O", None)
    cat = state // 4
    bioes = ["B", "I", "E", "S"][state % 4]
    return (bioes, cat)


def _allowed_successors(state: int) -> list[int]:
    """Return list of states reachable from `state` under BIOES validity rules."""
    letter, cat = _state_info(state)
    if letter in ("O", "E", "S"):
        # May start a new span (any B or S) or stay O
        result = [_O]
        for c in range(_N_CATS):
            result.append(_tag_index(c, "B"))
            result.append(_tag_index(c, "S"))
        return result
    if letter == "B":
        # Must continue same category: I or E
        return [_tag_index(cat, "I"), _tag_index(cat, "E")]
    if letter == "I":
        # Must continue same category: I or E
        return [_tag_index(cat, "I"), _tag_index(cat, "E")]
    raise ValueError(f"unreachable state {state}")


def _transition_bias(src: int, dst: int, bias: list[float]) -> float:
    """Additive log-prior for the src→dst transition.

    Mapping:
      bias[0] background_persistence : O→O
      bias[1] span_entry             : *→B or *→S (starting a new span from O/E/S)
      bias[2] span_continuation      : B→I or I→I
      bias[3] span_closure           : B→E or I→E
      bias[4] boundary_to_boundary   : E→B, E→S, S→B, S→S
      bias[5] category_switch_penalty: applied additionally when E/S→B/S and
                                       dst_category != src_category
    """
    src_letter, src_cat = _state_info(src)
    dst_letter, dst_cat = _state_info(dst)

    if src_letter == "O" and dst_letter == "O":
        return bias[0]
    if dst_letter in ("B", "S") and src_letter in ("O", "E", "S"):
        if src_letter in ("E", "S"):
            b = bias[4]
            if src_cat != dst_cat:
                b += bias[5]
            return b
        return bias[1]
    if dst_letter == "I":
        if src_letter == "B":
            return bias[2]
        if src_letter == "I":
            return bias[2]
    if dst_letter == "E":
        return bias[3]
    return 0.0


def _viterbi(logits: list[list[float]], bias: list[float]) -> list[int]:
    """Constrained Viterbi decode over a BIOES state space.

    Returns the most-probable valid BIOES tag sequence (list of state indices).
    """
    T = len(logits)

    # viterbi[t][s] = best log-score ending in state s at token t
    # back[t][s]    = predecessor state for the best path
    viterbi: list[list[float]] = [[_NEG_INF] * _N_STATES for _ in range(T)]
    back: list[list[int]] = [[-1] * _N_STATES for _ in range(T)]

    # Initialise: token 0 — only O, B_c, S_c are valid start states
    valid_starts = (
        [_O]
        + [_tag_index(c, "B") for c in range(_N_CATS)]
        + [_tag_index(c, "S") for c in range(_N_CATS)]
    )
    for s in valid_starts:
        viterbi[0][s] = logits[0][s]

    # Forward pass
    for t in range(1, T):
        for dst in range(_N_STATES):
            best_score = _NEG_INF
            best_src = -1
            for src in range(_N_STATES):
                if viterbi[t - 1][src] == _NEG_INF:
                    continue
                if dst not in _allowed_successors(src):
                    continue
                score = (
                    viterbi[t - 1][src]
                    + _transition_bias(src, dst, bias)
                    + logits[t][dst]
                )
                if score > best_score:
                    best_score = score
                    best_src = src
            viterbi[t][dst] = best_score
            back[t][dst] = best_src

    # Terminal constraint: valid end states are O, E_c, S_c
    valid_ends = (
        [_O]
        + [_tag_index(c, "E") for c in range(_N_CATS)]
        + [_tag_index(c, "S") for c in range(_N_CATS)]
    )
    best_final = max(valid_ends, key=lambda s: viterbi[T - 1][s])

    # Backtrack
    path = [best_final]
    for t in range(T - 1, 0, -1):
        path.append(back[t][path[-1]])
    path.reverse()
    return path


def _decode_spans(tag_seq: list[int], categories: list[str]) -> list[dict]:
    """Walk a BIOES tag sequence and group B/I*/E or S into spans."""
    spans = []
    i = 0
    while i < len(tag_seq):
        state = tag_seq[i]
        letter, cat = _state_info(state)
        if letter == "S":
            spans.append(
                {"token_start": i, "token_end": i + 1, "category": categories[cat]}
            )
            i += 1
        elif letter == "B":
            j = i + 1
            while j < len(tag_seq):
                nl, nc = _state_info(tag_seq[j])
                if nl == "E":
                    spans.append(
                        {
                            "token_start": i,
                            "token_end": j + 1,
                            "category": categories[cat],
                        }
                    )
                    j += 1
                    break
                j += 1
            i = j
        else:
            i += 1
    return spans


_TOKEN_PATTERN = re.compile(r"\w+|[^\w\s]")


def _join_tokens(tokens: list[str]) -> str:
    parts: list[str] = []
    for tok in tokens:
        if parts and re.fullmatch(r"[^\w\s]", tok):
            parts[-1] += tok
        else:
            if parts:
                parts.append(" " + tok)
            else:
                parts.append(tok)
    return "".join(parts)


def _reconstruct_redacted(tokens: list[str], spans: list[dict]) -> str:
    redacted = list(tokens)
    for span in sorted(spans, key=lambda s: s["token_start"], reverse=True):
        label = f"[REDACTED_{span['category'].upper()}]"
        start = span["token_start"]
        end = span["token_end"]
        redacted[start:end] = [label]
    return _join_tokens(redacted)


def _spans_equal(derived: list[dict], bundled: list[dict]) -> tuple[bool, str]:
    def _key(s: dict) -> tuple:
        return (s["token_start"], s["token_end"], s["category"])

    d_sorted = sorted(derived, key=_key)
    b_sorted = sorted(bundled, key=_key)

    if len(d_sorted) != len(b_sorted):
        return False, (
            f"span count mismatch: derived={len(d_sorted)} bundled={len(b_sorted)}"
        )
    for i, (d, b) in enumerate(zip(d_sorted, b_sorted)):
        if _key(d) != _key(b):
            return False, (f"span[{i}] mismatch: derived={_key(d)} bundled={_key(b)}")
    return True, ""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PII re-derivation check for pii_redaction_minimal audit bundles"
    )
    parser.add_argument("--bundle-dir", required=True, type=Path)
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    # Load inputs
    logits_path = bundle_dir / "payload" / "bioes_logits.json"
    tokens_path = bundle_dir / "payload" / "tokens.json"
    output_path = bundle_dir / "payload" / "redaction_output.json"

    for p in (logits_path, tokens_path, output_path):
        if not p.exists():
            err = {
                "error": "PII_REDACTION_REDERIVATION_MISMATCH",
                "reason": f"missing: {p.name}",
            }
            print(json.dumps(err))
            return 1

    try:
        logits_obj = json.loads(logits_path.read_text(encoding="utf-8"))
        tokens_obj = json.loads(tokens_path.read_text(encoding="utf-8"))
        output_obj = json.loads(output_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        err = {
            "error": "PII_REDACTION_REDERIVATION_MISMATCH",
            "reason": f"JSON parse error: {exc}",
        }
        print(json.dumps(err))
        return 1

    logits: list[list[float]] = logits_obj["logits"]
    tokens: list[str] = tokens_obj["tokens"]
    bias: list[float] = output_obj["bias_vector"]
    bundled_spans: list[dict] = output_obj["spans"]
    bundled_redacted: str = output_obj["redacted_text"]
    categories: list[str] = output_obj["categories"]

    if len(logits) != len(tokens):
        err = {
            "error": "PII_REDACTION_REDERIVATION_MISMATCH",
            "reason": f"logits seq_len={len(logits)} != tokens len={len(tokens)}",
        }
        print(json.dumps(err))
        return 1

    # Re-derive via constrained Viterbi
    tag_seq = _viterbi(logits, bias)
    derived_spans = _decode_spans(tag_seq, categories)

    # Strip confidence from derived spans (not a Viterbi output)
    bundled_spans_cmp = [
        {
            "token_start": s["token_start"],
            "token_end": s["token_end"],
            "category": s["category"],
        }
        for s in bundled_spans
    ]

    ok, reason = _spans_equal(derived_spans, bundled_spans_cmp)
    if not ok:
        err = {
            "error": "PII_REDACTION_REDERIVATION_MISMATCH",
            "reason": f"span mismatch: {reason}",
        }
        print(json.dumps(err))
        return 1

    derived_redacted = _reconstruct_redacted(tokens, derived_spans)
    if derived_redacted != bundled_redacted:
        err = {
            "error": "PII_REDACTION_REDERIVATION_MISMATCH",
            "reason": f"redacted_text mismatch: derived={derived_redacted!r} bundled={bundled_redacted!r}",
        }
        print(json.dumps(err))
        return 1

    print(json.dumps({"ok": True, "spans_verified": len(derived_spans)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
