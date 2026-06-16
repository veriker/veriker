"""pii_redaction_recompute.py — verifier-side PII-span re-derivation primitive.

Axis-2 value-return form (SPEC_PINNED_DISPATCH_ARCHITECTURE §3.3). Self-contained
per-dir migration of the pii_redaction_minimal pilot onto spec-pinned dispatch: the
recompute primitive lives HERE (verifier-distribution code, registered by the
spec-pinned builder), NOT in audit_bundle/rederivation/primitives/.

Re-derivation primitive (one sentence):
    redaction_spans = constrained-Viterbi decode over the committed BIOES logits
    tensor (payload/bioes_logits.json) under the committed transition-bias vector
    (redaction_output.bias_vector), aggregated to [token_start, token_end, category]
    span tuples via BIOES grouping.

The decode MIRRORS the legacy pack's _viterbi + _decode_spans EXACTLY
(pii_redaction_re_derivation.py): a 33-state BIOES space (8 categories × {B,I,E,S}
+ O), validity-constrained successors, a 6-float additive transition-bias log-prior
(background_persistence / span_entry / span_continuation / span_closure /
boundary_to_boundary / category_switch_penalty), max-scoring valid start states at
t=0, a forward DP pass, a terminal constraint to {O, E_c, S_c}, backtrack, then
B…E / S grouping into spans. The auditor's SHA-pinned spec binds the output type
"pii_redaction_spans" to this primitive_id and to a `set` comparator (no params —
order-independent collection equality). A producer cannot weaken the decode without
changing the primitive_id, which the anchor would reject.

Stdlib-only (§C5 contract). This module is importable WITHOUT audit_bundle on
sys.path (the RecomputedValue import is deferred into recompute()), so the
spec-pinned builder can import compute_redaction_spans() standalone.
"""

from __future__ import annotations

import json
from pathlib import Path

_NEG_INF = float("-inf")
_N_CATS = 8
_N_STATES = 33  # 8*4 + 1
_O = 32
_BIOES = ["B", "I", "E", "S"]


# ---------------------------------------------------------------------------
# Canonical computation (shared by the builder and the verifier — ONE source).
# Mirrors pii_redaction_re_derivation.py byte-for-byte so the honest spans and
# the re-derivation cannot drift.
# ---------------------------------------------------------------------------


def _tag_index(cat: int, bioes: str) -> int:
    return cat * 4 + _BIOES.index(bioes)


def _state_info(state: int) -> tuple[str, int | None]:
    """Return (bioes_letter, category_or_None) for a state index."""
    if state == _O:
        return ("O", None)
    cat = state // 4
    bioes = _BIOES[state % 4]
    return (bioes, cat)


def _allowed_successors(state: int) -> list[int]:
    """Return list of states reachable from `state` under BIOES validity rules."""
    letter, cat = _state_info(state)
    if letter in ("O", "E", "S"):
        result = [_O]
        for c in range(_N_CATS):
            result.append(_tag_index(c, "B"))
            result.append(_tag_index(c, "S"))
        return result
    if letter == "B":
        return [_tag_index(cat, "I"), _tag_index(cat, "E")]
    if letter == "I":
        return [_tag_index(cat, "I"), _tag_index(cat, "E")]
    raise ValueError(f"unreachable state {state}")


def _transition_bias(src: int, dst: int, bias: list[float]) -> float:
    """Additive log-prior for the src->dst transition (mirrors the legacy pack)."""
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

    viterbi: list[list[float]] = [[_NEG_INF] * _N_STATES for _ in range(T)]
    back: list[list[int]] = [[-1] * _N_STATES for _ in range(T)]

    valid_starts = (
        [_O]
        + [_tag_index(c, "B") for c in range(_N_CATS)]
        + [_tag_index(c, "S") for c in range(_N_CATS)]
    )
    for s in valid_starts:
        viterbi[0][s] = logits[0][s]

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

    valid_ends = (
        [_O]
        + [_tag_index(c, "E") for c in range(_N_CATS)]
        + [_tag_index(c, "S") for c in range(_N_CATS)]
    )
    best_final = max(valid_ends, key=lambda s: viterbi[T - 1][s])

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


def compute_redaction_spans(
    logits: list[list[float]], bias: list[float], categories: list[str]
) -> list[list]:
    """Canonical redaction-spans recompute. Mirrors the legacy pack's Viterbi
    decode + BIOES grouping. Builder and verifier share this ONE definition.

    Returns the aggregated spans as a list of [token_start, token_end, category]
    tuples (the `set` comparator compares it order-independently against the
    claimed collection).
    """
    tag_seq = _viterbi(logits, bias)
    spans = _decode_spans(tag_seq, categories)
    return [[s["token_start"], s["token_end"], s["category"]] for s in spans]


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered before BundleVerifier)
# ---------------------------------------------------------------------------


class PiiRedactionRecompute:
    """Verifier-side primitive for re-deriving the redaction-spans collection."""

    primitive_id: str = "pii_redaction_recompute"

    def recompute(self, inputs, pack_section: dict):
        """Recompute redaction spans from the committed BIOES logits + bias vector.

        inputs.bundle_dir is a read-only Path. pack_section carries
        {output_id, type, params} from the auditor's spec binding. Returns a
        RecomputedValue carrying the [start, end, category] span tuples; the
        verifier's `set` comparator compares it order-independently to the claimed
        value.
        """
        # Deferred import keeps this module importable standalone (builder use).
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        bundle_dir: Path = inputs.bundle_dir

        logits_path = bundle_dir / "payload" / "bioes_logits.json"
        output_path = bundle_dir / "payload" / "redaction_output.json"
        for p in (logits_path, output_path):
            if not p.is_file():
                raise FileNotFoundError(f"{p.name} not found in bundle at {bundle_dir}")

        logits_obj = json.loads(logits_path.read_text(encoding="utf-8"))
        output_obj = json.loads(output_path.read_text(encoding="utf-8"))

        logits: list[list[float]] = logits_obj["logits"]
        bias: list[float] = output_obj["bias_vector"]
        categories: list[str] = output_obj["categories"]

        value = compute_redaction_spans(logits, bias, categories)
        return RecomputedValue(
            value=value,
            detail=(
                f"re-derived {len(value)} PII span(s) via constrained-Viterbi decode "
                f"over {len(logits)} token(s) under bias={bias!r} -> {sorted(value)!r}"
            ),
        )
