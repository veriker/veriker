"""_build_bundle.py — build a deterministic pii_redaction_minimal audit bundle.

Demonstrates the re-derivation SHAPE for OpenAI Privacy Filter (Apache 2.0,
released 2026-04-22): a 1.5B/50M-active MoE BIOES token classifier whose
Viterbi decode is deterministic given a fixed checkpoint + bias vector.

V does NOT load the model. It re-derives the bundled spans from the bundled
logits tensor using a stdlib constrained-Viterbi implementation, asserting
span equality and redacted-text equality.

Bundle contents written to --out-dir:
  payload/bioes_logits.json      (seq_len × 33 float logits as list-of-lists)
  payload/tokens.json            (tokenization for redacted_text reconstruction)
  payload/redaction_output.json  (audited output: spans, redacted_text, HMAC, bias)
  payload/dispatch_records.jsonl (human-readable mirror; not loaded by verifier)
  manifest.json

Usage (from v-kernel-audit-bundle root):
    python examples/pii_redaction_minimal/_build_bundle.py --out-dir /tmp/pii_bundle

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.emitter import BundleContent, write_bundle
from audit_bundle.fragments.fragment_id import (
    OpaqueFragment,
    fragment_to_canonical_dict,
)

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "pii-redaction-minimal-rc"
_CREATED_AT = "2026-05-17T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
    "pii_redaction_re_derivation",
    "dispatch_record_wellformed",
]

# Placeholder model SHA — production wiring would pin the actual HF checkpoint
# SHA via §C9.1 append-only file pinning.
_MODEL_SHA = "a3f8c2d1e9b047563f1c4a82e7d056f3c8a1b2e4d7f0c3a6b9e2d5f8c1a4b7e0"
_MODEL_ID = "openai/privacy-filter"

# 8 PII categories (columns 0–7 each map to B/I/E/S sub-tags, column 32 = O).
# Layout: tag_index = category * 4 + bioes_index, where B=0 I=1 E=2 S=3.
# Tag 32 = O (outside). Total: 8*4 + 1 = 33 logits/token.
_CATEGORIES = [
    "private_person",  # 0: tags  0–3
    "private_address",  # 1: tags  4–7
    "private_email",  # 2: tags  8–11
    "private_phone",  # 3: tags 12–15
    "private_url",  # 4: tags 16–19
    "private_date",  # 5: tags 20–23
    "account_number",  # 6: tags 24–27
    "secret",  # 7: tags 28–31
]
_BIOES = ["B", "I", "E", "S"]

# Unit (all-zero) bias vector — no transition adjustments.
_BIAS_VECTOR = [0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

# HMAC key for input_text_hmac (fixed for synthetic fixture reproducibility).
_HMAC_KEY = b"pii-redaction-pilot-hmac-key-v0"

# Example sentence with private_person (multi-token), private_email (single),
# private_date (multi-token) to showcase three PII categories.
_INPUT_TEXT = (
    "Contact Harry Potter at harry@hogwarts.edu before 31 December 2025 for details."
)

# Simple whitespace+punctuation tokenizer (stdlib re).
_TOKEN_PATTERN = re.compile(r"\w+|[^\w\s]")


def _tokenize(text: str) -> list[str]:
    return _TOKEN_PATTERN.findall(text)


def _tag_index(category: int, bioes: str) -> int:
    return category * 4 + _BIOES.index(bioes)


def _make_logits(n_tokens: int, hot_tags: list[int]) -> list[list[float]]:
    """Build a seq_len × 33 logit matrix.

    hot_tags[i] = the intended gold tag index for token i.
    Peak the gold tag to 5.0; all others to -2.0 with tiny positional noise
    so the unit-bias Viterbi deterministically recovers the intended path.
    """
    O = 32
    logits = []
    for i, gold in enumerate(hot_tags):
        row = [-2.0] * 33
        row[gold] = 5.0
        # Tiny positional noise ensures no tie (irrelevant to correctness but
        # makes the fixture feel less synthetic in downstream inspection).
        for j in range(33):
            if j != gold:
                row[j] += (((i * 33 + j) % 7) - 3) * 0.01
        logits.append(row)
    return logits


def _build_gold_path(tokens: list[str]) -> tuple[list[int], list[dict]]:
    """Hand-craft gold BIOES tag sequence for the example sentence.

    Spans:
      "Harry Potter"      → private_person  B S E  (2 tokens: B E)
      "harry@hogwarts.edu" → private_email   S      (1 token)
      "31 December 2025"  → private_date    B I E  (3 tokens)

    Returns (gold_tags, spans) where spans carry token_start/token_end/category.
    """
    tokens_lower = [t.lower() for t in tokens]

    # Locate token positions
    harry_idx = next(i for i, t in enumerate(tokens) if t == "Harry")
    potter_idx = harry_idx + 1

    email_idx = next(i for i, t in enumerate(tokens) if "@" in t)

    date_31_idx = next(i for i, t in enumerate(tokens) if t == "31")
    date_dec_idx = date_31_idx + 1
    date_2025_idx = date_31_idx + 2

    gold = [32] * len(tokens)  # default: O

    # private_person: Harry (B), Potter (E)
    cat_person = _CATEGORIES.index("private_person")
    gold[harry_idx] = _tag_index(cat_person, "B")
    gold[potter_idx] = _tag_index(cat_person, "E")

    # private_email: harry@hogwarts.edu (S)
    cat_email = _CATEGORIES.index("private_email")
    gold[email_idx] = _tag_index(cat_email, "S")

    # private_date: 31 (B), December (I), 2025 (E)
    cat_date = _CATEGORIES.index("private_date")
    gold[date_31_idx] = _tag_index(cat_date, "B")
    gold[date_dec_idx] = _tag_index(cat_date, "I")
    gold[date_2025_idx] = _tag_index(cat_date, "E")

    spans = [
        {
            "token_start": harry_idx,
            "token_end": potter_idx + 1,
            "category": "private_person",
            "confidence": 0.99,
        },
        {
            "token_start": email_idx,
            "token_end": email_idx + 1,
            "category": "private_email",
            "confidence": 0.98,
        },
        {
            "token_start": date_31_idx,
            "token_end": date_2025_idx + 1,
            "category": "private_date",
            "confidence": 0.97,
        },
    ]
    return gold, spans


def _reconstruct_redacted(tokens: list[str], spans: list[dict]) -> str:
    """Reconstruct the redacted text by replacing each span's tokens with a tag.

    Joins tokens with a space, collapsing punctuation tokens (single non-alnum
    char) onto the preceding token without a space. This mirrors the
    reconstruct logic in the re-derivation pack — must be identical.
    """
    redacted_tokens = list(tokens)
    for span in sorted(spans, key=lambda s: s["token_start"], reverse=True):
        cat = span["category"].upper()
        label = f"[REDACTED_{cat}]"
        start = span["token_start"]
        end = span["token_end"]
        redacted_tokens[start:end] = [label]

    return _join_tokens(redacted_tokens)


def _join_tokens(tokens: list[str]) -> str:
    """Join tokens into a string, no space before standalone punctuation."""
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


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    tokens = _tokenize(_INPUT_TEXT)
    gold_tags, spans = _build_gold_path(tokens)
    logits = _make_logits(len(tokens), gold_tags)

    input_bytes = _INPUT_TEXT.encode("utf-8")
    input_hmac = hmac.new(_HMAC_KEY, input_bytes, hashlib.sha256).hexdigest()

    redacted_text = _reconstruct_redacted(tokens, spans)

    # ------------------------------------------------------------------
    # Prepare artifact bytes
    # ------------------------------------------------------------------
    bioes_logits = {"shape": [len(tokens), 33], "logits": logits}
    logits_bytes = (json.dumps(bioes_logits, indent=2) + "\n").encode("utf-8")

    tokens_obj = {"tokens": tokens}
    tokens_bytes = (json.dumps(tokens_obj, indent=2) + "\n").encode("utf-8")

    redaction_output = {
        "input_text_hmac": input_hmac,
        "redacted_text": redacted_text,
        "spans": spans,
        "model_sha": _MODEL_SHA,
        "model_id": _MODEL_ID,
        "bias_vector": _BIAS_VECTOR,
        "categories": _CATEGORIES,
    }
    output_bytes = (json.dumps(redaction_output, indent=2) + "\n").encode("utf-8")

    # Human-readable mirror of dispatch_records (included as a bundle file)
    dispatch_mirror = [
        {
            "schema_version": "0.1",
            "op": {"kind": "REDACT", "name": "pii_filter_bioes"},
            "inputs": ["payload/tokens.json"],
            "outputs": ["payload/redaction_output.json"],
            "effect": {},
            "locale": "en-US",
            "predicates": [],
            "stamp_declared": "INTERNAL_BENCHMARK",
            "stamp_observed": None,
        },
        {
            "schema_version": "0.1",
            "op": {"kind": "COMPUTE", "name": "viterbi_decode"},
            "inputs": ["payload/bioes_logits.json"],
            "outputs": ["payload/redaction_output.json"],
            "effect": {},
            "locale": "en-US",
            "predicates": [],
            "stamp_declared": "INTERNAL_BENCHMARK",
            "stamp_observed": None,
        },
    ]
    mirror_lines = "\n".join(json.dumps(r) for r in dispatch_mirror) + "\n"
    mirror_bytes = mirror_lines.encode("utf-8")

    # ------------------------------------------------------------------
    # OpaqueFragment anchors — one per PII span
    # source_cid = SHA-256 of tokens.json (the tokenised input surface)
    # ------------------------------------------------------------------
    tokens_cid = f"sha256:{hashlib.sha256(tokens_bytes).hexdigest()}"
    fragment_anchors: dict[str, dict] = {}
    for i, span in enumerate(spans):
        frag = OpaqueFragment(
            source_cid=tokens_cid,
            kind_tag="pii_span",
            locator={
                "token_start": span["token_start"],
                "token_end": span["token_end"],
            },
        )
        fragment_anchors[f"pii-span-{i:02d}"] = fragment_to_canonical_dict(frag)

    assert len(fragment_anchors) == len(spans), (
        f"Expected {len(spans)} fragment anchors; got {len(fragment_anchors)}"
    )

    # ------------------------------------------------------------------
    # dispatch_records — loaded by verifier from manifest (NOT from JSONL)
    # ------------------------------------------------------------------
    dispatch_records = [
        {
            "schema_version": "0.1",
            "op": {"kind": "REDACT", "name": "pii_filter_bioes"},
            "inputs": [],
            "outputs": [],
            "effect": {},
            "locale": "en-US",
            "predicates": [],
            "stamp_declared": "INTERNAL_BENCHMARK",
            "stamp_observed": None,
        },
        {
            "schema_version": "0.1",
            "op": {"kind": "COMPUTE", "name": "viterbi_decode"},
            "inputs": [],
            "outputs": [],
            "effect": {},
            "locale": "en-US",
            "predicates": [],
            "stamp_declared": "INTERNAL_BENCHMARK",
            "stamp_observed": None,
        },
    ]

    # ------------------------------------------------------------------
    # Emit via the reference-emitter SDK
    # ------------------------------------------------------------------
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "payload/bioes_logits.json": logits_bytes,
            "payload/tokens.json": tokens_bytes,
            "payload/redaction_output.json": output_bytes,
            "payload/dispatch_records.jsonl": mirror_bytes,
        },
        typed_checks=_TYPED_CHECKS,
        extra_manifest_fields={
            "fragment_anchors": fragment_anchors,
            "dispatch_records": dispatch_records,
        },
    )
    write_bundle(out_dir, content)

    print(f"Bundle written to {out_dir}")
    print(f"  tokens           : {len(tokens)}")
    print(
        f"  spans            : {len(spans)} PII spans across {len(set(s['category'] for s in spans))} categories"
    )
    print(f"  redacted_text    : {redacted_text!r}")
    print(f"  manifest files   : 4")
    print(
        f"  fragment anchors : {len(fragment_anchors)} OpaqueFragment (kind_tag=pii_span)"
    )
    print(f"  dispatch records : {len(dispatch_records)} (op.kinds=REDACT,COMPUTE)")
    print(f"  manifest         : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic pii_redaction_minimal audit bundle"
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        type=Path,
        help="Destination directory (created if absent)",
    )
    args = parser.parse_args()
    try:
        build(args.out_dir.resolve())
    except AssertionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
