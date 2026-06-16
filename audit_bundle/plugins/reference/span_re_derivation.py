#!/usr/bin/env python3
"""span_re_derivation.py — stdlib re-derivation pack for the text-output span domain.

DEPRECATED (2026-05-24, L8 fragment-attestation keel LOCKED). This pilot-private
shape reads payload/spans.json — a data model DISCONNECTED from the canonical
manifest.fragment_anchors (FragmentID) schema. Canonical span attestation now
lives in audit_bundle/plugins/fragment_attestation.py, which re-derives every
attestable fragment_anchor (one carrying a content_selector.exact quote claim)
on the DEFAULT verify path and fails closed on misquote / out-of-bounds /
segmenter drift. New pilots MUST emit canonical fragment_anchors (see
_build_bundle.py per-quote emission) instead of payload/spans.json. Retained
only for backward compatibility with bundles already carrying spans.json.

Mirrors the EXTRACTIVE stamper invariant locally — no stamper import.
Implements the audit-bundle contract §C6 (text-output generalization caveat);
this plugin is duplicated, not imported, into pilot bundles.

Reads payload/spans.json from --bundle-dir.  Each record must have:
  {
    "output_text": "<str>",
    "span":        {"start": <int>, "end": <int>},   # UTF-8 byte offsets into output_text
    "source_cid":  "<cid>",                           # corpus/<cid>.txt
    "fragment_id": "<int>"                            # 0-based sentence index in corpus file
  }

For each record: extracts span bytes from output_text, loads corpus/<source_cid>.txt,
segments into sentences (mirroring the canonical sentence_segments rules), retrieves the
fragment at fragment_id, normalizes both texts (mirroring the canonical normalize_text), and asserts
equality.  Exits 0 on full match; 1 on first mismatch with a description written to stderr.

If payload/spans.json is absent the bundle opted out of C6 → exits 0.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from pathlib import Path


# ---------------------------------------------------------------------------
# Normalization — canonical 5-rule normalizer (no import; duplicated here)
# ---------------------------------------------------------------------------


def _normalize(text: str) -> str:
    """Apply the canonical 5-rule normalization (identical to normalize_text())."""
    # Rule 1: NFC
    text = unicodedata.normalize("NFC", text)
    # Rule 2: casefold
    text = text.casefold()
    # Rule 3: drop punctuation (Unicode category P*)
    text = "".join(ch for ch in text if not unicodedata.category(ch).startswith("P"))
    # Rule 4: collapse whitespace
    text = re.sub(r"\s+", " ", text)
    # Rule 5: strip edges
    return text.strip()


# ---------------------------------------------------------------------------
# Admission-bounded JSON loading — duplicated, not imported (this file is a
# stdlib-only / standalone reference verifier; see module docstring). Mirrors
# audit_bundle.admission's discipline (RES-02, 2026-06-11): size-reject BEFORE
# allocation, bracket-depth scan BEFORE json.loads so a hostile depth bomb is
# a clean ValueError, never a RecursionError out of the parser.
# ---------------------------------------------------------------------------

_ADMIT_MAX_BYTES = 16 * 1024 * 1024
_ADMIT_MAX_DEPTH = 64


def _admit_depth_scan(raw, name):
    """Reject (ValueError) if raw's bracket/brace nesting outside JSON string
    literals exceeds _ADMIT_MAX_DEPTH — a structural upper bound on the
    recursion json.loads would perform."""
    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:  # closing quote
                in_string = False
            continue
        if byte == 0x22:  # opening quote
            in_string = True
        elif byte in b"[{":
            depth += 1
            if depth > _ADMIT_MAX_DEPTH:
                raise ValueError(
                    f"{name}: JSON nesting exceeds max depth {_ADMIT_MAX_DEPTH}"
                )
        elif byte in b"]}":
            if depth > 0:
                depth -= 1


def _admitted_json(path):
    """Size- and depth-bounded replacement for json.loads(path.read_text())."""
    size = path.stat().st_size
    if size > _ADMIT_MAX_BYTES:
        raise ValueError(f"{path.name}: {size} bytes exceeds max {_ADMIT_MAX_BYTES}")
    raw = path.read_bytes()
    _admit_depth_scan(raw, path.name)
    return json.loads(raw)



# ---------------------------------------------------------------------------
# Sentence segmentation — canonical segmenter (decimal exception)
# ---------------------------------------------------------------------------

# Sentence terminator: one or more .!? chars, NOT a decimal point between digits.
_SENT_END = re.compile(r"(?<!\d)[.!?]+(?!\d)")


def _sentence_segments(text: str) -> list[str]:
    """Split text into sentences using the canonical sentence_segments rules."""
    parts = _SENT_END.split(text)
    return [p.strip() for p in parts if p.strip()]


# ---------------------------------------------------------------------------
# Span record processing
# ---------------------------------------------------------------------------


def _resolve_within(root: Path, rel: str) -> Path | None:
    """Contain a bundle-controlled relative path inside ``root``; return None on
    escape (``..`` traversal, an absolute path, or a symlink out of tree) so the
    caller fails closed instead of reading an out-of-bundle file. Mirrors
    audit_bundle/rederivation/primitives/_safepath.resolve_within — this pack is
    stdlib-only / standalone, so it carries its own copy."""
    candidate = (root / rel).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return None
    return candidate


def _check_span(bundle_dir: Path, rec: dict, idx: int) -> str | None:
    """Return an error description on mismatch, or None on match."""
    try:
        output_text: str = rec["output_text"]
        span_d: dict = rec["span"]
        source_cid: str = rec["source_cid"]
        fragment_id: int = int(rec["fragment_id"])
        byte_start: int = int(span_d["start"])
        byte_end: int = int(span_d["end"])
    except (KeyError, TypeError, ValueError) as exc:
        return f"span[{idx}]: malformed record — {exc}"

    # Extract span text from output_text via UTF-8 byte offsets
    raw_out = output_text.encode("utf-8")
    if byte_end > len(raw_out) or byte_start < 0 or byte_start > byte_end:
        return (
            f"span[{idx}]: byte range [{byte_start}:{byte_end}] out of bounds "
            f"for output_text ({len(raw_out)} bytes)"
        )
    try:
        span_text = raw_out[byte_start:byte_end].decode("utf-8")
    except UnicodeDecodeError as exc:
        return (
            f"span[{idx}]: invalid UTF-8 in byte range [{byte_start}:{byte_end}]: {exc}"
        )

    # Load corpus file for source_cid. source_cid is bundle-controlled; contain
    # the read inside corpus/ so a hostile "../../etc/passwd" or absolute path
    # can't steer an arbitrary host-file read. Escape fails closed.
    corpus_path = _resolve_within(bundle_dir / "corpus", f"{source_cid}.txt")
    if corpus_path is None:
        return (
            f"span[{idx}]: source_cid {source_cid!r} resolves outside corpus/ "
            f"— refusing the read"
        )
    if not corpus_path.exists():
        return (
            f"span[{idx}]: corpus file not found: corpus/{source_cid}.txt "
            f"(source_cid={source_cid!r})"
        )

    doc_text = corpus_path.read_text(encoding="utf-8")

    # Segment the corpus document into sentence-level fragments
    fragments = _sentence_segments(doc_text)
    if fragment_id >= len(fragments):
        return (
            f"span[{idx}]: fragment_id={fragment_id} out of range — "
            f"corpus/{source_cid}.txt has {len(fragments)} fragment(s)"
        )

    fragment_text = fragments[fragment_id]

    # Normalize both and assert equality (EXTRACTIVE stamper invariant)
    norm_span = _normalize(span_text)
    norm_frag = _normalize(fragment_text)

    if norm_span != norm_frag:
        return (
            f"span[{idx}]: span text does not match source fragment after normalization\n"
            f"  source_cid={source_cid!r}  fragment_id={fragment_id}\n"
            f"  norm_span={norm_span!r}\n"
            f"  norm_frag={norm_frag!r}"
        )

    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Span re-derivation check for span-shaped audit bundles"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    spans_path = bundle_dir / "payload" / "spans.json"
    if not spans_path.exists():
        # Domain pilot opted out of C6 re-derivation — not a failure
        return 0

    try:
        records: list = _admitted_json(spans_path)
    except (ValueError, OSError) as exc:
        print(
            f"span_re_derivation: failed to read payload/spans.json: {exc}",
            file=sys.stderr,
        )
        return 1

    if not isinstance(records, list):
        print(
            "span_re_derivation: payload/spans.json must be a JSON array",
            file=sys.stderr,
        )
        return 1

    for idx, rec in enumerate(records):
        error = _check_span(bundle_dir, rec, idx)
        if error is not None:
            print(error, file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
