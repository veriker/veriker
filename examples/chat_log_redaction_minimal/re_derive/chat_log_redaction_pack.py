#!/usr/bin/env python3
"""chat_log_redaction_pack.py — stdlib re-derivation pack for chat-log PII redaction.

the audit-bundle contract §C5 (auditor independence) + AB4 (duplicate-don't-import):
no audit_bundle imports inside this script. Stdlib only.

Re-derivation steps:
  1. Load inputs/transcript.txt        — raw UTF-8 chat blob
  2. Load inputs/redaction_policy.json — {regex_patterns: {...}, entity_dict: [...]}
  3. Load payload/redaction_result.json — {spans: [...], redacted_output_sha: "..."}
  4. Re-run the identical deterministic regex + entity-dict scan:
       a. Collect all regex-pattern matches (byte offsets into UTF-8 encoding).
       b. Collect all entity-dict exact-string matches (kind=PERSON).
       c. Sort by start byte, resolve overlaps (greedy cover: keep first kind on tie,
          extend end if later span ends later).
       d. Apply [REDACTED:<kind>] right-to-left.
  5. Assert:
       - len(recomputed_spans) == len(bundled_spans)
       - per-span: start_byte, end_byte, entity_kind all equal
       - sha256(redacted_transcript.encode("utf-8")) == bundled redacted_output_sha
  6. Exit 0 on full match; exit 1 with [CLR_REDER_FAIL] <description> on stderr.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


def _fail(msg: str) -> int:
    print(f"[CLR_REDER_FAIL] {msg}", file=sys.stderr)
    return 1


def _apply_redaction_policy(transcript, policy):
    transcript_bytes = transcript.encode("utf-8")
    raw_spans = []

    for kind, pattern in policy["regex_patterns"].items():
        for m in re.finditer(pattern, transcript):
            start_b = len(transcript[: m.start()].encode("utf-8"))
            end_b = len(transcript[: m.end()].encode("utf-8"))
            raw_spans.append((start_b, end_b, kind))

    for name in policy["entity_dict"]:
        for m in re.finditer(re.escape(name), transcript):
            start_b = len(transcript[: m.start()].encode("utf-8"))
            end_b = len(transcript[: m.end()].encode("utf-8"))
            raw_spans.append((start_b, end_b, "PERSON"))

    raw_spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    accepted = []
    for span in raw_spans:
        if not accepted:
            accepted.append(span)
            continue
        last = accepted[-1]
        if span[0] < last[1]:
            if span[1] > last[1]:
                accepted[-1] = (last[0], span[1], last[2])
        else:
            accepted.append(span)

    result_bytes = bytearray(transcript_bytes)
    for start_b, end_b, kind in reversed(accepted):
        replacement = f"[REDACTED:{kind}]".encode("utf-8")
        result_bytes[start_b:end_b] = replacement

    redacted_str = result_bytes.decode("utf-8")
    return accepted, redacted_str


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Chat-log PII redaction re-derivation check"
    )
    parser.add_argument("--bundle-dir", required=True, type=Path)
    args = parser.parse_args()
    bundle_dir = args.bundle_dir.resolve()

    transcript_path = bundle_dir / "inputs" / "transcript.txt"
    policy_path = bundle_dir / "inputs" / "redaction_policy.json"
    result_path = bundle_dir / "payload" / "redaction_result.json"

    for p in (transcript_path, policy_path, result_path):
        if not p.exists():
            return _fail(f"required file missing: {p}")

    try:
        transcript = transcript_path.read_text(encoding="utf-8")
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        bundled = json.loads(result_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return _fail(f"failed to load bundle inputs/payload: {exc}")

    if not isinstance(bundled, dict):
        return _fail("payload/redaction_result.json must be a JSON object")

    bundled_spans = bundled.get("spans", [])
    bundled_sha = bundled.get("redacted_output_sha", "")

    recomputed_spans, redacted_str = _apply_redaction_policy(transcript, policy)
    recomputed_sha = hashlib.sha256(redacted_str.encode("utf-8")).hexdigest()

    if len(recomputed_spans) != len(bundled_spans):
        return _fail(
            f"span count mismatch: recomputed={len(recomputed_spans)} "
            f"bundled={len(bundled_spans)}"
        )

    for i, (rec, exp) in enumerate(zip(recomputed_spans, bundled_spans)):
        r_start, r_end, r_kind = rec
        e_start = exp.get("start_byte")
        e_end = exp.get("end_byte")
        e_kind = exp.get("entity_kind")
        if r_start != e_start or r_end != e_end or r_kind != e_kind:
            return _fail(
                f"span[{i}] mismatch: "
                f"recomputed=({r_start},{r_end},{r_kind!r}) "
                f"bundled=({e_start},{e_end},{e_kind!r})"
            )

    if recomputed_sha != bundled_sha:
        return _fail(
            f"redacted_output_sha mismatch: "
            f"recomputed={recomputed_sha!r} bundled={bundled_sha!r}"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
