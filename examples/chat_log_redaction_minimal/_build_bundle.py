"""_build_bundle.py — build a deterministic chat_log_redaction_minimal audit bundle.

Privacy / unstructured-chat PII-redaction domain pilot: a deterministic regex +
entity-dictionary policy scans a synthetic multi-turn chat transcript and produces
a list of byte-offset spans (start, end, entity_kind). The audit bundle captures
the raw transcript, the redaction policy, and the redacted output — enough for
an independent verifier to re-run the identical scan and assert that every span
AND the redacted_output_sha match byte-for-byte.

Re-derivation primitive (one sentence):
  Re-scan the bundled transcript using the bundled regex + entity-dict policy,
  producing (start_byte, end_byte, entity_kind) spans in ascending start-byte order,
  compute the redacted transcript (replace each span with "[REDACTED:<kind>]"),
  and assert the resulting span list and redacted_output_sha equal the bundled
  payload/redaction_result.json exactly.

Why this matters for privacy / compliance:
  GDPR / CCPA audit obligations require demonstrating that an automated redaction
  pipeline processed only the data it claimed to, produced exactly the output it
  claims, and can be independently re-derived from the committed inputs. The audit
  bundle is that receipt. This pilot demonstrates the substrate claim on a synthetic
  but structurally realistic multi-turn chat corpus; production integrators replace
  the regex engine with their vendor NLP/NER redactor run in determinism mode; the
  bundle shape and verification protocol are identical.

The fragment kind exercised is ByteOffsetFragment: one fragment per redacted span
in the transcript (half-open [start, end) byte range in the transcript blob).

Usage (from v-kernel-audit-bundle root, or anywhere):
    python examples/chat_log_redaction_minimal/_build_bundle.py
        # in-place build (canonical for cli/verify.py)

    python examples/chat_log_redaction_minimal/_build_bundle.py --out-dir /tmp/chat_bundle
        # standalone build into a fresh directory

Caveat:
  When --out-dir is specified, only the generated artifacts (inputs/, payload/,
  re_derive/ pack copy, manifest.json) are written. The pilot's own source files
  are not copied. The in-place build (default) is the canonical mode used by
  cli/verify.py: every file in the pilot directory is SHA-hashed into
  manifest.files so file_integrity_many_small Pass 3 (EXTRA_FILE_NOT_IN_MANIFEST)
  passes cleanly.

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.fragments.fragment_id import (
    ByteOffsetFragment,
    fragment_to_canonical_dict,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "chat-log-redaction-minimal-rc"
_CREATED_AT = "2026-05-18T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
    "re_derivation_invocation",
]

# ---------------------------------------------------------------------------
# Synthetic chat transcript — multi-turn, ~15 turns, fully invented
# ---------------------------------------------------------------------------

_TRANSCRIPT_TEXT = """\
[2026-05-10 09:01:12] Alice: Hey Bob, can you send the report to my email? It's alice.morgan@databridge.io
[2026-05-10 09:01:45] Bob: Sure, Alice! Also, the client Thomas Whitfield asked us to call him back at (415) 882-9043.
[2026-05-10 09:02:11] Alice: Got it. His billing address is 742 Evergreen Terrace, Springfield, IL 62704.
[2026-05-10 09:02:33] Bob: Right. His SSN for the KYC form is 534-87-2019, please keep that safe.
[2026-05-10 09:03:01] Alice: Of course. The alternate contact is Clara Nguyen — her cell is +1-650-334-7821.
[2026-05-10 09:03:29] Bob: Also note, Clara's personal email is c.nguyen92@mailhub.net.
[2026-05-10 09:04:05] Alice: The invoice was sent to the AP team. Contact is Derek Salazar at derek.salazar@corp-finance.com.
[2026-05-10 09:04:40] Bob: Perfect. Our internal ref is TXN-20260510-8847 — not PII but noted.
[2026-05-10 09:05:15] Alice: Agreed. Thomas's home address is 91 Lakeview Drive, Austin, TX 78701.
[2026-05-10 09:05:48] Bob: His passport number is X84921073 and expiry 2029-08-14.
[2026-05-10 09:06:22] Alice: Make sure the compliance doc has SSN 534-87-2019 redacted before sending.
[2026-05-10 09:06:55] Bob: Will do. The accountant Priya Kapoor's work email is p.kapoor@auditfirm.org.
[2026-05-10 09:07:30] Alice: She can also be reached at (312) 774-5566 during business hours.
[2026-05-10 09:08:01] Bob: Thanks. One more — client ref IP address 192.168.45.200 appeared in the logs.
[2026-05-10 09:08:35] Alice: Good catch. Flag it. My direct line is (212) 993-0010 if anything urgent comes up.
"""

# ---------------------------------------------------------------------------
# Redaction policy — regex patterns + entity dictionary
# ---------------------------------------------------------------------------
# Patterns keyed by entity_kind (applied in this order; first match wins for overlaps).
# Regex patterns are Python-dialect; entity_dict is a list of exact name strings.

_REDACTION_POLICY = {
    "regex_patterns": {
        "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
        "EMAIL": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        "PHONE": r"(?:\+1[-\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b",
        "PASSPORT": r"\b[A-Z]\d{8}\b",
        "IP_ADDRESS": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "ADDRESS": (
            r"\b\d+\s+[A-Z][a-zA-Z\s]+"
            r"(?:Drive|Terrace|Avenue|Street|Road|Way|Lane|Blvd|Boulevard)"
            r"(?:,\s*[A-Za-z\s]+,\s*[A-Z]{2}\s+\d{5})?\b"
        ),
    },
    "entity_dict": [
        "Alice Morgan",
        "Thomas Whitfield",
        "Clara Nguyen",
        "Derek Salazar",
        "Priya Kapoor",
        "Bob",
        "Alice",
    ],
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(obj) -> bytes:
    """Deterministic JSON: sort_keys + compact separators + trailing newline."""
    return (
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _apply_redaction_policy(
    transcript: str, policy: dict
) -> tuple[list[tuple[int, int, str]], str]:
    """Scan transcript for PII using regex patterns + entity dict.

    Returns:
      spans: list of (start_byte, end_byte, entity_kind) in ascending start order.
             Byte offsets are into the UTF-8 encoding of `transcript`.
      redacted: the redacted transcript string (UTF-8 round-trips cleanly for ASCII corpus).

    Algorithm:
      1. Collect all candidate spans from every regex pattern.
      2. Add entity-dict spans (case-sensitive whole-word match).
      3. Remove overlapping spans: walk left-to-right; if a new span overlaps the
         last accepted span, keep whichever ends later (greedy cover).
      4. Sort by start byte, apply [REDACTED:<kind>] substitutions right-to-left
         (so byte offsets stay valid as we mutate the string).
    """
    # Encode once to work in bytes.
    transcript_bytes = transcript.encode("utf-8")

    raw_spans: list[tuple[int, int, str]] = []

    # Step 1 — regex patterns
    for kind, pattern in policy["regex_patterns"].items():
        for m in re.finditer(pattern, transcript):
            # Convert character offsets to byte offsets via pre-encoding.
            start_b = len(transcript[: m.start()].encode("utf-8"))
            end_b = len(transcript[: m.end()].encode("utf-8"))
            raw_spans.append((start_b, end_b, kind))

    # Step 2 — entity dict (exact string match, case-sensitive)
    for name in policy["entity_dict"]:
        for m in re.finditer(re.escape(name), transcript):
            start_b = len(transcript[: m.start()].encode("utf-8"))
            end_b = len(transcript[: m.end()].encode("utf-8"))
            raw_spans.append((start_b, end_b, "PERSON"))

    # Step 3 — sort by start, resolve overlaps (greedy cover, keep first kind on tie)
    raw_spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    accepted: list[tuple[int, int, str]] = []
    for span in raw_spans:
        if not accepted:
            accepted.append(span)
            continue
        last = accepted[-1]
        if span[0] < last[1]:
            # Overlap: keep whichever ends later (greedy cover).
            if span[1] > last[1]:
                accepted[-1] = (last[0], span[1], last[2])
            # else span is fully covered — discard.
        else:
            accepted.append(span)

    # Step 4 — apply substitutions right-to-left to keep byte offsets stable
    result_bytes = bytearray(transcript_bytes)
    for start_b, end_b, kind in reversed(accepted):
        replacement = f"[REDACTED:{kind}]".encode("utf-8")
        result_bytes[start_b:end_b] = replacement

    redacted_str = result_bytes.decode("utf-8")
    return accepted, redacted_str


# ---------------------------------------------------------------------------
# Re-derivation pack source — written into re_derive/ inside the bundle
# ---------------------------------------------------------------------------

_RE_DERIVE_PACK_SOURCE: str = '''\
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
'''


# ---------------------------------------------------------------------------
# Bundle enumeration helper
# ---------------------------------------------------------------------------


def _enumerate_pilot_files_for_manifest(pilot_dir: Path) -> dict:
    """Walk the pilot dir and return {rel_path: sha256} for every file.

    Excludes manifest.json (the manifest itself), any __pycache__ tree, any
    .pyc artifacts, and any files inside spec/ or snapshots/ trees.
    """
    files: dict[str, str] = {}
    _SKIP_TOP = frozenset({"spec", "snapshots", "__pycache__"})
    for fpath in sorted(pilot_dir.rglob("*")):
        if fpath.is_dir():
            continue
        rel = fpath.relative_to(pilot_dir).as_posix()
        if rel == "manifest.json":
            continue
        parts = rel.split("/")
        if parts[0] in _SKIP_TOP:
            continue
        if any(p == "__pycache__" for p in parts):
            continue
        if rel.endswith(".pyc"):
            continue
        files[rel] = _sha256(fpath.read_bytes())
    return files


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    inputs_dir = out_dir / "inputs"
    payload_dir = out_dir / "payload"
    re_derive_dir = out_dir / "re_derive"
    for d in (inputs_dir, payload_dir, re_derive_dir):
        d.mkdir(parents=True, exist_ok=True)

    # --- Write re-derivation pack first (deterministic bytes) ---
    pack_path = re_derive_dir / "chat_log_redaction_pack.py"
    pack_path.write_bytes(_RE_DERIVE_PACK_SOURCE.encode("utf-8"))

    # --- Write transcript.txt ---
    transcript_bytes = _TRANSCRIPT_TEXT.encode("utf-8")
    (inputs_dir / "transcript.txt").write_bytes(transcript_bytes)
    transcript_cid = f"sha256:{_sha256(transcript_bytes)}"

    # --- Write redaction_policy.json ---
    policy_bytes = _canonical_json_bytes(_REDACTION_POLICY)
    (inputs_dir / "redaction_policy.json").write_bytes(policy_bytes)

    # --- Run the redaction and produce payload ---
    spans, redacted_str = _apply_redaction_policy(_TRANSCRIPT_TEXT, _REDACTION_POLICY)
    assert len(spans) >= 6, (
        f"Expected at least 6 PII spans in synthetic transcript; got {len(spans)}. "
        f"Check regex patterns and entity dict."
    )

    redacted_bytes = redacted_str.encode("utf-8")
    redacted_sha = _sha256(redacted_bytes)

    result_payload = {
        "redacted_output_sha": redacted_sha,
        "spans": [
            {"end_byte": end, "entity_kind": kind, "start_byte": start}
            for start, end, kind in spans
        ],
    }
    result_bytes = _canonical_json_bytes(result_payload)
    (payload_dir / "redaction_result.json").write_bytes(result_bytes)

    # --- Build ByteOffsetFragment anchors (one per span) ---
    fragment_anchors: dict[str, dict] = {}
    for i, (start, end, kind) in enumerate(spans):
        key = f"span-{i:03d}-{kind}"
        fragment_anchors[key] = fragment_to_canonical_dict(
            ByteOffsetFragment(
                source_cid=transcript_cid,
                start=start,
                end=end,
            )
        )

    # --- Build manifest.files ---
    if out_dir.resolve() == _HERE.resolve():
        # In-place build: hash every file in the pilot tree so
        # file_integrity_many_small Pass 3 doesn't trip.
        files = _enumerate_pilot_files_for_manifest(out_dir)
    else:
        files = {
            "inputs/transcript.txt": _sha256(transcript_bytes),
            "inputs/redaction_policy.json": _sha256(policy_bytes),
            "payload/redaction_result.json": _sha256(result_bytes),
            "re_derive/chat_log_redaction_pack.py": _sha256(
                _RE_DERIVE_PACK_SOURCE.encode("utf-8")
            ),
        }

    manifest = {
        "bundle_id": _BUNDLE_ID,
        "created_at": _CREATED_AT,
        "cross_refs": {},
        "files": files,
        "fragment_anchors": fragment_anchors,
        "payload": {},
        "schema_version": _SCHEMA_VERSION,
        "spec_files": {},
        "typed_checks": _TYPED_CHECKS,
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"Bundle written to {out_dir}")
    print(
        f"  transcript      : {len(transcript_bytes)} bytes, "
        f"{_TRANSCRIPT_TEXT.count(chr(10))} lines"
    )
    print(f"  redacted spans  : {len(spans)}")
    print(f"  ByteOffsetFrags : {len(fragment_anchors)}")
    print(f"  redacted_sha    : {redacted_sha[:16]}...")
    print(f"  manifest files  : {len(files)}")
    print(f"  manifest        : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic chat_log_redaction_minimal audit bundle"
    )
    parser.add_argument(
        "--out-dir",
        required=False,
        type=Path,
        default=_HERE,
        help=(
            "Destination directory. Defaults to the pilot's own directory "
            "(in-place build) so cli/verify.py --bundle-dir <pilot-dir> Just Works. "
            "Pass an explicit --out-dir to write a standalone bundle."
        ),
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
