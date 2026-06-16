"""_build_bundle.py — build a deterministic iso42001_event_log_minimal bundle.

ISO/IEC 42001 A.6 "AI-System Recording of Event Logs" integrity re-derivation
pilot. Re-derives the disclosed log-head digest (tip of a SHA-256 hash chain
over the ordered events) and compares it EXACT.

Why this matters:
  A 42001-conforming AIMS keeps operational event logs and commits a
  tamper-evident digest over them (A.6 logging). This pilot makes the disclosed
  head digest re-derivable: the AUDITOR anchors the spec that pins the chaining
  rule (via the primitive_id) and the exact comparator; the producer cannot
  weaken it. Editing, reordering, inserting, or deleting any event changes the
  head -> fail-closed.

  Re-derivability + internal tamper-evidence only — NOT a completeness guarantee
  (no event withheld before commitment), NOT truthfulness of the recorded
  actions, and NOT A.6 control conformance (which needs the logging process the
  AIMS owns). Synthetic data; no customer.

Usage (from v-kernel-audit-bundle root):
    python examples/iso42001_event_log_minimal/_build_bundle.py --out-dir /tmp/iso42001_log_bundle

Exit codes:
  0  success    1  failure
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from iso42001_event_log_recompute import compute_log_head_digest  # noqa: E402

from audit_bundle.emitter import BundleContent, write_bundle  # noqa: E402

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "iso42001-event-log-minimal-rc"
_CREATED_AT = "2026-06-02T00:00:00Z"
_TYPED_CHECKS = ["file_integrity_many_small"]

_OUTPUT_ID = "log_chain_head_digest"
_TYPE_KEY = "log_chain_head_digest"
_SPEC_SRC = _HERE / "spec_pinned" / "iso42001_event_log.spec.json"
_LOG_SRC = _HERE / "inputs" / "event_log.json"


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for pycache in out_dir.rglob("__pycache__"):
        if pycache.is_dir():
            shutil.rmtree(pycache, ignore_errors=True)

    log_bytes = _LOG_SRC.read_bytes()
    doc = json.loads(log_bytes)
    events = doc["events"]
    head = compute_log_head_digest(events)
    assert isinstance(head, str) and len(head) == 64  # sha256 hex

    spec_src_bytes = _SPEC_SRC.read_bytes()
    spec_basename = _SPEC_SRC.name

    claim_bytes = json.dumps({"value": head}, indent=2).encode("utf-8")

    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "inputs/event_log.json": log_bytes,
            f"outputs/{_OUTPUT_ID}.json": claim_bytes,
        },
        spec_files={spec_basename: spec_src_bytes},
        cross_refs={},
        payload={},
        typed_checks=_TYPED_CHECKS,
        extra_manifest_fields={
            "fragment_anchors": {},
            "outputs": [
                {"output_id": _OUTPUT_ID, "type": _TYPE_KEY, "conforms_to": f"spec/{spec_basename}"}
            ],
        },
    )
    write_bundle(out_dir, content)

    print(f"Bundle written to {out_dir}")
    print(f"  log_id           : {doc['log_id']}")
    print(f"  events           : {len(events)}")
    print(f"  log_head_digest  : {head}")
    print(f"  spec             : {spec_basename}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic iso42001_event_log_minimal audit bundle"
    )
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        build(args.out_dir.resolve())
    except (AssertionError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
