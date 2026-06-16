"""_build_bundle.py — build a deterministic iso42001_external_reporting_minimal bundle.

ISO/IEC 42001 A.8 (Information for Interested Parties) external-reporting
reconciliation pilot. Re-derives two EXTERNALLY-DISCLOSED figures from one
declared internal decision log:

  disclosed_automated_decision_count  (integer, compared exact)
  disclosed_human_oversight_rate_pct  (rate, compared scalar_epsilon)

Why this matters:
  A 42001-conforming AIMS publishes aggregate figures to regulators / users /
  the public (A.8 External Reporting). Those parties act on the numbers but
  cannot check them against the org's internal records. This pilot makes both
  disclosed figures re-derivable: the AUDITOR anchors a spec binding each
  disclosed figure to a verifier-side primitive + comparator; the producer
  cannot weaken them. A doctored disclosed number, a tampered log file, or a
  weaker producer-supplied spec all fail-closed.

  Re-derivability of the disclosed figures only — NOT a judgement that the log
  is complete/truthful or the disclosure adequate, and NOT A.8 control
  conformance. Synthetic data; no customer.

Usage (from v-kernel-audit-bundle root):
    python examples/iso42001_external_reporting_minimal/_build_bundle.py --out-dir /tmp/iso42001_er_bundle

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

from iso42001_external_reporting_recompute import (  # noqa: E402
    compute_automated_decision_count,
    compute_human_oversight_rate_pct,
)

from audit_bundle.emitter import BundleContent, write_bundle  # noqa: E402

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "iso42001-external-reporting-minimal-rc"
_CREATED_AT = "2026-06-02T00:00:00Z"
_TYPED_CHECKS = ["file_integrity_many_small"]

_SPEC_SRC = _HERE / "spec_pinned" / "iso42001_external_reporting.spec.json"
_LOG_SRC = _HERE / "inputs" / "decision_log.json"

# output_id -> (type, compute fn). output_id == type (one-to-one).
_COUNT_ID = "disclosed_automated_decision_count"
_RATE_ID = "disclosed_human_oversight_rate_pct"


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for pycache in out_dir.rglob("__pycache__"):
        if pycache.is_dir():
            shutil.rmtree(pycache, ignore_errors=True)

    # --- 1. Read inputs/decision_log.json (frozen fixture) ---
    log_bytes = _LOG_SRC.read_bytes()
    doc = json.loads(log_bytes)
    records = doc["decisions"]

    # --- 2. Compute honest disclosed figures ---
    count = compute_automated_decision_count(records)   # int
    rate = compute_human_oversight_rate_pct(records)     # float
    assert isinstance(count, int) and count > 0
    assert 0.0 < rate < 100.0

    # --- 3. Build claimed-value bytes (count is an int -> exact; rate is a float) ---
    files: dict[str, bytes] = {"inputs/decision_log.json": log_bytes}
    outputs_list = []
    for output_id, claimed in ((_COUNT_ID, count), (_RATE_ID, rate)):
        claim_bytes = json.dumps({"value": claimed}, indent=2).encode("utf-8")
        files[f"outputs/{output_id}.json"] = claim_bytes
        outputs_list.append(
            {
                "output_id": output_id,
                "type": output_id,
                "conforms_to": f"spec/{_SPEC_SRC.name}",
            }
        )

    # --- 4. Read spec ---
    spec_src_bytes = _SPEC_SRC.read_bytes()
    spec_basename = _SPEC_SRC.name

    # --- 5. Emit via SDK ---
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files=files,
        spec_files={spec_basename: spec_src_bytes},
        cross_refs={},
        payload={},
        typed_checks=_TYPED_CHECKS,
        extra_manifest_fields={
            "fragment_anchors": {},
            "outputs": outputs_list,
        },
    )
    write_bundle(out_dir, content)

    print(f"Bundle written to {out_dir}")
    print(f"  report_id        : {doc['report_id']}")
    print(f"  decisions        : {len(records)}")
    print(f"  {_COUNT_ID}: {count}  (exact)")
    print(f"  {_RATE_ID}: {rate:.15f}  (scalar_epsilon)")
    print(f"  spec             : {spec_basename}")
    print(f"  outputs declared : {len(outputs_list)}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic iso42001_external_reporting_minimal audit bundle"
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
