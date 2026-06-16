"""_build_bundle.py — build a deterministic iso42001_dataquality_minimal bundle.

ISO/IEC 42001 A.7 (Data for AI Systems) data-quality metric re-derivation pilot.

Re-derives THREE quality metrics from one declared synthetic dataset:
  data_completeness_pct  — % records with every required field non-null
  data_duplicate_rate_pct — % records that are exact duplicates on the required tuple
  data_positive_rate_pct — % label==1 among non-null-label records

Why this matters:
  A 42001-conforming AIMS reports data-quality figures for its datasets
  (A.7 Quality of Data / Data Preparation). Today an auditor takes those figures
  on the org's word. This pilot makes all three re-derivable: the AUDITOR anchors
  one spec binding three output types to one verifier-side primitive under an
  identical scalar_epsilon comparator; the producer cannot weaken any of them.

  Re-derivability of the reported figures only — NOT a judgement that the dataset
  is fit for training, the labels are correct, or that the org satisfies the A.7
  control (which needs the data-governance process the AIMS owns). Synthetic
  data; no customer. This is a MULTI-OUTPUT pilot (exercises the dispatch loop's
  per-output coverage invariant + a type-switching primitive).

Usage (from v-kernel-audit-bundle root):
    python examples/iso42001_dataquality_minimal/_build_bundle.py --out-dir /tmp/iso42001_dq_bundle

Exit codes:
  0  success
  1  assertion / computation failure
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

from iso42001_dataquality_recompute import (  # noqa: E402
    ALL_METRIC_TYPES,
    compute_completeness_pct,
    compute_duplicate_rate_pct,
    compute_positive_rate_pct,
)

from audit_bundle.emitter import BundleContent, write_bundle  # noqa: E402

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "iso42001-dataquality-minimal-rc"
_CREATED_AT = "2026-06-02T00:00:00Z"
_TYPED_CHECKS = ["file_integrity_many_small"]

_PRIMITIVE_ID = "iso42001_dataquality_recompute"
_SPEC_SRC = _HERE / "spec_pinned" / "iso42001_dataquality.spec.json"
_DATASET_SRC = _HERE / "inputs" / "dataset.json"

# output_id == type for each metric (one-to-one), in declared order.
_METRIC_COMPUTE = {
    "data_completeness_pct": compute_completeness_pct,
    "data_duplicate_rate_pct": compute_duplicate_rate_pct,
    "data_positive_rate_pct": compute_positive_rate_pct,
}


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for pycache in out_dir.rglob("__pycache__"):
        if pycache.is_dir():
            shutil.rmtree(pycache, ignore_errors=True)

    # --- 1. Read inputs/dataset.json (frozen fixture) ---
    dataset_bytes = _DATASET_SRC.read_bytes()
    doc = json.loads(dataset_bytes)
    records = doc["records"]

    # --- 2. Compute honest metrics + build claimed-value bytes per metric ---
    files: dict[str, bytes] = {"inputs/dataset.json": dataset_bytes}
    outputs_list = []
    computed: dict[str, float] = {}
    for metric_type, fn in _METRIC_COMPUTE.items():
        value = fn(records)
        computed[metric_type] = value
        claim_bytes = json.dumps({"value": value}, indent=2).encode("utf-8")
        files[f"outputs/{metric_type}.json"] = claim_bytes
        outputs_list.append(
            {
                "output_id": metric_type,
                "type": metric_type,
                "conforms_to": f"spec/{_SPEC_SRC.name}",
            }
        )

    # Sanity: the seeded fixture should yield non-trivial, distinct figures.
    assert 80.0 <= computed["data_completeness_pct"] < 100.0
    assert 0.0 < computed["data_duplicate_rate_pct"] <= 25.0
    assert 30.0 < computed["data_positive_rate_pct"] < 70.0

    # --- 3. Read spec ---
    spec_src_bytes = _SPEC_SRC.read_bytes()
    spec_basename = _SPEC_SRC.name

    # --- 4. Emit via SDK ---
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
    print(f"  dataset_id       : {doc['dataset_id']}")
    print(f"  records          : {len(records)}")
    print(f"  primitive        : {_PRIMITIVE_ID}")
    for mt in ALL_METRIC_TYPES:
        print(f"  {mt:24}: {computed[mt]:.15f}")
    print(f"  spec             : {spec_basename}")
    print(f"  outputs declared : {len(outputs_list)}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic iso42001_dataquality_minimal audit bundle"
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
