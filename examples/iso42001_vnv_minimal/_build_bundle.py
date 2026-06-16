"""_build_bundle.py — build a deterministic iso42001_vnv_minimal audit bundle.

ISO/IEC 42001 A.6 Verification-and-Validation Metric Re-Derivation pilot.

Given a frozen synthetic V&V holdout test set (per-item label + model score),
re-derive the reported ROC-AUC as the tie-averaged Mann-Whitney rank statistic:

    AUC = (R_pos - n_pos·(n_pos+1)/2) / (n_pos · n_neg)

Why this matters:
  A 42001-conforming AI Management System reports model-validation metrics
  (A.6 "AI-System Verification and Validation") in its V&V records. Today an
  auditor takes the reported AUC on the org's word — the test-set evidence and
  the metric computation are not independently re-checkable. This pilot makes
  the reported metric re-derivable: the AUDITOR anchors the spec that pins HOW
  the AUC is recomputed and the tolerance; the producer (the org being audited)
  cannot weaken it. A tampered claimed AUC or a tampered test-set file both
  fail-closed.

  This does NOT claim the model is good, the labels are correct, or the test set
  is representative; and it does NOT claim 42001 control conformance (that needs
  the V&V process + human judgement the AIMS owns). It claims the reported metric
  is RE-DERIVABLE and tamper-evident under the auditor's pinned method. The data
  is synthetic; there is no customer.

Re-derivation primitive (one sentence):
  ROC-AUC over the declared (label, score) pairs via tie-averaged ascending-rank
  Mann-Whitney U.

The metric method is FIXED in the verifier's primitive code; the auditor's spec
binding pins the primitive_id and epsilon.

Usage (from v-kernel-audit-bundle root):
    python examples/iso42001_vnv_minimal/_build_bundle.py --out-dir /tmp/iso42001_vnv_bundle

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

# Import the canonical compute function from the primitive module so the builder
# and the verifier share ONE definition and cannot drift.
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from iso42001_auc_recompute import compute_roc_auc  # noqa: E402

from audit_bundle.emitter import BundleContent, write_bundle  # noqa: E402

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "iso42001-vnv-minimal-rc"
_CREATED_AT = "2026-06-02T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
]

_OUTPUT_ID = "model_validation_auc"
_TYPE_KEY = "model_validation_auc"
_SPEC_SRC = _HERE / "spec_pinned" / "iso42001_vnv.spec.json"
_TEST_SET_SRC = _HERE / "inputs" / "test_set.json"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # Sweep __pycache__ before enumerating files (verifier-self-pollution guard)
    for pycache in out_dir.rglob("__pycache__"):
        if pycache.is_dir():
            shutil.rmtree(pycache, ignore_errors=True)

    # --- 1. Read inputs/test_set.json (frozen fixture) ---
    test_set_bytes = _TEST_SET_SRC.read_bytes()

    # --- 2. Compute honest ROC-AUC ---
    doc = json.loads(test_set_bytes)
    evaluations = doc["evaluations"]
    auc = compute_roc_auc(evaluations)

    # Sanity-check: the fixture should produce a non-trivial, sub-perfect AUC.
    assert 0.80 <= auc < 1.0, (
        f"Expected AUC in [0.80, 1.0); got {auc:.6f}. Check the fixture scores."
    )

    # --- 3. Read spec ---
    spec_src_bytes = _SPEC_SRC.read_bytes()
    spec_basename = _SPEC_SRC.name

    # --- 4. Build claimed-value bytes ---
    claim_bytes = json.dumps({"value": auc}, indent=2).encode("utf-8")

    outputs_list = [
        {
            "output_id": _OUTPUT_ID,
            "type": _TYPE_KEY,
            "conforms_to": f"spec/{spec_basename}",
        }
    ]

    # --- 5. Emit via SDK ---
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "inputs/test_set.json": test_set_bytes,
            f"outputs/{_OUTPUT_ID}.json": claim_bytes,
        },
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

    n_pos = sum(1 for e in evaluations if int(e["label"]) == 1)
    print(f"Bundle written to {out_dir}")
    print(f"  model_id         : {doc['model_id']}")
    print(f"  test items       : {len(evaluations)}  ({n_pos} pos / {len(evaluations) - n_pos} neg)")
    print(f"  metric           : {doc['metric']} ({doc['metric_method']})")
    print(f"  roc_auc          : {auc:.15f}")
    print(f"  output_id        : {_OUTPUT_ID}")
    print(f"  spec             : {spec_basename}")
    print(f"  manifest         : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic iso42001_vnv_minimal audit bundle"
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
    except (AssertionError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
