"""_build_bundle.py — build a deterministic iso42001_impact_fairness_minimal bundle.

ISO/IEC 42001 A.5 (Assessing Impacts of AI Systems) disparate-impact
re-derivation pilot. Re-derives the disclosed disparate-impact ratio (EEOC
four-fifths: min group approval rate / max group approval rate) from declared
per-subject outcomes.

Why this matters:
  A 42001-conforming AIMS discloses a fairness / adverse-impact figure in its
  impact assessment (A.5). Outside parties act on it but cannot check it against
  the underlying outcomes. This pilot makes the figure re-derivable: the AUDITOR
  anchors the spec that pins the metric method + tolerance; the producer cannot
  weaken it. A doctored disclosed ratio, a tampered outcomes file, or a weaker
  producer-supplied spec all fail-closed.

  Re-derivability of the disclosed figure only — NOT a judgement that the
  groups/outcomes are correctly recorded, that this is the right fairness
  measure, or that the org satisfies the A.5 control (which needs the
  impact-assessment process the AIMS owns). Synthetic data; no customer.

Usage (from v-kernel-audit-bundle root):
    python examples/iso42001_impact_fairness_minimal/_build_bundle.py --out-dir /tmp/iso42001_fair_bundle

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

from iso42001_fairness_recompute import compute_disparate_impact_ratio  # noqa: E402

from audit_bundle.emitter import BundleContent, write_bundle  # noqa: E402

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "iso42001-impact-fairness-minimal-rc"
_CREATED_AT = "2026-06-02T00:00:00Z"
_TYPED_CHECKS = ["file_integrity_many_small"]

_OUTPUT_ID = "disparate_impact_ratio"
_TYPE_KEY = "disparate_impact_ratio"
_SPEC_SRC = _HERE / "spec_pinned" / "iso42001_fairness.spec.json"
_OUTCOMES_SRC = _HERE / "inputs" / "outcomes.json"


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for pycache in out_dir.rglob("__pycache__"):
        if pycache.is_dir():
            shutil.rmtree(pycache, ignore_errors=True)

    outcomes_bytes = _OUTCOMES_SRC.read_bytes()
    doc = json.loads(outcomes_bytes)
    records = doc["outcomes"]
    dir_value = compute_disparate_impact_ratio(records)

    # Sanity: the seeded fixture should show a sub-four-fifths adverse impact.
    assert 0.0 < dir_value < 0.8, (
        f"Expected disparate-impact ratio in (0, 0.8); got {dir_value:.6f}."
    )

    spec_src_bytes = _SPEC_SRC.read_bytes()
    spec_basename = _SPEC_SRC.name

    claim_bytes = json.dumps({"value": dir_value}, indent=2).encode("utf-8")

    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "inputs/outcomes.json": outcomes_bytes,
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

    n_groups = len({r["group"] for r in records})
    print(f"Bundle written to {out_dir}")
    print(f"  assessment_id    : {doc['assessment_id']}")
    print(f"  subjects/groups  : {len(records)} subjects / {n_groups} groups")
    print(f"  disparate_impact_ratio: {dir_value:.15f}  (four-fifths threshold 0.8)")
    print(f"  spec             : {spec_basename}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic iso42001_impact_fairness_minimal audit bundle"
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
