#!/usr/bin/env python3
"""climate_emission_pack.py — stdlib re-derivation pack for climate emission domain.

the audit-bundle contract §C5 (auditor independence) + AB4 (duplicate-don't-import):
no audit_bundle imports inside this script. Stdlib only.

Re-derivation primitive:
  For each supplier in inputs/supplier_chain.json (in list order):
    attributed_kg_co2e = round(activity_amount * emission_factor_kg_co2e_per_unit, 6)
  Sum all per-supplier attributed_kg_co2e → total_scope3_kg_co2e (round to 6dp).

Assertions against payload/emission_report.json:
  - same number of attribution records
  - per-record: vendor_id, tier, attributed_kg_co2e must all match exactly
  - top-level total_scope3_kg_co2e must match exactly (round to 6dp)
  - aggregation_method must be "sum"

Exit 0 on full match; exit 1 with [CEM_REDER_FAIL] <description> on stderr.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _fail(msg: str) -> int:
    print(f"[CEM_REDER_FAIL] {msg}", file=sys.stderr)
    return 1


def _compute_attributions(supplier_chain: list) -> tuple:
    """Re-derive per-supplier attributed_kg_co2e and total from supplier_chain."""
    attributions = []
    for s in supplier_chain:
        attributed = round(
            float(s["activity_amount"]) * float(s["emission_factor_kg_co2e_per_unit"]),
            6,
        )
        attributions.append(
            {
                "vendor_id": s["vendor_id"],
                "tier": s["tier"],
                "attributed_kg_co2e": attributed,
            }
        )
    total = round(sum(a["attributed_kg_co2e"] for a in attributions), 6)
    return attributions, total


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Climate Scope-3 emission re-derivation check"
    )
    parser.add_argument("--bundle-dir", required=True, type=Path)
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    supplier_chain_path = bundle_dir / "inputs" / "supplier_chain.json"
    report_path = bundle_dir / "payload" / "emission_report.json"
    for p in (supplier_chain_path, report_path):
        if not p.exists():
            return _fail(f"required file missing: {p}")

    try:
        supplier_chain = json.loads(supplier_chain_path.read_text(encoding="utf-8"))
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return _fail(f"failed to load bundle inputs/payload: {exc}")

    if not isinstance(supplier_chain, list):
        return _fail("supplier_chain.json must be a JSON array")
    if not isinstance(report, dict):
        return _fail("emission_report.json must be a JSON object")

    bundled_attributions = report.get("attributions")
    if not isinstance(bundled_attributions, list):
        return _fail("emission_report.json missing 'attributions' array")
    bundled_total = report.get("total_scope3_kg_co2e")
    if bundled_total is None:
        return _fail("emission_report.json missing 'total_scope3_kg_co2e'")
    agg_method = report.get("aggregation_method")
    if agg_method != "sum":
        return _fail(
            f"emission_report.json aggregation_method must be 'sum'; got {agg_method!r}"
        )

    recomputed, recomputed_total = _compute_attributions(supplier_chain)

    if len(recomputed) != len(bundled_attributions):
        return _fail(
            f"attribution count mismatch: recomputed={len(recomputed)} "
            f"bundled={len(bundled_attributions)}"
        )

    for i, (rec, exp) in enumerate(zip(recomputed, bundled_attributions)):
        if rec["vendor_id"] != exp.get("vendor_id"):
            return _fail(
                f"attribution[{i}] vendor_id mismatch: "
                f"recomputed={rec['vendor_id']!r} bundled={exp.get('vendor_id')!r}"
            )
        if rec["tier"] != exp.get("tier"):
            return _fail(
                f"attribution[{i}] tier mismatch for {rec['vendor_id']!r}: "
                f"recomputed={rec['tier']} bundled={exp.get('tier')}"
            )
        rec_val = round(float(rec["attributed_kg_co2e"]), 6)
        exp_val = round(float(exp.get("attributed_kg_co2e", 0.0)), 6)
        if rec_val != exp_val:
            return _fail(
                f"attribution[{i}] attributed_kg_co2e mismatch for "
                f"{rec['vendor_id']!r}: recomputed={rec_val} bundled={exp_val}"
            )

    bundled_total_rounded = round(float(bundled_total), 6)
    if recomputed_total != bundled_total_rounded:
        return _fail(
            f"total_scope3_kg_co2e mismatch: recomputed={recomputed_total} "
            f"bundled={bundled_total_rounded}"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
