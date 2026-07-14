#!/usr/bin/env python3
"""dc_emissions_mrv_pack.py — stdlib re-derivation pack for data-center NSR.

the audit-bundle contract §C5 (auditor independence) + AB4 (duplicate-don't-import):
no audit_bundle imports. Stdlib only.

Re-derivation primitive:
  For each emission source in inputs/emission_sources.json (sorted by source_id):
    - if source_type == "diesel_genset_tier4f":
        tpy = count * rated_power_hp * annual_runtime_hr * EF_g_per_hp_hr
              / (453.59237 * 2000)   # g -> lb -> tons
    - if source_type == "combustion_turbine_subpart_kkkk":
        tpy = count * rated_power_mw * annual_runtime_hr * EF_lb_per_mwh
              / 2000                # lb -> tons
  Round each per-source tpy to 6 dp; sum per-pollutant; recompute classification
  via inputs/permit_thresholds.json:
    - total >= major_source_threshold     -> "major_source"
    - total >= synthetic_minor_threshold  -> "synthetic_minor_breach"
    - else                                -> "synthetic_minor"
  Overall classification = strictest pollutant classification.
  Embodied carbon: sum(quantity * EF) over inputs/embodied_carbon_inventory.json.
  Assert every per-source tpy, per-pollutant total, per-pollutant classification,
  embodied-carbon total, and overall_classification match payload/nsr_submission.json
  exactly.

Exit 0 on full match; exit 1 with [DCMRV_REDER_FAIL] <description> on stderr.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


_G_PER_LB = 453.59237
_LB_PER_TON = 2000.0
_CRITERIA_POLLUTANTS = ("NOx", "CO", "PM", "NMHC")


def _fail(msg: str) -> int:
    print(f"[DCMRV_REDER_FAIL] {msg}", file=sys.stderr)
    return 1


def _source_tpy(source: dict, pollutant: str) -> float:
    st = source["source_type"]
    if st == "diesel_genset_tier4f":
        ef = float(source["emission_factors_g_per_hp_hr"][pollutant])
        total_g = (
            float(source["count"])
            * float(source["rated_power_hp"])
            * float(source["annual_runtime_hr"])
            * ef
        )
        return round(total_g / (_G_PER_LB * _LB_PER_TON), 6)
    if st == "combustion_turbine_subpart_kkkk":
        ef = float(source["emission_factors_lb_per_mwh"][pollutant])
        total_lb = (
            float(source["count"])
            * float(source["rated_power_mw"])
            * float(source["annual_runtime_hr"])
            * ef
        )
        return round(total_lb / _LB_PER_TON, 6)
    raise ValueError(f"unknown source_type: {st!r}")


def _classify(total: float, synmin: float, majsrc: float) -> str:
    if total >= majsrc:
        return "major_source"
    if total >= synmin:
        return "synthetic_minor_breach"
    return "synthetic_minor"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Data-center NSR + embodied-carbon re-derivation check"
    )
    parser.add_argument("--bundle-dir", required=True, type=Path)
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    sources_path = bundle_dir / "inputs" / "emission_sources.json"
    materials_path = bundle_dir / "inputs" / "embodied_carbon_inventory.json"
    thresholds_path = bundle_dir / "inputs" / "permit_thresholds.json"
    submission_path = bundle_dir / "payload" / "nsr_submission.json"
    for p in (sources_path, materials_path, thresholds_path, submission_path):
        if not p.exists():
            return _fail(f"required file missing: {p}")

    try:
        sources = json.loads(sources_path.read_text(encoding="utf-8"))
        materials = json.loads(materials_path.read_text(encoding="utf-8"))
        thresholds = json.loads(thresholds_path.read_text(encoding="utf-8"))
        submission = json.loads(submission_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return _fail(f"failed to load bundle inputs/payload: {exc}")

    if not isinstance(sources, list):
        return _fail("emission_sources.json must be a JSON array")
    if not isinstance(materials, list):
        return _fail("embodied_carbon_inventory.json must be a JSON array")
    if not isinstance(submission, dict):
        return _fail("nsr_submission.json must be a JSON object")
    if submission.get("aggregation_method") != "sum":
        return _fail(
            f"nsr_submission.aggregation_method must be 'sum'; got "
            f"{submission.get('aggregation_method')!r}"
        )

    bundled_criteria = submission.get("criteria_pollutants")
    if not isinstance(bundled_criteria, dict):
        return _fail("nsr_submission missing 'criteria_pollutants' object")

    syn_thr = thresholds.get("synthetic_minor_thresholds_tpy", {})
    maj_thr = thresholds.get("major_source_thresholds_tpy", {})

    # ---- Citation-presence assertions (provenance is load-bearing) ----
    _REQUIRED_CITATION_KEYS = ("authority", "document_section", "document_url")

    def _check_citation(row, row_kind, row_id):
        c = row.get("citation")
        if not isinstance(c, dict):
            return f"{row_kind} {row_id!r} missing 'citation' object"
        for k in _REQUIRED_CITATION_KEYS:
            v = c.get(k)
            if not isinstance(v, str) or not v.strip():
                return (
                    f"{row_kind} {row_id!r} citation.{k} missing or empty "
                    f"(CITATION_MISSING)"
                )
        return None

    for s in sources:
        err = _check_citation(s, "emission_source", s.get("source_id", "?"))
        if err:
            return _fail(err)
    for m in materials:
        err = _check_citation(m, "embodied_carbon_material", m.get("material_id", "?"))
        if err:
            return _fail(err)
    err = _check_citation(thresholds, "permit_thresholds", thresholds.get("jurisdiction", "?"))
    if err:
        return _fail(err)

    # ---- Per-pollutant recompute ----
    for poll in _CRITERIA_POLLUTANTS:
        per_source = []
        for s in sources:
            per_source.append(
                {"source_id": s["source_id"], "tpy": _source_tpy(s, poll)}
            )
        total = round(sum(r["tpy"] for r in per_source), 6)
        synmin = float(syn_thr.get(poll, 0.0))
        majsrc = float(maj_thr.get(poll, 0.0))
        classification = _classify(total, synmin, majsrc)

        bundled = bundled_criteria.get(poll)
        if not isinstance(bundled, dict):
            return _fail(f"criteria_pollutants[{poll!r}] missing or wrong shape")
        b_total = round(float(bundled.get("total_tpy", 0.0)), 6)
        if total != b_total:
            return _fail(
                f"{poll} total_tpy mismatch: recomputed={total} bundled={b_total}"
            )
        if classification != bundled.get("classification"):
            return _fail(
                f"{poll} classification mismatch: recomputed={classification!r} "
                f"bundled={bundled.get('classification')!r}"
            )

        b_per_source = bundled.get("per_source_tpy", [])
        if len(b_per_source) != len(per_source):
            return _fail(
                f"{poll} per_source_tpy count mismatch: "
                f"recomputed={len(per_source)} bundled={len(b_per_source)}"
            )
        for i, (rec, exp) in enumerate(zip(per_source, b_per_source)):
            if rec["source_id"] != exp.get("source_id"):
                return _fail(
                    f"{poll} per_source_tpy[{i}] source_id mismatch: "
                    f"recomputed={rec['source_id']!r} bundled={exp.get('source_id')!r}"
                )
            rec_v = round(float(rec["tpy"]), 6)
            exp_v = round(float(exp.get("tpy", 0.0)), 6)
            if rec_v != exp_v:
                return _fail(
                    f"{poll} per_source_tpy[{i}] tpy mismatch for "
                    f"{rec['source_id']!r}: recomputed={rec_v} bundled={exp_v}"
                )

    # ---- Embodied carbon ----
    per_material = []
    for m in materials:
        attributed = round(
            float(m["quantity"]) * float(m["emission_factor_kg_co2e_per_unit"]), 6
        )
        per_material.append({"material_id": m["material_id"], "kg_co2e": attributed})
    total_embodied = round(sum(r["kg_co2e"] for r in per_material), 6)
    bundled_emb = submission.get("embodied_carbon", {})
    b_emb_total = round(float(bundled_emb.get("total_kg_co2e", 0.0)), 6)
    if total_embodied != b_emb_total:
        return _fail(
            f"embodied_carbon.total_kg_co2e mismatch: "
            f"recomputed={total_embodied} bundled={b_emb_total}"
        )

    # ---- Overall classification ----
    classes = {bundled_criteria[p]["classification"] for p in _CRITERIA_POLLUTANTS}
    if "major_source" in classes:
        overall = "major_source"
    elif "synthetic_minor_breach" in classes:
        overall = "synthetic_minor_breach"
    else:
        overall = "synthetic_minor"
    bundled_overall = submission.get("overall_classification")
    if overall != bundled_overall:
        return _fail(
            f"overall_classification mismatch: recomputed={overall!r} "
            f"bundled={bundled_overall!r}"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
