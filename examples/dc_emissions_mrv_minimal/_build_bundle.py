"""_build_bundle.py — build a deterministic dc_emissions_mrv_minimal audit bundle.

Data-center pre-construction NSR (New Source Review) air-permit + embodied-carbon
LCA submission pilot. Re-derivation primitive (one sentence):

  For each emission source, recompute annual tpy per criteria pollutant via the
  source-type-specific deterministic formula (diesel-genset:
  count * rated_power_hp * annual_runtime_hr * EF_g_per_hp_hr /
  (453.59237 * 2000); turbine: count * rated_power_mw * annual_runtime_hr *
  EF_lb_per_mwh / 2000); sum per-pollutant; recompute embodied-carbon per
  material via quantity * EF; assert per-source tpy, per-pollutant totals,
  per-pollutant NSR classification (synthetic-minor / major), embodied-carbon
  total, and overall facility classification all exactly match
  payload/nsr_submission.json.

Why this matters for data-center construction:
  NSR pre-construction air permits (Clean Air Act § 165 PSD / § 182 NAA) are
  the dominant gate that blocks data-center construction starts in 2026.
  State air-quality regulators flag NSR submissions that cannot show
  defensible derivations from EFs to per-pollutant tpy totals to major-source
  classification. The bundle is the receipt: every input EF, runtime
  assumption, and equipment count is SHA-pinned, the calculation is
  re-runnable offline by the auditor, and any tamper post-submission is
  caught by a 30-second verifier run.

  Real-world anchors (cited in README; pilot fixtures are synthetic):
   - 40 CFR Part 60 Subpart IIII (NSPS for stationary CI engines — diesel gensets)
   - 40 CFR Part 60 Subpart KKKK (NSPS for stationary combustion turbines)
   - EPA AP-42 §3.4 (large stationary diesel emission factors)
   - EPA "Begin Actual Construction" NSR proposed rule (May 13 2026)
   - Project Jupiter NM air-permit hearing (Apr 22 → Jul 21 2026 extension)

Honest framing:
  NOT a new shape — this is a domain exemplar in the numeric-aggregation shape
  family (same as climate_emission_minimal, agritech_sensor_minimal,
  a sensor score_pack). Production integrators swap the synthetic EFs and
  thresholds for jurisdiction-certified values (state-AQMD-issued, EPA AP-42
  table refs, NSPS subpart-specific limits); the bundle shape and
  verification protocol are identical.

Fragment kind: OpaqueFragment(kind_tag="nsr_emission_source_anchor") and
  OpaqueFragment(kind_tag="embodied_carbon_material_anchor"). Substrate
  validates shape only; semantic validation is owned by
  DCEmissionsMRVReDerivationCheck.

Usage:
    python examples/dc_emissions_mrv_minimal/_build_bundle.py
        # in-place build into the pilot directory

    python examples/dc_emissions_mrv_minimal/_build_bundle.py --out-dir /tmp/dcmrv_bundle
        # standalone bundle in a fresh out-dir

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.fragments.fragment_id import (
    OpaqueFragment,
    fragment_to_canonical_dict,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "dc-emissions-mrv-minimal-rc"
_CREATED_AT = "2026-05-20T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
    "re_derivation_invocation",
]

_FACILITY_ID = "DC-SYN-001"
_THRESHOLDS_JURISDICTION = "sacramento-metro-aqmd-ozone-severe-2008-naaqs"
_CRITERIA_POLLUTANTS = ("NOx", "CO", "PM", "NMHC")

# ---------------------------------------------------------------------------
# Cited fixtures — 100 MW hyperscaler config (sources sorted by source_id).
#
# Hardening discipline:
#  - Every emission-factor row carries a `citation` block — `authority`,
#    `document_section`, `document_url`, plus `factor_basis` distinguishing
#    "regulatory_limit" (NSPS standard, worst legal case) from
#    "realistic_post_aftertreatment" (typical engine/turbine output with
#    DPF/SCR/DOC controls, sub-limit) from "engine_oem_test_certificate"
#    (placeholder for production data).
#  - Permit thresholds carry a `citation` block tied to a SPECIFIC SIP-approved
#    AQMD rule and a SPECIFIC CAA section, NOT a vague handwave.
#  - The re-derivation pack asserts every input row carries a non-empty
#    citation triple; a stripped citation_url fires CITATION_MISSING and the
#    bundle fails — provenance is load-bearing.
#
# What is REAL vs SYNTHETIC:
#  - Regulatory CITATIONS (40 CFR sections, AQMD rule numbers, CAA sections,
#    NSPS subparts, AP-42 sections, EPD database identities like Bath ICE v3
#    and EC3) are real, with public URLs.
#  - Specific NUMERIC LIMITS quoted in the citation `note` field
#    (Tier-4-Final 0.40 g/kWh NMHC+NOx combined, Subpart KKKK Table 1 42 ppm
#    @ 15% O2 = 2.3 lb/MWh, SMAQMD Rule 214 25 tpy Severe NAA) are real
#    public regulatory values.
#  - EF magnitudes USED IN THE CALCULATION are synthetic engine-/turbine-
#    -specific values consistent with the cited regulatory ceilings — a real
#    permit consultant pulls these from OEM test cert sheets and EPD lookups,
#    NOT from the regulatory ceiling. The pilot uses realistic-magnitude
#    synthetics so the totals land in a realistic place.
#  - Embodied-carbon EFs are synthetic mean-range values consistent with
#    Bath ICE v3 / EC3 public database ranges (cited per material).
# ---------------------------------------------------------------------------

_EMISSION_SOURCES = [
    {
        "source_id": "GEN-001",
        "source_type": "diesel_genset_tier4f",
        "source_class": "internal_combustion_engine",
        "count": 120,
        "rated_power_hp": 3500.0,
        "annual_runtime_hr": 100.0,
        "annual_runtime_basis": (
            "non-emergency readiness testing cap — 40 CFR 60.4211(f)(2)(ii) "
            "permits up to 100 hr/yr for maintenance/readiness on stationary "
            "emergency CI engines; emergency use itself is uncapped"
        ),
        "emission_factors_g_per_hp_hr": {
            "NOx": 0.24,
            "CO": 0.70,
            "PM": 0.0224,
            "NMHC": 0.05,
        },
        "factor_basis": "engine_oem_test_certificate_synthetic_placeholder",
        "factor_source": "synthetic-engine-oem-test-cert/tier4f-stationary-diesel-gt750hp",
        "citation": {
            "authority": "US EPA / 40 CFR Part 60 Subpart IIII (NSPS) by reference to 40 CFR Part 1039 Tier 4 Final standards",
            "document_section": "40 CFR 60.4205(b) + 40 CFR 1039.101 Table 1 (engines > 560 kW / > 750 hp, model year 2015+)",
            "document_url": "https://www.ecfr.gov/current/title-40/chapter-I/subchapter-C/part-60/subpart-IIII",
            "regulatory_limit_note": (
                "Tier 4 Final ceiling: NMHC+NOx combined ≤ 0.40 g/kWh "
                "(≈ 0.298 g/hp-hr), PM ≤ 0.03 g/kWh (≈ 0.0224 g/hp-hr). "
                "The pilot's synthetic split (NOx 0.24 + NMHC 0.05 = 0.29 "
                "g/hp-hr combined) sits at the combined limit; CO uses a "
                "realistic post-DOC value, the engine-out 3.5 g/kWh ceiling "
                "is rarely seen in service. Production: replace with the "
                "OEM-issued engine certification test report."
            ),
            "accessed_at": "2026-05-20",
        },
    },
    {
        "source_id": "TRB-001",
        "source_type": "combustion_turbine_subpart_kkkk",
        "source_class": "combustion_turbine",
        "count": 1,
        "rated_power_mw": 50.0,
        "annual_runtime_hr": 200.0,
        "annual_runtime_basis": (
            "peak-shaving / backup operating envelope; modeled under the "
            "facility's proposed Title V annual-hours cap"
        ),
        "emission_factors_lb_per_mwh": {
            "NOx": 0.493,
            "CO": 0.05,
            "PM": 0.005,
            "NMHC": 0.005,
        },
        "factor_basis": "realistic_post_aftertreatment_synthetic",
        "factor_source": "synthetic-turbine-oem-test-cert/lean-premix-50mw-scr",
        "citation": {
            "authority": "US EPA / 40 CFR Part 60 Subpart KKKK (NSPS for stationary combustion turbines)",
            "document_section": "40 CFR 60.4320(a) + Table 1 to Subpart KKKK (NOx limits for new stationary combustion turbines)",
            "document_url": "https://www.ecfr.gov/current/title-40/chapter-I/subchapter-C/part-60/subpart-KKKK/subject-group-ECFR19767a6b7b4579c/section-60.4320",
            "regulatory_limit_note": (
                "Subpart KKKK Table 1 ceiling for new natural-gas turbines "
                "with heat input ≤ 50 MMBtu/h: 42 ppm NOx @ 15% O2 = 2.3 "
                "lb/MWh. Modern lean-premix combustors with SCR achieve "
                "~9 ppm = 0.493 lb/MWh, the value used in this pilot. "
                "Production: replace with the OEM stack-test report on the "
                "specific turbine model."
            ),
            "accessed_at": "2026-05-20",
        },
    },
]

_EMBODIED_CARBON_INVENTORY = [
    {
        "material_id": "ALUM-RACK-001",
        "material_name": "Server rack aluminium (extruded, primary mix)",
        "quantity": 2500.0,
        "unit": "tonne",
        "emission_factor_kg_co2e_per_unit": 8240.0,
        "epd_source": "synthetic-EPD-bath-ice-v3-aligned/aluminium-extrusion-primary",
        "citation": {
            "authority": "Bath Inventory of Carbon and Energy (ICE) v3 — Hammond & Jones, University of Bath / Circular Ecology",
            "document_section": "ICE v3 dataset entry: Aluminium, general (primary), 8.24 kgCO2e/kg",
            "document_url": "https://circularecology.com/embodied-carbon-footprint-database.html",
            "regulatory_limit_note": (
                "ICE v3 public mean for primary aluminium extrusion is "
                "8.24 kgCO2e/kg = 8240 kgCO2e/tonne, used directly. "
                "Production: replace with the supplier-issued EPD (e.g., via "
                "EC3 or One Click LCA) for the specific rack profile + alloy "
                "+ recycled-content fraction."
            ),
            "accessed_at": "2026-05-20",
        },
    },
    {
        "material_id": "CONC-FLR-001",
        "material_name": "Structural concrete 4000psi (raised floor + slab)",
        "quantity": 50000.0,
        "unit": "cubic_yard",
        "emission_factor_kg_co2e_per_unit": 220.0,
        "epd_source": "synthetic-EPD-ec3-aligned/concrete-4000psi-ready-mix",
        "citation": {
            "authority": "Building Transparency / EC3 (Embodied Carbon in Construction Calculator)",
            "document_section": "EC3 ready-mix concrete category, 4000 psi (27.6 MPa) typical industry-average GWP",
            "document_url": "https://buildingtransparency.org/ec3",
            "regulatory_limit_note": (
                "EC3 + Bath ICE v3 public range for 4000 psi ready-mix is "
                "roughly 150–300 kgCO2e/m³ depending on cement content + SCM "
                "substitution; 220 kgCO2e/yd³ ≈ 168 kgCO2e/m³, mid-low. "
                "Production: pull the regional NRMCA Type III EPD for the "
                "specific mix design (cement type, SCM%, w/c ratio)."
            ),
            "accessed_at": "2026-05-20",
        },
    },
    {
        "material_id": "GLAS-FAC-001",
        "material_name": "Curtain-wall glazing (double-pane insulated glazing unit)",
        "quantity": 800.0,
        "unit": "tonne",
        "emission_factor_kg_co2e_per_unit": 1450.0,
        "epd_source": "synthetic-EPD-ice-v3-aligned/insulated-glazing-unit",
        "citation": {
            "authority": "Bath ICE v3 / industry-average Type III EPD for insulated glazing units",
            "document_section": "Float glass + IGU assembly (frame excluded) — public ICE v3 entry",
            "document_url": "https://circularecology.com/embodied-carbon-footprint-database.html",
            "regulatory_limit_note": (
                "Float glass alone is ~1.4 kgCO2e/kg per ICE v3; insulated "
                "glazing units add spacer + low-E coating + sealant + 2nd "
                "pane, landing at ~1.45 kgCO2e/kg in industry-average EPDs. "
                "Production: replace with the GANA / IGMA Type III EPD on "
                "the specific unit assembly."
            ),
            "accessed_at": "2026-05-20",
        },
    },
    {
        "material_id": "STL-REB-001",
        "material_name": "Reinforcing steel (rebar, EAF — US industry-average)",
        "quantity": 8000.0,
        "unit": "tonne",
        "emission_factor_kg_co2e_per_unit": 1100.0,
        "epd_source": "synthetic-EPD-crsi-v2-aligned/steel-rebar-eaf-us",
        "citation": {
            "authority": "Concrete Reinforcing Steel Institute (CRSI) Industry-Average EPD for fabricated reinforcing steel",
            "document_section": "CRSI Type III EPD — US-mix EAF rebar, cradle-to-gate, declared unit 1 tonne",
            "document_url": "https://www.crsi.org/sustainability/",
            "regulatory_limit_note": (
                "CRSI / Bath ICE v3 US-mix EAF rebar range is roughly 0.9–"
                "1.4 kgCO2e/kg = 900–1400 kgCO2e/tonne. 1100 kgCO2e/tonne is "
                "a midpoint. Production: substitute the supplier's EPD "
                "(mill-specific scrap %, electricity grid mix matter)."
            ),
            "accessed_at": "2026-05-20",
        },
    },
    {
        "material_id": "STL-STR-001",
        "material_name": "Structural steel (wide-flange, EAF — AISC industry-average)",
        "quantity": 12000.0,
        "unit": "tonne",
        "emission_factor_kg_co2e_per_unit": 1000.0,
        "epd_source": "synthetic-EPD-aisc-v2-aligned/steel-structural-wide-flange-eaf",
        "citation": {
            "authority": "American Institute of Steel Construction (AISC) Industry-Average EPD for fabricated structural sections",
            "document_section": "AISC Type III EPD — US-mix EAF hot-rolled wide-flange, cradle-to-gate, declared unit 1 tonne",
            "document_url": "https://www.aisc.org/why-steel/sustainability/",
            "regulatory_limit_note": (
                "AISC / Bath ICE v3 US-mix EAF structural sections range is "
                "roughly 0.8–1.2 kgCO2e/kg = 800–1200 kgCO2e/tonne; 1000 "
                "kgCO2e/tonne is the AISC industry-average. Production: "
                "substitute the mill's plant-specific EPD."
            ),
            "accessed_at": "2026-05-20",
        },
    },
]

# Permit thresholds — real Sacramento Metropolitan AQMD Rule 214 values for the
# Sacramento Federal Ozone Nonattainment Area Severe classification under the
# 2008 8-hour ozone NAAQS. NOx + VOC major-source threshold for a Severe area is
# 25 tpy per CAA §182(d) classification table. SMAQMD Rule 214 is the SIP-
# approved federal NSR implementing rule.
#
# CO + PM thresholds are illustrative federal references chosen for the pilot's
# flexibility; a real permit application substitutes the jurisdiction's
# applicable Title V + PSD significance levels.
_PERMIT_THRESHOLDS = {
    "jurisdiction": _THRESHOLDS_JURISDICTION,
    "jurisdiction_name": (
        "Sacramento Federal Ozone Nonattainment Area — Severe-15 classification "
        "under the 2008 8-hour ozone NAAQS (Sacramento Metropolitan AQMD lead "
        "for SIP coordination)"
    ),
    "synthetic_minor_thresholds_tpy": {
        "NOx": 25.0,
        "CO": 100.0,
        "PM": 70.0,
        "NMHC": 25.0,
    },
    "major_source_thresholds_tpy": {
        "NOx": 50.0,
        "CO": 250.0,
        "PM": 100.0,
        "NMHC": 50.0,
    },
    "citation": {
        "authority": (
            "Sacramento Metropolitan AQMD Rule 214 (Federal New Source Review) "
            "+ Clean Air Act §182(d) (NAA severity-tier major-source "
            "thresholds) + §169 (PSD major-source thresholds)"
        ),
        "document_section": (
            "SMAQMD Rule 214 §202 (major-source definition keyed to NAA "
            "classification); CAA §182(d) Severe: 25 tpy NOx/VOC; §169 PSD: "
            "250 tpy attainment / 100 tpy listed-source-category"
        ),
        "document_url": "https://www.airquality.org/Businesses/Permits/Rules-and-Regulations",
        "regulatory_limit_note": (
            "Per CAA §182(d) the Severe-area NOx/VOC major-source threshold "
            "is 25 tpy; Sacramento is currently Severe under the 2008 8-hour "
            "ozone NAAQS and Serious (50 tpy) under the 2015 NAAQS — the "
            "stricter Severe threshold controls. SMAQMD Rule 214 is the "
            "SIP-approved federal NSR implementing rule. CO + PM values in "
            "this fixture are federal-significance illustrative; a real "
            "permit application uses the jurisdiction's applicable Title V "
            "+ PSD significance levels."
        ),
        "accessed_at": "2026-05-20",
    },
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_G_PER_LB = 453.59237
_LB_PER_TON = 2000.0


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(obj) -> bytes:
    return (
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


_REQUIRED_CITATION_KEYS = ("authority", "document_section", "document_url")


def _assert_citation_well_formed(row: dict, row_kind: str, row_id: str) -> None:
    """Each input row must carry a non-empty citation triple. Provenance is
    load-bearing: a row whose citation is missing or empty is rejected at
    build time AND by the re-derivation pack at verify time."""
    c = row.get("citation")
    if not isinstance(c, dict):
        raise AssertionError(f"{row_kind} {row_id!r} missing 'citation' object")
    for k in _REQUIRED_CITATION_KEYS:
        v = c.get(k)
        if not isinstance(v, str) or not v.strip():
            raise AssertionError(f"{row_kind} {row_id!r} citation.{k} missing or empty")


def _source_tpy(source: dict, pollutant: str) -> float:
    """Per-source per-pollutant tpy. Dispatches on source_type."""
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


def _compute_criteria_pollutants(sources: list, thresholds: dict) -> dict:
    out: dict = {}
    for poll in _CRITERIA_POLLUTANTS:
        per_source = []
        for s in sources:
            per_source.append(
                {"source_id": s["source_id"], "tpy": _source_tpy(s, poll)}
            )
        total = round(sum(r["tpy"] for r in per_source), 6)
        synmin = float(thresholds["synthetic_minor_thresholds_tpy"][poll])
        majsrc = float(thresholds["major_source_thresholds_tpy"][poll])
        if total >= majsrc:
            classification = "major_source"
        elif total >= synmin:
            classification = "synthetic_minor_breach"
        else:
            classification = "synthetic_minor"
        out[poll] = {
            "per_source_tpy": per_source,
            "total_tpy": total,
            "synthetic_minor_threshold_tpy": synmin,
            "major_source_threshold_tpy": majsrc,
            "classification": classification,
        }
    return out


def _compute_embodied_carbon(materials: list) -> dict:
    per_material = []
    for m in materials:
        attributed = round(
            float(m["quantity"]) * float(m["emission_factor_kg_co2e_per_unit"]), 6
        )
        per_material.append({"material_id": m["material_id"], "kg_co2e": attributed})
    total = round(sum(r["kg_co2e"] for r in per_material), 6)
    return {"per_material_kg_co2e": per_material, "total_kg_co2e": total}


def _overall_classification(criteria: dict) -> str:
    classes = {p["classification"] for p in criteria.values()}
    if "major_source" in classes:
        return "major_source"
    if "synthetic_minor_breach" in classes:
        return "synthetic_minor_breach"
    return "synthetic_minor"


def _build_fragment_anchors(
    sources: list,
    materials: list,
    sources_cid: str,
    materials_cid: str,
) -> dict:
    anchors: dict = {}
    for s in sources:
        key = f"src-{s['source_id']}"
        anchors[key] = fragment_to_canonical_dict(
            OpaqueFragment(
                source_cid=sources_cid,
                kind_tag="nsr_emission_source_anchor",
                locator={
                    "source_id": s["source_id"],
                    "source_type": s["source_type"],
                    "factor_source": s["factor_source"],
                    "factor_basis": s.get("factor_basis", ""),
                    "citation_authority": s["citation"]["authority"],
                    "citation_url": s["citation"]["document_url"],
                },
            )
        )
    for m in materials:
        key = f"mat-{m['material_id']}"
        anchors[key] = fragment_to_canonical_dict(
            OpaqueFragment(
                source_cid=materials_cid,
                kind_tag="embodied_carbon_material_anchor",
                locator={
                    "material_id": m["material_id"],
                    "epd_source": m["epd_source"],
                    "unit": m["unit"],
                    "citation_authority": m["citation"]["authority"],
                    "citation_url": m["citation"]["document_url"],
                },
            )
        )
    return anchors


# ---------------------------------------------------------------------------
# Re-derivation pack source — written into re_derive/ inside the bundle.
# Kept as a module-level string so _build_bundle.py is self-contained.
# AB4 — duplicate-don't-import (no audit_bundle imports inside this script).
# ---------------------------------------------------------------------------

_RE_DERIVE_PACK_SOURCE: str = '''#!/usr/bin/env python3
"""dc_emissions_mrv_pack.py — stdlib re-derivation pack for data-center NSR.

the audit-bundle contract §C5 (auditor independence) + AB4 (duplicate-don\'t-import):
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
            f"nsr_submission.aggregation_method must be \'sum\'; got "
            f"{submission.get(\'aggregation_method\')!r}"
        )

    bundled_criteria = submission.get("criteria_pollutants")
    if not isinstance(bundled_criteria, dict):
        return _fail("nsr_submission missing \'criteria_pollutants\' object")

    syn_thr = thresholds.get("synthetic_minor_thresholds_tpy", {})
    maj_thr = thresholds.get("major_source_thresholds_tpy", {})

    # ---- Citation-presence assertions (provenance is load-bearing) ----
    _REQUIRED_CITATION_KEYS = ("authority", "document_section", "document_url")

    def _check_citation(row, row_kind, row_id):
        c = row.get("citation")
        if not isinstance(c, dict):
            return f"{row_kind} {row_id!r} missing \'citation\' object"
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
                f"bundled={bundled.get(\'classification\')!r}"
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
                    f"recomputed={rec[\'source_id\']!r} bundled={exp.get(\'source_id\')!r}"
                )
            rec_v = round(float(rec["tpy"]), 6)
            exp_v = round(float(exp.get("tpy", 0.0)), 6)
            if rec_v != exp_v:
                return _fail(
                    f"{poll} per_source_tpy[{i}] tpy mismatch for "
                    f"{rec[\'source_id\']!r}: recomputed={rec_v} bundled={exp_v}"
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
'''


# ---------------------------------------------------------------------------
# Manifest file enumeration (in-place build)
# ---------------------------------------------------------------------------


def _enumerate_pilot_files_for_manifest(pilot_dir: Path) -> dict:
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

    # Sweep __pycache__ (verifier-self-pollution guard)
    for pycache in out_dir.rglob("__pycache__"):
        if pycache.is_dir():
            import shutil as _shutil

            _shutil.rmtree(pycache, ignore_errors=True)

    # --- Write re-derivation pack ---
    pack_path = re_derive_dir / "dc_emissions_mrv_pack.py"
    pack_path.write_bytes(_RE_DERIVE_PACK_SOURCE.encode("utf-8"))

    # --- Citation-presence guard (build-time, mirrors re-derive pack check) ---
    for s in _EMISSION_SOURCES:
        _assert_citation_well_formed(s, "emission_source", s["source_id"])
    for m in _EMBODIED_CARBON_INVENTORY:
        _assert_citation_well_formed(m, "embodied_carbon_material", m["material_id"])
    _assert_citation_well_formed(
        _PERMIT_THRESHOLDS, "permit_thresholds", _PERMIT_THRESHOLDS["jurisdiction"]
    )

    # --- Inputs (sorted by id for determinism) ---
    sorted_sources = sorted(_EMISSION_SOURCES, key=lambda s: s["source_id"])
    sources_bytes = _canonical_json_bytes(sorted_sources)
    (inputs_dir / "emission_sources.json").write_bytes(sources_bytes)
    sources_cid = f"sha256:{_sha256(sources_bytes)}"

    sorted_materials = sorted(
        _EMBODIED_CARBON_INVENTORY, key=lambda m: m["material_id"]
    )
    materials_bytes = _canonical_json_bytes(sorted_materials)
    (inputs_dir / "embodied_carbon_inventory.json").write_bytes(materials_bytes)
    materials_cid = f"sha256:{_sha256(materials_bytes)}"

    thresholds_bytes = _canonical_json_bytes(_PERMIT_THRESHOLDS)
    (inputs_dir / "permit_thresholds.json").write_bytes(thresholds_bytes)

    # --- Compute outputs ---
    criteria = _compute_criteria_pollutants(sorted_sources, _PERMIT_THRESHOLDS)
    embodied = _compute_embodied_carbon(sorted_materials)
    overall = _overall_classification(criteria)

    submission = {
        "facility_id": _FACILITY_ID,
        "submission_type": "pre_construction_nsr_synthetic_minor",
        "aggregation_method": "sum",
        "thresholds_jurisdiction": _THRESHOLDS_JURISDICTION,
        "criteria_pollutants": criteria,
        "embodied_carbon": embodied,
        "overall_classification": overall,
    }
    submission_bytes = _canonical_json_bytes(submission)
    (payload_dir / "nsr_submission.json").write_bytes(submission_bytes)

    # Sanity assertions — fixtures must land inside synthetic-minor envelope.
    assert overall == "synthetic_minor", (
        f"Pilot fixture expected overall=synthetic_minor; got {overall!r}. "
        f"Criteria totals: "
        f"{ {p: criteria[p]['total_tpy'] for p in _CRITERIA_POLLUTANTS} }"
    )
    for poll in _CRITERIA_POLLUTANTS:
        assert criteria[poll]["total_tpy"] > 0, (
            f"{poll} total_tpy must be positive on non-trivial fixtures"
        )

    fragment_anchors = _build_fragment_anchors(
        sorted_sources, sorted_materials, sources_cid, materials_cid
    )
    expected_anchors = len(sorted_sources) + len(sorted_materials)
    assert len(fragment_anchors) == expected_anchors, (
        f"Expected {expected_anchors} anchors; got {len(fragment_anchors)}."
    )

    if out_dir.resolve() == _HERE.resolve():
        files = _enumerate_pilot_files_for_manifest(out_dir)
    else:
        files = {
            "inputs/emission_sources.json": _sha256(sources_bytes),
            "inputs/embodied_carbon_inventory.json": _sha256(materials_bytes),
            "inputs/permit_thresholds.json": _sha256(thresholds_bytes),
            "payload/nsr_submission.json": _sha256(submission_bytes),
            "re_derive/dc_emissions_mrv_pack.py": _sha256(
                _RE_DERIVE_PACK_SOURCE.encode("utf-8")
            ),
        }

    manifest = {
        "schema_version": _SCHEMA_VERSION,
        "bundle_id": _BUNDLE_ID,
        "created_at": _CREATED_AT,
        "files": files,
        "spec_files": {},
        "cross_refs": {},
        "payload": {},
        "typed_checks": _TYPED_CHECKS,
        "fragment_anchors": fragment_anchors,
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"Bundle written to {out_dir}")
    print(f"  emission sources  : {len(sorted_sources)}")
    print(f"  embodied materials: {len(sorted_materials)}")
    for poll in _CRITERIA_POLLUTANTS:
        c = criteria[poll]
        print(
            f"  {poll:>4} total_tpy : {c['total_tpy']:>10.6f} "
            f"(syn-min {c['synthetic_minor_threshold_tpy']:.1f}, "
            f"maj-src {c['major_source_threshold_tpy']:.1f}) -> {c['classification']}"
        )
    print(f"  embodied_total    : {embodied['total_kg_co2e']:.2f} kg CO2e")
    print(f"  overall           : {overall}")
    print(f"  fragment anchors  : {len(fragment_anchors)}")
    print(f"  manifest          : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic dc_emissions_mrv_minimal audit bundle"
    )
    parser.add_argument(
        "--out-dir",
        required=False,
        type=Path,
        default=_HERE,
        help=(
            "Destination directory. Defaults to the pilot's own directory "
            "(in-place build) so cli/verify.py --bundle-dir <pilot-dir> Just Works."
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
