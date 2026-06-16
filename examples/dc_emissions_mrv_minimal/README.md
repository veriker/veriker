# dc_emissions_mrv_minimal — V-Kernel S0 pilot

Domain: **data-center pre-construction NSR (New Source Review) air-permit
submission + embodied-carbon LCA**.

Re-derivation primitive (one sentence): for each emission source in
`inputs/emission_sources.json` (sorted by `source_id`), recompute annual
`tpy` per criteria pollutant via the source-type-specific deterministic
formula (diesel-genset:
`count * rated_power_hp * annual_runtime_hr * EF_g_per_hp_hr / (453.59237 * 2000)`;
turbine: `count * rated_power_mw * annual_runtime_hr * EF_lb_per_mwh / 2000`);
sum per-pollutant; recompute embodied-carbon per material via
`quantity * EF`; recompute per-pollutant NSR classification from
`inputs/permit_thresholds.json`; assert every per-source tpy, per-pollutant
total, per-pollutant classification, embodied-carbon total, and overall
facility classification exactly match `payload/nsr_submission.json`.

## NOT a new shape

This pilot is a **domain exemplar** in the numeric-aggregation shape family
already demonstrated by `climate_emission_minimal`,
`agritech_sensor_minimal`, and a sensor `score_pack.py`. Same primitive
(deterministic multiply-and-sum over committed numeric inputs);
new domain (NSR + LCA) with source-type-dispatched per-row formula
and threshold-based classification. The README / portfolio entry must
NOT claim this opens a new shape.

## Why this matters

Data-center NSR pre-construction air permits (Clean Air Act §165 PSD /
§182 NAA, NSPS Subparts IIII + KKKK) are now the dominant gate that
blocks construction starts. Concrete public signals in 2026:

- **EPA proposed "Begin Actual Construction" rule** (May 13 2026 Federal
  Register) — EPA itself is reworking the NSR pre-construction-permit
  boundary because the current rule is bottlenecking data-center +
  power-plant projects.
- **Project Jupiter (Doña Ana County, NM)** — 7,000+ public comments on
  the air-quality permit; state extended its decision deadline from
  Apr 22 → Jul 21 2026 to hold a hearing.
- **Embodied-carbon disputes** (iMasons Climate Accord pre-construction
  LCA best practices, Schneider Electric Scope-3 quantification papers)
  — the auditor's challenge to EFs and EPD vintages is the same shape
  as the NSR EF challenge.

The recurring failure mode the bundle defends against: a state air-quality
agency or third-party MRV verifier challenges an emission factor, a runtime
assumption, or an equipment count, and the developer cannot defensibly
chain back from "NOx total = 23.83 tpy < 25 tpy synthetic-minor threshold"
through every spreadsheet cell to the source artifact that justifies each
input. The bundle is that chain: SHA-pinned inputs + a 30-second offline
re-derivation.

Real-world regulatory anchors (cited only — pilot fixtures are synthetic):

- **40 CFR Part 60 Subpart IIII** — NSPS for stationary compression-ignition
  internal-combustion engines (diesel backup gensets).
- **40 CFR Part 60 Subpart KKKK** — NSPS for stationary combustion turbines.
- **EPA AP-42 §3.4** — large stationary diesel emission factors.
- **40 CFR §52.21 (PSD)** — major-source classification under attainment;
  **CAA §182** — NAA classification with tightening thresholds.

## Quick start

```bash
cd v-kernel-audit-bundle

# In-place build (cli/verify.py canonical mode):
python examples/dc_emissions_mrv_minimal/_build_bundle.py
python cli/verify.py --bundle-dir examples/dc_emissions_mrv_minimal/    # PASS

# Out-of-tree build + pilot-local verify wrapper:
python examples/dc_emissions_mrv_minimal/_build_bundle.py --out-dir /tmp/dcmrv_bundle
python examples/dc_emissions_mrv_minimal/verify.py --bundle-dir /tmp/dcmrv_bundle   # PASS

# Pilot pytest:
python -m pytest tests/test_dc_emissions_mrv_minimal.py -v
```

## Tamper-flow demo

```bash
# (1) Mutate an EF in inputs/emission_sources.json without realigning the
#     manifest SHA → file_integrity_many_small catches BAD_FILE_SHA.
# (2) Inflate criteria_pollutants.NOx.total_tpy in payload AND realign
#     manifest SHA → file_integrity passes; re-derivation pack catches
#     DCMRV_REDER_FAIL on the NOx total mismatch (and on the classification
#     flip if the new value crosses the 25 tpy SMAQMD Rule 214 Severe-NAA
#     synthetic-minor threshold).
# (3) Blank a citation_url in inputs/emission_sources.json AND realign
#     manifest SHA → file_integrity passes; re-derivation pack catches
#     CITATION_MISSING (provenance is load-bearing — a permit submission
#     with an EF that cannot be traced back to its regulatory authority is
#     rejected by design).
# See tests/test_dc_emissions_mrv_minimal.py for all three flows.
```

## File layout

| File | Purpose |
|---|---|
| `_build_bundle.py` | Manifest construction; embeds `re_derive/dc_emissions_mrv_pack.py` source for self-containment. Sweeps `__pycache__` before enumerating files. |
| `verify.py` | Pilot-local verifier shell — registers `FileIntegrityManySmall`, `ReDerivationInvocationCheck(pack_filename="dc_emissions_mrv_pack.py")`, and `DCEmissionsMRVReDerivationCheck`. |
| `DCEmissionsMRVReDerivationCheck.py` | TypedCheck plugin wrapping the subprocess call. |
| `re_derive/dc_emissions_mrv_pack.py` | Stdlib-only re-derivation pack (AB4 — no audit_bundle imports). |
| `inputs/emission_sources.json` | (generated) 120 Tier-4-Final diesel gensets + 1 lean-premix turbine; per-row `citation` block pointing at 40 CFR Subpart IIII / Subpart KKKK §60.4320. |
| `inputs/embodied_carbon_inventory.json` | (generated) 5 material lines (concrete / rebar / structural steel / aluminium racks / glazing); per-row `citation` block pointing at Bath ICE v3 / EC3 / CRSI / AISC industry-average EPDs. |
| `inputs/permit_thresholds.json` | (generated) Sacramento Metro AQMD Rule 214 Severe-NAA 2008-NAAQS thresholds (25 tpy NOx/VOC) + illustrative federal CO/PM significance levels; `citation` block pointing at SMAQMD Rule 214 + CAA §182(d) + §169. |
| `payload/nsr_submission.json` | (generated) Per-source per-pollutant tpy + totals + classifications + embodied-carbon total + overall classification. |
| `manifest.json` | (generated) Bundle manifest. `OpaqueFragment(kind_tag="nsr_emission_source_anchor")` per source + `OpaqueFragment(kind_tag="embodied_carbon_material_anchor")` per material. |

## Fragment kinds

Two `OpaqueFragment` kind_tags:

- `nsr_emission_source_anchor` — one anchor per emission source; locator
  carries `(source_id, source_type, factor_source, factor_basis,
  citation_authority, citation_url)`.
- `embodied_carbon_material_anchor` — one anchor per LCA material; locator
  carries `(material_id, epd_source, unit, citation_authority, citation_url)`.

Substrate validates shape only; semantic validation (does the EF map to the
cited NSPS subpart? does the EPD vintage match the declared material?) is
owned by `DCEmissionsMRVReDerivationCheck`. Citation-presence is enforced by
the re-derivation pack as a hard fail (`CITATION_MISSING`).

## Cited regulatory anchors

Each input row in the pilot carries a `citation` object with `authority`,
`document_section`, `document_url`, and `regulatory_limit_note` — and the
re-derivation pack fails (`CITATION_MISSING`) on any row whose triple is
absent or empty. The five regulatory authorities cited:

| Input row | Authority | Document URL |
|---|---|---|
| Diesel-genset EFs (GEN-001) | 40 CFR Part 60 Subpart IIII (NSPS) by reference to 40 CFR Part 1039 Tier 4 Final standards | https://www.ecfr.gov/current/title-40/chapter-I/subchapter-C/part-60/subpart-IIII |
| Turbine EFs (TRB-001) | 40 CFR Part 60 Subpart KKKK §60.4320 + Table 1 | https://www.ecfr.gov/current/title-40/chapter-I/subchapter-C/part-60/subpart-KKKK/subject-group-ECFR19767a6b7b4579c/section-60.4320 |
| Permit thresholds | SMAQMD Rule 214 (Federal NSR) + CAA §182(d) (NAA major-source thresholds) + §169 (PSD) | https://www.airquality.org/Businesses/Permits/Rules-and-Regulations |
| Aluminium / glass / concrete EPDs | Bath Inventory of Carbon and Energy (ICE) v3 + Building Transparency EC3 | https://circularecology.com/embodied-carbon-footprint-database.html  + https://buildingtransparency.org/ec3 |
| Steel EPDs | CRSI Industry-Average EPD (rebar) + AISC Industry-Average EPD (structural) | https://www.crsi.org/sustainability/  + https://www.aisc.org/why-steel/sustainability/ |

## What's real vs synthetic

**Real (cited; sources accessed 2026-05-20):**

- Every regulatory citation (CFR section, AQMD rule number, CAA section,
  NSPS subpart, AP-42 section, EPD database identity) is real with a public URL.
- The specific numeric ceilings quoted in `regulatory_limit_note` fields —
  Tier-4-Final 0.40 g/kWh NMHC+NOx combined / 0.03 g/kWh PM for >560 kW
  engines (40 CFR 1039.101 Table 1); Subpart KKKK Table 1 42 ppm NOx @ 15%
  O2 = 2.3 lb/MWh for new natural-gas turbines ≤ 50 MMBtu/h heat input;
  SMAQMD Rule 214 / CAA §182(d) 25 tpy NOx/VOC for Severe ozone NAAs
  (Sacramento is Severe-15 under the 2008 8-hour ozone NAAQS); ICE v3 mean
  8.24 kgCO2e/kg for primary aluminium extrusion.

**Synthetic (engine/turbine/material-specific values):**

- The diesel EFs *used in the calculation* (NOx 0.24, NMHC 0.05, PM 0.0224,
  CO 0.70 g/hp-hr) are synthetic engine-OEM-test-cert-shaped values
  consistent with the cited Tier-4-Final ceilings — production swaps these
  for the manufacturer-issued certification report on the specific engine.
- The turbine EF for NOx (0.493 lb/MWh) represents a realistic 9 ppm @ 15%
  O2 lean-premix-with-SCR performance well under the 42 ppm regulatory
  ceiling — production swaps for OEM stack-test data on the specific
  turbine model.
- Embodied-carbon EFs are synthetic mean-range values consistent with public
  ICE v3 / EC3 / CRSI / AISC database ranges (see `citation` blocks per
  material).
- Equipment counts, runtimes, and quantities are synthetic for a generic
  100 MW hyperscaler facility.

This split is the hardening discipline: every value in the calculation has
a public regulatory anchor visible to the auditor, and the gap between
"cited ceiling" and "value used in calc" is named, not hidden.

## Production integration

A real permit consultant forks this pilot and swaps three things:

- `inputs/emission_sources.json` — per-source rows now carry OEM-certification
  EFs (from the manufacturer's engine certification or turbine stack-test
  report). The `citation` block points at the OEM test-cert document; the
  `factor_basis` field shifts from `engine_oem_test_certificate_synthetic_
  placeholder` to `engine_oem_test_certificate_real`.
- `inputs/embodied_carbon_inventory.json` — per-material rows now point at
  supplier-specific Type III EPDs (via EC3 or One Click LCA exports).
- `inputs/permit_thresholds.json` — siting jurisdiction's
  applicable AQMD rule numbers (the Severe-NAA 25 tpy default already
  matches Sacramento Metro). A facility in a different NAA classification
  pulls the corresponding §182 threshold (Marginal/Moderate 100 tpy;
  Serious 50 tpy; Severe 25 tpy; Extreme 10 tpy).

Neither the deterministic per-source-type tpy formula nor the
synthetic-minor / major classification logic changes. The bundle's
verifier code is unchanged across all hyperscaler siting packages.

## Patent context

Adds one row to the S0 demonstration table in
`the internal design notes` as a
**numeric-aggregation domain exemplar** — NOT a new shape. Strengthens
the data-center / construction-emissions / pre-construction-MRV domain
demonstration alongside `climate_emission_minimal`.
