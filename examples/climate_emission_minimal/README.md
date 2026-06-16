# climate_emission_minimal — V-Kernel S0 pilot

Domain: **climate / ESG** — Scope-3 supply-chain emission attribution.

Re-derivation primitive (one sentence): for each supplier in
`inputs/supplier_chain.json` (in list order, sorted by tier then `vendor_id`),
compute `attributed_kg_co2e = round(activity_amount * emission_factor_kg_co2e_per_unit, 6)`;
sum to `total_scope3_kg_co2e` (round 6dp); assert per-supplier values + total
match `payload/emission_report.json` exactly.

## Quick start

```bash
cd v-kernel-audit-bundle

# Build the bundle in-place (cli/verify.py canonical mode):
python examples/climate_emission_minimal/_build_bundle.py
python cli/verify.py --bundle-dir examples/climate_emission_minimal/    # PASS

# Or build out-of-tree + use the pilot-local verify.py wrapper:
python examples/climate_emission_minimal/_build_bundle.py --out-dir /tmp/climate_bundle
python examples/climate_emission_minimal/verify.py --bundle-dir /tmp/climate_bundle   # PASS

# Pilot pytest:
python -m pytest tests/test_climate_emission_minimal.py -v
```

## Tamper-flow demo

```bash
# (1) Mutate emission factor in inputs/supplier_chain.json (without realigning
#     manifest SHA) → file_integrity_many_small catches BAD_FILE_SHA.
# (2) Mutate total_scope3_kg_co2e in payload AND re-align manifest SHA →
#     file_integrity passes; re-derivation pack catches CEM_REDER_FAIL.
# See tests/test_climate_emission_minimal.py for both flows.
```

## File layout

| File | Purpose |
|---|---|
| `_build_bundle.py` | Manifest construction; embeds `re_derive/climate_emission_pack.py` source for self-containment. Sweeps `__pycache__` before enumerating files (verifier-self-pollution guard). |
| `verify.py` | Pilot-local verifier shell — registers `FileIntegrityManySmall`, `ReDerivationInvocationCheck(pack_filename="climate_emission_pack.py")`, and `ClimateEmissionReDerivationCheck`. |
| `ClimateEmissionReDerivationCheck.py` | TypedCheck plugin wrapping the subprocess call to the re-derivation pack. |
| `re_derive/climate_emission_pack.py` | Stdlib-only re-derivation pack (AB4 — no audit_bundle imports). |
| `inputs/supplier_chain.json` | (generated) 4-tier synthetic supplier chain (8 suppliers). |
| `payload/emission_report.json` | (generated) Per-supplier attributions + `total_scope3_kg_co2e` + `aggregation_method: "sum"`. |
| `manifest.json` | (generated) Bundle manifest. `OpaqueFragment(kind_tag="supplier_emission_anchor")` per supplier. |

## Fragment kind

`OpaqueFragment(kind_tag="supplier_emission_anchor")` — one anchor per supplier
locating `(vendor_id, factor_source, tier)`. Substrate validates shape only;
semantic validation is owned by `ClimateEmissionReDerivationCheck`.

## Synthetic-data caveat

Emission factors are plausible but **invented** (`synthetic-EF-v1.0/*`) — not
lifted from a real EF database (DEFRA, EPA, ecoinvent). Production integrators
replace the synthetic supplier chain with real procurement data + a certified
EF source; the bundle shape and verification protocol stay identical.

## Production integration

Real integrators swap `_SUPPLIER_CHAIN` in `_build_bundle.py` for live procurement
data, and the synthetic-EF tags for the integrator's certified EF database
references (DEFRA / EPA / ecoinvent / GHG Protocol). The deterministic
multiply-and-sum primitive does not change.

## Patent context

Demonstrates the V-Kernel S0 integrator on climate / ESG numeric-aggregation. One
row in the N-domain demonstration table of
`the internal design notes` (orchestrator updates
the portfolio after merge).
