"""audit_bundle.rederivation.primitives — verifier-side recompute primitives.

Importing this package self-registers every bundled ReDerivationPrimitive into
the registry (audit_bundle.rederivation.registry). These are verifier-
DISTRIBUTION code, never bundle-supplied (§C5/§C6, V8 [0010]).

Promoted recompute primitives (RECIPE_BOOK.md tracker; comparator in parens):
  - spectra_span_recompute     -> text_normalized  (examples/spectra_minimal)
  - climate_emission_recompute -> exact            (examples/climate_emission_minimal)
  - fea_vonmises_recompute     -> scalar_epsilon   (the FEA pilot)
  - tabular_recompute          -> exact            (examples/tabular_minimal)
  - bom_recompute              -> exact            (examples/bom_minimal)
  - kg_recompute               -> set              (examples/kg_minimal)
  - ml_recompute               -> exact            (examples/ml_minimal)
  - build_recompute            -> exact            (examples/build_minimal)
  - dp_recompute               -> scalar_epsilon   (examples/dp_minimal; differential privacy)
  - streaming_recompute        -> exact            (examples/streaming_minimal)
  - scrabble_recompute         -> exact            (examples/scrabble_minimal; lexical-membership adjudication)
  - raster_recompute           -> exact            (examples/raster_minimal; geospatial zonal count, point-in-polygon)
  - build_real_compiler_recompute -> exact         (examples/build_real_compiler_minimal; recompile mod_a.py -> .pyc sha256)
  - audio_recompute            -> set              (examples/audio_minimal; frame-energy VAD boundary pairs)
  - fp_ml_recompute            -> scalar_epsilon   (examples/fp_ml_minimal; float32 linear-classifier logit)
  - event_log_replay_recompute -> exact            (GENERIC; absorbs hipaa/mica/mifid2/pci_dss/sec_17a4/ai_act_art12/the HR-logging pilot — replay CREATE/AMEND log -> record digest)
  - fintech_audit_recompute     -> exact            (examples/fintech_audit_minimal; all-pairs policy-verdict decision list — Tier-3 decision-list cluster, all-pairs sub-family)
  - prior_auth_recompute        -> exact            (examples/prior_auth_minimal; first-match-with-default decision list — Tier-3 decision-list cluster, first-match sub-family)
  - anticheat_adjudication_recompute -> exact       (examples/anticheat_adjudication_minimal; first-match-with-default, 2nd first-match member — distinct condition vocab from prior_auth, see RECIPE_BOOK N=2 boundary)
  - healthcare_diagnosis_recompute -> exact          (examples/healthcare_diagnosis_minimal; fire-and-collect ICD-10 code list — Tier-3 decision-list cluster, family C; collects icd10_code of every firing rule, confidence floats out of scope)
  - auto_ubi_recompute          -> exact            (examples/auto_ubi_minimal; per-entity feature-aggregation -> rate-table tier classify — Tier-3 family D, AGGREGATION shape not decision-list; categorical tier only, float features + adjustment_pct out of scope)

The remaining corpus primitives are phased over the provisional window per the
RECIPE_BOOK.md promotion tracker (audit_bundle/rederivation/RECIPE_BOOK.md) —
deliberate phasing by computation shape, not a silent cap.

Note: gaci_composite registers two primitives (gaci_composite_recompute and
gaci_hype_substance_gap_recompute), so the registry count exceeds the module
count by one.
"""

from __future__ import annotations

from . import (  # noqa: F401
    anticheat_adjudication,
    audio,
    auto_ubi,
    bom,
    build,
    build_real_compiler,
    climate_emission,
    dp,
    event_log_replay,
    fea_vonmises,
    fintech_audit,
    fp_ml,
    healthcare_diagnosis,
    kg,
    ml,
    prior_auth,
    raster,
    scrabble,
    spectra_span,
    streaming,
    tabular,
)
