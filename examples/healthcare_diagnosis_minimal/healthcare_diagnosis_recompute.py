"""healthcare_diagnosis_recompute.py — re-export shim for the PROMOTED primitive.

The healthcare_diagnosis re-derivation primitive (the fire-and-collect ICD-10
code-list shape) has been promoted into the shippable core registry:
audit_bundle/rederivation/primitives/healthcare_diagnosis.py (RECIPE_BOOK.md,
shape `deterministic rule/predicate evaluation → ordered categorical decision list`,
control-structure sub-family C. fire-and-collect). The recompute rule now lives in
verifier-DISTRIBUTION code and the generic verifier carries it — a third party
running the generic verifier against a healthcare_diagnosis bundle recomputes on the
SAFE spec-pinned path with no demo-local code.

This module is kept as a thin re-export so the existing per-dir call sites
(spec_pinned_check.py) import the SAME `compute_icd10_codes` and
`HealthcareDiagnosisRecompute` the core registry uses. Sharing ONE definition is the
point: the verifier's re-derivation cannot drift across the per-dir and the core
path, and registering `HealthcareDiagnosisRecompute()` here is idempotent with the
core auto-registration (identical class object).

Importing this module now requires audit_bundle on sys.path (the core package). Every
real call site already puts the package root on sys.path; nothing imports this module
standalone (_build_bundle.py carries its OWN producer-side rule-traversal copy and
does not import from here — the producer↔verifier disjointness guard depends on that).
"""

from __future__ import annotations

from audit_bundle.rederivation.primitives.healthcare_diagnosis import (  # noqa: F401
    HealthcareDiagnosisRecompute,
    _eval_condition,
    _load_rules,
    _load_symptoms,
    compute_icd10_codes,
)

__all__ = [
    "HealthcareDiagnosisRecompute",
    "compute_icd10_codes",
    "_eval_condition",
    "_load_rules",
    "_load_symptoms",
]
