"""fp_ml_recompute.py — re-export shim for the PROMOTED primitive.

The fp_ml re-derivation primitive has been promoted into the shippable core
registry: audit_bundle/rederivation/primitives/fp_ml.py (RECIPE_BOOK.md, shape
`floating-point ML`). The float32 aggregation rule now lives in
verifier-DISTRIBUTION code and the generic verifier carries it — a third party
running the generic verifier against an fp_ml bundle recomputes on the SAFE
spec-pinned path with no demo-local code.

This module is kept as a thin re-export so the existing per-dir call sites
(spec_pinned_check.py, tests/test_fp_ml_spec_pinned.py) import the SAME
`compute_rep_logit` / `_f32` / class object that the core registry uses. Sharing
ONE definition is the point: the honest producer claim and the verifier's
re-derivation cannot drift, and registering `FpMlRecompute()` from a call site is
idempotent with the core auto-registration (same class object — register_primitive
raises only on same-id/DIFFERENT-class).

Importing this module now requires audit_bundle on sys.path (the core package).
Every real call site already puts the package root on sys.path.
"""

from __future__ import annotations

from audit_bundle.rederivation.primitives.fp_ml import (  # noqa: F401
    FpMlRecompute,
    _f32,
    compute_rep_logit,
)

__all__ = [
    "FpMlRecompute",
    "_f32",
    "compute_rep_logit",
]
