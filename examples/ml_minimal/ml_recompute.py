"""ml_recompute.py — re-export shim for the PROMOTED ml primitive.

The ML inference re-derivation primitive has been promoted into the shippable
core registry: audit_bundle/rederivation/primitives/ml.py (RECIPE_BOOK.md,
shape `ML metric`). The recompute rule now lives in verifier-DISTRIBUTION code
and the generic verifier carries it — a third party running the generic verifier
against an ml_minimal bundle recompute on the SAFE spec-pinned path with no
demo-local code.

This module is kept as a thin re-export so existing per-dir call sites
(spec_pinned_check.py) import the SAME `compute_prediction_classes` and
`MlRecompute` the core registry uses. Sharing ONE definition is the point: the
honest producer claim and the verifier's re-derivation cannot drift, and
registering `MlRecompute()` here is idempotent with the core auto-registration
(identical class object).

Importing this module now requires audit_bundle on sys.path (the core package).
Every real call site already puts the package root on sys.path; nothing imports
this module standalone (_build_bundle.py carries its own producer-side
computation copy and does not import from here).
"""

from __future__ import annotations

from audit_bundle.rederivation.primitives.ml import (  # noqa: F401
    MlRecompute,
    _argmax,
    _compute_logits,
    compute_prediction_classes,
)

__all__ = [
    "MlRecompute",
    "compute_prediction_classes",
    "_compute_logits",
    "_argmax",
]
