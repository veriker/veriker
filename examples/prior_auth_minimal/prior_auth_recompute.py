"""prior_auth_recompute.py — re-export shim for the PROMOTED prior_auth primitive.

The prior_auth re-derivation primitive (the first-match-with-default decision-list
shape) has been promoted into the shippable core registry:
audit_bundle/rederivation/primitives/prior_auth.py (RECIPE_BOOK.md, shape
`deterministic rule/predicate evaluation → ordered categorical decision list`,
control-structure sub-family first-match rule → verdict + default). The recompute
rule now lives in verifier-DISTRIBUTION code and the generic verifier carries it — a
third party running the generic verifier against a prior_auth bundle recomputes on
the SAFE spec-pinned path with no demo-local code.

This module is kept as a thin re-export so the existing per-dir call sites
(spec_pinned_check.py) import the SAME `compute_decisions` and `PriorAuthRecompute`
the core registry uses. Sharing ONE definition is the point: the honest producer
claim path and the verifier's re-derivation cannot drift, and registering
`PriorAuthRecompute()` here is idempotent with the core auto-registration (identical
class object).

Importing this module now requires audit_bundle on sys.path (the core package).
Every real call site already puts the package root on sys.path; nothing imports this
module standalone (_build_bundle.py carries its OWN producer-side rule-traversal copy
and does not import from here — the producer↔verifier disjointness guard depends on
that).
"""

from __future__ import annotations

from audit_bundle.rederivation.primitives.prior_auth import (  # noqa: F401
    PriorAuthRecompute,
    _derive_decision,
    _evaluate_rule,
    compute_decisions,
)

__all__ = [
    "PriorAuthRecompute",
    "compute_decisions",
    "_derive_decision",
    "_evaluate_rule",
]
