"""fintech_audit_recompute.py — re-export shim for the PROMOTED fintech_audit primitive.

The fintech_audit re-derivation primitive (the all-pairs policy-verdict shape) has
been promoted into the shippable core registry:
audit_bundle/rederivation/primitives/fintech_audit.py (RECIPE_BOOK.md, shape
`deterministic rule/predicate evaluation → ordered categorical decision list`,
control-structure sub-family all-pairs predicate → verdict-or-NOT_APPLICABLE). The
recompute rule now lives in verifier-DISTRIBUTION code and the generic verifier
carries it — a third party running the generic verifier against a fintech_audit
bundle recomputes on the SAFE spec-pinned path with no demo-local code.

This module is kept as a thin re-export so the existing per-dir call sites
(spec_pinned_check.py) import the SAME `compute_policy_verdicts`, `_load_ordered`,
and `FintechAuditRecompute` the core registry uses. Sharing ONE definition is the
point: the honest producer claim path and the verifier's re-derivation cannot drift,
and registering `FintechAuditRecompute()` here is idempotent with the core
auto-registration (identical class object).

Importing this module now requires audit_bundle on sys.path (the core package).
Every real call site already puts the package root on sys.path; nothing imports
this module standalone (_build_bundle.py carries its OWN producer-side evaluation
copy and does not import from here — the producer↔verifier disjointness guard
depends on that).
"""

from __future__ import annotations

from audit_bundle.rederivation.primitives.fintech_audit import (  # noqa: F401
    FintechAuditRecompute,
    _eval_condition,
    _eval_policy,
    _load_ordered,
    compute_policy_verdicts,
)

__all__ = [
    "FintechAuditRecompute",
    "compute_policy_verdicts",
    "_eval_condition",
    "_eval_policy",
    "_load_ordered",
]
