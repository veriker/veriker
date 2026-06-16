"""auto_ubi_recompute.py — re-export shim for the PROMOTED primitive.

The auto_ubi re-derivation primitive (the per-entity feature-aggregation →
rate-table tier-classify shape, Tier-3 family D) has been promoted into the
shippable core registry: audit_bundle/rederivation/primitives/auto_ubi.py
(RECIPE_BOOK.md). The recompute rule now lives in verifier-DISTRIBUTION code and the
generic verifier carries it — a third party running the generic verifier against an
auto_ubi bundle recomputes on the SAFE spec-pinned path with no demo-local code.

This module is kept as a thin re-export so the existing per-dir call sites
(spec_pinned_check.py) import the SAME `compute_tier_list` and `AutoUbiRecompute`
the core registry uses. Sharing ONE definition is the point: the verifier's
re-derivation cannot drift across the per-dir and the core path, and registering
`AutoUbiRecompute()` here is idempotent with the core auto-registration (identical
class object).

Importing this module now requires audit_bundle on sys.path (the core package). Every
real call site already puts the package root on sys.path; nothing imports this module
standalone (_build_bundle.py carries its OWN producer-side aggregation/classification
copy and does not import from here — the producer↔verifier disjointness guard depends
on that).
"""

from __future__ import annotations

from audit_bundle.rederivation.primitives.auto_ubi import (  # noqa: F401
    AutoUbiRecompute,
    _aggregate_features,
    _classify_tier,
    _load_rate_table,
    _load_trips,
    compute_tier_list,
)

__all__ = [
    "AutoUbiRecompute",
    "compute_tier_list",
    "_aggregate_features",
    "_classify_tier",
    "_load_trips",
    "_load_rate_table",
]
