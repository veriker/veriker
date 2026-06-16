"""bom_recompute.py — re-export shim for the PROMOTED bom primitive.

The BOM re-derivation primitive has been promoted into the shippable core
registry: audit_bundle/rederivation/primitives/bom.py (RECIPE_BOOK.md, shape
`bill-of-materials rollup`). The recompute rule now lives in verifier-DISTRIBUTION
code and the generic verifier carries it — a third party running the generic
verifier against a bom bundle recomputes on the SAFE spec-pinned path with no
demo-local code.

This module is kept as a thin re-export so the existing per-dir call sites
(spec_pinned_check.py) import the SAME `compute_resolved_tree`, `compute_resolution_order`,
and `BomRecompute` the core registry uses. Sharing ONE definition is the point:
the honest producer claim and the verifier's re-derivation cannot drift, and
registering `BomRecompute()` here is idempotent with the core auto-registration
(identical class object).

Importing this module now requires audit_bundle on sys.path (the core package).
Every real call site already puts the package root on sys.path; nothing imports
this module standalone (_build_bundle.py carries its own producer-side BFS copy
and does not import from here).
"""

from __future__ import annotations

from audit_bundle.rederivation.primitives.bom import (  # noqa: F401
    BomRecompute,
    compute_resolution_order,
    compute_resolved_tree,
)

__all__ = [
    "BomRecompute",
    "compute_resolved_tree",
    "compute_resolution_order",
]
