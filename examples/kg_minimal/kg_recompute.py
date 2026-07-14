"""kg_recompute.py — re-export shim for the PROMOTED kg primitive.

The kg re-derivation primitive has been promoted into the shippable core
registry: audit_bundle/rederivation/primitives/kg.py (RECIPE_BOOK.md, shape
`knowledge-graph derivation`). The recompute rule now lives in verifier-
DISTRIBUTION code and the generic verifier carries it — a third party running
the generic verifier against a kg bundle recomputes on the SAFE spec-pinned path
with no demo-local code.

This module is kept as a thin re-export so the existing per-dir call sites
(spec_pinned_check.py, tests/test_kg_spec_pinned.py) import the SAME
`compute_answer_nodes` and `KgRecompute` the core registry uses. Sharing ONE
definition is the point: the honest producer claim and the verifier's
re-derivation cannot drift, and registering `KgRecompute()` in
spec_pinned_check.py is idempotent with the core auto-registration (identical
class object, same `primitive_id` — registry deduplication allows same-class
re-registration without error).

Importing this module now requires audit_bundle on sys.path (the core package).
Every real call site already puts the package root on sys.path; nothing imports
this module standalone. In particular _build_bundle.py does NOT import
compute_answer_nodes from here — the producer computes answer_nodes with its own
independent BFS copy (_producer_bfs in _build_bundle.py), so the producer claim
and the verifier re-derivation are genuinely separate implementations and any
drift between them is caught by the spec-pinned dispatch.
"""

from __future__ import annotations

from audit_bundle.rederivation.primitives.kg import (  # noqa: F401
    KgRecompute,
    _bfs_closure,
    compute_answer_nodes,
)

__all__ = [
    "KgRecompute",
    "compute_answer_nodes",
    "_bfs_closure",
]
