"""streaming_recompute.py — re-export shim for the PROMOTED streaming primitive.

The streaming re-derivation primitive has been promoted into the shippable core
registry: audit_bundle/rederivation/primitives/streaming.py (RECIPE_BOOK.md,
shape `streaming aggregation`). The recompute rule now lives in verifier-
DISTRIBUTION code and the generic verifier carries it — a third party running
the generic verifier against a streaming bundle recomputes on the SAFE spec-pinned
path with no demo-local code.

This module is kept as a thin re-export so the existing per-dir call sites
(spec_pinned_check.py, tests/test_streaming_spec_pinned.py) import the SAME
`compute_window_aggregates`, `_parse_stream`, and `StreamingRecompute` the core
registry uses. Sharing ONE definition is the point: the honest producer claim and
the verifier's re-derivation cannot drift, and registering `StreamingRecompute()`
in spec_pinned_check.py is idempotent with the core auto-registration (identical
class object).

Importing this module now requires audit_bundle on sys.path (the core package).
Every real call site already puts the package root on sys.path; nothing imports
this module standalone (_build_bundle.py carries its own producer-side aggregation
copy and does not import from here).
"""

from __future__ import annotations

from audit_bundle.rederivation.primitives.streaming import (  # noqa: F401
    StreamingRecompute,
    _apply_aggregator,
    _parse_stream,
    compute_window_aggregates,
)

__all__ = [
    "StreamingRecompute",
    "compute_window_aggregates",
    "_apply_aggregator",
    "_parse_stream",
]
