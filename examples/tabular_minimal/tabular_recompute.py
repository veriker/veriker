"""tabular_recompute.py — re-export shim for the PROMOTED tabular primitive.

The tabular re-derivation primitive has been promoted into the shippable core
registry: audit_bundle/rederivation/primitives/tabular.py (RECIPE_BOOK.md, shape
`tabular`). The recompute rule now lives in verifier-DISTRIBUTION code and the
generic verifier carries it — a third party running the generic verifier against
a tabular bundle recompute on the SAFE spec-pinned path with no demo-local code.

This module is kept as a thin re-export so the existing per-dir call sites
(spec_pinned_check.py, tests/test_tabular_spec_pinned.py) import the SAME
`compute_result_sha` and `TabularRecompute` the core registry uses. Sharing ONE
definition is the point: the honest producer claim and the verifier's
re-derivation cannot drift, and registering `TabularRecompute()` here is
idempotent with the core auto-registration (identical class object).

Importing this module now requires audit_bundle on sys.path (the core package).
Every real call site already puts the package root on sys.path; nothing imports
this module standalone (_build_bundle.py carries its own producer-side
aggregation copy and does not import from here).
"""

from __future__ import annotations

from audit_bundle.rederivation.primitives.tabular import (  # noqa: F401
    TabularRecompute,
    _aggregate,
    _rows_to_csv_bytes,
    compute_result_sha,
)

__all__ = [
    "TabularRecompute",
    "compute_result_sha",
    "_aggregate",
    "_rows_to_csv_bytes",
]
