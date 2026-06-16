"""raster_recompute.py — re-export shim for the PROMOTED raster primitive.

The raster re-derivation primitive has been promoted into the shippable core
registry: audit_bundle/rederivation/primitives/raster.py (RECIPE_BOOK.md, shape
`geospatial zonal count (point-in-polygon)`). The recompute rule now lives in
verifier-DISTRIBUTION code and
the generic verifier carries it — a third party running the generic verifier
against a raster bundle recomputes on the SAFE spec-pinned path with no
demo-local code.

This module is kept as a thin re-export so the existing per-dir call sites
(spec_pinned_check.py, tests/test_raster_spec_pinned.py) import the SAME
`compute_in_polygon_cell_count`, `_read_raster`, and `RasterRecompute` the core
registry uses. Sharing ONE definition is the point: the honest producer claim and
the verifier's re-derivation cannot drift, and registering `RasterRecompute()`
here is idempotent with the core auto-registration (identical class object).

Importing this module now requires audit_bundle on sys.path (the core package).
Every real call site already puts the package root on sys.path; the producer
builder (_build_bundle.py) carries its own producer-side raster + polygon logic
and does not import from here.
"""

from __future__ import annotations

from audit_bundle.rederivation.primitives.raster import (  # noqa: F401
    RasterRecompute,
    _point_in_polygon,
    _read_raster,
    compute_in_polygon_cell_count,
)

__all__ = [
    "RasterRecompute",
    "compute_in_polygon_cell_count",
    "_read_raster",
    "_point_in_polygon",
]
