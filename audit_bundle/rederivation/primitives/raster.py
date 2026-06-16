"""raster_recompute — verifier-side geospatial zonal-count re-derivation primitive.

Axis-2 value-return form of the zonal-count re-derivation, PROMOTED into the
shippable core registry (RECIPE_BOOK.md, shape `geospatial zonal count
(point-in-polygon)`). The generic verifier recomputes the representative output
on the SAFE spec-pinned path: no subprocess, no bundle-supplied code — the
recompute rule lives HERE in verifier-distribution code and the comparator comes
from the auditor-anchored spec.

Re-derivation primitive (one sentence):
    in_polygon_cell_count = number of grid cells whose center (c+0.5, r+0.5) is
    inside the polygon, decided by a standard horizontal ray-casting crossing
    count, driven by the committed polygon vertices and grid dimensions in
    spec/zonal_query.json.

NOTE ON INPUTS: the recomputed value is a function of the committed POLYGON
vertices and the grid DIMENSIONS (rows/cols) only — both read from
spec/zonal_query.json. It is NOT a function of the contents of raster/grid.bin:
no pixel value is read or indexed when computing the count. grid.bin is read only
to confirm its byte length matches rows×cols (a shape check); its byte contents do
not affect the count. This is a geospatial zonal CELL-COUNT, not an image/raster
read.

The grid-dimension read, the ray-casting point-in-polygon test, and the
in-polygon counting rule are FIXED in this primitive — the primitive_id
("raster_recompute") IS the rule. The auditor's SHA-pinned spec binds the output
type "raster_in_polygon_cell_count" to this primitive_id and to an `exact`
comparator (no params; a deterministic integer compared for equality); a producer
cannot weaken the rule without changing the primitive_id / spec SHA, which the
anchor rejects.

Faithfulness (Gate B):
  - The representative output is the in_polygon_cell_count integer — a plain
    Python int. There is NO serialized-bytes representation and therefore NO
    serialization format risk: the `exact` comparator compares the integer value
    directly.  No column ordering, no line endings, no header bytes.
  - The ray-casting test is computed in pure INTEGER arithmetic: coordinates are
    scaled by 2 (so the half-cell-center offset 0.5 → integer 1) and the edge-
    crossing x comparison is an integer cross-multiplication with NO division.
    The inside/outside boolean (and thus the count) is therefore exactly
    platform-stable — safe under the `exact` comparator. No IEEE-754 float
    division is involved.
  - The half-open-interval convention matches the producer copy: crossings
    counted only when the edge strictly crosses the ray's y-level
    ((yi > py) != (yj > py)).
  - Cell center is (c + 0.5, r + 0.5) for col c, row r — matches the producer.
  - The count is a pure integer summation (no float accumulation) — order-
    independent and exact → `exact` comparator is correct.

Verified on the committed raster_minimal exemplar. The producer
(examples/raster_minimal/_build_bundle.py) holds a verbatim copy of this
ray-casting + counting logic, kept in sync — not independently authored.

Stdlib-only (§C5 core verify() path).
"""

from __future__ import annotations

from pathlib import Path

from ...admission import admit_json_file
from ...plugin import ParsedInputs, RecomputedValue
from ..registry import register_primitive


# ---------------------------------------------------------------------------
# Raster reading — verbatim copy of the producer's _read_raster, kept in sync
#
# Read only to confirm the committed grid.bin is rows×cols bytes (a shape check).
# The grid CONTENTS do not affect the in-polygon cell count.
# ---------------------------------------------------------------------------


def _read_raster(grid_path: Path, rows: int, cols: int) -> list[list[int]]:
    """Unpack raw bytes to rows×cols list-of-lists of signed ints.

    int.from_bytes(b, "little", signed=True) per cell — no struct module.
    Verbatim copy of the producer's _read_raster, kept in sync. Used only to
    confirm grid.bin has the rows×cols byte length declared in the spec; the
    grid contents are NOT consumed by the cell count.
    """
    data = grid_path.read_bytes()
    expected = rows * cols
    if len(data) != expected:
        raise ValueError(
            f"grid.bin has {len(data)} bytes; expected {expected} ({rows}×{cols})"
        )
    grid: list[list[int]] = []
    offset = 0
    for _ in range(rows):
        row: list[int] = []
        for _ in range(cols):
            val = int.from_bytes(data[offset : offset + 1], "little", signed=True)
            row.append(val)
            offset += 1
        grid.append(row)
    return grid


# ---------------------------------------------------------------------------
# Ray-casting point-in-polygon — INTEGER cross-multiplication (no division)
# ---------------------------------------------------------------------------


def _point_in_polygon(px2: int, py2: int, polygon: list[list[int]]) -> bool:
    """Standard horizontal-ray cast test. Returns True iff the point is inside.

    Integer, division-free reformulation: the test point (px2, py2) and the
    polygon vertices are all expressed in DOUBLED coordinates (scaled by 2), so a
    cell-center half-offset of 0.5 becomes the integer 1 and every value is an
    int. The float crossing test
        px < (xj - xi) * (py - yi) / (yj - yi) + xi
    is rewritten by multiplying through by (yj - yi):
        (px - xi) * (yj - yi)  <  (xj - xi) * (py - yi)
    and the inequality is flipped when (yj - yi) is negative. This avoids IEEE-754
    float division, so the inside/outside boolean (and the integer count) is
    exactly platform-stable — required by the `exact` comparator.

    Half-open-interval convention: crossings counted only when the edge strictly
    crosses the ray's y-level ((yi > py) != (yj > py)). Verbatim with the
    producer's copy in examples/raster_minimal/_build_bundle.py.
    """
    n = len(polygon)
    inside = False
    j = n - 1
    for i in range(n):
        # Doubled (×2) integer vertex coordinates.
        xi, yi = polygon[i][0] * 2, polygon[i][1] * 2
        xj, yj = polygon[j][0] * 2, polygon[j][1] * 2
        if (yi > py2) != (yj > py2):
            dy = yj - yi
            lhs = (px2 - xi) * dy
            rhs = (xj - xi) * (py2 - yi)
            # px < x_intersect  ->  lhs < rhs when dy > 0, lhs > rhs when dy < 0.
            crosses = lhs < rhs if dy > 0 else lhs > rhs
            if crosses:
                inside = not inside
        j = i
    return inside


# ---------------------------------------------------------------------------
# Canonical computation (the verifier's authoritative re-derivation rule)
# ---------------------------------------------------------------------------


def compute_in_polygon_cell_count(
    grid: list[list[int]], polygon: list[list[int]]
) -> int:
    """Canonical in-polygon cell count re-derivation.

    For every cell of the grid, tests its center (c+0.5, r+0.5) against the
    polygon via integer ray-casting and counts the in-polygon cells. The count
    depends on the polygon vertices and the grid DIMENSIONS only; grid contents
    are not consulted.

    Cell centers are passed in DOUBLED integer coordinates (2c+1, 2r+1) so the
    point-in-polygon test stays division-free. Verbatim with the producer copy.
    Fail-closed: raises on a polygon with fewer than 3 vertices (the verifier
    must not invent a count).
    """
    if len(polygon) < 3:
        raise ValueError(f"polygon must have ≥3 vertices; got {len(polygon)}")
    rows = len(grid)
    cols = len(grid[0]) if rows else 0
    count = 0
    for r in range(rows):
        for c in range(cols):
            # Doubled cell-center coords: (c + 0.5)*2 = 2c + 1, (r + 0.5)*2 = 2r + 1.
            cx2 = 2 * c + 1
            cy2 = 2 * r + 1
            if _point_in_polygon(cx2, cy2, polygon):
                count += 1
    return count


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered at import for the core registry)
# ---------------------------------------------------------------------------


class RasterRecompute:
    """Verifier-side primitive for re-deriving the in_polygon_cell_count integer.

    The count is recomputed from the committed polygon vertices and grid
    dimensions in spec/zonal_query.json. grid.bin contents do not affect it.
    """

    primitive_id: str = "raster_recompute"

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        """Recompute in_polygon_cell_count from the committed polygon + grid dims.

        Reads the polygon vertices and grid dimensions (rows/cols) from
        spec/zonal_query.json, runs the integer ray-casting point-in-polygon test
        for each cell center, and returns the count. raster/grid.bin is read only
        to confirm its byte length matches rows×cols; its contents do not affect
        the count.

        Returns the recomputed VALUE only — it reads no acceptance epsilon and
        does not compare; the auditor-anchored `exact` comparator decides
        agreement against outputs/<id>.json.
        """
        bundle_dir: Path = inputs.bundle_dir
        grid_path = bundle_dir / "raster" / "grid.bin"
        spec_path = bundle_dir / "spec" / "zonal_query.json"
        if not grid_path.is_file():
            raise FileNotFoundError(
                f"raster/grid.bin not found in bundle at {bundle_dir}"
            )
        if not spec_path.is_file():
            raise FileNotFoundError(
                f"spec/zonal_query.json not found in bundle at {bundle_dir}"
            )

        spec = admit_json_file(spec_path)
        if not isinstance(spec, dict):
            raise ValueError("spec/zonal_query.json: top-level must be an object")
        raster_meta = spec.get("raster", {})
        shape = raster_meta.get("shape", [32, 32])
        rows, cols = int(shape[0]), int(shape[1])
        polygon: list[list[int]] = spec.get("polygon", [])

        grid = _read_raster(grid_path, rows, cols)
        value = compute_in_polygon_cell_count(grid, polygon)
        return RecomputedValue(
            value=value,
            detail=(
                f"re-derived in_polygon_cell_count={value} via ray-casting over "
                f"{rows}×{cols} int8 grid and {len(polygon)}-vertex polygon"
            ),
        )


register_primitive(RasterRecompute())
