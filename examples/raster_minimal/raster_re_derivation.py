#!/usr/bin/env python3
"""raster_re_derivation.py — LEGACY gated §C6 in-bundle re-derivation pack.

THIS IS NOT THE PROMOTED RECIPE'S SOURCE OF TRUTH. This file is the legacy
§C6 in-bundle subprocess pack: it is invoked by RasterReDerivationCheck.py via
`subprocess.run([... this file ...])`. NOTE — this pilot's own
examples/raster_minimal/verify.py registers RasterReDerivationCheck, whose check()
runs this pack via subprocess UNCONDITIONALLY (no permit_execution gate, no
--unsafe flag); so on the pilot's legacy verify path this pack IS executed, not
inert. It is the genuine SAFE path — the generic spec-pinned dispatch
(BundleVerifier + the core registry) — that recomputes the shape in-process via
primitives/raster.py and runs no bundle-supplied code. This pack is a DELIBERATE
separate copy retained as the legacy demo verification path pending deprecation.

The single source of truth for the promoted recipe is the verifier primitive
audit_bundle/rederivation/primitives/raster.py (plus its re-export shim). The
integer, division-free ray-casting reformulation here is kept VERBATIM with that
primitive so this legacy copy cannot silently drift from the promoted rule.

Re-derives the zonal aggregate by:
  1. Reading raster/grid.bin — raw 1024-byte int8 little-endian grid.
  2. Reading spec/zonal_query.json — polygon vertices + aggregator.
  3. Running a ray-casting point-in-polygon test for each cell center.
  4. Summing in-polygon cell values and counting in-polygon cells.
  5. Comparing against payload/zonal_result.json.

the audit-bundle contract §C6 (re-derivation pack — domain-agnostic substrate).
AB4: stdlib only, no imports from audit_bundle.

Uses int.from_bytes(b, "little", signed=True) per cell — no struct module.

Exits 0 on match; 1 on mismatch with [RASTER_REDER_FAIL] on stderr.

Usage:
    python raster_re_derivation.py --bundle-dir /path/to/bundle
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Raster reading
# ---------------------------------------------------------------------------


def _read_raster(grid_path: Path, rows: int, cols: int) -> list[list[int]]:
    """Unpack raw bytes to rows×cols list-of-lists of signed ints."""
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
# Ray-casting point-in-polygon (identical logic to _build_bundle.py)
# ---------------------------------------------------------------------------


def _point_in_polygon(px2: int, py2: int, polygon: list[list[int]]) -> bool:
    """Standard horizontal-ray cast test.  Returns True iff the point is inside.

    Integer, division-free reformulation kept VERBATIM with the verifier
    primitive audit_bundle/rederivation/primitives/raster._point_in_polygon:
    coordinates are DOUBLED (×2) so a 0.5 cell-center offset becomes the integer
    1, and the float crossing test is replaced by the integer cross-multiplication
    (px - xi) * (yj - yi) < (xj - xi) * (py - yi), flipped when (yj - yi) < 0 —
    no IEEE-754 division.
    """
    n = len(polygon)
    inside = False
    j = n - 1
    for i in range(n):
        xi, yi = polygon[i][0] * 2, polygon[i][1] * 2
        xj, yj = polygon[j][0] * 2, polygon[j][1] * 2
        if (yi > py2) != (yj > py2):
            dy = yj - yi
            lhs = (px2 - xi) * dy
            rhs = (xj - xi) * (py2 - yi)
            crosses = lhs < rhs if dy > 0 else lhs > rhs
            if crosses:
                inside = not inside
        j = i
    return inside


# ---------------------------------------------------------------------------
# Zonal aggregation
# ---------------------------------------------------------------------------


def _zonal_aggregate(
    grid: list[list[int]],
    polygon: list[list[int]],
    rows: int,
    cols: int,
) -> tuple[int, int]:
    """Return (in_polygon_cell_count, sum) for cells whose center is inside polygon."""
    count = 0
    total = 0
    for r in range(rows):
        for c in range(cols):
            # Doubled cell-center coords: (c + 0.5)*2 = 2c + 1, (r + 0.5)*2 = 2r + 1.
            cx2 = 2 * c + 1
            cy2 = 2 * r + 1
            if _point_in_polygon(cx2, cy2, polygon):
                count += 1
                total += grid[r][c]
    return count, total


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _verify(bundle_dir: Path) -> str | None:
    """Return an error description on mismatch, or None on success."""
    grid_path = bundle_dir / "raster" / "grid.bin"
    spec_path = bundle_dir / "spec" / "zonal_query.json"
    result_path = bundle_dir / "payload" / "zonal_result.json"

    # Check required files exist
    for p in (grid_path, spec_path, result_path):
        if not p.exists():
            return f"{p.relative_to(bundle_dir)} absent from bundle_dir {bundle_dir}"

    # Load spec
    try:
        spec: dict = json.loads(spec_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return f"failed to read spec/zonal_query.json: {exc}"

    # Load expected result
    try:
        expected_result: dict = json.loads(result_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return f"failed to read payload/zonal_result.json: {exc}"

    # Parse spec
    raster_meta = spec.get("raster", {})
    shape = raster_meta.get("shape", [32, 32])
    rows, cols = int(shape[0]), int(shape[1])
    polygon: list[list[int]] = spec.get("polygon", [])

    if len(polygon) < 3:
        return f"polygon must have ≥3 vertices; got {len(polygon)}"

    # Read raster
    try:
        grid = _read_raster(grid_path, rows, cols)
    except (ValueError, OSError) as exc:
        return f"failed to read raster/grid.bin: {exc}"

    # Re-derive aggregate
    derived_count, derived_sum = _zonal_aggregate(grid, polygon, rows, cols)

    # Compare
    expected_count = expected_result.get("in_polygon_cell_count")
    expected_sum = expected_result.get("sum")

    if derived_count != expected_count:
        return (
            f"in_polygon_cell_count mismatch: "
            f"re-derived={derived_count}, bundled={expected_count}"
        )

    if derived_sum != expected_sum:
        return f"sum mismatch: re-derived={derived_sum}, bundled={expected_sum}"

    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Raster zonal re-derivation check for geospatial audit bundles"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    error = _verify(bundle_dir)
    if error is None:
        return 0

    print(f"[RASTER_REDER_FAIL] {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
