"""_build_bundle.py — build a deterministic raster_minimal audit bundle.

Generates a synthetic 32×32 int8 raster, evaluates a non-trivial polygon
(L-shaped pentagon, 6 vertices) via ray-casting, and emits a zonal aggregate
payload with a standards-compliant manifest.

Usage (from v-kernel-audit-bundle root):
    python examples/raster_minimal/_build_bundle.py --out-dir /tmp/raster_bundle

Outputs:
  <out-dir>/raster/grid.bin          (1024 bytes, 32×32 int8 little-endian)
  <out-dir>/spec/zonal_query.json    (polygon + aggregator spec)
  <out-dir>/payload/zonal_result.json (aggregate result)
  <out-dir>/manifest.json

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.emitter import BundleContent, write_bundle  # noqa: E402

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "raster-minimal-rc"
_CREATED_AT = "2026-05-09T00:00:00Z"
_TYPED_CHECKS = [
    "spec_sha_pin",
    "file_integrity_many_small",
    "raster_re_derivation",
]

# ---------------------------------------------------------------------------
# Raster generator — deterministic 32×32 int8 grid
#
# value = ((row * 31 + col * 17) % 200) - 100
# Range: [-100, 99] — valid signed int8
# ---------------------------------------------------------------------------

_ROWS = 32
_COLS = 32


def _generate_raster() -> list[list[int]]:
    """Return a 32×32 list-of-lists of signed ints in [-100, 99]."""
    return [
        [((row * 31 + col * 17) % 200) - 100 for col in range(_COLS)]
        for row in range(_ROWS)
    ]


def _raster_to_bytes(grid: list[list[int]]) -> bytes:
    """Pack int8 grid row-major to 1024 bytes, little-endian per cell."""
    data = bytearray()
    for row in grid:
        for val in row:
            data += val.to_bytes(1, "little", signed=True)
    return bytes(data)


# ---------------------------------------------------------------------------
# Polygon — L-shaped hexagon (6 vertices, pixel-corner coords in [0..32])
#
# Shape (pixel-corner coords):
#   (4,4) → (20,4) → (20,12) → (12,12) → (12,28) → (4,28) → back to (4,4)
#
# This is a proper L-shape: a tall-left rectangle (col 4-12, row 4-28)
# plus a right arm (col 12-20, row 4-12).  Uses exactly 6 vertices,
# is non-convex (concave at (20,12)→(12,12)→(12,28)), and exercises the
# ray-casting path with horizontal-edge edge cases.
#
# Polygon vertices are (x=col, y=row) pixel-corner coordinates.
# A cell center at (c + 0.5, r + 0.5) is tested against this polygon.
# ---------------------------------------------------------------------------

_POLYGON: list[list[int]] = [
    [4, 4],
    [20, 4],
    [20, 12],
    [12, 12],
    [12, 28],
    [4, 28],
]


# ---------------------------------------------------------------------------
# Ray-casting point-in-polygon
# ---------------------------------------------------------------------------


def _point_in_polygon(px2: int, py2: int, polygon: list[list[int]]) -> bool:
    """Standard horizontal-ray cast test.  Returns True iff the point is inside.

    Integer, division-free reformulation (verbatim with the verifier primitive
    audit_bundle/rederivation/primitives/raster._point_in_polygon, kept in sync):
    the test point (px2, py2) and the polygon vertices are in DOUBLED coordinates
    (scaled by 2), so a 0.5 cell-center offset becomes the integer 1. The float
    test  px < (xj - xi) * (py - yi) / (yj - yi) + xi  is rewritten as the integer
    cross-multiplication  (px - xi) * (yj - yi) < (xj - xi) * (py - yi),  with the
    inequality flipped when (yj - yi) is negative — no IEEE-754 division.

    A point exactly on a horizontal edge is treated as outside per the
    standard half-open-interval convention (ray goes right, crossings counted
    only when edge strictly crosses the ray's y-level).
    """
    n = len(polygon)
    inside = False
    j = n - 1
    for i in range(n):
        xi, yi = polygon[i][0] * 2, polygon[i][1] * 2
        xj, yj = polygon[j][0] * 2, polygon[j][1] * 2
        # Edge (j→i) crosses the horizontal ray from the point going right iff:
        # 1. The edge crosses y=py2 (one endpoint strictly above, one ≤)
        # 2. The crossing x is > px2
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
) -> tuple[int, int]:
    """Return (in_polygon_cell_count, sum) for cells whose center is inside polygon."""
    count = 0
    total = 0
    for r in range(_ROWS):
        for c in range(_COLS):
            # Doubled cell-center coords: (c + 0.5)*2 = 2c + 1, (r + 0.5)*2 = 2r + 1.
            cx2 = 2 * c + 1
            cy2 = 2 * r + 1
            if _point_in_polygon(cx2, cy2, polygon):
                count += 1
                total += grid[r][c]
    return count, total


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def build(out_dir: Path) -> None:
    grid = _generate_raster()
    raster_bytes = _raster_to_bytes(grid)

    # --- Build spec/zonal_query.json bytes ---
    spec = {
        "raster": {
            "shape": [_ROWS, _COLS],
            "dtype": "int8",
            "byte_order": "little",
        },
        "polygon": _POLYGON,
        "aggregator": "sum",
    }
    spec_bytes = json.dumps(spec, indent=2).encode("utf-8")

    # --- Compute zonal aggregate ---
    in_polygon_count, zonal_sum = _zonal_aggregate(grid, _POLYGON)

    # --- Build payload/zonal_result.json bytes ---
    result_payload = {
        "polygon_id": "p1",
        "in_polygon_cell_count": in_polygon_count,
        "sum": zonal_sum,
    }
    result_bytes = json.dumps(result_payload, indent=2).encode("utf-8")

    # --- Emit via the reference-emitter SDK (scaffold + digests + manifest) ---
    # spec/ tree is owned by spec_files (walked by SpecShaPinCheck), not files
    # (which FileIntegrityManySmall skips for spec/). The two plugins cover
    # disjoint trees by construction.
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "raster/grid.bin": raster_bytes,
            "payload/zonal_result.json": result_bytes,
        },
        spec_files={
            "zonal_query.json": spec_bytes,
        },
        typed_checks=_TYPED_CHECKS,
    )
    manifest = write_bundle(out_dir, content)

    print(f"Bundle written to {out_dir}")
    print(f"  raster shape      : {_ROWS}×{_COLS} int8")
    print(f"  polygon vertices  : {len(_POLYGON)}")
    print(f"  in-polygon cells  : {in_polygon_count}")
    print(f"  zonal sum         : {zonal_sum}")
    print(f"  manifest files    : {len(manifest['files'])}")
    print(f"  manifest          : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic raster_minimal audit bundle"
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        type=Path,
        help="Destination directory (created if absent)",
    )
    args = parser.parse_args()
    try:
        build(args.out_dir.resolve())
    except AssertionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
