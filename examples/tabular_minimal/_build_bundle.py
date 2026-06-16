"""_build_bundle.py — build a deterministic tabular_minimal audit bundle.

Generates a synthetic 50-row sales CSV, runs a GROUP BY + SUM aggregate
query against it, and emits a standards-compliant manifest.

Usage (from v-kernel-audit-bundle root):
    python examples/tabular_minimal/_build_bundle.py --out-dir /tmp/tabular_bundle

Outputs:
  <out-dir>/data/sales.csv          (50-row deterministic synthetic dataset)
  <out-dir>/spec/query.json         (GROUP BY query DSL — not in manifest.files)
  <out-dir>/payload/result.csv      (aggregated result rows)
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
_BUNDLE_ID = "tabular-minimal-rc"
_CREATED_AT = "2026-05-09T00:00:00Z"
_TYPED_CHECKS = [
    "spec_sha_pin",
    "file_integrity_many_small",
    "tabular_re_derivation",
]

# ---------------------------------------------------------------------------
# Synthetic dataset — 50 deterministic rows, no random seed needed
#
# Row i (0..49):
#   region  = ["NA","EU","APAC","LATAM"][i % 4]
#   product = ["A","B","C","D","E"][i % 5]
#   units   = (i * 7) % 50 + 1
#   revenue = units * 100 + (i % 13) * 7
# ---------------------------------------------------------------------------

_REGIONS = ["NA", "EU", "APAC", "LATAM"]
_PRODUCTS = ["A", "B", "C", "D", "E"]


def _generate_rows() -> list[dict]:
    rows = []
    for i in range(50):
        units = (i * 7) % 50 + 1
        revenue = units * 100 + (i % 13) * 7
        rows.append({
            "region": _REGIONS[i % 4],
            "product": _PRODUCTS[i % 5],
            "units": units,
            "revenue": revenue,
        })
    return rows


def _rows_to_csv_bytes(rows: list[dict], columns: list[str]) -> bytes:
    """Serialize rows to CSV bytes with LF line endings, no trailing newline."""
    lines = [",".join(columns)]
    for row in rows:
        lines.append(",".join(str(row[c]) for c in columns))
    return "\n".join(lines).encode("utf-8")


def _aggregate(rows: list[dict], query: dict) -> list[dict]:
    """Execute the GROUP BY + SUM/COUNT aggregate described by query."""
    group_by_cols: list[str] = query["group_by"]
    select_spec: list[dict] = query["select"]
    order_by_cols: list[str] = query["order_by"]

    # Group rows
    groups: dict[tuple, dict] = {}
    for row in rows:
        key = tuple(row[c] for c in group_by_cols)
        if key not in groups:
            groups[key] = {c: row[c] for c in group_by_cols}
            for spec in select_spec:
                if spec["kind"] == "agg":
                    groups[key][spec["alias"]] = 0
        for spec in select_spec:
            if spec["kind"] == "agg":
                if spec["func"] == "sum":
                    groups[key][spec["alias"]] += int(row[spec["column"]])
                elif spec["func"] == "count":
                    groups[key][spec["alias"]] += 1

    result_rows = list(groups.values())

    # Sort by order_by columns alphabetically ascending
    result_rows.sort(key=lambda r: tuple(str(r[c]) for c in order_by_cols))
    return result_rows


def build(out_dir: Path) -> None:
    # ---- Generate sales.csv ----
    rows = _generate_rows()
    sales_bytes = _rows_to_csv_bytes(rows, ["region", "product", "units", "revenue"])

    # ---- Build query.json (spec/, not tracked in manifest.files) ----
    query = {
        "schema": "tabular-query-v1",
        "table": "data/sales.csv",
        "select": [
            {"kind": "column", "name": "region"},
            {"kind": "agg", "func": "sum", "column": "units", "alias": "total_units"},
            {"kind": "agg", "func": "sum", "column": "revenue", "alias": "total_revenue"},
        ],
        "group_by": ["region"],
        "order_by": ["region"],
    }
    query_bytes = json.dumps(query, indent=2).encode("utf-8")

    # ---- Aggregate and build payload/result.csv ----
    result_rows = _aggregate(rows, query)

    # Build output column order: group_by columns first, then agg aliases
    out_columns: list[str] = []
    for spec in query["select"]:
        if spec["kind"] == "column":
            out_columns.append(spec["name"])
        elif spec["kind"] == "agg":
            out_columns.append(spec["alias"])

    result_bytes = _rows_to_csv_bytes(result_rows, out_columns)

    # ---- emit via the reference-emitter SDK ----
    # spec/ tree is owned by spec_files (walked by SpecShaPinCheck), not files
    # (which FileIntegrityManySmall skips for spec/). The two plugins cover
    # disjoint trees by construction.
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "data/sales.csv": sales_bytes,
            "payload/result.csv": result_bytes,
        },
        spec_files={
            "query.json": query_bytes,
        },
        typed_checks=_TYPED_CHECKS,
    )
    manifest = write_bundle(out_dir, content)

    print(f"Bundle written to {out_dir}")
    print(f"  sales rows       : {len(rows)}")
    print(f"  result groups    : {len(result_rows)}")
    print(f"  manifest files   : {len(manifest['files'])}")
    print(f"  manifest         : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic tabular_minimal audit bundle"
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
