#!/usr/bin/env python3
"""tabular_re_derivation.py — stdlib re-derivation pack for tabular SQL aggregate domain.

Re-executes the declared GROUP BY + SUM/COUNT aggregate query against the committed
CSV snapshot and asserts the produced result CSV is byte-identical to the bundled result.

the audit-bundle contract §C6 (re-derivation pack — domain-agnostic substrate).
AB4: stdlib only — csv, json, pathlib. No imports from audit_bundle.

Reads:
  spec/query.json        — GROUP BY query DSL (tabular-query-v1 schema)
  data/sales.csv         — committed input snapshot
  payload/result.csv     — bundled aggregate result to verify against

Exits 0 on byte-identical match; 1 with [TABULAR_REDER_FAIL] <description> on stderr
on any mismatch.

Usage:
    python tabular_re_derivation.py --bundle-dir /path/to/bundle
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Aggregation engine
# ---------------------------------------------------------------------------


def _aggregate(rows: list[dict], query: dict) -> list[dict]:
    """Execute the GROUP BY aggregate described by query.

    Supported select kinds: {kind: column}, {kind: agg, func: "sum"|"count"}.
    Order-by is alphabetical ascending on the named columns.
    """
    group_by_cols: list[str] = query["group_by"]
    select_spec: list[dict] = query["select"]
    order_by_cols: list[str] = query["order_by"]

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
    result_rows.sort(key=lambda r: tuple(str(r[c]) for c in order_by_cols))
    return result_rows


def _rows_to_csv_bytes(rows: list[dict], columns: list[str]) -> bytes:
    """Serialize rows to CSV bytes with LF line endings, no trailing newline."""
    lines = [",".join(columns)]
    for row in rows:
        lines.append(",".join(str(row[c]) for c in columns))
    return "\n".join(lines).encode("utf-8")


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _verify(bundle_dir: Path) -> str | None:
    """Return an error description on mismatch, or None on success."""
    query_path = bundle_dir / "spec" / "query.json"
    sales_path = bundle_dir / "data" / "sales.csv"
    result_path = bundle_dir / "payload" / "result.csv"

    if not query_path.exists():
        return f"spec/query.json absent from bundle_dir {bundle_dir}"
    if not sales_path.exists():
        return f"data/sales.csv absent from bundle_dir {bundle_dir}"
    if not result_path.exists():
        return f"payload/result.csv absent from bundle_dir {bundle_dir}"

    # 1. Load and validate query
    try:
        query: dict = json.loads(query_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return f"failed to read spec/query.json: {exc}"

    schema = query.get("schema")
    if schema != "tabular-query-v1":
        return f"query schema mismatch: expected 'tabular-query-v1', got {schema!r}"

    # 2. Read input CSV
    try:
        raw_text = sales_path.read_bytes().decode("utf-8")
    except OSError as exc:
        return f"failed to read data/sales.csv: {exc}"

    try:
        reader = csv.DictReader(raw_text.splitlines())
        input_rows: list[dict] = list(reader)
    except Exception as exc:
        return f"failed to parse data/sales.csv: {exc}"

    # 3. Re-execute aggregation
    try:
        derived_rows = _aggregate(input_rows, query)
    except (KeyError, ValueError) as exc:
        return f"aggregation failed: {exc}"

    # 4. Determine output column order from select spec
    out_columns: list[str] = []
    for spec in query.get("select", []):
        if spec["kind"] == "column":
            out_columns.append(spec["name"])
        elif spec["kind"] == "agg":
            out_columns.append(spec["alias"])

    # 5. Serialize to CSV bytes (LF-only, no trailing newline)
    derived_bytes = _rows_to_csv_bytes(derived_rows, out_columns)

    # 6. Load bundled result bytes
    try:
        bundled_bytes = result_path.read_bytes()
    except OSError as exc:
        return f"failed to read payload/result.csv: {exc}"

    # 7. Byte-identical comparison
    if derived_bytes != bundled_bytes:
        derived_str = derived_bytes.decode("utf-8", errors="replace")
        bundled_str = bundled_bytes.decode("utf-8", errors="replace")
        return (
            f"result.csv mismatch\n"
            f"  derived :\n{derived_str}\n"
            f"  bundled :\n{bundled_str}"
        )

    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Tabular re-derivation check for GROUP BY aggregate audit bundles"
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

    print(f"[TABULAR_REDER_FAIL] {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
