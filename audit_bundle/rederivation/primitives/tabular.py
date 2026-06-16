"""tabular_recompute — verifier-side tabular GROUP BY + SUM/COUNT re-derivation.

Axis-2 value-return form of the tabular re-derivation, PROMOTED into the
shippable core registry (RECIPE_BOOK.md, shape `tabular`). The generic verifier
recompute the representative output on the SAFE spec-pinned path: no subprocess,
no bundle-supplied code — the recompute rule lives HERE in verifier-distribution
code and the comparator + tolerance come from the auditor-anchored spec.

Re-derivation primitive (one sentence):
    result_sha = sha256( serialize( aggregate(data/sales.csv, spec/query.json) ) ).hexdigest()

The representative re-derived output is the SHA-256 hex digest of the result CSV
bytes obtained by re-executing the committed GROUP BY + SUM/COUNT query
(spec/query.json, tabular-query-v1 DSL) over data/sales.csv, serialized with the
SAME column order as the producer's pack — i.e. the query's select-declaration
order (which, for the committed query, lists the group_by column first then the
agg aliases; the order is whatever `select` declares, not an enforced group_by-
first rule) — and LF-only, no-trailing-newline formatting. The aggregation + serialization +
hashing rule is FIXED in this primitive — the primitive_id ("tabular_recompute")
IS the rule. The auditor's SHA-pinned spec binds the output type "result_sha" to
this primitive_id and to an `exact` comparator (byte-exact string equality of the
hex digest); a producer cannot weaken the aggregation, serialization, or
comparison without changing the primitive_id / spec SHA, which the anchor rejects.

result_sha is the representative value because it is a deterministic, key-free
recompute: re-execute the query, serialize byte-identically, hash. No producer
key is needed (only the committed query + input + result bytes).

Faithfulness (the only query classes this primitive re-derives):
  - GROUP BY over string columns; SUM/COUNT aggregates only.
  - SUM is INTEGER summation (int(row[col])); the comparator is `exact`
    (byte-exact hex). There is NO float summation-order divergence: aggregation
    is over integers, so the result is order-independent and exact. A query that
    summed floats would NOT be byte-exact across summation orders and must NOT
    bind to this primitive with an `exact` comparator (use scalar_epsilon or a
    canonicalizing primitive instead). This primitive rejects nothing at runtime
    on that account — it is the SPEC's responsibility to bind only integer/decimal
    SUM/COUNT queries to (tabular_recompute, exact).
  - ORDER BY is alphabetical-ascending str() on the named columns (mirrors the
    producer pack), so the serialized row order is deterministic.

Stdlib-only (§C5 core verify() path).
"""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from ...admission import InputInadmissible, admit_bytes
from ...plugin import ParsedInputs, RecomputedValue
from ..registry import register_primitive


# ---------------------------------------------------------------------------
# Aggregation engine — byte-identical to the producer pack
# (examples/tabular_minimal/_build_bundle._aggregate / _rows_to_csv_bytes)
# ---------------------------------------------------------------------------


def _aggregate(rows: list[dict], query: dict) -> list[dict]:
    """Execute the GROUP BY + SUM/COUNT aggregate described by query.

    Supported select kinds: {kind: column}, {kind: agg, func: "sum"|"count"}.
    SUM is integer summation; ORDER BY is alphabetical ascending (str) on the
    named columns. This mirrors the producer's pack exactly so the honest claimed
    sha and the verifier's recompute share ONE definition and cannot drift.
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
    """Serialize rows to CSV bytes with LF line endings, no trailing newline.

    Byte-identical to the producer pack's _rows_to_csv_bytes.
    """
    lines = [",".join(columns)]
    for row in rows:
        lines.append(",".join(str(row[c]) for c in columns))
    return "\n".join(lines).encode("utf-8")


# ---------------------------------------------------------------------------
# Canonical computation (the verifier's authoritative re-derivation rule)
# ---------------------------------------------------------------------------


def compute_result_sha(query_bytes: bytes, sales_bytes: bytes) -> str:
    """Canonical result-CSV SHA-256 hex digest.

    Re-executes the committed GROUP BY + SUM/COUNT query (query_bytes,
    tabular-query-v1 DSL) over the committed input CSV (sales_bytes), serializes
    the aggregated rows to result CSV bytes with byte-identical column order
    (group_by columns then agg aliases) and LF-only / no-trailing-newline
    formatting as the producer's pack, and returns sha256(result_csv_bytes) as a
    lowercase hex string.
    """
    # Admission-bounded (RES-02): the committed query is bundle-controlled
    # bytes — depth-scan BEFORE parse. InputInadmissible subclasses ValueError,
    # so the dispatch boundary records the breach fail-closed (RECOMPUTE_ERROR)
    # exactly like any other malformed-input raise.
    breach = admit_bytes(query_bytes, check_name="tabular_query_admission")
    if breach is not None:
        raise InputInadmissible(breach)
    query: dict = json.loads(query_bytes.decode("utf-8"))

    reader = csv.DictReader(sales_bytes.decode("utf-8").splitlines())
    input_rows: list[dict] = list(reader)

    derived_rows = _aggregate(input_rows, query)

    out_columns: list[str] = []
    for spec in query.get("select", []):
        if spec["kind"] == "column":
            out_columns.append(spec["name"])
        elif spec["kind"] == "agg":
            out_columns.append(spec["alias"])

    result_bytes = _rows_to_csv_bytes(derived_rows, out_columns)
    return hashlib.sha256(result_bytes).hexdigest()


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered at import for the core registry)
# ---------------------------------------------------------------------------


class TabularRecompute:
    """Verifier-side primitive for re-deriving the result-CSV SHA-256."""

    primitive_id: str = "tabular_recompute"

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        """Recompute the result-CSV SHA-256 hex digest from the committed query +
        input CSV. Returns the recomputed VALUE only — it reads no acceptance
        epsilon and does not compare; the auditor-anchored `exact` comparator
        decides agreement against outputs/<id>.json.
        """
        bundle_dir: Path = inputs.bundle_dir
        query_path = bundle_dir / "spec" / "query.json"
        sales_path = bundle_dir / "data" / "sales.csv"
        if not query_path.is_file():
            raise FileNotFoundError(
                f"spec/query.json not found in bundle at {bundle_dir}"
            )
        if not sales_path.is_file():
            raise FileNotFoundError(
                f"data/sales.csv not found in bundle at {bundle_dir}"
            )
        value = compute_result_sha(query_path.read_bytes(), sales_path.read_bytes())
        return RecomputedValue(
            value=value,
            detail=(
                f"re-derived result.csv sha256 by re-executing query over "
                f"{sales_path.stat().st_size} input byte(s)"
            ),
        )


register_primitive(TabularRecompute())
