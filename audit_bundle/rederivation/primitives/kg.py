"""kg_recompute — verifier-side KG BFS path-query answer_nodes re-derivation.

Axis-2 value-return form of the kg re-derivation, PROMOTED into the shippable
core registry (RECIPE_BOOK.md, shape `knowledge-graph derivation`). The generic
verifier recomputes the representative output on the SAFE spec-pinned path: no
subprocess, no bundle-supplied code — the recompute rule lives HERE in
verifier-distribution code and the comparator + tolerance come from the
auditor-anchored spec.

Re-derivation primitive (one sentence):
    answer_nodes = BFS reachability closure of (query.start, query.predicate,
    query.max_depth) over the bundled triple set kg/triples.jsonl, excluding
    query.start itself; a node is visited at most once (seen-guard).

The BFS traversal MIRRORS the pilot's kg_recompute.py EXACTLY (which itself
mirrors the legacy kg_re_derivation._bfs_closure). Breadth-first from
query.start, following only triples whose predicate matches query.predicate,
stopping at query.max_depth hops; a node enters `visited` only when first
reached (not start). The auditor's SHA-pinned spec binds the output type
"kg_answer_nodes" to this primitive_id ("kg_recompute") and to the `set`
comparator (no params — order-independent collection equality). A producer
cannot weaken the traversal without changing the primitive_id, which the anchor
rejects.

answer_nodes is the representative value because it is a deterministic, key-free
recompute: re-execute the BFS over the committed triple set from the query
embedded in the committed payload, and return the reachable node-id list. No
producer key is needed (only the committed triples + query params). The `set`
comparator compares it order-independently against the claimed collection.

Faithfulness (the only query classes this primitive re-derives):
  - BFS reachability from a single start node, single predicate, bounded depth.
  - answer_nodes excludes the start node itself (seen-guard initialised with
    start).
  - Deduplication is achieved via the seen-guard (each node visited at most
    once); the returned list may be in any order — the `set` comparator is
    correct (order-independent equality, no params).
  - The comparator is `set` (not `exact`): the producer's answer_nodes list may
    be serialised in any order; two enumerations of the same BFS frontier are
    equal as sets even if their list representations differ.

Stdlib-only (§C5 core verify() path).
"""

from __future__ import annotations

from collections import deque
from pathlib import Path

from ...admission import admit_json_file, admit_jsonl_file
from ...plugin import ParsedInputs, RecomputedValue
from ..registry import register_primitive


# ---------------------------------------------------------------------------
# BFS engine — computes the same reachability SET as the pilot's kg_recompute.py
# (examples/kg_minimal/kg_recompute.py::_bfs_closure / compute_answer_nodes).
# Not byte-identical output ordering: this copy accumulates into a set, the
# producer copy (_build_bundle.py) into an insertion-ordered list — they agree as
# reachability sets, which is exactly what the spec-pinned `set` comparator checks.
# ---------------------------------------------------------------------------


def _bfs_closure(
    start: str,
    predicate: str,
    max_depth: int,
    triple_set: set[tuple[str, str, str]],
) -> set[str]:
    """BFS over triples matching predicate, up to max_depth hops from start.

    Returns the set of node ids reachable (excluding start itself). Mirrors the
    pilot's _bfs_closure exactly: breadth-first, seen-guard initialised with
    start, visit a node only when first reached, stop expanding at max_depth.
    """
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(start, 0)])
    seen: set[str] = {start}
    while queue:
        node, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for s, p, o in triple_set:
            if s == node and p == predicate and o not in seen:
                seen.add(o)
                visited.add(o)
                queue.append((o, depth + 1))
    return visited


def compute_answer_nodes(query: dict, triples: list[dict]) -> list[str]:
    """Canonical answer_nodes recompute. Mirrors the pilot's compute_answer_nodes.

    Returns the reachable node ids as a list (the `set` comparator compares it
    order-independently against the claimed collection).
    """
    triple_set: set[tuple[str, str, str]] = {
        (t["subject"], t["predicate"], t["object"]) for t in triples
    }
    start = query["start"]
    predicate = query["predicate"]
    max_depth = int(query["max_depth"])
    return list(_bfs_closure(start, predicate, max_depth, triple_set))


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered at import for the core registry)
# ---------------------------------------------------------------------------


class KgRecompute:
    """Verifier-side primitive for re-deriving the answer_nodes collection."""

    primitive_id: str = "kg_recompute"

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        """Recompute answer_nodes from the committed triple set + payload query.

        Reads kg/triples.jsonl (the committed triple set) and
        payload/query_result.json (for the query parameters), executes the BFS
        reachability closure, and returns the node-id list as a RecomputedValue.
        Returns the VALUE only — reads no acceptance epsilon and does not
        compare; the auditor-anchored `set` comparator decides agreement against
        outputs/<id>.json.
        """
        bundle_dir: Path = inputs.bundle_dir

        triples_path = bundle_dir / "kg" / "triples.jsonl"
        if not triples_path.is_file():
            raise FileNotFoundError(
                f"kg/triples.jsonl not found in bundle at {bundle_dir}"
            )
        triples = admit_jsonl_file(triples_path)

        qr_path = bundle_dir / "payload" / "query_result.json"
        if not qr_path.is_file():
            raise FileNotFoundError(
                f"payload/query_result.json not found in bundle at {bundle_dir}"
            )
        qr = admit_json_file(qr_path)
        query = qr.get("query")
        if not isinstance(query, dict):
            raise ValueError("payload.query is absent or not a dict")

        value = compute_answer_nodes(query, triples)
        return RecomputedValue(
            value=value,
            detail=(
                f"re-derived answer_nodes via BFS from start={query.get('start')!r} "
                f"predicate={query.get('predicate')!r} "
                f"max_depth={query.get('max_depth')!r} "
                f"-> {sorted(value)!r}"
            ),
        )


register_primitive(KgRecompute())
