#!/usr/bin/env python3
"""kg_re_derivation.py — stdlib re-derivation pack for the kg_minimal domain pilot.

Verifies that a KG path-query result is derivable from the bundled triple set.
the audit-bundle contract §C6 (domain generalization) + AB4 (duplicate-don't-import).

Reads from --bundle-dir:
  kg/triples.jsonl         — the bundled RDF-style triple set
  payload/query_result.json — the path-query output to re-derive

Three invariants checked:
  1. Every path_edge in the result exists in the bundled triple set.
  2. The answer_nodes set equals the BFS closure of (query.start, query.predicate,
     max_depth) over the bundled triples.
  3. The answer_nodes set equals the set of terminal (object) nodes in path_edges
     (consistency check).

Exit 0 on full match; exit 1 on first mismatch with [KG_REDERIVATION_MISMATCH] on stderr.

If kg/triples.jsonl or payload/query_result.json is absent the bundle opted out
of KG re-derivation — exits 0.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import deque
from pathlib import Path


def _load_triples(bundle_dir: Path) -> list[dict] | None:
    triples_path = bundle_dir / "kg" / "triples.jsonl"
    if not triples_path.exists():
        return None
    triples = []
    for line in triples_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            triples.append(json.loads(line))
        except json.JSONDecodeError as exc:
            print(f"[KG_REDERIVATION_MISMATCH] kg/triples.jsonl: JSON parse error: {exc}", file=sys.stderr)
            return None
    return triples


def _load_query_result(bundle_dir: Path) -> dict | None:
    qr_path = bundle_dir / "payload" / "query_result.json"
    if not qr_path.exists():
        return None
    try:
        return json.loads(qr_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"[KG_REDERIVATION_MISMATCH] payload/query_result.json: JSON parse error: {exc}", file=sys.stderr)
        return None


def _triple_key(t: dict) -> tuple[str, str, str]:
    return (t["subject"], t["predicate"], t["object"])


def _bfs_closure(
    start: str,
    predicate: str,
    max_depth: int,
    triple_set: set[tuple[str, str, str]],
) -> set[str]:
    """BFS over triples matching predicate, up to max_depth hops from start.

    Returns the set of nodes reachable (excluding start itself).
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="KG path-query re-derivation check for kg_minimal audit bundles"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    triples = _load_triples(bundle_dir)
    if triples is None and not (bundle_dir / "kg" / "triples.jsonl").exists():
        # Domain opted out — not a failure
        return 0
    if triples is None:
        # Already printed error
        return 1

    qr = _load_query_result(bundle_dir)
    if qr is None and not (bundle_dir / "payload" / "query_result.json").exists():
        return 0
    if qr is None:
        return 1

    # Build triple set for fast membership checks
    triple_set: set[tuple[str, str, str]] = set()
    for i, t in enumerate(triples):
        try:
            triple_set.add(_triple_key(t))
        except (KeyError, TypeError) as exc:
            print(
                f"[KG_REDERIVATION_MISMATCH] kg/triples.jsonl line {i}: malformed triple: {exc}",
                file=sys.stderr,
            )
            return 1

    # Extract query parameters
    try:
        query = qr["query"]
        start: str = query["start"]
        predicate: str = query["predicate"]
        max_depth: int = int(query["max_depth"])
        answer_nodes: list[str] = list(qr["answer_nodes"])
        path_edges: list[dict] = list(qr["path_edges"])
    except (KeyError, TypeError, ValueError) as exc:
        print(
            f"[KG_REDERIVATION_MISMATCH] payload/query_result.json: malformed structure: {exc}",
            file=sys.stderr,
        )
        return 1

    # Invariant 1 — every path_edge must exist in the bundled triple set
    for i, edge in enumerate(path_edges):
        try:
            key = _triple_key(edge)
        except (KeyError, TypeError) as exc:
            print(
                f"[KG_REDERIVATION_MISMATCH] path_edges[{i}]: malformed edge: {exc}",
                file=sys.stderr,
            )
            return 1
        if key not in triple_set:
            print(
                f"[KG_REDERIVATION_MISMATCH] path_edges[{i}]: edge {key!r} not found in bundled triples",
                file=sys.stderr,
            )
            return 1

    # Invariant 2 — answer_nodes equals BFS closure
    bfs_result = _bfs_closure(start, predicate, max_depth, triple_set)
    answer_set = set(answer_nodes)
    if answer_set != bfs_result:
        only_in_answer = sorted(answer_set - bfs_result)
        only_in_bfs = sorted(bfs_result - answer_set)
        print(
            f"[KG_REDERIVATION_MISMATCH] answer_nodes does not match BFS closure\n"
            f"  in answer_nodes but not BFS: {only_in_answer}\n"
            f"  in BFS but not answer_nodes: {only_in_bfs}",
            file=sys.stderr,
        )
        return 1

    # Invariant 3 — answer_nodes equals terminal nodes of path_edges
    terminal_nodes: set[str] = set()
    for edge in path_edges:
        terminal_nodes.add(edge["object"])
    if answer_set != terminal_nodes:
        only_in_answer = sorted(answer_set - terminal_nodes)
        only_in_terminal = sorted(terminal_nodes - answer_set)
        print(
            f"[KG_REDERIVATION_MISMATCH] answer_nodes inconsistent with path_edges terminal nodes\n"
            f"  in answer_nodes but not path_edges terminals: {only_in_answer}\n"
            f"  in path_edges terminals but not answer_nodes: {only_in_terminal}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
