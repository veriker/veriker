"""_build_bundle.py — build a deterministic kg_minimal audit bundle.

Writes a knowledge-graph path-query domain bundle into --out-dir:
  kg/triples.jsonl              (12 deterministic RDF-style triples)
  payload/query_result.json     (path-query result from ex:Alice via ex:knows)
  manifest.json

The claimed answer_nodes in payload/query_result.json is computed PRODUCER-SIDE
by an independent BFS (_producer_bfs) over the committed triples — a deliberately
separate hand-copy of the traversal the verifier carries (it imports neither the
core primitive nor the pilot's compute_answer_nodes). It is NOT a hardcoded
literal; producer↔verifier drift is therefore observable, exactly mirroring how
the tabular template's producer runs its own _aggregate.

Exercises two V-Kernel extension points (commit d1d80a5e):
  OpaqueFragment(source_cid, kind_tag="kg_triple", locator={...})
    — one fragment anchor per path_edge in the query result
  DispatchRecordWellformedCheck(op_kinds_admitted=frozenset({"GRAPH_QUERY", "COMPUTE"}))
    — admits the new "GRAPH_QUERY" op kind defined by this domain pilot

Usage (from v-kernel-audit-bundle root):
    python examples/kg_minimal/_build_bundle.py --out-dir /tmp/kg_bundle

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import deque
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.emitter import BundleContent, write_bundle
from audit_bundle.fragments.fragment_id import (
    OpaqueFragment,
    fragment_to_canonical_dict,
)

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "kg-minimal-rc"
_CREATED_AT = "2026-05-08T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
    "kg_re_derivation",
    "dispatch_record_wellformed",
]

# Deterministic 12-triple org/family knowledge graph
_TRIPLES: list[dict] = [
    {"subject": "ex:Alice", "predicate": "ex:knows", "object": "ex:Bob"},
    {"subject": "ex:Bob", "predicate": "ex:knows", "object": "ex:Carol"},
    {"subject": "ex:Carol", "predicate": "ex:knows", "object": "ex:Dave"},
    {"subject": "ex:Alice", "predicate": "ex:worksAt", "object": "ex:AcmeCo"},
    {"subject": "ex:Bob", "predicate": "ex:worksAt", "object": "ex:BetaCorp"},
    {"subject": "ex:Carol", "predicate": "ex:worksAt", "object": "ex:AcmeCo"},
    {"subject": "ex:Dave", "predicate": "ex:worksAt", "object": "ex:GammaCo"},
    {"subject": "ex:AcmeCo", "predicate": "ex:locatedIn", "object": "ex:CityA"},
    {"subject": "ex:BetaCorp", "predicate": "ex:locatedIn", "object": "ex:CityB"},
    {"subject": "ex:GammaCo", "predicate": "ex:locatedIn", "object": "ex:CityA"},
    {"subject": "ex:Eve", "predicate": "ex:knows", "object": "ex:Alice"},
    {"subject": "ex:Frank", "predicate": "ex:worksAt", "object": "ex:BetaCorp"},
]

# Path-query: reachable from ex:Alice via ex:knows (max_depth=3)
_QUERY: dict = {"start": "ex:Alice", "predicate": "ex:knows", "max_depth": 3}


# ---------------------------------------------------------------------------
# Producer-side BFS — a DELIBERATELY SEPARATE hand-copy of the reachability
# traversal. This is NOT imported from the core primitive
# (audit_bundle.rederivation.primitives.kg) nor from the pilot's kg_recompute
# re-export shim: it is an independent producer implementation so that any drift
# between what the producer claims and what the verifier re-derives is actually
# caught (two hand-copies of BFS is the intended design, exactly like the
# tabular template's producer running its own _aggregate). The bundle's claimed
# answer_nodes is computed HERE from the committed triple set, not hardcoded.
# ---------------------------------------------------------------------------


def _producer_bfs(
    start: str,
    predicate: str,
    max_depth: int,
    triples: list[dict],
) -> list[str]:
    """Producer-side reachability closure over the committed triples.

    Breadth-first from `start`, following only triples whose predicate matches
    `predicate`, stopping at `max_depth` hops; excludes `start` itself (seen-guard
    initialised with start). Returns the reachable node ids as a list. Independent
    copy of the same traversal the verifier primitive carries — if either side
    ever drifts, the spec-pinned dispatch's set comparator catches it.
    """
    triple_set: set[tuple[str, str, str]] = {
        (t["subject"], t["predicate"], t["object"]) for t in triples
    }
    visited: list[str] = []
    queue: deque[tuple[str, int]] = deque([(start, 0)])
    seen: set[str] = {start}
    while queue:
        node, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for s, p, o in triple_set:
            if s == node and p == predicate and o not in seen:
                seen.add(o)
                visited.append(o)
                queue.append((o, depth + 1))
    return visited


def _build_query_result() -> dict:
    """Assemble the path-query result, computing answer_nodes producer-side via
    the independent BFS over the committed triples (NOT a hardcoded literal)."""
    answer_nodes = _producer_bfs(
        _QUERY["start"], _QUERY["predicate"], _QUERY["max_depth"], _TRIPLES
    )
    path_edges = [
        {"subject": "ex:Alice", "predicate": "ex:knows", "object": "ex:Bob"},
        {"subject": "ex:Bob", "predicate": "ex:knows", "object": "ex:Carol"},
        {"subject": "ex:Carol", "predicate": "ex:knows", "object": "ex:Dave"},
    ]
    return {
        "query": dict(_QUERY),
        "answer_nodes": answer_nodes,
        "path_edges": path_edges,
    }


_QUERY_RESULT: dict = _build_query_result()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build(out_dir: Path) -> None:
    # ------------------------------------------------------------------
    # Prepare artifact bytes
    # ------------------------------------------------------------------
    triples_text = "\n".join(json.dumps(t, sort_keys=True) for t in _TRIPLES) + "\n"
    triples_bytes = triples_text.encode("utf-8")

    qr_bytes = (json.dumps(_QUERY_RESULT, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )

    # ------------------------------------------------------------------
    # OpaqueFragment anchors — one per path_edge in the query result
    # Uses the SHA-256 of the bundled triples file as source_cid.
    # ------------------------------------------------------------------
    triples_cid = f"sha256:{_sha256(triples_bytes)}"
    fragment_anchors: dict[str, dict] = {}

    for i, edge in enumerate(_QUERY_RESULT["path_edges"]):
        frag = OpaqueFragment(
            source_cid=triples_cid,
            kind_tag="kg_triple",
            locator={
                "subject": edge["subject"],
                "predicate": edge["predicate"],
                "object": edge["object"],
            },
        )
        anchor_key = f"path-edge-{i:02d}"
        fragment_anchors[anchor_key] = fragment_to_canonical_dict(frag)

    assert len(fragment_anchors) >= 3, (
        f"Expected at least 3 OpaqueFragment anchors; got {len(fragment_anchors)}"
    )

    # ------------------------------------------------------------------
    # dispatch_records — one GRAPH_QUERY record (new op kind)
    # Keep effect={} and no execution_trace to stay on advisory posture
    # (avoids C15 WASM complexity per design spec).
    # ------------------------------------------------------------------
    dispatch_records = [
        {
            "schema_version": "0.1",
            "op": {
                "kind": "GRAPH_QUERY",
                "name": "kg_bfs_path_query",
            },
            "inputs": [],
            "outputs": [],
            "effect": {},
            "locale": "en-US",
            "predicates": [],
            "stamp_declared": "INTERNAL_BENCHMARK",
            "stamp_observed": None,
        }
    ]

    # ------------------------------------------------------------------
    # Emit via the reference-emitter SDK
    # ------------------------------------------------------------------
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "kg/triples.jsonl": triples_bytes,
            "payload/query_result.json": qr_bytes,
        },
        typed_checks=_TYPED_CHECKS,
        extra_manifest_fields={
            "fragment_anchors": fragment_anchors,
            "dispatch_records": dispatch_records,
        },
    )
    write_bundle(out_dir, content)

    print(f"Bundle written to {out_dir}")
    print(f"  kg triples       : {len(_TRIPLES)}")
    print(f"  manifest files   : 2")
    print(
        f"  fragment anchors : {len(fragment_anchors)} OpaqueFragment (kind_tag=kg_triple)"
    )
    print(f"  dispatch records : {len(dispatch_records)} (op.kind=GRAPH_QUERY)")
    print(f"  manifest         : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic kg_minimal audit bundle"
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
