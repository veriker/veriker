"""bom_recompute — verifier-side BOM resolved-tree re-derivation primitive.

Axis-2 value-return form of the BOM re-derivation, PROMOTED into the
shippable core registry (RECIPE_BOOK.md, shape `bill-of-materials rollup`).
The generic verifier recomputes the representative output on the SAFE
spec-pinned path: no subprocess, no bundle-supplied code — the recompute
rule lives HERE in verifier-distribution code and the comparator + tolerance
come from the auditor-anchored spec.

Re-derivation primitive (one sentence):
    resolved_tree = BFS walk of the committed lockfile DAG from root that
    produces the full per-package tree (id, hash, depth, deps per node in
    resolution order) and the deterministic resolution_order list; returned
    as a canonical dict {root, nodes, resolution_order}.

over the committed lockfile (lockfile/lockfile.json: root + packages{id->{deps,hash}})
in the bundle. The BFS resolution rule (ascending depth, alphabetical tie-break,
fail-closed reads) is FIXED in this primitive — the primitive_id ("bom_recompute")
IS the rule. The auditor's SHA-pinned spec binds the output type
"bom_resolved_tree" to this primitive_id and to an `exact` comparator
(deep structural equality of the resolved-tree dict — root string, ordered
nodes list, and resolution_order list); a producer cannot weaken the
resolution without changing the primitive_id / spec SHA, which the anchor
rejects.

Faithfulness (the only input classes this primitive re-derives):
  - BFS resolution of a JSON lockfile DAG: {root: str, packages: {id: {deps: [str], hash: str}}}.
  - Tie-breaking is alphabetical ascending (str) within each BFS depth level, so
    the resolution order and node ordering are deterministic and platform-independent.
  - The representative value is a dict {root: str, nodes: list[dict], resolution_order: list[str]};
    each node dict carries {id, hash, depth, deps} in resolution order. The comparator
    is `exact` (Python == on parsed-JSON objects). There are NO floats and NO
    summation-order divergence — all fields are ordered string/int/list values,
    so the comparison is unambiguous regardless of platform.
  - A producer cannot alter any field in the resolved tree without changing the
    primitive_id; this primitive rejects nothing at runtime beyond a malformed lockfile.

Stdlib-only (§C5 core verify() path).
"""

from __future__ import annotations

from collections import deque
from pathlib import Path

from ...admission import admit_json_file
from ...plugin import ParsedInputs, RecomputedValue
from ..registry import register_primitive


# ---------------------------------------------------------------------------
# Canonical computation — faithful verifier-side reimplementation of the
# producer's _build_bundle._bfs_resolve + resolved_tree construction
# (examples/bom_minimal/_build_bundle.py).  The verifier re-derives the same
# structure from the committed lockfile; agreement proves the producer's emitted
# artifact matches the canonical derivation. NOTE: this is a faithful
# reimplementation maintained alongside the producer, not a separate codebase —
# it catches producer<->verifier OUTPUT divergence (edit-drift), not a logic bug
# present identically in both.
# ---------------------------------------------------------------------------


def _bfs_order(lockfile: dict) -> tuple[dict[str, int], dict[int, list[str]]]:
    """BFS walk from root; return (visited{id->depth}, level_map{depth->ids}).

    Fail-closed: raises KeyError/TypeError if the lockfile is missing 'root' or
    'packages', or is otherwise malformed (the verifier must not invent an order).
    Alphabetical sort on deps ensures deterministic queue ordering.
    """
    root_id: str = lockfile["root"]
    packages = lockfile["packages"]
    if not isinstance(packages, dict):
        raise TypeError("lockfile 'packages' must be a dict")

    visited: dict[str, int] = {}  # id -> depth
    level_map: dict[int, list[str]] = {}
    queue: deque[tuple[str, int]] = deque()
    queue.append((root_id, 0))

    while queue:
        pkg_id, depth = queue.popleft()
        if pkg_id in visited:
            continue
        visited[pkg_id] = depth
        level_map.setdefault(depth, []).append(pkg_id)

        pkg = packages.get(pkg_id)
        if pkg is None:
            continue
        # Sort deps alphabetically to ensure deterministic queue ordering.
        for dep_id in sorted(pkg.get("deps", [])):
            if dep_id not in visited:
                queue.append((dep_id, depth + 1))

    return visited, level_map


def compute_resolved_tree(lockfile: dict) -> dict:
    """Canonical BFS resolved-tree re-derivation.

    Walk the lockfile DAG from root, build the resolution order (BFS levels
    ascending, ids sorted alphabetically within each level), and construct
    the full per-package node list in that order.  Each node carries:
        {id: str, hash: str, depth: int, deps: list[str]}
    matching the producer's _build_bundle._bfs_resolve node structure exactly.

    Returns the full resolved-tree dict:
        {root: str, nodes: list[dict], resolution_order: list[str]}

    This mirrors the structure the producer emits to payload/resolved_tree.json
    (via json.dumps(resolved_tree, indent=2)) so the `exact` comparator can
    compare the parsed JSON objects directly with Python ==.

    Fail-closed: raises on a malformed lockfile so the verifier cannot produce
    a spuriously passing result from partial data.
    """
    root_id: str = lockfile["root"]
    packages = lockfile["packages"]

    visited, level_map = _bfs_order(lockfile)

    # Resolution order: BFS levels ascending, ids sorted alphabetically within level.
    resolution_order: list[str] = []
    for depth in sorted(level_map):
        for pkg_id in sorted(level_map[depth]):
            resolution_order.append(pkg_id)

    # Nodes list in resolution order — matches _build_bundle.py's nodes construction.
    nodes: list[dict] = []
    for pkg_id in resolution_order:
        depth = visited[pkg_id]
        pkg = packages.get(pkg_id, {})
        nodes.append(
            {
                "id": pkg_id,
                "hash": pkg.get("hash", ""),
                "depth": depth,
                "deps": sorted(pkg.get("deps", [])),
            }
        )

    return {
        "root": root_id,
        "nodes": nodes,
        "resolution_order": resolution_order,
    }


def compute_resolution_order(lockfile: dict) -> list[str]:
    """Return only the resolution_order list (compat helper; prefer compute_resolved_tree).

    Thin wrapper: runs the full BFS and extracts resolution_order from the result.
    Kept so call sites that only need the ordered id list don't have to unpack
    the full resolved_tree dict.
    """
    return compute_resolved_tree(lockfile)["resolution_order"]


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered at import for the core registry)
# ---------------------------------------------------------------------------


class BomRecompute:
    """Verifier-side primitive for re-deriving the full BOM resolved dependency tree.

    Re-derives the complete resolved_tree structure (root, per-package nodes with
    id/hash/depth/deps, and resolution_order) from the committed lockfile via a
    faithful verifier-side BFS reimplementation.  The recomputed tree is compared
    against the producer's independently-emitted payload/resolved_tree.json via
    the `exact` comparator — an output divergence (edit-drift between producer and
    verifier implementations, or a tampered claimed value) surfaces as
    REDERIVATION_MISMATCH.  This catches producer↔verifier output disagreement;
    it does not claim to detect bugs that are identical in both implementations.
    """

    primitive_id: str = "bom_recompute"

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        """Recompute the full resolved_tree dict from the committed lockfile DAG.

        Returns the recomputed VALUE only — a dict {root, nodes, resolution_order}
        matching the producer's payload/resolved_tree.json structure.  The primitive
        reads no acceptance epsilon and does not compare; the auditor-anchored `exact`
        comparator decides agreement against outputs/<id>.json.
        """
        bundle_dir: Path = inputs.bundle_dir
        lockfile_path = bundle_dir / "lockfile" / "lockfile.json"
        if not lockfile_path.is_file():
            raise FileNotFoundError(
                f"lockfile/lockfile.json not found in bundle at {bundle_dir}"
            )
        lockfile = admit_json_file(lockfile_path)
        if not isinstance(lockfile, dict):
            raise ValueError("lockfile/lockfile.json: top-level must be an object")
        if "root" not in lockfile or "packages" not in lockfile:
            raise ValueError(
                "lockfile/lockfile.json: missing required 'root' or 'packages'"
            )
        value = compute_resolved_tree(lockfile)
        return RecomputedValue(
            value=value,
            detail=(
                f"re-derived resolved_tree ({len(value['nodes'])} nodes, "
                f"{len(value['resolution_order'])} resolution_order entries) "
                f"from lockfile root={lockfile['root']!r}"
            ),
        )


register_primitive(BomRecompute())
