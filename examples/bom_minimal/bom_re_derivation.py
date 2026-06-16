#!/usr/bin/env python3
"""bom_re_derivation.py — stdlib re-derivation pack for BOM (bill-of-materials) domain.

Re-derives the resolved dependency tree from a lockfile via BFS.
the audit-bundle contract §C6 (re-derivation pack — domain-agnostic substrate).
AB4: stdlib only, no imports from audit_bundle.

Reads:
  lockfile/lockfile.json    — deterministic mini-lockfile with pinned hashes
  payload/resolved_tree.json — resolved dependency tree produced by the model

For each record in resolved_tree.json the pack verifies:
  1. Every node's `hash` matches the lockfile's recorded hash for that package.
  2. Every node's `deps` matches the lockfile's deps for that package.
  3. Every node's `depth` matches the BFS depth from root.
  4. `resolution_order` matches the deterministic BFS order (ties broken by id).
  5. The `nodes` set membership equals the full reachable closure from root.

Exits 0 on full match; 1 on first mismatch with a [BOM_REDER_FAIL] line on stderr.

Usage:
    python bom_re_derivation.py --bundle-dir /path/to/bundle
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import deque
from pathlib import Path


# ---------------------------------------------------------------------------
# BFS re-derivation
# ---------------------------------------------------------------------------


def _bfs_resolve(lockfile: dict) -> tuple[dict, list[str]]:
    """Walk the lockfile DAG from root via BFS.

    Returns:
        nodes    — dict[id -> {id, hash, depth, deps}]
        order    — deterministic resolution order (BFS, ties broken alphabetically)
    """
    root_id: str = lockfile["root"]
    packages: dict[str, dict] = lockfile["packages"]

    visited: dict[str, int] = {}  # id -> depth
    queue: deque[tuple[str, int]] = deque()
    queue.append((root_id, 0))

    # BFS — process in alphabetical order within each depth level
    level_map: dict[int, list[str]] = {}
    while queue:
        pkg_id, depth = queue.popleft()
        if pkg_id in visited:
            continue
        visited[pkg_id] = depth
        level_map.setdefault(depth, []).append(pkg_id)

        pkg = packages.get(pkg_id)
        if pkg is None:
            continue
        # Sort deps alphabetically to ensure deterministic queue ordering
        for dep_id in sorted(pkg.get("deps", [])):
            if dep_id not in visited:
                queue.append((dep_id, depth + 1))

    # Build resolution_order: BFS levels in order, ties broken alphabetically
    order: list[str] = []
    for depth in sorted(level_map):
        for pkg_id in sorted(level_map[depth]):
            order.append(pkg_id)

    # Build nodes dict
    nodes: dict[str, dict] = {}
    for pkg_id, depth in visited.items():
        pkg = packages.get(pkg_id, {})
        nodes[pkg_id] = {
            "id": pkg_id,
            "hash": pkg.get("hash", ""),
            "depth": depth,
            "deps": sorted(pkg.get("deps", [])),
        }

    return nodes, order


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _verify(bundle_dir: Path) -> str | None:
    """Return an error description on mismatch, or None on success."""
    lockfile_path = bundle_dir / "lockfile" / "lockfile.json"
    tree_path = bundle_dir / "payload" / "resolved_tree.json"

    if not lockfile_path.exists():
        return f"lockfile/lockfile.json absent from bundle_dir {bundle_dir}"
    if not tree_path.exists():
        return f"payload/resolved_tree.json absent from bundle_dir {bundle_dir}"

    try:
        lockfile: dict = json.loads(lockfile_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return f"failed to read lockfile/lockfile.json: {exc}"

    try:
        tree: dict = json.loads(tree_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return f"failed to read payload/resolved_tree.json: {exc}"

    # Re-derive the expected tree
    expected_nodes, expected_order = _bfs_resolve(lockfile)

    # 1. Check root
    tree_root = tree.get("root")
    if tree_root != lockfile.get("root"):
        return (
            f"root mismatch: lockfile root={lockfile.get('root')!r}, "
            f"resolved_tree root={tree_root!r}"
        )

    # 2. Check nodes set membership
    tree_nodes_list: list[dict] = tree.get("nodes", [])
    tree_nodes: dict[str, dict] = {n["id"]: n for n in tree_nodes_list}
    expected_ids = set(expected_nodes.keys())
    actual_ids = set(tree_nodes.keys())

    if expected_ids != actual_ids:
        extra = actual_ids - expected_ids
        missing = expected_ids - actual_ids
        parts = []
        if missing:
            parts.append(f"missing from resolved_tree: {sorted(missing)}")
        if extra:
            parts.append(f"extra in resolved_tree (not reachable from root): {sorted(extra)}")
        return "nodes set mismatch — " + "; ".join(parts)

    # 3. Check each node's hash, deps, and depth
    for pkg_id, expected in expected_nodes.items():
        actual = tree_nodes[pkg_id]

        if actual.get("hash") != expected["hash"]:
            return (
                f"node {pkg_id!r}: hash mismatch — "
                f"lockfile={expected['hash']!r}, resolved_tree={actual.get('hash')!r}"
            )

        actual_deps = sorted(actual.get("deps", []))
        if actual_deps != expected["deps"]:
            return (
                f"node {pkg_id!r}: deps mismatch — "
                f"lockfile={expected['deps']!r}, resolved_tree={actual_deps!r}"
            )

        if actual.get("depth") != expected["depth"]:
            return (
                f"node {pkg_id!r}: depth mismatch — "
                f"expected={expected['depth']}, resolved_tree={actual.get('depth')!r}"
            )

    # 4. Check resolution_order
    tree_order: list[str] = tree.get("resolution_order", [])
    if tree_order != expected_order:
        return (
            f"resolution_order mismatch\n"
            f"  expected={expected_order!r}\n"
            f"  got     ={tree_order!r}"
        )

    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="BOM re-derivation check for supply-chain audit bundles"
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

    print(f"[BOM_REDER_FAIL] {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
