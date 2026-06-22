"""_build_bundle.py — build a deterministic bom_minimal audit bundle.

Generates a synthetic npm-style lockfile with 10 packages forming a DAG,
resolves the dependency tree via BFS, and emits a standards-compliant manifest.

Usage (from v-kernel-audit-bundle root):
    python examples/bom_minimal/_build_bundle.py --out-dir /tmp/bom_bundle

Outputs:
  <out-dir>/lockfile/lockfile.json   (10-package deterministic DAG lockfile)
  <out-dir>/payload/resolved_tree.json  (BFS-resolved dependency tree)
  <out-dir>/manifest.json

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

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.emitter import BundleContent, write_bundle  # noqa: E402

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "bom-minimal-rc"
_CREATED_AT = "2026-05-08T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
    "bom_re_derivation",
]

# ---------------------------------------------------------------------------
# Synthetic lockfile — deterministic 10-package DAG
#
# Dependency graph (no cycles):
#   myapp@1.0.0          depth=0  deps: [express@4.18.2, lodash@4.17.21, uuid@9.0.0]
#   express@4.18.2       depth=1  deps: [accepts@1.3.8, qs@6.11.0]
#   lodash@4.17.21       depth=1  deps: []
#   uuid@9.0.0           depth=1  deps: []
#   accepts@1.3.8        depth=2  deps: [mime-types@2.1.35, negotiator@0.6.3]
#   qs@6.11.0            depth=2  deps: []
#   mime-types@2.1.35    depth=3  deps: [mime-db@1.52.0]
#   negotiator@0.6.3     depth=3  deps: []
#   mime-db@1.52.0       depth=4  deps: []
#
# That is 9 reachable nodes from root. Adding a 10th package that is also
# reachable from root:
#   body-parser@1.20.2   depth=1  deps: [qs@6.11.0]
#   (qs@6.11.0 is already depth=2 via express; body-parser shares it)
#
# Full 10 packages:
#   myapp@1.0.0, express@4.18.2, lodash@4.17.21, uuid@9.0.0,
#   body-parser@1.20.2, accepts@1.3.8, qs@6.11.0,
#   mime-types@2.1.35, negotiator@0.6.3, mime-db@1.52.0
# ---------------------------------------------------------------------------

# Pre-computed deterministic SHA-256 values (sha256 of the UTF-8 package-id string).
def _pkg_hash(pkg_id: str) -> str:
    """Deterministic fake content hash: sha256 of the package id bytes."""
    return "sha256:" + hashlib.sha256(pkg_id.encode("utf-8")).hexdigest()


_LOCKFILE: dict = {
    "root": "myapp@1.0.0",
    "packages": {
        "myapp@1.0.0": {
            "hash": _pkg_hash("myapp@1.0.0"),
            "deps": ["body-parser@1.20.2", "express@4.18.2", "lodash@4.17.21", "uuid@9.0.0"],
        },
        "express@4.18.2": {
            "hash": _pkg_hash("express@4.18.2"),
            "deps": ["accepts@1.3.8", "qs@6.11.0"],
        },
        "lodash@4.17.21": {
            "hash": _pkg_hash("lodash@4.17.21"),
            "deps": [],
        },
        "uuid@9.0.0": {
            "hash": _pkg_hash("uuid@9.0.0"),
            "deps": [],
        },
        "body-parser@1.20.2": {
            "hash": _pkg_hash("body-parser@1.20.2"),
            "deps": ["qs@6.11.0"],
        },
        "accepts@1.3.8": {
            "hash": _pkg_hash("accepts@1.3.8"),
            "deps": ["mime-types@2.1.35", "negotiator@0.6.3"],
        },
        "qs@6.11.0": {
            "hash": _pkg_hash("qs@6.11.0"),
            "deps": [],
        },
        "mime-types@2.1.35": {
            "hash": _pkg_hash("mime-types@2.1.35"),
            "deps": ["mime-db@1.52.0"],
        },
        "negotiator@0.6.3": {
            "hash": _pkg_hash("negotiator@0.6.3"),
            "deps": [],
        },
        "mime-db@1.52.0": {
            "hash": _pkg_hash("mime-db@1.52.0"),
            "deps": [],
        },
    },
}


def _bfs_resolve(lockfile: dict) -> tuple[list[dict], list[str]]:
    """Walk lockfile from root via BFS; return (nodes_list, resolution_order).

    Tie-breaking: within each BFS depth level, nodes are sorted alphabetically
    by id before being added to the order.  This is the canonical deterministic
    topological order the re-derivation pack re-produces.
    """
    root_id: str = lockfile["root"]
    packages: dict[str, dict] = lockfile["packages"]

    visited: dict[str, int] = {}  # id -> depth
    # level_map collects all ids discovered at each depth level, then sorts them.
    level_map: dict[int, list[str]] = {}
    queue: deque[tuple[str, int]] = deque()
    queue.append((root_id, 0))

    while queue:
        pkg_id, depth = queue.popleft()
        if pkg_id in visited:
            continue
        visited[pkg_id] = depth
        level_map.setdefault(depth, []).append(pkg_id)

        pkg = packages.get(pkg_id, {})
        for dep_id in sorted(pkg.get("deps", [])):
            if dep_id not in visited:
                queue.append((dep_id, depth + 1))

    # Resolution order: BFS levels in ascending order, ids sorted alphabetically
    resolution_order: list[str] = []
    for depth_level in sorted(level_map):
        for pkg_id in sorted(level_map[depth_level]):
            resolution_order.append(pkg_id)

    # Nodes list in resolution order
    nodes: list[dict] = []
    for pkg_id in resolution_order:
        depth = visited[pkg_id]
        pkg = packages.get(pkg_id, {})
        nodes.append({
            "id": pkg_id,
            "hash": pkg.get("hash", ""),
            "depth": depth,
            "deps": sorted(pkg.get("deps", [])),
        })

    return nodes, resolution_order


def build(out_dir: Path) -> None:
    # Lockfile bytes
    lockfile_bytes = json.dumps(_LOCKFILE, indent=2, sort_keys=True).encode("utf-8")

    # Resolve the dependency tree
    nodes, resolution_order = _bfs_resolve(_LOCKFILE)

    resolved_tree = {
        "root": _LOCKFILE["root"],
        "nodes": nodes,
        "resolution_order": resolution_order,
    }

    # Resolved tree bytes
    tree_bytes = json.dumps(resolved_tree, indent=2).encode("utf-8")

    # Emit via the reference-emitter SDK
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "lockfile/lockfile.json": lockfile_bytes,
            "payload/resolved_tree.json": tree_bytes,
        },
        typed_checks=_TYPED_CHECKS,
    )
    manifest = write_bundle(out_dir, content)
    files = manifest["files"]

    print(f"Bundle written to {out_dir}")
    print(f"  packages         : {len(_LOCKFILE['packages'])}")
    print(f"  resolved nodes   : {len(nodes)}")
    print(f"  manifest files   : {len(files)}")
    print(f"  manifest         : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic bom_minimal audit bundle"
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
