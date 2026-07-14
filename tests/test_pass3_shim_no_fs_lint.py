"""Pass-3 shim no-filesystem lint: the widened anti-re-fork guard (D5).

The ``file_integrity_many_small`` Pass-3 surplus sweep is a shim over the
core conservation gate: it consumes ONLY the finalized ConservationResult.
The predecessor anti-re-fork guard banned the literal skip-set frozensets;
this lint widens it structurally (same delivery vehicle as
test_applies_to_files_exact_path_lint.py) — the shim module
(``audit_bundle/plugins/pass3_conservation_shim.py``) may not perform ANY
filesystem access, so re-forking the membership decision (a second walk, a
recomputed classification, a sneaky ``open``) is unrepresentable there:

  1. no import of an OS/filesystem-bearing module (os, io, pathlib, shutil,
     glob, tempfile, stat) and no import of the integrity-ownership map or
     the conservation engine at runtime (TYPE_CHECKING-only is fine — types,
     not decisions);
  2. no call to the ``open`` builtin;
  3. no attribute call whose name is a filesystem accessor (read_bytes,
     rglob, scandir, lstat, exists, ...).

This file:
  1. Implements find_fs_access(source, filename) via AST.
  2. Seeded-snippet tests: each forbidden shape is caught; the allowed
     pure-computation shapes pass.
  3. Real-tree test: the shipped shim module has zero hits.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SHIM_PATH = REPO_ROOT / "audit_bundle" / "plugins" / "pass3_conservation_shim.py"

# Modules whose import gives the shim filesystem reach (or a path back to a
# second membership decision). TYPE_CHECKING-gated imports are exempt: they
# never execute, so they carry types, not decisions.
_FORBIDDEN_MODULES = frozenset(
    {
        "os",
        "io",
        "pathlib",
        "shutil",
        "glob",
        "tempfile",
        "stat",
        "fileinput",
        "audit_bundle.integrity_ownership",
        "audit_bundle.conservation",
    }
)

# Attribute-call names that reach the filesystem on common receiver types.
_FORBIDDEN_ATTR_CALLS = frozenset(
    {
        "open",
        "read_bytes",
        "read_text",
        "write_bytes",
        "write_text",
        "rglob",
        "glob",
        "iterdir",
        "scandir",
        "walk",
        "lstat",
        "stat",
        "exists",
        "is_file",
        "is_dir",
        "is_symlink",
        "resolve",
        "mkdir",
        "mkfifo",
        "listdir",
        "unlink",
    }
)


def _type_checking_blocks(tree: ast.Module) -> list[ast.If]:
    """Top-level ``if TYPE_CHECKING:`` blocks (imports there never execute)."""
    blocks = []
    for node in tree.body:
        if isinstance(node, ast.If):
            test = node.test
            if (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
                isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
            ):
                blocks.append(node)
    return blocks


def find_fs_access(source: str, filename: str) -> list[str]:
    """Return violation strings for any filesystem-access shape in *source*."""
    tree = ast.parse(source, filename=filename)
    exempt_nodes: set[int] = set()
    for block in _type_checking_blocks(tree):
        for sub in ast.walk(block):
            exempt_nodes.add(id(sub))

    violations: list[str] = []
    for node in ast.walk(tree):
        if id(node) in exempt_nodes:
            continue
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name
                if root in _FORBIDDEN_MODULES or root.split(".")[0] in (
                    _FORBIDDEN_MODULES
                ):
                    violations.append(
                        f"{filename}:{node.lineno}: forbidden import {alias.name!r}"
                    )
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod in _FORBIDDEN_MODULES or mod.split(".")[0] in _FORBIDDEN_MODULES:
                violations.append(
                    f"{filename}:{node.lineno}: forbidden import from {mod!r}"
                )
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "open":
                violations.append(f"{filename}:{node.lineno}: call to builtin open()")
            elif isinstance(func, ast.Attribute) and func.attr in _FORBIDDEN_ATTR_CALLS:
                violations.append(
                    f"{filename}:{node.lineno}: filesystem attribute call "
                    f".{func.attr}()"
                )
    return violations


# ---------------------------------------------------------------------------
# Seeded snippets — the lint catches each forbidden shape
# ---------------------------------------------------------------------------


def test_seeded_import_os_caught():
    assert find_fs_access("import os\n", "snippet.py")


def test_seeded_import_pathlib_caught():
    assert find_fs_access("from pathlib import Path\n", "snippet.py")


def test_seeded_map_import_caught():
    src = "from audit_bundle.integrity_ownership import classify_path\n"
    assert find_fs_access(src, "snippet.py")


def test_seeded_conservation_import_caught():
    src = "from audit_bundle.conservation import run_conservation\n"
    assert find_fs_access(src, "snippet.py")


def test_seeded_open_call_caught():
    assert find_fs_access("data = open('x').read()\n", "snippet.py")


def test_seeded_rglob_call_caught():
    assert find_fs_access("def f(d):\n    return sorted(d.rglob('*'))\n", "snippet.py")


def test_seeded_read_bytes_call_caught():
    assert find_fs_access("def f(p):\n    return p.read_bytes()\n", "snippet.py")


def test_seeded_type_checking_import_allowed():
    src = (
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    from audit_bundle.conservation import ConservationResult\n"
    )
    assert find_fs_access(src, "snippet.py") == []


def test_seeded_pure_computation_allowed():
    src = (
        "def f(result, root):\n"
        "    return tuple(f'{root}/{p}' for p in result.unowned)\n"
    )
    assert find_fs_access(src, "snippet.py") == []


# ---------------------------------------------------------------------------
# The real tree — the shipped shim module is filesystem-free
# ---------------------------------------------------------------------------


def test_shipped_shim_module_has_no_fs_access():
    source = SHIM_PATH.read_text(encoding="utf-8")
    violations = find_fs_access(source, SHIM_PATH.name)
    assert violations == [], violations
