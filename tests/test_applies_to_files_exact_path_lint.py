"""applies_to_files exact-path lint: forbid trailing-slash pseudo-prefixes.

Encodes the D3 contract as a standing structural invariant (same delivery
vehicle as test_broad_except_tuple_lint.py): a plugin's ``applies_to_files``
set is consumed by the strict-SHA membership decision via EXACT string match
(``rel_path in plugin_files``), so a directory-prefix entry ending in ``/``
(e.g. ``"corpus/"``) can never match a real bundle-relative file path. Such an
entry is silently inert — it looks like it exempts a whole tree from
byte-equality but exempts nothing. Worse, anyone later "fixing" it to real
prefix matching would EXEMPT whole trees from strict-SHA: a weakening
masquerading as a fix.

applies_to_files entries MUST be exact bundle-relative file paths. This lint
fails closed on any ``/``-suffixed string literal inside an applies_to_files
assignment anywhere in the shipped tree.

This file:
  1. Implements find_trailing_slash_applies_to_files(source, filename) via AST.
  2. Seeded-snippet tests: trailing-slash entries caught; exact paths allowed.
  3. Real-tree test: audit_bundle/, scripts/, cli/, release/ have zero hits.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path


def _string_consts(node: ast.AST) -> list[ast.Constant]:
    """Every str Constant in the subtree rooted at node."""
    return [
        n
        for n in ast.walk(node)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    ]


def find_trailing_slash_applies_to_files(source: str, filename: str) -> list[str]:
    """Return violations for ``/``-suffixed strings in applies_to_files assigns.

    Scans every assignment (annotated or plain) whose target is the name
    ``applies_to_files`` and flags any string literal in its value that ends in
    ``/``. Unparseable source returns no violations (mirrors the sibling lints'
    posture on generated/binary files).
    """
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError:
        return []
    hits: list[str] = []
    for node in ast.walk(tree):
        targets: list[ast.expr] = []
        value: ast.expr | None = None
        if isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
            value = node.value
        elif isinstance(node, ast.Assign):
            targets = list(node.targets)
            value = node.value
        else:
            continue
        names = {t.id for t in targets if isinstance(t, ast.Name)}
        if "applies_to_files" not in names or value is None:
            continue
        for const in _string_consts(value):
            if const.value.endswith("/"):
                hits.append(
                    f"{filename}:{const.lineno}: applies_to_files entry "
                    f"{const.value!r} ends in '/' — a trailing-slash pseudo-"
                    "prefix is consumed by EXACT match and exempts nothing "
                    "(D3); use exact bundle-relative file paths only"
                )
    return hits


# ---------------------------------------------------------------------------
# Seeded snippets: trailing-slash shapes must be caught
# ---------------------------------------------------------------------------


def test_detector_catches_trailing_slash_entry() -> None:
    bad = 'applies_to_files: frozenset[str] = frozenset({"corpus/"})\n'
    hits = find_trailing_slash_applies_to_files(bad, "<seed>")
    assert hits and "exempts nothing" in hits[0]


def test_detector_catches_one_of_several_entries() -> None:
    bad = (
        "applies_to_files: frozenset[str] = frozenset(\n"
        '    {"energy_score.json", "raw_traces/"}\n'
        ")\n"
    )
    assert find_trailing_slash_applies_to_files(bad, "<seed>")


def test_detector_catches_plain_assign() -> None:
    bad = 'applies_to_files = frozenset({"spec/"})\n'
    assert find_trailing_slash_applies_to_files(bad, "<seed>")


# ---------------------------------------------------------------------------
# Seeded snippets: exact paths and empty sets must NOT be flagged
# ---------------------------------------------------------------------------


def test_detector_allows_exact_paths() -> None:
    ok = (
        "applies_to_files: frozenset[str] = frozenset(\n"
        '    {"energy_score.json", "sleep_stages.json"}\n'
        ")\n"
    )
    assert not find_trailing_slash_applies_to_files(ok, "<seed>")


def test_detector_allows_empty_set() -> None:
    ok = "applies_to_files: frozenset[str] = frozenset()\n"
    assert not find_trailing_slash_applies_to_files(ok, "<seed>")


def test_detector_ignores_other_assignments() -> None:
    # A trailing-slash string somewhere else is not this lint's concern.
    ok = 'some_other_paths = frozenset({"corpus/"})\n'
    assert not find_trailing_slash_applies_to_files(ok, "<seed>")


# ---------------------------------------------------------------------------
# Real tree must be clean
# ---------------------------------------------------------------------------

_PRODUCT_ROOT = Path(__file__).resolve().parents[1]
_SCAN_DIRS = ["audit_bundle", "scripts", "veriker", "release"]


def _collect_py_files() -> list[Path]:
    files: list[Path] = []
    for d in _SCAN_DIRS:
        scan_root = _PRODUCT_ROOT / d
        if not scan_root.exists():
            continue
        for dirpath, _dirnames, filenames in os.walk(scan_root):
            for fname in filenames:
                if fname.endswith(".py"):
                    files.append(Path(dirpath) / fname)
    return files


def test_real_tree_has_no_trailing_slash_applies_to_files() -> None:
    py_files = _collect_py_files()
    assert py_files, (
        f"no .py files found under {_SCAN_DIRS} relative to {_PRODUCT_ROOT} — "
        "check _PRODUCT_ROOT resolution"
    )
    violations: list[str] = []
    for path in py_files:
        source = path.read_text(encoding="utf-8", errors="replace")
        violations.extend(
            find_trailing_slash_applies_to_files(
                source, str(path.relative_to(_PRODUCT_ROOT))
            )
        )
    assert not violations, (
        "trailing-slash applies_to_files entries found:\n" + "\n".join(violations)
    )
