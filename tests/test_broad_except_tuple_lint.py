"""Broad-except-tuple lint: AST detector for ``except (X, ..., Exception)``.

Encodes redteam finding M8 as a standing structural invariant (the same
delivery vehicle as test_dsse_d3_bypass_lint.py): an except TUPLE that
contains ``Exception`` or ``BaseException`` alongside other members makes the
specific members dead and catches every verifier bug — laundering crashes
into whatever the handler produces (typically a REJECT-class verdict error).
A REJECT is a claim about the bundle; a crash is a claim about the verifier.

A bare ``except Exception:`` (or a one-element tuple) is NOT flagged: the
deliberate Pattern-1b fail-closed wraps around hostile bundle data use that
shape on purpose. The lint targets only the dead-specific-member tuple shape,
which is always an authoring error.

This file:
  1. Implements find_broad_except_tuples(source, filename) -> list[str] via AST.
  2. Seeded-snippet tests: the M8 shapes are caught; allowed shapes are not.
  3. Real-tree test: audit_bundle/, scripts/, cli/, release/ have zero hits.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path

_BROAD_NAMES = frozenset({"Exception", "BaseException"})


def _broad_member(elt: ast.expr) -> str | None:
    """Return the broad class name if elt names Exception/BaseException."""
    if isinstance(elt, ast.Name) and elt.id in _BROAD_NAMES:
        return elt.id
    # builtins.Exception / builtins.BaseException spelled as attributes.
    if isinstance(elt, ast.Attribute) and elt.attr in _BROAD_NAMES:
        return elt.attr
    return None


def find_broad_except_tuples(source: str, filename: str) -> list[str]:
    """Return violation strings for except tuples that bury Exception/BaseException.

    Flags ``except (X, Exception)`` and any multi-member except tuple containing
    Exception or BaseException. Does NOT flag ``except Exception:`` alone or a
    one-element tuple (equivalent to the bare form). Unparseable source returns
    no violations (mirrors the d3 lint's posture on generated/binary files).
    """
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError:
        return []
    hits: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        if not isinstance(node.type, ast.Tuple):
            continue
        if len(node.type.elts) < 2:
            continue
        for elt in node.type.elts:
            broad = _broad_member(elt)
            if broad is not None:
                hits.append(
                    f"{filename}:{node.lineno}: except tuple buries {broad} — "
                    "the specific members are dead and verifier bugs are "
                    "swallowed (M8); catch the documented hostile-data family "
                    f"or use a bare 'except {broad}:' if the breadth is deliberate"
                )
                break
    return hits


# ---------------------------------------------------------------------------
# Seeded snippets: M8 shapes must be caught
# ---------------------------------------------------------------------------


def test_detector_catches_specific_plus_exception() -> None:
    bad = "try:\n    pass\nexcept (ValueError, Exception):\n    pass\n"
    hits = find_broad_except_tuples(bad, "<seed>")
    assert hits and "buries Exception" in hits[0]


def test_detector_catches_exception_first_in_tuple() -> None:
    bad = "try:\n    pass\nexcept (Exception, KeyError) as exc:\n    pass\n"
    assert find_broad_except_tuples(bad, "<seed>")


def test_detector_catches_base_exception_in_tuple() -> None:
    bad = "try:\n    pass\nexcept (OSError, BaseException):\n    pass\n"
    hits = find_broad_except_tuples(bad, "<seed>")
    assert hits and "buries BaseException" in hits[0]


def test_detector_catches_three_member_tuple() -> None:
    bad = "try:\n    pass\nexcept (KeyError, TypeError, Exception):\n    pass\n"
    assert find_broad_except_tuples(bad, "<seed>")


# ---------------------------------------------------------------------------
# Seeded snippets: deliberate shapes must NOT be flagged
# ---------------------------------------------------------------------------


def test_detector_allows_bare_except_exception() -> None:
    """Pattern-1b fail-closed wraps around hostile data are deliberate."""
    ok = "try:\n    pass\nexcept Exception as exc:\n    pass\n"
    assert not find_broad_except_tuples(ok, "<seed>")


def test_detector_allows_specific_tuple() -> None:
    ok = "try:\n    pass\nexcept (ValueError, KeyError):\n    pass\n"
    assert not find_broad_except_tuples(ok, "<seed>")


def test_detector_allows_one_element_tuple() -> None:
    """(Exception,) is just a parenthesised bare form — same posture."""
    ok = "try:\n    pass\nexcept (Exception,):\n    pass\n"
    assert not find_broad_except_tuples(ok, "<seed>")


def test_detector_allows_custom_exception_named_like() -> None:
    """A project class merely CONTAINING the word is not broad."""
    ok = "try:\n    pass\nexcept (ValueError, MyException):\n    pass\n"
    assert not find_broad_except_tuples(ok, "<seed>")


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


def test_real_tree_has_no_broad_except_tuples() -> None:
    py_files = _collect_py_files()
    assert py_files, (
        f"no .py files found under {_SCAN_DIRS} relative to {_PRODUCT_ROOT} — "
        "check _PRODUCT_ROOT resolution"
    )
    violations: list[str] = []
    for path in py_files:
        source = path.read_text(encoding="utf-8", errors="replace")
        violations.extend(
            find_broad_except_tuples(source, str(path.relative_to(_PRODUCT_ROOT)))
        )
    assert not violations, "M8-shape except tuples found:\n" + "\n".join(violations)
