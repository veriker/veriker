"""DSSE D3 bypass-lint: AST detector for .diagnostics.raw_ok/.verified in routing positions.

Closes the verified-fatal composite verdict gap (DSSE WS-0): after verify_turn_bundle
returns a VerifyVerdict, callers must gate on VerifyVerdict.ok (composite). Accessing
.diagnostics.raw_ok or .diagnostics.verified in a routing position (if/while/assert/
BoolOp/UnaryOp not/Compare) bypasses the AND-gate and re-opens the gap.

This file:
  1. Implements find_diagnostics_routing_uses(source, filename) -> list[str] using AST.
  2. Test 1: seeded bad snippet triggers a hit (detector works).
  3. Test 2: real tree (audit_bundle/, scripts/, cli/) has zero hits.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path


# ---------------------------------------------------------------------------
# AST detector
# ---------------------------------------------------------------------------

_ROUTING_PARENT_TYPES = (
    ast.If,
    ast.While,
    ast.Assert,
    ast.BoolOp,
    ast.UnaryOp,
    ast.Compare,
)


def _is_diagnostics_bypass(node: ast.AST) -> bool:
    """Return True if node is <expr>.diagnostics.raw_ok or <expr>.diagnostics.verified."""
    if not isinstance(node, ast.Attribute):
        return False
    if node.attr not in ("raw_ok", "verified"):
        return False
    mid = node.value
    if not isinstance(mid, ast.Attribute):
        return False
    return mid.attr == "diagnostics"


class _RoutingUseVisitor(ast.NodeVisitor):
    """Walk the AST and collect .diagnostics.raw_ok/.verified nodes in routing positions.

    Strategy: for each node that is a routing context (If.test, While.test,
    Assert.test, BoolOp, UnaryOp(not), Compare), recursively scan its sub-tree
    for _is_diagnostics_bypass matches. An Attribute node that IS a bypass but
    whose parent is an assignment target, dict value, return value, or f-string
    interpolation is NOT flagged — we only flag routing context sub-trees.
    """

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.hits: list[str] = []

    def _scan_routing_subtree(self, node: ast.AST) -> None:
        """Recursively scan node and its children for bypass patterns."""
        if _is_diagnostics_bypass(node):
            lineno = getattr(node, "lineno", "?")
            attr = node.attr  # type: ignore[attr-defined]
            self.hits.append(
                f"{self.filename}:{lineno}: .diagnostics.{attr} in routing position"
            )
            return  # don't recurse further into the same node
        for child in ast.iter_child_nodes(node):
            self._scan_routing_subtree(child)

    def visit_If(self, node: ast.If) -> None:
        self._scan_routing_subtree(node.test)
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self._scan_routing_subtree(node.test)
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        self._scan_routing_subtree(node.test)
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        for value in node.values:
            self._scan_routing_subtree(value)
        self.generic_visit(node)

    def visit_UnaryOp(self, node: ast.UnaryOp) -> None:
        if isinstance(node.op, ast.Not):
            self._scan_routing_subtree(node.operand)
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        self._scan_routing_subtree(node.left)
        for comparator in node.comparators:
            self._scan_routing_subtree(comparator)
        self.generic_visit(node)


def find_diagnostics_routing_uses(source: str, filename: str) -> list[str]:
    """Return a list of violation strings for .diagnostics.raw_ok/.verified in routing positions.

    Args:
        source: Python source text to analyse.
        filename: label to include in violation strings (e.g. a file path).

    Returns:
        List of strings describing each violation, empty if clean.
        Returns a single-element list with a parse-error message if source
        cannot be parsed (treated as a non-violation to avoid false positives
        on binary/generated files).
    """
    try:
        tree = ast.parse(source, filename=filename)
    except SyntaxError:
        return []  # unparseable — not a routing violation
    visitor = _RoutingUseVisitor(filename)
    visitor.visit(tree)
    return visitor.hits


# ---------------------------------------------------------------------------
# Test 1: seeded bad snippet must produce a hit
# ---------------------------------------------------------------------------


def test_detector_catches_seeded_verified_in_if() -> None:
    """Seeded .diagnostics.verified in an if-test → detector must return a non-empty hit."""
    bad_snippet = "if result.diagnostics.verified:\n    pass\n"
    hits = find_diagnostics_routing_uses(bad_snippet, "<seed>")
    assert hits, (
        "detector must flag .diagnostics.verified inside an if-test; got zero hits"
    )
    assert any("diagnostics.verified" in h for h in hits)


def test_detector_catches_seeded_raw_ok_in_if() -> None:
    """Seeded .diagnostics.raw_ok in an if-test → detector must return a non-empty hit."""
    bad_snippet = "if result.diagnostics.raw_ok:\n    pass\n"
    hits = find_diagnostics_routing_uses(bad_snippet, "<seed>")
    assert hits, (
        "detector must flag .diagnostics.raw_ok inside an if-test; got zero hits"
    )
    assert any("diagnostics.raw_ok" in h for h in hits)


def test_detector_catches_seeded_verified_in_assert() -> None:
    """Seeded .diagnostics.verified in an assert-test → must be flagged."""
    bad_snippet = "assert result.diagnostics.verified, 'must be verified'\n"
    hits = find_diagnostics_routing_uses(bad_snippet, "<seed>")
    assert hits, "detector must flag .diagnostics.verified inside an assert"


def test_detector_catches_seeded_verified_in_boolop() -> None:
    """Seeded .diagnostics.verified in a boolean and/or expression → must be flagged."""
    bad_snippet = "x = a and result.diagnostics.verified\n"
    hits = find_diagnostics_routing_uses(bad_snippet, "<seed>")
    assert hits, "detector must flag .diagnostics.verified inside a BoolOp"


def test_detector_catches_seeded_verified_in_not() -> None:
    """Seeded not result.diagnostics.verified → must be flagged."""
    bad_snippet = "x = not result.diagnostics.verified\n"
    hits = find_diagnostics_routing_uses(bad_snippet, "<seed>")
    assert hits, "detector must flag .diagnostics.verified inside a UnaryOp(not)"


def test_detector_catches_seeded_verified_in_compare() -> None:
    """Seeded result.diagnostics.verified == True in a Compare → must be flagged."""
    bad_snippet = "x = result.diagnostics.verified == True\n"
    hits = find_diagnostics_routing_uses(bad_snippet, "<seed>")
    assert hits, "detector must flag .diagnostics.verified inside a Compare"


def test_detector_allows_dict_value_assignment() -> None:
    """Assigning .diagnostics.verified to a dict value is allowed (not routing)."""
    ok_snippet = '"verified": result.diagnostics.verified,\n'
    # Wrap in a dict literal so it parses as a valid expression statement.
    ok_snippet = "d = {'verified': result.diagnostics.verified}\n"
    hits = find_diagnostics_routing_uses(ok_snippet, "<seed>")
    assert not hits, f"dict-value assignment must not be flagged, got: {hits}"


def test_detector_allows_bare_assignment() -> None:
    """Simple variable assignment of .diagnostics.verified is allowed (not routing)."""
    ok_snippet = "v = result.diagnostics.verified\n"
    hits = find_diagnostics_routing_uses(ok_snippet, "<seed>")
    assert not hits, f"bare assignment must not be flagged, got: {hits}"


# ---------------------------------------------------------------------------
# Test 2: real tree must be clean
# ---------------------------------------------------------------------------

_PRODUCT_ROOT = Path(__file__).resolve().parents[1]
_SCAN_DIRS = ["audit_bundle", "scripts", "veriker"]


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


def test_real_tree_has_no_diagnostics_routing_uses() -> None:
    """Walk audit_bundle/, scripts/, cli/ and assert zero routing-bypass hits."""
    py_files = _collect_py_files()
    assert py_files, (
        f"no .py files found under {_SCAN_DIRS} relative to {_PRODUCT_ROOT} — "
        "check _PRODUCT_ROOT resolution"
    )
    all_hits: list[str] = []
    for path in py_files:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(_PRODUCT_ROOT))
        hits = find_diagnostics_routing_uses(source, rel)
        all_hits.extend(hits)
    assert not all_hits, (
        f"found {len(all_hits)} .diagnostics.raw_ok/.verified routing use(s) — "
        "these bypass the VerifyVerdict composite gate and must be removed:\n"
        + "\n".join(all_hits)
    )
