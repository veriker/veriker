"""audit_bundle/plugins/falsification_negative_test.py — TypedCheck: falsification NEGATIVE TEST (C12).

Implements the audit-bundle contract §C12 (hedge-out catcher).
For each rule_*.json under falsification_rules/, verifies that the falsify_if
expression is not always-false (unfalsifiable) over all legal inputs defined
by trigger_expression's domain.  A rule that can never fire is a hedge-out
lever, not a credentialing primitive.

Evaluator is a tiny bounded-arithmetic stub over a restricted grammar:
  ==, !=, <, >, <=, >=, and, or, not, integer literals, identifier names.
No eval().  AST-walk only.  Any expression using tokens outside this grammar
FAILS CLOSED as FALSIFICATION_FRAGMENT_OUT_OF_SCOPE (ok=False): a rule whose
falsifiability the verifier cannot decide must not ride a green verdict —
otherwise the NEGATIVE TEST is evadable by simply using an unsupported
operator (an unfalsifiable rule dressed in out-of-grammar tokens would pass).
Mirrors the C16 posture for out-of-fragment refinement formulas
(DISCHARGE_FRAGMENT_OUT_OF_SCOPE). The earlier non-blocking
PROCEED_WITH_CAVEAT behaviour is retired (deprecated emit-never alias in
REASON_CODES.md).

Reference: the internal falsification-spec v1.0 NEGATIVE-TEST contract.
"""

from __future__ import annotations

import ast
import itertools
from pathlib import Path
from typing import Any

from audit_bundle.bundle_manifest import register_typed_check
from ..admission import admit_json_file
from audit_bundle.plugin import PluginResult

# ---------------------------------------------------------------------------
# Grammar definition
# ---------------------------------------------------------------------------

_BOUNDED_VALS: tuple[int, ...] = (-2, -1, 0, 1, 2)

_COMPARE_OPS: frozenset[type] = frozenset(
    {ast.Eq, ast.NotEq, ast.Lt, ast.Gt, ast.LtE, ast.GtE}
)
_BOOL_OPS: frozenset[type] = frozenset({ast.And, ast.Or})
_UNARY_OPS: frozenset[type] = frozenset({ast.Not})


# ---------------------------------------------------------------------------
# Tiny bounded-arithmetic evaluator
# ---------------------------------------------------------------------------


_TRANSPARENT_NODES: frozenset[type] = frozenset(
    # ast.walk visits operator and context singleton nodes (e.g. ast.Lt,
    # ast.And, ast.Load) as children of Compare/BoolOp/UnaryOp/Name.
    # We validate them via their parent nodes; let them pass transparently.
    {
        ast.Eq,
        ast.NotEq,
        ast.Lt,
        ast.Gt,
        ast.LtE,
        ast.GtE,
        ast.And,
        ast.Or,
        ast.Not,
        ast.USub,
        ast.Load,
        ast.Store,
        ast.Del,
    }
)


def _is_neg_int_literal(node: ast.AST) -> bool:
    """Return True iff *node* is the AST form of a negative integer literal (-N)."""
    return (
        isinstance(node, ast.UnaryOp)
        and isinstance(node.op, ast.USub)
        and isinstance(node.operand, ast.Constant)
        and isinstance(node.operand.value, int)
    )


def _grammar_ok(tree: ast.AST) -> bool:
    """Return True iff every node in the AST uses only the supported grammar."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Expression):
            continue
        if type(node) in _TRANSPARENT_NODES:
            # Operator/context singletons — validated via their parent node.
            continue
        if isinstance(node, ast.Constant):
            # bool is a subclass of int; True/False are acceptable integer-like literals.
            if not isinstance(node.value, int):
                return False
        elif isinstance(node, ast.Name):
            pass
        elif isinstance(node, ast.Compare):
            if any(type(op) not in _COMPARE_OPS for op in node.ops):
                return False
        elif isinstance(node, ast.BoolOp):
            if type(node.op) not in _BOOL_OPS:
                return False
        elif isinstance(node, ast.UnaryOp):
            if isinstance(node.op, ast.Not):
                pass  # logical not — always supported
            elif _is_neg_int_literal(node):
                pass  # negative integer literal (-N) — treated as a literal
            else:
                return False
        else:
            return False
    return True


def _names(tree: ast.AST) -> list[str]:
    """Return sorted list of all identifier names in the tree."""
    return sorted({n.id for n in ast.walk(tree) if isinstance(n, ast.Name)})


def _eval_node(node: ast.AST, env: dict[str, int]) -> Any:
    """Evaluate a grammar-validated AST node under the given variable bindings."""
    if isinstance(node, ast.Expression):
        return _eval_node(node.body, env)
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return env[node.id]
    if isinstance(node, ast.UnaryOp):
        if isinstance(node.op, ast.Not):
            return not _eval_node(node.operand, env)
        if isinstance(node.op, ast.USub):
            return -_eval_node(node.operand, env)
        raise TypeError(f"Unsupported unary op: {type(node.op).__name__}")
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            for v in node.values:
                if not _eval_node(v, env):
                    return False
            return True
        # Or
        for v in node.values:
            if _eval_node(v, env):
                return True
        return False
    if isinstance(node, ast.Compare):
        left = _eval_node(node.left, env)
        for op, comp in zip(node.ops, node.comparators):
            right = _eval_node(comp, env)
            if isinstance(op, ast.Eq) and not (left == right):
                return False
            elif isinstance(op, ast.NotEq) and not (left != right):
                return False
            elif isinstance(op, ast.Lt) and not (left < right):
                return False
            elif isinstance(op, ast.Gt) and not (left > right):
                return False
            elif isinstance(op, ast.LtE) and not (left <= right):
                return False
            elif isinstance(op, ast.GtE) and not (left >= right):
                return False
            left = right
        return True
    raise TypeError(f"Unsupported AST node: {type(node).__name__}")


def _is_always_false(falsify_if: str, domain_names: list[str]) -> bool | None:
    """
    Probe whether *falsify_if* is always False over *_BOUNDED_VALS* for every
    variable in *domain_names* (plus any extra names in the expression itself).

    Returns:
        True   — every tested combination gave False (unfalsifiable at v1)
        False  — at least one combination gave True (can fire → ok)
        None   — unsupported grammar or parse/eval error (decidability unknown)
    """
    try:
        tree = ast.parse(falsify_if, mode="eval")
    except SyntaxError:
        return None
    if not _grammar_ok(tree):
        return None

    fi_names = _names(tree)
    eval_vars = sorted(set(domain_names) | set(fi_names))

    if not eval_vars:
        try:
            val = _eval_node(tree, {})
        except Exception:
            return None
        return not bool(val)

    for vals in itertools.product(_BOUNDED_VALS, repeat=len(eval_vars)):
        env = dict(zip(eval_vars, vals))
        try:
            val = _eval_node(tree, env)
        except Exception:
            return None
        if val:
            return False  # found at least one input that makes it True
    return True  # all sampled inputs gave False → unfalsifiable


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


class FalsificationNegativeTestCheck:
    name: str = "falsification_negative_test"
    # exact-path-only: the former {"falsification_rules/"} trailing-slash
    # pseudo-prefix was inert (consumed by exact match, never matched). Dropped.
    applies_to_files: frozenset[str] = frozenset()

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        """For each rule_*.json in falsification_rules/, run the NEGATIVE TEST."""
        rules_dir = bundle_dir / "falsification_rules"

        if not rules_dir.exists():
            return PluginResult(
                ok=True,
                reason_code="PASS",
                detail="no falsification_rules/ directory; nothing to check",
                files_audited=(),
            )

        rule_files = sorted(rules_dir.glob("rule_*.json"))
        if not rule_files:
            return PluginResult(
                ok=True,
                reason_code="PASS",
                detail="falsification_rules/ contains no rule_*.json files",
                files_audited=(),
            )

        files_audited: list[str] = []

        for rf in rule_files:
            files_audited.append(str(rf))
            stem = rf.stem
            rule_id = stem[len("rule_") :] if stem.startswith("rule_") else stem

            # ------------------------------------------------------------------
            # Parse the rule file.
            # ------------------------------------------------------------------
            # UnicodeDecodeError is a ValueError subclass, NOT an OSError —
            # without naming it, an invalid-UTF-8 rule file escapes the
            # except and crashes the run (exit 2) instead of rejecting.
            try:
                rule = admit_json_file(rf)
            except (ValueError, OSError) as exc:
                return PluginResult(
                    ok=False,
                    reason_code="FALSIFICATION_RULE_PARSE_ERROR",
                    detail=f"rule {rule_id!r}: cannot parse JSON: {exc}",
                    files_audited=tuple(files_audited),
                )

            # Valid JSON that is not an object ([] / "foo" / 123) would raise
            # AttributeError on rule.get() below — fail closed instead.
            if not isinstance(rule, dict):
                return PluginResult(
                    ok=False,
                    reason_code="FALSIFICATION_RULE_SCHEMA_ERROR",
                    detail=(
                        f"rule {rule_id!r}: rule file must contain a JSON "
                        f"object, got {type(rule).__name__!r}"
                    ),
                    files_audited=tuple(files_audited),
                )

            trigger_expr = rule.get("trigger_expression", "")
            falsify_if = rule.get("falsify_if", "")

            if not isinstance(trigger_expr, str) or not isinstance(falsify_if, str):
                return PluginResult(
                    ok=False,
                    reason_code="FALSIFICATION_RULE_SCHEMA_ERROR",
                    detail=(
                        f"rule {rule_id!r}: trigger_expression and falsify_if "
                        "must both be strings"
                    ),
                    files_audited=tuple(files_audited),
                )

            # ------------------------------------------------------------------
            # Extract domain names from trigger_expression. An unparseable or
            # out-of-grammar trigger means the rule's domain cannot be
            # established → the NEGATIVE TEST is undecidable for this rule →
            # FAIL CLOSED. (The earlier non-blocking caveat made the C12
            # guarantee evadable: any unfalsifiable rule could ride a green
            # verdict by using one unsupported operator.)
            # ------------------------------------------------------------------
            try:
                trigger_tree = ast.parse(trigger_expr, mode="eval")
                if not _grammar_ok(trigger_tree):
                    return PluginResult(
                        ok=False,
                        reason_code="FALSIFICATION_FRAGMENT_OUT_OF_SCOPE",
                        detail=(
                            f"rule {rule_id!r}: trigger_expression uses tokens "
                            "outside the v1 bounded grammar; the NEGATIVE TEST "
                            "is undecidable for this rule — failing closed "
                            "(undecidable falsifiability must not ride a green "
                            "verdict)"
                        ),
                        files_audited=tuple(files_audited),
                    )
                domain_names = _names(trigger_tree)
            except SyntaxError:
                return PluginResult(
                    ok=False,
                    reason_code="FALSIFICATION_FRAGMENT_OUT_OF_SCOPE",
                    detail=(
                        f"rule {rule_id!r}: trigger_expression does not parse; "
                        "the NEGATIVE TEST is undecidable for this rule — "
                        "failing closed"
                    ),
                    files_audited=tuple(files_audited),
                )

            # ------------------------------------------------------------------
            # Run the NEGATIVE TEST.
            # ------------------------------------------------------------------
            result = _is_always_false(falsify_if, domain_names)

            if result is None:
                # Unsupported grammar / parse / eval failure in falsify_if —
                # the exact M6 evasion surface — FAIL CLOSED.
                return PluginResult(
                    ok=False,
                    reason_code="FALSIFICATION_FRAGMENT_OUT_OF_SCOPE",
                    detail=(
                        f"rule {rule_id!r}: falsify_if uses tokens outside the "
                        "v1 bounded grammar (or fails to parse/evaluate); the "
                        "NEGATIVE TEST is undecidable for this rule — failing "
                        "closed (an unfalsifiable rule must not become "
                        "acceptable by dressing itself in unsupported "
                        "operators)"
                    ),
                    files_audited=tuple(files_audited),
                )

            if result:
                return PluginResult(
                    ok=False,
                    reason_code="FALSIFICATION_TAUTOLOGICAL",
                    detail=f"rule {rule_id!r} is unfalsifiable",
                    files_audited=tuple(files_audited),
                )

        # ------------------------------------------------------------------
        # All rules processed (every rule decidable and non-tautological).
        # ------------------------------------------------------------------
        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail=(
                f"NEGATIVE TEST passed for all {len(rule_files)} rule(s): "
                "no unfalsifiable falsify_if expressions detected"
            ),
            files_audited=tuple(files_audited),
        )


register_typed_check("falsification_negative_test")
