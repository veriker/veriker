"""Dispatch-exhaustiveness ratchet — no silent fall-through on string-enum dispatch.

THE CLASS (GPT redteam BLOCK-01, 2026-06-12, generalized). prior_auth and
anticheat_adjudication evaluated policy comparators with guard-style dispatch::

    if comparator == ">=" and not (value >= threshold):
        return False
    if comparator == "<=" and not (value <= threshold):
        return False
    return True          # <- unknown comparator falls through: condition PASSES

A typo'd ">" / "=>" on a medical-necessity lab threshold made the condition
silently un-asserted on BOTH producer and verifier — exact agreement, GREEN
verdict, threshold never evaluated. The promotion-era code DISCLOSED this in
the module docstring and deferred the hardening, but prose has no forcing
function: nothing tracked it, and an external redteam re-derived it from
scratch five days later. The sweep then found the same shape in the cloudflare
pilot (unknown detector ``klass`` silently skipped) and a drifted fintech pack
copy (unknown ``op`` swallowed to False while its producer raises).

THE RATCHET. AST-scan every shipped Python surface for string-equality
dispatch groups — ≥2 distinct string literals compared (``==``) against the
same local name inside ``if`` tests of one function — and require each group
to handle the no-match case EXPLICITLY, via any of:

  (a) an ``else`` branch on a chain containing a group compare;
  (b) a terminal ``raise`` after the last group compare (outside the arms);
  (c) an upfront closed-world guard ``if name not in <registry>: raise``
      before the first compare.

Groups with none of these are flagged and must equal the CLOSED allowlist
below — every entry carries the reviewed justification for why its
fall-through is safe (open input vocabulary, or a terminal structured-failure
``return`` the detector cannot distinguish from a silent pass). The
comparison is EXACT in both directions: a new silent-fall-through dispatch
fails the test, and a stale allowlist entry (site fixed or removed) fails the
test, so the list can only shrink truthfully.

Scope: ``audit_bundle/**`` (verifier distribution) plus the pilots'
``_build_bundle.py`` producers and ``*_re_derivation.py`` in-bundle packs
(Gate-B mirror surfaces — a permissive producer is exactly how BLOCK-01's
no-op stayed "faithful").
"""

from __future__ import annotations

import ast
from pathlib import Path

PKG_ROOT = Path(__file__).resolve().parents[1]

# (file relative to package root, function name, dispatch variable)
#   -> reviewed justification for the silent fall-through
ALLOWLIST: dict[tuple[str, str, str], str] = {
    (
        "audit_bundle/discharge/smtlib_parser.py",
        "parse_one",
        "tok",
    ): "open token vocabulary — non-delimiter tokens are atoms, returned "
    "verbatim and fragment-checked downstream",
    (
        "audit_bundle/discharge/smtlib_parser.py",
        "_walk",
        "head",
    ): "open head vocabulary — the terminal general case walks head and every "
    "child defensively (unknown symbols are uninterpreted free vars; sort and "
    "theory checks still apply)",
    (
        "audit_bundle/discharge/z3_runner.py",
        "invoker_from_policy",
        "kind",
    ): "recorded venue is non-verdict-bearing (recheck determinism rides the "
    "rlimit lattice); deliberate best-effort venue reproduction with fallback",
    (
        "audit_bundle/discharge/z3_runner.py",
        "run",
        "first_line",
    ): "open solver-output vocabulary — terminal return is a structured "
    "SUBPROCESS_FAILURE, not a pass",
    (
        "audit_bundle/extensions/c19/cross_host_peerreview.py",
        "_check_timestamp_evidence_shape",
        "kind",
    ): "terminal return is a structured UNKNOWN_KIND hard-fail (RFC 2119 MUST), "
    "not a pass — return-shaped, so invisible to the raise heuristic",
    (
        "audit_bundle/plugins/dispatch_record_wellformed.py",
        "_parens_balanced",
        "ch",
    ): "open text vocabulary — scanning arbitrary chars for two delimiters; "
    "non-delimiter chars are legitimately no-ops",
    (
        "audit_bundle/verifier.py",
        "_step_extension_receipts",
        "status",
    ): "closed internal vocabulary from evaluate_extension_receipt; the "
    "fall-through IS the failure branch (failures.append after the chain)",
    (
        "examples/pii_redaction_minimal/pii_redaction_re_derivation.py",
        "_transition_bias",
        "src_letter",
    ): "closed internal BIOES letter vocabulary (not committed-policy input); "
    "terminal `return 0.0` is the explicit no-bias default, identical on the "
    "producer side",
    (
        "examples/pii_redaction_minimal/pii_redaction_re_derivation.py",
        "_transition_bias",
        "dst_letter",
    ): "same site as src_letter — see above",
}


def _own_nodes(func: ast.AST):
    """Yield nodes of `func` WITHOUT descending into nested function defs,
    so a dispatch group is attributed to its innermost function only."""
    stack = list(ast.iter_child_nodes(func))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            stack.extend(ast.iter_child_nodes(node))


def _str_eq_compares(test: ast.AST):
    """(name, literal, Compare) for `name == "literal"` inside an if-test."""
    for node in ast.walk(test):
        if (
            isinstance(node, ast.Compare)
            and len(node.ops) == 1
            and isinstance(node.ops[0], ast.Eq)
            and isinstance(node.left, ast.Name)
            and isinstance(node.comparators[0], ast.Constant)
            and isinstance(node.comparators[0].value, str)
        ):
            yield node.left.id, node.comparators[0].value, node


def _chain_has_else(if_node: ast.If) -> bool:
    cur = if_node
    while cur.orelse:
        if len(cur.orelse) == 1 and isinstance(cur.orelse[0], ast.If):
            cur = cur.orelse[0]
            continue
        return True
    return False


def _flag_function(func) -> list[str]:
    """Return the dispatch-variable names flagged in this function."""
    ifs = [n for n in _own_nodes(func) if isinstance(n, ast.If)]
    raises = [n for n in _own_nodes(func) if isinstance(n, ast.Raise)]

    # name -> list[(literal, compare, owning if)]
    groups: dict[str, list[tuple[str, ast.Compare, ast.If]]] = {}
    for i in ifs:
        for name, literal, cmp_ in _str_eq_compares(i.test):
            groups.setdefault(name, []).append((literal, cmp_, i))

    flagged = []
    for name, triples in groups.items():
        literals = {lit for lit, _, _ in triples}
        if len(literals) < 2:
            continue
        group_ifs = {id(i): i for _, _, i in triples}.values()
        # (a) explicit else on a chain containing a group compare
        if any(_chain_has_else(i) for i in group_ifs):
            continue
        first_line = min(c.lineno for _, c, _ in triples)
        last_line = max(c.lineno for _, c, _ in triples)
        # (b) terminal raise after the last compare, outside the group arms
        arm_raises = {
            id(r) for i in group_ifs for r in ast.walk(i) if isinstance(r, ast.Raise)
        }
        if any(r.lineno > last_line for r in raises if id(r) not in arm_raises):
            continue
        # (c) upfront closed-world guard: `if name not in <x>: raise` earlier
        guarded = False
        for i in ifs:
            if i.lineno >= first_line:
                continue
            for cmp_ in ast.walk(i.test):
                if (
                    isinstance(cmp_, ast.Compare)
                    and len(cmp_.ops) == 1
                    and isinstance(cmp_.ops[0], ast.NotIn)
                    and isinstance(cmp_.left, ast.Name)
                    and cmp_.left.id == name
                    and any(isinstance(x, ast.Raise) for x in i.body)
                ):
                    guarded = True
        if guarded:
            continue
        flagged.append(name)
    return flagged


def _scan() -> set[tuple[str, str, str]]:
    targets = sorted(
        set(PKG_ROOT.glob("audit_bundle/**/*.py"))
        | set(PKG_ROOT.glob("examples/*/_build_bundle.py"))
        | set(PKG_ROOT.glob("examples/*/*_re_derivation.py"))
    )
    found: set[tuple[str, str, str]] = set()
    for path in targets:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        rel = path.relative_to(PKG_ROOT).as_posix()
        for func in ast.walk(tree):
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for name in _flag_function(func):
                found.add((rel, func.name, name))
    return found


def test_no_silent_fallthrough_string_dispatch():
    found = _scan()
    allowed = set(ALLOWLIST)

    new = found - allowed
    assert not new, (
        "NEW silent-fall-through string-enum dispatch site(s) — a value outside "
        "the compared literals is silently ignored. On a policy/grammar surface "
        "that turns an unevaluable condition into a pass (BLOCK-01). Make the "
        "dispatch exhaustive (else-raise, terminal raise, or upfront not-in "
        "guard), or — only if the fall-through is reviewed-safe (open input "
        "vocabulary / terminal structured failure) — add an ALLOWLIST entry "
        f"with its justification: {sorted(new)!r}"
    )

    # Export-safe gating: the open-tier mirror does not carry every example
    # tree, so an entry only counts as stale when its FILE is present but the
    # site no longer flags (fixed, renamed, or made exhaustive).
    stale = {entry for entry in allowed - found if (PKG_ROOT / entry[0]).is_file()}
    assert not stale, (
        "Stale ALLOWLIST entries (site fixed, renamed, or removed) — delete "
        f"them so the list only shrinks truthfully: {sorted(stale)!r}"
    )


def test_detector_still_bites():
    """The detector flags the exact BLOCK-01 shape (guard-style comparator
    dispatch falling through to an accepting return) — guards against the
    scanner itself rotting into a vacuous pass."""
    src = (
        "def _evaluate(value, comparator, threshold):\n"
        "    if comparator == '>=' and not (value >= threshold):\n"
        "        return False\n"
        "    if comparator == '<=' and not (value <= threshold):\n"
        "        return False\n"
        "    return True\n"
    )
    func = ast.parse(src).body[0]
    assert _flag_function(func) == ["comparator"]

    hardened = (
        "def _evaluate(value, comparator, threshold):\n"
        "    if comparator == '>=':\n"
        "        if not (value >= threshold):\n"
        "            return False\n"
        "    elif comparator == '<=':\n"
        "        if not (value <= threshold):\n"
        "            return False\n"
        "    else:\n"
        "        raise ValueError('unknown comparator')\n"
        "    return True\n"
    )
    func = ast.parse(hardened).body[0]
    assert _flag_function(func) == []
