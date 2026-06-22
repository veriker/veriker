"""Tests for audit_bundle/discharge/context_substitution.py."""

from __future__ import annotations

import math

import pytest

from audit_bundle.discharge.smtlib_parser import parse_refinement
from audit_bundle.discharge.context_substitution import (
    ContextSubstitutionError,
    SmtScript,
    substitute,
)


def test_substitute_int_concrete_values():
    parsed = parse_refinement("(= (+ a b) total)")
    script = substitute(parsed, {"a": 3, "b": 4, "total": 7}, logic="QF_LIA")
    assert isinstance(script, SmtScript)
    assert "(set-logic QF_LIA)" in script.text
    assert "(assert (not (= (+ 3 4) 7)))" in script.text
    assert script.declared_symbols == ()
    assert script.free_symbols_resolved == frozenset({"a", "b", "total"})


def test_substitute_float_concrete_values():
    parsed = parse_refinement("(= (+ a b) total)")
    script = substitute(
        parsed,
        {"a": 1.5, "b": 2.5, "total": 4.0},
        logic="QF_LRA",
    )
    assert "(= (+ 1.5 2.5) 4.0)" in script.text


def test_substitute_negative_int_uses_prefix_form():
    """SMT-LIB v2 disallows -3 as a token; the substitution must emit (- 3)."""
    parsed = parse_refinement("(= n target)")
    script = substitute(parsed, {"n": -3, "target": 0}, logic="QF_LIA")
    assert "(- 3)" in script.text


def test_substitute_bool_value():
    parsed = parse_refinement("(= flag target)")
    script = substitute(parsed, {"flag": True, "target": False}, logic="QF_UF")
    assert "true" in script.text
    assert "false" in script.text


def test_substitute_with_sort_declaration_leaves_symbol_free():
    parsed = parse_refinement("(>= n 0)")
    script = substitute(
        parsed,
        {"__sorts__": {"n": "Int"}},
        logic="QF_LIA",
    )
    assert "(declare-const n Int)" in script.text
    assert script.declared_symbols == (("n", "Int"),)


def test_substitute_mixed_concrete_and_declared():
    parsed = parse_refinement("(= (+ a b) total)")
    script = substitute(
        parsed,
        {"a": 5, "b": 10, "__sorts__": {"total": "Int"}},
        logic="QF_LIA",
    )
    assert "(declare-const total Int)" in script.text
    assert "(= (+ 5 10) total)" in script.text


def test_substitute_missing_symbol_raises():
    parsed = parse_refinement("(= (+ a b) total)")
    with pytest.raises(ContextSubstitutionError) as exc_info:
        substitute(parsed, {"a": 1, "b": 2}, logic="QF_LIA")
    assert "total" in str(exc_info.value)


def test_substitute_unsupported_value_type_raises():
    parsed = parse_refinement("(= a 0)")
    with pytest.raises(ContextSubstitutionError):
        substitute(parsed, {"a": [1, 2, 3]}, logic="QF_LIA")  # type: ignore[arg-type]


def test_substitute_nan_rejected():
    parsed = parse_refinement("(= a 0.0)")
    with pytest.raises(ContextSubstitutionError) as exc_info:
        substitute(parsed, {"a": math.nan}, logic="QF_LRA")
    assert "NaN" in str(exc_info.value)


def test_substitute_infinity_rejected():
    parsed = parse_refinement("(= a 0.0)")
    with pytest.raises(ContextSubstitutionError) as exc_info:
        substitute(parsed, {"a": math.inf}, logic="QF_LRA")
    assert "Infinity" in str(exc_info.value)


def test_substitute_invalid_logic_rejected():
    parsed = parse_refinement("(= a 1)")
    with pytest.raises(ContextSubstitutionError):
        substitute(parsed, {"a": 1}, logic="MADE_UP_LOGIC")


def test_substitute_emits_check_sat_at_end():
    parsed = parse_refinement("(= a 1)")
    script = substitute(parsed, {"a": 1}, logic="QF_LIA")
    assert script.text.rstrip().endswith("(check-sat)")


def test_substitute_preserves_nested_structure():
    """Nested expressions should round-trip through serialisation."""
    parsed = parse_refinement("(or (= a 1) (= b 2))")
    script = substitute(parsed, {"a": 0, "b": 5}, logic="QF_LIA")
    assert "(or (= 0 1) (= 5 2))" in script.text


# ============================================================================
# Regressions — V16 panel review (Sonnet 4.6 2026-05-02)
# ============================================================================


def test_panel_bug_6_str_context_value_rejected_no_injection():
    """BUG 6 (panel review 2026-05-02): a `str`-typed context value used to
    be emitted verbatim, enabling SMT-LIB injection. Now rejected as
    ContextSubstitutionError."""
    parsed = parse_refinement("(>= x 0)")
    injection = "(+ 1 1)) (assert false) (check-sat\n;"
    with pytest.raises(ContextSubstitutionError) as exc:
        substitute(parsed, {"x": injection}, logic="QF_LIA")
    assert "string-typed" in str(exc.value) or "SMT-LIB injection" in str(exc.value)


def test_panel_bug_6_smtlib_literal_envelope_admitted():
    """The SmtLibLiteral envelope routes through parse_refinement, so a
    pre-validated sub-expression CAN still be substituted — but only via
    the explicit envelope, not bare strings."""
    from audit_bundle.discharge.context_substitution import SmtLibLiteral

    parsed = parse_refinement("(>= x 0)")
    # A legitimate use: substitute x with a parsed sub-expression
    script = substitute(parsed, {"x": SmtLibLiteral.parse("(+ 1 2)")}, logic="QF_LIA")
    assert "(+ 1 2)" in script.text


def test_panel_bug_6_smtlib_literal_rejects_out_of_fragment_payload():
    """SmtLibLiteral.parse routes through parse_refinement, so an attempt
    to slip a quantifier (or any out-of-fragment construct) into a context
    value via the envelope is caught at construction time."""
    from audit_bundle.discharge.context_substitution import SmtLibLiteral
    from audit_bundle.discharge.smtlib_parser import FragmentOutOfScope

    with pytest.raises(FragmentOutOfScope):
        SmtLibLiteral.parse("(forall ((y Int)) (= y 0))")


def test_panel_bug_6_strength_check_unpatched_path_would_inject(monkeypatch):
    """Strength check for BUG 6: with the str-rejection branch monkeypatched
    away, the same payload lands verbatim in the emitted script and Z3 would
    see two extra top-level forms — `(assert false)` and a second `(check-sat)`.
    Demonstrates the regression test above is guarding a real attack surface,
    not a vacuous invariant."""
    from audit_bundle.discharge import context_substitution as cs

    def broken_format_literal(value):
        if isinstance(value, str):
            return value
        return cs._format_literal(value)

    monkeypatch.setattr(cs, "_format_literal", broken_format_literal)
    parsed = parse_refinement("(>= x 0)")
    injection = "(+ 1 1)) (assert false) (check-sat\n;"
    script = cs.substitute(parsed, {"x": injection}, logic="QF_LIA")
    assert "(assert false)" in script.text
    assert injection in script.text


def test_panel_bug_8_unsupported_logic_rejected():
    """BUG 8 (panel review 2026-05-02): _SUPPORTED_LOGICS no longer admits
    QF_NIA, QF_NRA, QF_AUFLIA, QF_AUFLIRA, or ALL. Callers (or hostile
    dispatchers via __logic__ in recheck_context) cannot request out-of-
    fragment logics."""
    parsed = parse_refinement("(>= x 0)")
    for bad_logic in ("ALL", "QF_NIA", "QF_NRA", "QF_AUFLIA", "QF_AUFLIRA"):
        with pytest.raises(ContextSubstitutionError):
            substitute(parsed, {"x": 0}, logic=bad_logic)


# ============================================================================
# Regressions — Gate 3a frontier-pair (Opus 4.7 §a1, 2026-05-19)
# ============================================================================


def test_sorts_injection_admitted_by_substitute():
    """Gate 3a P1 (Opus 4.7 §a1, 2026-05-19): sort strings flow unsanitised
    into ``(declare-const <name> <sort>)`` lines in the discharge script.
    A dispatcher who supplies a sort like ``"Int) (assert false"`` injects
    a top-level form that Z3 then accepts — the assertion-set is jointly
    UNSAT and the runner classifies a forgery as DISCHARGED. _format_literal's
    str-rejection (BUG 6) covered the value-substitution path; this test
    pins the parallel sort-substitution path closed."""
    from audit_bundle.discharge.context_substitution import SubstrateInvalidSort

    parsed = parse_refinement("(>= n 0)")
    with pytest.raises(SubstrateInvalidSort) as exc:
        substitute(
            parsed,
            {"__sorts__": {"n": "Int) (assert false"}},
            logic="QF_LIA",
        )
    assert "SUBSTRATE_INVALID_SORT" in str(exc.value) or "allowlist" in str(exc.value)


def test_panel_p1_permitted_sorts_admitted():
    """Sanity: the allowlist admits the sorts production code actually uses
    (Int / Real / Bool / BitVec families). Pins the patch against
    over-rejection of legitimate inputs."""
    parsed = parse_refinement("(>= n 0)")
    for ok_sort in ("Int", "Real", "Bool", "(_ BitVec 32)", "(_ BitVec 64)"):
        script = substitute(
            parsed,
            {"__sorts__": {"n": ok_sort}},
            logic="QF_LIA",
        )
        assert f"(declare-const n {ok_sort})" in script.text


def test_panel_p1_strength_check_unpatched_path_would_inject(monkeypatch):
    """Strength check for P1: with the sort-allowlist gate monkeypatched
    away (admit every string), the same payload lands verbatim in the
    emitted script and Z3 would see an injected ``(assert false)`` top-
    level form. Demonstrates the regression test above is guarding a real
    attack surface, not a vacuous invariant. Mirrors the BUG 6 strength-
    check pattern above."""
    from audit_bundle.discharge import context_substitution as cs

    # Replace the allowlist with one that admits the adversarial sort, so
    # the substitution proceeds to emission. The patched code rejects at
    # the gate; the bypassed code reaches the f-string emit and lands the
    # injection.
    monkeypatch.setattr(
        cs,
        "_PERMITTED_SORTS",
        cs._PERMITTED_SORTS | frozenset({"Int) (assert false"}),
    )
    parsed = parse_refinement("(>= n 0)")
    script = cs.substitute(
        parsed,
        {"__sorts__": {"n": "Int) (assert false"}},
        logic="QF_LIA",
    )
    assert "(declare-const n Int) (assert false)" in script.text
    assert "(assert false)" in script.text
