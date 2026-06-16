"""Adversarial tests for audit_bundle/discharge/smtlib_parser.py — fragment lock.

The v0.1 fragment per o_kernel/REFINEMENT_TYPES.md is QF_LIA + QF_BV + QF_LRA + QF_UF.
Anything else MUST raise FragmentOutOfScope at parse time.

These tests are written first — against a deliberately-broken parser stand-in
that accepts every input (broken-first discipline per the v0.2 sprint plan).
The full set of out-of-fragment shapes below MUST raise FragmentOutOfScope; the
in-fragment positive cases MUST parse cleanly.

Out-of-fragment categories exercised:
  1. Quantifiers       — forall, exists
  2. Arrays            — select / store / Array sort
  3. Strings           — String sort, str.* ops
  4. Recursive types   — declare-datatype / declare-datatypes
  5. Nonlinear mul     — (* x y) where both x,y are variables
  6. Nonlinear div     — (/ x y) where divisor y is a variable (LRA admits / by
                         literal only, so var divisor is non-LRA)

Each category has at least one negative test. There is also a positive test
suite covering plausible in-fragment refinements (sum invariants, bit-vector
range checks, uninterpreted-function equalities) that MUST pass.
"""

from __future__ import annotations

import pytest

from audit_bundle.discharge.smtlib_parser import (
    FragmentOutOfScope,
    ParsedRefinement,
    SmtLibParseError,
    parse_refinement,
)


# ============================================================================
# 1. Quantifier rejection
# ============================================================================


@pytest.mark.parametrize(
    "formula",
    [
        "(forall ((x Int)) (= x 0))",
        "(exists ((y Int)) (> y 5))",
        "(forall ((x Int) (y Int)) (= (+ x y) (+ y x)))",
        "(not (forall ((z Real)) (>= z 0.0)))",
    ],
)
def test_quantifier_rejected(formula):
    with pytest.raises(FragmentOutOfScope) as exc_info:
        parse_refinement(formula)
    assert "quantifier" in str(
        exc_info.value
    ).lower() or exc_info.value.offending_token in {"forall", "exists"}


# ============================================================================
# 2. Array rejection
# ============================================================================


@pytest.mark.parametrize(
    "formula",
    [
        "(= (select arr 3) 7)",
        "(= (store arr 0 5) arr2)",
        "((as const (Array Int Int)) 0)",
    ],
)
def test_arrays_rejected(formula):
    with pytest.raises(FragmentOutOfScope) as exc_info:
        parse_refinement(formula)
    msg = str(exc_info.value).lower()
    tok = exc_info.value.offending_token.lower()
    assert "array" in msg or tok in {"select", "store", "array"}


# ============================================================================
# 3. String rejection
# ============================================================================


@pytest.mark.parametrize(
    "formula",
    [
        '(str.contains x "hello")',
        "(= (str.len s) 5)",
        "(str.++ a b)",
    ],
)
def test_strings_rejected(formula):
    with pytest.raises(FragmentOutOfScope) as exc_info:
        parse_refinement(formula)
    msg = str(exc_info.value).lower()
    assert "string" in msg or exc_info.value.offending_token.startswith("str.")


# ============================================================================
# 3b. 'as' short-form must not bypass the fragment check (M5 regression)
# ============================================================================
# A short/malformed (as <expr>) — fewer than 3 elements — previously skipped
# the operand walk and returned OK, letting a quantifier/array/string nested
# inside escape the fragment check. The coerced expression MUST be walked
# regardless of arity.


@pytest.mark.parametrize(
    "formula",
    [
        "(= (as (exists ((x Int)) (> x 0))) 1)",  # the reported PoC
        "(as (exists ((y Int)) (> y 5)))",  # bare short-as wrapping a quantifier
        "(as (forall ((z Int)) (= z 0)))",
        "(as (select arr 3))",  # array op under short-as
        "(as (str.len s))",  # string op under short-as
    ],
)
def test_as_short_form_does_not_bypass_fragment(formula):
    with pytest.raises(FragmentOutOfScope):
        parse_refinement(formula)


def test_as_well_formed_coercion_still_parses():
    """The canonical (as <expr> <sort>) with in-fragment content still parses."""
    parsed = parse_refinement("(= (as x Int) 0)")
    assert "x" in parsed.free_symbols


# ============================================================================
# 3c. division-family / indexed-sort partial-walk must not bypass (sweep)
# ============================================================================
# Sweep siblings of the M5 `as` early-return: branches that walk children only
# partially (under a length/shape guard) let nested out-of-fragment constructs
# escape. `/`, `div`, `mod` checked only the first divisor and dropped expr[3:];
# `_check_sort` inspected only sort[1] of an indexed sort.


@pytest.mark.parametrize(
    "formula",
    [
        "(/ x 2 (exists ((y Int)) (> y 0)))",  # quantifier in a later divisor slot
        "(/ x 2 (select arr 0))",  # array op in a later divisor slot
        "(div x 2 (exists ((y Int)) (> y 0)))",
        "(mod x 2 (str.len s))",  # string op in a later operand
    ],
)
def test_division_family_later_operand_not_bypassed(formula):
    with pytest.raises(FragmentOutOfScope):
        parse_refinement(formula)


@pytest.mark.parametrize(
    "formula",
    [
        "(= (as x (_ FooSort String)) 0)",  # string in a later index slot
        "(= (as x (_ FooSort Array Int Int)) 0)",  # array in a later index slot
        "(= (as x (_ Foo (Array Int Int))) 0)",  # array nested in a compound sort
    ],
)
def test_indexed_sort_string_array_not_bypassed(formula):
    with pytest.raises(FragmentOutOfScope):
        parse_refinement(formula)


def test_division_and_indexed_sort_in_fragment_still_parse():
    """Legitimate division-by-literal and (_ BitVec N) sorts must still parse."""
    assert parse_refinement("(= (/ x 2.0) 1.0)").free_symbols == frozenset({"x"})
    assert parse_refinement("(= (div x 2) 0)").free_symbols == frozenset({"x"})
    parsed = parse_refinement("(= (as bv (_ BitVec 32)) #x00000000)")
    assert "bv" in parsed.free_symbols


# ============================================================================
# 4. Recursive datatype rejection
# ============================================================================


@pytest.mark.parametrize(
    "formula",
    [
        "(declare-datatype Tree (par (T) ((leaf) (node (val T) (children Tree)))))",
        "(declare-datatypes ((Pair 0)) (((mk (a Int) (b Int)))))",
        "(declare-rec foo ((x Int)) Int)",
    ],
)
def test_recursive_datatype_rejected(formula):
    with pytest.raises(FragmentOutOfScope) as exc_info:
        parse_refinement(formula)
    msg = str(exc_info.value).lower()
    assert (
        "datatype" in msg
        or "recursive" in msg
        or exc_info.value.offending_token.startswith("declare-")
    )


# ============================================================================
# 5. Nonlinear multiplication rejection (NIA)
# ============================================================================


@pytest.mark.parametrize(
    "formula",
    [
        "(= (* a b) total)",  # both factors are variables — NIA
        "(>= (* x x) 0)",  # square — NIA
        "(= (* a (* b c)) result)",  # triple product — NIA
    ],
)
def test_nonlinear_mul_rejected(formula):
    with pytest.raises(FragmentOutOfScope) as exc_info:
        parse_refinement(formula)
    msg = str(exc_info.value).lower()
    assert "nonlinear" in msg or "nia" in msg or exc_info.value.offending_token == "*"


# ============================================================================
# 6. Nonlinear division rejection
# ============================================================================


@pytest.mark.parametrize(
    "formula",
    [
        "(= (/ a b) c)",  # var divisor — non-LRA
        "(>= (div x y) 0)",  # int div with var divisor
    ],
)
def test_nonlinear_div_rejected(formula):
    with pytest.raises(FragmentOutOfScope) as exc_info:
        parse_refinement(formula)
    msg = str(exc_info.value).lower()
    assert "nonlinear" in msg or exc_info.value.offending_token in {"/", "div"}


# ============================================================================
# In-fragment positive tests — must parse cleanly + extract free symbols
# ============================================================================


def test_qf_lra_sum_invariant_parses():
    """The U1 Shapley Flow invariant from REFINEMENT_TYPES.md."""
    parsed = parse_refinement("(= (+ a b c) total)")
    assert isinstance(parsed, ParsedRefinement)
    assert {"a", "b", "c", "total"}.issubset(parsed.free_symbols)


def test_qf_lia_linear_inequality_parses():
    parsed = parse_refinement("(>= n 0)")
    assert "n" in parsed.free_symbols


def test_qf_lia_linear_with_constant_coefficient_parses():
    """Linear with literal coefficient is in-fragment (not nonlinear)."""
    parsed = parse_refinement("(= (* 3 x) y)")
    assert {"x", "y"}.issubset(parsed.free_symbols)


def test_qf_lra_real_division_by_literal_parses():
    """LRA admits division by a literal."""
    parsed = parse_refinement("(<= (/ x 2.0) 1.0)")
    assert "x" in parsed.free_symbols


def test_qf_bv_bitvector_constraint_parses():
    parsed = parse_refinement("(= ((_ extract 7 0) bv) #x00)")
    assert "bv" in parsed.free_symbols


def test_qf_uf_uninterpreted_function_parses():
    """Uninterpreted f applied to args is QF_UF."""
    parsed = parse_refinement("(= (f x) (f y))")
    assert {"f", "x", "y"}.issubset(parsed.free_symbols) or {"x", "y"}.issubset(
        parsed.free_symbols
    )


def test_qf_lia_modulo_parses():
    """`mod` is in QF_LIA — was incorrectly banned in C15 v0.1 regex; v0.2
    parser must admit it."""
    parsed = parse_refinement("(= (mod x 3) 0)")
    assert "x" in parsed.free_symbols


def test_qf_lia_div_by_literal_parses():
    """Integer `div` by literal is in QF_LIA."""
    parsed = parse_refinement("(= (div x 2) y)")
    assert {"x", "y"}.issubset(parsed.free_symbols)


# ============================================================================
# Lexical / syntactic rejection — separate from fragment scope
# ============================================================================


@pytest.mark.parametrize(
    "formula,expected_exc",
    [
        ("", SmtLibParseError),
        ("   ", SmtLibParseError),
        ("(= a b", SmtLibParseError),  # unbalanced
        ("(= a b))", SmtLibParseError),  # unbalanced
        ('(= "unterminated', SmtLibParseError),  # bad string literal
    ],
)
def test_syntax_errors_rejected(formula, expected_exc):
    with pytest.raises(expected_exc):
        parse_refinement(formula)


def test_non_string_input_rejected():
    with pytest.raises((SmtLibParseError, TypeError)):
        parse_refinement(123)  # type: ignore[arg-type]


def test_offending_token_field_set_on_fragment_violation():
    """The FragmentOutOfScope exception carries the offending token so the C16
    plugin's error detail can name it."""
    with pytest.raises(FragmentOutOfScope) as exc_info:
        parse_refinement("(forall ((x Int)) (= x 0))")
    assert exc_info.value.offending_token != ""


# ============================================================================
# Regressions — V16 panel review (Sonnet 4.6 2026-05-02)
# ============================================================================


def test_let_binders_must_be_tuple_not_atom():
    """BUG 3 (panel review 2026-05-02): malformed `(let x body)` where binders
    is a bare atom must raise SmtLibParseError, not silently bypass the body
    walk. Prior code returned without walking expr[2], allowing quantifiers
    inside `body` to escape the fragment check."""
    with pytest.raises(SmtLibParseError):
        parse_refinement("(let x (forall ((y Int)) (= y 0)))")


def test_let_binder_pair_shape_required():
    """BUG 3 (panel review 2026-05-02): a binder must be a (name value) pair;
    a bare atom inside the binders tuple is malformed."""
    with pytest.raises(SmtLibParseError):
        parse_refinement("(let (badbinder) body)")


def test_let_trailing_children_walked():
    """BUG 4 (panel review 2026-05-02): `(let ((x 1)) body extra)` had only
    `body` (expr[2]) walked; trailing children escaped fragment check.
    Now every child after the binders is walked."""
    with pytest.raises(FragmentOutOfScope):
        parse_refinement("(let ((x 1)) (= x 0) (forall ((y Int)) (= y 0)))")


def test_let_in_fragment_still_passes():
    """Sanity: a well-formed in-fragment `let` continues to parse cleanly."""
    parsed = parse_refinement("(let ((y (+ a b))) (= y total))")
    # `y` is locally bound and should not appear in free_symbols
    assert "y" not in parsed.free_symbols
    assert {"a", "b", "total"}.issubset(parsed.free_symbols)


def test_indexed_identifier_walks_subexpressions():
    """BUG 5 (panel review 2026-05-02): `(_ extract <subexpr> 0)` had every
    child after expr[1] silently skipped. A quantifier (or any out-of-
    fragment construct) hidden inside an index position now raises."""
    with pytest.raises(FragmentOutOfScope):
        parse_refinement("(= (_ extract (forall ((x Int)) (= x 0)) 0) #x00)")


def test_indexed_identifier_normal_extract_still_passes():
    """Sanity: `((_ extract 7 0) bv)` continues to parse cleanly — the
    BUG 5 fix walks all children but legitimate uses still succeed."""
    parsed = parse_refinement("(= ((_ extract 7 0) bv) #x00)")
    assert "bv" in parsed.free_symbols
