"""tests/test_comparator_numeric_model.py — the optional `numeric_model` auditor
annotation on a comparator's params.

`numeric_model` is a DOCUMENTARY, closed-world-validated tag that lets an auditor
reading a SHA-pinned spec distinguish an INTENTIONALLY tolerant float comparison
(e.g. a tolerance sized for cross-platform libm non-determinism) from an
accidental coercion. Contract:
  - present + allowlisted        -> accepted, surfaced in the comparator detail
  - present + unknown/garbage    -> fail-closed (UnknownComparatorParam) at
                                    validate_comparator_params (anchor-load)
  - absent                       -> fine (back-compatible; existing specs work)
  - it NEVER changes pass/fail   -> same verdict with or without the tag
"""

from __future__ import annotations

import pytest

from audit_bundle.rederivation.comparators import (
    _NUMERIC_MODELS,
    UnknownComparatorParam,
    resolve_comparator,
    validate_comparator_params,
)


# --- validation (anchor-load) ----------------------------------------------


def test_known_numeric_model_validates_on_scalar_epsilon():
    for nm in _NUMERIC_MODELS:
        validate_comparator_params(
            "scalar_epsilon", {"epsilon": 1e-6, "numeric_model": nm}
        )  # no raise


def test_unknown_numeric_model_fails_closed():
    with pytest.raises(UnknownComparatorParam):
        validate_comparator_params(
            "scalar_epsilon", {"epsilon": 1e-6, "numeric_model": "float_whatever"}
        )


def test_non_string_numeric_model_fails_closed():
    with pytest.raises(UnknownComparatorParam):
        validate_comparator_params(
            "scalar_epsilon", {"epsilon": 1e-6, "numeric_model": 64}
        )


def test_numeric_model_absent_is_back_compatible():
    validate_comparator_params("scalar_epsilon", {"epsilon": 1e-6})  # no raise


def test_numeric_model_is_kind_independent():
    # The annotation is validated wherever it appears, not only on scalar_epsilon.
    validate_comparator_params("exact", {"numeric_model": "binary64_exact"})
    with pytest.raises(UnknownComparatorParam):
        validate_comparator_params("exact", {"numeric_model": "nope"})


# --- surfaced in detail, does not change pass/fail --------------------------


def test_marker_surfaced_in_detail_and_does_not_change_verdict():
    cmp = resolve_comparator("scalar_epsilon")
    tagged = {"epsilon": 1e-6, "numeric_model": "binary64_libm_tolerated"}
    untagged = {"epsilon": 1e-6}

    # PASS case: identical ok with/without the tag; detail names the model.
    ok_t, detail_t = cmp(1.0, 1.0 + 1e-9, tagged)
    ok_u, _ = cmp(1.0, 1.0 + 1e-9, untagged)
    assert ok_t is True and ok_u is True
    assert "numeric_model=binary64_libm_tolerated" in detail_t

    # FAIL case: identical reject; detail still names the model.
    bad_t, detail_bad = cmp(1.0, 2.0, tagged)
    bad_u, _ = cmp(1.0, 2.0, untagged)
    assert bad_t is False and bad_u is False
    assert "numeric_model=binary64_libm_tolerated" in detail_bad


def test_absent_marker_detail_has_no_suffix():
    cmp = resolve_comparator("scalar_epsilon")
    ok, detail = cmp(1.0, 1.0, {"epsilon": 1e-6})
    assert ok is True
    assert "numeric_model" not in detail
