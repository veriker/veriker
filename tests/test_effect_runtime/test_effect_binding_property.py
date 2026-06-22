"""Hypothesis property-based tests for effect_binding.

s15-010 deliverable: round-trip allowlist invariants — for any subset of
the locked v0.1 vocabulary, the translation function preserves the
declared-effects-bound-observed-effects soundness property.

These tests are the closest thing to a mechanized check of the
effect-containment statement from EFFECT_CALCULUS.md §"Soundness
statement" without a Lean proof — Hypothesis enumerates ~hundreds of
declared-effect subsets and confirms the round-trip identity holds.
"""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings, strategies as st

from audit_bundle.effect_runtime.effect_binding import (
    EFFECT_LABEL_TO_IMPORTS,
    IMPORT_TO_EFFECT_LABEL,
    LOCKED_LABELS,
    RESERVED_LABELS,
    EffectBindingError,
    label_admits_import,
    reverse_map_import,
    translate_effects_to_allowlist,
)


_LOCKED_LIST = sorted(LOCKED_LABELS)
_RESERVED_LIST = sorted(RESERVED_LABELS)
_ALL_IMPORTS = sorted(IMPORT_TO_EFFECT_LABEL.keys())


# A strategy that picks an arbitrary subset of the locked vocabulary,
# wrapping each as a dict (the on-the-wire dispatch_record.effect shape).
def _effect_dict_strategy() -> st.SearchStrategy[dict]:
    return st.builds(
        lambda labels: {label: [] for label in labels},
        st.lists(
            st.sampled_from(_LOCKED_LIST), unique=True, min_size=0,
            max_size=len(_LOCKED_LIST),
        ),
    )


# ---------------------------------------------------------------------------
# Property 1 — every translated import reverse-maps to one of the
# declared effect labels (effect-containment soundness)
# ---------------------------------------------------------------------------


@settings(deadline=None, max_examples=400,
          suppress_health_check=[HealthCheck.too_slow])
@given(declared=_effect_dict_strategy())
def test_property_every_import_admitted_by_a_declared_label(declared):
    """`reverse_map_import(imp) ∈ declared.keys()` for every imp in
    f(declared). This is the formal restatement of effect-containment:
    if the dispatcher runs in the f(declared)-bound sandbox, every
    import it could possibly call is admitted by an effect it declared."""
    allowlist = translate_effects_to_allowlist(declared, mode="wasm")
    for imp in allowlist:
        admitted_label = reverse_map_import(imp)
        assert admitted_label is not None, \
            f"import {imp!r} not in reverse map"
        assert admitted_label in declared, (
            f"import {imp!r} admitted by label {admitted_label!r}, "
            f"which is NOT among declared effects {sorted(declared.keys())}"
        )


# ---------------------------------------------------------------------------
# Property 2 — translation is monotone in declared effects (subset-preserving)
# ---------------------------------------------------------------------------


@settings(deadline=None, max_examples=200,
          suppress_health_check=[HealthCheck.too_slow])
@given(
    declared=_effect_dict_strategy(),
    extra_label=st.sampled_from(_LOCKED_LIST),
)
def test_property_translation_is_monotone(declared, extra_label):
    """Adding a label to declared effects can only ADD imports to the
    allowlist, never remove or replace. Formally:
      f(L) ⊆ f(L ∪ {extra_label})."""
    base_allow = translate_effects_to_allowlist(declared, mode="wasm")
    extended = dict(declared)
    extended[extra_label] = []
    extended_allow = translate_effects_to_allowlist(extended, mode="wasm")
    assert base_allow <= extended_allow


# ---------------------------------------------------------------------------
# Property 3 — translation is union-distributive
# ---------------------------------------------------------------------------


@settings(deadline=None, max_examples=200,
          suppress_health_check=[HealthCheck.too_slow])
@given(
    a=_effect_dict_strategy(),
    b=_effect_dict_strategy(),
)
def test_property_union_distributive(a, b):
    """f(A ∪ B) = f(A) ∪ f(B). The allowlist of the union of two effect
    dicts equals the union of the per-dict allowlists."""
    union = dict(a)
    union.update(b)
    f_union = translate_effects_to_allowlist(union, mode="wasm")
    f_a = translate_effects_to_allowlist(a, mode="wasm")
    f_b = translate_effects_to_allowlist(b, mode="wasm")
    assert f_union == f_a | f_b


# ---------------------------------------------------------------------------
# Property 4 — empty effect ↔ empty allowlist (terminal case)
# ---------------------------------------------------------------------------


def test_property_empty_effect_means_empty_allowlist():
    """f({}) = ∅. Pure-compute dispatch admits no imports."""
    assert translate_effects_to_allowlist({}, mode="wasm") == frozenset()


# ---------------------------------------------------------------------------
# Property 5 — reserved label always rejects under mode='wasm'
# ---------------------------------------------------------------------------


@settings(deadline=None, max_examples=200,
          suppress_health_check=[HealthCheck.too_slow])
@given(
    declared=_effect_dict_strategy(),
    reserved=st.sampled_from(_RESERVED_LIST),
)
def test_property_reserved_label_always_rejects(declared, reserved):
    """No matter what other labels are declared, adding ANY reserved
    label under mode='wasm' makes the translation reject."""
    contaminated = dict(declared)
    contaminated[reserved] = []
    try:
        translate_effects_to_allowlist(contaminated, mode="wasm")
    except EffectBindingError:
        pass
    else:
        raise AssertionError(
            f"reserved label {reserved!r} silently admitted under "
            f"mode='wasm' alongside {sorted(declared.keys())}"
        )


# ---------------------------------------------------------------------------
# Property 6 — reverse-map ⊕ label_admits_import are mutually consistent
# ---------------------------------------------------------------------------


@settings(deadline=None, max_examples=200,
          suppress_health_check=[HealthCheck.too_slow])
@given(imp=st.sampled_from(_ALL_IMPORTS))
def test_property_reverse_map_implies_label_admits(imp):
    """For every import in the substrate vocabulary,
    label_admits_import(reverse_map(imp), imp) must be True."""
    label = reverse_map_import(imp)
    assert label is not None
    assert label_admits_import(label, imp)


@settings(deadline=None, max_examples=200,
          suppress_health_check=[HealthCheck.too_slow])
@given(imp=st.sampled_from(_ALL_IMPORTS), wrong=st.sampled_from(_LOCKED_LIST))
def test_property_label_admits_import_unique(imp, wrong):
    """No import is admitted by two different labels."""
    correct = reverse_map_import(imp)
    if wrong == correct:
        return  # vacuous
    assert not label_admits_import(wrong, imp)
