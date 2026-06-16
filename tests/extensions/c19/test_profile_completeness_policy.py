"""Tests for the CC-2b D1 profile-completeness policy (G1/G2 + floor resolution).

The security-critical assertions are the *rejections*: a non-monotone policy
must fail to construct (G1), a below-floor / incomparable declared profile must
REJECT (D1), and an old / expired / too-young policy target must be inadmissible
(G2). A policy that silently accepts any of these relocates the downgrade.
"""

from __future__ import annotations

import pytest

from audit_bundle.extensions.c19.profile_completeness_policy import (
    NO_TOLERANCE_BOUND,
    POLICY_BORN_BEFORE_CUTOFF,
    POLICY_EPOCH_BELOW_FLOOR,
    POLICY_EXPIRED,
    PROFILE_DECLARATION_REQUIRED_AT_FLOOR,
    PROFILE_DECLARED_BELOW_PINNED_FLOOR,
    PROFILE_DECLARED_UNKNOWN,
    PROFILE_NOT_COMPARABLE_TO_FLOOR,
    CompletenessPolicy,
    ObligationLattice,
    Profile,
    policy_admissible,
    resolve_effective_profile,
)

# --- fixtures: a small but representative 3-profile lattice ---------------
# baseline <= standard <= high (linear chain), plus an incomparable
# jurisdictional branch `high_jp` above `standard` but not comparable to `high`.

TSA = "per_batch_tsa_root"
RT = "per_event_roughtime"
XH = "cross_host_authenticators"

_O_TSA_WEAK = ObligationLattice(
    required_checks={"root_bound_to_events"}, min_count=1, distinctness_level=1
)
_O_TSA_STRONG = ObligationLattice(
    required_checks={"root_bound_to_events", "distinct_tsa_quorum", "bls_required"},
    min_count=2,
    distinctness_level=2,
    max_time_tolerance_ms=60_000,
)
_O_RT_STRONG = ObligationLattice(
    required_checks={"coverage_bijection"}, coverage_level=2
)


def _good_policy() -> CompletenessPolicy:
    baseline = Profile("baseline")
    standard = Profile(
        "standard",
        required_structures={TSA},
        obligations={TSA: _O_TSA_WEAK},
    )
    high = Profile(
        "high",
        required_structures={TSA, RT},
        obligations={TSA: _O_TSA_STRONG, RT: _O_RT_STRONG},
    )
    high_jp = Profile(
        "high_jp",
        required_structures={TSA, XH},
        obligations={TSA: _O_TSA_STRONG, XH: ObligationLattice(min_count=1)},
    )
    return CompletenessPolicy(
        profiles={p.profile_id: p for p in (baseline, standard, high, high_jp)},
        order_edges={("standard", "baseline"), ("high", "standard"),
                     ("high_jp", "standard")},
        policy_epoch=5,
    )


# --- preorder ----------------------------------------------------------------


def test_preorder_reachability_and_comparability():
    pol = _good_policy()
    assert pol.geq("high", "baseline")  # transitive
    assert pol.geq("high", "high")  # reflexive
    assert not pol.geq("baseline", "high")
    # high and high_jp share `standard` below them but neither dominates.
    assert not pol.comparable("high", "high_jp")
    assert pol.comparable("high", "standard")


# --- G1: monotonicity enforced at construction -------------------------------


def test_nonmonotone_required_set_rejected_at_construction():
    # high >= standard but R(high) drops TSA that R(standard) requires.
    standard = Profile("standard", required_structures={TSA},
                        obligations={TSA: _O_TSA_WEAK})
    high = Profile("high", required_structures={RT},
                   obligations={RT: _O_RT_STRONG})
    with pytest.raises(ValueError, match="non-monotone policy"):
        CompletenessPolicy(
            profiles={"standard": standard, "high": high},
            order_edges={("high", "standard")},
        )


def test_nonmonotone_obligation_rejected_at_construction():
    # high >= standard, both require TSA, but high's obligation is WEAKER.
    standard = Profile("standard", required_structures={TSA},
                       obligations={TSA: _O_TSA_STRONG})
    high = Profile("high", required_structures={TSA},
                   obligations={TSA: _O_TSA_WEAK})
    with pytest.raises(ValueError, match="non-monotone policy"):
        CompletenessPolicy(
            profiles={"standard": standard, "high": high},
            order_edges={("high", "standard")},
        )


def test_good_policy_constructs():
    pol = _good_policy()
    assert pol.required_structures("high") == frozenset({TSA, RT})
    assert pol.effective_required_structures("high_jp", floor="standard") == (
        frozenset({TSA, XH})
    )


# --- ObligationLattice strength ordering --------------------------------------


def test_obligation_strength_each_dimension():
    base = ObligationLattice(required_checks={"a"}, min_count=1,
                             max_time_tolerance_ms=100, distinctness_level=1,
                             coverage_level=1)
    assert base.at_least_as_strong_as(base)
    # superset of checks = stronger
    assert ObligationLattice(required_checks={"a", "b"}, min_count=1,
                             max_time_tolerance_ms=100, distinctness_level=1,
                             coverage_level=1).at_least_as_strong_as(base)
    # larger min_count = stronger; smaller tolerance = stronger
    assert ObligationLattice(required_checks={"a"}, min_count=2,
                             max_time_tolerance_ms=50, distinctness_level=1,
                             coverage_level=1).at_least_as_strong_as(base)
    # weaker on any one dimension breaks >=
    assert not ObligationLattice(required_checks={"a"}, min_count=0,
                                 max_time_tolerance_ms=100, distinctness_level=1,
                                 coverage_level=1).at_least_as_strong_as(base)


def test_tolerance_unbounded_is_weakest():
    bounded = ObligationLattice(max_time_tolerance_ms=10_000)
    unbounded = ObligationLattice(max_time_tolerance_ms=NO_TOLERANCE_BOUND)
    assert bounded.at_least_as_strong_as(unbounded)
    assert not unbounded.at_least_as_strong_as(bounded)


# --- Profile invariants ------------------------------------------------------


def test_required_structure_without_obligation_rejected():
    with pytest.raises(ValueError, match="without an obligation"):
        Profile("p", required_structures={TSA}, obligations={})


def test_obligation_for_non_required_structure_rejected():
    with pytest.raises(ValueError, match="non-required"):
        Profile("p", required_structures=set(), obligations={TSA: _O_TSA_WEAK})


# --- D1 floor resolution -----------------------------------------------------


def test_declared_above_floor_grades_at_declared():
    pol = _good_policy()
    eff, reason = resolve_effective_profile(pol, floor="standard", declared="high")
    assert (eff, reason) == ("high", None)


def test_declared_equal_floor_grades_at_declared():
    pol = _good_policy()
    eff, reason = resolve_effective_profile(pol, floor="standard",
                                            declared="standard")
    assert (eff, reason) == ("standard", None)


def test_declared_below_floor_rejected():
    pol = _good_policy()
    eff, reason = resolve_effective_profile(pol, floor="high", declared="standard")
    assert eff is None
    assert reason == PROFILE_DECLARED_BELOW_PINNED_FLOOR


def test_declared_incomparable_to_floor_rejected():
    pol = _good_policy()
    # high_jp is incomparable to high.
    eff, reason = resolve_effective_profile(pol, floor="high", declared="high_jp")
    assert eff is None
    assert reason == PROFILE_NOT_COMPARABLE_TO_FLOOR


def test_declared_unknown_rejected():
    pol = _good_policy()
    eff, reason = resolve_effective_profile(pol, floor="standard",
                                            declared="bogus-profile")
    assert eff is None
    assert reason == PROFILE_DECLARED_UNKNOWN


def test_absent_declaration_grades_at_floor():
    pol = _good_policy()
    eff, reason = resolve_effective_profile(pol, floor="standard", declared=None)
    assert (eff, reason) == ("standard", None)


def test_absent_declaration_required_at_stakes_rejected():
    pol = _good_policy()
    eff, reason = resolve_effective_profile(
        pol, floor="high", declared=None, require_declaration=True
    )
    assert eff is None
    assert reason == PROFILE_DECLARATION_REQUIRED_AT_FLOOR


def test_unknown_floor_is_construction_error_not_silent():
    pol = _good_policy()
    with pytest.raises(ValueError, match="not a profile"):
        resolve_effective_profile(pol, floor="nonexistent", declared="high")


# --- G2 anti-rollback --------------------------------------------------------


def test_policy_epoch_below_floor_inadmissible():
    pol = _good_policy()  # epoch 5
    ok, reason = policy_admissible(pol, policy_epoch_floor=6, now_ms=1_000)
    assert not ok and reason == POLICY_EPOCH_BELOW_FLOOR


def test_policy_at_or_above_epoch_floor_admissible():
    pol = _good_policy()
    ok, reason = policy_admissible(pol, policy_epoch_floor=5, now_ms=1_000)
    assert ok and reason is None


def test_expired_policy_inadmissible():
    baseline = Profile("baseline")
    pol = CompletenessPolicy(profiles={"baseline": baseline}, policy_epoch=1,
                             expiry_ms=10_000)
    ok, reason = policy_admissible(pol, policy_epoch_floor=0, now_ms=10_001)
    assert not ok and reason == POLICY_EXPIRED


def test_born_before_cutoff_inadmissible():
    baseline = Profile("baseline")
    pol = CompletenessPolicy(profiles={"baseline": baseline}, policy_epoch=1,
                             born_at_ms=500)
    ok, reason = policy_admissible(pol, policy_epoch_floor=0, now_ms=1_000,
                                   born_after_ms=600)
    assert not ok and reason == POLICY_BORN_BEFORE_CUTOFF


def test_born_after_cutoff_admissible():
    baseline = Profile("baseline")
    pol = CompletenessPolicy(profiles={"baseline": baseline}, policy_epoch=1,
                             born_at_ms=700, expiry_ms=10_000)
    ok, reason = policy_admissible(pol, policy_epoch_floor=0, now_ms=1_000,
                                   born_after_ms=600)
    assert ok and reason is None
