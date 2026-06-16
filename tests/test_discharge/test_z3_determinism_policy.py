"""Determinism-doctrine tests for the C16 Z3 recheck (tribunal-ratified 2026-06-10).

Covers the three-cell divergence matrix, the coarse verdict lattice, the
pinned __solver_policy__ (HMAC-bound via recheck_context), the verifier-side
under-resourcing floor, and the version-skew / accepted_z3_versions authority
rules. Companion to the legacy-record cases in test_refinement_discharge_v0_2.py.

The matrix under test:

    claim == replay (coarse)                     -> confirmed (PASS)
    claim != replay, replay AUTHORITATIVE        -> DISCHARGE_STATUS_VERIFIER_DIVERGENCE (REJECT)
    claim != replay, replay NON-AUTHORITATIVE    -> DISCHARGE_STATUS_NOT_CONFIRMED (clean-ERROR)
    discharged <-> failed                        -> ALWAYS divergence (sat/unsat contradiction)
    pinned rlimit < floor on not_proved claim    -> DISCHARGE_UNDER_RESOURCED (clean-ERROR)
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from audit_bundle.plugins.refinement_discharge import (
    DEFAULT_MIN_PINNED_RLIMIT,
    RefinementDischargeCheck,
)
from audit_bundle.discharge.verifier_signing import (
    VerifierSigningKey,
    sign_and_write,
)
from audit_bundle.discharge.z3_runner import (
    FakeZ3Invoker,
    InProcessZ3Invoker,
    Z3Result,
    Z3Status,
)


class _Manifest:
    def __init__(self, dispatch_records=(), bundle_id="bundle-test-001"):
        self.dispatch_records = dispatch_records
        self.bundle_id = bundle_id


_KEY = VerifierSigningKey(verifier_id="v-kernel-test", secret=b"deadbeef" * 4)
_BUNDLE_ID = "bundle-test-001"

# A fake-solver identity above the floor; pinned policies in these tests
# either copy it exactly (authoritative) or perturb one field.
_FAKE_IDENTITY = {
    "invoker_kind": "fake",
    "random_seed": 0,
    "rlimit": 2_000_000,
    "z3_version": "4.16.0",
}


def _write_obligation(tmp_path: Path) -> tuple[str, str]:
    rel = "proofs/obligation.smt2"
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    data = b"-- obligation\n"
    p.write_bytes(data)
    return rel, hashlib.sha256(data).hexdigest()


def _signed_record(
    tmp_path,
    *,
    claimed: str,
    solver_policy: dict | None = None,
    context_overrides: dict | None = None,
):
    """Build + verifier-sign an smt-z3 record whose recheck_context carries
    the given pinned __solver_policy__ (None = legacy record, no pin)."""
    rel, sha = _write_obligation(tmp_path)
    context = {"a": 1, "b": 2, "total": 3, "__logic__": "QF_LIA"}
    if solver_policy is not None:
        context["__solver_policy__"] = dict(solver_policy)
    if context_overrides:
        context.update(context_overrides)
    record = {
        "schema_version": "0.1",
        "op": {"kind": "COMPUTE", "name": "verify"},
        "inputs": [],
        "outputs": [
            {"name": "r", "type": {"base": "Int", "refine": "(= (+ a b) total)"}}
        ],
        "effect": {},
        "predicates": [],
        "stamp_declared": "INTERNAL_BENCHMARK",
        "stamp_observed": None,
        "proof": {
            "kind": "smt-z3",
            "obligation_uri": rel,
            "obligation_sha": sha,
            "discharge_status": claimed,
            "recheck_context": context,
        },
    }
    return sign_and_write(
        record,
        key=_KEY,
        discharge_status=claimed,
        z3_status=claimed,
        bundle_id=_BUNDLE_ID,
    )


def _fake(responses, **identity):
    merged = dict(_FAKE_IDENTITY)
    merged.update(identity)
    return FakeZ3Invoker(
        responses,
        z3_version=merged["z3_version"],
        random_seed=merged["random_seed"],
        rlimit=merged["rlimit"],
    )


def _z3result(status: Z3Status) -> Z3Result:
    return Z3Result(status, f"scripted {status.value}", 0.01, "fake")


# ============================================================================
# Coarse lattice
# ============================================================================


def test_claimed_timeout_vs_replayed_unknown_is_not_a_divergence(tmp_path):
    """timeout and unknown share the not_proved coarse cell: the fine split
    rides Z3 reason strings / budget mechanics that never bear verdict
    weight. Pre-doctrine, this exact pair was a false REJECT."""
    signed = _signed_record(tmp_path, claimed="timeout")
    plugin = RefinementDischargeCheck(
        recheck_key=_KEY, recheck_invoker=_fake([_z3result(Z3Status.UNKNOWN)])
    )
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is True, result.detail
    assert result.reason_code == "PASS"


def test_honest_unknown_above_floor_confirms(tmp_path):
    signed = _signed_record(tmp_path, claimed="unknown", solver_policy=_FAKE_IDENTITY)
    plugin = RefinementDischargeCheck(
        recheck_key=_KEY, recheck_invoker=_fake([_z3result(Z3Status.UNKNOWN)])
    )
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is True, result.detail


# ============================================================================
# Cell 2 — authoritative replay contradicts the claim -> divergence REJECT
# ============================================================================


def test_authoritative_mismatch_is_divergence_reject(tmp_path):
    """Pinned policy replayed exactly (same kind/seed/rlimit/version) and the
    outcome still contradicts the signed claim: deterministic replay leaves
    forgery or corruption as the only explanation."""
    signed = _signed_record(
        tmp_path, claimed="discharged", solver_policy=_FAKE_IDENTITY
    )
    plugin = RefinementDischargeCheck(
        recheck_key=_KEY, recheck_invoker=_fake([_z3result(Z3Status.UNKNOWN)])
    )
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is False
    assert result.incomplete is False
    assert result.reason_code == "DISCHARGE_STATUS_VERIFIER_DIVERGENCE"
    assert "pinned solver policy" in result.detail


def test_conclusive_contradiction_rejects_even_without_pin(tmp_path):
    """discharged vs failed is sat<->unsat — no budget, seed, or version skew
    explains it. Authority is irrelevant; legacy records still REJECT."""
    signed = _signed_record(tmp_path, claimed="discharged")  # no pin
    plugin = RefinementDischargeCheck(
        recheck_key=_KEY, recheck_invoker=_fake([_z3result(Z3Status.FAILED)])
    )
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is False
    assert result.incomplete is False
    assert result.reason_code == "DISCHARGE_STATUS_VERIFIER_DIVERGENCE"


# ============================================================================
# Cell 3 — non-authoritative replay mismatch -> NOT_CONFIRMED (clean-ERROR)
# ============================================================================


def test_version_skew_mismatch_is_not_confirmed(tmp_path):
    pinned = dict(_FAKE_IDENTITY, z3_version="4.15.3")  # minted on older z3
    signed = _signed_record(tmp_path, claimed="discharged", solver_policy=pinned)
    plugin = RefinementDischargeCheck(
        recheck_key=_KEY, recheck_invoker=_fake([_z3result(Z3Status.UNKNOWN)])
    )
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is False
    assert result.incomplete is True
    assert result.reason_code == "DISCHARGE_STATUS_NOT_CONFIRMED"
    assert "version skew" in result.detail


def test_accepted_z3_versions_restores_authority_across_skew(tmp_path):
    """Operator-owned widening: when both versions sit in
    accepted_z3_versions, the same skewed mismatch is a divergence again."""
    pinned = dict(_FAKE_IDENTITY, z3_version="4.15.3")
    signed = _signed_record(tmp_path, claimed="discharged", solver_policy=pinned)
    plugin = RefinementDischargeCheck(
        recheck_key=_KEY,
        recheck_invoker=_fake([_z3result(Z3Status.UNKNOWN)]),
        accepted_z3_versions=frozenset({"4.15.3", "4.16.0"}),
    )
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is False
    assert result.incomplete is False
    assert result.reason_code == "DISCHARGE_STATUS_VERIFIER_DIVERGENCE"


def test_malformed_pin_is_not_confirmed(tmp_path):
    """A malformed __solver_policy__ is signed material (the HMAC covers the
    context), so it is a minting defect: replay terms cannot be established —
    could-not-conclude, not forgery."""
    signed = _signed_record(
        tmp_path,
        claimed="discharged",
        context_overrides={"__solver_policy__": "not-a-dict"},
    )
    plugin = RefinementDischargeCheck(recheck_key=_KEY, recheck_invoker=_fake([]))
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is False
    assert result.incomplete is True
    assert result.reason_code == "DISCHARGE_STATUS_NOT_CONFIRMED"


# ============================================================================
# Under-resourcing floor
# ============================================================================


def test_under_floor_not_proved_claim_is_under_resourced(tmp_path):
    """A producer pinning a tiny rlimit makes 'unknown' deterministically true
    for every obligation — zero proof content. The empty FakeZ3Invoker proves
    the floor fires BEFORE any solver invocation."""
    pinned = dict(_FAKE_IDENTITY, rlimit=10)
    signed = _signed_record(tmp_path, claimed="unknown", solver_policy=pinned)
    plugin = RefinementDischargeCheck(
        recheck_key=_KEY,
        recheck_invoker=_fake([]),  # must never be called
    )
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is False
    assert result.incomplete is True
    assert result.reason_code == "DISCHARGE_UNDER_RESOURCED"
    assert str(DEFAULT_MIN_PINNED_RLIMIT) in result.detail


def test_floor_does_not_apply_to_conclusive_claims(tmp_path):
    """unsat is unsat at any budget: a 'discharged' claim minted under a tiny
    rlimit is conclusive, so the floor is skipped and confirmation proceeds."""
    pinned = dict(_FAKE_IDENTITY, rlimit=10)
    signed = _signed_record(tmp_path, claimed="discharged", solver_policy=pinned)
    plugin = RefinementDischargeCheck(
        recheck_key=_KEY,
        recheck_invoker=_fake([_z3result(Z3Status.DISCHARGED)], rlimit=10),
    )
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is True, result.detail


# ============================================================================
# Pin integrity — the policy rides the HMAC-bound context
# ============================================================================


def test_tampered_pin_breaks_the_signature(tmp_path):
    """Stripping or weakening a pinned policy post-signing (e.g. to downgrade
    a would-be divergence REJECT into NOT_CONFIRMED) changes
    context_canonical_sha256 and fails HMAC verification."""
    signed = _signed_record(
        tmp_path, claimed="discharged", solver_policy=_FAKE_IDENTITY
    )
    signed["proof"]["recheck_context"]["__solver_policy__"]["z3_version"] = "9.9.9"
    plugin = RefinementDischargeCheck(recheck_key=_KEY, recheck_invoker=_fake([]))
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is False
    assert result.reason_code == "DISCHARGE_STATUS_FORGED"


# ============================================================================
# Honest residuals + infra errors
# ============================================================================


def test_non_authoritative_confirmation_surfaces_disclosure(tmp_path):
    """Legacy record confirmed under the verifier's own policy: the claim is
    accepted but the verdict face discloses that forgery-detection ran at
    reduced strength."""
    signed = _signed_record(tmp_path, claimed="discharged")  # no pin
    plugin = RefinementDischargeCheck(
        recheck_key=_KEY, recheck_invoker=_fake([_z3result(Z3Status.DISCHARGED)])
    )
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is True
    assert any("non-authoritative" in d for d in result.disclosures), result.disclosures


def test_authoritative_confirmation_has_no_residual_disclosure(tmp_path):
    signed = _signed_record(
        tmp_path, claimed="discharged", solver_policy=_FAKE_IDENTITY
    )
    plugin = RefinementDischargeCheck(
        recheck_key=_KEY, recheck_invoker=_fake([_z3result(Z3Status.DISCHARGED)])
    )
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is True
    assert result.disclosures == ()


def test_subprocess_failure_is_clean_error_not_reject(tmp_path):
    """Solver infrastructure failure: the artifact was neither shown bad nor
    confirmed — could-not-conclude (incomplete=True), not a REJECT."""
    signed = _signed_record(tmp_path, claimed="discharged")
    plugin = RefinementDischargeCheck(
        recheck_key=_KEY,
        recheck_invoker=_fake([_z3result(Z3Status.SUBPROCESS_FAILURE)]),
    )
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is False
    assert result.incomplete is True
    assert result.reason_code == "Z3_SUBPROCESS_FAILURE"


# ============================================================================
# Real-Z3 end-to-end (skipped when z3-solver is unavailable)
# ============================================================================

z3 = pytest.importorskip("z3")


def test_real_z3_pinned_policy_round_trip_is_authoritative_and_replayable(tmp_path):
    """Mint with a real in-process invoker's solver_policy(), recheck with a
    plain default invoker: the plugin reconstructs the pinned policy,
    authority holds (same z3 in both roles), the claim confirms, and a
    second verify produces an identical result object."""
    mint_invoker = InProcessZ3Invoker(random_seed=0, rlimit=2_000_000)
    pinned = mint_invoker.solver_policy()
    signed = _signed_record(tmp_path, claimed="discharged", solver_policy=pinned)
    plugin = RefinementDischargeCheck(
        recheck_key=_KEY, recheck_invoker=InProcessZ3Invoker()
    )
    first = plugin.check(tmp_path, _Manifest((signed,)))
    second = plugin.check(tmp_path, _Manifest((signed,)))
    assert first.ok is True, first.detail
    assert first.disclosures == ()  # authoritative — no residual
    assert first == second  # replay: identical verdict object
