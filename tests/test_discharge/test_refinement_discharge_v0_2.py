"""Adversarial tests for refinement_discharge.py v0.2 — verifier-set discipline
under the SMT-LIB discharge pipeline.

Exercises the five attack categories named in
the audit-bundle contract §Stream V16 §Adversarial test suite:

  1. SMT solver crash  -> Z3_SUBPROCESS_FAILURE
  2. Solver timeout     -> verifier-divergence when claimed != actual
  3. Solver unknown     -> claimed-vs-actual mismatch path
  4. Z3 nondeterminism  -> retry-with-different-seed surfaces both outcomes verbatim
                           (see test_z3_runner.py::test_adversarial_nondeterminism_does_not_silent_retry)
  5. Dispatcher-forged status -> DISCHARGE_STATUS_FORGED (unsigned) +
                                  DISCHARGE_STATUS_VERIFIER_DIVERGENCE (signed but Z3 disagrees)

Plus the BROKEN-FIRST regression test that confirms DISCHARGE_FRAGMENT_OUT_OF_SCOPE
fires on out-of-fragment refinements.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from audit_bundle.plugins.refinement_discharge import RefinementDischargeCheck
from audit_bundle.discharge.verifier_signing import (
    DIVERGENCE_KIND_CONTEXT_SUBSTITUTION,
    DIVERGENCE_KIND_RUNNER_MISMATCH,
    DIVERGENCE_RECORD_KIND,
    VerifierSigningKey,
    sign_and_write,
    verify_divergence_record,
)
from audit_bundle.discharge.z3_runner import (
    FakeZ3Invoker,
    InProcessZ3Invoker,
    Z3Result,
    Z3Status,
)


# ---------------------------------------------------------------------------
# Manifest stub + helpers
# ---------------------------------------------------------------------------


class _Manifest:
    def __init__(self, dispatch_records=(), bundle_id="bundle-test-001"):
        self.dispatch_records = dispatch_records
        self.bundle_id = bundle_id


_KEY = VerifierSigningKey(verifier_id="v-kernel-test", secret=b"deadbeef" * 4)
_OTHER_KEY = VerifierSigningKey(verifier_id="v-kernel-test", secret=b"feedbeef" * 4)
_BUNDLE_ID = "bundle-test-001"


def _write_obligation(tmp_path: Path, text: str = "-- obligation\n") -> tuple[str, str]:
    """Write a stub obligation file inside tmp_path; return (relative_uri, sha256).
    Uses write_bytes to bypass Windows newline translation."""
    rel = "proofs/obligation.smt2"
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    data = text.encode("utf-8")
    p.write_bytes(data)
    return rel, hashlib.sha256(data).hexdigest()


_DEFAULT_REFINE = "(= a b)"
_DEFAULT_RECHECK_CONTEXT = {"a": 1, "b": 1, "__logic__": "QF_LIA"}


def _record(
    *,
    kind="smt-z3",
    refine=_DEFAULT_REFINE,
    obligation_uri="proofs/obligation.smt2",
    obligation_sha="a" * 64,
    discharge_status="not-attempted",
    recheck_context=None,
):
    """Build a v0.2 dispatch record. Defaults to a trivial in-fragment
    refinement + matching context so sign_and_write has a formula+context
    to bind the signature to (V16 panel review BUG 2 fix). Tests that need
    a different formula (e.g. fragment-out-of-scope adversarial tests) pass
    refine=... explicitly."""
    rec = {
        "schema_version": "0.1",
        "op": {"kind": "COMPUTE", "name": "verify"},
        "inputs": [],
        "outputs": [
            {
                "name": "r",
                "type": {"base": "Int", "refine": refine}
                if refine is not None
                else {"base": "Int"},
            }
        ],
        "effect": {},
        "predicates": [],
        "stamp_declared": "INTERNAL_BENCHMARK",
        "stamp_observed": None,
        "proof": {
            "kind": kind,
            "obligation_uri": obligation_uri,
            "obligation_sha": obligation_sha,
            "discharge_status": discharge_status,
        },
    }
    # Default recheck_context is supplied so sign_and_write can bind the
    # signature to it. Tests that override pass recheck_context= explicitly.
    rec["proof"]["recheck_context"] = (
        recheck_context
        if recheck_context is not None
        else dict(_DEFAULT_RECHECK_CONTEXT)
    )
    return rec


# ============================================================================
# v0.2 — verifier-signed records pass. RES-01 availability discipline
# (2026-06-11): admission now requires a Z3 backend able to replay the
# claim — these tests wire a scripted invoker that agrees with the signed
# status. The no-invoker construction is covered by the availability-
# discipline section at the bottom of this file (clean-ERROR, never GREEN).
# ============================================================================


def test_verifier_signed_discharged_admitted(tmp_path):
    rel, sha = _write_obligation(tmp_path)
    record = _record(obligation_uri=rel, obligation_sha=sha)
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
    )
    fake = FakeZ3Invoker([Z3Result(Z3Status.DISCHARGED, "unsat", 0.01, "fake")])
    plugin = RefinementDischargeCheck(recheck_key=_KEY, recheck_invoker=fake)
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is True, result.detail
    assert "verifier-signed" in result.detail


def test_verifier_signed_failed_admitted(tmp_path):
    """A signed 'failed' status is honest — the verifier ran Z3 and the
    refinement did NOT discharge. The bundle still verifies; downstream
    consumers see discharge_status='failed' and decide what to do."""
    rel, sha = _write_obligation(tmp_path)
    record = _record(obligation_uri=rel, obligation_sha=sha)
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="failed",
        z3_status="failed",
        bundle_id=_BUNDLE_ID,
    )
    fake = FakeZ3Invoker([Z3Result(Z3Status.FAILED, "sat", 0.01, "fake")])
    plugin = RefinementDischargeCheck(recheck_key=_KEY, recheck_invoker=fake)
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is True


def test_verifier_signed_timeout_admitted(tmp_path):
    rel, sha = _write_obligation(tmp_path)
    record = _record(obligation_uri=rel, obligation_sha=sha)
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="timeout",
        z3_status="timeout",
        bundle_id=_BUNDLE_ID,
    )
    fake = FakeZ3Invoker([Z3Result(Z3Status.TIMEOUT, "timeout", 0.01, "fake")])
    plugin = RefinementDischargeCheck(recheck_key=_KEY, recheck_invoker=fake)
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is True


# ============================================================================
# Adversarial 5a — Dispatcher-forged status (unsigned)
# ============================================================================


def test_unsigned_discharged_status_rejected_as_forged(tmp_path):
    """v0.1 behavior: unsigned non-trivial discharge_status is forged. v0.2
    preserves this: a record with discharge_status='discharged' but no
    verifier_signature still fails."""
    rel, sha = _write_obligation(tmp_path)
    record = _record(
        obligation_uri=rel,
        obligation_sha=sha,
        discharge_status="discharged",  # dispatcher-forged
    )
    plugin = RefinementDischargeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, _Manifest((record,)))
    assert result.ok is False
    assert result.reason_code == "DISCHARGE_STATUS_FORGED"


# ============================================================================
# Adversarial 5b — Forged signature under a different key
# ============================================================================


def test_signed_under_wrong_key_rejected(tmp_path):
    rel, sha = _write_obligation(tmp_path)
    record = _record(obligation_uri=rel, obligation_sha=sha)
    signed = sign_and_write(
        record,
        key=_OTHER_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
    )
    plugin = RefinementDischargeCheck(recheck_key=_KEY)  # different key
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is False
    assert result.reason_code == "DISCHARGE_STATUS_FORGED"


# ============================================================================
# Adversarial 5c — Tampered status after signing (claimed upgrade attempt)
# ============================================================================


def test_signed_then_tampered_rejected(tmp_path):
    """Sign as 'failed', then tamper to claim 'discharged'. MAC computed over
    'failed' fails to verify after the post-signing edit."""
    rel, sha = _write_obligation(tmp_path)
    record = _record(obligation_uri=rel, obligation_sha=sha)
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="failed",
        z3_status="failed",
        bundle_id=_BUNDLE_ID,
    )
    signed["proof"]["discharge_status"] = "discharged"  # tamper
    plugin = RefinementDischargeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is False
    assert result.reason_code == "DISCHARGE_STATUS_FORGED"


# ============================================================================
# v0.2 BROKEN-FIRST regression — DISCHARGE_FRAGMENT_OUT_OF_SCOPE on quantifier
# ============================================================================


def test_out_of_fragment_refinement_rejected(tmp_path):
    """Plugin walks every output.type.refine and rejects out-of-fragment
    formulas. This is the broken-first target for V16: the broken parser
    accepted these; the real parser rejects them; the plugin surfaces the
    rejection as DISCHARGE_FRAGMENT_OUT_OF_SCOPE."""
    rel, sha = _write_obligation(tmp_path)
    record = _record(
        obligation_uri=rel,
        obligation_sha=sha,
        refine="(forall ((x Int)) (= x 0))",  # quantifier — out of fragment
    )
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
    )
    plugin = RefinementDischargeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is False
    assert result.reason_code == "DISCHARGE_FRAGMENT_OUT_OF_SCOPE"
    assert "forall" in result.detail


def test_out_of_fragment_nonlinear_mul_rejected(tmp_path):
    rel, sha = _write_obligation(tmp_path)
    record = _record(
        obligation_uri=rel,
        obligation_sha=sha,
        refine="(= (* a b) total)",
    )
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
    )
    plugin = RefinementDischargeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is False
    assert result.reason_code == "DISCHARGE_FRAGMENT_OUT_OF_SCOPE"


# ============================================================================
# Adversarial 5d — Verifier-claim divergence under Z3 re-discharge
# ============================================================================


def test_recheck_divergence_when_z3_disagrees_with_signed_status(tmp_path):
    """The verifier signed 'discharged' but on re-run Z3 returns 'sat' (i.e.
    the formula is FAILED). The plugin must surface this as
    DISCHARGE_STATUS_VERIFIER_DIVERGENCE, not silently trust the signature."""
    rel, sha = _write_obligation(tmp_path)
    record = _record(
        obligation_uri=rel,
        obligation_sha=sha,
        refine="(= (+ a b) total)",
        recheck_context={"a": 1, "b": 2, "total": 7, "__logic__": "QF_LIA"},
    )
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
    )
    fake = FakeZ3Invoker(
        [
            Z3Result(Z3Status.FAILED, "sat", 0.01, "fake"),  # Z3 says FAILED
        ]
    )
    plugin = RefinementDischargeCheck(recheck_key=_KEY, recheck_invoker=fake)
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is False
    assert result.reason_code == "DISCHARGE_STATUS_VERIFIER_DIVERGENCE"
    assert "discharged" in result.detail
    assert "failed" in result.detail


def test_recheck_agreement_passes(tmp_path):
    rel, sha = _write_obligation(tmp_path)
    record = _record(
        obligation_uri=rel,
        obligation_sha=sha,
        refine="(= (+ a b) total)",
        recheck_context={"a": 3, "b": 4, "total": 7, "__logic__": "QF_LIA"},
    )
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
    )
    fake = FakeZ3Invoker(
        [
            Z3Result(Z3Status.DISCHARGED, "unsat", 0.01, "fake"),
        ]
    )
    plugin = RefinementDischargeCheck(recheck_key=_KEY, recheck_invoker=fake)
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is True
    assert "1 re-discharged" in result.detail


# ============================================================================
# Adversarial 1 — Z3 subprocess failure surfaces as Z3_SUBPROCESS_FAILURE
# ============================================================================


def test_z3_subprocess_failure_surfaces(tmp_path):
    rel, sha = _write_obligation(tmp_path)
    record = _record(
        obligation_uri=rel,
        obligation_sha=sha,
        refine="(= (+ a b) total)",
        recheck_context={"a": 1, "b": 2, "total": 3, "__logic__": "QF_LIA"},
    )
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
    )
    fake = FakeZ3Invoker(
        [
            Z3Result(
                Z3Status.SUBPROCESS_FAILURE, "z3 segfault: signal 11", 0.5, "fake"
            ),
        ]
    )
    plugin = RefinementDischargeCheck(recheck_key=_KEY, recheck_invoker=fake)
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is False
    assert result.reason_code == "Z3_SUBPROCESS_FAILURE"
    assert "segfault" in result.detail


# ============================================================================
# Adversarial 2 — Timeout when claimed=discharged
# ============================================================================


def test_timeout_when_claimed_discharged_not_confirmed_on_legacy_record(tmp_path):
    """Determinism doctrine (2026-06-10): a legacy record (no pinned
    __solver_policy__) whose conclusive claim cannot be reproduced is
    present-but-unverified — clean-ERROR, NOT forgery. The replay ran under
    the verifier's own budget, not the minting budget, so the mismatch is
    explainable by environment. (The pre-doctrine behaviour — hard
    DIVERGENCE — manufactured forgery accusations out of machine-speed
    differences; the authoritative-pin divergence path is covered in
    test_z3_determinism_policy.py.)"""
    rel, sha = _write_obligation(tmp_path)
    record = _record(
        obligation_uri=rel,
        obligation_sha=sha,
        refine="(= (+ a b) total)",
        recheck_context={"a": 1, "b": 2, "total": 3, "__logic__": "QF_LIA"},
    )
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
    )
    fake = FakeZ3Invoker(
        [
            Z3Result(Z3Status.TIMEOUT, "timeout 30s", 30.0, "fake"),
        ]
    )
    plugin = RefinementDischargeCheck(recheck_key=_KEY, recheck_invoker=fake)
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is False
    assert result.incomplete is True
    assert result.reason_code == "DISCHARGE_STATUS_NOT_CONFIRMED"


# ============================================================================
# Adversarial 3 — Unknown when claimed=discharged
# ============================================================================


def test_unknown_when_claimed_discharged_not_confirmed_on_legacy_record(tmp_path):
    """Sibling of the timeout case above: unknown and timeout sit on the same
    coarse-lattice cell (not_proved), so both produce the same NOT_CONFIRMED
    outcome against a conclusive claim on an unpinned record."""
    rel, sha = _write_obligation(tmp_path)
    record = _record(
        obligation_uri=rel,
        obligation_sha=sha,
        refine="(= (+ a b) total)",
        recheck_context={"a": 1, "b": 2, "total": 3, "__logic__": "QF_LIA"},
    )
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
    )
    fake = FakeZ3Invoker(
        [
            Z3Result(Z3Status.UNKNOWN, "unknown", 0.1, "fake"),
        ]
    )
    plugin = RefinementDischargeCheck(recheck_key=_KEY, recheck_invoker=fake)
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is False
    assert result.incomplete is True
    assert result.reason_code == "DISCHARGE_STATUS_NOT_CONFIRMED"


# ============================================================================
# v0.2 — smt-z3 added to kind enum
# ============================================================================


def test_smt_z3_kind_admitted(tmp_path):
    rel, sha = _write_obligation(tmp_path)
    record = _record(
        kind="smt-z3",
        obligation_uri=rel,
        obligation_sha=sha,
        discharge_status="not-attempted",
    )
    plugin = RefinementDischargeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, _Manifest((record,)))
    assert result.ok is True


# ============================================================================
# Backward compat — v0.1 not-attempted records still pass
# ============================================================================


def test_v0_1_not_attempted_record_still_passes(tmp_path):
    rel, sha = _write_obligation(tmp_path)
    record = _record(
        kind="lean-4",
        obligation_uri=rel,
        obligation_sha=sha,
        discharge_status="not-attempted",
    )
    plugin = RefinementDischargeCheck()  # no key required for v0.1 mode
    result = plugin.check(tmp_path, _Manifest((record,)))
    assert result.ok is True


# ============================================================================
# Mixed multi-record manifest — first signed, second unsigned-forged
# ============================================================================


def test_mixed_records_first_signed_second_unsigned_fails_on_second(tmp_path):
    rel, sha = _write_obligation(tmp_path)
    good = _record(obligation_uri=rel, obligation_sha=sha)
    good_signed = sign_and_write(
        good,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
    )
    bad = _record(
        obligation_uri=rel, obligation_sha=sha, discharge_status="discharged"
    )  # unsigned forge
    plugin = RefinementDischargeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, _Manifest((good_signed, bad)))
    assert result.ok is False
    assert result.reason_code == "DISCHARGE_STATUS_FORGED"
    assert "record[1]" in result.detail


# ============================================================================
# In-process Z3 happy-path through the plugin (real-Z3 integration)
# ============================================================================


def test_in_process_z3_real_discharge_through_plugin(tmp_path):
    """End-to-end: refinement '(= (+ a b) total)' with concrete substitution
    a=3, b=4, total=7 — Z3 (in-process) discharges this. Plugin re-runs Z3
    and confirms agreement with the signed claim."""
    rel, sha = _write_obligation(tmp_path)
    record = _record(
        obligation_uri=rel,
        obligation_sha=sha,
        refine="(= (+ a b) total)",
        recheck_context={"a": 3, "b": 4, "total": 7, "__logic__": "QF_LIA"},
    )
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
    )
    plugin = RefinementDischargeCheck(
        recheck_key=_KEY,
        recheck_invoker=InProcessZ3Invoker(),
    )
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is True, result.detail
    assert "1 re-discharged" in result.detail


def test_in_process_z3_real_disagreement_caught(tmp_path):
    """Same as above but with a context where the refinement is FALSE
    (a=1+b=2 vs total=99). The verifier signed 'discharged' but Z3 finds
    the formula false → DISCHARGE_STATUS_VERIFIER_DIVERGENCE."""
    rel, sha = _write_obligation(tmp_path)
    record = _record(
        obligation_uri=rel,
        obligation_sha=sha,
        refine="(= (+ a b) total)",
        recheck_context={"a": 1, "b": 2, "total": 99, "__logic__": "QF_LIA"},
    )
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
    )
    plugin = RefinementDischargeCheck(
        recheck_key=_KEY,
        recheck_invoker=InProcessZ3Invoker(),
    )
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is False
    assert result.reason_code == "DISCHARGE_STATUS_VERIFIER_DIVERGENCE"


# ============================================================================
# Regressions — V16 panel review (Sonnet 4.6 2026-05-02)
# ============================================================================


def test_panel_bug_1_fail_closed_when_no_recheck_key(tmp_path):
    """BUG 1 (panel review 2026-05-02): when RefinementDischargeCheck is
    constructed without recheck_key, ANY non-trivial discharge_status must
    be rejected as DISCHARGE_STATUS_FORGED — including records carrying a
    structurally-valid (but unverifiable) verifier_signature dict.

    Prior behaviour: the plugin checked only that verifier_signature was a
    dict and passed. An attacker forged a sig dict with `mac=0*64` and got
    the bundle through.
    """
    rel, sha = _write_obligation(tmp_path)
    forged_record = {
        "schema_version": "0.1",
        "op": {"kind": "COMPUTE", "name": "x"},
        "inputs": [],
        "outputs": [],
        "effect": {},
        "predicates": [],
        "stamp_declared": "INTERNAL_BENCHMARK",
        "stamp_observed": None,
        "proof": {
            "kind": "smt-z3",
            "obligation_uri": rel,
            "obligation_sha": sha,
            "discharge_status": "discharged",
            "verifier_signature": {
                "algorithm": "hmac-sha256",
                "verifier_id": "attacker",
                "z3_status": "discharged",
                "timestamp_utc": "2024-01-01T00:00:00Z",
                "bundle_id": "anything",
                "record_idx": 0,
                "refine_text_sha256": "a" * 64,
                "context_canonical_sha256": "b" * 64,
                "mac": "0" * 64,
            },
        },
    }

    plugin = RefinementDischargeCheck()  # NO recheck_key
    result = plugin.check(tmp_path, _Manifest((forged_record,)))
    assert result.ok is False
    assert result.reason_code == "DISCHARGE_STATUS_FORGED"
    assert (
        "without a recheck_key" in result.detail
        or "BUG 1" in result.detail
        or "v0.1 strict" in result.detail
    )


def test_panel_bug_2_cross_bundle_replay_rejected(tmp_path):
    """BUG 2 (panel review 2026-05-02): a signature legitimately produced
    for bundle A must NOT validate when copied into bundle B. The fix binds
    `bundle_id` into the HMAC payload."""
    rel, sha = _write_obligation(tmp_path)
    record = _record(obligation_uri=rel, obligation_sha=sha)
    # Sign in bundle A
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id="bundle-A",
    )
    # Carry the signed record into bundle B (different bundle_id on manifest)
    plugin = RefinementDischargeCheck(recheck_key=_KEY)
    manifest_b = _Manifest((signed,), bundle_id="bundle-B")
    result = plugin.check(tmp_path, manifest_b)
    assert result.ok is False
    assert result.reason_code == "DISCHARGE_STATUS_FORGED"


def test_panel_bug_2_cross_record_replay_rejected_via_formula_binding(tmp_path):
    """BUG 2 follow-up: same bundle, same obligation, but the attacker copies
    a signature from a record claiming refine X onto a record claiming
    refine Y. The signature is bound to refine_text_sha256 — the swap fails
    to verify."""
    rel, sha = _write_obligation(tmp_path)
    rec_a = _record(
        obligation_uri=rel,
        obligation_sha=sha,
        refine="(= a b)",
    )
    signed_a = sign_and_write(
        rec_a,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
    )

    # Build rec_b with a DIFFERENT formula but copy rec_a's signature dict
    rec_b = _record(
        obligation_uri=rel,
        obligation_sha=sha,
        refine="(= (+ a b) total)",  # different formula
        recheck_context={"a": 1, "b": 1, "total": 2, "__logic__": "QF_LIA"},
    )
    rec_b["proof"]["discharge_status"] = "discharged"
    rec_b["proof"]["verifier_signature"] = signed_a["proof"]["verifier_signature"]

    plugin = RefinementDischargeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, _Manifest((rec_b,)))
    assert result.ok is False
    assert result.reason_code == "DISCHARGE_STATUS_FORGED"


def test_panel_bug_2_cross_context_replay_rejected(tmp_path):
    """BUG 2 follow-up: same bundle, same formula, same obligation, but the
    attacker swaps the recheck_context (so the substitution would yield a
    different SMT script). The signature is bound to context_canonical_sha256
    — the swap fails to verify."""
    rel, sha = _write_obligation(tmp_path)
    rec_a = _record(
        obligation_uri=rel,
        obligation_sha=sha,
        refine="(= (+ a b) total)",
        recheck_context={"a": 1, "b": 1, "total": 2, "__logic__": "QF_LIA"},
    )
    signed_a = sign_and_write(
        rec_a,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
    )
    # Swap the context inside rec_b but keep rec_a's signature
    rec_b_proof = signed_a["proof"].copy()
    rec_b_proof["recheck_context"] = {
        "a": 999,
        "b": 999,
        "total": 999,
        "__logic__": "QF_LIA",
    }
    rec_b = {**signed_a, "proof": rec_b_proof}

    plugin = RefinementDischargeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, _Manifest((rec_b,)))
    assert result.ok is False
    assert result.reason_code == "DISCHARGE_STATUS_FORGED"


def test_panel_bug_8_recheck_context_with_unsupported_logic_rejected(tmp_path):
    """BUG 8 (panel review 2026-05-02): a hostile dispatcher sets
    __logic__='ALL' (or QF_NIA, or anything outside the v0.1 fragment lock).
    context_substitution.substitute now restricts to the in-fragment set,
    so the recheck path raises ContextSubstitutionError surfaced as
    DISCHARGE_STATUS_VERIFIER_DIVERGENCE."""
    rel, sha = _write_obligation(tmp_path)
    record = _record(
        obligation_uri=rel,
        obligation_sha=sha,
        refine="(= (+ a b) total)",
        recheck_context={"a": 1, "b": 2, "total": 3, "__logic__": "ALL"},
    )
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
    )
    plugin = RefinementDischargeCheck(
        recheck_key=_KEY,
        recheck_invoker=InProcessZ3Invoker(),
    )
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is False
    assert result.reason_code == "DISCHARGE_STATUS_VERIFIER_DIVERGENCE"


# ============================================================================
# Gate 3a frontier-pair P3 (Opus 4.7 §b2 + Sonnet 4.6 §A3, 2026-05-19)
# ============================================================================


def test_p3_recheck_smt_z3_uses_extract_refine_text_helper(tmp_path, monkeypatch):
    """Gate 3a P3 (Opus 4.7 §b2 + Sonnet 4.6 §A3, 2026-05-19):
    _recheck_smt_z3 previously hand-rolled the "first outputs[*].type.refine"
    extraction in a 9-line loop. The BUG 5 fix from C14 tribunal pass
    claimed this was unified through `extract_refine_text` so V14/V16/C14
    would never drift; in fact `_recheck_smt_z3` kept its own copy. A
    future extension of `extract_refine_text` (e.g. output_idx-aware in
    v0.3) would silently fail to propagate.

    Falsifiable prediction: instrument `extract_refine_text` with a call
    counter. Pre-patch the plugin's check() calls it once per record (at
    V16 signature setup, line ~421). Post-patch it's called twice per
    record (also from `_recheck_smt_z3`, line ~511) — confirming
    `_recheck_smt_z3` now reads the helper rather than its own copy.
    Wraps the real function so the discharge still works end-to-end."""
    from audit_bundle.plugins import refinement_discharge as rd

    real_extract = rd.extract_refine_text
    call_count = {"n": 0}

    def counting_extract(record):
        call_count["n"] += 1
        return real_extract(record)

    monkeypatch.setattr(rd, "extract_refine_text", counting_extract)

    rel, sha = _write_obligation(tmp_path)
    record = _record(
        obligation_uri=rel,
        obligation_sha=sha,
        refine="(= a b)",
        recheck_context={"a": 1, "b": 1, "__logic__": "QF_LIA"},
    )
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
    )
    plugin = RefinementDischargeCheck(
        recheck_key=_KEY,
        recheck_invoker=InProcessZ3Invoker(),
    )
    result = plugin.check(tmp_path, _Manifest((signed,)))

    # End-to-end: discharge still succeeds with the wrapping helper.
    assert result.ok is True, result.detail
    # Post-patch behavior: _recheck_smt_z3 also calls the helper, so two
    # invocations per discharged record (V16 sig setup + recheck).
    # Pre-patch this would be 1 — the hand-rolled loop did not call it.
    assert call_count["n"] == 2, (
        f"expected extract_refine_text called twice (V16 sig setup + "
        f"_recheck_smt_z3 post-P3 consolidation); got {call_count['n']}. "
        "If this is 1, _recheck_smt_z3 is back to hand-rolling its own "
        "extraction and the P3 consolidation has regressed."
    )


def test_p3_recheck_smt_z3_helper_consolidation_smoke(tmp_path):
    """P3 smoke: a legitimately-signed discharged record still re-verifies
    after the helper consolidation. Guards against regression in the
    common path where extract_refine_text returns the right formula."""
    rel, sha = _write_obligation(tmp_path)
    record = _record(
        obligation_uri=rel,
        obligation_sha=sha,
        refine="(= a b)",
        recheck_context={"a": 1, "b": 1, "__logic__": "QF_LIA"},
    )
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
    )
    plugin = RefinementDischargeCheck(
        recheck_key=_KEY,
        recheck_invoker=InProcessZ3Invoker(),
    )
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is True, result.detail


# ============================================================================
# Tier C — C16 Fork A: retained, verifier-signed divergence record
# ============================================================================
#
# On divergence the bundle is still REJECTED (ok=False), but the producer's
# claim + the verifier's independent computation are retained as a signed
# artifact delivered on the verdict face via PluginResult.disclosures (the
# §103 "teaches away from PCC's discard" delta). Read-only invariant
# (2026-06-10): retention previously appended to bundle_dir/events.jsonl;
# the conservation gate classifies a verifier-written events.jsonl as
# UNOWNED surplus, so the append changed the re-verification failure set —
# the signed record now reaches the consumer in the verdict itself and
# persistence is caller-owned.


def _diverging_signed_record(tmp_path, *, total=99):
    """Build + sign a record whose Z3 re-run will disagree with the claimed
    'discharged' status (a + b != total)."""
    rel, sha = _write_obligation(tmp_path)
    record = _record(
        obligation_uri=rel,
        obligation_sha=sha,
        refine="(= (+ a b) total)",
        recheck_context={"a": 1, "b": 2, "total": total, "__logic__": "QF_LIA"},
    )
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
    )
    return signed, sha


def _read_single_retained_record(result):
    """Parse the verifier-signed divergence record from the failing
    PluginResult's disclosures (verdict-face retention channel)."""
    disclosures = [
        d for d in result.disclosures if "DISCHARGE_STATUS_VERIFIER_DIVERGENCE" in d
    ]
    assert len(disclosures) == 1, (
        f"expected exactly one retained divergence disclosure, got "
        f"{len(disclosures)}: {result.disclosures!r}"
    )
    return json.loads(disclosures[0].split(" — ", 1)[1])


def test_divergence_record_retained_on_verdict_face(tmp_path):
    """5(a): the runner-vs-claim divergence retains a signed record on the
    verdict face even though the verdict is a hard reject — and writes
    NOTHING into bundle_dir (read-only invariant)."""
    signed, sha = _diverging_signed_record(tmp_path)
    plugin = RefinementDischargeCheck(
        recheck_key=_KEY, recheck_invoker=InProcessZ3Invoker()
    )
    result = plugin.check(tmp_path, _Manifest((signed,)))

    # Verdict is unchanged: retain-and-still-reject.
    assert result.ok is False
    assert result.reason_code == "DISCHARGE_STATUS_VERIFIER_DIVERGENCE"
    # Read-only invariant: no event log materializes in the bundle.
    assert not (tmp_path / "events.jsonl").exists()

    rec = _read_single_retained_record(result)
    assert rec["record_kind"] == DIVERGENCE_RECORD_KIND
    assert rec["producer_claimed"] == "discharged"
    assert rec["verifier_computed"] == "failed"  # a+b != total -> sat -> FAILED
    assert rec["divergence_kind"] == DIVERGENCE_KIND_RUNNER_MISMATCH
    assert rec["bundle_id"] == _BUNDLE_ID
    assert rec["record_idx"] == 0
    assert rec["obligation_sha"] == sha


def test_divergence_record_signature_verifies_and_rejects_replay(tmp_path):
    """5(b): the retained record is signature-verifiable and rejects
    cross-bundle / cross-record / wrong-key replay."""
    signed, _ = _diverging_signed_record(tmp_path)
    plugin = RefinementDischargeCheck(
        recheck_key=_KEY, recheck_invoker=InProcessZ3Invoker()
    )
    result = plugin.check(tmp_path, _Manifest((signed,)))
    rec = _read_single_retained_record(result)

    # Authoritative bindings re-verify.
    assert (
        verify_divergence_record(rec, key=_KEY, bundle_id=_BUNDLE_ID, record_idx=0)
        is True
    )
    # Wrong key.
    assert (
        verify_divergence_record(
            rec, key=_OTHER_KEY, bundle_id=_BUNDLE_ID, record_idx=0
        )
        is False
    )
    # Cross-bundle replay.
    assert (
        verify_divergence_record(rec, key=_KEY, bundle_id="other-bundle", record_idx=0)
        is False
    )
    # Cross-record replay.
    assert (
        verify_divergence_record(rec, key=_KEY, bundle_id=_BUNDLE_ID, record_idx=5)
        is False
    )


def test_divergence_record_emitted_on_context_substitution_error(tmp_path):
    """Both divergence branches retain a record. Here the re-substitution
    fails (out-of-fragment __logic__) before Z3 runs; verifier_computed is
    the sentinel and divergence_kind reflects the substitution failure."""
    rel, sha = _write_obligation(tmp_path)
    record = _record(
        obligation_uri=rel,
        obligation_sha=sha,
        refine="(= (+ a b) total)",
        recheck_context={"a": 1, "b": 2, "total": 3, "__logic__": "ALL"},
    )
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
    )
    plugin = RefinementDischargeCheck(
        recheck_key=_KEY, recheck_invoker=InProcessZ3Invoker()
    )
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is False
    assert result.reason_code == "DISCHARGE_STATUS_VERIFIER_DIVERGENCE"

    rec = _read_single_retained_record(result)
    assert rec["divergence_kind"] == DIVERGENCE_KIND_CONTEXT_SUBSTITUTION
    assert rec["verifier_computed"] == "context_substitution_error"
    assert rec["producer_claimed"] == "discharged"
    assert (
        verify_divergence_record(rec, key=_KEY, bundle_id=_BUNDLE_ID, record_idx=0)
        is True
    )


def test_divergence_path_leaves_bundle_dir_untouched(tmp_path):
    """5(c) (read-only invariant): the divergence path performs NO file IO in
    bundle_dir — retention rides the verdict face, so the reject verdict and
    its reason set are byte-identical on every re-run. (Replaces the
    best-effort-emit test from the events.jsonl era: with no write there is
    no emit-failure mode left to guard.)"""
    signed, _ = _diverging_signed_record(tmp_path)
    before = sorted(
        (p.relative_to(tmp_path), p.read_bytes() if p.is_file() else None)
        for p in tmp_path.rglob("*")
    )
    plugin = RefinementDischargeCheck(
        recheck_key=_KEY, recheck_invoker=InProcessZ3Invoker()
    )
    result = plugin.check(tmp_path, _Manifest((signed,)))
    assert result.ok is False
    assert result.reason_code == "DISCHARGE_STATUS_VERIFIER_DIVERGENCE"
    after = sorted(
        (p.relative_to(tmp_path), p.read_bytes() if p.is_file() else None)
        for p in tmp_path.rglob("*")
    )
    assert before == after, "divergence path wrote into bundle_dir"

    # Replayability: the retained record stamps the deterministic
    # DIVERGENCE_TS_UNRECORDED sentinel by default (no wall-clock read on
    # the verify path), so a re-run mints a byte-identical disclosure.
    rerun = plugin.check(tmp_path, _Manifest((signed,)))
    assert rerun.disclosures == result.disclosures, (
        "re-run minted a different retained record — wall clock leaked into "
        "the verdict face"
    )
    rec = _read_single_retained_record(result)
    assert rec["timestamp_utc"] == RefinementDischargeCheck.DIVERGENCE_TS_UNRECORDED


# ============================================================================
# Availability discipline (RES-01, 2026-06-11) — signed semantic claims that
# THIS host cannot replay must never pass silently. Pre-fix: a host with no
# Z3 backend constructed the plugin with recheck_invoker=None and signed
# smt-z3 records passed on signature alone, GREEN with "0 re-discharged"
# buried in detail prose — while a host whose z3 CRASHED mid-run got
# Z3_SUBPROCESS_FAILURE (incomplete=True, exit 2). The weaker host got the
# stronger verdict.
# ============================================================================


def test_signed_smt_z3_without_invoker_is_clean_error(tmp_path):
    """No Z3 backend + a verifier-signed smt-z3 claim -> Z3_RECHECK_NOT_AVAILABLE
    (incomplete=True, clean-ERROR), never a silent signature-only GREEN."""
    rel, sha = _write_obligation(tmp_path)
    record = sign_and_write(
        _record(obligation_uri=rel, obligation_sha=sha),
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
    )
    plugin = RefinementDischargeCheck(recheck_key=_KEY)  # no invoker wired
    result = plugin.check(tmp_path, _Manifest((record,)))
    assert result.ok is False
    assert result.incomplete is True
    assert result.reason_code == "Z3_RECHECK_NOT_AVAILABLE"
    assert "indices [0]" in result.detail


def test_multiple_signed_records_without_invoker_all_indices_reported(tmp_path):
    rel, sha = _write_obligation(tmp_path)
    records = tuple(
        sign_and_write(
            _record(obligation_uri=rel, obligation_sha=sha),
            key=_KEY,
            discharge_status="discharged",
            z3_status="discharged",
            bundle_id=_BUNDLE_ID,
            record_idx=i,
        )
        for i in range(2)
    )
    plugin = RefinementDischargeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, _Manifest(records))
    assert result.ok is False
    assert result.incomplete is True
    assert result.reason_code == "Z3_RECHECK_NOT_AVAILABLE"
    assert "indices [0, 1]" in result.detail


def test_not_attempted_without_invoker_still_passes(tmp_path):
    """'not-attempted' carries no semantic claim — W3-baseline and
    dispatch-only bundles verify identically on hosts with and without z3."""
    rel, sha = _write_obligation(tmp_path)
    record = _record(
        obligation_uri=rel, obligation_sha=sha, discharge_status="not-attempted"
    )
    plugin = RefinementDischargeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, _Manifest((record,)))
    assert result.ok is True
    assert result.incomplete is False


def test_forged_record_outranks_availability_error(tmp_path):
    """A REJECT-class defect later in the manifest must surface as its REJECT,
    not be masked by the earlier record's availability clean-ERROR."""
    rel, sha = _write_obligation(tmp_path)
    good_signed = sign_and_write(
        _record(obligation_uri=rel, obligation_sha=sha),
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
    )
    bad = _record(
        obligation_uri=rel, obligation_sha=sha, discharge_status="discharged"
    )  # unsigned forge
    plugin = RefinementDischargeCheck(recheck_key=_KEY)  # no invoker
    result = plugin.check(tmp_path, _Manifest((good_signed, bad)))
    assert result.ok is False
    assert result.incomplete is False
    assert result.reason_code == "DISCHARGE_STATUS_FORGED"
    assert "record[1]" in result.detail


def test_resolver_returning_non_dict_is_clean_error(tmp_path):
    """The resolver-supplied-context twin of the missing-invoker case: a
    custom recheck_context_resolver returning a non-dict used to pass the
    record silently (the __init__ docstring even promised an 'advisory note'
    that was never emitted). Now: DISCHARGE_STATUS_NOT_CONFIRMED,
    incomplete=True."""
    rel, sha = _write_obligation(tmp_path)
    record = sign_and_write(
        _record(obligation_uri=rel, obligation_sha=sha),
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
    )
    plugin = RefinementDischargeCheck(
        recheck_key=_KEY,
        recheck_invoker=InProcessZ3Invoker(),
        recheck_context_resolver=lambda _record_arg: None,
    )
    result = plugin.check(tmp_path, _Manifest((record,)))
    assert result.ok is False
    assert result.incomplete is True
    assert result.reason_code == "DISCHARGE_STATUS_NOT_CONFIRMED"
    assert "non-dict" in result.detail
