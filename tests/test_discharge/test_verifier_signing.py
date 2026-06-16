"""Tests for audit_bundle/discharge/verifier_signing.py — sole writer of
proof.discharge_status (V14+V16 cross-file invariant)."""

from __future__ import annotations

import pytest

from audit_bundle.discharge.verifier_signing import (
    SIGNED_DISCHARGE_STATUS_VALUES,
    SigningError,
    VerifierSigningKey,
    sign_and_write,
    verify_signature,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_KEY_BYTES = b"deadbeef" * 4  # 32 bytes
_KEY = VerifierSigningKey(verifier_id="v-kernel-test", secret=_KEY_BYTES)
_OTHER_KEY = VerifierSigningKey(verifier_id="v-kernel-test", secret=b"feedbeef" * 4)

_BUNDLE_ID = "bundle-test-001"
_DEFAULT_REFINE = "(= a b)"
_DEFAULT_CONTEXT = {"a": 1, "b": 1, "__logic__": "QF_LIA"}

_SIGN_KWARGS = {
    "bundle_id": _BUNDLE_ID,
    "refine_text": _DEFAULT_REFINE,
    "recheck_context": _DEFAULT_CONTEXT,
    # Cumulative-pre-soak Patch 6 (Gate 1, 2026-05-04): verify_signature
    # now requires authoritative caller-supplied record_idx. Tests sign
    # at the default record_idx=0 and verify against the same value.
    "record_idx": 0,
}


def _record(obligation_sha="a" * 64):
    return {
        "schema_version": "0.1",
        "op": {"kind": "COMPUTE", "name": "verify"},
        "outputs": [
            {"name": "r", "type": {"base": "Int", "refine": _DEFAULT_REFINE}},
        ],
        "effect": {},
        "predicates": [],
        "stamp_declared": "INTERNAL_BENCHMARK",
        "stamp_observed": None,
        "proof": {
            "kind": "smt-z3",
            "obligation_uri": "proofs/main.smt2",
            "obligation_sha": obligation_sha,
            "discharge_status": "not-attempted",
            "recheck_context": _DEFAULT_CONTEXT,
        },
    }


# ---------------------------------------------------------------------------
# Key envelope
# ---------------------------------------------------------------------------


def test_from_env_missing_var_raises(monkeypatch):
    # delenv via monkeypatch so the var is RESTORED at teardown. A bare
    # os.environ.pop() here leaks the unset state process-globally, breaking any
    # later test that spawns a subprocess inheriting os.environ (e.g. gxp_part11's
    # _build, which needs VKERNEL_VERIFIER_HMAC_KEY in the child env).
    monkeypatch.delenv("VKERNEL_VERIFIER_HMAC_KEY", raising=False)
    with pytest.raises(SigningError):
        VerifierSigningKey.from_env()


def test_from_env_reads_secret(monkeypatch):
    monkeypatch.setenv("VKERNEL_VERIFIER_HMAC_KEY", "test-secret-value")
    key = VerifierSigningKey.from_env(verifier_id="x")
    assert key.verifier_id == "x"
    assert key.secret == b"test-secret-value"


def test_from_secret_bytes_rejects_too_short():
    with pytest.raises(SigningError):
        VerifierSigningKey.from_secret_bytes(b"short")


# ---------------------------------------------------------------------------
# sign_and_write
# ---------------------------------------------------------------------------


def test_sign_and_write_happy_path_discharged():
    record = _record()
    out = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        timestamp_utc="2026-05-02T00:00:00Z",
        **_SIGN_KWARGS,
    )
    assert out["proof"]["discharge_status"] == "discharged"
    sig = out["proof"]["verifier_signature"]
    assert sig["algorithm"] == "hmac-sha256"
    assert sig["verifier_id"] == "v-kernel-test"
    assert sig["z3_status"] == "discharged"
    assert sig["mac"]
    # original record not mutated
    assert record["proof"]["discharge_status"] == "not-attempted"
    assert "verifier_signature" not in record["proof"]


def test_sign_and_write_happy_path_failed():
    record = _record()
    out = sign_and_write(
        record,
        key=_KEY,
        discharge_status="failed",
        z3_status="failed",
        timestamp_utc="2026-05-02T00:00:00Z",
        **_SIGN_KWARGS,
    )
    assert out["proof"]["discharge_status"] == "failed"


def test_sign_and_write_rejects_not_attempted():
    record = _record()
    with pytest.raises(SigningError) as exc:
        sign_and_write(
            record,
            key=_KEY,
            discharge_status="not-attempted",
            z3_status="discharged",
            **_SIGN_KWARGS,
        )
    assert "not-attempted" in str(exc.value)


def test_sign_and_write_rejects_unknown_status():
    record = _record()
    with pytest.raises(SigningError):
        sign_and_write(
            record,
            key=_KEY,
            discharge_status="bogus",
            z3_status="discharged",
            **_SIGN_KWARGS,
        )


def test_sign_and_write_rejects_inconsistent_pairing():
    """sign_and_write refuses to sign discharge_status='discharged' when Z3
    actually returned 'failed' or 'unknown' — that would let the verifier
    write a stronger claim than Z3 supported."""
    record = _record()
    with pytest.raises(SigningError):
        sign_and_write(
            record,
            key=_KEY,
            discharge_status="discharged",
            z3_status="failed",
            **_SIGN_KWARGS,
        )


def test_sign_and_write_rejects_missing_obligation_sha():
    record = _record()
    record["proof"]["obligation_sha"] = ""
    with pytest.raises(SigningError):
        sign_and_write(
            record,
            key=_KEY,
            discharge_status="discharged",
            z3_status="discharged",
            **_SIGN_KWARGS,
        )


def test_sign_and_write_rejects_missing_proof():
    record = _record()
    del record["proof"]
    with pytest.raises(SigningError):
        sign_and_write(
            record,
            key=_KEY,
            discharge_status="discharged",
            z3_status="discharged",
            **_SIGN_KWARGS,
        )


def test_sign_and_write_timestamp_default_is_iso8601_utc():
    record = _record()
    out = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        **_SIGN_KWARGS,
    )
    ts = out["proof"]["verifier_signature"]["timestamp_utc"]
    assert ts.endswith("Z")
    assert "T" in ts


# ---------------------------------------------------------------------------
# verify_signature
# ---------------------------------------------------------------------------


def test_verify_round_trip_passes():
    record = _record()
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        **_SIGN_KWARGS,
    )
    assert (
        verify_signature(
            signed,
            key=_KEY,
            **_SIGN_KWARGS,
        )
        is True
    )


def test_verify_with_wrong_key_fails():
    record = _record()
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        **_SIGN_KWARGS,
    )
    assert (
        verify_signature(
            signed,
            key=_OTHER_KEY,
            **_SIGN_KWARGS,
        )
        is False
    )


def test_verify_after_status_tamper_fails():
    """Adversarial: dispatcher tries to upgrade a 'failed' signature into a
    'discharged' claim by editing the discharge_status field. The MAC was
    computed over the original status, so the tampered record fails to verify."""
    record = _record()
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="failed",
        z3_status="failed",
        **_SIGN_KWARGS,
    )
    signed["proof"]["discharge_status"] = "discharged"  # tamper
    assert (
        verify_signature(
            signed,
            key=_KEY,
            **_SIGN_KWARGS,
        )
        is False
    )


def test_verify_after_obligation_sha_tamper_fails():
    record = _record()
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        **_SIGN_KWARGS,
    )
    signed["proof"]["obligation_sha"] = "f" * 64  # tamper
    assert (
        verify_signature(
            signed,
            key=_KEY,
            **_SIGN_KWARGS,
        )
        is False
    )


def test_verify_unsigned_record_fails():
    record = _record()
    assert (
        verify_signature(
            record,
            key=_KEY,
            **_SIGN_KWARGS,
        )
        is False
    )


def test_verify_signature_with_wrong_algorithm_fails():
    record = _record()
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        **_SIGN_KWARGS,
    )
    signed["proof"]["verifier_signature"]["algorithm"] = "ed25519"  # claim wrong algo
    assert (
        verify_signature(
            signed,
            key=_KEY,
            **_SIGN_KWARGS,
        )
        is False
    )


def test_verify_handles_garbage_input_without_raising():
    """Adversarial input shapes (None, list, malformed dict) must yield False
    without raising — the C16 plugin's call site does not want crashes."""
    assert (
        verify_signature(
            None,
            key=_KEY,
            **_SIGN_KWARGS,
        )
        is False
    )  # type: ignore[arg-type]
    assert (
        verify_signature(
            [],
            key=_KEY,
            **_SIGN_KWARGS,
        )
        is False
    )  # type: ignore[arg-type]
    assert (
        verify_signature(
            {"proof": "not a dict"},
            key=_KEY,
            **_SIGN_KWARGS,
        )
        is False
    )
    assert (
        verify_signature(
            {"proof": {"verifier_signature": "bad"}},
            key=_KEY,
            **_SIGN_KWARGS,
        )
        is False
    )


def test_signed_discharge_status_values_constant():
    assert SIGNED_DISCHARGE_STATUS_VALUES == frozenset(
        {
            "discharged",
            "failed",
            "timeout",
            "unknown",
        }
    )


# ---------------------------------------------------------------------------
# Cumulative-pre-soak Patch 6 (Gate 1, 2026-05-04) regression tests:
# verify_signature now requires authoritative record_idx, closing the
# intra-bundle row-replay niche surfaced by GPT-5 in chunk A of the
# 2026-05-04-v-kernel-v0_2-cumulative tribunal review.
# ---------------------------------------------------------------------------


def test_verify_with_wrong_record_idx_fails():
    """Adversarial: a signed proof for record_idx=0 is copied into a verifier
    call asking about record_idx=5. Pre-Patch-6, verify_signature read the
    record_idx from the sig dict (which still says 0) and verified successfully
    against payload(record_idx=0) — even though the verifier was asking about
    a different row. This is the intra-bundle row-replay surface for templated
    dispatches where two rows might share (bundle_id, refine_text,
    recheck_context, obligation_sha). Post-Patch-6, the caller-authoritative
    record_idx must match the sig's self-report."""
    record = _record()
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        **_SIGN_KWARGS,
    )
    # Caller asks about row 5 — sig was minted for row 0.
    other_row_kwargs = dict(_SIGN_KWARGS)
    other_row_kwargs["record_idx"] = 5
    assert verify_signature(signed, key=_KEY, **other_row_kwargs) is False


def test_verify_with_bool_record_idx_fails():
    """isinstance(True, int) is True in Python; verify_signature must exclude
    bool subclass so a forgetful caller passing record_idx=True doesn't silently
    verify a sig minted for record_idx=1."""
    record = _record()
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_SIGN_KWARGS["bundle_id"],
        refine_text=_SIGN_KWARGS["refine_text"],
        recheck_context=_SIGN_KWARGS["recheck_context"],
        record_idx=1,
    )
    bool_kwargs = dict(_SIGN_KWARGS)
    bool_kwargs["record_idx"] = True  # type: ignore[assignment]
    assert verify_signature(signed, key=_KEY, **bool_kwargs) is False


def test_verify_with_negative_record_idx_fails():
    record = _record()
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        **_SIGN_KWARGS,
    )
    neg_kwargs = dict(_SIGN_KWARGS)
    neg_kwargs["record_idx"] = -1
    assert verify_signature(signed, key=_KEY, **neg_kwargs) is False


# ============================================================================
# Gate 3a frontier-pair P5 (Opus 4.7 §a2 + §a4, 2026-05-19)
# ============================================================================


def test_proof_kind_rebinding_breaks_signature_verify():
    """Gate 3a P5: V16 signatures must bind `proof.kind`. Pre-patch the
    HMAC payload did not include kind, so a sig minted for
    `proof.kind='smt-z3'` re-verified cleanly after the dispatcher rewrote
    proof.kind to 'lean-4'. The C16 plugin's optional Z3 re-discharge is
    gated by `proof['kind'] == 'smt-z3'`; rewriting routes around the
    re-discharge check without breaking the HMAC, laundering a Z3-
    discharged claim as a Lean-4 obligation that the v0.2 backend would
    never actually attempt to re-verify.

    Falsifiable prediction (Opus 4.7 §a2): sign with kind='smt-z3',
    mutate to kind='lean-4', re-verify. Pre-patch: True. Post-patch: False
    — kind is now in the canonical HMAC payload, so any mutation breaks
    MAC equality."""
    record = _record()
    assert record["proof"]["kind"] == "smt-z3"
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        **_SIGN_KWARGS,
    )
    # Mutate proof.kind post-signing. The sig dict itself is untouched.
    signed["proof"]["kind"] = "lean-4"

    assert verify_signature(signed, key=_KEY, **_SIGN_KWARGS) is False


def test_proof_kind_missing_at_verify_rejected():
    """Gate 3a P5: deleting proof.kind on a signed record causes verify
    to reject (returns False) rather than crashing or admitting under a
    sentinel default. Mirrors the discipline of P4's missing-bundle_id
    test on the V14 stream."""
    record = _record()
    signed = sign_and_write(
        record,
        key=_KEY,
        discharge_status="discharged",
        z3_status="discharged",
        **_SIGN_KWARGS,
    )
    del signed["proof"]["kind"]
    assert verify_signature(signed, key=_KEY, **_SIGN_KWARGS) is False


def test_proof_kind_required_at_sign_time():
    """Gate 3a P5: sign_and_write rejects a record missing proof.kind
    with a clear SigningError. The verifier cannot make sense of a sig
    that didn't bind a kind, so the binding must be enforced fail-fast
    at the signing layer."""
    record = _record()
    del record["proof"]["kind"]
    with pytest.raises(SigningError) as exc:
        sign_and_write(
            record,
            key=_KEY,
            discharge_status="discharged",
            z3_status="discharged",
            **_SIGN_KWARGS,
        )
    assert "kind" in str(exc.value).lower()


def test_v16_payload_carries_kind_domain_separation_tag():
    """Gate 3a P5: V14 (`_build_stamp_upgrade_payload`) and V15
    (`_build_trace_payload`) carry `_kind="stamp_upgrade.v0.2"` and
    `_kind="execution_trace.v0.2"` respectively. V16 was the asymmetric
    anchor — the other two streams added `_kind` to defend AGAINST
    V16-shaped payloads. Closing the asymmetry."""
    from audit_bundle.discharge.verifier_signing import _build_payload

    payload = _build_payload(
        bundle_id=_BUNDLE_ID,
        record_idx=0,
        kind="smt-z3",
        obligation_sha="a" * 64,
        refine_text_sha256="b" * 64,
        context_canonical_sha256="c" * 64,
        discharge_status="discharged",
        z3_status="discharged",
        verifier_id="v-kernel-test",
        timestamp_utc="2026-05-19T00:00:00Z",
    )
    # Canonical bytes must carry both `_kind` and `kind`.
    assert b'"_kind":"discharge_proof.v0.2"' in payload
    assert b'"kind":"smt-z3"' in payload


# ---------------------------------------------------------------------------
# Payload-key drift guards — _PAYLOAD_KEYS / _STAMP_UPGRADE_PAYLOAD_KEYS are
# the documented contract of the HMAC payload; the builders hardcode the dict
# literals. _PAYLOAD_KEYS drifted silently once (P5 added `_kind`/`kind` to
# the builder only). These pin constant == builder output.
# ---------------------------------------------------------------------------


def test_payload_keys_constant_matches_builder():
    import json as _json

    from audit_bundle.discharge.verifier_signing import _build_payload, _PAYLOAD_KEYS

    payload = _json.loads(
        _build_payload(
            "b",
            0,
            "smt-z3",
            "0" * 64,
            "1" * 64,
            "2" * 64,
            "discharged",
            "discharged",
            "v-kernel-test",
            "2026-06-10T00:00:00Z",
        )
    )
    assert sorted(payload.keys()) == sorted(_PAYLOAD_KEYS)


def test_stamp_upgrade_payload_keys_constant_matches_builder():
    import json as _json

    from audit_bundle.discharge.verifier_signing import (
        _build_stamp_upgrade_payload,
        _STAMP_UPGRADE_PAYLOAD_KEYS,
    )

    payload = _json.loads(
        _build_stamp_upgrade_payload(
            bundle_id="b",
            record_idx=0,
            from_stamp="UNVERIFIED",
            to_stamp="TARGET",
            upgrade_reason="discharged",
            discharge_obligation_sha="0" * 64,
            verifier_id="v-kernel-test",
            timestamp_utc="2026-06-10T00:00:00Z",
        )
    )
    assert sorted(payload.keys()) == sorted(_STAMP_UPGRADE_PAYLOAD_KEYS)
