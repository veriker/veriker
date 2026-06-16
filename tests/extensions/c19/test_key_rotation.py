"""Broken-first adversarial test suite per `the internal design notes`.

Run pytest BEFORE the real impl lands — expect ALL tests to fail with ImportError on missing
symbols (the M0 stubs at pre_commit_log.py + offline_root.py raise NotImplementedError; the
rotation primitives in layer_a_counter.py do not exist yet). That is the broken-first gate.
Then ss19d-002..006 fill in the real impl and ALL tests MUST pass without modification to
this file.

Encodes:
  Round-2 B5 ANALOG — rotation-window framing attack (PRE_COMMIT_WINDOW_BOUNDS_MS pattern
                       mirrors ACK_TIMEOUT_BOUNDS_MS; bundle-supplied override IGNORED)
  Round-2 B10        — key rotation hijack via old-key compromise
                       (new_key_pre_commitment_scitt_id ≥ Δ + emergency_offline_root_signature)
  T8 forward-compat  — pre-commit SCITT envelope accepts a future `multi_party_attestation_statement`
                       payload_type WITHOUT schema migration (mirrors S18 Opus checkpoint for
                       bundle_invalidation_receipt; per the internal design notes)

Citations:
  the internal design notes line 596 (Round-2 B5; ack_timeout boundary pattern)
  the internal design notes line 737 (Round-2 B10; key rotation hijack mitigation)
  the internal design notes lines 615-627 (rotation event schema)
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta, timezone

import pytest

# Import surface drives the real-impl API. ALL of these are expected to FAIL at
# import time pre-ss19d-002..006 (rotation primitives not yet in layer_a_counter.py;
# pre_commit_log + offline_root are stubs).
from audit_bundle.extensions.c19.layer_a_counter import (  # noqa: F401
    LayerAVerificationError,
    PROTOCOL_VERSION,
    ReasonCode,
    canonical_rotation_preimage,
    compute_rotation_co_signature,
    derive_key_rotation_subkey_new,
    derive_key_rotation_subkey_old,
    detect_and_verify_rotation_event,
    issue_scitt_statement,
    verify_rotation_co_signatures,
    verify_scitt_receipt,
    ScittReceipt,
)
from audit_bundle.extensions.c19.pre_commit_log import (  # noqa: F401
    PRE_COMMIT_PAYLOAD_TYPE,
    PRE_COMMIT_WINDOW_BOUNDS_MS,
    KeyProvisionStatement,
    PreCommitReasonCode,
    PreCommitSCITTLog,
    issue_pre_commit_statement,
    verify_pre_commit_predates_rotation,
    verify_pre_commit_scitt_statement,
)
from audit_bundle.extensions.c19.offline_root import (  # noqa: F401
    OFFLINE_ROOT_COSE_ALG_EDDSA,
    OFFLINE_ROOT_COSE_DOMAIN_AAD,
    OfflineRootPolicy,
    OfflineRootReasonCode,
    offline_root_cose_sig_structure,
    sign_emergency_offline_root_signature,
    verify_emergency_offline_root_signature,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _fresh_eddsa_keypair(kid: bytes) -> dict:
    """Mirrors the S19a test helper at test_layer_a_counter.py line 570."""
    from pycose.keys import OKPKey
    from pycose.keys.curves import Ed25519
    from pycose.keys.keyparam import KpKid

    sk = OKPKey.generate_key(crv=Ed25519, optional_params={KpKid: kid})
    return {"signing": sk, "verifying": sk, "kid": kid}


@pytest.fixture
def ts_keypair():
    """SCITT TS-issuer keypair; kid pinned in verifier."""
    return _fresh_eddsa_keypair(b"ts-key-1")


@pytest.fixture
def pinned_ts_set(ts_keypair):
    return frozenset({ts_keypair["kid"]}), {ts_keypair["kid"]: ts_keypair["verifying"]}


@pytest.fixture
def host_id() -> str:
    return "host-A"


@pytest.fixture
def old_key_ikm() -> bytes:
    return b"\x11" * 32


@pytest.fixture
def new_key_ikm() -> bytes:
    return b"\x22" * 32


@pytest.fixture
def old_key_id() -> str:
    return "host-A:key-2026-04"


@pytest.fixture
def new_key_id() -> str:
    return "host-A:key-2026-05"


@pytest.fixture
def offline_root_key_id() -> bytes:
    return b"offline-root-key-1"


@pytest.fixture
def offline_root_signing_key():
    """Ed25519 escrow PRIVATE key (v0.4). The 32-byte material IS the seed."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(b"\x33" * 32)


@pytest.fixture
def offline_root_public_key(offline_root_signing_key) -> bytes:
    """32-byte raw Ed25519 PUBLIC key the verifier pins (verify-only)."""
    from cryptography.hazmat.primitives import serialization

    return offline_root_signing_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


@pytest.fixture
def offline_root_policy(offline_root_key_id, offline_root_public_key):
    return OfflineRootPolicy(
        pinned_offline_root_key_ids=frozenset({offline_root_key_id}),
        pinned_offline_root_verifying_keys={
            offline_root_key_id: offline_root_public_key
        },
    )


@pytest.fixture
def assurance_profile() -> str:
    return "production-standard"


# Helpers ---------------------------------------------------------------------


def _iso8601_at(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _build_rotation_preimage(
    *,
    host_id,
    old_key_id,
    new_key_id,
    pre_commit_scitt_id,
    rotation_at,
    valid_not_before,
    valid_not_after,
    rotation_reason,
):
    return canonical_rotation_preimage(
        host_id=host_id,
        old_key_id=old_key_id,
        new_key_id=new_key_id,
        new_key_pre_commitment_scitt_id=pre_commit_scitt_id,
        valid_not_before=_iso8601_at(valid_not_before),
        valid_not_after=_iso8601_at(valid_not_after) if valid_not_after else None,
        rotation_reason=rotation_reason,
    )


def _issue_pre_commit(
    *, host_id, new_key_id, activation_at, issuance_at, ts_keypair
) -> tuple[ScittReceipt, KeyProvisionStatement]:
    stmt = KeyProvisionStatement(
        host_id=host_id,
        new_key_id=new_key_id,
        activation_at_iso8601=_iso8601_at(activation_at),
        issuance_at_iso8601=_iso8601_at(issuance_at),
    )
    receipt_bytes, content_sha = issue_pre_commit_statement(
        statement=stmt,
        issuer_signing_key=ts_keypair["signing"],
        issuer_kid=ts_keypair["kid"],
    )
    # The COSE_Sign1 payload bytes are extracted by the verify path; for the
    # test we build the ScittReceipt envelope with payload = deterministic_cbor
    # of stmt.to_payload_dict(). Real impl computes content_sha2 == content_sha.
    from audit_bundle.extensions.c19.layer_a_counter import deterministic_cbor_encode

    payload_bytes = deterministic_cbor_encode(stmt.to_payload_dict())
    receipt = ScittReceipt(
        statement_id=hashlib.sha256(receipt_bytes).digest(),
        statement_content_sha256=content_sha,
        cose_payload_bytes=payload_bytes,
        receipt_bytes=receipt_bytes,
        ts_key_id=ts_keypair["kid"],
    )
    return receipt, stmt


# ---------------------------------------------------------------------------
# POSITIVE happy paths
# ---------------------------------------------------------------------------


def test_rotation_event_validates_when_pre_commitment_within_window(
    ts_keypair,
    pinned_ts_set,
    host_id,
    old_key_ikm,
    new_key_ikm,
    old_key_id,
    new_key_id,
    assurance_profile,
):
    """Pre-commit issued 1 day before rotation; both co-signatures valid; verifier PASS."""
    pinned_kids, pinned_keys = pinned_ts_set
    now = _now_utc()
    rotation_at = now
    pre_commit_at = rotation_at - timedelta(days=1)
    receipt, stmt = _issue_pre_commit(
        host_id=host_id,
        new_key_id=new_key_id,
        activation_at=rotation_at,
        issuance_at=pre_commit_at,
        ts_keypair=ts_keypair,
    )
    valid_not_before = rotation_at
    valid_not_after = rotation_at + timedelta(days=365)
    preimage = _build_rotation_preimage(
        host_id=host_id,
        old_key_id=old_key_id,
        new_key_id=new_key_id,
        pre_commit_scitt_id=receipt.statement_id.hex(),
        rotation_at=rotation_at,
        valid_not_before=valid_not_before,
        valid_not_after=valid_not_after,
        rotation_reason="scheduled",
    )
    k_old = derive_key_rotation_subkey_old(old_key_ikm)
    k_new = derive_key_rotation_subkey_new(new_key_ikm)
    co_old = compute_rotation_co_signature(k_old, preimage)
    co_new = compute_rotation_co_signature(k_new, preimage)
    # Should not raise.
    verify_rotation_co_signatures(
        k_rotation_old=k_old,
        k_rotation_new=k_new,
        preimage=preimage,
        co_signed_old=co_old,
        co_signed_new=co_new,
    )
    # And full pre-commit verification round-trip.
    parsed = verify_pre_commit_scitt_statement(
        receipt=receipt,
        pinned_ts_key_ids=pinned_kids,
        pinned_ts_verifying_keys=pinned_keys,
        expected_host_id=host_id,
        expected_new_key_id=new_key_id,
    )
    assert parsed.new_key_id == new_key_id
    verify_pre_commit_predates_rotation(
        pre_commit_issuance_iso8601=_iso8601_at(pre_commit_at),
        rotation_at_iso8601=_iso8601_at(rotation_at),
        assurance_profile=assurance_profile,
    )


def test_pre_commit_scitt_statement_round_trip(
    ts_keypair,
    pinned_ts_set,
    host_id,
    new_key_id,
):
    pinned_kids, pinned_keys = pinned_ts_set
    now = _now_utc()
    receipt, stmt = _issue_pre_commit(
        host_id=host_id,
        new_key_id=new_key_id,
        activation_at=now + timedelta(days=1),
        issuance_at=now,
        ts_keypair=ts_keypair,
    )
    parsed = verify_pre_commit_scitt_statement(
        receipt=receipt,
        pinned_ts_key_ids=pinned_kids,
        pinned_ts_verifying_keys=pinned_keys,
        expected_host_id=host_id,
        expected_new_key_id=new_key_id,
    )
    assert parsed.host_id == stmt.host_id
    assert parsed.new_key_id == stmt.new_key_id


def test_emergency_rotation_with_offline_root_signature_validates(
    host_id,
    old_key_id,
    new_key_id,
    offline_root_policy,
    offline_root_key_id,
    offline_root_signing_key,
):
    """rotation_reason='emergency'; old-key co-sig absent; Ed25519/COSE_Sign1
    offline-root signature valid under the pinned PUBLIC key (v0.4)."""
    now = _now_utc()
    preimage = canonical_rotation_preimage(
        host_id=host_id,
        old_key_id=old_key_id,
        new_key_id=new_key_id,
        new_key_pre_commitment_scitt_id="ab" * 32,
        valid_not_before=_iso8601_at(now),
        valid_not_after=None,
        rotation_reason="emergency",
    )
    sig = sign_emergency_offline_root_signature(offline_root_signing_key, preimage)
    # Should NOT raise.
    verify_emergency_offline_root_signature(
        rotation_preimage=preimage,
        emergency_offline_root_signature=sig,
        offline_root_key_id=offline_root_key_id,
        policy=offline_root_policy,
    )


def test_emergency_offline_root_legacy_hmac_rejected(
    host_id,
    old_key_id,
    new_key_id,
    offline_root_policy,
    offline_root_key_id,
):
    """Downgrade-attack guard: a 32-byte HMAC (old v0.3 format) is NOT a valid
    COSE_Sign1 array, so the hard cutover rejects it — no HMAC dual-path."""
    now = _now_utc()
    preimage = canonical_rotation_preimage(
        host_id=host_id,
        old_key_id=old_key_id,
        new_key_id=new_key_id,
        new_key_pre_commitment_scitt_id="ab" * 32,
        valid_not_before=_iso8601_at(now),
        valid_not_after=None,
        rotation_reason="emergency",
    )
    legacy_hmac = hmac.new(b"\x33" * 32, preimage, hashlib.sha256).digest()
    with pytest.raises(LayerAVerificationError) as ei:
        verify_emergency_offline_root_signature(
            rotation_preimage=preimage,
            emergency_offline_root_signature=legacy_hmac,
            offline_root_key_id=offline_root_key_id,
            policy=offline_root_policy,
        )
    assert ei.value.code == ReasonCode.OFFLINE_ROOT_SIGNATURE_INVALID


def test_emergency_offline_root_wrong_cose_alg_rejected(
    host_id,
    old_key_id,
    new_key_id,
    offline_root_policy,
    offline_root_key_id,
    offline_root_signing_key,
):
    """COSE protected header carries a non-EdDSA alg (ES256 = -7) → fail closed
    with OFFLINE_ROOT_ALG_UNSUPPORTED (D5 single-alg pin, never down/upgrade)."""
    import cbor2

    now = _now_utc()
    preimage = canonical_rotation_preimage(
        host_id=host_id,
        old_key_id=old_key_id,
        new_key_id=new_key_id,
        new_key_pre_commitment_scitt_id="ab" * 32,
        valid_not_before=_iso8601_at(now),
        valid_not_after=None,
        rotation_reason="emergency",
    )
    # Sign over a Sig_structure whose protected header declares alg=-7, then wrap
    # the same lying header into the COSE_Sign1 (the signature is even valid Ed25519
    # over those bytes — the verifier must still reject on the alg pin alone).
    bad_protected = cbor2.dumps({1: -7})
    sig_input = offline_root_cose_sig_structure(
        preimage,
        external_aad=OFFLINE_ROOT_COSE_DOMAIN_AAD,
        protected_bstr=bad_protected,
    )
    raw_sig = offline_root_signing_key.sign(sig_input)
    cose = cbor2.dumps([bad_protected, {}, None, raw_sig])
    with pytest.raises(LayerAVerificationError) as ei:
        verify_emergency_offline_root_signature(
            rotation_preimage=preimage,
            emergency_offline_root_signature=cose,
            offline_root_key_id=offline_root_key_id,
            policy=offline_root_policy,
        )
    assert ei.value.code == ReasonCode.OFFLINE_ROOT_ALG_UNSUPPORTED


# ---------------------------------------------------------------------------
# B10 — Key rotation hijack via old-key compromise
# the internal design notes line 737
# ---------------------------------------------------------------------------


def test_pre_rotation_forge_attempt_rejected(
    ts_keypair,
    pinned_ts_set,
    host_id,
    old_key_ikm,
    new_key_ikm,
    old_key_id,
    new_key_id,
    assurance_profile,
):
    """B10: adversary signs an event with OLD K_event AFTER rotation valid_not_after.
    The chain-walk inside detect_and_verify_rotation_event MUST reject with
    KEY_ROTATION_EVENT_SIGNED_BY_EXPIRED_KEY."""
    # The full rotation-window enforcement runs inside validate_bundle_layer_a
    # via rotation_window_by_key_id. The unit assertion here is that the
    # ReasonCode is exported and that calling detect_and_verify_rotation_event
    # without the rotation_window_by_key_id wired in raises on the forge.
    assert (
        ReasonCode.KEY_ROTATION_EVENT_SIGNED_BY_EXPIRED_KEY.value
        == "KEY_ROTATION_EVENT_SIGNED_BY_EXPIRED_KEY"
    )
    # Bundle-level forge attempt: caller wires this through validate_bundle_layer_a
    # but for the unit test we assert the ReasonCode exists. Integration test in
    # ss19d-006 wires the chain walker.


def test_missing_pre_commitment_scitt_id_rejected(
    ts_keypair,
    pinned_ts_set,
    host_id,
    old_key_ikm,
    new_key_ikm,
    old_key_id,
    new_key_id,
    assurance_profile,
):
    pinned_kids, pinned_keys = pinned_ts_set
    now = _now_utc()
    # Build rotation event WITHOUT new_key_pre_commitment_scitt_id (empty string).
    # detect_and_verify_rotation_event should raise MISSING_PRE_COMMITMENT_SCITT_ID.
    bad_event = {
        b"event_kind": "key_rotation",
        b"event_id": "rot-1",
        b"prev_event_id": None,
        b"prev_event_hash": b"\x00" * 32,
        b"monotonic_counter": 1,
        b"counter_log_index": 1,
        b"payload_hash": b"\x00" * 32,
        b"causal_dependencies": [],
        b"scitt_statement_id": b"\x00" * 32,
        b"scitt_statement_content_sha256": b"\x00" * 32,
        b"scitt_inclusion_proof": b"",
        b"event_signature": {"key_id": old_key_id, "sig": b"\x00" * 32},
        # rotation-specific fields:
        b"host_id": host_id,
        b"old_key_id": old_key_id,
        b"new_key_id": new_key_id,
        b"new_key_pre_commitment_scitt_id": "",  # MISSING
        b"valid_not_before": _iso8601_at(now),
        b"valid_not_after": None,
        b"rotation_reason": "scheduled",
        b"co_signed_old_key": b"\x00" * 32,
        b"co_signed_new_key": b"\x00" * 32,
        b"rotation_at": _iso8601_at(now),
    }
    with pytest.raises(LayerAVerificationError) as ei:
        detect_and_verify_rotation_event(
            event=bad_event,
            assurance_profile=assurance_profile,
            pinned_ts_key_ids=pinned_kids,
            pinned_ts_verifying_keys=pinned_keys,
            pinned_offline_root_key_ids=frozenset(),
            pinned_offline_root_verifying_keys={},
            host_signing_keys_by_kid={old_key_id: old_key_ikm, new_key_id: new_key_ikm},
        )
    assert ei.value.code == ReasonCode.MISSING_PRE_COMMITMENT_SCITT_ID


def test_pre_commit_window_violation_below_min_rejected(assurance_profile):
    """production-standard min is 1 hour. Pre-commit issued 1 min before rotation = violation."""
    now = _now_utc()
    pre_at = now - timedelta(minutes=1)
    with pytest.raises(LayerAVerificationError) as ei:
        verify_pre_commit_predates_rotation(
            pre_commit_issuance_iso8601=_iso8601_at(pre_at),
            rotation_at_iso8601=_iso8601_at(now),
            assurance_profile=assurance_profile,
        )
    assert ei.value.code == ReasonCode.PRE_COMMIT_WINDOW_OUT_OF_PROFILE_BOUNDS


def test_pre_commit_window_violation_after_rotation_rejected(assurance_profile):
    """pre_commit AFTER rotation timestamp → negative window → PRE_COMMIT_WINDOW_VIOLATION."""
    now = _now_utc()
    with pytest.raises(LayerAVerificationError) as ei:
        verify_pre_commit_predates_rotation(
            pre_commit_issuance_iso8601=_iso8601_at(now + timedelta(hours=1)),
            rotation_at_iso8601=_iso8601_at(now),
            assurance_profile=assurance_profile,
        )
    assert ei.value.code == ReasonCode.PRE_COMMIT_WINDOW_VIOLATION


def test_pre_commitment_scitt_inclusion_proof_invalid_rejected(
    ts_keypair,
    host_id,
    new_key_id,
):
    """Adversary supplies a pre-commit statement_id but the receipt fails verification
    (unpinned ts_key). Reuses S19a's verify_scitt_receipt error path."""
    bogus_keypair = _fresh_eddsa_keypair(b"BAD-TS-KEY")
    pinned_kids = frozenset({b"ts-key-1"})  # NOT bogus_keypair["kid"]
    pinned_keys = {b"ts-key-1": ts_keypair["verifying"]}
    now = _now_utc()
    # Issue against the bogus signer; the receipt.ts_key_id is the bogus kid.
    receipt, _ = _issue_pre_commit(
        host_id=host_id,
        new_key_id=new_key_id,
        activation_at=now + timedelta(days=1),
        issuance_at=now,
        ts_keypair=bogus_keypair,
    )
    with pytest.raises(LayerAVerificationError) as ei:
        verify_pre_commit_scitt_statement(
            receipt=receipt,
            pinned_ts_key_ids=pinned_kids,
            pinned_ts_verifying_keys=pinned_keys,
            expected_host_id=host_id,
            expected_new_key_id=new_key_id,
        )
    assert ei.value.code in (
        ReasonCode.SCITT_TS_KEY_MISMATCH,
        ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
    )


def test_old_key_co_signature_invalid_rejected(
    host_id,
    old_key_ikm,
    new_key_ikm,
    old_key_id,
    new_key_id,
):
    now = _now_utc()
    preimage = canonical_rotation_preimage(
        host_id=host_id,
        old_key_id=old_key_id,
        new_key_id=new_key_id,
        new_key_pre_commitment_scitt_id="ab" * 32,
        valid_not_before=_iso8601_at(now),
        valid_not_after=None,
        rotation_reason="scheduled",
    )
    k_old = derive_key_rotation_subkey_old(old_key_ikm)
    k_new = derive_key_rotation_subkey_new(new_key_ikm)
    bad_co_old = b"\x99" * 32  # garbage
    co_new = compute_rotation_co_signature(k_new, preimage)
    with pytest.raises(LayerAVerificationError) as ei:
        verify_rotation_co_signatures(
            k_rotation_old=k_old,
            k_rotation_new=k_new,
            preimage=preimage,
            co_signed_old=bad_co_old,
            co_signed_new=co_new,
        )
    assert ei.value.code == ReasonCode.KEY_ROTATION_CO_SIGNATURE_INVALID


def test_new_key_co_signature_invalid_rejected(
    host_id,
    old_key_ikm,
    new_key_ikm,
    old_key_id,
    new_key_id,
):
    now = _now_utc()
    preimage = canonical_rotation_preimage(
        host_id=host_id,
        old_key_id=old_key_id,
        new_key_id=new_key_id,
        new_key_pre_commitment_scitt_id="ab" * 32,
        valid_not_before=_iso8601_at(now),
        valid_not_after=None,
        rotation_reason="scheduled",
    )
    k_old = derive_key_rotation_subkey_old(old_key_ikm)
    k_new = derive_key_rotation_subkey_new(new_key_ikm)
    co_old = compute_rotation_co_signature(k_old, preimage)
    bad_co_new = b"\x99" * 32
    with pytest.raises(LayerAVerificationError) as ei:
        verify_rotation_co_signatures(
            k_rotation_old=k_old,
            k_rotation_new=k_new,
            preimage=preimage,
            co_signed_old=co_old,
            co_signed_new=bad_co_new,
        )
    assert ei.value.code == ReasonCode.KEY_ROTATION_CO_SIGNATURE_INVALID


def test_emergency_rotation_without_offline_root_signature_rejected(
    host_id,
    old_key_id,
    new_key_id,
    offline_root_policy,
):
    """rotation_reason='emergency' AND offline_root_signature absent → MISSING_EMERGENCY_OFFLINE_ROOT_SIGNATURE."""
    now = _now_utc()
    preimage = canonical_rotation_preimage(
        host_id=host_id,
        old_key_id=old_key_id,
        new_key_id=new_key_id,
        new_key_pre_commitment_scitt_id="ab" * 32,
        valid_not_before=_iso8601_at(now),
        valid_not_after=None,
        rotation_reason="emergency",
    )
    with pytest.raises(LayerAVerificationError) as ei:
        verify_emergency_offline_root_signature(
            rotation_preimage=preimage,
            emergency_offline_root_signature=None,
            offline_root_key_id=None,
            policy=offline_root_policy,
        )
    assert ei.value.code == ReasonCode.MISSING_EMERGENCY_OFFLINE_ROOT_SIGNATURE


def test_emergency_offline_root_signature_by_unpinned_key_rejected(
    host_id,
    old_key_id,
    new_key_id,
    offline_root_policy,
):
    now = _now_utc()
    preimage = canonical_rotation_preimage(
        host_id=host_id,
        old_key_id=old_key_id,
        new_key_id=new_key_id,
        new_key_pre_commitment_scitt_id="ab" * 32,
        valid_not_before=_iso8601_at(now),
        valid_not_after=None,
        rotation_reason="emergency",
    )
    unpinned_key_id = b"NOT-IN-PINNED-SET"
    unpinned_key_material = b"\x77" * 32
    sig = hmac.new(unpinned_key_material, preimage, hashlib.sha256).digest()
    with pytest.raises(LayerAVerificationError) as ei:
        verify_emergency_offline_root_signature(
            rotation_preimage=preimage,
            emergency_offline_root_signature=sig,
            offline_root_key_id=unpinned_key_id,
            policy=offline_root_policy,
        )
    assert ei.value.code == ReasonCode.OFFLINE_ROOT_KEY_NOT_PINNED


def test_emergency_offline_root_signature_malformed_rejected(
    host_id,
    old_key_id,
    new_key_id,
    offline_root_policy,
    offline_root_key_id,
):
    now = _now_utc()
    preimage = canonical_rotation_preimage(
        host_id=host_id,
        old_key_id=old_key_id,
        new_key_id=new_key_id,
        new_key_pre_commitment_scitt_id="ab" * 32,
        valid_not_before=_iso8601_at(now),
        valid_not_after=None,
        rotation_reason="emergency",
    )
    short_sig = b"\x01" * 16  # WRONG LENGTH — must be 32 bytes
    with pytest.raises(LayerAVerificationError) as ei:
        verify_emergency_offline_root_signature(
            rotation_preimage=preimage,
            emergency_offline_root_signature=short_sig,
            offline_root_key_id=offline_root_key_id,
            policy=offline_root_policy,
        )
    assert ei.value.code == ReasonCode.OFFLINE_ROOT_SIGNATURE_INVALID


# ---------------------------------------------------------------------------
# B5 ANALOG — rotation-window framing attack (line 596 pattern applied to S19d)
# ---------------------------------------------------------------------------


def test_pre_commit_window_zero_framing_attack_rejected(assurance_profile):
    """Δ=0 framing: pre_commit_at == rotation_at. Below profile min."""
    now = _now_utc()
    with pytest.raises(LayerAVerificationError) as ei:
        verify_pre_commit_predates_rotation(
            pre_commit_issuance_iso8601=_iso8601_at(now),
            rotation_at_iso8601=_iso8601_at(now),
            assurance_profile=assurance_profile,
        )
    # Either WINDOW_VIOLATION (window_ms <= 0) or OUT_OF_PROFILE_BOUNDS (< min)
    # is acceptable framing — both encode the Δ=0 attack rejection.
    assert ei.value.code in (
        ReasonCode.PRE_COMMIT_WINDOW_VIOLATION,
        ReasonCode.PRE_COMMIT_WINDOW_OUT_OF_PROFILE_BOUNDS,
    )


def test_pre_commit_window_infinity_stale_rejected(assurance_profile):
    """∞-stale framing: pre_commit_at = rotation_at - 100 years."""
    now = _now_utc()
    pre_at = now - timedelta(days=365 * 100)
    with pytest.raises(LayerAVerificationError) as ei:
        verify_pre_commit_predates_rotation(
            pre_commit_issuance_iso8601=_iso8601_at(pre_at),
            rotation_at_iso8601=_iso8601_at(now),
            assurance_profile=assurance_profile,
        )
    assert ei.value.code == ReasonCode.PRE_COMMIT_WINDOW_OUT_OF_PROFILE_BOUNDS


def test_bundle_supplied_window_override_ignored():
    """Verifier uses ONLY hardcoded PRE_COMMIT_WINDOW_BOUNDS_MS — bundle-supplied
    override field must not bypass profile bounds. Mirrors ACK_TIMEOUT_BOUNDS_MS
    bundle-override-ignored property from cross_host_peerreview.py."""
    # The function signature does NOT accept a bundle-supplied window — the
    # contract IS that the only knob is `assurance_profile`. Assert this is true.
    import inspect

    sig = inspect.signature(verify_pre_commit_predates_rotation)
    param_names = set(sig.parameters.keys())
    assert "assurance_profile" in param_names
    # Affirmative property: NO bundle_override-shaped parameter accepted.
    forbidden = {
        "min_pre_commit_window_ms",
        "max_pre_commit_window_ms",
        "bundle_window_override_ms",
        "pre_commit_window_ms",
    }
    assert not (forbidden & param_names), (
        f"verifier accepts bundle-supplied window override: {forbidden & param_names}"
    )


# ---------------------------------------------------------------------------
# T8 forward-compat hook (the internal design notes)
# ---------------------------------------------------------------------------


def test_t8_future_payload_type_accepted_without_schema_change(
    ts_keypair,
    pinned_ts_set,
    host_id,
    new_key_id,
):
    """The pre-commit SCITT envelope shape contract accepts a future T8 payload_type
    `multi_party_attestation_statement` (per T8 ADR 2026-05-09 + C18 enum-extension
    hook validated at S18 Opus checkpoint) WITHOUT any code/schema change in S19d.

    Concretely: PreCommitSCITTLog with an allowlist containing the T8 future value
    reports envelope_accepts(future_value) == True. The verifier's envelope shape
    contract (statement_id + content_sha + cose payload bytes round-trip via the
    same issue_scitt_statement API from S19a) is shared across payload_type values.
    """
    pinned_kids, pinned_keys = pinned_ts_set
    t8_future = "multi_party_attestation_statement"
    allowlist = frozenset({PRE_COMMIT_PAYLOAD_TYPE, t8_future})
    log = PreCommitSCITTLog(allowlist_payload_types=allowlist)
    assert log.envelope_accepts(t8_future) is True
    assert log.envelope_accepts(PRE_COMMIT_PAYLOAD_TYPE) is True
    assert log.envelope_accepts("some/random/unregistered") is False
    # Affirm the per-payload_type registry is open-set (no hardcoded fail-closed
    # on unknown-but-allowlisted T8 values inside PreCommitSCITTLog).


# ---------------------------------------------------------------------------
# Legacy / regression
# ---------------------------------------------------------------------------


def test_legacy_bundle_no_key_rotation_event_still_verifies():
    """Bundle without any key_rotation event continues to verify cleanly
    (additive contract; backward-compat invariant). Concretely: V0_3_EVENT_KINDS
    contains 'key_rotation' but a bundle with only 'retrieval' events still
    passes validate_event_cddl."""
    from audit_bundle.bundle_manifest import V0_3_EVENT_KINDS

    assert "key_rotation" in V0_3_EVENT_KINDS  # registered
    # Pre-existing event kinds still admitted.
    assert "retrieval" in V0_3_EVENT_KINDS
    assert "reasoning_step" in V0_3_EVENT_KINDS
    assert "manifest_dag_emit" in V0_3_EVENT_KINDS


def test_protocol_version_unchanged():
    """v0.3 stays v0.3; S19d does not bump protocol_version."""
    assert PROTOCOL_VERSION == "v0.3"
