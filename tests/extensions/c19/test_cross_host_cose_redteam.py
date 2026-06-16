"""S19b cross-host COSE_Sign1 RED-TEAM + FINDING-1 FIX regression suite.

History: a fresh-context adversarial red-team of commit a2539ea5 found FINDING-1
(HIGH) — the cross-org COSE path verified both the sender authenticator and the
`receiver_acknowledgment` under whatever kid each carried, with NO bind from the
ack's kid to `receiver_host_id`. The shipped policy pinned ONE key per two-party
edge and the builder signed BOTH directions with the sender's key, so a single
dishonest sender could mint a fully-verifying edge whose acknowledgment the named
receiver never produced.

FIX (C2c kid->host binding): `CrossOrgKeyPolicy` now binds every COSE kid to
exactly one owning host (constructor-enforced), and
`verify_cross_host_edge_authenticator` REQUIRES `expected_host_id` and rejects an
authenticator whose kid is not the one bound to that host
(`CROSS_HOST_KEY_HOST_BINDING_VIOLATION`). The sender authenticator must be the
sender's kid; the ack must be the receiver's own kid. A sender cannot forge the
receiver's acknowledgment under its own key, and cannot present it under the
receiver's kid because it does not hold the receiver's private key.

This suite locks the fix (the forgery is now rejected) and keeps the surviving
crypto-core confirmations: cross-protocol replay closure (C1/C1a), single-alg
EdDSA pin (D5), empty-external_aad rejection, and fail-closed COSE parsing.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as _ser

from audit_bundle.extensions.c19.cross_host_peerreview import (
    CROSS_HOST_COSE_DOMAIN_AAD,
    CrossOrgKeyPolicy,
    _CTX_ACK,
    _CTX_SENDER,
    construct_ack_preimage,
    construct_sender_signature_preimage,
    cross_host_cose_kid,
    sign_cross_host_authenticator_cose,
    verify_cross_host_authenticator_cose,
    verify_cross_host_edge_authenticator,
)
from audit_bundle.extensions.c19.offline_root import (
    OFFLINE_ROOT_COSE_ALG_EDDSA,
    OFFLINE_ROOT_COSE_DOMAIN_AAD,
    OfflineRootPolicy,
    offline_root_cose_sig_structure,
    sign_emergency_offline_root_signature,
    verify_emergency_offline_root_signature,
)
from audit_bundle.extensions.c19.layer_a_counter import (
    LayerAVerificationError,
    ReasonCode,
)
import cbor2

_SENDER_HOST = "DE-RP"
_RECEIVER_HOST = "be-qtsp-qes-signer"


def _raw_pub(priv: Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)


def _sender_preimage(**ov) -> bytes:
    base = dict(
        sender_host_id=_SENDER_HOST,
        receiver_host_id=_RECEIVER_HOST,
        channel_id="ch_derp_qes_crossorg",
        message_id="m_crossorg_qes_request_1",
        message_hash=b"\x11" * 32,
        sender_local_counter=1,
        ack_timeout_ms=1_000,
        bundle_id="eidas-eudi-minimal-rc",
        receiver_challenge_token=b"\x22" * 32,
    )
    base.update(ov)
    return construct_sender_signature_preimage(**base)


def _ack_preimage(**ov) -> bytes:
    base = dict(
        sender_host_id=_SENDER_HOST,
        receiver_host_id=_RECEIVER_HOST,
        channel_id="ch_derp_qes_crossorg",
        message_id="m_crossorg_qes_request_1",
        message_hash=b"\x11" * 32,
        receiver_local_counter=1,
        kind="ack",
        reason_code_if_nack=None,
        bundle_id="eidas-eudi-minimal-rc",
        ack_timeout_ms=1_000,
        sender_local_counter=1,
        receiver_challenge_token=b"\x22" * 32,
    )
    base.update(ov)
    return construct_ack_preimage(**base)


def _two_party_policy():
    """Verifier policy mirroring the fixed eidas pilot: sender + receiver keys,
    each bound to its own host (C2c)."""
    sender_priv = Ed25519PrivateKey.from_private_bytes(b"\x44" * 32)
    receiver_priv = Ed25519PrivateKey.from_private_bytes(b"\x55" * 32)
    sender_pub, receiver_pub = _raw_pub(sender_priv), _raw_pub(receiver_priv)
    sender_kid = cross_host_cose_kid(sender_pub)
    receiver_kid = cross_host_cose_kid(receiver_pub)
    policy = CrossOrgKeyPolicy(
        pinned_cose_keys={sender_kid: sender_pub, receiver_kid: receiver_pub},
        pinned_hmac_ikm={},
        pinned_cose_key_hosts={
            sender_kid: _SENDER_HOST,
            receiver_kid: _RECEIVER_HOST,
        },
    )
    return sender_priv, receiver_priv, sender_kid, receiver_kid, policy


# ===========================================================================
# FINDING-1 FIX — sender can no longer forge the receiver's acknowledgment
# ===========================================================================


def test_FINDING1_fixed_sender_ack_under_own_kid_rejected():
    """The original break: sender signs an ack with its OWN key and presents it
    under its OWN (sender) kid. The verifier now rejects on the kid->host bind —
    the ack must come from the receiver's kid."""
    sender_priv, _receiver_priv, sender_kid, _rk, policy = _two_party_policy()
    forged = sign_cross_host_authenticator_cose(
        private_key=sender_priv, preimage=_ack_preimage(receiver_local_counter=999)
    )
    ok, code, _ = verify_cross_host_edge_authenticator(
        kid=sender_kid,  # attacker presents the SENDER's kid for the ack
        presented_kind="cose_sign1",
        preimage=_ack_preimage(receiver_local_counter=999),
        authenticator=forged,
        policy=policy,
        info_label=_CTX_ACK,
        expected_host_id=_RECEIVER_HOST,  # ack role binds to receiver
        role="ack",
    )
    assert ok is False
    assert code == "CROSS_HOST_KEY_HOST_BINDING_VIOLATION"


def test_FINDING1_fixed_sender_ack_under_receiver_kid_fails_crypto():
    """The other escape route: sender presents the forged ack under the RECEIVER's
    kid. The kid->host bind passes, but the receiver's pinned PUBLIC key cannot
    validate a sender-signed signature → ACK_SIGNATURE_VERIFICATION_FAILED. A
    single dishonest sender has no winning move."""
    sender_priv, _rp, _sk, receiver_kid, policy = _two_party_policy()
    ack_pre = _ack_preimage()
    forged = sign_cross_host_authenticator_cose(
        private_key=sender_priv, preimage=ack_pre
    )
    ok, code, _ = verify_cross_host_edge_authenticator(
        kid=receiver_kid,
        presented_kind="cose_sign1",
        preimage=ack_pre,
        authenticator=forged,
        policy=policy,
        info_label=_CTX_ACK,
        expected_host_id=_RECEIVER_HOST,
        role="ack",
    )
    assert ok is False
    assert code == "ACK_SIGNATURE_VERIFICATION_FAILED"


def test_FINDING1_fixed_legitimate_receiver_signed_ack_passes():
    """Positive: a genuine ack signed by the RECEIVER's key under the receiver's
    kid verifies — the fix rejects forgeries, not honest acknowledgments."""
    _sp, receiver_priv, _sk, receiver_kid, policy = _two_party_policy()
    ack_pre = _ack_preimage()
    legit = sign_cross_host_authenticator_cose(
        private_key=receiver_priv, preimage=ack_pre
    )
    ok, code, _ = verify_cross_host_edge_authenticator(
        kid=receiver_kid,
        presented_kind="cose_sign1",
        preimage=ack_pre,
        authenticator=legit,
        policy=policy,
        info_label=_CTX_ACK,
        expected_host_id=_RECEIVER_HOST,
        role="ack",
    )
    assert ok is True and code == "PASS"


def test_FINDING1_fixed_sender_kid_misused_for_sender_role_still_ok():
    """Regression guard: the sender authenticator under the sender's kid + sender
    host still passes — the bind is per-direction, not a blanket reject."""
    sender_priv, _rp, sender_kid, _rk, policy = _two_party_policy()
    sp = _sender_preimage()
    sig = sign_cross_host_authenticator_cose(private_key=sender_priv, preimage=sp)
    ok, code, _ = verify_cross_host_edge_authenticator(
        kid=sender_kid,
        presented_kind="cose_sign1",
        preimage=sp,
        authenticator=sig,
        policy=policy,
        info_label=_CTX_SENDER,
        expected_host_id=_SENDER_HOST,
        role="sender",
    )
    assert ok is True and code == "PASS"


def test_C2c_hardening_empty_expected_host_id_rejected():
    """Tribunal HIGH: an empty/None expected_host_id cannot collapse the bind
    into a tautology — it is rejected before the comparison."""
    sender_priv, _rp, sender_kid, _rk, policy = _two_party_policy()
    sp = _sender_preimage()
    sig = sign_cross_host_authenticator_cose(private_key=sender_priv, preimage=sp)
    for bad_host in ("", None):
        ok, code, _ = verify_cross_host_edge_authenticator(
            kid=sender_kid,
            presented_kind="cose_sign1",
            preimage=sp,
            authenticator=sig,
            policy=policy,
            info_label=_CTX_SENDER,
            expected_host_id=bad_host,
            role="sender",
        )
        assert ok is False and code == "CROSS_HOST_KEY_HOST_BINDING_VIOLATION"


def test_C2c_hardening_policy_rejects_empty_host_binding_at_construction():
    """Tribunal HIGH: a kid pinned to an empty/non-string host is rejected at
    construction so the verifier never faces a degenerate (None/"") pin."""
    priv = Ed25519PrivateKey.from_private_bytes(b"\xee" * 32)
    kid = cross_host_cose_kid(_raw_pub(priv))
    for bad in ("", None):
        with pytest.raises(ValueError, match="host-binding"):
            CrossOrgKeyPolicy(
                pinned_cose_keys={kid: _raw_pub(priv)},
                pinned_hmac_ikm={},
                pinned_cose_key_hosts={kid: bad},
            )


def test_C2c_hardening_none_policy_fails_closed():
    """Tribunal LOW: the verifier defends its own API boundary against a missing
    policy rather than raising AttributeError."""
    ok, code, _ = verify_cross_host_edge_authenticator(
        kid=b"\x00" * 32,
        presented_kind="cose_sign1",
        preimage=_sender_preimage(),
        authenticator=b"\x00",
        policy=None,
        info_label=_CTX_SENDER,
        expected_host_id=_SENDER_HOST,
        role="sender",
    )
    assert ok is False and code == "CROSS_HOST_KEY_NOT_PINNED"


def test_FINDING1_fixed_policy_rejects_unbound_cose_kid_at_construction():
    """C2c construction guard: a COSE kid with no host binding cannot be
    constructed — the verifier can never silently fall back to the unbound
    (forgeable) path."""
    priv = Ed25519PrivateKey.from_private_bytes(b"\x66" * 32)
    kid = cross_host_cose_kid(_raw_pub(priv))
    with pytest.raises(ValueError, match="host-binding"):
        CrossOrgKeyPolicy(
            pinned_cose_keys={kid: _raw_pub(priv)},
            pinned_hmac_ikm={},
            # pinned_cose_key_hosts deliberately omitted
        )


# ===========================================================================
# SURVIVING CLAIMS — crypto core holds (these were and remain green)
# ===========================================================================


def test_survives_cross_protocol_replay_offline_to_crosshost_rejected():
    """C1/C1a: an offline-root COSE_Sign1 cannot verify as a cross-host
    authenticator over the same preimage (external_aad differs)."""
    priv = Ed25519PrivateKey.from_private_bytes(b"\x77" * 32)
    pre = _sender_preimage()
    offline_sig = sign_emergency_offline_root_signature(priv, pre)
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=_raw_pub(priv),
        preimage=pre,
        cose_bytes=offline_sig,
        role="sender",
    )
    assert ok is False
    assert code == "SENDER_SIGNATURE_VERIFICATION_FAILED"


def test_survives_cross_protocol_replay_crosshost_to_offline_rejected():
    """C1/C1a reverse direction."""
    priv = Ed25519PrivateKey.from_private_bytes(b"\x88" * 32)
    pub = _raw_pub(priv)
    pre = _sender_preimage()
    ch_sig = sign_cross_host_authenticator_cose(private_key=priv, preimage=pre)
    kid = cross_host_cose_kid(pub)
    policy = OfflineRootPolicy(
        pinned_offline_root_key_ids=frozenset({kid}),
        pinned_offline_root_verifying_keys={kid: pub},
    )
    with pytest.raises(LayerAVerificationError) as ei:
        verify_emergency_offline_root_signature(
            rotation_preimage=pre,
            emergency_offline_root_signature=ch_sig,
            offline_root_key_id=kid,
            policy=policy,
        )
    assert ei.value.code == ReasonCode.OFFLINE_ROOT_SIGNATURE_INVALID


def test_survives_empty_external_aad_rejected_by_shared_encoder():
    """C1a: the shared encoder refuses an empty domain tag."""
    with pytest.raises(ValueError):
        offline_root_cose_sig_structure(b"preimage", external_aad=b"")


def test_survives_es256_alg_rejected_fail_closed():
    """D5: alg=ES256 (-7) is rejected, not down-negotiated."""
    priv = Ed25519PrivateKey.from_private_bytes(b"\x99" * 32)
    pub = _raw_pub(priv)
    pre = _sender_preimage()
    es256_protected = cbor2.dumps({1: -7})
    sig = priv.sign(
        offline_root_cose_sig_structure(
            pre, external_aad=CROSS_HOST_COSE_DOMAIN_AAD, protected_bstr=es256_protected
        )
    )
    cose = cbor2.dumps([es256_protected, {}, None, sig])
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=pub, preimage=pre, cose_bytes=cose, role="sender"
    )
    assert ok is False and code == "CROSS_HOST_ALG_UNSUPPORTED"


@pytest.mark.parametrize(
    "bad", [None, b"", b"\xff\xff garbage", cbor2.dumps([1, 2, 3])]
)
def test_survives_malformed_cose_fails_closed(bad):
    """C4: every malformed COSE input returns ok=False, never an uncaught raise."""
    priv = Ed25519PrivateKey.from_private_bytes(b"\xab" * 32)
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=_raw_pub(priv),
        preimage=_sender_preimage(),
        cose_bytes=bad,
        role="sender",
    )
    assert ok is False
    assert code in {"CROSS_HOST_COSE_MALFORMED", "COSE_PROTECTED_HEADER_MALFORMED"}


# ===========================================================================
# MINOR-OBSERVATION FIX — offline-root rejects unknown protected-header labels
# (parity with the cross-host verifier; the two shared-encoder consumers agree).
# ===========================================================================


def test_offline_root_rejects_extra_protected_header_labels():
    priv = Ed25519PrivateKey.from_private_bytes(b"\xcd" * 32)
    pub = _raw_pub(priv)
    pre = b"rotation-preimage"
    kid = b"k_offline_root"
    # Protected header carries an extra (crit-like) label besides alg {1}.
    bad_protected = cbor2.dumps({1: OFFLINE_ROOT_COSE_ALG_EDDSA, 2: [99]})
    sig = priv.sign(
        offline_root_cose_sig_structure(
            pre, external_aad=OFFLINE_ROOT_COSE_DOMAIN_AAD, protected_bstr=bad_protected
        )
    )
    cose = cbor2.dumps([bad_protected, {}, None, sig])
    policy = OfflineRootPolicy(
        pinned_offline_root_key_ids=frozenset({kid}),
        pinned_offline_root_verifying_keys={kid: pub},
    )
    with pytest.raises(LayerAVerificationError) as ei:
        verify_emergency_offline_root_signature(
            rotation_preimage=pre,
            emergency_offline_root_signature=cose,
            offline_root_key_id=kid,
            policy=policy,
        )
    assert ei.value.code == ReasonCode.OFFLINE_ROOT_SIGNATURE_INVALID
