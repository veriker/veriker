"""S19b cross-host COSE_Sign1 / Ed25519 authenticator — adversarial suite.

Encodes the attack model the S19b tribunal (Pass 1 + 2) ratified BEFORE the
verify logic existed: per-protocol domain separation (C1/C1a), kid-namespace
partition + route-on-kid (C2b), canonical kid (C2a), single-alg pin (D5), and
fail-closed COSE parsing (C5/C7). Each adversarial case asserts its own reason
code; first-failure-wins per the C9 specific-message contract.
"""

from __future__ import annotations

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import pytest

from audit_bundle.extensions.c19.offline_root import (
    OFFLINE_ROOT_COSE_ALG_EDDSA,
    OFFLINE_ROOT_COSE_DOMAIN_AAD,
    offline_root_cose_sig_structure,
)
from audit_bundle.extensions.c19.cross_host_peerreview import (
    CROSS_HOST_COSE_DOMAIN_AAD,
    CrossOrgKeyPolicy,
    cross_host_cose_kid,
    sign_cross_host_authenticator_cose,
    verify_cross_host_authenticator_cose,
    verify_cross_host_edge_authenticator,
    derive_cross_host_receipt_key,
    sign_cross_host_authenticator,
    construct_sender_signature_preimage,
    construct_ack_preimage,
)


# ---------------------------------------------------------------------------
# Frozen determinism vectors (C6/C9/C1a) — guards against cbor2-version drift
# after the hand-rolled CBOR subset was deleted. Bytes pinned 2026-05-22.
# ---------------------------------------------------------------------------

_FROZEN_SENDER_PREIMAGE_HEX = "8b78226e6578692f61756469742f76302e332f63726f73732d686f73742d726563656970746476302e3366686f73742d4166686f73742d4263636964636d696458200000000000000000000000000000000000000000000000000000000000000000011903e86362696450aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
_FROZEN_ACK_PREIMAGE_HEX = "8e78266e6578692f61756469742f76302e332f63726f73732d686f73742d726563656970742d61636b6476302e3366686f73742d4166686f73742d4263636964636d696458200000000000000000000000000000000000000000000000000000000000000000026361636bf6636269641903e80150aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def test_frozen_sender_preimage_vector():
    p = construct_sender_signature_preimage(
        sender_host_id="host-A",
        receiver_host_id="host-B",
        channel_id="cid",
        message_id="mid",
        message_hash=b"\x00" * 32,
        sender_local_counter=1,
        ack_timeout_ms=1000,
        bundle_id="bid",
        receiver_challenge_token=b"\xaa" * 16,
    )
    assert p.hex() == _FROZEN_SENDER_PREIMAGE_HEX.replace(" ", "")


def test_frozen_ack_preimage_vector():
    a = construct_ack_preimage(
        sender_host_id="host-A",
        receiver_host_id="host-B",
        channel_id="cid",
        message_id="mid",
        message_hash=b"\x00" * 32,
        receiver_local_counter=2,
        kind="ack",
        reason_code_if_nack=None,
        bundle_id="bid",
        ack_timeout_ms=1000,
        sender_local_counter=1,
        receiver_challenge_token=b"\xaa" * 16,
    )
    assert a.hex() == _FROZEN_ACK_PREIMAGE_HEX.replace(" ", "")


def test_frozen_cose_envelope_vector():
    priv = Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32)
    cose = sign_cross_host_authenticator_cose(private_key=priv, preimage=b"frozen")
    assert cose.hex() == (
        "8443a10127a0f658403861817e7684ba48909f5d0e6f6d269ab65c5b738449de07214b39"
        "edee763654fd4ea26d165d49aa4c49c5a1f7cf1a41300fb92ae3f612c09dbec1d45fecc504"
    )


def _key(seed_byte: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed_byte]) * 32)


def _raw_pub(priv: Ed25519PrivateKey) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


_PREIMAGE = b"cross-host-canonical-preimage-bytes"


# ---------------------------------------------------------------------------
# Positive path
# ---------------------------------------------------------------------------


def test_valid_cose_sign_verify_roundtrip():
    priv = _key(1)
    cose = sign_cross_host_authenticator_cose(private_key=priv, preimage=_PREIMAGE)
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=_raw_pub(priv), preimage=_PREIMAGE, cose_bytes=cose
    )
    assert ok and code == "PASS"


def test_valid_cose_verify_accepts_hex_string():
    priv = _key(2)
    cose = sign_cross_host_authenticator_cose(private_key=priv, preimage=_PREIMAGE)
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=_raw_pub(priv), preimage=_PREIMAGE, cose_bytes=cose.hex()
    )
    assert ok and code == "PASS"


# ---------------------------------------------------------------------------
# Cross-protocol replay closure (C1/C1a) — THE load-bearing crypto test
# ---------------------------------------------------------------------------


def test_offline_root_signature_not_replayable_as_cross_host():
    """A COSE_Sign1 minted under the OFFLINE-ROOT domain tag must NOT verify as a
    cross-host authenticator, even with the same key, same preimage, same alg."""
    priv = _key(3)
    protected = cbor2.dumps({1: OFFLINE_ROOT_COSE_ALG_EDDSA})
    sig = priv.sign(
        offline_root_cose_sig_structure(
            _PREIMAGE,
            external_aad=OFFLINE_ROOT_COSE_DOMAIN_AAD,  # wrong domain for cross-host
            protected_bstr=protected,
        )
    )
    forged = cbor2.dumps([protected, {}, None, sig])
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=_raw_pub(priv), preimage=_PREIMAGE, cose_bytes=forged
    )
    assert not ok and code == "SENDER_SIGNATURE_VERIFICATION_FAILED"


def test_cross_host_signature_not_replayable_as_offline_root():
    """Symmetric direction: a cross-host sig must not verify under the offline-root
    domain reconstruction (proves the tags genuinely separate, not just one side)."""
    priv = _key(4)
    cose = sign_cross_host_authenticator_cose(private_key=priv, preimage=_PREIMAGE)
    _protected, _u, _p, signature = cbor2.loads(cose)
    # Reconstruct what an offline-root verifier would check (its own domain tag):
    offline_input = offline_root_cose_sig_structure(
        _PREIMAGE, external_aad=OFFLINE_ROOT_COSE_DOMAIN_AAD
    )
    from cryptography.exceptions import InvalidSignature

    with pytest.raises(InvalidSignature):
        priv.public_key().verify(signature, offline_input)


# ---------------------------------------------------------------------------
# Adversarial COSE parsing / crypto
# ---------------------------------------------------------------------------


def test_tampered_signature_byte_rejected():
    priv = _key(5)
    cose = bytearray(
        sign_cross_host_authenticator_cose(private_key=priv, preimage=_PREIMAGE)
    )
    cose[-1] ^= 0x01
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=_raw_pub(priv), preimage=_PREIMAGE, cose_bytes=bytes(cose)
    )
    assert not ok and code == "SENDER_SIGNATURE_VERIFICATION_FAILED"


def test_wrong_key_rejected():
    priv = _key(6)
    other = _key(7)
    cose = sign_cross_host_authenticator_cose(private_key=priv, preimage=_PREIMAGE)
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=_raw_pub(other), preimage=_PREIMAGE, cose_bytes=cose
    )
    assert not ok and code == "SENDER_SIGNATURE_VERIFICATION_FAILED"


def test_tampered_preimage_rejected():
    priv = _key(8)
    cose = sign_cross_host_authenticator_cose(private_key=priv, preimage=_PREIMAGE)
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=_raw_pub(priv), preimage=_PREIMAGE + b"!", cose_bytes=cose
    )
    assert not ok and code == "SENDER_SIGNATURE_VERIFICATION_FAILED"


def test_wrong_alg_in_protected_header_rejected():
    priv = _key(9)
    protected = cbor2.dumps({1: -7})  # ES256, not the pinned EdDSA
    sig = priv.sign(
        offline_root_cose_sig_structure(
            _PREIMAGE, external_aad=CROSS_HOST_COSE_DOMAIN_AAD, protected_bstr=protected
        )
    )
    cose = cbor2.dumps([protected, {}, None, sig])
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=_raw_pub(priv), preimage=_PREIMAGE, cose_bytes=cose
    )
    assert not ok and code == "CROSS_HOST_ALG_UNSUPPORTED"


def test_unknown_protected_header_label_rejected():
    priv = _key(10)
    protected = cbor2.dumps({1: OFFLINE_ROOT_COSE_ALG_EDDSA, 99: b"x"})
    sig = priv.sign(
        offline_root_cose_sig_structure(
            _PREIMAGE, external_aad=CROSS_HOST_COSE_DOMAIN_AAD, protected_bstr=protected
        )
    )
    cose = cbor2.dumps([protected, {}, None, sig])
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=_raw_pub(priv), preimage=_PREIMAGE, cose_bytes=cose
    )
    assert not ok and code == "CROSS_HOST_COSE_HEADER_UNSUPPORTED"


# ---------------------------------------------------------------------------
# A4 (red-team) — non-canonical protected headers rejected before the alg pin.
# Each header is SIGNED over its exact (non-canonical) bytes, so the signature
# itself is valid; the rejection MUST come from the canonical-header gate, not
# a signature failure. All three variants below decode to {1: EdDSA}.
# ---------------------------------------------------------------------------


def _sign_with_protected(priv, protected_bstr):
    sig = priv.sign(
        offline_root_cose_sig_structure(
            _PREIMAGE,
            external_aad=CROSS_HOST_COSE_DOMAIN_AAD,
            protected_bstr=protected_bstr,
        )
    )
    return cbor2.dumps([protected_bstr, {}, None, sig])


def test_a4_dup_key_protected_header_rejected():
    """{1:-7, 1:-8} (a2 01 26 01 27): cbor2 last-wins -> EdDSA here, but ES256
    to a first-wins consumer. The parser differential that defeats the D5 pin."""
    priv = _key(40)
    protected = bytes([0xA2, 0x01, 0x26, 0x01, 0x27])
    cose = _sign_with_protected(priv, protected)
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=_raw_pub(priv), preimage=_PREIMAGE, cose_bytes=cose
    )
    assert not ok and code == "COSE_PROTECTED_HEADER_NONCANONICAL"


def test_a4_indefinite_length_protected_header_rejected():
    """0xBF .. 0xFF indefinite-length map {1:-8}."""
    priv = _key(41)
    protected = bytes([0xBF, 0x01, 0x27, 0xFF])
    cose = _sign_with_protected(priv, protected)
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=_raw_pub(priv), preimage=_PREIMAGE, cose_bytes=cose
    )
    assert not ok and code == "COSE_PROTECTED_HEADER_NONCANONICAL"


def test_a4_non_shortest_int_protected_header_rejected():
    """{1:-8} with -8 as a 1-byte negative (0x38 0x07) instead of shortest 0x27."""
    priv = _key(42)
    protected = bytes([0xA1, 0x01, 0x38, 0x07])
    cose = _sign_with_protected(priv, protected)
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=_raw_pub(priv), preimage=_PREIMAGE, cose_bytes=cose
    )
    assert not ok and code == "COSE_PROTECTED_HEADER_NONCANONICAL"


def test_a4_canonical_protected_header_still_verifies():
    """Control: the shortest-form canonical {1:-8} header verifies green."""
    priv = _key(43)
    protected = cbor2.dumps({1: OFFLINE_ROOT_COSE_ALG_EDDSA})
    cose = _sign_with_protected(priv, protected)
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=_raw_pub(priv), preimage=_PREIMAGE, cose_bytes=cose
    )
    assert ok and code == "PASS"


def test_a5_ack_bound_to_challenged_send():
    """A5: an ack now binds bundle_id / ack_timeout_ms / sender_local_counter /
    receiver_challenge_token. An ack minted for one send must NOT verify against
    a preimage that differs only in the (previously-unbound) challenge token —
    i.e. it can't be transplanted onto a different challenged send."""
    priv = _key(44)
    base = dict(
        sender_host_id="host-A",
        receiver_host_id="host-B",
        channel_id="cid",
        message_id="mid",
        message_hash=b"\x00" * 32,
        receiver_local_counter=2,
        kind="ack",
        reason_code_if_nack=None,
        bundle_id="bid",
        ack_timeout_ms=1000,
        sender_local_counter=1,
        receiver_challenge_token=b"\xaa" * 16,
    )
    legit = construct_ack_preimage(**base)
    cose = sign_cross_host_authenticator_cose(private_key=priv, preimage=legit)
    # Verifies against its own challenged send.
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=_raw_pub(priv), preimage=legit, cose_bytes=cose, role="ack"
    )
    assert ok and code == "PASS"
    # Same ack bytes, but the receiver's anti-replay nonce differs → the
    # reconstructed preimage differs → the signature no longer matches.
    transplanted = construct_ack_preimage(
        **{**base, "receiver_challenge_token": b"\xbb" * 16}
    )
    assert transplanted != legit
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=_raw_pub(priv),
        preimage=transplanted,
        cose_bytes=cose,
        role="ack",
    )
    assert not ok and code == "ACK_SIGNATURE_VERIFICATION_FAILED"


def test_wrong_signature_length_rejected():
    priv = _key(11)
    protected = cbor2.dumps({1: OFFLINE_ROOT_COSE_ALG_EDDSA})
    cose = cbor2.dumps([protected, {}, None, b"\x00" * 32])  # 32 != 64
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=_raw_pub(priv), preimage=_PREIMAGE, cose_bytes=cose
    )
    assert not ok and code == "CROSS_HOST_COSE_MALFORMED"


def test_non_four_element_cose_rejected():
    priv = _key(12)
    cose = cbor2.dumps([b"only", b"three", b"elems"])
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=_raw_pub(priv), preimage=_PREIMAGE, cose_bytes=cose
    )
    assert not ok and code == "CROSS_HOST_COSE_MALFORMED"


def test_garbage_bytes_rejected():
    priv = _key(13)
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=_raw_pub(priv), preimage=_PREIMAGE, cose_bytes=b"\xff\xff\xff"
    )
    assert not ok and code == "CROSS_HOST_COSE_MALFORMED"


def test_ack_role_emits_ack_failure_code():
    priv = _key(14)
    cose = bytearray(
        sign_cross_host_authenticator_cose(private_key=priv, preimage=_PREIMAGE)
    )
    cose[-1] ^= 0x01
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=_raw_pub(priv),
        preimage=_PREIMAGE,
        cose_bytes=bytes(cose),
        role="ack",
    )
    assert not ok and code == "ACK_SIGNATURE_VERIFICATION_FAILED"


# ---------------------------------------------------------------------------
# Canonical kid (C2a)
# ---------------------------------------------------------------------------


def test_canonical_kid_is_raw_pubkey():
    priv = _key(15)
    pub = _raw_pub(priv)
    assert cross_host_cose_kid(pub) == pub
    assert len(cross_host_cose_kid(pub)) == 32


def test_canonical_kid_rejects_non_32_bytes():
    with pytest.raises(ValueError):
        cross_host_cose_kid(b"short")


# ---------------------------------------------------------------------------
# CrossOrgKeyPolicy + route-on-kid (C2b)
# ---------------------------------------------------------------------------


def test_kid_partition_violation_rejected_at_construction():
    """A kid bound to BOTH primitives is a construction error (the kid-collision
    attack surface Opus surfaced in Pass 2)."""
    shared_kid = b"\xaa" * 32
    with pytest.raises(ValueError, match="partition"):
        CrossOrgKeyPolicy(
            pinned_cose_keys={shared_kid: b"\x01" * 32},
            pinned_hmac_ikm={shared_kid: b"ikm"},
        )


def test_route_on_kid_valid_cose_edge():
    priv = _key(16)
    pub = _raw_pub(priv)
    kid = cross_host_cose_kid(pub)
    policy = CrossOrgKeyPolicy(
        pinned_cose_keys={kid: pub},
        pinned_hmac_ikm={},
        pinned_cose_key_hosts={kid: "host-A"},
    )
    cose = sign_cross_host_authenticator_cose(private_key=priv, preimage=_PREIMAGE)
    ok, code, _ = verify_cross_host_edge_authenticator(
        kid=kid,
        presented_kind="cose_sign1",
        preimage=_PREIMAGE,
        authenticator=cose,
        policy=policy,
        info_label="nexi/audit/v0.3/cross-host-receipt",
        expected_host_id="host-A",
    )
    assert ok and code == "PASS"


def test_unpinned_kid_fails_closed():
    policy = CrossOrgKeyPolicy(pinned_cose_keys={}, pinned_hmac_ikm={})
    ok, code, _ = verify_cross_host_edge_authenticator(
        kid=b"\x00" * 32,
        presented_kind="cose_sign1",
        preimage=_PREIMAGE,
        authenticator=b"\x00",
        policy=policy,
        info_label="nexi/audit/v0.3/cross-host-receipt",
        expected_host_id="host-A",
    )
    assert not ok and code == "CROSS_HOST_KEY_NOT_PINNED"


def test_presented_kind_mismatch_is_policy_violation():
    """kid pinned for COSE, but the bundle declares hmac → hard fail on the
    mechanism-policy mismatch (routing ignores the attacker-controlled field)."""
    priv = _key(17)
    pub = _raw_pub(priv)
    kid = cross_host_cose_kid(pub)
    policy = CrossOrgKeyPolicy(
        pinned_cose_keys={kid: pub},
        pinned_hmac_ikm={},
        pinned_cose_key_hosts={kid: "host-A"},
    )
    ok, code, _ = verify_cross_host_edge_authenticator(
        kid=kid,
        presented_kind="hmac",  # attacker tries to flip primitive
        preimage=_PREIMAGE,
        authenticator=b"\x00" * 32,
        policy=policy,
        info_label="nexi/audit/v0.3/cross-host-receipt",
        expected_host_id="host-A",
    )
    assert not ok and code == "CROSS_HOST_AUTH_MECHANISM_POLICY_VIOLATION"


def test_kid_collision_attack_closed_even_without_presented_kind():
    """Even if the attacker omits authenticator_kind, a kid pinned for COSE routes
    to COSE; an HMAC tag presented under it fails COSE-decode, never HMAC verify."""
    priv = _key(18)
    pub = _raw_pub(priv)
    kid = cross_host_cose_kid(pub)
    policy = CrossOrgKeyPolicy(
        pinned_cose_keys={kid: pub},
        pinned_hmac_ikm={},
        pinned_cose_key_hosts={kid: "host-A"},
    )
    hmac_tag = sign_cross_host_authenticator(
        K=b"k" * 32, preimage=_PREIMAGE
    )  # 32 bytes
    ok, code, _ = verify_cross_host_edge_authenticator(
        kid=kid,
        presented_kind=None,
        preimage=_PREIMAGE,
        authenticator=hmac_tag,
        policy=policy,
        info_label="nexi/audit/v0.3/cross-host-receipt",
        expected_host_id="host-A",
    )
    assert not ok and code == "CROSS_HOST_COSE_MALFORMED"


def test_route_on_kid_valid_single_org_hmac_edge():
    """D3 option (c): single-org HMAC still works, keyed on a pinned kid bound to
    the org IKM — no in-bundle key material, routing on the pinned kid."""
    ikm = b"org-signing-key-material-32-bytes!!"[:32]
    kid = b"\x11" * 32
    policy = CrossOrgKeyPolicy(pinned_cose_keys={}, pinned_hmac_ikm={kid: ikm})
    info = "nexi/audit/v0.3/cross-host-receipt"
    K = derive_cross_host_receipt_key(sender_signing_key_material=ikm, info_label=info)
    preimage = construct_sender_signature_preimage(
        sender_host_id="a",
        receiver_host_id="b",
        channel_id="c",
        message_id="m",
        message_hash=b"\x00" * 32,
        sender_local_counter=1,
        ack_timeout_ms=1000,
        bundle_id="bid",
        receiver_challenge_token=b"\x01" * 16,
    )
    sig = sign_cross_host_authenticator(K=K, preimage=preimage)
    ok, code, _ = verify_cross_host_edge_authenticator(
        kid=kid,
        presented_kind="hmac",
        preimage=preimage,
        authenticator=sig,
        policy=policy,
        info_label=info,
        expected_host_id="a",
    )
    assert ok and code == "PASS"
