"""Tests for asymmetric (Ed25519) disbursement-gate verdict signing.

Mirrors ``test_gate_verdict_signing.py`` (the HMAC suite) field-for-field, then
adds the load-bearing one the HMAC path structurally cannot offer:
``test_verify_key_holder_cannot_forge`` — a party holding ONLY the public
verify key cannot mint a signature that verifies.
"""

from __future__ import annotations

import pytest

from audit_bundle.gate import (
    Ed25519VerifierKey,
    Ed25519VerifyKey,
    SigningError,
    sign_gate_verdict_ed25519,
    sign_payload,
    verify_gate_verdict_ed25519,
    verify_payload,
)


# A fixed valid set of gate-verdict fields reused across tests.
_FIELDS = dict(
    bundle_id="bundle-001",
    case_id="case-001",
    rule_id="rule-001",
    gate="AUTO_APPROVE",
    rederived_net_cents=900_000_00,
    rules_sha="a" * 64,
)


def _sign(key, **overrides):
    return sign_gate_verdict_ed25519(**{**_FIELDS, **overrides}, key=key)


def _verify(verify_key, signature, **overrides):
    return verify_gate_verdict_ed25519(
        **{**_FIELDS, **overrides}, signature=signature, verify_key=verify_key
    )


def test_round_trip_valid_signature():
    key = Ed25519VerifierKey.generate()
    sig = _sign(key)
    assert _verify(key.public_key(), sig)


def test_tamper_gate_breaks_signature():
    key = Ed25519VerifierKey.generate()
    sig = _sign(key)
    assert not _verify(key.public_key(), sig, gate="HUMAN_REVIEW")


def test_tamper_amount_breaks_signature():
    key = Ed25519VerifierKey.generate()
    sig = _sign(key)
    assert not _verify(key.public_key(), sig, rederived_net_cents=1)


def test_tamper_bundle_id_breaks_signature():
    key = Ed25519VerifierKey.generate()
    sig = _sign(key)
    assert not _verify(key.public_key(), sig, bundle_id="bundle-002")


def test_tamper_case_id_breaks_signature():
    key = Ed25519VerifierKey.generate()
    sig = _sign(key)
    assert not _verify(key.public_key(), sig, case_id="case-002")


def test_tamper_rule_id_breaks_signature():
    key = Ed25519VerifierKey.generate()
    sig = _sign(key)
    assert not _verify(key.public_key(), sig, rule_id="rule-002")


def test_tamper_rules_sha_breaks_signature():
    key = Ed25519VerifierKey.generate()
    sig = _sign(key)
    assert not _verify(key.public_key(), sig, rules_sha="b" * 64)


def test_none_amount_round_trip():
    key = Ed25519VerifierKey.generate()
    sig = _sign(key, gate="HUMAN_REVIEW", rederived_net_cents=None)
    assert _verify(key.public_key(), sig, gate="HUMAN_REVIEW", rederived_net_cents=None)


def test_none_amount_distinct_from_zero():
    key = Ed25519VerifierKey.generate()
    sig = _sign(key, gate="HUMAN_REVIEW", rederived_net_cents=None)
    # A zero amount must not verify against a None-amount signature.
    assert not _verify(key.public_key(), sig, gate="HUMAN_REVIEW", rederived_net_cents=0)


def test_wrong_key_fails():
    key = Ed25519VerifierKey.generate()
    other = Ed25519VerifierKey.generate()
    sig = _sign(key)
    assert not _verify(other.public_key(), sig)


def test_invalid_gate_rejected_on_sign():
    # The shared canonical payload rejects any gate outside GATE_VALUES — signing
    # an out-of-domain gate raises (it can never become a real verdict).
    key = Ed25519VerifierKey.generate()
    with pytest.raises(SigningError):
        _sign(key, gate="NONSENSE")


def test_invalid_gate_returns_false_on_verify():
    # And verifying against an out-of-domain gate is a miss, never a raise.
    key = Ed25519VerifierKey.generate()
    sig = _sign(key)
    assert not _verify(key.public_key(), sig, gate="NONSENSE")


def test_domain_separation_distinct_payloads():
    key = Ed25519VerifierKey.generate()
    a = _sign(key)
    b = _sign(key, case_id="case-XYZ")
    assert a != b


def test_key_hex_round_trip():
    key = Ed25519VerifierKey.generate()
    restored_priv = Ed25519VerifierKey.from_hex(key.to_hex())
    sig = _sign(restored_priv)
    # And a public key reconstituted from hex still verifies.
    restored_pub = Ed25519VerifyKey.from_hex(key.public_key().to_hex())
    assert _verify(restored_pub, sig)


def test_empty_non_gate_fields_still_sign():
    # Every field except gate may be empty (gate must be in GATE_VALUES).
    key = Ed25519VerifierKey.generate()
    fields = dict(
        bundle_id="",
        case_id="",
        rule_id="",
        gate="AUTO_APPROVE",
        rederived_net_cents=None,
        rules_sha="",
    )
    sig = sign_gate_verdict_ed25519(**fields, key=key)
    assert verify_gate_verdict_ed25519(
        **fields, signature=sig, verify_key=key.public_key()
    )


def test_malformed_signature_returns_false():
    key = Ed25519VerifierKey.generate()
    assert not _verify(key.public_key(), "not-hex-zz")
    assert not _verify(key.public_key(), "abcd")  # valid hex, wrong length


def test_no_key_raises_fail_closed():
    # Fail-closed: a verify call with no key must raise, never silently pass.
    key = Ed25519VerifierKey.generate()
    sig = _sign(key)
    with pytest.raises(TypeError):
        verify_gate_verdict_ed25519(**_FIELDS, signature=sig, verify_key=None)


def test_verify_key_holder_cannot_forge():
    """THE load-bearing test: holding ONLY the public key cannot forge a verdict.

    A disburser is given the public verify key. It tries to mint its own
    "AUTO_APPROVE, $9M" verdict and have it verify. There is no API path from
    the public key to a valid signature — the private key is required.
    """
    verifier = Ed25519VerifierKey.generate()
    pub: Ed25519VerifyKey = verifier.public_key()  # all the disburser holds

    forged_fields = dict(
        bundle_id="bundle-FORGE",
        case_id="case-FORGE",
        rule_id="rule-FORGE",
        gate="AUTO_APPROVE",
        rederived_net_cents=9_000_000_00,
        rules_sha="f" * 64,
    )

    # 1. The signing function demands an Ed25519VerifierKey (private). The public
    #    key cannot be passed where a private signer is required.
    assert not hasattr(pub, "sign")
    assert not hasattr(pub, "_private")

    # 2. Best forgery available to a public-key holder: any byte string it
    #    invents. None verifies. Exhaust the plausible structural guesses.
    guesses = [
        "00" * 64,                       # all-zero 64-byte sig
        "ff" * 64,                       # all-ones 64-byte sig
        pub.to_hex() + pub.to_hex(),     # the public key bytes themselves (64B)
        sign_gate_verdict_ed25519(       # a *valid* sig over the forged fields
            **forged_fields,             # but minted with a DIFFERENT keypair
            key=Ed25519VerifierKey.generate(),
        ),
    ]
    for g in guesses:
        assert not verify_gate_verdict_ed25519(
            **forged_fields, signature=g, verify_key=pub
        )

    # 3. Sanity: the *legitimate* private holder CAN produce a verifying sig over
    #    the same fields — proving it's the private key, not the fields, that's
    #    the missing capability for the forger.
    real = sign_gate_verdict_ed25519(**forged_fields, key=verifier)
    assert verify_gate_verdict_ed25519(**forged_fields, signature=real, verify_key=pub)


# ---------------------------------------------------------------------------
# Generic sign_payload / verify_payload — the primitive the gate-verdict
# functions and pilot attestation legs build on. It signs ALREADY-canonical
# bytes; the caller owns the encoding.
# ---------------------------------------------------------------------------

_PAYLOAD = b"vkernel.test.domain\x00arbitrary-canonical-payload-bytes"


def test_payload_round_trip():
    key = Ed25519VerifierKey.generate()
    sig = sign_payload(_PAYLOAD, key)
    assert verify_payload(_PAYLOAD, sig, key.public_key())


def test_payload_tamper_breaks_signature():
    key = Ed25519VerifierKey.generate()
    sig = sign_payload(_PAYLOAD, key)
    assert not verify_payload(_PAYLOAD + b"x", sig, key.public_key())


def test_payload_wrong_key_fails():
    key = Ed25519VerifierKey.generate()
    other = Ed25519VerifierKey.generate()
    sig = sign_payload(_PAYLOAD, key)
    assert not verify_payload(_PAYLOAD, sig, other.public_key())


def test_payload_empty_bytes_round_trip():
    key = Ed25519VerifierKey.generate()
    sig = sign_payload(b"", key)
    assert verify_payload(b"", sig, key.public_key())


def test_payload_malformed_signature_returns_false():
    key = Ed25519VerifierKey.generate()
    assert not verify_payload(_PAYLOAD, "not-hex-zz", key.public_key())
    assert not verify_payload(_PAYLOAD, "abcd", key.public_key())  # valid hex, wrong length


def test_payload_non_str_signature_returns_false():
    key = Ed25519VerifierKey.generate()
    assert not verify_payload(_PAYLOAD, None, key.public_key())  # type: ignore[arg-type]


def test_sign_payload_rejects_public_key():
    # A public-only key cannot sign — fail-closed with TypeError, never a silent
    # empty/garbage signature.
    key = Ed25519VerifierKey.generate()
    with pytest.raises(TypeError):
        sign_payload(_PAYLOAD, key.public_key())  # type: ignore[arg-type]


def test_verify_payload_no_key_raises_fail_closed():
    key = Ed25519VerifierKey.generate()
    sig = sign_payload(_PAYLOAD, key)
    with pytest.raises(TypeError):
        verify_payload(_PAYLOAD, sig, None)  # type: ignore[arg-type]


def test_payload_verify_key_holder_cannot_forge():
    # The same load-bearing property as the gate-verdict path, at the generic
    # layer: holding only the public key cannot mint a verifying signature.
    verifier = Ed25519VerifierKey.generate()
    pub = verifier.public_key()
    forged = sign_payload(_PAYLOAD, Ed25519VerifierKey.generate())  # different keypair
    assert not verify_payload(_PAYLOAD, forged, pub)


def test_gate_verdict_signature_verifies_via_generic_helper():
    # The gate-verdict signer now delegates to sign_payload; a verdict signature
    # is therefore a plain payload signature over the canonical gate tuple. Prove
    # the two layers agree by verifying a gate verdict through verify_payload.
    from audit_bundle.gate.verdict_signing import _canonical_gate_payload

    key = Ed25519VerifierKey.generate()
    sig = _sign(key)
    payload = _canonical_gate_payload(**_FIELDS)
    assert verify_payload(payload, sig, key.public_key())
