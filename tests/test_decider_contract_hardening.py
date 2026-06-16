"""tests/test_decider_contract_hardening.py — regression tests for the 2026-06-10
trust-decider contract-hardening pass (reviewer findings).

Each test pins a contract a decider/parse-helper previously violated:

  #1 b64url_nopad_decode is STRICT — non-alphabet characters raise (the stdlib
     urlsafe_b64decode silently strips them, which would let two distinct sidecar
     strings decode to identical bytes: envelope malleability).
  #2 _cmp_scalar_epsilon rejects a non-finite / negative epsilon in isolation
     (defence-in-depth; an inf epsilon would otherwise pass every delta).
  #3 SignatureVerifier.verify returns the documented (False, None) on off-contract
     (non-bytes / wrong-length) signature input instead of raising.
"""

from __future__ import annotations

import base64
import binascii

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit_bundle.dsse.pae import b64url_nopad_decode
from audit_bundle.rederivation.comparators import _cmp_scalar_epsilon
from audit_bundle.source_registry.signature_verifier import SignatureVerifier


# --- #1 strict base64url ----------------------------------------------------


def test_b64url_roundtrip_valid() -> None:
    payload = b"hello-strict-world!!"
    s = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    assert b64url_nopad_decode(s) == payload


def test_b64url_rejects_non_alphabet_chars() -> None:
    payload = b"hello-strict-world!!"
    s = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    # Replace one alphabet char (length preserved) with a non-alphabet char the
    # stdlib would otherwise silently strip — must now raise, not decode.
    for junk in ("\n", "*", " ", "+"):  # '+' is standard-b64, NOT urlsafe
        malleable = s[:4] + junk + s[5:]
        with pytest.raises(binascii.Error):
            b64url_nopad_decode(malleable)


# --- #2 epsilon defence-in-depth -------------------------------------------


def test_scalar_epsilon_rejects_non_finite_epsilon() -> None:
    ok, msg = _cmp_scalar_epsilon(1.0, 1e9, {"epsilon": float("inf")})
    assert ok is False and "finite" in msg


def test_scalar_epsilon_rejects_negative_epsilon() -> None:
    ok, _ = _cmp_scalar_epsilon(1.0, 1.0, {"epsilon": -1.0})
    assert ok is False


def test_scalar_epsilon_valid_still_passes() -> None:
    ok, _ = _cmp_scalar_epsilon(1.0, 1.0000001, {"epsilon": 1e-3})
    assert ok is True


# --- #3 signature verifier off-contract input ------------------------------


def _ed25519_pub_pem() -> bytes:
    return (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def test_signature_verifier_non_bytes_signature_is_false_not_crash() -> None:
    sv = SignatureVerifier()
    sv.register_key("k", _ed25519_pub_pem())
    # str signature_bytes (off-contract) -> documented (False, None), not TypeError
    ok, kid = sv.verify("cid", b"message", "not-bytes", "k")  # type: ignore[arg-type]
    assert ok is False and kid is None


def test_signature_verifier_wrong_length_signature_is_false_not_crash() -> None:
    sv = SignatureVerifier()
    sv.register_key("k", _ed25519_pub_pem())
    ok, kid = sv.verify("cid", b"message", b"\x00" * 10, "k")
    assert ok is False and kid is None
