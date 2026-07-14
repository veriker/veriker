"""RFC 5869 HKDF Appendix A vector regression for the hand-rolled
`_hkdf_extract` / `_hkdf_expand` in `audit_bundle.extensions.c19.layer_a_counter`.

Closes the standing test-vector gap (project memory `the internal design notes`):
the substrate's HKDF is hand-rolled rather than borrowed from `cryptography.hazmat`,
so RFC 5869 §2.2 / §2.3 conformance is a load-bearing property that must be pinned
against the official vectors — not just covered by output-shape unit tests
(`test_hkdf_output_is_32_bytes`, `test_hkdf_distinct_info_labels_…`).

Vectors transcribed from RFC 5869 Appendix A (Krawczyk + Eronen, May 2010).
Only the SHA-256 cases (A.1 / A.2 / A.3) are reproduced — Cases A.4 / A.5 / A.6
target SHA-1 and the substrate uses SHA-256 exclusively (see `_HKDF_HASH` in
layer_a_counter.py).

Bound standards:
  - RFC 5869 §2.2 (HKDF-Extract; empty-salt = HashLen zeros)
  - RFC 5869 §2.3 (HKDF-Expand; T(i) = HMAC-Hash(PRK, T(i-1) || info || i))
  - RFC 5869 Appendix A.1 / A.2 / A.3 (SHA-256 reference vectors)
  - RFC 2104 (HMAC), RFC 6234 (SHA-256)
"""

from __future__ import annotations

import hashlib
import hmac as _hmac

import pytest

from audit_bundle.extensions.c19.layer_a_counter import (
    _CTX_EVENT,
    _hkdf_expand,
    _hkdf_extract,
    derive_event_signature_key,
)


# ---------------------------------------------------------------------------
# RFC 5869 Appendix A SHA-256 vectors.
# ---------------------------------------------------------------------------

# Case 1 — A.1 "Basic test case with SHA-256".
_A1 = {
    "ikm": bytes.fromhex("0b" * 22),
    "salt": bytes.fromhex("000102030405060708090a0b0c"),
    "info": bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
    "L": 42,
    "prk": bytes.fromhex(
        "077709362c2e32df0ddc3f0dc47bba63"
        "90b6c73bb50f9c3122ec844ad7c2b3e5"
    ),
    "okm": bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    ),
}

# Case 2 — A.2 "Test with SHA-256 and longer inputs/outputs".
_A2 = {
    "ikm": bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f"
        "303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f"
    ),
    "salt": bytes.fromhex(
        "606162636465666768696a6b6c6d6e6f"
        "707172737475767778797a7b7c7d7e7f"
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    ),
    "info": bytes.fromhex(
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    ),
    "L": 82,
    "prk": bytes.fromhex(
        "06a6b88c5853361a06104c9ceb35b45c"
        "ef760014904671014a193f40c15fc244"
    ),
    "okm": bytes.fromhex(
        "b11e398dc80327a1c8e7f78c596a4934"
        "4f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09"
        "da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f"
        "1d87"
    ),
}

# Case 3 — A.3 "Test with SHA-256 and zero-length salt/info".
_A3 = {
    "ikm": bytes.fromhex("0b" * 22),
    "salt": b"",
    "info": b"",
    "L": 42,
    "prk": bytes.fromhex(
        "19ef24a32c717b167f33a91d6f648bdf"
        "96596776afdb6377ac434c1c293ccb04"
    ),
    "okm": bytes.fromhex(
        "8da4e775a563c18f715f802a063c5a31"
        "b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8"
    ),
}


_VECTORS = [
    pytest.param(_A1, id="rfc5869-A.1-sha256-basic"),
    pytest.param(_A2, id="rfc5869-A.2-sha256-long-io"),
    pytest.param(_A3, id="rfc5869-A.3-sha256-zero-len-salt-info"),
]


# ---------------------------------------------------------------------------
# Extract-stage tests.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("v", _VECTORS)
def test_hkdf_extract_matches_rfc5869_appendix_a(v):
    """`_hkdf_extract(salt, ikm)` byte-equals the RFC 5869 Appendix A PRK."""
    prk = _hkdf_extract(salt=v["salt"], ikm=v["ikm"])
    assert prk == v["prk"], (
        f"PRK mismatch: got {prk.hex()}, want {v['prk'].hex()}"
    )


# ---------------------------------------------------------------------------
# Expand-stage tests.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("v", _VECTORS)
def test_hkdf_expand_matches_rfc5869_appendix_a(v):
    """`_hkdf_expand(prk, info, L)` byte-equals the RFC 5869 Appendix A OKM."""
    okm = _hkdf_expand(prk=v["prk"], info=v["info"], length=v["L"])
    assert okm == v["okm"], (
        f"OKM mismatch: got {okm.hex()}, want {v['okm'].hex()}"
    )


# ---------------------------------------------------------------------------
# End-to-end (Extract + Expand) tests.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("v", _VECTORS)
def test_hkdf_extract_then_expand_end_to_end(v):
    """Full RFC 5869 chain: HKDF(salt, IKM, info, L) → expected OKM."""
    prk = _hkdf_extract(salt=v["salt"], ikm=v["ikm"])
    okm = _hkdf_expand(prk=prk, info=v["info"], length=v["L"])
    assert okm == v["okm"]


# ---------------------------------------------------------------------------
# Empty-salt edge case — exercised by every substrate `derive_*` call.
# ---------------------------------------------------------------------------


def test_hkdf_extract_empty_salt_substitutes_hashlen_zeros():
    """RFC 5869 §2.2 step 1: empty salt MUST resolve to HashLen zero octets,
    not be passed through as b"".

    `derive_event_signature_key` and the two `derive_key_rotation_subkey_*`
    helpers all call `_hkdf_extract(salt=b"", …)`; correct substitution is
    load-bearing for the K_event derivation.
    """
    ikm = bytes.fromhex("0b" * 22)
    expected = _hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    got = _hkdf_extract(salt=b"", ikm=ikm)
    assert got == expected, (
        "empty-salt did NOT substitute HashLen zeros — "
        f"got {got.hex()}, want {expected.hex()}"
    )


def test_hkdf_extract_empty_salt_equals_explicit_zero_salt():
    """Explicit `salt=b"\\x00"*32` and `salt=b""` must yield identical PRK."""
    ikm = bytes.fromhex("0b" * 22)
    prk_empty = _hkdf_extract(salt=b"", ikm=ikm)
    prk_zeros = _hkdf_extract(salt=b"\x00" * 32, ikm=ikm)
    assert prk_empty == prk_zeros


# ---------------------------------------------------------------------------
# Substrate-bound vector: derive_event_signature_key end-to-end against a
# hand-computed RFC-conformant chain. Pins the actual production call path.
# ---------------------------------------------------------------------------


def test_derive_event_signature_key_matches_rfc_conformant_chain():
    """`derive_event_signature_key(host_ikm)` byte-equals the hand-computed
    RFC 5869 chain with salt=HashLen zeros + info=_CTX_EVENT + L=32.

    This is the production call. If this test diverges from the textbook
    extract+expand composition, K_event is non-interoperable with any external
    HKDF implementation — and the cross-host-receipt construction silently
    relies on a non-standard KDF.
    """
    host_ikm = b"\x11" * 32

    # Reference implementation: RFC 5869 verbatim, no substrate calls.
    salt_zeros = b"\x00" * 32
    expected_prk = _hmac.new(salt_zeros, host_ikm, hashlib.sha256).digest()
    # Expand to L=32 → exactly one T(1) block.
    expected_t1 = _hmac.new(
        expected_prk, b"" + _CTX_EVENT + bytes([1]), hashlib.sha256
    ).digest()
    expected_k_event = expected_t1[:32]

    got = derive_event_signature_key(host_ikm)
    assert got == expected_k_event, (
        f"K_event derivation diverges from RFC 5869 chain: "
        f"got {got.hex()}, want {expected_k_event.hex()}"
    )
    assert len(got) == 32


def test_derive_event_signature_key_uses_event_context_label_verbatim():
    """If `_CTX_EVENT` is paraphrased (e.g. trailing newline, case change),
    the OKM changes — bytewise-identical info-label is load-bearing.

    Pins the on-the-wire info bytes against a frozen literal so a future
    refactor that 'cleans up' the label string is caught here.
    """
    assert _CTX_EVENT == b"nexi/audit/v0.3/event"
