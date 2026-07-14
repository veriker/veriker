"""Layer-3 atheris findings 2026-05-27 — structure-aware COSE_Sign1 fuzz.

The Layer-3 harness (tests/fuzz/atheris_verify_cose_layer3.py) decodes the
canonical envelope into its 4-slot CBOR structure, mutates sub-elements
while preserving outer-CBOR validity, re-encodes, and feeds the result to
verify_cross_host_authenticator_cose. It surfaces bypasses Layer 2 (raw
byte mutation, saturated 2026-05-26 at 83.4M iter / 0 new) cannot reach.

This file is the regression-test sibling of `test_cose_bundle_slot_safety.py`
(Layer-2 findings #1-#4) — same pattern, new findings.

----------------------------------------------------------------------------
Finding #1 (2026-05-27) — non-canonical outer-array encoding bypass [MED]

  Envelope: `9f <protected_bstr> <unprotected_map> <payload> <signature> ff`

  9f = indefinite-length array start (RFC 8949 §3.2.2); ff = break.
  Same logical 4-tuple as the canonical envelope; protected_bstr,
  unprotected, payload, signature are all byte-identical to the canonical
  ones. Sig_structure is rebuilt from the unchanged protected_bstr, so the
  Ed25519 signature verifies. Yet the envelope bytes differ (74 bytes vs
  73 canonical) — an attacker can mint arbitrarily many byte-different
  envelopes that all verify under the same (pubkey, preimage), breaking
  audit-trail uniqueness and any dedup keyed on the envelope SHA-256.

  Same message-malleability CLASS as Layer-2 finding #2 (trailing bytes),
  reached through a different parser-laxity channel (cbor2 transparently
  decodes indefinite-length arrays). RFC 9052 §3 forbids indefinite-length
  encodings on COSE messages.

  Fixed by `cbor2.dumps(cose, canonical=True) == bytes(cose_bytes)` after
  the 4-element shape check — same A4-style canonical-re-encode equality
  test the inner protected header uses (`is_canonical_cose_protected_header`).
  This generalizes: it also catches non-shortest-length array headers
  (e.g. `8404 ...` vs `84 ...`) and non-canonical inner unprotected-map /
  payload-bstr encodings. New reason code: `COSE_OUTER_NONCANONICAL`.

  Crash artifact replay: tests/fuzz/crashes/cose_bundle_layer3/
  crash-34b3abde72b1d421f9a663e361945a2a830b1eee — True before the fix,
  False after.
"""

from __future__ import annotations

import cbor2
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit_bundle.extensions.c19.cross_host_peerreview import (
    sign_cross_host_authenticator_cose,
    verify_cross_host_authenticator_cose,
)


# Deterministic keypair + preimage — match the Layer-3 atheris harness
# (tests/fuzz/atheris_verify_cose_layer3.py) so the crash artifact replays.
_PRIV_SEED = bytes.fromhex(
    "00010203" "04050607" "08090a0b" "0c0d0e0f"
    "10111213" "14151617" "18191a1b" "1c1d1e1f"
)
_PRIV = Ed25519PrivateKey.from_private_bytes(_PRIV_SEED)
_PUB_RAW = _PRIV.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
_PREIMAGE = b"v-kernel layer-2 cose fuzz canonical preimage"
_CANONICAL_COSE = sign_cross_host_authenticator_cose(
    private_key=_PRIV, preimage=_PREIMAGE
)
_CANONICAL_DECODED = cbor2.loads(_CANONICAL_COSE)
_PROTECTED_BSTR, _UNPROTECTED, _PAYLOAD, _SIG = _CANONICAL_DECODED


def _verify(envelope: bytes) -> tuple[bool, str, str]:
    return verify_cross_host_authenticator_cose(
        public_key_raw=_PUB_RAW,
        preimage=_PREIMAGE,
        cose_bytes=envelope,
        role="sender",
    )


# ---------------------------------------------------------------------------
# Finding #1 — non-canonical outer-array encoding (indefinite-length, non-
# shortest-length, etc.)
# ---------------------------------------------------------------------------


def _indefinite_length_outer(
    protected_bstr: bytes,
    unprotected,
    payload,
    signature: bytes,
) -> bytes:
    """Hand-build `9f <prot> <unprot> <payload> <sig> ff` — an indefinite-
    length CBOR array that decodes to the same 4-tuple as a canonical
    definite-length array.
    """
    return (
        b"\x9f"
        + cbor2.dumps(protected_bstr)
        + cbor2.dumps(unprotected)
        + cbor2.dumps(payload)
        + cbor2.dumps(signature)
        + b"\xff"
    )


def test_canonical_envelope_still_verifies() -> None:
    """Sanity: the canonical (definite-length) envelope verifies under the
    same fixture used to derive the bypass."""
    ok, reason, _ = _verify(_CANONICAL_COSE)
    assert ok is True
    assert reason == "PASS"


def test_indefinite_length_outer_array_rejected() -> None:
    """The Layer-3 finding #1 PoC. Same logical 4-tuple, indefinite-length
    outer encoding — was (True, 'PASS', '') before the fix; now must be
    rejected with the new canonical-encoding reason code."""
    envelope = _indefinite_length_outer(
        _PROTECTED_BSTR, _UNPROTECTED, _PAYLOAD, _SIG
    )
    # Sanity: the indefinite-length envelope is structurally distinct from
    # the canonical one yet decodes to the same Python value.
    assert envelope != _CANONICAL_COSE
    assert cbor2.loads(envelope) == cbor2.loads(_CANONICAL_COSE)
    ok, reason, _ = _verify(envelope)
    assert ok is False
    assert reason == "COSE_OUTER_NONCANONICAL"


def test_non_shortest_length_array_header_rejected() -> None:
    """Definite-length 4-element array CAN be encoded with a non-shortest
    length prefix (e.g. `98 04 ...` — 1-byte length tag for 4 — instead of
    the canonical `84 ...` — short-form 4). RFC 8949 §4.2 mandates the
    shortest encoding; the outer-canonical check catches this too."""
    # Canonical: 84 <prot> <unprot> <payload> <sig>
    # Non-canonical: 98 04 <prot> <unprot> <payload> <sig>
    envelope = (
        b"\x98\x04"
        + cbor2.dumps(_PROTECTED_BSTR)
        + cbor2.dumps(_UNPROTECTED)
        + cbor2.dumps(_PAYLOAD)
        + cbor2.dumps(_SIG)
    )
    assert envelope != _CANONICAL_COSE
    assert cbor2.loads(envelope) == cbor2.loads(_CANONICAL_COSE)
    ok, reason, _ = _verify(envelope)
    assert ok is False
    assert reason == "COSE_OUTER_NONCANONICAL"


def test_indefinite_length_inner_unprotected_map_rejected() -> None:
    """An indefinite-length unprotected map (`bf ff` instead of `a0`) — the
    canonical check operates on the encoded envelope BYTES, so non-canonical
    encodings of any inner element are caught."""
    # Definite-length empty map = a0; indefinite-length empty map = bf ff
    # Build the envelope by hand replacing slot-1 encoding.
    envelope = (
        b"\x84"  # 4-element array
        + cbor2.dumps(_PROTECTED_BSTR)  # slot 0
        + b"\xbf\xff"  # slot 1: indefinite-length empty map
        + cbor2.dumps(_PAYLOAD)  # slot 2: null = f6
        + cbor2.dumps(_SIG)  # slot 3
    )
    assert envelope != _CANONICAL_COSE
    assert cbor2.loads(envelope) == cbor2.loads(_CANONICAL_COSE)
    ok, reason, _ = _verify(envelope)
    assert ok is False
    assert reason == "COSE_OUTER_NONCANONICAL"


@pytest.mark.parametrize(
    "envelope_factory",
    [
        lambda: _indefinite_length_outer(_PROTECTED_BSTR, _UNPROTECTED, _PAYLOAD, _SIG),
        # 0x98 0x04 = non-shortest-length array header for length=4
        lambda: (
            b"\x98\x04"
            + cbor2.dumps(_PROTECTED_BSTR)
            + cbor2.dumps(_UNPROTECTED)
            + cbor2.dumps(_PAYLOAD)
            + cbor2.dumps(_SIG)
        ),
        # Indefinite-length empty unprotected map
        lambda: (
            b"\x84"
            + cbor2.dumps(_PROTECTED_BSTR)
            + b"\xbf\xff"
            + cbor2.dumps(_PAYLOAD)
            + cbor2.dumps(_SIG)
        ),
    ],
    ids=[
        "indefinite_length_outer_array",
        "non_shortest_length_array_header",
        "indefinite_length_unprotected_map",
    ],
)
def test_outer_noncanonical_variants_all_rejected(envelope_factory) -> None:
    """Parametric coverage of the outer-noncanonical bypass family. Each
    variant must (a) decode to the same Python 4-tuple as the canonical
    envelope (so the verifier's structural checks pass) and (b) be
    rejected by the canonical re-encode equality check."""
    envelope = envelope_factory()
    assert envelope != _CANONICAL_COSE
    assert cbor2.loads(envelope) == cbor2.loads(_CANONICAL_COSE)
    ok, reason, _ = _verify(envelope)
    assert ok is False
    assert reason == "COSE_OUTER_NONCANONICAL"


# ---------------------------------------------------------------------------
# Replay the saved Layer-3 crash artifact through the patched verifier.
# Mirrors `test_cose_bundle_slot_safety.py` -> _replay_crash_artifacts pattern.
# ---------------------------------------------------------------------------


_LAYER3_CRASH_HEX = (
    "9f43a10127a0f658406757f0b2ee7498555593b2f6105b0c78e7c8007119aca745bb"
    "67b55caae3ca1c7d4b4453250e48883176f69959cb5c021fc35c5bd70fb6748946ef"
    "c3ea56a50bff"
)


def test_layer3_finding1_crash_artifact_replay_clean() -> None:
    """The atheris-saved crash artifact must NOT cause the verifier to return
    (True, 'PASS') under the patched code. Locks in the regression so the
    Layer-3 finding cannot silently come back."""
    envelope = bytes.fromhex(_LAYER3_CRASH_HEX)
    ok, reason, _ = _verify(envelope)
    assert ok is False
    assert reason == "COSE_OUTER_NONCANONICAL"
