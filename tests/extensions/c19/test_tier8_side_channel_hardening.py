"""Tier 8 side-channel hardening regression — digest-equality discipline.

The Tier 8 audit (the internal design notes) found one
Category-(b) finding: verify_scitt_receipt compared the recomputed payload
digest against the receipt-asserted statement_content_sha256 with raw `!=`.
Even though SHA-256 preimage resistance makes a timing leak unexploitable
here, raw `!=` is the wrong primitive for digest equality. The fix swaps to
hmac.compare_digest, which is what the rest of the c19 substrate uses for
authenticator / digest comparison (cf. layer_a_counter._hmac.compare_digest
usage in verify_event_signature and verify_rotation_co_signatures, and
cross_host_peerreview._stdlib_hmac.compare_digest in
verify_cross_host_authenticator).

This test pins the behavioral contract — verify_scitt_receipt raises
SCITT_RECEIPT_PAYLOAD_MISMATCH on digest mismatch, returns None on match —
so a future regression away from compare_digest cannot silently re-introduce
the discipline gap.
"""

from __future__ import annotations

import hashlib

import pytest
from pycose.algorithms import EdDSA
from pycose.headers import KID, Algorithm
from pycose.keys import OKPKey
from pycose.keys.curves import Ed25519
from pycose.keys.keyparam import KpKid
from pycose.messages import Sign1Message

from audit_bundle.extensions.c19.layer_a_counter import (
    LayerAVerificationError,
    ReasonCode,
    ScittReceipt,
    verify_scitt_receipt,
)

TS_KID = b"ts-key-tier8"
_cose_key = OKPKey.generate_key(crv=Ed25519, optional_params={KpKid: TS_KID})


def _mint_receipt(payload_bytes: bytes) -> bytes:
    msg = Sign1Message(
        phdr={Algorithm: EdDSA, KID: TS_KID}, uhdr={}, payload=payload_bytes
    )
    msg.key = _cose_key
    return msg.encode()


def _mint(payload_bytes: bytes, claimed_sha256: bytes) -> ScittReceipt:
    """Build a ScittReceipt whose claimed statement_content_sha256 may or may
    not equal sha256(payload_bytes). The verifier's payload-binding check is
    what tells the two apart."""
    return ScittReceipt(
        statement_id=claimed_sha256,
        statement_content_sha256=claimed_sha256,
        cose_payload_bytes=payload_bytes,
        receipt_bytes=_mint_receipt(payload_bytes),
        ts_key_id=TS_KID,
    )


def test_matched_digest_verifies_clean():
    payload = b"tier8-side-channel-payload-matched"
    digest = hashlib.sha256(payload).digest()
    receipt = _mint(payload, claimed_sha256=digest)
    verify_scitt_receipt(
        receipt=receipt,
        pinned_ts_key_ids=frozenset({TS_KID}),
        pinned_ts_verifying_keys={TS_KID: _cose_key},
    )


def test_mismatched_digest_raises_payload_mismatch():
    payload = b"tier8-side-channel-payload-mismatch"
    real_digest = hashlib.sha256(payload).digest()
    forged_digest = bytes([real_digest[0] ^ 0x01]) + real_digest[1:]
    receipt = _mint(payload, claimed_sha256=forged_digest)
    with pytest.raises(LayerAVerificationError) as ei:
        verify_scitt_receipt(
            receipt=receipt,
            pinned_ts_key_ids=frozenset({TS_KID}),
            pinned_ts_verifying_keys={TS_KID: _cose_key},
        )
    assert ei.value.code == ReasonCode.SCITT_RECEIPT_PAYLOAD_MISMATCH


def test_full_bitflip_sweep_each_byte_rejected():
    """Sweep one-bit flips across all 32 digest bytes — each must be rejected
    with PAYLOAD_MISMATCH. Pins that compare_digest's byte-by-byte equality
    semantics remain behaviorally identical to raw `!=` (every flipped digest
    rejected, no early-exit short-circuit changes the verdict)."""
    payload = b"tier8-bitflip-sweep"
    real_digest = hashlib.sha256(payload).digest()
    for byte_idx in range(32):
        forged = bytearray(real_digest)
        forged[byte_idx] ^= 0x80
        receipt = _mint(payload, claimed_sha256=bytes(forged))
        with pytest.raises(LayerAVerificationError) as ei:
            verify_scitt_receipt(
                receipt=receipt,
                pinned_ts_key_ids=frozenset({TS_KID}),
                pinned_ts_verifying_keys={TS_KID: _cose_key},
            )
        assert ei.value.code == ReasonCode.SCITT_RECEIPT_PAYLOAD_MISMATCH, (
            f"byte {byte_idx} flip did not produce PAYLOAD_MISMATCH"
        )
