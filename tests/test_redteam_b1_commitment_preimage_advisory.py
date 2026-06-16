"""Red-team B-1 regression — low-entropy commitment-preimage advisory.

Exported unsalted sha256(content) commitments are a dictionary recovery oracle
when the committed content is a low-entropy sensitive field (phone/DOB/...). The
hash itself is load-bearing (verifier recomputes the Merkle root + binds it into
signatures), so the fix is a producer-side advisory + disclosure (OF-3), not
removal. This locks the advisory's behavior.
"""

from __future__ import annotations

from audit_bundle.extensions.c19.layer_a_counter import deterministic_cbor_encode
from audit_bundle.snapshots.cid import (
    LOW_ENTROPY_PREIMAGE_THRESHOLD_BYTES,
    commitment_preimage_advisory,
)


def test_bare_pii_field_trips_advisory():
    """The exact PoC PII record canonical-encodes to a short preimage → advised."""
    dob = deterministic_cbor_encode("1986-07-23")
    assert len(dob) < LOW_ENTROPY_PREIMAGE_THRESHOLD_BYTES
    adv = commitment_preimage_advisory(dob, context="snapshot DOB field")
    assert adv is not None
    assert "recovery oracle" in adv
    assert "snapshot DOB field" in adv


def test_long_high_entropy_preimage_not_advised():
    """A full multi-field record above the threshold → no advisory."""
    record = deterministic_cbor_encode(
        {
            "event_id": "ev-00000000-0000-4000-8000-000000000001",
            "host_id": "be-qtsp-qes-signer",
            "monotonic_counter": 7,
            "payload": {"decision": "APPROVE", "reason": "all checks passed"},
        }
    )
    assert len(record) >= LOW_ENTROPY_PREIMAGE_THRESHOLD_BYTES
    assert commitment_preimage_advisory(record) is None


def test_threshold_boundary():
    assert (
        commitment_preimage_advisory(b"x" * LOW_ENTROPY_PREIMAGE_THRESHOLD_BYTES)
        is None
    )
    assert (
        commitment_preimage_advisory(b"x" * (LOW_ENTROPY_PREIMAGE_THRESHOLD_BYTES - 1))
        is not None
    )
