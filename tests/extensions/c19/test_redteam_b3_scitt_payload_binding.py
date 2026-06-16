"""Red-team B-3 regression — SCITT notary statement bound to tree content.

B-3: a bundle whose SCITT receipt notarizes statement_X ("DENY") while the
leaf-bound payload_hash covers payload_Y ("APPROVE") verified GREEN, because
verify_scitt_receipt only proved the receipt internally consistent
(sha256(cose_payload_bytes) == statement_content_sha256) and never asserted
statement_content_sha256 == payload_hash. An attestation that says PASS while
the signed decision and the tree-bound decision disagree is the worst failure
class for this product.

The fix asserts statement_content_sha256 == payload_hash per event during the
verify pipeline (SCITT_STATEMENT_PAYLOAD_DECOUPLED on mismatch). This test
builds the decoupled bundle from the same primitives the substrate uses (no
mocks) and asserts the verifier now rejects it, plus a clean control that
verifies green.
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

from audit_bundle.extensions.c19 import layer_a_counter as LA
from audit_bundle.extensions.c19.layer_a_counter import (
    ReasonCode,
    canonical_event_preimage,
    compute_event_hash,
    compute_event_signature,
    derive_event_signature_key,
    deterministic_cbor_encode,
    seal_of1_manifest_anchor,
    verify_bundle_layer_a,
)

HOST = "host-A"
BUNDLE_ID = "bundle-b3-regression"
IKM = hashlib.sha256(b"host-A-ikm").digest()
TS_KID = b"ts-key-1"

_cose_key = OKPKey.generate_key(crv=Ed25519, optional_params={KpKid: TS_KID})


def _scitt_receipt(payload_bytes: bytes) -> bytes:
    msg = Sign1Message(
        phdr={Algorithm: EdDSA, KID: TS_KID}, uhdr={}, payload=payload_bytes
    )
    msg.key = _cose_key
    return msg.encode()


def _build_event(
    *, monotonic_counter, prev_event_hash, leaf_payload, notarized_payload
):
    """Build one event whose SCITT receipt notarizes `notarized_payload` while
    the leaf/signature bind `leaf_payload`. When the two payloads differ the
    bundle is the B-3 attack; when identical it is the clean control."""
    leaf_bytes = deterministic_cbor_encode(leaf_payload)
    leaf_payload_hash = hashlib.sha256(leaf_bytes).digest()

    notarized_bytes = deterministic_cbor_encode(notarized_payload)
    notarized_hash = hashlib.sha256(notarized_bytes).digest()
    receipt = _scitt_receipt(notarized_bytes)

    event_id = f"ev-{monotonic_counter}"
    k_event = derive_event_signature_key(IKM)
    preimage = canonical_event_preimage(
        host_id=HOST,
        event_id=event_id,
        prev_event_hash=prev_event_hash,
        bundle_id=BUNDLE_ID,
        monotonic_counter=monotonic_counter,
        payload_hash=leaf_payload_hash,
    )
    sig = compute_event_signature(k_event, preimage)
    ev = {
        "event_id": event_id,
        "prev_event_id": None,
        "prev_event_hash": prev_event_hash.hex(),
        "host_id": HOST,
        "event_kind": "dispatch_record",
        "monotonic_counter": monotonic_counter,
        "counter_log_index": monotonic_counter,
        # notarized statement content — what the receipt actually signs
        "scitt_statement_id": notarized_hash.hex(),
        "scitt_statement_content_sha256": notarized_hash.hex(),
        "scitt_inclusion_proof": receipt.hex(),
        # leaf-bound payload — what enters the Merkle tree + event signature
        "payload_hash": leaf_payload_hash.hex(),
        "event_signature": {"key_id": "k_event_A", "sig": sig.hex()},
        "causal_dependencies": [],
    }
    normalized = {
        "event_id": event_id,
        "prev_event_id": None,
        "prev_event_hash": prev_event_hash,
        "monotonic_counter": monotonic_counter,
        "counter_log_index": monotonic_counter,
        "event_kind": "dispatch_record",
        "payload_hash": leaf_payload_hash,
    }
    event_hash = compute_event_hash(deterministic_cbor_encode(normalized))
    return ev, event_hash


def _build_layer_a(*, leaf_payload, notarized_payload):
    ev1, h1 = _build_event(
        monotonic_counter=1,
        prev_event_hash=b"\x00" * 32,
        leaf_payload=leaf_payload,
        notarized_payload=notarized_payload,
    )
    sealed = seal_of1_manifest_anchor(
        event_hashes=[h1],
        bundle_id=BUNDLE_ID,
        created_at="2026-05-22T00:00:00Z",
        dispatch_records=[],
    )
    return {
        "bundle_id": BUNDLE_ID,
        "protocol_version": "v0.3",
        "scitt_log_id": "log-1",
        "assurance_profile": "production-standard",
        "chain_height": 1,
        "events": [ev1],
        "event_dag_merkle_root": sealed["event_dag_merkle_root"],
        "manifest_header_merkle_leaf": sealed["manifest_header_merkle_leaf"],
    }


def _verify(la):
    return verify_bundle_layer_a(
        bundle_bytes=deterministic_cbor_encode(la),
        layer_a=la,
        pinned_ts_key_ids=frozenset({TS_KID}),
        pinned_ts_verifying_keys={TS_KID: _cose_key},
        pinned_issuer_keys={HOST: IKM},
    )


_APPROVE = {"recipient": "alice@hospital.example", "policy_decision": "APPROVE"}
_DENY = {"recipient": "alice@hospital.example", "policy_decision": "DENY"}


def test_clean_bundle_statement_equals_payload_verifies():
    """Control: receipt notarizes the same payload that's leaf-bound → green."""
    la = _build_layer_a(leaf_payload=_APPROVE, notarized_payload=_APPROVE)
    root = _verify(la)
    assert isinstance(root, bytes) and len(root) == 32


def test_notary_deny_tree_approve_is_rejected():
    """B-3 core: receipt notarizes DENY while the tree binds APPROVE → reject."""
    la = _build_layer_a(leaf_payload=_APPROVE, notarized_payload=_DENY)
    with pytest.raises(LA.LayerAVerificationError) as exc:
        _verify(la)
    assert exc.value.code == ReasonCode.SCITT_STATEMENT_PAYLOAD_DECOUPLED


def test_statement_envelope_convention_commits_to_payload_hash():
    """Convention (2): the receipt notarizes a statement ENVELOPE that carries
    the event's payload_hash as a field (not the raw payload). The B-3 binding
    must accept this — it commits to the leaf-bound payload_hash — and reject an
    envelope that carries the wrong payload_hash."""
    from audit_bundle.extensions.c19.layer_a_counter import (
        _scitt_statement_commits_to_payload,
    )

    ph = hashlib.sha256(b"the-real-payload").digest()
    good = deterministic_cbor_encode(
        {"event_id": "ev-1", "payload_hash": ph, "host_id": "host-A"}
    )
    bad = deterministic_cbor_encode(
        {"event_id": "ev-1", "payload_hash": b"\x00" * 32, "host_id": "host-A"}
    )
    assert _scitt_statement_commits_to_payload(
        statement_sha=hashlib.sha256(good).digest(),
        cose_payload_bytes=good,
        payload_hash=ph,
    )
    assert not _scitt_statement_commits_to_payload(
        statement_sha=hashlib.sha256(bad).digest(),
        cose_payload_bytes=bad,
        payload_hash=ph,
    )
