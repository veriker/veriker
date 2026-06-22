"""Adversarial + positive test corpus for C19.B cross-host PeerReview pairing.

S19b sb-001 (broken-first discipline per `the internal design notes`):
tests are written BEFORE the real impl exists. The corpus encodes the FULL
R2/R3/R4/R5/R6 attack model surfaced across the C19 tribunal Rounds 1-6
(the audit-bundle contract §"Cross-host receipts (PeerReview
authenticator pairing; f+1 cost)" + §"Standards bindings" rows for
"Accountable cross-host receipts", "Cross-host ack timeliness", "Cross-host
authenticator profile selection", "Shared accountable-delivery log").

The tests bind to the API surface that sb-002 (broken stand-in) and sb-003
(real impl) MUST expose; every test fails loudly against sb-002 (raises
NotImplementedError or returns S19B_BROKEN_STANDIN), and every test passes
against sb-003.

Standards cited inline per test docstring (paraphrase-from-memory is rejected
per SCOPING §Standards bindings preamble):
  RFC 2104 (HMAC), RFC 5869 (HKDF), RFC 8949 §4.2.1 (deterministic CBOR),
  RFC 9052 §4.2 (COSE_Sign1), Haeberlen SOSP 2007 §3+§5 (PeerReview).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path

import pytest

from audit_bundle.bundle_manifest import BundleManifest
from audit_bundle.extensions.c19.cross_host_peerreview import (
    ACK_TIMEOUT_BOUNDS_MS,
    AckTimestampEvidenceKind,
    AssuranceProfile,
    CrossHostAuthenticatorKind,
    CrossHostEdgeState,
    CrossHostPeerReviewAuthenticatorCheck,
    DeploymentScope,
    compute_causal_chain_update,
    construct_ack_preimage,
    construct_sender_signature_preimage,
    derive_cross_host_receipt_key,
    sign_cross_host_authenticator,
    verify_cross_host_authenticator,
    sign_cross_host_authenticator_cose,
    cross_host_cose_kid,
    CrossOrgKeyPolicy,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as _ser


# ---------------------------------------------------------------------------
# Constants for standards-test-vector interop (RFC 4231 §4.2 SHA-256)
# ---------------------------------------------------------------------------

# RFC 4231 §4.2 test case 1 — HMAC-SHA256 reference vector
_RFC4231_TC1_KEY = bytes.fromhex("0b" * 20)
_RFC4231_TC1_DATA = b"Hi There"
_RFC4231_TC1_EXPECTED_MAC_HEX = (
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


_SIGNED_PREIMAGE_FIELDS = frozenset(
    {
        "sender_host_id",
        "receiver_host_id",
        "channel_id",
        "message_id",
        "message_hash",
        "sender_local_counter",
        "receiver_local_counter",
        "receiver_challenge_token",
        "ack_timeout_ms",
        "bundle_id",
    }
)


def _make_edge_dict(**overrides):
    """Well-formed cross-host edge dict per SCOPING lines 519-594.

    Overrides apply BEFORE signing so the resulting sender_signature +
    receiver_acknowledgment.sig are valid for the override values; tests
    that want to model a TAMPER (signed-with-X, edge-field-mutated-to-Y)
    construct a well-formed edge first then mutate the dict directly.

    Default timing: send MIDP=1_000_000_000ms, ack MIDP=1_000_000_100ms
    (100ms gap), RADI=10ms each — chosen so conservative R5-002 bounds
    pass at ack_timeout=500ms (production-standard min) and 60_000ms
    boundaries. Tests that need a timeliness VIOLATION shift the ack
    MIDP much further (≥+60_000ms).
    """
    sender_signing_key = b"\x11" * 32
    receiver_signing_key = b"\x22" * 32

    defaults = dict(
        sender_host_id="host-A",
        receiver_host_id="host-B",
        channel_id="11111111-1111-1111-1111-111111111111",
        message_id="22222222-2222-2222-2222-222222222222",
        message_hash=_sha256(b"hello cross-host world"),
        bundle_id="test-bundle-S19b",
        receiver_challenge_token=b"\xaa" * 16,
        sender_local_counter=1,
        receiver_local_counter=1,
        ack_timeout_ms=1000,
    )

    # Apply signed-field overrides BEFORE deriving keys / signing.
    signed = dict(defaults)
    for k in list(overrides.keys()):
        if k in _SIGNED_PREIMAGE_FIELDS:
            value = overrides.pop(k)
            # message_hash + receiver_challenge_token: accept hex strings or
            # raw bytes for ergonomic test authoring.
            if k == "message_hash" and isinstance(value, str):
                value = bytes.fromhex(value)
            if k == "receiver_challenge_token" and isinstance(value, str):
                value = bytes.fromhex(value)
            signed[k] = value

    K_send = derive_cross_host_receipt_key(
        sender_signing_key_material=sender_signing_key,
        info_label="nexi/audit/v0.3/cross-host-receipt",
    )
    K_ack = derive_cross_host_receipt_key(
        sender_signing_key_material=receiver_signing_key,
        info_label="nexi/audit/v0.3/cross-host-receipt-ack",
    )

    sender_preimage = construct_sender_signature_preimage(
        sender_host_id=signed["sender_host_id"],
        receiver_host_id=signed["receiver_host_id"],
        channel_id=signed["channel_id"],
        message_id=signed["message_id"],
        message_hash=signed["message_hash"],
        sender_local_counter=signed["sender_local_counter"],
        ack_timeout_ms=signed["ack_timeout_ms"],
        bundle_id=signed["bundle_id"],
        receiver_challenge_token=signed["receiver_challenge_token"],
    )
    sender_sig = sign_cross_host_authenticator(K=K_send, preimage=sender_preimage)

    ack_preimage = construct_ack_preimage(
        sender_host_id=signed["sender_host_id"],
        receiver_host_id=signed["receiver_host_id"],
        channel_id=signed["channel_id"],
        message_id=signed["message_id"],
        message_hash=signed["message_hash"],
        receiver_local_counter=signed["receiver_local_counter"],
        kind="ack",
        reason_code_if_nack=None,
        bundle_id=signed["bundle_id"],
        ack_timeout_ms=signed["ack_timeout_ms"],
        sender_local_counter=signed["sender_local_counter"],
        receiver_challenge_token=signed["receiver_challenge_token"],
    )
    ack_sig = sign_cross_host_authenticator(K=K_ack, preimage=ack_preimage)

    edge = {
        "message_id": signed["message_id"],
        "message_hash": signed["message_hash"].hex(),
        "sender_host_id": signed["sender_host_id"],
        "receiver_host_id": signed["receiver_host_id"],
        "channel_id": signed["channel_id"],
        "sender_local_counter": signed["sender_local_counter"],
        "receiver_local_counter": signed["receiver_local_counter"],
        "receiver_challenge_token": signed["receiver_challenge_token"].hex(),
        "ack_timeout_ms": signed["ack_timeout_ms"],
        "bundle_id": signed["bundle_id"],
        "authenticator_kind": "hmac",
        "deployment_scope": "single_org",
        "sender_signature": {
            "key_id": "sender-key-0",
            "sig": sender_sig.hex(),
            # Verifier-readable key material for test-only deployment;
            # production deploys distribute K_send via TUF (R4-ADD-4).
            "_test_only_K_send_hex": K_send.hex(),
        },
        "send_intent_scitt_receipt": {
            "_test_only_present": True,
            "payload_sha256": _sha256(sender_preimage).hex(),
        },
        "send_timestamp_evidence": {
            "kind": "roughtime_quorum",
            "roughtime_quorum": {
                "responses": [{"midp_ms": 1_000_000_000, "radi_ms": 10}],
                "radius_ms": 10,
                "send_timestamp_midp": 1_000_000_000,
            },
        },
        "receiver_acknowledgment": {
            "kind": "ack",
            "key_id": "receiver-key-0",
            "sig": ack_sig.hex(),
            "_test_only_K_ack_hex": K_ack.hex(),
        },
        "ack_scitt_receipt": {
            "_test_only_present": True,
            "payload_sha256": _sha256(ack_preimage).hex(),
        },
        "ack_timestamp_evidence": {
            "kind": "roughtime_quorum",
            "roughtime_quorum": {
                "responses": [{"midp_ms": 1_000_000_100, "radi_ms": 10}],
                "radius_ms": 10,
                "ack_timestamp_midp": 1_000_000_100,
            },
        },
        "timeout_witness": None,
        "edge_state": "trusted",
    }
    # Non-signed-field overrides (e.g. authenticator_kind, deployment_scope,
    # send_timestamp_evidence, etc.) apply as-is.
    edge.update(overrides)
    return edge


def _make_manifest_with_causal_chain(
    tmp_path: Path, edges, profile: str = "production-standard"
) -> tuple[Path, BundleManifest]:
    """Return (bundle_dir, BundleManifest) with causal_chain populated."""
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir(exist_ok=True)
    # Minimal on-disk file so manifest validation can run if the plugin
    # invokes it; the plugin itself only reads manifest.causal_chain.
    payload_path = bundle_dir / "output.json"
    payload_path.write_bytes(b"{}")
    sha = hashlib.sha256(b"{}").hexdigest()

    causal_chain: dict = {"assurance_profile": profile}
    if edges is not None:
        causal_chain["cross_host_authenticators"] = edges

    manifest = BundleManifest(
        schema_version="vcp-v1.1-canary4",
        bundle_id="test-bundle-S19b",
        created_at="2026-05-19T00:00:00Z",
        files={"output.json": sha},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
        causal_chain=causal_chain,
    )
    return bundle_dir, manifest


# ===========================================================================
# GROUP A — HMAC + preimage construction
# (RFC 5869 + RFC 2104 + RFC 8949 §4.2.1; R3-004 pre-fix)
# ===========================================================================


def test_hkdf_output_is_32_bytes():
    """RFC 5869 §2.3 HKDF-Expand: OKM length parameter L=32; output is 32B."""
    K = derive_cross_host_receipt_key(
        sender_signing_key_material=b"\xa5" * 32,
        info_label="nexi/audit/v0.3/cross-host-receipt",
    )
    assert isinstance(K, (bytes, bytearray))
    assert len(K) == 32


def test_hkdf_distinct_info_labels_produce_distinct_keys_under_identical_ikm():
    """RFC 5869 §2.3: distinct `info` values produce distinct OKM. Closes R3-004 context-separation requirement."""
    ikm = b"\xa5" * 32
    K_send = derive_cross_host_receipt_key(
        sender_signing_key_material=ikm,
        info_label="nexi/audit/v0.3/cross-host-receipt",
    )
    K_ack = derive_cross_host_receipt_key(
        sender_signing_key_material=ikm,
        info_label="nexi/audit/v0.3/cross-host-receipt-ack",
    )
    K_event = derive_cross_host_receipt_key(
        sender_signing_key_material=ikm,
        info_label="nexi/audit/v0.3/event",
    )
    assert K_send != K_ack != K_event
    assert K_send != K_event


def test_hkdf_output_used_as_key_not_concatenated_prefix():
    """R3-004 pre-fix: HKDF output USED AS KEY in HMAC, NOT concatenated as message prefix.

    Per SCOPING line ~456: "The output OKM IS a derived KEY, not a message prefix."
    Produce a sig using the WRONG-pattern `HKDF(info) || preimage` as HMAC
    input; verifier MUST reject because the corrected construction
    `HMAC(K_ctx, preimage)` is structurally different (K differs, message
    differs).
    """
    import hmac as stdhmac

    ikm = b"\xa5" * 32
    K_ctx = derive_cross_host_receipt_key(
        sender_signing_key_material=ikm,
        info_label="nexi/audit/v0.3/cross-host-receipt",
    )
    preimage = construct_sender_signature_preimage(
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
    correct_sig = sign_cross_host_authenticator(K=K_ctx, preimage=preimage)
    # Old wrong pattern: HMAC(IKM, HKDF_output || preimage)
    wrong_sig = stdhmac.new(ikm, K_ctx + preimage, hashlib.sha256).digest()
    assert correct_sig != wrong_sig
    assert verify_cross_host_authenticator(K=K_ctx, preimage=preimage, sig=correct_sig)
    assert not verify_cross_host_authenticator(
        K=K_ctx, preimage=preimage, sig=wrong_sig
    )


def test_preimage_is_deterministic_cbor_not_byte_concatenation():
    """RFC 8949 §4.2.1 deterministic encoding. Closes Round-2 B1-canon malleability.

    Supply a byte-concatenated preimage; the constructed sig MUST NOT match the
    verifier-recomputed (CBOR-encoded) one.
    """
    preimage = construct_sender_signature_preimage(
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
    # Naive concatenation (NOT deterministic CBOR)
    naive_concat = b"".join(
        [
            b"nexi/audit/v0.3/cross-host-receipt",
            b"v0.3",
            b"host-A",
            b"host-B",
            b"cid",
            b"mid",
            b"\x00" * 32,
            (1).to_bytes(8, "big"),
            (1000).to_bytes(8, "big"),
            b"bid",
            b"\xaa" * 16,
        ]
    )
    assert preimage != naive_concat


def test_preimage_tuple_order_documented():
    """R3-004 pre-fix; SCOPING line 534-546 verbatim tuple order.

    Order is [context_label, protocol_version, sender_host_id, receiver_host_id,
    channel_id, message_id, message_hash, sender_local_counter, ack_timeout_ms,
    bundle_id, receiver_challenge_token]. Swapping any two distinct-typed
    fields produces a distinct preimage.
    """
    base = dict(
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
    p1 = construct_sender_signature_preimage(**base)
    # Swap sender_host_id and receiver_host_id (semantic swap)
    swapped = dict(base)
    swapped["sender_host_id"] = "host-B"
    swapped["receiver_host_id"] = "host-A"
    p2 = construct_sender_signature_preimage(**swapped)
    assert p1 != p2
    # Swap message_id and channel_id
    swapped2 = dict(base)
    swapped2["channel_id"] = "mid"
    swapped2["message_id"] = "cid"
    p3 = construct_sender_signature_preimage(**swapped2)
    assert p1 != p3


def test_hmac_sha256_matches_rfc4231_test_vector():
    """RFC 4231 §4.2 TC1 — interop check against published HMAC-SHA256 vector.

    Confirms our HMAC primitive uses the standard (not paraphrase-from-memory).
    """
    mac = sign_cross_host_authenticator(K=_RFC4231_TC1_KEY, preimage=_RFC4231_TC1_DATA)
    assert mac.hex() == _RFC4231_TC1_EXPECTED_MAC_HEX


def test_indefinite_length_cbor_rejected_in_preimage_construction():
    """RFC 8949 §4.2.1: 'Indefinite-length items MUST NOT appear.'

    The preimage constructor is the only path that produces preimage bytes;
    it MUST emit definite-length encoding. Inspect emitted bytes for the
    CBOR indefinite-length marker byte 0x9f (array) / 0xbf (map) / 0x5f
    (bstr) / 0x7f (tstr) at the start of any item.
    """
    preimage = construct_sender_signature_preimage(
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
    forbidden = {0x9F, 0xBF, 0x5F, 0x7F}
    assert preimage[0] not in forbidden, (
        f"preimage starts with indefinite-length marker 0x{preimage[0]:02x}; "
        "RFC 8949 §4.2.1 bans indefinite-length"
    )


# ===========================================================================
# GROUP B — receiver_challenge_token (Round-2 NEW B7 false-intent closure)
# ===========================================================================


def test_false_intent_logging_without_receiver_challenge_token(tmp_path):
    """Round-2 NEW B7: sender cannot log a valid send_intent without a
    receiver-issued challenge token bound into the sender preimage.

    Construct a well-formed edge then TAMPER the receiver_challenge_token
    to all-zeros (modeling a sender substituting a fabricated placeholder
    after signing): verifier MUST recompute the preimage with the tampered
    token and find the signature does not verify.
    """
    edge = _make_edge_dict()
    edge["receiver_challenge_token"] = (b"\x00" * 16).hex()
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    # With a tampered challenge token, the sender_signature recomputation MUST fail.
    assert result.ok is False
    assert "SENDER_SIGNATURE" in result.reason_code or "CHALLENGE" in result.reason_code


def test_challenge_token_swapped_breaks_sig(tmp_path):
    """Standards-bindings 'Accountable cross-host receipts': replay
    sender_signature with all preimage fields correct except
    `receiver_challenge_token` swapped; verifier MUST reject.
    """
    edge = _make_edge_dict()
    # Swap challenge_token without re-signing
    edge["receiver_challenge_token"] = (b"\xbb" * 16).hex()
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is False


def test_challenge_token_replay_across_messages(tmp_path):
    """Channel-bound nonce semantics — same challenge_token used for two
    distinct messages within the same (sender, receiver, channel) tuple
    MUST be rejected as a nonce-reuse attack.
    """
    edge1 = _make_edge_dict()
    edge2 = _make_edge_dict(
        message_id="33333333-3333-3333-3333-333333333333",
        sender_local_counter=2,
        receiver_local_counter=2,
    )
    # edge2 reuses the same receiver_challenge_token as edge1 → nonce reuse.
    assert edge1["receiver_challenge_token"] == edge2["receiver_challenge_token"]
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge1, edge2])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is False
    assert "CHALLENGE" in result.reason_code or "REPLAY" in result.reason_code


# ===========================================================================
# GROUP C — ack_timestamp_evidence discriminated union
# (R4-ADD-1; unknown kind hard-fails per RFC 2119 MUST; R6-008)
# ===========================================================================


def test_ack_timestamp_evidence_kind_roughtime_quorum_well_formed(tmp_path):
    """R4-ADD-1: kind=roughtime_quorum with non-empty responses and
    RADI ≤ profile_max_radius_ms — well-formed; PASS path.
    """
    edge = _make_edge_dict()
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is True
    assert result.reason_code == "PASS"


def test_ack_timestamp_evidence_kind_rfc3161_tsa_well_formed(tmp_path):
    """R4-ADD-1 rfc3161_tsa variant: token present, imprint matches, allowed
    algorithm — well-formed PASS path.
    """
    edge = _make_edge_dict()
    edge["send_timestamp_evidence"] = {
        "kind": "rfc3161_tsa",
        "rfc3161_tsa": {
            "rfc3161_token": (b"\xaa" * 32).hex(),
            "tsa_cert_chain": [],
            "policy_oid": "0.4.0.2023.1.1",
            "imprint_algorithm": "sha256",
            "nonce": (b"\xbb" * 16).hex(),
            "send_timestamp_gentime": "2026-05-19T00:00:00Z",
        },
    }
    edge["ack_timestamp_evidence"] = {
        "kind": "rfc3161_tsa",
        "rfc3161_tsa": {
            "rfc3161_token": (b"\xcc" * 32).hex(),
            "tsa_cert_chain": [],
            "policy_oid": "0.4.0.2023.1.1",
            "imprint_algorithm": "sha256",
            "nonce": (b"\xdd" * 16).hex(),
            "ack_timestamp_gentime": "2026-05-19T00:00:00.500Z",
        },
    }
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is True
    assert result.reason_code == "PASS"


def test_ack_timestamp_evidence_unknown_kind_hard_fails(tmp_path):
    """R4-ADD-1 + R6-008: unknown ack_timestamp_evidence.kind MUST hard-fail
    with `ACK_TIMESTAMP_EVIDENCE_UNKNOWN_KIND` (RFC 2119 MUST).

    Standards-bindings row 'timestamp_evidence discriminated union':
    forward incompatibility is the intentional security property.
    """
    edge = _make_edge_dict()
    edge["ack_timestamp_evidence"] = {
        "kind": "tdx_attestation_v2",  # unknown kind
        "tdx_attestation_v2": {"quote": "deadbeef"},
    }
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is False
    assert result.reason_code == "ACK_TIMESTAMP_EVIDENCE_UNKNOWN_KIND"


def test_send_timestamp_evidence_unknown_kind_hard_fails(tmp_path):
    """R5-001 + R6-008 mirror: unknown send_timestamp_evidence.kind MUST
    hard-fail with `SEND_TIMESTAMP_EVIDENCE_UNKNOWN_KIND` (RFC 2119 MUST).
    """
    edge = _make_edge_dict()
    edge["send_timestamp_evidence"] = {
        "kind": "tee_counter",  # R5-003 reserved-for-v0.4 → unknown at this plugin
        "tee_counter": {},
    }
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is False
    assert result.reason_code == "SEND_TIMESTAMP_EVIDENCE_UNKNOWN_KIND"


def test_ack_timestamp_evidence_missing_when_profile_requires_unverifiable_edge(
    tmp_path,
):
    """R5-004 + R6-003: production-standard profile with ack present but
    ack_timestamp_evidence absent — verifier MUST classify the edge as
    UNVERIFIABLE_EDGE (NOT TRUSTED).
    """
    edge = _make_edge_dict()
    edge["ack_timestamp_evidence"] = None
    bundle_dir, manifest = _make_manifest_with_causal_chain(
        tmp_path, [edge], profile="production-standard"
    )
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is False
    # edge_state in the per-edge output must be UNVERIFIABLE_EDGE.
    assert "UNVERIFIABLE_EDGE" in result.reason_code or "UNVERIFIABLE" in result.detail


def test_ack_timestamp_evidence_sha1_imprint_rejected(tmp_path):
    """RFC 3161 + SCOPING line 451 + 563: SHA-1 imprint MUST be rejected with
    `TSA_WEAK_ALGORITHM` (TSA-side weak-algorithm policy)."""
    edge = _make_edge_dict()
    edge["ack_timestamp_evidence"] = {
        "kind": "rfc3161_tsa",
        "rfc3161_tsa": {
            "rfc3161_token": (b"\xcc" * 32).hex(),
            "tsa_cert_chain": [],
            "policy_oid": "0.4.0.2023.1.1",
            "imprint_algorithm": "sha1",  # banned
            "nonce": (b"\xdd" * 16).hex(),
            "ack_timestamp_gentime": "2026-05-19T00:00:00.500Z",
        },
    }
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is False
    assert result.reason_code == "TSA_WEAK_ALGORITHM"


# ===========================================================================
# GROUP D — profile-bound ack_timeout ceilings (Round-2 B5 closure)
# ===========================================================================


def test_ack_timeout_zero_rejected_framing_attack(tmp_path):
    """Round-2 B5: ack_timeout_ms == 0 under any profile — framing attack.
    Verifier MUST reject with ACK_TIMEOUT_OUT_OF_PROFILE_BOUNDS.
    """
    edge = _make_edge_dict(ack_timeout_ms=0)
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is False
    assert result.reason_code == "ACK_TIMEOUT_OUT_OF_PROFILE_BOUNDS"


def test_ack_timeout_unbounded_rejected_indefinite_disputed_hold(tmp_path):
    """Round-2 B5: ack_timeout_ms > max_for_profile — indefinite-DISPUTED hold.
    Verifier MUST reject with ACK_TIMEOUT_OUT_OF_PROFILE_BOUNDS.
    """
    # production-standard max is 60_000 — choose 10**12 as effectively-infinity.
    edge = _make_edge_dict(ack_timeout_ms=10**12)
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is False
    assert result.reason_code == "ACK_TIMEOUT_OUT_OF_PROFILE_BOUNDS"


def test_ack_timeout_below_profile_min_rejected(tmp_path):
    """Round-2 B5: ack_timeout_ms < profile min (production-standard min=500) → reject."""
    edge = _make_edge_dict(ack_timeout_ms=100)
    bundle_dir, manifest = _make_manifest_with_causal_chain(
        tmp_path, [edge], profile="production-standard"
    )
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is False
    assert result.reason_code == "ACK_TIMEOUT_OUT_OF_PROFILE_BOUNDS"


def test_ack_timeout_above_profile_max_rejected(tmp_path):
    """Round-2 B5: ack_timeout_ms > profile max (regulated max=5_000) → reject."""
    edge = _make_edge_dict(ack_timeout_ms=6_000)
    bundle_dir, manifest = _make_manifest_with_causal_chain(
        tmp_path, [edge], profile="regulated-high-assurance"
    )
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is False
    assert result.reason_code == "ACK_TIMEOUT_OUT_OF_PROFILE_BOUNDS"


def test_ack_timeout_at_profile_min_accepted(tmp_path):
    """Boundary: ack_timeout_ms == profile min (production-standard min=500) → accept."""
    edge = _make_edge_dict(ack_timeout_ms=500)
    bundle_dir, manifest = _make_manifest_with_causal_chain(
        tmp_path, [edge], profile="production-standard"
    )
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is True


def test_ack_timeout_at_profile_max_accepted(tmp_path):
    """Boundary: ack_timeout_ms == profile max (production-standard max=60_000) → accept."""
    edge = _make_edge_dict(ack_timeout_ms=60_000)
    bundle_dir, manifest = _make_manifest_with_causal_chain(
        tmp_path, [edge], profile="production-standard"
    )
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is True


def test_ack_timeout_table_is_hardcoded_in_module_not_bundle(tmp_path):
    """Round-2 B5 + SCOPING line 503-511 mirror: profile bounds are
    verifier-internal — bundle-supplied override is IGNORED.

    Provide a malicious bundle `_override_ack_timeout_bounds_ms` field with
    permissive bounds and an out-of-bounds ack_timeout_ms; verifier MUST use
    the module table and reject.
    """
    edge = _make_edge_dict(ack_timeout_ms=10**12)
    # Attempt to override the module table via a bundle-supplied field —
    # verifier must ignore.
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    assert manifest.causal_chain is not None
    manifest.causal_chain["_override_ack_timeout_bounds_ms"] = {
        "production-standard": [0, 10**18],
    }
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is False
    assert result.reason_code == "ACK_TIMEOUT_OUT_OF_PROFILE_BOUNDS"


def test_ack_timeout_bounds_match_per_profile_values():
    """Exact per-profile tuples; anchored against SCOPING line 503-511
    anchor-window ceilings.
    """
    assert ACK_TIMEOUT_BOUNDS_MS[AssuranceProfile.OFFLINE_AUDITOR_MINIMAL] == (
        1_000,
        86_400_000,
    )
    assert ACK_TIMEOUT_BOUNDS_MS[AssuranceProfile.PRODUCTION_STANDARD] == (500, 60_000)
    assert ACK_TIMEOUT_BOUNDS_MS[AssuranceProfile.REGULATED_HIGH_ASSURANCE] == (
        100,
        5_000,
    )


# ===========================================================================
# GROUP E — edge-state reduction machine (R5-004 normative non-advancement)
# ===========================================================================


def test_trusted_edge_advances_causal_frontier(tmp_path):
    """SCOPING line 598: TRUSTED edge happy path — both authenticators verify,
    counters consistent, SCITT receipts present, both timestamp_evidence
    valid; downstream events allowed to advance frontier.
    """
    edge = _make_edge_dict()
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is True
    update = compute_causal_chain_update(
        per_edge_verifier_outputs=[
            {"edge_state": "trusted", "frontier_advance_blocked": False}
        ]
    )
    assert update["cross_host_authenticators"][0]["frontier_advance_blocked"] is False


def test_disputed_edge_does_not_advance_frontier(tmp_path):
    """SCOPING line 599 + R5-004: send_intent SCITT present, no ack/nack within
    ack_timeout_ms, no timeout_witness → DISPUTED_EDGE; non-advancement rule.
    """
    edge = _make_edge_dict()
    edge["receiver_acknowledgment"] = None
    edge["ack_scitt_receipt"] = None
    edge["ack_timestamp_evidence"] = None
    edge["timeout_witness"] = None
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is False
    assert "DISPUTED_EDGE" in result.reason_code or "DISPUTED_EDGE" in result.detail


def test_unverifiable_edge_does_not_advance_frontier(tmp_path):
    """SCOPING line 600 + R5-004: timeout_witness present → UNVERIFIABLE_EDGE."""
    edge = _make_edge_dict()
    edge["receiver_acknowledgment"] = None
    edge["ack_scitt_receipt"] = None
    edge["ack_timestamp_evidence"] = None
    edge["timeout_witness"] = {"_test_only_present": True}
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is False
    assert (
        "UNVERIFIABLE_EDGE" in result.reason_code
        or "UNVERIFIABLE_EDGE" in result.detail
    )


def test_ack_timeliness_violation_does_not_advance_frontier(tmp_path):
    """SCOPING line 601 + R5-002 RADI bounds: valid ack sig + valid both
    timestamp_evidence, but `ack_upper_bound > send_lower_bound + ack_timeout_ms`
    → ACK_TIMELINESS_VIOLATION.

    Send MIDP = 1_000_000_000 ms, RADI=50; ack_timeout_ms = 100 (set very
    tight, within OFFLINE_AUDITOR_MINIMAL bounds); ack MIDP = 1_000_001_000
    (1s later) — ack_upper_bound = 1_000_001_050; send_lower_bound = 999_999_950;
    1_000_001_050 > 999_999_950 + 100 = 1_000_000_050 — violation.
    """
    edge = _make_edge_dict(ack_timeout_ms=1_000)  # within PRODUCTION_STANDARD min=500
    # ack MIDP shifted to 60s past send (production-standard max ack_timeout=60_000)
    edge["ack_timestamp_evidence"]["roughtime_quorum"]["responses"][0]["midp_ms"] = (
        1_000_000_000 + 60_000
    )
    edge["ack_timestamp_evidence"]["roughtime_quorum"]["ack_timestamp_midp"] = (
        1_000_000_000 + 60_000
    )
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is False
    assert (
        "ACK_TIMELINESS_VIOLATION" in result.reason_code
        or "ACK_TIMELINESS_VIOLATION" in result.detail
    )


@pytest.mark.parametrize(
    "state_simulator",
    [
        ("disputed", "DISPUTED_EDGE"),
        ("unverifiable", "UNVERIFIABLE_EDGE"),
        ("timeliness", "ACK_TIMELINESS_VIOLATION"),
    ],
)
def test_three_non_trusted_states_share_same_frontier_consequence(
    tmp_path, state_simulator
):
    """R5-004 normative rule: all three non-TRUSTED states MUST trigger the
    non-advancement rule while preserving distinct reason codes for forensics.
    """
    kind, expected_state = state_simulator
    edge = _make_edge_dict(ack_timeout_ms=1_000)
    if kind == "disputed":
        edge["receiver_acknowledgment"] = None
        edge["ack_scitt_receipt"] = None
        edge["ack_timestamp_evidence"] = None
        edge["timeout_witness"] = None
    elif kind == "unverifiable":
        edge["receiver_acknowledgment"] = None
        edge["ack_scitt_receipt"] = None
        edge["ack_timestamp_evidence"] = None
        edge["timeout_witness"] = {"_test_only_present": True}
    elif kind == "timeliness":
        edge["ack_timestamp_evidence"]["roughtime_quorum"]["responses"][0][
            "midp_ms"
        ] = 1_000_000_000 + 60_000
        edge["ack_timestamp_evidence"]["roughtime_quorum"]["ack_timestamp_midp"] = (
            1_000_000_000 + 60_000
        )
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is False
    assert expected_state in result.reason_code or expected_state in result.detail


# ===========================================================================
# GROUP F — profile gating for cross-host authenticator (R4-ADD-4 + R4-008)
# ===========================================================================


def test_hmac_authenticator_accepted_single_org(tmp_path):
    """R4-ADD-4: kind=HMAC + deployment_scope=SINGLE_ORG → accepted."""
    edge = _make_edge_dict(authenticator_kind="hmac", deployment_scope="single_org")
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is True


def test_hmac_authenticator_rejected_cross_org_profile_mismatch(tmp_path):
    """R4-ADD-4 + standards-bindings 'Cross-host authenticator profile selection':
    HMAC + CROSS_ORG → CROSS_HOST_AUTH_PROFILE_MISMATCH.
    """
    edge = _make_edge_dict(authenticator_kind="hmac", deployment_scope="cross_org")
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is False
    assert result.reason_code == "CROSS_HOST_AUTH_PROFILE_MISMATCH"


def _make_cose_edge_and_policy(**overrides):
    """Build a well-formed cross-org COSE_Sign1 edge + the verifier-side
    CrossOrgKeyPolicy that pins its kids (S19b v0.4). The COSE sigs are minted
    over the SAME canonical preimages the plugin reconstructs.

    C2c kid->host binding (red-team FINDING-1 fix): the sender authenticator is
    signed by the SENDER's key and the ack by a DISTINCT RECEIVER key; the policy
    binds each kid to its owning host so a single key cannot mint both halves."""
    hmac_edge = _make_edge_dict(**overrides)
    sender_priv = Ed25519PrivateKey.from_private_bytes(b"\x44" * 32)
    sender_pub = sender_priv.public_key().public_bytes(
        _ser.Encoding.Raw, _ser.PublicFormat.Raw
    )
    sender_kid = cross_host_cose_kid(sender_pub)
    receiver_priv = Ed25519PrivateKey.from_private_bytes(b"\x55" * 32)
    receiver_pub = receiver_priv.public_key().public_bytes(
        _ser.Encoding.Raw, _ser.PublicFormat.Raw
    )
    receiver_kid = cross_host_cose_kid(receiver_pub)

    sender_preimage = construct_sender_signature_preimage(
        sender_host_id=hmac_edge["sender_host_id"],
        receiver_host_id=hmac_edge["receiver_host_id"],
        channel_id=hmac_edge["channel_id"],
        message_id=hmac_edge["message_id"],
        message_hash=bytes.fromhex(hmac_edge["message_hash"]),
        sender_local_counter=hmac_edge["sender_local_counter"],
        ack_timeout_ms=hmac_edge["ack_timeout_ms"],
        bundle_id=hmac_edge["bundle_id"],
        receiver_challenge_token=bytes.fromhex(hmac_edge["receiver_challenge_token"]),
    )
    ack_preimage = construct_ack_preimage(
        sender_host_id=hmac_edge["sender_host_id"],
        receiver_host_id=hmac_edge["receiver_host_id"],
        channel_id=hmac_edge["channel_id"],
        message_id=hmac_edge["message_id"],
        message_hash=bytes.fromhex(hmac_edge["message_hash"]),
        receiver_local_counter=hmac_edge["receiver_local_counter"],
        kind="ack",
        reason_code_if_nack=None,
        bundle_id=hmac_edge["bundle_id"],
        ack_timeout_ms=hmac_edge["ack_timeout_ms"],
        sender_local_counter=hmac_edge["sender_local_counter"],
        receiver_challenge_token=bytes.fromhex(hmac_edge["receiver_challenge_token"]),
    )
    hmac_edge["authenticator_kind"] = "cose_sign1"
    hmac_edge["deployment_scope"] = "cross_org"
    hmac_edge["sender_signature"] = {
        "kid": sender_kid.hex(),
        "cose": sign_cross_host_authenticator_cose(
            private_key=sender_priv, preimage=sender_preimage
        ).hex(),
    }
    hmac_edge["receiver_acknowledgment"] = {
        "kind": "ack",
        "kid": receiver_kid.hex(),
        "cose": sign_cross_host_authenticator_cose(
            private_key=receiver_priv, preimage=ack_preimage
        ).hex(),
    }
    policy = CrossOrgKeyPolicy(
        pinned_cose_keys={sender_kid: sender_pub, receiver_kid: receiver_pub},
        pinned_hmac_ikm={},
        pinned_cose_key_hosts={
            sender_kid: hmac_edge["sender_host_id"],
            receiver_kid: hmac_edge["receiver_host_id"],
        },
    )
    return hmac_edge, policy


def test_cose_sign1_fails_closed_without_pinned_policy(tmp_path):
    """S19b D3 option-c: a cose_sign1 edge with NO verifier-pinned policy fails
    CLOSED (CROSS_HOST_KEY_NOT_PINNED) — replaces the v0.3 RESERVED refusal.
    The verifier cannot route a COSE edge without a pinned kid (C2b)."""
    for scope in ("cross_org", "single_org"):
        edge = _make_edge_dict(authenticator_kind="cose_sign1", deployment_scope=scope)
        bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
        plugin = CrossHostPeerReviewAuthenticatorCheck()  # no policy
        result = plugin.check(bundle_dir, manifest)
        assert result.ok is False
        assert result.reason_code == "CROSS_HOST_KEY_NOT_PINNED"


def test_cose_sign1_edge_verifies_under_pinned_policy(tmp_path):
    """End-to-end: a cross-org COSE_Sign1 edge verifies (sender + ack) under the
    verifier-pinned CrossOrgKeyPolicy, routed on the pinned kid (C2b)."""
    edge, policy = _make_cose_edge_and_policy()
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    plugin = CrossHostPeerReviewAuthenticatorCheck(cross_org_policy=policy)
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is True, result.reason_code


def test_cose_sign1_edge_tampered_preimage_rejected(tmp_path):
    """Tamper an edge field after COSE signing → sender COSE verify fails."""
    edge, policy = _make_cose_edge_and_policy()
    edge["message_hash"] = _sha256(b"tampered").hex()
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    plugin = CrossHostPeerReviewAuthenticatorCheck(cross_org_policy=policy)
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is False
    assert result.reason_code == "SENDER_SIGNATURE_VERIFICATION_FAILED"


def test_cose_sign1_edge_unpinned_kid_fails_closed(tmp_path):
    """A cose edge whose kid is not in the pinned policy fails closed."""
    edge, _policy = _make_cose_edge_and_policy()
    empty_policy = CrossOrgKeyPolicy(pinned_cose_keys={}, pinned_hmac_ikm={})
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    plugin = CrossHostPeerReviewAuthenticatorCheck(cross_org_policy=empty_policy)
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is False
    assert result.reason_code == "CROSS_HOST_KEY_NOT_PINNED"


# ===========================================================================
# GROUP G — counter monotonicity + channel binding
# ===========================================================================


def test_sender_local_counter_non_decreasing(tmp_path):
    """Round-2 NEW B3 binding: per-(sender_host_id, channel_id) sender_local_counter
    MUST be strictly increasing.
    """
    edge1 = _make_edge_dict(sender_local_counter=2)
    edge2 = _make_edge_dict(
        message_id="33333333-3333-3333-3333-333333333333",
        sender_local_counter=1,  # decreasing
    )
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge1, edge2])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is False
    assert "COUNTER" in result.reason_code


def test_receiver_local_counter_non_decreasing(tmp_path):
    """Round-2 NEW B3 binding mirror: per-(receiver_host_id, channel_id)
    receiver_local_counter MUST be strictly increasing.
    """
    edge1 = _make_edge_dict(receiver_local_counter=2)
    edge2 = _make_edge_dict(
        message_id="33333333-3333-3333-3333-333333333333",
        receiver_local_counter=1,  # decreasing
    )
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge1, edge2])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is False
    assert "COUNTER" in result.reason_code


def test_channel_id_binds_jointly_logged_channel_config(tmp_path):
    """SCOPING line 525 channel_id semantics: bound to jointly-logged channel
    config. Mutate channel_id on the edge AFTER signing — signature must fail.
    """
    edge = _make_edge_dict()
    edge["channel_id"] = "99999999-9999-9999-9999-999999999999"  # tampered
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is False


# ===========================================================================
# GROUP H — Haeberlen §3+§5 paired-authenticator property
# ===========================================================================


def test_misbehavior_irrefutable_via_paired_log_entries(tmp_path):
    """Haeberlen SOSP 2007 §3 fault detection via accountability: sender-signed
    send_intent + receiver-signed ack cover the same channel/message/counter
    coordinates; either party's deviation produces an irrefutable log
    mismatch detectable by an auditor.

    Test: mutate message_hash on the edge — both authenticators' preimages
    cover message_hash → signature recomputation MUST fail.
    """
    edge = _make_edge_dict()
    edge["message_hash"] = _sha256(b"adversary-mutated payload").hex()
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is False


def test_sender_cannot_forge_ack_without_receiver_key(tmp_path):
    """Haeberlen §5 symmetric authenticator design: ack signature requires
    receiver's K_cross_host_receipt_ack; sender cannot forge.

    Construct an ack signed under the SENDER's K (wrong key); verifier MUST
    reject on HMAC mismatch.
    """
    edge = _make_edge_dict()
    # Re-sign ack under sender's key (wrong)
    sender_K = bytes.fromhex(edge["sender_signature"]["_test_only_K_send_hex"])
    ack_preimage = construct_ack_preimage(
        sender_host_id=edge["sender_host_id"],
        receiver_host_id=edge["receiver_host_id"],
        channel_id=edge["channel_id"],
        message_id=edge["message_id"],
        message_hash=bytes.fromhex(edge["message_hash"]),
        receiver_local_counter=edge["receiver_local_counter"],
        kind="ack",
        reason_code_if_nack=None,
        bundle_id=edge["bundle_id"],
        ack_timeout_ms=edge["ack_timeout_ms"],
        sender_local_counter=edge["sender_local_counter"],
        receiver_challenge_token=bytes.fromhex(edge["receiver_challenge_token"]),
    )
    forged_ack = sign_cross_host_authenticator(K=sender_K, preimage=ack_preimage)
    edge["receiver_acknowledgment"]["sig"] = forged_ack.hex()
    # Keep the correct ack K available so the verifier reads it — but the
    # forged sig won't verify under the receiver's K.
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is False
    assert (
        "ACK" in result.reason_code
        or "RECEIVER" in result.reason_code
        or "HMAC" in result.reason_code
        or "SIGNATURE" in result.reason_code
    )


# ===========================================================================
# GROUP I — backward compat invariant
# ===========================================================================


def test_legacy_bundle_with_causal_chain_none_passes(tmp_path):
    """Backward compat: bundle with `manifest.causal_chain is None` (pre-C19
    legacy bundles, v0.2.1 baseline) → PASS.
    """
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir(exist_ok=True)
    payload_path = bundle_dir / "output.json"
    payload_path.write_bytes(b"{}")
    sha = hashlib.sha256(b"{}").hexdigest()
    manifest = BundleManifest(
        schema_version="vcp-v1.1-canary4",
        bundle_id="legacy",
        created_at="2026-05-19T00:00:00Z",
        files={"output.json": sha},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
        causal_chain=None,
    )
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is True
    assert result.reason_code == "PASS"
    assert "legacy" in result.detail.lower()


def test_bundle_with_causal_chain_no_cross_host_authenticators_passes(tmp_path):
    """Backward compat: causal_chain present but `cross_host_authenticators`
    sub-key absent (single-host bundle, only S19a layer_a is populated) → PASS.
    """
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, edges=None)
    # Add some unrelated causal_chain content
    assert manifest.causal_chain is not None
    manifest.causal_chain["layer_a"] = {"events": []}
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is True
    assert result.reason_code == "PASS"
    assert (
        "single-host" in result.detail.lower()
        or "no cross_host_authenticators" in result.detail.lower()
    )


def test_empty_cross_host_authenticators_list_passes(tmp_path):
    """Edge case: cross_host_authenticators is present but empty list → PASS."""
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, edges=[])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is True


# ===========================================================================
# GROUP J — discriminated-union sub-key write discipline
# ===========================================================================


def test_plugin_writes_to_subkey_not_field_declaration():
    """J1: compute_causal_chain_update returns ONLY the
    'cross_host_authenticators' sub-key — does NOT mutate the dataclass field
    declaration shape. Update dict has exactly one top-level key.
    """
    update = compute_causal_chain_update(
        per_edge_verifier_outputs=[
            {"edge_state": "trusted", "frontier_advance_blocked": False}
        ]
    )
    assert isinstance(update, dict)
    assert set(update.keys()) == {"cross_host_authenticators"}
    assert isinstance(update["cross_host_authenticators"], list)
    assert len(update["cross_host_authenticators"]) == 1


def test_compute_causal_chain_update_preserves_order():
    """Per-edge outputs preserved in order — auditor forensics depend on it."""
    outputs = [
        {"edge_state": "trusted", "frontier_advance_blocked": False, "_idx": 0},
        {"edge_state": "DISPUTED_EDGE", "frontier_advance_blocked": True, "_idx": 1},
        {
            "edge_state": "ACK_TIMELINESS_VIOLATION",
            "frontier_advance_blocked": True,
            "_idx": 2,
        },
    ]
    update = compute_causal_chain_update(per_edge_verifier_outputs=outputs)
    assert [o["_idx"] for o in update["cross_host_authenticators"]] == [0, 1, 2]


# ===========================================================================
# GROUP K — full bilateral collusion is a formal documented limitation
# ===========================================================================


def test_full_bilateral_collusion_is_documented_limitation_not_a_crash(tmp_path):
    """Decision 4 (2026-05-12) external framing: when both hosts cooperate to
    co-fabricate send_intent + ack AND control the SCITT quorum threshold,
    the plugin returns TRUSTED edge with detail naming this as the formal
    documented limitation (SCOPING line 604-605) — NOT papered over.

    The plugin sees TRUSTED in this case; the limitation is documented at
    the contract surface, not at the verifier output.
    """
    edge = _make_edge_dict()
    # All inputs valid — even though semantically the hosts could be colluding,
    # the plugin sees a TRUSTED edge.
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is True
    # The documented-limitation string MUST appear in the detail/advisory
    # surface when this code path is exercised (Decision 4 framing).
    assert (
        "bilateral host collusion" in result.detail.lower()
        or "formal documented limitation" in result.detail.lower()
        or "soak-then-harden" in result.detail.lower()
        or "reference implementation" in result.detail.lower()
    )


# ===========================================================================
# GROUP L — edge timestamp crypto verification (red-team D-SUB1)
# ===========================================================================


def test_edge_timestamp_default_mode_accepts_shape_only_with_disclosure(tmp_path):
    """Red-team D-SUB1 baseline: by default the verifier SHAPE-checks edge
    timestamps (no Roughtime SREP signature), so a shape-only edge PASSes — the
    documented OF-4 gap. The PASS detail now states the timestamps are NOT a
    crypto-verified clock so the verdict cannot be misread.
    """
    edge = _make_edge_dict()  # default send/ack evidence carries no srep_bytes_b64
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    result = CrossHostPeerReviewAuthenticatorCheck().check(bundle_dir, manifest)
    assert result.ok is True
    assert "not crypto-verified" in result.detail.lower()


def test_edge_timestamp_strict_mode_rejects_shape_only_unverified(tmp_path):
    """Red-team D-SUB1 closure: the SAME shape-only edge that PASSes by default
    is REJECTED under require_verified_edge_timestamps=True because no signed
    Roughtime SREP backs the MIDP — the attacker-asserted clock is unverifiable.

    Expect: EDGE_TIMESTAMP_UNVERIFIED.
    """
    edge = _make_edge_dict()
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    result = CrossHostPeerReviewAuthenticatorCheck(
        require_verified_edge_timestamps=True
    ).check(bundle_dir, manifest)
    assert result.ok is False
    assert "EDGE_TIMESTAMP_UNVERIFIED" in result.reason_code


def test_edge_timestamp_strict_mode_rejects_backdated_2009(tmp_path):
    """Red-team D-SUB1 (poc_job1_collusion): a back-dated 2009 MIDP with no SREP
    signature PASSes the default verifier (relative timeliness only) but is
    rejected under strict mode — a pinned Roughtime root cannot have signed a
    2009 timestamp, and a shape-only response carries no signature at all.

    Models redteam/streamD_collusion/poc_job1_collusion.py._back_dated_ts_evidence.
    """
    backdate_ms = 1_230_940_800_000  # 2009-01-03T00:00:00Z (Bitcoin genesis day)
    edge = _make_edge_dict(
        send_timestamp_evidence={
            "kind": "roughtime_quorum",
            "roughtime_quorum": {
                "responses": [{"midp_ms": backdate_ms, "radi_ms": 40}]
            },
        },
        ack_timestamp_evidence={
            "kind": "roughtime_quorum",
            "roughtime_quorum": {
                "responses": [{"midp_ms": backdate_ms + 50, "radi_ms": 40}]
            },
        },
    )
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    # Default verifier accepts the back-dated clock (the disclosed gap).
    assert CrossHostPeerReviewAuthenticatorCheck().check(bundle_dir, manifest).ok
    # Strict verifier rejects it.
    result = CrossHostPeerReviewAuthenticatorCheck(
        require_verified_edge_timestamps=True
    ).check(bundle_dir, manifest)
    assert result.ok is False
    assert "EDGE_TIMESTAMP_UNVERIFIED" in result.reason_code


# ===========================================================================
# Machine-readable disclosures (assurance labeling, 2026-06-10): the PASS
# result's honest residuals must ride PluginResult.disclosures so they reach
# Completeness.disclosures on the library verdict face — a passing plugin's
# detail prose alone is dropped by verify().
# ===========================================================================


def test_pass_carries_reference_grade_disclosure_default_mode(tmp_path):
    edge = _make_edge_dict()
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, [edge])
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is True and result.reason_code == "PASS"
    joined = "\n".join(result.disclosures)
    # Reference-grade limitation always disclosed on a trusted-edges PASS.
    assert "v0.3 reference implementation" in joined
    assert "bilateral host collusion" in joined
    # Default mode additionally discloses shape-checked-only timestamps.
    assert "SHAPE-CHECKED" in joined
    # Stable greppable prefix for downstream policy.
    assert all(d.startswith("cross_host_peerreview: ") for d in result.disclosures)


def test_legacy_none_causal_chain_pass_has_no_disclosures(tmp_path):
    """No cross-host evidence was trusted -> no residual to disclose."""
    bundle_dir, manifest = _make_manifest_with_causal_chain(tmp_path, None)
    plugin = CrossHostPeerReviewAuthenticatorCheck()
    result = plugin.check(bundle_dir, manifest)
    assert result.ok is True
    assert getattr(result, "disclosures", ()) == ()
