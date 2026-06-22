"""Tier 7 hardening regression suite for the cross-host receipt path.

Two surfaces, both filed in `the internal design notes` as session-doable
Tier 7 items after the Tier 6 vector-coverage sweep closed.

(a) **Single-host edge K_send soundness** when sender_host == receiver_host.
    Scope: SOUNDNESS PIN, not a contract change. PoC1 scoping Q1 explicitly
    leaves the trust-model question OPEN ("acceptable trade-off, or should
    single-host edges use a different key derivation?" — tribunal call), so
    the verifier reject contract is NOT widened here. What IS pinned: the
    crypto-level invariant that K_send ≠ K_ack even when both derive from
    the SAME host IKM (RFC 5869 §2.3 info-label separation property — same
    IKM, distinct info, distinct OKM); and the observable fact that the
    current substrate accepts self-edges silently — so a future change to
    that contract is loudly visible. See PoC1 scoping doc Q1.

(b) **Bundle-wide receiver_challenge_token uniqueness.** Pre-Tier-7 the
    nonce-replay check was scoped per (sender, receiver, channel) at both
    `check_cross_host_edge_set_stateful` and
    `CrossHostPeerReviewAuthenticatorCheck._check_edge`. Cross-channel and
    cross-receiver RCT reuse silently passed. RCT is supposed to be a
    globally-fresh receiver-issued nonce; reuse anywhere in the bundle
    indicates RNG failure, equivocating receiver, or operator error. The
    check is widened to bundle-wide scope (subsumes per-channel; existing
    `test_challenge_token_replay_across_messages` still passes).

Bound: RFC 5869 §2.3, Haeberlen SOSP 2007 §3 (PeerReview anti-replay).
"""

from __future__ import annotations

import hashlib

import pytest

from audit_bundle.extensions.c19.cross_host_peerreview import (
    _CTX_ACK,
    _CTX_SENDER,
    check_cross_host_edge_set_stateful,
    construct_ack_preimage,
    construct_sender_signature_preimage,
    derive_cross_host_receipt_key,
    sign_cross_host_authenticator,
    verify_cross_host_authenticator,
)


# ---------------------------------------------------------------------------
# Tier 7(a) — single-host edge soundness pin.
# ---------------------------------------------------------------------------


def test_self_edge_k_send_distinct_from_k_ack_when_sender_equals_receiver():
    """Crypto-level soundness: when sender_host == receiver_host, K_send and
    K_ack derive from the SAME host IKM but DIFFERENT info_labels. RFC 5869
    §2.3 guarantees `info` is a binding input to the OKM; distinct info →
    distinct OKM. So even on a self-edge, the two derived keys differ —
    sender and ack signatures cannot collide via key-equality.

    This is the narrow-crypto soundness property; the wider trust-model
    question (whether self-edges should be permitted at all, or routed
    through a different scheme) is PoC1 scoping Q1 — deferred to tribunal.
    """
    host_ikm = b"\x33" * 32  # single host's signing IKM — same on both ends
    k_send = derive_cross_host_receipt_key(
        sender_signing_key_material=host_ikm,
        info_label=_CTX_SENDER,
    )
    k_ack = derive_cross_host_receipt_key(
        sender_signing_key_material=host_ikm,
        info_label=_CTX_ACK,
    )
    assert len(k_send) == 32
    assert len(k_ack) == 32
    assert k_send != k_ack, (
        "RFC 5869 §2.3 info-label separation FAILED on self-edge: K_send "
        "and K_ack collided despite distinct info labels — self-edges would "
        "lose send/ack distinguishability"
    )


def test_self_edge_per_edge_signatures_verify_correctly():
    """Operational soundness pin: on a self-edge, the sender_authenticator
    and ack_authenticator each correctly verify against their own preimage
    + key. Sender-sig under K_send + sender_preimage; ack-sig under K_ack +
    ack_preimage. This is what would make a self-edge a real artifact a
    consumer could (in principle) inspect, regardless of the open trust
    question about whether they SHOULD be permitted.
    """
    host_ikm = b"\x44" * 32
    k_send = derive_cross_host_receipt_key(
        sender_signing_key_material=host_ikm, info_label=_CTX_SENDER
    )
    k_ack = derive_cross_host_receipt_key(
        sender_signing_key_material=host_ikm, info_label=_CTX_ACK
    )
    self_host = "host-X"
    sender_pre = construct_sender_signature_preimage(
        sender_host_id=self_host,
        receiver_host_id=self_host,  # self-edge
        channel_id="chan-self",
        message_id="msg-self-1",
        message_hash=hashlib.sha256(b"self-payload").digest(),
        sender_local_counter=1,
        ack_timeout_ms=1000,
        bundle_id="self-bundle",
        receiver_challenge_token=b"\x55" * 16,
    )
    ack_pre = construct_ack_preimage(
        sender_host_id=self_host,
        receiver_host_id=self_host,
        channel_id="chan-self",
        message_id="msg-self-1",
        message_hash=hashlib.sha256(b"self-payload").digest(),
        receiver_local_counter=1,
        kind="ack",
        reason_code_if_nack=None,
        bundle_id="self-bundle",
        ack_timeout_ms=1000,
        sender_local_counter=1,
        receiver_challenge_token=b"\x55" * 16,
    )
    sender_sig = sign_cross_host_authenticator(K=k_send, preimage=sender_pre)
    ack_sig = sign_cross_host_authenticator(K=k_ack, preimage=ack_pre)

    # Each authenticator verifies under ITS OWN key + preimage.
    assert verify_cross_host_authenticator(K=k_send, preimage=sender_pre, sig=sender_sig)
    assert verify_cross_host_authenticator(K=k_ack, preimage=ack_pre, sig=ack_sig)

    # Cross-verification (sender-sig under K_ack, etc.) MUST fail — proves
    # the info-label separation translates into authenticator distinguishability,
    # not just key-byte distinguishability.
    assert not verify_cross_host_authenticator(
        K=k_ack, preimage=sender_pre, sig=sender_sig
    )
    assert not verify_cross_host_authenticator(
        K=k_send, preimage=ack_pre, sig=ack_sig
    )


def test_self_edge_currently_accepted_by_stateful_walk_q1_open():
    """Behavior pin: the current substrate ACCEPTS self-edges (sender_host_id
    == receiver_host_id) silently — they pass `check_cross_host_edge_set_stateful`.

    This is the observable state. The narrow crypto soundness above
    (test_self_edge_k_send_distinct_from_k_ack_…) confirms the math holds;
    PoC1 scoping Q1 OPENS the trust-model question of whether self-edges
    should be rejected outright, accepted-with-a-downgraded-trust-label, or
    routed through a different key derivation. This test fails LOUDLY if a
    future change makes self-edges reject silently — forcing the change to
    pass through a tribunal decision rather than a drive-by edit.

    See: the internal design notes
    Q1.
    """
    self_edge = {
        "sender_host_id": "host-A",
        "receiver_host_id": "host-A",  # self
        "channel_id": "chan-1",
        "message_id": "msg-1",
        "sender_local_counter": 1,
        "receiver_local_counter": 1,
        "receiver_challenge_token": "aa" * 16,
    }
    ok, reason, _ = check_cross_host_edge_set_stateful([self_edge])
    assert ok is True, (
        "self-edge stateful-walk behavior changed — if this is intentional, "
        "update the test alongside the tribunal decision on PoC1 Q1; if not, "
        "investigate before merging. Q1 is OPEN per "
        "the internal design notes."
    )
    assert reason == "PASS"


# ---------------------------------------------------------------------------
# Tier 7(b) — bundle-wide RCT uniqueness.
# ---------------------------------------------------------------------------


def _stateful_edge(
    *,
    sender_host_id: str = "host-A",
    receiver_host_id: str = "host-B",
    channel_id: str = "chan-1",
    message_id: str,
    sender_local_counter: int,
    receiver_local_counter: int,
    rct_hex: str,
) -> dict:
    """Minimal edge dict for `check_cross_host_edge_set_stateful` (flat path).
    Only the fields the stateful walk reads — no signatures needed since this
    function is shape-only on the listed keys.
    """
    return {
        "sender_host_id": sender_host_id,
        "receiver_host_id": receiver_host_id,
        "channel_id": channel_id,
        "message_id": message_id,
        "sender_local_counter": sender_local_counter,
        "receiver_local_counter": receiver_local_counter,
        "receiver_challenge_token": rct_hex,
    }


def test_rct_reuse_within_same_channel_still_rejected_post_7b():
    """The pre-7b per-channel check still fires post-7b (bundle-wide
    subsumes per-channel). Companion to the existing
    test_challenge_token_replay_across_messages — pins the contract from
    the flat-schema path."""
    rct = "aa" * 16
    edge1 = _stateful_edge(
        message_id="m1", sender_local_counter=1, receiver_local_counter=1, rct_hex=rct
    )
    edge2 = _stateful_edge(
        message_id="m2", sender_local_counter=2, receiver_local_counter=2, rct_hex=rct
    )
    ok, reason, detail = check_cross_host_edge_set_stateful([edge1, edge2])
    assert ok is False
    assert reason == "CHALLENGE_TOKEN_REPLAY_DETECTED"
    assert "bundle" in detail.lower(), (
        f"expected bundle-wide framing in detail; got {detail!r}"
    )


def test_rct_reuse_across_distinct_channels_rejected_post_7b():
    """Pre-7b: same RCT on (sender_A, recv_B, chan_1) and (sender_A, recv_B,
    chan_2) silently passed (channel_key differed). Post-7b: REJECTED — RCT
    is a globally-fresh nonce, channel boundary does not relax that.
    """
    rct = "bb" * 16
    edge1 = _stateful_edge(
        channel_id="chan-1",
        message_id="m1",
        sender_local_counter=1,
        receiver_local_counter=1,
        rct_hex=rct,
    )
    edge2 = _stateful_edge(
        channel_id="chan-2",
        message_id="m2",
        sender_local_counter=1,  # fresh channel, fresh counter
        receiver_local_counter=1,
        rct_hex=rct,
    )
    ok, reason, detail = check_cross_host_edge_set_stateful([edge1, edge2])
    assert ok is False, (
        "cross-channel RCT reuse silently accepted — Tier 7b widening did "
        "not take effect"
    )
    assert reason == "CHALLENGE_TOKEN_REPLAY_DETECTED"
    assert "chan-2" in detail or "chan-1" in detail


def test_rct_reuse_across_distinct_receivers_rejected_post_7b():
    """Pre-7b: receiver_B and receiver_C could both issue the same RCT to
    sender_A and the bundle passed. Post-7b: REJECTED. Catches the
    equivocating-receiver / shared-bad-RNG class.
    """
    rct = "cc" * 16
    edge1 = _stateful_edge(
        sender_host_id="host-A",
        receiver_host_id="host-B",
        channel_id="chan-AB",
        message_id="m1",
        sender_local_counter=1,
        receiver_local_counter=1,
        rct_hex=rct,
    )
    edge2 = _stateful_edge(
        sender_host_id="host-A",
        receiver_host_id="host-C",  # different receiver
        channel_id="chan-AC",
        message_id="m2",
        sender_local_counter=1,
        receiver_local_counter=1,
        rct_hex=rct,
    )
    ok, reason, detail = check_cross_host_edge_set_stateful([edge1, edge2])
    assert ok is False
    assert reason == "CHALLENGE_TOKEN_REPLAY_DETECTED"
    assert "host-C" in detail or "host-B" in detail


def test_distinct_rct_across_two_edges_still_passes_post_7b():
    """Sanity tripwire — the bundle-wide widening must NOT over-reject. Two
    edges with distinct RCTs are fine on any channel/host pair.
    """
    edge1 = _stateful_edge(
        message_id="m1",
        sender_local_counter=1,
        receiver_local_counter=1,
        rct_hex="dd" * 16,
    )
    edge2 = _stateful_edge(
        message_id="m2",
        sender_local_counter=2,
        receiver_local_counter=2,
        rct_hex="ee" * 16,
    )
    ok, reason, _ = check_cross_host_edge_set_stateful([edge1, edge2])
    assert ok is True
    assert reason == "PASS"


def test_rct_reuse_detail_message_names_the_offending_edge_index():
    """Operability: the detail message must identify which edge failed so a
    consumer can locate the duplicate without re-walking the bundle."""
    rct = "ff" * 16
    edge1 = _stateful_edge(
        channel_id="chan-1",
        message_id="m1",
        sender_local_counter=1,
        receiver_local_counter=1,
        rct_hex=rct,
    )
    # Insert a benign edge between the two duplicates to make sure the index
    # in the detail is the SECOND occurrence (idx=2), not the first.
    edge_mid = _stateful_edge(
        channel_id="chan-1",
        message_id="m-mid",
        sender_local_counter=2,
        receiver_local_counter=2,
        rct_hex="01" * 16,
    )
    edge3 = _stateful_edge(
        channel_id="chan-2",
        message_id="m3",
        sender_local_counter=1,
        receiver_local_counter=1,
        rct_hex=rct,  # reuses edge1's RCT
    )
    ok, reason, detail = check_cross_host_edge_set_stateful([edge1, edge_mid, edge3])
    assert ok is False
    assert reason == "CHALLENGE_TOKEN_REPLAY_DETECTED"
    assert "edge[2]" in detail, (
        f"expected edge[2] to be flagged (the second occurrence); detail={detail!r}"
    )
