"""Unit tests for STH-gossip structural pre-check (c18-019).

Per S18 PRD this leg targets Rekor split-view detection. At v0.3 the
implementation is a STRUCTURAL pre-check only: it performs NO cryptographic
signature, witness-co-signature, or RFC-6962 consistency verification (that is
v0.4 work, gated on a pinned witness key + second-monitor outreach). These
tests pin that honest contract — in particular, a present-but-bogus signature
must NOT be reported as cryptographically verified.
"""

from __future__ import annotations

import pytest

from audit_bundle.extensions.c18_tuf_client import (
    REASON_STH_GOSSIP_CONSISTENCY_PROOF_FAILED,
    REASON_STH_GOSSIP_INCLUSION_PROOF_DIVERGES,
    REASON_STH_GOSSIP_SIGNATURE_INVALID,
    SthGossipResult,
    check_sth_gossip_structure,
)


def _sth_with_placeholder_sig(
    tree_size: int = 100, root_hash: str = "deadbeef" * 8
) -> dict:
    # NOTE: the signature here is a PLACEHOLDER. v0.3 never cryptographically
    # verifies the signature bytes, so the value is intentionally not a real
    # Rekor signature — the tests below assert it is reported as NOT verified.
    return {
        "signed_tree_head": {
            "tree_size": tree_size,
            "root_hash": root_hash,
            "log_id": "rekor.sigstore.dev",
            "signature": "MEQCIBogus...",
        },
    }


def _valid_inclusion_proof(
    leaf_index: int = 50,
    tree_size: int = 100,
    root_hash: str = "deadbeef" * 8,
) -> dict:
    return {
        "leaf_index": leaf_index,
        "tree_size": tree_size,
        "hashes": ["aa" * 32, "bb" * 32],
        "root_hash": root_hash,
    }


def test_result_is_never_cryptographically_verified_at_v03():
    """The v0.3 path performs no crypto, so cryptographically_verified is
    ALWAYS False — even for a structurally-consistent STH with a present
    (but bogus) signature. An empty reason-set is NOT a cryptographic PASS."""
    sth = _sth_with_placeholder_sig(tree_size=100)
    proof = _valid_inclusion_proof(leaf_index=50, tree_size=100)
    result = check_sth_gossip_structure(sth, proof)
    assert isinstance(result, SthGossipResult)
    # No structural divergence...
    assert result.reasons == []
    # ...but explicitly NOT cryptographically verified (bogus sig not checked).
    assert result.cryptographically_verified is False


def test_structural_only_even_when_no_inclusion_proof():
    """With only the STH (empty inclusion proof), only the signature-presence
    shape check runs and the result is still not cryptographically verified."""
    sth = _sth_with_placeholder_sig()
    result = check_sth_gossip_structure(sth, {})
    assert result.reasons == []
    assert result.cryptographically_verified is False


def test_sth_signature_absent_returns_reason():
    """STH missing its signature field → STH_GOSSIP_SIGNATURE_INVALID (shape
    check), and still not cryptographically verified."""
    sth = _sth_with_placeholder_sig()
    del sth["signed_tree_head"]["signature"]
    proof = _valid_inclusion_proof()
    result = check_sth_gossip_structure(sth, proof)
    assert REASON_STH_GOSSIP_SIGNATURE_INVALID in result.reasons
    assert result.cryptographically_verified is False


def test_inclusion_proof_diverges_from_gossiped_sth():
    """Inclusion-proof tree_size > gossiped STH tree_size →
    STH_GOSSIP_INCLUSION_PROOF_DIVERGES_FROM_GOSSIPED_STH.

    This catches the structural split-view signal where Rekor served a newer
    log state to the bundle producer than to the monitor.
    """
    sth = _sth_with_placeholder_sig(tree_size=80)  # monitor sees 80
    proof = _valid_inclusion_proof(tree_size=100)  # bundle producer saw 100
    result = check_sth_gossip_structure(sth, proof)
    assert REASON_STH_GOSSIP_INCLUSION_PROOF_DIVERGES in result.reasons
    assert result.cryptographically_verified is False


def test_consistency_proof_failed_when_same_tree_size_different_root():
    """Same tree_size but root_hash mismatch → CONSISTENCY_PROOF_FAILED
    (structural check)."""
    sth = _sth_with_placeholder_sig(tree_size=100, root_hash="aa" * 32)
    proof = _valid_inclusion_proof(tree_size=100, root_hash="bb" * 32)
    result = check_sth_gossip_structure(sth, proof)
    assert REASON_STH_GOSSIP_CONSISTENCY_PROOF_FAILED in result.reasons
    assert result.cryptographically_verified is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
