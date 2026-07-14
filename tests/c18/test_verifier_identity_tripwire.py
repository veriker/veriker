"""Unit tests for audit_bundle.plugins.verifier_identity_tripwire (c18-013).

Per S18 PRD: 6 scenarios covering legacy pass-through + valid identity +
tripwire fire (logging-only, ok=True) + structural FAIL paths.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from audit_bundle.plugins.verifier_identity_tripwire import (
    EVENT_KIND_VERIFIER_IDENTITY_DIVERGENCE,
    VerifierIdentityTripwireCheck,
)


VALID_REKOR_PROOF = {
    "leaf_index": 100,
    "tree_size": 200,
    "hashes": ["aa" * 32, "bb" * 32],
    "root_hash": "deadbeef" * 8,
}


def _valid_identity_block(**overrides) -> dict:
    block = {
        "verifier_release_id": "v0.3.0",
        "verifier_oci_digest": "sha256:" + "a" * 64,
        "verifier_self_check_status": "passed",
        "release_manifest_url": "https://manifest.vkernel.dev/v0.3.0.json",
        "release_manifest_hash": "sha256:" + "0" * 64,
        "scitt_statement_hash": "sha256:" + "1" * 64,
        "sigstore_bundle_hash": "sha256:" + "2" * 64,
        "rekor_inclusion_proof": dict(VALID_REKOR_PROOF),
    }
    block.update(overrides)
    return block


def _manifest_with(block: dict | None) -> dict:
    if block is None:
        return {"evidence": {}}
    return {"evidence": {"verifier_identity": block}}


def test_empty_bundle_no_verifier_identity_passes(tmp_path: Path):
    """Test 1: empty bundle (no verifier_identity) → PASS (no events written)."""
    check = VerifierIdentityTripwireCheck()
    result = check.check(tmp_path, _manifest_with(None))
    assert result.ok is True
    assert "no verifier_identity field present" in (result.detail or "")
    # No events.jsonl should be created.
    assert not (tmp_path / "events.jsonl").exists()


def test_valid_identity_self_check_passed(tmp_path: Path):
    """Test 2: valid identity + self_check=passed → PASS, no events written."""
    check = VerifierIdentityTripwireCheck()
    result = check.check(tmp_path, _manifest_with(_valid_identity_block()))
    assert result.ok is True
    assert "self-check" in (result.detail or "").lower()
    assert "tripwire signal, not trust assertion" in (result.detail or "").lower()
    assert not (tmp_path / "events.jsonl").exists()


def test_valid_identity_self_check_failed_fires_tripwire(tmp_path: Path):
    """Test 3: valid identity + self_check=failed → tripwire FIRES.

    CRITICAL: ok=True (logging-only signal per CV4); the divergence is
    surfaced as a verdict-face disclosure, NOT a bundle_dir write (read-only
    invariant — a verifier-written events.jsonl is UNOWNED surplus to the
    conservation gate and would flip the bundle RED on re-verification).
    """
    check = VerifierIdentityTripwireCheck()
    block = _valid_identity_block(verifier_self_check_status="failed")
    result = check.check(tmp_path, _manifest_with(block))
    # PLUGIN DOES NOT BLOCK — ok=True even when tripwire fires.
    assert result.ok is True, "tripwire MUST NOT block per CV4 disposition"
    assert "tripwire fired" in (result.detail or "").lower()
    # bundle_dir is NOT written.
    assert not (tmp_path / "events.jsonl").exists()
    # The disclosure carries the kind + the producer-reported status.
    assert len(result.disclosures) == 1
    disclosure = result.disclosures[0]
    assert EVENT_KIND_VERIFIER_IDENTITY_DIVERGENCE in disclosure
    payload = json.loads(disclosure.split(" — ", 1)[1])
    assert payload["reported_self_check_status"] == "failed"
    assert payload["verifier_oci_digest"] == block["verifier_oci_digest"]


def test_structural_fail_malformed_oci_digest(tmp_path: Path):
    """Test 4: malformed OCI digest → FAIL with VERIFIER_IDENTITY_OCI_DIGEST_MALFORMED."""
    check = VerifierIdentityTripwireCheck()
    block = _valid_identity_block(verifier_oci_digest="bogus-not-sha256")
    result = check.check(tmp_path, _manifest_with(block))
    assert result.ok is False
    assert result.reason_code == "VERIFIER_IDENTITY_OCI_DIGEST_MALFORMED"


def test_structural_fail_self_check_unknown_status(tmp_path: Path):
    """Test 5: self_check_status='unknown' → FAIL with VERIFIER_SELF_CHECK_UNKNOWN_STATUS
    per Pass-1 tightening item 13."""
    check = VerifierIdentityTripwireCheck()
    block = _valid_identity_block(verifier_self_check_status="bogus-status")
    result = check.check(tmp_path, _manifest_with(block))
    assert result.ok is False
    assert result.reason_code == "VERIFIER_SELF_CHECK_UNKNOWN_STATUS"


def test_tripwire_fire_leaves_bundle_dir_untouched(tmp_path: Path):
    """Test 6 (read-only invariant): the tripwire-fire path must not create
    or modify ANY file in bundle_dir — the conservation gate classifies a
    verifier-written file as UNOWNED surplus on re-verification."""
    check = VerifierIdentityTripwireCheck()
    (tmp_path / "manifest.json").write_text("{}")
    before = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*"))
    block = _valid_identity_block(verifier_self_check_status="failed")
    result = check.check(tmp_path, _manifest_with(block))
    assert result.ok is True
    assert result.disclosures, "tripwire fire must surface a disclosure"
    after = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*"))
    assert before == after, "tripwire fire wrote into bundle_dir"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
