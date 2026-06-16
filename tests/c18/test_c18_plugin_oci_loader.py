"""Unit tests for audit_bundle.extensions.c18_plugin_oci_loader (c18-016).

Per S18 PRD: 5 scenarios covering CV5 closure.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from audit_bundle.extensions.c18_plugin_oci_loader import (
    EVENT_KIND_PLUGIN_LOADED,
    REASON_PLUGIN_COSIGN_VERIFY_FAILED,
    REASON_PLUGIN_NOT_IN_ALLOWLIST,
    REASON_PLUGIN_OCI_DIGEST_MISMATCH,
    REASON_PLUGIN_REGISTRY_ORG_NOT_ALLOWLISTED,
    PluginOCILoader,
)


def _sample_allowlist(
    plugin_name: str = "spec_sha_pin",
    *,
    oci_digest: str = "sha256:" + "a" * 64,
    slsa_digest: str = "sha256:" + "s" * 64,
    cosign_cert: str = (
        "https://github.com/nexiverify/veriker"
        "/.github/workflows/release.yml@refs/tags/v0.3.0"
    ),
    registry_org: str = "ghcr.io/nexiverify/",
    oci_artifact: str = (
        "ghcr.io/nexiverify/veriker-plugins/spec-sha-pin:v0.3.0"
    ),
) -> dict:
    """Build a minimal plugin_allowlist.json shape."""
    return {
        "role_name": "plugin-allowlist",
        "registry_org_allowlist": [registry_org],
        "entries": {
            plugin_name: {
                "oci_artifact": oci_artifact,
                "oci_digest_at_v0_3_cut": oci_digest,
                "cosign_cert_identity": cosign_cert,
                "slsa_provenance_digest_at_v0_3_cut": slsa_digest,
            }
        },
    }


def _mock_cosign_ok(**kwargs):
    return True, ""


def _mock_cosign_fail(**kwargs):
    return False, "fulcio cert identity does not match expected"


def _mock_slsa_lookup_match(expected_slsa: str):
    def _inner(**kwargs):
        return expected_slsa

    return _inner


def _mock_slsa_lookup_drift(**kwargs):
    return "sha256:" + "Z" * 64  # always mismatches


def test_plugin_in_allowlist_with_matching_digest_loads(tmp_path: Path):
    """Test 1: plugin in allowlist + matching digest → LOAD + events.jsonl row."""
    plugin_name = "spec_sha_pin"
    plugin_bytes = b"plugin source bytes - fixture only"
    plugin_digest = "sha256:" + hashlib.sha256(plugin_bytes).hexdigest()
    allowlist = _sample_allowlist(plugin_name=plugin_name, oci_digest=plugin_digest)
    slsa_digest = allowlist["entries"][plugin_name][
        "slsa_provenance_digest_at_v0_3_cut"
    ]

    loader = PluginOCILoader(
        bundle_dir=tmp_path,
        allowlist=allowlist,
        allow_direct_import=False,
        cosign_runner=_mock_cosign_ok,
        slsa_provenance_lookup=_mock_slsa_lookup_match(slsa_digest),
    )
    outcome = loader.load_plugin(plugin_name, local_plugin_bytes=plugin_bytes)
    assert outcome.ok is True
    assert outcome.oci_digest == plugin_digest
    # events.jsonl row written.
    rows = [
        json.loads(line)
        for line in (tmp_path / "events.jsonl").read_text().splitlines()
        if line.strip()
    ]
    assert len(rows) == 1
    assert rows[0]["kind"] == EVENT_KIND_PLUGIN_LOADED
    assert rows[0]["detail"]["plugin_name"] == plugin_name


def test_plugin_not_in_allowlist_rejected(tmp_path: Path):
    """Test 2: plugin not in allowlist → PLUGIN_NOT_IN_ALLOWLIST."""
    allowlist = _sample_allowlist(plugin_name="spec_sha_pin")
    loader = PluginOCILoader(
        bundle_dir=tmp_path,
        allowlist=allowlist,
        cosign_runner=_mock_cosign_ok,
    )
    outcome = loader.load_plugin(
        "completely_unknown_plugin",
        local_plugin_bytes=b"anything",
    )
    assert outcome.ok is False
    assert outcome.reason_code == REASON_PLUGIN_NOT_IN_ALLOWLIST


def test_plugin_digest_mismatch_rejected(tmp_path: Path):
    """Test 3: plugin in allowlist but digest mismatch → PLUGIN_OCI_DIGEST_MISMATCH."""
    plugin_name = "spec_sha_pin"
    plugin_bytes = b"actual plugin bytes"
    wrong_digest_for_allowlist = "sha256:" + "f" * 64  # not the hash of plugin_bytes
    allowlist = _sample_allowlist(
        plugin_name=plugin_name,
        oci_digest=wrong_digest_for_allowlist,
    )
    loader = PluginOCILoader(
        bundle_dir=tmp_path,
        allowlist=allowlist,
        cosign_runner=_mock_cosign_ok,
    )
    outcome = loader.load_plugin(plugin_name, local_plugin_bytes=plugin_bytes)
    assert outcome.ok is False
    assert outcome.reason_code == REASON_PLUGIN_OCI_DIGEST_MISMATCH


def test_plugin_cosign_verify_failed_rejected(tmp_path: Path):
    """Test 4: plugin in allowlist + matching digest + bad cosign cert → PLUGIN_COSIGN_VERIFY_FAILED."""
    plugin_name = "spec_sha_pin"
    plugin_bytes = b"plugin source bytes - cosign-fail fixture"
    plugin_digest = "sha256:" + hashlib.sha256(plugin_bytes).hexdigest()
    allowlist = _sample_allowlist(plugin_name=plugin_name, oci_digest=plugin_digest)

    loader = PluginOCILoader(
        bundle_dir=tmp_path,
        allowlist=allowlist,
        cosign_runner=_mock_cosign_fail,
    )
    outcome = loader.load_plugin(plugin_name, local_plugin_bytes=plugin_bytes)
    assert outcome.ok is False
    assert outcome.reason_code == REASON_PLUGIN_COSIGN_VERIFY_FAILED


def test_plugin_registry_org_not_allowlisted_rejected(tmp_path: Path):
    """Test 5: plugin in allowlist from WRONG registry → PLUGIN_REGISTRY_ORG_NOT_ALLOWLISTED."""
    plugin_name = "spec_sha_pin"
    # Allowlist's registry_org_allowlist is ghcr.io/nexiverify/ but the entry
    # itself names a different registry.
    allowlist = _sample_allowlist(
        plugin_name=plugin_name,
        oci_artifact="docker.io/random/spec-sha-pin:v0.3.0",
    )
    loader = PluginOCILoader(
        bundle_dir=tmp_path,
        allowlist=allowlist,
        cosign_runner=_mock_cosign_ok,
    )
    outcome = loader.load_plugin(
        plugin_name,
        local_plugin_bytes=b"plugin source",
    )
    assert outcome.ok is False
    assert outcome.reason_code == REASON_PLUGIN_REGISTRY_ORG_NOT_ALLOWLISTED


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


def test_default_slsa_lookup_fails_closed(tmp_path: Path):
    """Test 6: reaching the SLSA step without a wired lookup must raise, not
    compare a placeholder. A returned sentinel could tautologically match an
    allowlist entry still carrying the same pre-release placeholder (false
    green: plugin admitted with no provenance check)."""
    from audit_bundle.extensions.c18_plugin_oci_loader import PluginLoaderError

    plugin_name = "spec_sha_pin"
    plugin_bytes = b"plugin source bytes - default-slsa fixture"
    plugin_digest = "sha256:" + hashlib.sha256(plugin_bytes).hexdigest()
    allowlist = _sample_allowlist(plugin_name=plugin_name, oci_digest=plugin_digest)

    loader = PluginOCILoader(
        bundle_dir=tmp_path,
        allowlist=allowlist,
        cosign_runner=_mock_cosign_ok,
        # no slsa_provenance_lookup -> pre-release-cut default
    )
    with pytest.raises(PluginLoaderError, match="not wired"):
        loader.load_plugin(plugin_name, local_plugin_bytes=plugin_bytes)
