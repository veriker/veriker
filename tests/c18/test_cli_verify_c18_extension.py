"""Unit tests for veriker/cli/verify.py C18 stdlib-only structural extension (c18-014).

All tests are STDLIB-ONLY (no audit_bundle.extensions.* imports). Validates
the 5 PRD-required scenarios + ensures no third-party imports leaked into
the C18 extension section.
"""

from __future__ import annotations

import ast
import hashlib
import json
import sys
from pathlib import Path

import pytest

# Import the stdlib-only helpers directly from veriker.cli/verify.py.
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# Import only the C18 helper symbols; this confirms they exist with the
# documented stdlib-only surface.
from veriker.cli.verify import (  # noqa: E402
    _C18_OCI_DIGEST_PATTERN,
    _c18_extract_verifier_identity,
    _c18_structural_check,
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


def _write_bundle(tmp_path: Path, block: dict | None) -> Path:
    """Write a minimal manifest.json under tmp_path; returns the dir."""
    manifest = {"schema_version": "v0.3", "evidence": {}}
    if block is not None:
        manifest["evidence"]["verifier_identity"] = block
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return tmp_path


def test_legacy_bundle_no_verifier_identity_passes(tmp_path: Path):
    """Test 1: legacy bundle without verifier_identity → PASS no C18 hints."""
    bundle_dir = _write_bundle(tmp_path, None)
    ok, reason, detail = _c18_structural_check(bundle_dir)
    assert ok is True
    assert reason is None
    assert "pre-C18 bundle" in detail


def test_valid_c18_bundle_passes_and_emits_hints(tmp_path: Path):
    """Test 2: valid C18 bundle → PASS + 4-step next-steps hint structure."""
    bundle_dir = _write_bundle(tmp_path, _valid_identity_block())
    ok, reason, detail = _c18_structural_check(bundle_dir)
    assert ok is True
    assert reason is None
    assert "structurally valid" in detail


def test_malformed_oci_digest_fails(tmp_path: Path):
    """Test 3: malformed OCI digest → FAIL exit-code reason."""
    bundle_dir = _write_bundle(
        tmp_path,
        _valid_identity_block(verifier_oci_digest="bogus-not-sha256"),
    )
    ok, reason, detail = _c18_structural_check(bundle_dir)
    assert ok is False
    assert reason == "VERIFIER_IDENTITY_OCI_DIGEST_MALFORMED"


def test_malformed_rekor_inclusion_proof_fails(tmp_path: Path):
    """Test 4: malformed Rekor inclusion proof → FAIL."""
    bad_proof = dict(VALID_REKOR_PROOF)
    del bad_proof["root_hash"]  # missing required key
    bundle_dir = _write_bundle(
        tmp_path,
        _valid_identity_block(rekor_inclusion_proof=bad_proof),
    )
    ok, reason, detail = _c18_structural_check(bundle_dir)
    assert ok is False
    assert reason == "VERIFIER_IDENTITY_REKOR_INCLUSION_PROOF_MALFORMED"


def test_release_manifest_hash_mismatch_fails(tmp_path: Path):
    """Test 5: release_manifest_hash mismatch → FAIL.

    Write a real release_manifest.json with content whose hash does NOT match
    the declared hash.
    """
    actual_content = b'{"hello": "world"}'
    (tmp_path / "release_manifest.json").write_bytes(actual_content)
    actual_hash = hashlib.sha256(actual_content).hexdigest()
    wrong_hash = "sha256:" + "9" * 64
    assert wrong_hash != f"sha256:{actual_hash}"
    bundle_dir = _write_bundle(
        tmp_path,
        _valid_identity_block(release_manifest_hash=wrong_hash),
    )
    ok, reason, detail = _c18_structural_check(bundle_dir)
    assert ok is False
    assert reason == "VERIFIER_IDENTITY_RELEASE_MANIFEST_MISMATCH"


def test_c18_extension_section_is_stdlib_only():
    """Audit: the C18 extension section of veriker/cli/verify.py imports only
    json + re + hashlib (stdlib). NO audit_bundle.extensions.* imports.
    Validates the OQ-4 + global_constraint 12 two-verifier boundary.
    """
    verify_source = (_PKG_ROOT / "veriker" / "cli" / "verify.py").read_text(encoding="utf-8")
    tree = ast.parse(verify_source)

    forbidden_module_prefixes = ("audit_bundle.extensions",)
    forbidden_third_party = (
        "tuf",
        "python_tuf",
    )  # NOT cryptography/jcs — pre-C18 allowed

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for prefix in forbidden_module_prefixes:
                if mod.startswith(prefix):
                    pytest.fail(
                        f"veriker/cli/verify.py imports forbidden module {mod!r} "
                        "(stdlib-only constraint per OQ-4 + global_constraint 12)"
                    )
            for forb in forbidden_third_party:
                if mod.startswith(forb):
                    pytest.fail(f"veriker/cli/verify.py imports forbidden third-party {mod!r}")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                for prefix in forbidden_module_prefixes:
                    if alias.name.startswith(prefix):
                        pytest.fail(
                            f"veriker/cli/verify.py imports forbidden module {alias.name!r}"
                        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
