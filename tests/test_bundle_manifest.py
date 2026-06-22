"""Tests for audit_bundle.bundle_manifest — schema validation and tamper detection."""

from __future__ import annotations

import dataclasses
import hashlib
from pathlib import Path

import pytest

from audit_bundle.bundle_manifest import (
    BundleManifest,
    CrossRefBroken,
    FileSHAMismatch,
    ManifestError,
    SchemaVersionError,
    SpecSHAMissing,
    TypedCheckUnregistered,
    _TYPED_CHECK_REGISTRY,
    register_typed_check,
    validate_manifest,
)


# ---------------------------------------------------------------------------
# Registry isolation — snapshot/restore around each test
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_registry():
    snapshot = frozenset(_TYPED_CHECK_REGISTRY)
    yield
    _TYPED_CHECK_REGISTRY.clear()
    _TYPED_CHECK_REGISTRY.update(snapshot)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _make_file(tmp_path: Path, name: str, content: bytes) -> tuple[str, str]:
    """Write file under tmp_path; return (relative_name, sha256_hex)."""
    (tmp_path / name).write_bytes(content)
    return name, _sha256(content)


def _make_valid_manifest(tmp_path: Path) -> BundleManifest:
    """Build a BundleManifest with real on-disk file (no typed_checks)."""
    rel, sha = _make_file(tmp_path, "output.json", b'{"ok": true}')
    return BundleManifest(
        schema_version="vcp-v1.1-canary4",
        bundle_id="test-bundle-001",
        created_at="2026-04-30T00:00:00Z",
        files={rel: sha},
        spec_files={"spec/vcp.md": "deadbeef" * 8},
        cross_refs={"main_output": rel},
        payload={"result": rel},
        typed_checks=[],
    )


# ---------------------------------------------------------------------------
# Happy-path tests
# ---------------------------------------------------------------------------


def test_valid_manifest_passes(tmp_path: Path) -> None:
    m = _make_valid_manifest(tmp_path)
    validate_manifest(m, tmp_path)  # must not raise


def test_legacy_schema_version_passes(tmp_path: Path) -> None:
    m = _make_valid_manifest(tmp_path)
    m2 = dataclasses.replace(m, schema_version="legacy")
    validate_manifest(m2, tmp_path)


def test_empty_optional_sections_pass(tmp_path: Path) -> None:
    """Empty files / spec_files / cross_refs / typed_checks are all valid."""
    m = BundleManifest(
        schema_version="vcp-v1.1-canary4",
        bundle_id="empty-bundle",
        created_at="2026-04-30T00:00:00Z",
        files={},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
    )
    validate_manifest(m, tmp_path)


def test_registered_typed_check_passes(tmp_path: Path) -> None:
    register_typed_check("sha-chain-v1")
    m = _make_valid_manifest(tmp_path)
    m2 = dataclasses.replace(m, typed_checks=["sha-chain-v1"])
    validate_manifest(m2, tmp_path)


# ---------------------------------------------------------------------------
# Tamper — SchemaVersionError
# ---------------------------------------------------------------------------


def test_schema_version_wrong_raises(tmp_path: Path) -> None:
    m = _make_valid_manifest(tmp_path)
    bad = dataclasses.replace(m, schema_version="bad-version-99")
    with pytest.raises(SchemaVersionError):
        validate_manifest(bad, tmp_path)


def test_schema_version_empty_raises(tmp_path: Path) -> None:
    m = _make_valid_manifest(tmp_path)
    bad = dataclasses.replace(m, schema_version="")
    with pytest.raises(SchemaVersionError):
        validate_manifest(bad, tmp_path)


def test_schema_version_error_is_manifest_error(tmp_path: Path) -> None:
    m = dataclasses.replace(_make_valid_manifest(tmp_path), schema_version="nope")
    with pytest.raises(ManifestError):
        validate_manifest(m, tmp_path)


# ---------------------------------------------------------------------------
# Tamper — FileSHAMismatch
# ---------------------------------------------------------------------------


def test_file_sha_wrong_hash_raises(tmp_path: Path) -> None:
    m = _make_valid_manifest(tmp_path)
    tampered = {k: "0" * 64 for k in m.files}
    bad = dataclasses.replace(m, files=tampered)
    with pytest.raises(FileSHAMismatch):
        validate_manifest(bad, tmp_path)


def test_file_missing_from_disk_raises(tmp_path: Path) -> None:
    """Referencing a file that does not exist on disk → FileSHAMismatch."""
    m = _make_valid_manifest(tmp_path)
    bad = dataclasses.replace(
        m,
        files={"ghost/nonexistent.json": "a" * 64},
        cross_refs={},
    )
    with pytest.raises(FileSHAMismatch):
        validate_manifest(bad, tmp_path)


def test_file_sha_mismatch_is_manifest_error(tmp_path: Path) -> None:
    m = _make_valid_manifest(tmp_path)
    bad = dataclasses.replace(m, files={k: "f" * 64 for k in m.files})
    with pytest.raises(ManifestError):
        validate_manifest(bad, tmp_path)


def test_multiple_files_second_tampered(tmp_path: Path) -> None:
    """First file is valid; second has wrong SHA — should still raise FileSHAMismatch."""
    rel1, sha1 = _make_file(tmp_path, "a.txt", b"aaaaa")
    rel2, _ = _make_file(tmp_path, "b.txt", b"bbbbb")
    m = BundleManifest(
        schema_version="vcp-v1.1-canary4",
        bundle_id="multi",
        created_at="2026-04-30T00:00:00Z",
        files={rel1: sha1, rel2: "0" * 64},  # rel2 SHA is wrong
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
    )
    with pytest.raises(FileSHAMismatch):
        validate_manifest(m, tmp_path)


# ---------------------------------------------------------------------------
# Tamper — SpecSHAMissing
# ---------------------------------------------------------------------------


def test_spec_sha_empty_raises(tmp_path: Path) -> None:
    m = _make_valid_manifest(tmp_path)
    bad = dataclasses.replace(m, spec_files={"spec/vcp.md": ""})
    with pytest.raises(SpecSHAMissing):
        validate_manifest(bad, tmp_path)


def test_spec_sha_missing_is_manifest_error(tmp_path: Path) -> None:
    m = _make_valid_manifest(tmp_path)
    bad = dataclasses.replace(m, spec_files={"spec/vcp.md": ""})
    with pytest.raises(ManifestError):
        validate_manifest(bad, tmp_path)


def test_spec_sha_non_empty_passes(tmp_path: Path) -> None:
    m = _make_valid_manifest(tmp_path)
    good = dataclasses.replace(m, spec_files={"spec/vcp.md": "nonempty-sha"})
    validate_manifest(good, tmp_path)


# ---------------------------------------------------------------------------
# Tamper — CrossRefBroken
# ---------------------------------------------------------------------------


def test_cross_ref_target_not_in_files_or_spec_raises(tmp_path: Path) -> None:
    m = _make_valid_manifest(tmp_path)
    bad = dataclasses.replace(m, cross_refs={"main": "nonexistent/path.json"})
    with pytest.raises(CrossRefBroken):
        validate_manifest(bad, tmp_path)


def test_cross_ref_resolves_to_spec_files_passes(tmp_path: Path) -> None:
    m = _make_valid_manifest(tmp_path)
    good = dataclasses.replace(
        m,
        cross_refs={"spec_ref": "spec/vcp.md"},  # key in spec_files
    )
    validate_manifest(good, tmp_path)


def test_cross_ref_broken_is_manifest_error(tmp_path: Path) -> None:
    m = _make_valid_manifest(tmp_path)
    bad = dataclasses.replace(m, cross_refs={"x": "does/not/exist"})
    with pytest.raises(ManifestError):
        validate_manifest(bad, tmp_path)


# ---------------------------------------------------------------------------
# Tamper — TypedCheckUnregistered
# ---------------------------------------------------------------------------


def test_unregistered_typed_check_raises(tmp_path: Path) -> None:
    m = _make_valid_manifest(tmp_path)
    bad = dataclasses.replace(m, typed_checks=["__not_registered_ever__"])
    with pytest.raises(TypedCheckUnregistered):
        validate_manifest(bad, tmp_path)


def test_typed_check_unregistered_is_manifest_error(tmp_path: Path) -> None:
    m = _make_valid_manifest(tmp_path)
    bad = dataclasses.replace(m, typed_checks=["__unknown__"])
    with pytest.raises(ManifestError):
        validate_manifest(bad, tmp_path)


def test_partially_registered_typed_checks_raises(tmp_path: Path) -> None:
    """First check registered, second not — should still raise."""
    register_typed_check("registered-check")
    m = _make_valid_manifest(tmp_path)
    bad = dataclasses.replace(m, typed_checks=["registered-check", "__missing__"])
    with pytest.raises(TypedCheckUnregistered):
        validate_manifest(bad, tmp_path)
