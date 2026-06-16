"""Regression suite — BundleVerifier._step_spec_sha_pinning offline-copy path safety.

Distinct from tests/test_plugin_path_safety.py, which covers the
``SpecShaPinCheck`` *plugin*. The bug closed here lives in the verifier's
OWN offline-first spec-pinning step (``BundleVerifier._step_spec_sha_pinning``,
audit_bundle/verifier.py), which read ``bundle_dir/spec/<basename>`` directly
and followed symlinks — unlike ``manifest.files``, which routes through
``_safe_bundle_path``.

Codex HIGH finding (2026-06-06): a bundle carrying ``spec/leak.md ->
/etc/hostname`` made the verifier hash ``/etc/hostname`` and echo the
computed SHA back through the failure detail (a hash oracle for any file
the verifier process can read). A directory at that path turned an
artifact problem into ``VerdictState.ERROR`` via ``IsADirectoryError``.

The step uses ``Path(spec_path).name`` (basename only), so ``..``-traversal
in the manifest key is already defused — the live vector is a SYMLINK (or a
directory) physically sitting at ``bundle_dir/spec/<basename>``. The fix
routes the offline copy through ``_safe_bundle_path``: ``.resolve()``
collapses the symlink and rejects the escape; ``is_dir()`` rejects the
directory. This suite pins both so the regression cannot return silently.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

from audit_bundle.bundle_manifest import BundleManifest
from audit_bundle.verifier import BundleVerifier, VerifyFailure


def _manifest_with_spec(spec_basename: str, expected_sha: str) -> BundleManifest:
    return BundleManifest(
        schema_version="legacy",
        bundle_id="b",
        created_at="2026-01-01T00:00:00Z",
        files={},
        spec_files={spec_basename: expected_sha},
        cross_refs={},
        payload={},
        typed_checks=[],
    )


def _run_step(bundle_dir: Path, manifest: BundleManifest) -> list[VerifyFailure]:
    failures: list[VerifyFailure] = []
    # Must not raise — §C9 "verify never raises", collect-don't-propagate.
    BundleVerifier()._step_spec_sha_pinning(
        bundle_dir, manifest, failures, [], sealed=False
    )
    return failures


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink semantics")
def test_offline_symlink_escape_is_rejected_and_leaks_no_hash(tmp_path: Path) -> None:
    """spec/leak.md -> <external file>: structured path_escape failure, and the
    external file's SHA must NOT appear anywhere in the failure detail."""
    spec_dir = tmp_path / "spec"
    spec_dir.mkdir()

    external = tmp_path.parent / "verifier_spec_external_target.txt"
    external.write_text("attacker-visible-marker\n")
    try:
        (spec_dir / "leak.md").symlink_to(external)

        manifest = _manifest_with_spec("leak.md", "ab" * 32)
        failures = _run_step(tmp_path, manifest)

        assert len(failures) == 1, "expected exactly one structured failure"
        f = failures[0]
        assert f.check_name == "spec_sha_pinning"
        assert f.reason_code == "path_escape", (
            f"symlink escape not fail-closed as path_escape: {f.reason_code!r}"
        )
        external_sha = hashlib.sha256(external.read_bytes()).hexdigest()
        assert external_sha not in f.detail, (
            "verifier leaked external-file SHA through spec failure detail "
            "(hash oracle)"
        )
    finally:
        if external.exists():
            external.unlink()


def test_offline_directory_target_does_not_error(tmp_path: Path) -> None:
    """A directory at spec/<basename> must yield a structured path_escape
    failure, not an IsADirectoryError propagating to VerdictState.ERROR."""
    spec_dir = tmp_path / "spec"
    spec_dir.mkdir()
    (spec_dir / "schema.json").mkdir()  # directory where a file is expected

    manifest = _manifest_with_spec("schema.json", "ab" * 32)
    failures = _run_step(tmp_path, manifest)

    assert len(failures) == 1
    assert failures[0].reason_code == "path_escape", (
        f"directory target not fail-closed: {failures[0].reason_code!r}"
    )


def test_offline_legitimate_spec_copy_still_verifies(tmp_path: Path) -> None:
    """Sanity: a normal in-bundle spec/<file> with a matching SHA must still
    pass the offline path (no false positive from the new guard)."""
    spec_dir = tmp_path / "spec"
    spec_dir.mkdir()
    blob = b'{"k": "v"}'
    (spec_dir / "schema.json").write_bytes(blob)
    good_sha = hashlib.sha256(blob).hexdigest()

    manifest = _manifest_with_spec("schema.json", good_sha)
    failures = _run_step(tmp_path, manifest)

    assert failures == [], f"legitimate offline spec copy rejected: {failures}"


def test_offline_legitimate_copy_with_bad_sha_reports_missing_blob(
    tmp_path: Path,
) -> None:
    """An in-bundle spec copy whose bytes don't match the recorded SHA must
    still surface as missing_spec_blob (the SHA-mismatch path), confirming the
    guard didn't swallow the normal failure mode."""
    spec_dir = tmp_path / "spec"
    spec_dir.mkdir()
    (spec_dir / "schema.json").write_bytes(b"different bytes")

    manifest = _manifest_with_spec("schema.json", "ab" * 32)
    failures = _run_step(tmp_path, manifest)

    assert len(failures) == 1
    assert failures[0].reason_code == "missing_spec_blob"
