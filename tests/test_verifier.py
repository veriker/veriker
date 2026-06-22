"""Tests for audit_bundle.verifier — BundleVerifier against valid and tampered bundles.

Attack vectors exercised (§C9: no generic 'tampered' fallback; each failure
carries a specific check_name and reason_code):

  tampered_file          file_integrity    / bad_file_sha        SHA mismatch
  tampered_spec_subst    spec_sha_pinning  / missing_spec_blob   wrong spec SHA
  tampered_cross_ref     cross_refs        / broken_cross_ref    unreachable target
  tampered_silent_drop   file_integrity    / bad_file_sha        file deleted silently
  tampered_sum_invariant typed_check_plugins / plugin_failed     xfail (vab-021/022)
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from audit_bundle.verifier import BundleVerifier, VerifyResult
from tests.fixtures._generate_canary4 import (
    CanaryBundle,
    build_canary4_bundle,
    make_tampered_cross_ref_manifest,
    make_tampered_file_manifest,
    make_tampered_silent_drop_manifest,
    make_tampered_spec_substitution_manifest,
    make_tampered_sum_invariant_manifest,
)


# ---------------------------------------------------------------------------
# Session-scoped git repo + bundle
# ---------------------------------------------------------------------------


def _git(args: list[str], cwd: Path) -> None:
    subprocess.run(["git"] + args, cwd=str(cwd), check=True, capture_output=True)


@pytest.fixture(scope="session")
def git_repo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Throwaway git repository; spec doc committed here for blob-resolver fallback."""
    repo = tmp_path_factory.mktemp("canary4_git")
    _git(["init"], repo)
    _git(["config", "user.email", "ci@test.local"], repo)
    _git(["config", "user.name", "CI Test"], repo)
    return repo


@pytest.fixture(scope="session")
def canary4(tmp_path_factory: pytest.TempPathFactory, git_repo: Path) -> CanaryBundle:
    """Valid canary4 bundle built once per test session."""
    dest = tmp_path_factory.mktemp("canary4_bundle")
    return build_canary4_bundle(dest, git_repo=git_repo)


# ---------------------------------------------------------------------------
# Helper: clone valid bundle and inject tampered manifest / disk mutations
# ---------------------------------------------------------------------------


def _tampered_bundle(
    tmp_path: Path,
    canary4: CanaryBundle,
    manifest_override: dict,
    *,
    delete_file: str | None = None,
) -> Path:
    """Copy the valid bundle to tmp_path, swap manifest.json, optionally delete a file."""
    bundle_dir = tmp_path / "bundle"
    shutil.copytree(canary4.bundle_dir, bundle_dir)
    (bundle_dir / "manifest.json").write_text(
        json.dumps(manifest_override, indent=2), encoding="utf-8"
    )
    if delete_file is not None:
        (bundle_dir / delete_file).unlink()
    return bundle_dir


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_verifier_passes_on_valid(canary4: CanaryBundle) -> None:
    """BundleVerifier.verify() returns ok=True and an empty failures list for a clean bundle."""
    result: VerifyResult = BundleVerifier().verify(canary4.bundle_dir)
    assert result.ok is True
    assert result.failures == []


# ---------------------------------------------------------------------------
# Attack vector 1 — tampered file (SHA mismatch)
# ---------------------------------------------------------------------------


def test_tampered_file_returns_ok_false(tmp_path: Path, canary4: CanaryBundle) -> None:
    """Stale SHA in manifest.files is detected; verifier must not return ok=True."""
    bundle_dir = _tampered_bundle(
        tmp_path, canary4, make_tampered_file_manifest(canary4)
    )
    result = BundleVerifier().verify(bundle_dir)
    assert result.ok is False


def test_tampered_file_check_name(tmp_path: Path, canary4: CanaryBundle) -> None:
    """Failure is attributed to file_integrity, not a generic check."""
    bundle_dir = _tampered_bundle(
        tmp_path, canary4, make_tampered_file_manifest(canary4)
    )
    result = BundleVerifier().verify(bundle_dir)
    check_names = {f.check_name for f in result.failures}
    assert "file_integrity" in check_names, (
        f"expected 'file_integrity' in check_names; got {check_names}"
    )


def test_tampered_file_reason_code(tmp_path: Path, canary4: CanaryBundle) -> None:
    """Reason code must be 'bad_file_sha', not a catch-all (§C9)."""
    bundle_dir = _tampered_bundle(
        tmp_path, canary4, make_tampered_file_manifest(canary4)
    )
    result = BundleVerifier().verify(bundle_dir)
    reason_codes = {f.reason_code for f in result.failures}
    assert "bad_file_sha" in reason_codes, (
        f"expected 'bad_file_sha' in reason_codes; got {reason_codes}"
    )


# ---------------------------------------------------------------------------
# Attack vector 2 — spec SHA substitution
# ---------------------------------------------------------------------------


def test_tampered_spec_substitution_returns_ok_false(
    tmp_path: Path, canary4: CanaryBundle
) -> None:
    """Wrong SHA in manifest.spec_files is detected."""
    bundle_dir = _tampered_bundle(
        tmp_path, canary4, make_tampered_spec_substitution_manifest(canary4)
    )
    result = BundleVerifier().verify(bundle_dir)
    assert result.ok is False


def test_tampered_spec_substitution_check_name(
    tmp_path: Path, canary4: CanaryBundle
) -> None:
    """Failure is attributed to spec_sha_pinning."""
    bundle_dir = _tampered_bundle(
        tmp_path, canary4, make_tampered_spec_substitution_manifest(canary4)
    )
    result = BundleVerifier().verify(bundle_dir)
    check_names = {f.check_name for f in result.failures}
    assert "spec_sha_pinning" in check_names, (
        f"expected 'spec_sha_pinning' in check_names; got {check_names}"
    )


def test_tampered_spec_substitution_reason_code(
    tmp_path: Path, canary4: CanaryBundle
) -> None:
    """Reason code must be 'missing_spec_blob' (§C9)."""
    bundle_dir = _tampered_bundle(
        tmp_path, canary4, make_tampered_spec_substitution_manifest(canary4)
    )
    result = BundleVerifier().verify(bundle_dir)
    reason_codes = {f.reason_code for f in result.failures}
    assert "missing_spec_blob" in reason_codes, (
        f"expected 'missing_spec_blob' in reason_codes; got {reason_codes}"
    )


# ---------------------------------------------------------------------------
# Attack vector 3 — broken cross-reference
# ---------------------------------------------------------------------------


def test_tampered_cross_ref_returns_ok_false(
    tmp_path: Path, canary4: CanaryBundle
) -> None:
    """Unreachable cross_refs target is detected."""
    bundle_dir = _tampered_bundle(
        tmp_path, canary4, make_tampered_cross_ref_manifest(canary4)
    )
    result = BundleVerifier().verify(bundle_dir)
    assert result.ok is False


def test_tampered_cross_ref_check_name(tmp_path: Path, canary4: CanaryBundle) -> None:
    """Failure is attributed to cross_refs."""
    bundle_dir = _tampered_bundle(
        tmp_path, canary4, make_tampered_cross_ref_manifest(canary4)
    )
    result = BundleVerifier().verify(bundle_dir)
    check_names = {f.check_name for f in result.failures}
    assert "cross_refs" in check_names, (
        f"expected 'cross_refs' in check_names; got {check_names}"
    )


def test_tampered_cross_ref_reason_code(tmp_path: Path, canary4: CanaryBundle) -> None:
    """Reason code must be 'broken_cross_ref' (§C9)."""
    bundle_dir = _tampered_bundle(
        tmp_path, canary4, make_tampered_cross_ref_manifest(canary4)
    )
    result = BundleVerifier().verify(bundle_dir)
    reason_codes = {f.reason_code for f in result.failures}
    assert "broken_cross_ref" in reason_codes, (
        f"expected 'broken_cross_ref' in reason_codes; got {reason_codes}"
    )


# ---------------------------------------------------------------------------
# Attack vector 4 — silent file drop
# ---------------------------------------------------------------------------


def test_tampered_silent_drop_returns_ok_false(
    tmp_path: Path, canary4: CanaryBundle
) -> None:
    """File listed in manifest but absent from disk is detected."""
    bundle_dir = _tampered_bundle(
        tmp_path,
        canary4,
        make_tampered_silent_drop_manifest(canary4),
        delete_file="payload/output.txt",
    )
    result = BundleVerifier().verify(bundle_dir)
    assert result.ok is False


def test_tampered_silent_drop_check_name(tmp_path: Path, canary4: CanaryBundle) -> None:
    """Missing-file failure is attributed to file_integrity."""
    bundle_dir = _tampered_bundle(
        tmp_path,
        canary4,
        make_tampered_silent_drop_manifest(canary4),
        delete_file="payload/output.txt",
    )
    result = BundleVerifier().verify(bundle_dir)
    check_names = {f.check_name for f in result.failures}
    assert "file_integrity" in check_names, (
        f"expected 'file_integrity' in check_names; got {check_names}"
    )


def test_tampered_silent_drop_reason_code(tmp_path: Path, canary4: CanaryBundle) -> None:
    """Reason code must be 'bad_file_sha' for a missing file (§C9)."""
    bundle_dir = _tampered_bundle(
        tmp_path,
        canary4,
        make_tampered_silent_drop_manifest(canary4),
        delete_file="payload/output.txt",
    )
    result = BundleVerifier().verify(bundle_dir)
    reason_codes = {f.reason_code for f in result.failures}
    assert "bad_file_sha" in reason_codes, (
        f"expected 'bad_file_sha' in reason_codes; got {reason_codes}"
    )


# ---------------------------------------------------------------------------
# Attack vector 5 — coverage sum-invariant violation (CC2 cross-check)
# ---------------------------------------------------------------------------


def test_tampered_sum_invariant_returns_ok_false(
    tmp_path: Path, canary4: CanaryBundle
) -> None:
    """Coverage n_eligible != n_issued + n_withheld must be detected as a failure.

    The manifest claims typed_checks=['coverage-sum-v1'] but no such plugin
    instance is in BundleVerifier._plugins. The CC2 cross-check in
    _step_typed_check_plugins emits plugin_failed for any name in
    manifest.typed_checks without a matching instance, so result.ok is False.
    """
    bundle_dir = _tampered_bundle(
        tmp_path, canary4, make_tampered_sum_invariant_manifest(canary4)
    )
    result = BundleVerifier().verify(bundle_dir)
    assert result.ok is False
    check_names = {f.check_name for f in result.failures}
    reason_codes = {f.reason_code for f in result.failures}
    assert "typed_check_plugins:coverage-sum-v1" in check_names, (
        f"expected coverage plugin check_name; got {check_names}"
    )
    assert "plugin_failed" in reason_codes, (
        f"expected 'plugin_failed' in reason_codes; got {reason_codes}"
    )


# ---------------------------------------------------------------------------
# Consolidated parametrised view (matches task description: test_verifier_fails_specific_messages)
# ---------------------------------------------------------------------------

_TAMPERED_CASES = [
    pytest.param(
        "file",
        "file_integrity",
        "bad_file_sha",
        None,
        id="tampered_file",
    ),
    pytest.param(
        "spec_substitution",
        "spec_sha_pinning",
        "missing_spec_blob",
        None,
        id="tampered_spec_substitution",
    ),
    pytest.param(
        "cross_ref",
        "cross_refs",
        "broken_cross_ref",
        None,
        id="tampered_cross_ref",
    ),
    pytest.param(
        "silent_drop",
        "file_integrity",
        "bad_file_sha",
        "payload/output.txt",
        id="tampered_silent_drop",
    ),
]

_MANIFEST_BUILDERS = {
    "file": make_tampered_file_manifest,
    "spec_substitution": make_tampered_spec_substitution_manifest,
    "cross_ref": make_tampered_cross_ref_manifest,
    "silent_drop": make_tampered_silent_drop_manifest,
}


@pytest.mark.parametrize(
    "variant,expected_check_name,expected_reason_code,delete_file",
    _TAMPERED_CASES,
)
def test_verifier_fails_specific_messages(
    tmp_path: Path,
    canary4: CanaryBundle,
    variant: str,
    expected_check_name: str,
    expected_reason_code: str,
    delete_file: str | None,
) -> None:
    """Each tampered bundle returns ok=False with EXACT check_name + reason_code (§C9).

    No generic 'tampered' fallback is permitted; every failure path must be
    attributed to a named step with a specific reason code.
    """
    builder = _MANIFEST_BUILDERS[variant]
    bundle_dir = _tampered_bundle(
        tmp_path,
        canary4,
        builder(canary4),
        delete_file=delete_file,
    )
    result: VerifyResult = BundleVerifier().verify(bundle_dir)

    assert result.ok is False, (
        f"[{variant}] expected ok=False but verifier returned ok=True; "
        f"failures={result.failures}"
    )
    check_names = {f.check_name for f in result.failures}
    reason_codes = {f.reason_code for f in result.failures}
    assert expected_check_name in check_names, (
        f"[{variant}] expected check_name={expected_check_name!r}; got {check_names}"
    )
    assert expected_reason_code in reason_codes, (
        f"[{variant}] expected reason_code={expected_reason_code!r}; got {reason_codes}"
    )
