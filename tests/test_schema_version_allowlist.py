"""BLOCK-03 regression — unknown manifest schema versions must NEVER verify green.

schema_version is the contract boundary for verifier semantics: it selects
DSSE-cutover behavior, reserved-field handling, and versioned audit semantics,
and ``is_post_cutover`` is total over unknown tags (returns False) — so an
un-allowlisted version would not merely verify under wrong semantics, it would
ride the weaker PRE-cutover lane.

The allowlist gate historically lived only in ``validate_manifest()``'s shallow
step 1. The ef9a197 fail-closed refactor moved the CLI off validate_manifest()
onto ``BundleVerifier.verify()`` ("verify() subsumes the deep validators") —
but verify()'s parse boundary never replicated the SHALLOW schema check, so a
bundle with ``schema_version: "evil-future-schema"`` and otherwise-valid hashes
verified OK through BOTH the library and the CLI (ChatGPT BLOCK-03, reproduced
2026-06-11). The fix is one shared helper (``validate_schema_version``) called
by validate_manifest() AND the verifier's raw-parse boundary
(``_validate_manifest_shape``), so the two paths cannot drift again.

These tests pin BOTH entry points and all four input classes (unknown / empty /
absent / known).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from audit_bundle.bundle_manifest import SchemaVersionError, validate_schema_version
from audit_bundle.verdict import VerdictState
from audit_bundle.verifier import BundleVerifier

_PKG_ROOT = Path(__file__).resolve().parent.parent


def _build_bundle(tmp_path: Path, schema_version: str | None) -> Path:
    """Minimal otherwise-green bundle; schema_version=None omits the field."""
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    data = b"hello world\n"
    (bundle_dir / "data.txt").write_bytes(data)
    manifest: dict = {
        "bundle_id": "schema-allowlist-test",
        "files": {"data.txt": hashlib.sha256(data).hexdigest()},
        "spec_files": {},
        "cross_refs": {},
        "typed_checks": [],
    }
    if schema_version is not None:
        manifest["schema_version"] = schema_version
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return bundle_dir


# ---------------------------------------------------------------------------
# Library entry point — BundleVerifier.verify()
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_version",
    ["evil-future-schema", "", "vcp-v9.9", "LEGACY"],  # case-sensitive allowlist
)
def test_unknown_schema_version_rejects_via_library(
    tmp_path: Path, bad_version: str
) -> None:
    verdict = BundleVerifier().verify(_build_bundle(tmp_path, bad_version))
    assert not verdict.ok
    assert verdict.state is VerdictState.REJECT
    assert any(r.reason_code == "schema_version" for r in verdict.reasons), [
        (r.reason_code, r.detail) for r in verdict.reasons
    ]


def test_absent_schema_version_defaults_to_legacy_and_passes(tmp_path: Path) -> None:
    """Absent ⇒ the constructor's 'legacy' default — the SAME semantics
    validate_manifest() has always applied to the constructed dataclass. The
    parse-boundary gate validates the defaulted value, so this stays accepted
    (no behavior change for legacy bundles) while EMPTY-STRING stays rejected."""
    verdict = BundleVerifier().verify(_build_bundle(tmp_path, None))
    assert verdict.ok, [(r.reason_code, r.detail) for r in verdict.reasons]


@pytest.mark.parametrize(
    "good_version", ["vcp-v1.1-canary4", "vcp-v1.1", "legacy", "vcp-v1.2-dsse"]
)
def test_known_schema_versions_still_accepted(
    tmp_path: Path, good_version: str
) -> None:
    verdict = BundleVerifier().verify(_build_bundle(tmp_path, good_version))
    # vcp-v1.2-dsse routes down the sealed/post-cutover lane and may require
    # gate inputs this minimal bundle lacks — the pinned property here is only
    # that the schema allowlist itself does not reject a known version.
    assert not any(r.reason_code == "schema_version" for r in verdict.reasons), [
        (r.reason_code, r.detail) for r in verdict.reasons
    ]


# ---------------------------------------------------------------------------
# Shared helper — single definition both paths consume
# ---------------------------------------------------------------------------


def test_helper_rejects_non_string_values() -> None:
    for bad in (None, 42, ["vcp-v1.1"], {"v": 1}):
        with pytest.raises(SchemaVersionError):
            validate_schema_version(bad)


# ---------------------------------------------------------------------------
# CLI entry point — veriker/cli/verify.py must exit non-zero
# ---------------------------------------------------------------------------


def test_unknown_schema_version_cli_exits_nonzero(tmp_path: Path) -> None:
    bundle_dir = _build_bundle(tmp_path, "evil-future-schema")
    proc = subprocess.run(
        [
            sys.executable,
            str(_PKG_ROOT / "veriker" / "cli" / "verify.py"),
            "--bundle-dir",
            str(bundle_dir),
        ],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
        env={**os.environ, "PYTHONPATH": str(_PKG_ROOT)},
    )
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "SchemaVersionError" in (proc.stdout + proc.stderr)
