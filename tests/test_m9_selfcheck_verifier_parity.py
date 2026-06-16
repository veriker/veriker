"""tests/test_m9_selfcheck_verifier_parity.py — M9: producer self-check IS the verifier.

Redteam finding M9
------------------
write_bundle(validate=True) ran validate_manifest() — a parallel shallow
orchestration of "the same" checks the verifier runs differently:

  * its file loop had no typed-check/plugin/append-only skip set (the
    verifier's _step_file_integrity has one),
  * its spec_files check was presence-only (the verifier hashes the blob),
  * its typed_checks check was registration-only (the verifier executes
    plugins),
  * it never saw surplus on-disk files or the DSSE seal at all.

So "emitter says green" and "verifier says green" could diverge on the same
bundle in both directions. The fix kills the parallel orchestration: the
self-check now runs BundleVerifier.verify() with the CLI's default plugin
set (veriker.cli.verify._build_plugins) — one code path, drift impossible by
construction — and raises BundleSelfCheckFailed on any non-OK verdict.

Unifying also surfaced (and fixed) a live drift instance: the
file_integrity_many_small Pass-3 surplus sweep skipped manifest.json but not
bundle.dsse.json, so the CLI plugin set rejected every sealed bundle even
though the seam spec defines BOTH as structural envelope files
(_SEAM_EXCLUDED) that cannot appear in manifest.files.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit_bundle.emitter.pipeline import (
    BundleContent,
    BundleSelfCheckFailed,
    _self_check,
    write_bundle,
)
from audit_bundle.conservation import run_conservation
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.verifier import _load_manifest


def _bound_check(bundle_dir, manifest):
    """Direct Pass-3 probe: bind the conservation result the D5 shim consumes
    (verify()'s orchestration in miniature; an unbound check() hard-errors)."""
    plugin = FileIntegrityManySmall()
    plugin.bind_conservation(
        run_conservation(
            bundle_dir,
            manifest,
            frozenset(),
            sealed=(bundle_dir / "bundle.dsse.json").exists(),
        )
    )
    return plugin.check(bundle_dir, manifest)


def _content() -> BundleContent:
    return BundleContent(
        bundle_id="m9-parity",
        created_at="2026-06-10T00:00:00Z",
        files={"data/x.txt": b"hello m9"},
    )


# ---------------------------------------------------------------------------
# Clean bundles pass the self-check
# ---------------------------------------------------------------------------


def test_clean_unsealed_bundle_validates(tmp_path):
    write_bundle(tmp_path / "b", _content(), validate=True)  # must not raise


def test_clean_sealed_bundle_validates(tmp_path):
    """The seal itself is now part of the self-check (verified vs the key just used)."""
    write_bundle(
        tmp_path / "b",
        _content(),
        validate=True,
        dsse_signing_key=Ed25519PrivateKey.generate(),
    )  # must not raise


# ---------------------------------------------------------------------------
# Verifier-red bundles now fail the self-check too
# ---------------------------------------------------------------------------


def test_tampered_file_fails_self_check(tmp_path):
    bundle_dir = tmp_path / "b"
    write_bundle(bundle_dir, _content(), validate=True)
    (bundle_dir / "data" / "x.txt").write_bytes(b"tampered")
    with pytest.raises(BundleSelfCheckFailed, match="bad_file_sha"):
        _self_check(bundle_dir, None)


def test_surplus_file_fails_self_check(tmp_path):
    """Divergence class the old walk was BLIND to: validate_manifest only
    iterated manifest.files, so an unlisted on-disk file was emitter-green
    while the verifier's plugin sweep rejects it."""
    bundle_dir = tmp_path / "b"
    write_bundle(bundle_dir, _content(), validate=True)
    (bundle_dir / "data" / "sneaky.txt").write_bytes(b"unlisted")
    with pytest.raises(BundleSelfCheckFailed, match="absent from manifest.files"):
        _self_check(bundle_dir, None)


def test_sealed_manifest_rewrite_fails_self_check(tmp_path):
    """Second blind spot killed: re-serialise manifest.json with different
    whitespace. Every per-file hash still matches, so the OLD
    validate_manifest walk stayed green — but the DSSE payload binding
    (sha256 of manifest BYTES) breaks. The self-check must agree with the
    verifier and reject."""
    bundle_dir = tmp_path / "b"
    key = Ed25519PrivateKey.generate()
    write_bundle(bundle_dir, _content(), validate=True, dsse_signing_key=key)

    manifest_path = bundle_dir / "manifest.json"
    manifest_dict = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_path.write_text(json.dumps(manifest_dict, indent=2), encoding="utf-8")

    with pytest.raises(BundleSelfCheckFailed, match="DSSE_PAYLOAD_BINDING_MISMATCH"):
        _self_check(bundle_dir, key)


# ---------------------------------------------------------------------------
# The drift instance the unification surfaced: sidecar vs Pass-3 sweep
# ---------------------------------------------------------------------------


def test_sidecar_not_flagged_as_extra_file(tmp_path):
    """bundle.dsse.json is a structural envelope file (seam spec): the Pass-3
    surplus sweep must skip it exactly like manifest.json. Before the fix,
    the CLI's default plugin set rejected every sealed bundle."""
    bundle_dir = tmp_path / "b"
    write_bundle(
        bundle_dir,
        _content(),
        dsse_signing_key=Ed25519PrivateKey.generate(),
    )
    assert (bundle_dir / "bundle.dsse.json").exists()
    result = _bound_check(bundle_dir, _load_manifest(bundle_dir))
    assert result.ok, f"sealed bundle flagged: {result.reason_code} {result.detail}"


def test_genuine_extra_file_still_flagged(tmp_path):
    """The envelope-file skip must not weaken the sweep for anything else."""
    bundle_dir = tmp_path / "b"
    write_bundle(bundle_dir, _content())
    (bundle_dir / "data" / "extra.bin").write_bytes(b"x")
    result = _bound_check(bundle_dir, _load_manifest(bundle_dir))
    assert not result.ok
    assert result.reason_code == "EXTRA_FILE_NOT_IN_MANIFEST"
