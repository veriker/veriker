"""tests/test_conservation_gate.py — the core file-space conservation gate.

The gate (audit_bundle/conservation.py, wired unconditionally into
``BundleVerifier.verify()``) closes the unsealed-library conservation gap: a
library consumer calling ``BundleVerifier(plugins=()).verify()`` on a
sidecar-absent bundle previously got NO surplus sweep at all, so UNOWNED
on-disk files rode a green verdict. Covered here:

  * plugin-less verify() REJECTS a surplus file (the headline integration);
  * all three ENVELOPE lanes: sealed (DSSE gate IS the envelope checker),
    sidecar-present-unsealed (fail-closed pre-gate reject — conservation is
    honestly never reached), sidecar-absent (parse-validated residual
    DISCLOSED on the verdict face, never silently passed);
  * the auditor fs_ignore view: construction-time only, default empty,
    exact-path/anchored-glob validation, never matches a declared/ENVELOPE
    path (verdict ERROR on conflict — artifact not proven bad), ignored paths
    reported verbosely, sealed bundles ignore NOTHING;
  * non-regular objects (FIFO) fail closed BEFORE any content step — even
    when declared (as-built, a declared FIFO would hang the strict-SHA
    read_bytes; the gate rejects first);
  * symlink semantics: an undeclared in-tree symlink is UNOWNED (rejected),
    a declared in-tree symlink stays owned by its declared class (as-built
    tolerance — strict-SHA resolves it under containment);
  * the D5 Pass-3 shim fails closed (hard error) without a bound
    conservation result, and on a stale/cross-bundle binding.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from audit_bundle.conservation import (
    VERIFIER_FS_IGNORE_CONFLICT,
    run_conservation,
    validate_fs_ignore_patterns,
)
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.plugins.pass3_conservation_shim import ConservationResultAbsent
from audit_bundle.verdict import VerdictState
from audit_bundle.verifier import BundleVerifier, _load_manifest


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_unsealed_bundle(bundle_dir: Path, *, extra: dict | None = None) -> None:
    """Minimal pre-cutover (sidecar-absent) bundle: one declared file."""
    bundle_dir.mkdir(parents=True, exist_ok=True)
    data = b"conservation gate payload"
    (bundle_dir / "data.txt").write_bytes(data)
    manifest = {
        "schema_version": "vcp-v1.1-canary4",
        "bundle_id": "conservation-gate-test",
        "created_at": "2026-06-10T00:00:00Z",
        "files": {"data.txt": _sha(data)},
        "spec_files": {},
        "cross_refs": {},
    }
    if extra:
        manifest.update(extra)
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def _sealed_bundle(tmp_path: Path):
    """One sealed bundle + its signing key (emitter-produced, gate-green)."""
    from audit_bundle.emitter.pipeline import BundleContent, write_bundle
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    bundle_dir = tmp_path / "sealed"
    write_bundle(
        bundle_dir,
        BundleContent(
            bundle_id="conservation-sealed",
            created_at="2026-06-10T00:00:00Z",
            files={"data/x.txt": b"sealed conservation data"},
        ),
        dsse_signing_key=key,
    )
    return bundle_dir, key


def _dsse_ctx_for(key):
    import time

    from audit_bundle.dsse.pae import kid_from_raw32
    from audit_bundle.revocation import RevocationList

    pub_raw32 = key.public_key().public_bytes_raw()
    now = int(time.time())
    return SimpleNamespace(
        allowlist={kid_from_raw32(pub_raw32): pub_raw32},
        verifier_now=now,
        revocation_list=RevocationList(
            entries={}, issued_at=now, expires=now + 3600, revocation_list_hash=""
        ),
        require_dsse=True,
        allow_legacy=False,
    )


# ---------------------------------------------------------------------------
# The headline: plugin-less verify() rejects surplus (D5 rider / §4.2 gap)
# ---------------------------------------------------------------------------


def test_pluginless_verify_rejects_surplus_file(tmp_path):
    bundle_dir = tmp_path / "b"
    _write_unsealed_bundle(bundle_dir)
    (bundle_dir / "stray.bin").write_bytes(b"unattested")

    verdict = BundleVerifier(plugins=()).verify(bundle_dir)

    assert not verdict.ok
    assert any(
        f.check_name == "conservation"
        and f.reason_code == "EXTRA_FILE_NOT_IN_MANIFEST"
        and "'stray.bin'" in f.detail
        for f in verdict.failures
    )


def test_pluginless_verify_clean_bundle_green_with_conservation_layer(tmp_path):
    bundle_dir = tmp_path / "b"
    _write_unsealed_bundle(bundle_dir)

    verdict = BundleVerifier(plugins=()).verify(bundle_dir)

    assert verdict.ok, [(f.reason_code, f.detail) for f in verdict.failures]
    assert "conservation" in verdict.completeness.layers


def test_deep_undeclared_scaffold_is_surplus_to_pluginless_verify(tmp_path):
    """D4 alignment: the scaffold allowance is TOP-LEVEL only, and the core
    gate enforces the same classification the Pass-3 sweep does."""
    bundle_dir = tmp_path / "b"
    _write_unsealed_bundle(bundle_dir)
    (bundle_dir / "deep" / "dir").mkdir(parents=True)
    (bundle_dir / "deep" / "dir" / "README.md").write_bytes(b"# deep")
    (bundle_dir / "README.md").write_bytes(b"# top-level tolerated")

    verdict = BundleVerifier(plugins=()).verify(bundle_dir)

    assert not verdict.ok
    assert any("'deep/dir/README.md'" in f.detail for f in verdict.failures)
    # the top-level scaffold rides the allowance (not among the failures)
    assert not any("'README.md'" in f.detail for f in verdict.failures)


# ---------------------------------------------------------------------------
# ENVELOPE per-lane semantics (§C9.2 / panel finding №1)
# ---------------------------------------------------------------------------


def test_envelope_lane_sealed_dsse_gate_is_the_checker(tmp_path):
    """Sealed lane: reaching conservation means the DSSE gate ran and passed
    — the envelope files are claimed with no unsealed residual disclosed."""
    bundle_dir, key = _sealed_bundle(tmp_path)

    verdict = BundleVerifier(plugins=()).verify(bundle_dir, dsse=_dsse_ctx_for(key))

    assert verdict.ok, [(f.reason_code, f.detail) for f in verdict.failures]
    assert "conservation" in verdict.completeness.layers
    assert not any(
        "parse-validated only" in d for d in verdict.completeness.disclosures
    )


def test_envelope_lane_sidecar_present_unsealed_fail_closed(tmp_path):
    """Sidecar present + no DSSE context: the pre-gate rejects fail-closed;
    conservation is never reached on this lane (that IS its semantics)."""
    bundle_dir, _key = _sealed_bundle(tmp_path)

    verdict = BundleVerifier(plugins=()).verify(bundle_dir, dsse=None)

    assert not verdict.ok
    assert any(f.reason_code == "DSSE_SIGNATURE_INVALID" for f in verdict.failures)


def test_envelope_lane_sidecar_absent_residual_disclosed(tmp_path):
    """Sidecar-absent lane: manifest.json's checker is the parse validator +
    admission bounds. Parse-validated ≠ byte-integrity-owned — the verdict
    face says so on an otherwise GREEN verdict (disclosed, never silent)."""
    bundle_dir = tmp_path / "b"
    _write_unsealed_bundle(bundle_dir)

    verdict = BundleVerifier(plugins=()).verify(bundle_dir)

    assert verdict.ok
    assert any(
        "manifest.json is parse-validated only" in d
        and "byte-integrity-owned by nobody" in d
        for d in verdict.completeness.disclosures
    )


# ---------------------------------------------------------------------------
# Auditor fs_ignore view (D1 rider)
# ---------------------------------------------------------------------------


def test_fs_ignore_default_empty_tolerates_nothing(tmp_path):
    bundle_dir = tmp_path / "b"
    _write_unsealed_bundle(bundle_dir)
    (bundle_dir / "stray.bin").write_bytes(b"x")
    assert not BundleVerifier(plugins=()).verify(bundle_dir).ok


def test_fs_ignore_exact_path_tolerated_and_reported_verbosely(tmp_path):
    bundle_dir = tmp_path / "b"
    _write_unsealed_bundle(bundle_dir)
    (bundle_dir / "stray.bin").write_bytes(b"x")

    verdict = BundleVerifier(plugins=(), fs_ignore=("stray.bin",)).verify(bundle_dir)

    assert verdict.ok
    assert any(
        "'stray.bin'" in d and "fs_ignore" in d
        for d in verdict.completeness.disclosures
    )


def test_fs_ignore_anchored_glob(tmp_path):
    bundle_dir = tmp_path / "b"
    _write_unsealed_bundle(bundle_dir)
    (bundle_dir / "__pycache__").mkdir()
    (bundle_dir / "__pycache__" / "junk.cpython-312.pyc").write_bytes(b"\x00")

    rejected = BundleVerifier(plugins=()).verify(bundle_dir)
    assert not rejected.ok

    tolerated = BundleVerifier(plugins=(), fs_ignore=("__pycache__/*",)).verify(
        bundle_dir
    )
    assert tolerated.ok
    assert any("__pycache__/junk" in d for d in tolerated.completeness.disclosures)


@pytest.mark.parametrize(
    "bad_pattern",
    [
        "",
        "*",
        "*.pyc",
        "?cache",
        "[ab]/x",
        "**/x",
        "a/**",
        "a/../b",
        "/abs/path",
        "dir/",
        "back\\slash",
    ],
)
def test_fs_ignore_invalid_patterns_rejected_at_construction(bad_pattern):
    """Exact-path or anchored-glob only — bare substrings, unanchored
    wildcards, recursive globs, traversal, absolute paths all raise at
    construction (auditor-side configuration, fail early)."""
    with pytest.raises(ValueError):
        BundleVerifier(fs_ignore=(bad_pattern,))


def test_fs_ignore_pattern_matching_declared_path_is_verdict_error(tmp_path):
    """A pattern that matches a DECLARED path is an auditor configuration
    conflict: verdict ERROR (could-not-conclude), never a REJECT and never a
    silent weakening of a declared owner."""
    bundle_dir = tmp_path / "b"
    _write_unsealed_bundle(bundle_dir)

    verdict = BundleVerifier(plugins=(), fs_ignore=("data.txt",)).verify(bundle_dir)

    assert verdict.state is VerdictState.ERROR
    assert verdict.reasons[0].code == VERIFIER_FS_IGNORE_CONFLICT


def test_fs_ignore_pattern_matching_envelope_path_is_verdict_error(tmp_path):
    bundle_dir = tmp_path / "b"
    _write_unsealed_bundle(bundle_dir)

    verdict = BundleVerifier(plugins=(), fs_ignore=("manifest.json",)).verify(
        bundle_dir
    )

    assert verdict.state is VerdictState.ERROR
    assert verdict.reasons[0].code == VERIFIER_FS_IGNORE_CONFLICT


def test_fs_ignore_sealed_bundles_ignore_nothing(tmp_path):
    """Under seal the patterns are inert: a surplus file still rejects (the
    set-closure gate fires regardless of any auditor tolerance), and
    run_conservation applies no ignore on the sealed lane."""
    bundle_dir, key = _sealed_bundle(tmp_path)
    (bundle_dir / "stray.bin").write_bytes(b"x")

    verdict = BundleVerifier(plugins=(), fs_ignore=("stray.bin",)).verify(
        bundle_dir, dsse=_dsse_ctx_for(key)
    )
    assert not verdict.ok

    # Unit level: sealed conservation never ignores, and never conflicts.
    manifest = _load_manifest(bundle_dir)
    result = run_conservation(
        bundle_dir, manifest, frozenset(), sealed=True, fs_ignore=("stray.bin",)
    )
    assert result.ignored == ()
    assert "stray.bin" in result.unowned


def test_fs_ignore_never_sourced_from_manifest(tmp_path):
    """A manifest field named fs_ignore is meaningless to the verifier — the
    view is construction-time only (never producer-controlled)."""
    bundle_dir = tmp_path / "b"
    _write_unsealed_bundle(bundle_dir, extra={"fs_ignore": ["stray.bin"]})
    (bundle_dir / "stray.bin").write_bytes(b"x")

    verdict = BundleVerifier(plugins=()).verify(bundle_dir)

    assert not verdict.ok
    assert any("'stray.bin'" in f.detail for f in verdict.failures)


def test_validate_fs_ignore_accepts_exact_and_anchored(tmp_path):
    assert validate_fs_ignore_patterns(
        ("stray.bin", "__pycache__/*", "build/tmp-?.log")
    ) == ("stray.bin", "__pycache__/*", "build/tmp-?.log")


# ---------------------------------------------------------------------------
# Non-regular objects (§F.2 №2) — fail closed before any content step
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "linux", reason="mkfifo semantics")
def test_undeclared_fifo_rejects(tmp_path):
    bundle_dir = tmp_path / "b"
    _write_unsealed_bundle(bundle_dir)
    os.mkfifo(bundle_dir / "pipe.fifo")

    verdict = BundleVerifier(plugins=()).verify(bundle_dir)

    assert not verdict.ok
    assert any(
        f.reason_code == "EXTRA_FILE_NOT_IN_MANIFEST"
        and "non-regular file object (fifo)" in f.detail
        for f in verdict.failures
    )


@pytest.mark.skipif(sys.platform != "linux", reason="mkfifo semantics")
def test_declared_fifo_rejects_without_hanging(tmp_path):
    """A DECLARED FIFO classifies UNOWNED regardless (it can never satisfy a
    byte-equality contract) and the gate rejects BEFORE the strict-SHA walk
    opens it — as-built, read_bytes() on a FIFO blocks forever."""
    bundle_dir = tmp_path / "b"
    bundle_dir.mkdir()
    fifo_sha = "0" * 64
    manifest = {
        "schema_version": "vcp-v1.1-canary4",
        "bundle_id": "fifo-declared",
        "created_at": "2026-06-10T00:00:00Z",
        "files": {"pipe.fifo": fifo_sha},
        "spec_files": {},
        "cross_refs": {},
    }
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    os.mkfifo(bundle_dir / "pipe.fifo")

    verdict = BundleVerifier(plugins=()).verify(bundle_dir)

    assert not verdict.ok
    assert any(
        "non-regular file object (fifo)" in f.detail
        and "regardless of declaration" in f.detail
        for f in verdict.failures
    )


@pytest.mark.skipif(sys.platform != "linux", reason="symlink semantics")
def test_undeclared_symlink_is_unowned_surplus(tmp_path):
    bundle_dir = tmp_path / "b"
    _write_unsealed_bundle(bundle_dir)
    (bundle_dir / "alias.txt").symlink_to(bundle_dir / "data.txt")

    verdict = BundleVerifier(plugins=()).verify(bundle_dir)

    assert not verdict.ok
    assert any("'alias.txt'" in f.detail for f in verdict.failures)


@pytest.mark.skipif(sys.platform != "linux", reason="symlink semantics")
def test_declared_in_tree_symlink_keeps_as_built_tolerance(tmp_path):
    """A DECLARED in-tree symlink is owned by its declared class; the
    strict-SHA walk resolves it under the containment guard (as-built
    behavior, unchanged by the gate)."""
    bundle_dir = tmp_path / "b"
    bundle_dir.mkdir()
    data = b"linked payload"
    (bundle_dir / "real.txt").write_bytes(data)
    (bundle_dir / "alias.txt").symlink_to(bundle_dir / "real.txt")
    manifest = {
        "schema_version": "vcp-v1.1-canary4",
        "bundle_id": "symlink-declared",
        "created_at": "2026-06-10T00:00:00Z",
        "files": {"real.txt": _sha(data), "alias.txt": _sha(data)},
        "spec_files": {},
        "cross_refs": {},
    }
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    verdict = BundleVerifier(plugins=()).verify(bundle_dir)

    assert verdict.ok, [(f.reason_code, f.detail) for f in verdict.failures]


# ---------------------------------------------------------------------------
# D5 Pass-3 shim — fails closed without a finalized conservation result
# ---------------------------------------------------------------------------


def test_shim_hard_errors_when_invoked_directly(tmp_path):
    bundle_dir = tmp_path / "b"
    _write_unsealed_bundle(bundle_dir)
    manifest = _load_manifest(bundle_dir)

    with pytest.raises(ConservationResultAbsent):
        FileIntegrityManySmall().check(bundle_dir, manifest)


def test_shim_hard_errors_on_cross_bundle_binding(tmp_path):
    bundle_a = tmp_path / "a"
    bundle_b = tmp_path / "b"
    _write_unsealed_bundle(bundle_a)
    _write_unsealed_bundle(bundle_b)
    manifest_a = _load_manifest(bundle_a)

    plugin = FileIntegrityManySmall()
    plugin.bind_conservation(
        run_conservation(bundle_a, manifest_a, frozenset(), sealed=False)
    )
    with pytest.raises(ConservationResultAbsent):
        plugin.check(bundle_b, _load_manifest(bundle_b))


def test_verify_clears_binding_after_dispatch(tmp_path):
    """verify() binds the result around plugin dispatch and clears it after,
    so a later direct check() cannot ride a stale binding."""
    bundle_dir = tmp_path / "b"
    _write_unsealed_bundle(bundle_dir)
    plugin = FileIntegrityManySmall()

    verdict = BundleVerifier(plugins=(plugin,)).verify(bundle_dir)
    assert verdict.ok

    with pytest.raises(ConservationResultAbsent):
        plugin.check(bundle_dir, _load_manifest(bundle_dir))


def test_shim_agrees_with_core_gate_on_surplus(tmp_path):
    """Redundant-but-agreeing: with the plugin registered, the same surplus
    surfaces from both the core gate and the plugin shim — one decision,
    two reporting faces."""
    bundle_dir = tmp_path / "b"
    _write_unsealed_bundle(bundle_dir, extra={"typed_checks": []})
    (bundle_dir / "stray.bin").write_bytes(b"x")

    verdict = BundleVerifier(plugins=(FileIntegrityManySmall(),)).verify(bundle_dir)

    assert not verdict.ok
    conservation_hits = [f for f in verdict.failures if f.check_name == "conservation"]
    plugin_hits = [
        f
        for f in verdict.failures
        if f.check_name.startswith("typed_check_plugins") and "stray.bin" in f.detail
    ]
    assert conservation_hits and plugin_hits
