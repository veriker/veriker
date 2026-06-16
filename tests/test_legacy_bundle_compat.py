"""tests/test_legacy_bundle_compat.py — Backward-compat invariant: pre-C14/C15/C16 bundles.

Proves that W3-baseline bundles (v1.0.0rc1, written before the C14/C15/C16 sprint)
verify cleanly under the post-W3 verifier with default_post_w3_plugin_set() registered.
This is the BACKWARD-COMPAT INVARIANT from global_constraints: C14/C15/C16 additions
are additive-only; any bundle that omits dispatch_records must continue to pass.

Three test cases:
  1. test_legacy_bundle_dispatch_records_absent — dispatch_records / aggregate_stamp keys
     omitted entirely from manifest.json.  Mirrors a W3 bundle builder with no knowledge
     of Phase-0 fields.
  2. test_legacy_bundle_dispatch_records_explicit_null — dispatch_records: null per
     the audit-bundle contract §C15 'explicit-null is the forward-compatible legacy marker'.
     Treated identically to absent at v0.1.
  3. test_w3_baseline_full_suite_unchanged — synthesized W3-baseline bundle (two corpus
     files with real SHA-256 entries, no dispatch_records) run through the full verifier.
     NOTE: examples/spectra_minimal/manifest.json carries spec_files as a JSON array ([]);
     BundleVerifier._step_spec_sha_pinning calls manifest.spec_files.items() which raises
     AttributeError on a list.  The examples/ bundles target the CLI / validate_manifest
     path, not BundleVerifier.verify() directly, so this test synthesizes an equivalent
     W3-baseline bundle with spec_files: {} to exercise the same backward-compat claim.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from audit_bundle.plugins import default_post_w3_plugin_set
from audit_bundle.verifier import BundleVerifier

_VERIFIER = BundleVerifier(plugins=default_post_w3_plugin_set())


# ---------------------------------------------------------------------------
# Bundle builder helper
# ---------------------------------------------------------------------------


def _make_bundle(tmp_path: Path, **manifest_overrides) -> Path:
    """Build a minimal W3-baseline bundle dir with real corpus files.

    Writes two small corpus files so file_integrity step has real SHA-256 work.
    Returns the bundle_dir Path.  Pass keyword overrides to inject or replace
    specific manifest fields (e.g. dispatch_records=None for test 2).
    """
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    corpus_dir = bundle_dir / "corpus"
    corpus_dir.mkdir()

    files: dict[str, str] = {}
    for i, content in enumerate([b"alpha corpus entry", b"beta corpus entry"]):
        rel = f"corpus/entry{i}.txt"
        (corpus_dir / f"entry{i}.txt").write_bytes(content)
        files[rel] = hashlib.sha256(content).hexdigest()

    manifest: dict = {
        "schema_version": "legacy",
        "bundle_id": "legacy-compat-test",
        "created_at": "2026-01-01T00:00:00Z",
        "files": files,
        "spec_files": {},
        "cross_refs": {},
        "payload": {},
        "typed_checks": [],
        "per_output_manifests": [],
    }
    manifest.update(manifest_overrides)
    (bundle_dir / "manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    return bundle_dir


# ---------------------------------------------------------------------------
# Test 1 — dispatch_records field absent entirely
# ---------------------------------------------------------------------------


def test_legacy_bundle_dispatch_records_absent(tmp_path: Path) -> None:
    """W3-baseline bundle with dispatch_records omitted entirely → ok=True.

    Mirrors a bundle written by W3 builder code with no knowledge of Phase-0
    fields.  _load_manifest normalises absent key → None → [] → empty tuple;
    all three C14/C15/C16 plugins short-circuit to PASS on empty dispatch_records.
    """
    bundle_dir = _make_bundle(tmp_path)
    raw = json.loads((bundle_dir / "manifest.json").read_text())
    assert "dispatch_records" not in raw, "pre-condition: field must be absent"
    assert "aggregate_stamp" not in raw, "pre-condition: field must be absent"

    result = _VERIFIER.verify(bundle_dir)

    assert result.ok is True
    assert result.failures == []


# ---------------------------------------------------------------------------
# Test 2 — dispatch_records: null (explicit-null legacy marker)
# ---------------------------------------------------------------------------


def test_legacy_bundle_dispatch_records_explicit_null(tmp_path: Path) -> None:
    """dispatch_records: null in manifest.json → ok=True (explicit-null legacy marker).

    Per the audit-bundle contract §C15: explicit-null is the forward-compatible
    legacy marker.  _load_manifest normalises null → empty tuple via `or []`,
    so this path is identical to the absent-field case at v0.1.
    """
    bundle_dir = _make_bundle(tmp_path, dispatch_records=None)
    raw = json.loads((bundle_dir / "manifest.json").read_text())
    assert raw["dispatch_records"] is None, "pre-condition: must be JSON null"

    result = _VERIFIER.verify(bundle_dir)

    assert result.ok is True
    assert result.failures == []


# ---------------------------------------------------------------------------
# Test 3 — full W3-baseline bundle (strongest backward-compat signal)
# ---------------------------------------------------------------------------


def test_w3_baseline_full_suite_unchanged(tmp_path: Path) -> None:
    """Synthesized W3-baseline bundle (no dispatch_records) passes all three C14/C15/C16 plugins.

    The examples/spectra_minimal/manifest.json carries spec_files as a JSON array ([])
    rather than an object ({}).  BundleVerifier._step_spec_sha_pinning calls
    manifest.spec_files.items(), which raises AttributeError on a list.  The examples/
    bundles target the CLI / validate_manifest path, not BundleVerifier.verify() directly.
    This test synthesizes an equivalent W3-baseline bundle (spec_files: {}, two corpus
    files with real SHA-256 entries, no dispatch_records) to prove the same invariant:
    the post-sprint verifier with the full C14/C15/C16 plugin set emits zero failures
    against a pre-sprint bundle shape.
    """
    bundle_dir = _make_bundle(tmp_path)
    raw = json.loads((bundle_dir / "manifest.json").read_text())
    assert "dispatch_records" not in raw, "pre-condition: W3-baseline has no dispatch_records"

    result = _VERIFIER.verify(bundle_dir)

    assert result.ok is True, (
        f"W3-baseline bundle must pass all post-W3 plugins; "
        f"failures: {[(f.check_name, f.reason_code) for f in result.failures]}"
    )
    assert result.failures == [], "No advisories or failures for a W3-baseline bundle"

    c14_c15_c16 = {"dispatch_record_wellformed", "stamp_lattice", "refinement_discharge"}
    failing = {
        f.check_name.split(":")[-1]
        for f in result.failures
        if f.check_name.startswith("typed_check_plugins:")
    }
    assert not failing & c14_c15_c16, (
        f"C14/C15/C16 plugins must not fail on a W3-baseline bundle; got {failing}"
    )
