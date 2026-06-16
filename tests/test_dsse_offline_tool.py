"""tests/test_dsse_offline_tool.py — DSSE sidecar guard for the offline stdlib verifier.

Tests the fail-closed behavior added in WS-8 (DSSE v0.4 Tier-4 PRD, Option A):

  1. Sealed-bundle unit — _dsse_sidecar_offline_check returns sealed=True +
     DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO when bundle.dsse.json carries a
     post-cutover schema_version.
  2. Legacy-bundle unit — _dsse_sidecar_offline_check returns sealed=False when
     sidecar is absent.
  3. Pre-cutover-sidecar unit — sealed=False when sidecar payload schema_version
     is NOT a post-cutover tag.
  4. Full main() end-to-end (subprocess) — exit code 1 + DSSE code in stderr for
     a sealed bundle; NEVER exits 0.
  5. Pre-cutover main() end-to-end — DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO NOT
     emitted on a bundle with no sidecar.
  6. Transitive-closure import probe — `import veriker.cli.verify` does not pull
     cryptography, jcs, or rfc8785 into sys.modules.

All tests are stdlib-only on the test side (subprocess, json, base64, pathlib).
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PKG_ROOT = Path(__file__).resolve().parents[1]  # v-kernel-audit-bundle/
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from veriker.cli.verify import _dsse_sidecar_offline_check  # noqa: E402

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

_POST_CUTOVER_SV = "vcp-v1.2-dsse"
_PRE_CUTOVER_SV = "vcp-v1.1"


def _b64url_nopad_encode(b: bytes) -> str:
    """Encode bytes as base64url without padding (stdlib only)."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _make_dsse_sidecar(schema_version: str) -> dict:
    """Build a minimal bundle.dsse.json dict with the given schema_version.

    The signature is a dummy bytes value — the offline tool does NOT check
    signatures; only the payload schema_version is read.
    """
    payload_obj = {
        "schema_version": schema_version,
        "manifest_sha256": "a" * 64,
        "iat": 0,
        "files": [],
    }
    payload_b64 = _b64url_nopad_encode(json.dumps(payload_obj).encode("utf-8"))
    return {
        "payloadType": "application/vnd.vkernel.bundle.v1+json",
        "payload": payload_b64,
        "signatures": [{"keyid": "x", "sig": "AAAA"}],
    }


def _write_minimal_bundle(
    tmp_path: Path,
    *,
    add_dsse_sidecar: bool = False,
    dsse_schema_version: str = _POST_CUTOVER_SV,
) -> Path:
    """Write a minimal bundle dir.

    manifest.json uses schema_version='legacy' so validate_manifest() in
    veriker/cli/verify.py main() accepts it.  Adds real SHA-256 entries so the
    file_integrity step does not reject the bundle.  Optionally writes a
    bundle.dsse.json sidecar.
    """
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    corpus_dir = bundle_dir / "corpus"
    corpus_dir.mkdir()

    # Write one real corpus file so file_integrity has something to hash.
    content = b"synthetic corpus entry for dsse offline tool test"
    corpus_file = corpus_dir / "entry0.txt"
    corpus_file.write_bytes(content)
    file_sha = hashlib.sha256(content).hexdigest()

    manifest = {
        "schema_version": "legacy",
        "bundle_id": "dsse-offline-test",
        "created_at": "2026-01-01T00:00:00Z",
        "files": {"corpus/entry0.txt": file_sha},
        "spec_files": {},
        "cross_refs": {},
        "payload": {},
        "typed_checks": [],
        "per_output_manifests": [],
    }
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    if add_dsse_sidecar:
        sidecar = _make_dsse_sidecar(dsse_schema_version)
        (bundle_dir / "bundle.dsse.json").write_text(
            json.dumps(sidecar), encoding="utf-8"
        )

    return bundle_dir


# ---------------------------------------------------------------------------
# Unit tests — _dsse_sidecar_offline_check()
# ---------------------------------------------------------------------------


def test_sealed_bundle_returns_sealed_true(tmp_path: Path) -> None:
    """Sidecar with post-cutover schema_version → sealed=True + correct code."""
    bundle_dir = _write_minimal_bundle(
        tmp_path, add_dsse_sidecar=True, dsse_schema_version=_POST_CUTOVER_SV
    )
    sealed, reason, detail = _dsse_sidecar_offline_check(bundle_dir)
    assert sealed is True
    assert reason == "DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO"
    assert "DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO" in reason
    # The remediation pointer must steer the user to the REAL, working library
    # primitive shipped in this distribution + the out-of-band trust root.
    assert "verify_envelope" in detail
    assert "allowlist" in detail.lower()
    # ...and must NOT resurrect the dead pointers the old hint named: the
    # orchestrator_turn package is excluded from this distribution, and
    # audit_bundle/verifier.py has no CLI entry point.
    assert "orchestrator_turn" not in detail
    assert "verifier.py" not in detail


def test_sealed_bundle_never_returns_verified_true(tmp_path: Path) -> None:
    """sealed=True means verified MUST be False — direct guard assertion."""
    bundle_dir = _write_minimal_bundle(
        tmp_path, add_dsse_sidecar=True, dsse_schema_version=_POST_CUTOVER_SV
    )
    sealed, reason, _detail = _dsse_sidecar_offline_check(bundle_dir)
    # If sealed, the caller must NOT emit verified=True.  We assert here that
    # the helper correctly signals the sealed state.
    assert sealed is True, "post-cutover sidecar must be detected as sealed"
    assert reason is not None, "sealed bundle must carry a reason code"
    # Explicit: the only acceptable reason code for a sealed bundle.
    assert reason == "DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO"


def test_no_sidecar_returns_not_sealed(tmp_path: Path) -> None:
    """No bundle.dsse.json → sealed=False (legacy / pre-DSSE path unaffected)."""
    bundle_dir = _write_minimal_bundle(tmp_path, add_dsse_sidecar=False)
    sealed, reason, _detail = _dsse_sidecar_offline_check(bundle_dir)
    assert sealed is False
    assert reason is None


def test_pre_cutover_sidecar_returns_not_sealed(tmp_path: Path) -> None:
    """Sidecar with non-post-cutover schema_version → sealed=False."""
    bundle_dir = _write_minimal_bundle(
        tmp_path, add_dsse_sidecar=True, dsse_schema_version=_PRE_CUTOVER_SV
    )
    sealed, reason, _detail = _dsse_sidecar_offline_check(bundle_dir)
    assert sealed is False
    assert reason is None


def test_pre_cutover_sidecar_no_dsse_code(tmp_path: Path) -> None:
    """Pre-cutover sidecar must NOT emit DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO."""
    bundle_dir = _write_minimal_bundle(
        tmp_path, add_dsse_sidecar=True, dsse_schema_version=_PRE_CUTOVER_SV
    )
    sealed, reason, _detail = _dsse_sidecar_offline_check(bundle_dir)
    assert reason != "DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO"


def test_malformed_sidecar_fails_closed(tmp_path: Path) -> None:
    """Malformed bundle.dsse.json (invalid JSON) → sealed=True, fail-closed."""
    bundle_dir = _write_minimal_bundle(tmp_path, add_dsse_sidecar=False)
    (bundle_dir / "bundle.dsse.json").write_text("NOT VALID JSON", encoding="utf-8")
    sealed, reason, _detail = _dsse_sidecar_offline_check(bundle_dir)
    assert sealed is True
    assert reason == "DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO"


def test_sidecar_missing_payload_field_fails_closed(tmp_path: Path) -> None:
    """bundle.dsse.json with no 'payload' field → sealed=True, fail-closed."""
    bundle_dir = _write_minimal_bundle(tmp_path, add_dsse_sidecar=False)
    (bundle_dir / "bundle.dsse.json").write_text(
        json.dumps({"payloadType": "x", "signatures": []}), encoding="utf-8"
    )
    sealed, reason, _detail = _dsse_sidecar_offline_check(bundle_dir)
    assert sealed is True
    assert reason == "DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO"


# ---------------------------------------------------------------------------
# End-to-end subprocess tests — main() via veriker/cli/verify.py
# ---------------------------------------------------------------------------


def _run_verify_cli(bundle_dir: Path) -> subprocess.CompletedProcess:
    """Run veriker/cli/verify.py main() in a subprocess."""
    return subprocess.run(
        [
            sys.executable,
            str(_PKG_ROOT / "veriker" / "cli" / "verify.py"),
            "--bundle-dir",
            str(bundle_dir),
        ],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )


def test_main_sealed_bundle_exits_1(tmp_path: Path) -> None:
    """Sealed bundle: main() exits 1 (verified=False) + DSSE code in stderr."""
    bundle_dir = _write_minimal_bundle(
        tmp_path, add_dsse_sidecar=True, dsse_schema_version=_POST_CUTOVER_SV
    )
    result = _run_verify_cli(bundle_dir)
    # Exit code 1 = verified False.
    assert result.returncode == 1, (
        f"Expected exit 1 for sealed bundle; got {result.returncode}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    # DSSE code must appear in stderr output.
    assert "DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO" in result.stderr, (
        f"Expected DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO in stderr; got:\n{result.stderr}"
    )


def test_main_sealed_bundle_never_exits_0(tmp_path: Path) -> None:
    """Sealed bundle MUST NOT exit 0 (which would mean verified=True)."""
    bundle_dir = _write_minimal_bundle(
        tmp_path, add_dsse_sidecar=True, dsse_schema_version=_POST_CUTOVER_SV
    )
    result = _run_verify_cli(bundle_dir)
    assert result.returncode != 0, (
        "veriker/cli/verify.py returned exit 0 (verified=True) for a sealed DSSE bundle — "
        "this violates the fail-closed invariant."
    )


def test_main_no_sidecar_no_dsse_code(tmp_path: Path) -> None:
    """Bundle with no sidecar: DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO must NOT appear."""
    bundle_dir = _write_minimal_bundle(tmp_path, add_dsse_sidecar=False)
    result = _run_verify_cli(bundle_dir)
    combined = result.stdout + result.stderr
    assert "DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO" not in combined, (
        "DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO must not appear for a legacy bundle "
        f"(no sidecar).\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )


# ---------------------------------------------------------------------------
# Transitive-closure import probe — crypto-free invariant
# ---------------------------------------------------------------------------


def test_cli_verify_import_is_crypto_free() -> None:
    """Importing veriker.cli.verify must NOT pull cryptography, jcs, or rfc8785.

    Uses subprocess so the probe sees a clean module table (not the test
    process's already-loaded modules).
    """
    probe = (
        "import sys; "
        "sys.path.insert(0, '.'); "
        "import veriker.cli.verify; "
        "forbidden = {'cryptography', 'jcs', 'rfc8785'}; "
        "loaded = forbidden & set(sys.modules); "
        "assert not loaded, f'forbidden modules loaded: {loaded}'; "
        "print('offline tool crypto-free')"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )
    assert result.returncode == 0, (
        "Transitive-closure probe FAILED — veriker/cli/verify.py (or a transitive import) "
        f"pulled a forbidden module.\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "offline tool crypto-free" in result.stdout
