"""Round-trip integration test for examples/content_provenance_minimal/verify.py.

Test flow:
  1. Build a clean bundle via _build_bundle.py into a temp directory.
  2. Run verify.py via subprocess from a separate cwd (clean working dir).
  3. Assert exit 0 and 'PASS' in stdout.
  4. Tamper the content file on disk (flip one byte).
  5. Re-run verify.py.
  6. Assert exit 1 and CONTENT_PROVENANCE_ALTERED or BAD_FILE_SHA in stderr.

SCOPE BOUNDARY TEST:
  test_false_content_passes_provenance_check — an artifact with a factually false
  claim but unaltered, correctly-signed bytes PASSES (result.ok is True).
  This is correct by design: the check is provenance, not truth.

The bundle is constructed from _build_bundle.py so the test exercises the full
production build path.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PKG_ROOT = Path(__file__).resolve().parents[1]  # v-kernel-audit-bundle/
_BUILD_PY = (
    _PKG_ROOT / "examples" / "content_provenance_minimal" / "_build_bundle.py"
)
_VERIFY_PY = _PKG_ROOT / "examples" / "content_provenance_minimal" / "verify.py"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_bundle(out_dir: Path) -> subprocess.CompletedProcess:
    """Run _build_bundle.py to generate a clean bundle into out_dir."""
    return subprocess.run(
        [sys.executable, str(_BUILD_PY), "--out-dir", str(out_dir)],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )


def _run_verify(
    bundle_dir: Path, cwd: Path | None = None
) -> subprocess.CompletedProcess:
    """Invoke verify.py as a subprocess from cwd (defaults to bundle_dir.parent)."""
    effective_cwd = cwd if cwd is not None else bundle_dir.parent
    return subprocess.run(
        [sys.executable, str(_VERIFY_PY), "--bundle-dir", str(bundle_dir)],
        capture_output=True,
        text=True,
        cwd=str(effective_cwd),
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def clean_bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Bundle built once per module from _build_bundle.py; must not be mutated."""
    dest = tmp_path_factory.mktemp("content_prov_clean_bundle")
    result = _build_bundle(dest)
    assert result.returncode == 0, (
        f"_build_bundle.py failed (exit {result.returncode})\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
    )
    return dest


@pytest.fixture
def tampered_content_bundle(tmp_path: Path) -> Path:
    """Fresh bundle with the content file's first byte flipped."""
    bundle = tmp_path / "bundle"
    result = _build_bundle(bundle)
    assert result.returncode == 0, (
        f"_build_bundle.py failed while setting up tamper fixture\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
    )
    content_path = bundle / "artifact" / "content.txt"
    original = bytearray(content_path.read_bytes())
    original[0] = (original[0] + 1) % 256  # flip one byte
    content_path.write_bytes(bytes(original))
    return bundle


# ---------------------------------------------------------------------------
# Happy-path: clean bundle
# ---------------------------------------------------------------------------


def test_clean_bundle_build_exits_zero(tmp_path: Path) -> None:
    """_build_bundle.py must exit 0 for a fresh build."""
    result = _build_bundle(tmp_path / "bundle")
    assert result.returncode == 0, (
        f"expected exit 0; got {result.returncode}\n"
        f"stdout: {result.stdout!r}\nstderr: {result.stderr!r}"
    )


def test_clean_bundle_verify_exits_zero(clean_bundle: Path, tmp_path: Path) -> None:
    """verify.py must exit 0 for an untampered bundle."""
    proc = _run_verify(clean_bundle, cwd=tmp_path)
    assert proc.returncode == 0, (
        f"expected exit 0; got {proc.returncode}\n"
        f"stdout: {proc.stdout!r}\nstderr: {proc.stderr!r}"
    )


def test_clean_bundle_prints_pass(clean_bundle: Path, tmp_path: Path) -> None:
    """'PASS' must appear in stdout for a clean bundle."""
    proc = _run_verify(clean_bundle, cwd=tmp_path)
    assert "PASS" in proc.stdout, (
        f"expected 'PASS' in stdout; got: {proc.stdout!r}\nstderr: {proc.stderr!r}"
    )


def test_clean_bundle_has_expected_files(clean_bundle: Path) -> None:
    """Bundle must contain the three committed files."""
    assert (clean_bundle / "artifact" / "content.txt").exists()
    assert (clean_bundle / "artifact" / "provenance.json").exists()
    assert (clean_bundle / "payload" / "provenance_result.json").exists()
    assert (clean_bundle / "manifest.json").exists()


def test_clean_bundle_payload_fields(clean_bundle: Path) -> None:
    """payload/provenance_result.json must have the required fields."""
    payload = json.loads(
        (clean_bundle / "payload" / "provenance_result.json").read_bytes()
    )
    assert "content_sha" in payload
    assert "provenance_sha" in payload
    assert "producer_id" in payload
    assert "generation_inputs" in payload
    assert "producer_hmac" in payload
    assert "provenance_status" in payload
    assert payload["provenance_status"] == "CONTENT_PROVENANCE_VERIFIED"
    assert payload["producer_hmac"].startswith("hmac-sha256:")


def test_clean_bundle_provenance_manifest_fields(clean_bundle: Path) -> None:
    """artifact/provenance.json must have required provenance manifest fields."""
    manifest = json.loads(
        (clean_bundle / "artifact" / "provenance.json").read_bytes()
    )
    assert manifest["schema"] == "content-provenance-v1"
    assert "producer_id" in manifest
    assert "content_sha" in manifest
    assert "generation_inputs" in manifest
    assert "producer_hmac" in manifest
    assert manifest["producer_hmac"].startswith("hmac-sha256:")


# ---------------------------------------------------------------------------
# SCOPE BOUNDARY TEST — false content passes (by design)
# ---------------------------------------------------------------------------


def test_false_content_passes_provenance_check(tmp_path: Path) -> None:
    """SCOPE BOUNDARY: A factually false but unaltered, correctly-signed artifact PASSES.

    This is the explicit scope-boundary test.  The synthetic news article in the
    bundle contains a fabricated claim ("Scientists Announce Breakthrough...").
    The content is factually false, but the bytes are unaltered since producer signing
    and the HMAC is valid.  The provenance check MUST return result.ok is True.

    This documents that the check is provenance, not truth.  A false article signed
    by its AI producer PASSES — that is by design and out of scope of this substrate.

    The content_sha matches, the producer_hmac is valid, the provenance chain is
    intact.  The verifier has no knowledge of factual accuracy — that is a separate
    domain-specific concern requiring a fact-checking layer.
    """
    # Add the pilot and pkg root to sys.path for the Python API call
    sys.path.insert(0, str(_PKG_ROOT))
    sys.path.insert(0, str(_PKG_ROOT / "examples" / "content_provenance_minimal"))

    from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
    from audit_bundle.verifier import BundleVerifier
    from ContentProvenanceReDerivationCheck import ContentProvenanceReDerivationCheck

    # Build a clean bundle — the article is factually fabricated (see _build_bundle.py)
    bundle = tmp_path / "bundle"
    r = _build_bundle(bundle)
    assert r.returncode == 0, (
        f"_build_bundle.py failed in scope-boundary test\n"
        f"stdout: {r.stdout!r}\nstderr: {r.stderr!r}"
    )

    # Confirm the content contains the fabricated claim (it's a false statement)
    content = (bundle / "artifact" / "content.txt").read_bytes().decode("utf-8")
    assert "battery" in content.lower() or "breakthrough" in content.lower() or "synthetic" in content.lower(), (
        "Expected fabricated battery/breakthrough claim in synthetic content"
    )
    # The note in the article itself declares it's fabricated
    assert "SYNTHETIC" in content or "fabricated" in content.lower() or "demo" in content.lower(), (
        "Expected demo/synthetic disclaimer in content"
    )

    # Verify via Python API — MUST PASS despite the false claim
    verifier = BundleVerifier(
        plugins=[FileIntegrityManySmall(), ContentProvenanceReDerivationCheck()]
    )
    result = verifier.verify(bundle)

    # THIS ASSERTION IS THE SCOPE BOUNDARY:
    # A factually false but unaltered, correctly-signed content artifact PASSES.
    # The verifier proves provenance, not truth.
    assert result.ok is True, (
        "SCOPE BOUNDARY FAILED: Expected result.ok is True for a false-but-unaltered "
        "correctly-signed artifact.  The provenance check must PASS for unaltered content "
        "regardless of factual accuracy — truth-detection is out of scope.\n"
        f"Failures: {result.failures!r}"
    )


# ---------------------------------------------------------------------------
# Tamper path: content file byte flipped
# ---------------------------------------------------------------------------


def test_tampered_content_exits_one(tampered_content_bundle: Path) -> None:
    """verify.py must exit 1 when the content file is modified on disk."""
    proc = _run_verify(tampered_content_bundle)
    assert proc.returncode == 1, (
        f"expected exit 1; got {proc.returncode}\n"
        f"stdout: {proc.stdout!r}\nstderr: {proc.stderr!r}"
    )


def test_tampered_content_does_not_print_pass(tampered_content_bundle: Path) -> None:
    """'PASS' must not appear in stdout for a tampered bundle."""
    proc = _run_verify(tampered_content_bundle)
    assert "PASS" not in proc.stdout, (
        f"'PASS' must not appear in stdout for a tampered bundle; got: {proc.stdout!r}"
    )


def test_tampered_content_reports_mismatch_reason(tampered_content_bundle: Path) -> None:
    """stderr must include either BAD_FILE_SHA or CONTENT_PROVENANCE_ALTERED for a tampered file.

    FileIntegrityManySmall (pass-2) emits BAD_FILE_SHA when the content hash
    no longer matches the manifest.  ContentProvenanceReDerivationCheck emits
    CONTENT_PROVENANCE_ALTERED when the SHA or HMAC does not match.
    Either or both may appear.
    """
    proc = _run_verify(tampered_content_bundle)
    combined = (proc.stdout + proc.stderr).upper()
    assert "BAD_FILE_SHA" in combined or "CONTENT_PROVENANCE_ALTERED" in combined, (
        f"expected BAD_FILE_SHA or CONTENT_PROVENANCE_ALTERED in output;\n"
        f"stdout: {proc.stdout!r}\nstderr: {proc.stderr!r}"
    )


def test_tampered_content_result_ok_is_false(tmp_path: Path) -> None:
    """Direct API: BundleVerifier.verify() must return result.ok is False for tampered content.

    This test exercises the Python API directly (not subprocess) to assert
    result.ok is False with a meaningful reason_code present in the failures list.
    """
    sys.path.insert(0, str(_PKG_ROOT))
    sys.path.insert(0, str(_PKG_ROOT / "examples" / "content_provenance_minimal"))

    from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
    from audit_bundle.verifier import BundleVerifier
    from ContentProvenanceReDerivationCheck import ContentProvenanceReDerivationCheck

    # Build a fresh bundle
    bundle = tmp_path / "bundle"
    r = _build_bundle(bundle)
    assert r.returncode == 0

    # Tamper the content
    content_path = bundle / "artifact" / "content.txt"
    original = bytearray(content_path.read_bytes())
    original[0] = (original[0] + 1) % 256
    content_path.write_bytes(bytes(original))

    # Verify via Python API
    verifier = BundleVerifier(
        plugins=[FileIntegrityManySmall(), ContentProvenanceReDerivationCheck()]
    )
    result = verifier.verify(bundle)

    assert result.ok is False, (
        "Expected result.ok is False for a tampered-content bundle; got True"
    )
    reason_codes = {f.reason_code for f in result.failures}
    reason_codes_upper = {rc.upper() for rc in reason_codes}
    assert reason_codes_upper & {
        "BAD_FILE_SHA",
        "CONTENT_PROVENANCE_ALTERED",
        "PLUGIN_FAILED",
    }, f"Expected a tamper-indicating reason code in failures; got {reason_codes!r}"
