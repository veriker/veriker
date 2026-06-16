"""Round-trip integration test for examples/build_minimal/verify.py.

Test flow:
  1. Build a clean bundle from the synthetic sources + recipe into a temp dir.
  2. Run the verifier with the pilot's plugin set.
  3. Assert result.ok is True.
  4. Tamper test (re-derivation): keep source SHA aligned with manifest by
     mutating the bundled artifact bytes instead — file_integrity catches
     that, so to isolate the BUILD_REDERIVATION_MISMATCH path we tamper a
     source file AND update its manifest SHA so file_integrity passes;
     then build_re_derivation sees the divergence.
  5. Tamper test (file integrity): mutate a source file in place without
     manifest update — file_integrity_many_small catches the SHA mismatch.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PKG_ROOT = Path(__file__).resolve().parents[1]  # v-kernel-audit-bundle/
_PILOT_DIR = _PKG_ROOT / "examples" / "build_minimal"

# Ensure both pkg root and pilot dir are importable
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

# ---------------------------------------------------------------------------
# Lazy imports (after path setup)
# ---------------------------------------------------------------------------

from examples.build_minimal._build_bundle import build  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from BuildReDerivationCheck import BuildReDerivationCheck  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(plugins=[
        FileIntegrityManySmall(),
        BuildReDerivationCheck(),
    ])


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_clean_bundle_passes(tmp_path: Path) -> None:
    """build + verify on a clean bundle must return result.ok == True."""
    bundle_dir = tmp_path / "build_bundle"
    build(bundle_dir)
    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is True, (
        f"expected ok=True; failures: {result.failures}"
    )


def test_tamper_source_no_manifest_update_fails_file_integrity(tmp_path: Path) -> None:
    """Mutating a source file in place must trigger file_integrity SHA mismatch."""
    bundle_dir = tmp_path / "build_bundle_tamper_a"
    build(bundle_dir)

    # Mutate sources/a.txt without updating the manifest entry.
    src = bundle_dir / "sources" / "a.txt"
    src.write_bytes(b"tampered alpha source\n")

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False after mutating sources/a.txt without manifest update"
    )
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    # FileIntegrityManySmall fires a SHA-mismatch reason code; accept any of
    # the conventional spellings used by the substrate plugin.
    assert (
        "SHA" in combined or "INTEGRITY" in combined or "FILE_HASH" in combined
    ), f"expected file-integrity SHA-mismatch failure; got: {result.failures}"


def test_tamper_source_with_aligned_manifest_fails_re_derivation(tmp_path: Path) -> None:
    """Mutating source AND updating the manifest SHA isolates the BUILD_REDERIVATION_MISMATCH path.

    Without the manifest update, file_integrity catches the tamper first
    (covered by the previous test). To exercise build_re_derivation, we
    re-align manifest.files["sources/a.txt"] to the tampered SHA so file
    integrity passes; the recipe then re-executes against the tampered source
    and produces a gzip artifact with different bytes than the bundled one.
    """
    bundle_dir = tmp_path / "build_bundle_tamper_b"
    build(bundle_dir)

    src = bundle_dir / "sources" / "a.txt"
    tampered = b"tampered alpha source\nextra line\n"
    src.write_bytes(tampered)

    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["sources/a.txt"] = _sha256(tampered)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False once the recipe re-execution diverges from bundled artifact"
    )
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    assert "BUILD_REDERIV" in combined or "BUILD_REDER_FAIL" in combined, (
        f"expected BUILD_REDERIVATION_MISMATCH or BUILD_REDER_FAIL; got: {result.failures}"
    )
