"""Round-trip integration test for examples/raster_minimal/verify.py.

Test flow:
  1. Build a clean bundle from the synthetic raster into a temp directory.
  2. Run the verifier with the pilot's plugin set.
  3. Assert result.ok is True.
  4. Tamper test: mutate one raster cell byte in raster/grid.bin,
     re-align its file SHA in the manifest (so FileIntegrityManySmall
     passes), then assert RasterReDerivationCheck returns
     RASTER_REDERIVATION_MISMATCH.
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
_PILOT_DIR = _PKG_ROOT / "examples" / "raster_minimal"

# Ensure both pkg root and pilot dir are importable
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

# ---------------------------------------------------------------------------
# Lazy imports (after path setup)
# ---------------------------------------------------------------------------

from examples.raster_minimal._build_bundle import build  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from RasterReDerivationCheck import RasterReDerivationCheck  # noqa: E402


# ---------------------------------------------------------------------------
# Helper: create verifier
# ---------------------------------------------------------------------------


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(plugins=[
        SpecShaPinCheck(),
        FileIntegrityManySmall(),
        RasterReDerivationCheck(),
    ])


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_clean_bundle_passes(tmp_path: Path) -> None:
    """build + verify on a clean bundle must return result.ok == True."""
    bundle_dir = tmp_path / "raster_bundle"
    build(bundle_dir)
    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is True, (
        f"expected ok=True; failures: {result.failures}"
    )


def test_tamper_raster_cell_fails(tmp_path: Path) -> None:
    """Mutate a raster cell value, re-align manifest SHA, then assert RASTER_REDERIVATION_MISMATCH.

    The tamper preserves the file SHA so FileIntegrityManySmall passes, but
    the re-derived zonal sum diverges from the bundled payload/zonal_result.json,
    causing RasterReDerivationCheck to fail.
    """
    bundle_dir = tmp_path / "raster_bundle_tamper"
    build(bundle_dir)

    # --- Mutate a single byte in raster/grid.bin ---
    grid_path = bundle_dir / "raster" / "grid.bin"
    data = bytearray(grid_path.read_bytes())

    # Flip cell (row=5, col=5): center (5.5, 5.5) is inside the L-polygon.
    # Original value = ((5*31 + 5*17) % 200) - 100 = ((155 + 85) % 200) - 100
    #                = (240 % 200) - 100 = 40 - 100 = -60.
    # Byte index: 5 * 32 + 5 = 165.
    # Changing this value shifts the zonal sum and triggers a mismatch.
    byte_idx = 5 * 32 + 5
    original_byte = data[byte_idx]
    data[byte_idx] = (original_byte + 1) & 0xFF
    grid_path.write_bytes(bytes(data))

    # Re-align the manifest SHA for raster/grid.bin so FileIntegrityManySmall passes.
    new_sha = hashlib.sha256(bytes(data)).hexdigest()
    manifest_path = bundle_dir / "manifest.json"
    manifest_dict = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_dict["files"]["raster/grid.bin"] = new_sha
    manifest_path.write_text(json.dumps(manifest_dict, indent=2), encoding="utf-8")

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "expected ok=False after tampering raster cell value"
    )

    # Accept RASTER_REDERIVATION_MISMATCH (reason_code) or RASTER_REDER_FAIL
    # (stderr tag) anywhere in the combined failure string.
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    assert "RASTER_REDERIV" in combined or "RASTER_REDER_FAIL" in combined, (
        f"expected RASTER_REDERIVATION_MISMATCH or RASTER_REDER_FAIL in failures; "
        f"got: {result.failures}"
    )


def test_tamper_spec_query_fails_spec_sha(tmp_path: Path) -> None:
    """Mutate spec/zonal_query.json with a SHA-changing-but-semantics-preserving edit
    (trailing whitespace; ignored by json.loads). manifest.spec_files SHA is NOT
    realigned, so SpecShaPinCheck catches the divergence in isolation — re-derivation
    still passes because parsed JSON is identical.
    """
    bundle_dir = tmp_path / "raster_bundle_spec_tamper"
    build(bundle_dir)

    spec_path = bundle_dir / "spec" / "zonal_query.json"
    original = spec_path.read_text(encoding="utf-8")
    spec_path.write_text(original + "\n   \n", encoding="utf-8")

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False after tampering spec/zonal_query.json without realigning manifest.spec_files"
    )
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    # Substrate wraps plugin reason codes inside an outer plugin_failed detail;
    # match either the verifier-level reason (MISSING_SPEC_BLOB), the plugin's
    # SPEC_SHA_MISMATCH if it surfaces, or the literal "SHA MISMATCH" wording
    # that survives the wrap.
    assert (
        "SPEC_SHA_MISMATCH" in combined
        or "MISSING_SPEC_BLOB" in combined
        or ("SPEC" in combined and "SHA MISMATCH" in combined)
    ), f"expected spec-SHA-mismatch indicator in failures; got: {result.failures}"
