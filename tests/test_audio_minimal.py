"""Round-trip integration test for examples/audio_minimal/verify.py.

Test flow:
  1. Build a clean bundle from the synthetic waveform into a temp directory.
  2. Run the verifier with the pilot's plugin set.
  3. Assert result.ok is True.
  4. Tamper test: zero out 1600 bytes (800 int16 samples) spanning the second
     voiced region (bytes 3200..4799 of audio/samples.bin), re-align the file
     SHA in the manifest, and assert AUDIO_REDERIVATION_MISMATCH appears in
     failures because the re-derived segment count drops from 5 to 4.
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
_PILOT_DIR = _PKG_ROOT / "examples" / "audio_minimal"

# Ensure both pkg root and pilot dir are importable
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

# ---------------------------------------------------------------------------
# Lazy imports (after path setup)
# ---------------------------------------------------------------------------

from examples.audio_minimal._build_bundle import build  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from AudioReDerivationCheck import AudioReDerivationCheck  # noqa: E402


# ---------------------------------------------------------------------------
# Helper: build verifier
# ---------------------------------------------------------------------------


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(plugins=[
        SpecShaPinCheck(),
        FileIntegrityManySmall(),
        AudioReDerivationCheck(),
    ])


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_clean_bundle_passes(tmp_path: Path) -> None:
    """build + verify on a clean bundle must return result.ok == True."""
    bundle_dir = tmp_path / "audio_bundle"
    build(bundle_dir)
    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is True, (
        f"expected ok=True; failures: {result.failures}"
    )


def test_tamper_voiced_region_fails(tmp_path: Path) -> None:
    """Zeroing the second voiced region must trigger AUDIO_REDERIVATION_MISMATCH.

    The second voiced segment spans samples 1600..2399 (bytes 3200..4799).
    Zeroing those bytes silences that region, reducing the re-derived segment
    count from 5 to 4 while the committed transcript still claims 5 segments.
    The file SHA in the manifest is re-aligned so FileIntegrityManySmall passes
    and the failure is caught exclusively by the re-derivation plugin.
    """
    bundle_dir = tmp_path / "audio_bundle_tamper"
    build(bundle_dir)

    # Tamper: zero out bytes 3200..4799 (voiced region 2, samples 1600..2399)
    audio_path = bundle_dir / "audio" / "samples.bin"
    raw = bytearray(audio_path.read_bytes())
    raw[3200:4800] = b"\x00" * 1600
    audio_path.write_bytes(bytes(raw))

    # Re-align manifest SHA so file_integrity_many_small does not fire first
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["audio/samples.bin"] = hashlib.sha256(bytes(raw)).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "expected ok=False after zeroing a voiced region of samples.bin"
    )
    # Accept AUDIO_REDERIVATION_MISMATCH reason_code or [AUDIO_REDER_FAIL] in detail
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    assert "AUDIO_REDERIV" in combined or "AUDIO_REDER_FAIL" in combined, (
        f"expected AUDIO_REDERIVATION_MISMATCH or AUDIO_REDER_FAIL in failures; "
        f"got: {result.failures}"
    )


def test_tamper_spec_segmentation_fails_spec_sha(tmp_path: Path) -> None:
    """Mutate spec/segmentation.json with a SHA-changing-but-semantics-preserving
    edit (trailing whitespace; ignored by json.loads). manifest.spec_files SHA is
    NOT realigned, so SpecShaPinCheck catches the divergence in isolation —
    re-derivation still passes because parsed JSON is identical.
    """
    bundle_dir = tmp_path / "audio_bundle_spec_tamper"
    build(bundle_dir)

    spec_path = bundle_dir / "spec" / "segmentation.json"
    original = spec_path.read_text(encoding="utf-8")
    spec_path.write_text(original + "\n   \n", encoding="utf-8")

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False after tampering spec/segmentation.json without realigning manifest.spec_files"
    )
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    assert (
        "SPEC_SHA_MISMATCH" in combined
        or "MISSING_SPEC_BLOB" in combined
        or ("SPEC" in combined and "SHA MISMATCH" in combined)
    ), f"expected spec-SHA-mismatch indicator in failures; got: {result.failures}"
