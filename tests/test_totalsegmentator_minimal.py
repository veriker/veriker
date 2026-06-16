"""Round-trip integration test for examples/totalsegmentator_minimal/verify.py.

Test flow:
  1. Build a clean bundle by running TotalSegmentator inference on the
     committed phantom fixture.
  2. Run the verifier with the pilot's plugin set.
  3. Assert result.ok is True (ROUND-TRIP test).
  4. PRIMARY TAMPER: mutate one voxel-region in source/phantom.nii.gz;
     re-align its SHA in manifest.files so FileIntegrityManySmall passes;
     assert TOTALSEGMENTATOR_REDERIVATION_MISMATCH because the re-derived
     segmentation sha differs from the committed sha.
  5. SPEC TAMPER: append whitespace to spec/tooling.json without realigning
     manifest.spec_files; assert SPEC_SHA_MISMATCH from SpecShaPinCheck.

Skipped when torch or TotalSegmentator cannot be imported — the re-derivation
pack needs both. Also skipped when the task-297 model checkpoint is not on
disk (avoids triggering a 135 MB weight download mid-pytest).
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
_PILOT_DIR = _PKG_ROOT / "examples" / "totalsegmentator_minimal"

if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))


# ---------------------------------------------------------------------------
# Skip gates — module-level import + checkpoint presence
# ---------------------------------------------------------------------------


def _have_imports() -> bool:
    try:
        import torch  # noqa: F401
        import totalsegmentator  # noqa: F401
        import nnunetv2  # noqa: F401
        import nibabel  # noqa: F401
        return True
    except ImportError:
        return False


def _have_checkpoint() -> bool:
    chk = (
        Path.home()
        / ".totalsegmentator"
        / "nnunet"
        / "results"
        / "Dataset297_TotalSegmentator_total_3mm_1559subj"
        / "nnUNetTrainer_4000epochs_NoMirroring__nnUNetPlans__3d_fullres"
        / "fold_0"
        / "checkpoint_final.pth"
    )
    return chk.exists()


_HAVE_IMPORTS = _have_imports()
_HAVE_CHECKPOINT = _have_checkpoint()

pytestmark = pytest.mark.skipif(
    not (_HAVE_IMPORTS and _HAVE_CHECKPOINT),
    reason=(
        "totalsegmentator_minimal needs torch + TotalSegmentator + nnUNetv2 + nibabel "
        "AND the task-297 checkpoint pre-downloaded "
        "(~/.totalsegmentator/nnunet/results/Dataset297_*)"
    ),
)


# ---------------------------------------------------------------------------
# Lazy imports (after path + skip-gate setup)
# ---------------------------------------------------------------------------

from examples.totalsegmentator_minimal._build_bundle import build  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from TotalSegmentatorReDerivationCheck import TotalSegmentatorReDerivationCheck  # noqa: E402


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(plugins=[
        SpecShaPinCheck(),
        FileIntegrityManySmall(),
        TotalSegmentatorReDerivationCheck(),
    ])


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_clean_bundle_passes(tmp_path: Path) -> None:
    """build + verify on a clean bundle must return result.ok == True."""
    bundle_dir = tmp_path / "ts_bundle"
    build(bundle_dir)
    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is True, (
        f"expected ok=True; failures: {result.failures}"
    )


def test_tamper_input_ct_fails_rederivation(tmp_path: Path) -> None:
    """Mutating source/phantom.nii.gz with SHA-realignment must trigger
    TOTALSEGMENTATOR_REDERIVATION_MISMATCH.

    The bundled segmentation was inferred from the original phantom voxels.
    Even a tiny voxel-region change shifts inference outputs (nnUNet's
    softmax field is sensitive to nearby HU values). The SHA in
    manifest.files is re-aligned so file_integrity_many_small passes and the
    re-derivation plugin is the exclusive failure path.
    """
    bundle_dir = tmp_path / "ts_bundle_ct_tamper"
    build(bundle_dir)

    # Tamper: open the phantom, flip a central voxel-region to a different HU
    import nibabel as nib
    import numpy as np
    phantom_path = bundle_dir / "source" / "phantom.nii.gz"
    img = nib.load(str(phantom_path))
    arr = np.asarray(img.dataobj, dtype=np.int16).copy()
    # Move a central 8x8x8 cube from its current value to +500 (different organ class)
    cx, cy, cz = (s // 2 for s in arr.shape)
    arr[cx-4:cx+4, cy-4:cy+4, cz-4:cz+4] = 500
    new_img = nib.Nifti1Image(arr, img.affine, img.header)
    nib.save(new_img, str(phantom_path))

    # Re-align manifest SHA so file_integrity_many_small does not fire first
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["source/phantom.nii.gz"] = _sha256_file(phantom_path)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "expected ok=False after mutating source/phantom.nii.gz"
    )
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    assert "TOTALSEGMENTATOR_REDERIVATION_MISMATCH" in combined, (
        f"expected TOTALSEGMENTATOR_REDERIVATION_MISMATCH in failures; "
        f"got: {result.failures}"
    )


def test_tamper_tooling_spec_fails_spec_sha(tmp_path: Path) -> None:
    """Appending whitespace to spec/tooling.json without realigning
    manifest.spec_files must trigger a spec-SHA failure from SpecShaPinCheck.

    json.loads ignores trailing whitespace so the parsed spec is unchanged
    and re-derivation could still succeed — but the bundle's integrity
    contract requires manifest-pinned SHAs to match on-disk bytes exactly.
    """
    bundle_dir = tmp_path / "ts_bundle_spec_tamper"
    build(bundle_dir)

    spec_path = bundle_dir / "spec" / "tooling.json"
    original = spec_path.read_text(encoding="utf-8")
    spec_path.write_text(original + "\n   \n", encoding="utf-8")

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False after appending whitespace to spec/tooling.json"
    )
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    assert (
        "SPEC_SHA_MISMATCH" in combined
        or "MISSING_SPEC_BLOB" in combined
        or ("SPEC" in combined and "SHA MISMATCH" in combined)
    ), (
        f"expected spec-SHA-mismatch indicator in failures; "
        f"got: {result.failures}"
    )
