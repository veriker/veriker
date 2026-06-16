"""Round-trip integration test for examples/ml_minimal.

Test flow:
  1. Build a clean bundle into a tmp_path.
  2. Run the verifier with the pilot's plugin set.
  3. Assert result.ok is True.
  4. Tamper test: mutate W[0][0] in weights/model.json from 3 to 2 (a
     one-element change), re-align the SHA in the manifest so
     FileIntegrityManySmall does not catch the file-level change, and assert
     the verifier returns ok=False with ML_REDERIVATION_MISMATCH in failures
     because the predicted class for input_idx=6 flips from 1 to 2.
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
_ML_MINIMAL = _PKG_ROOT / "examples" / "ml_minimal"

# Ensure the pilot directory is importable (for MlReDerivationCheck).
if str(_ML_MINIMAL) not in sys.path:
    sys.path.insert(0, str(_ML_MINIMAL))
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# ---------------------------------------------------------------------------
# Imports (after sys.path is set)
# ---------------------------------------------------------------------------

from examples.ml_minimal._build_bundle import build  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.verifier import BundleVerifier
from MlReDerivationCheck import MlReDerivationCheck  # type: ignore[import]  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(plugins=[FileIntegrityManySmall(), MlReDerivationCheck()])


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Happy-path test
# ---------------------------------------------------------------------------


def test_ml_minimal_build_and_verify(tmp_path: Path) -> None:
    """Build an ml_minimal bundle and verify it passes all checks."""
    bundle_dir = tmp_path / "ml_bundle"
    build(bundle_dir)

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is True, (
        "Expected ok=True; failures: "
        + ", ".join(
            f"{f.check_name}/{f.reason_code}: {f.detail}" for f in result.failures
        )
    )


# ---------------------------------------------------------------------------
# Tamper test — mutate W[0][0] and re-align the manifest SHA so the file
# integrity plugin passes but the re-derivation plugin catches the mismatch.
# ---------------------------------------------------------------------------


def test_ml_minimal_tamper_weight_fails(tmp_path: Path) -> None:
    """Mutating W[0][0] (3→2) must cause ML_REDERIVATION_MISMATCH.

    W[0][0]=3→2 flips the predicted class at input_idx=6 from 1 to 2.
    We re-align the weights/model.json SHA in the manifest so that
    FileIntegrityManySmall passes and the failure is caught exclusively by
    MlReDerivationCheck, exercising the re-derivation plugin path.
    """
    bundle_dir = tmp_path / "ml_bundle_tampered"
    build(bundle_dir)

    # --- Mutate W[0][0]: 3 → 2 ---
    model_path = bundle_dir / "weights" / "model.json"
    model = json.loads(model_path.read_text(encoding="utf-8"))
    assert model["W"][0][0] == 3, "Precondition: W[0][0] must be 3 as built"
    model["W"][0][0] = 2
    tampered_bytes = (json.dumps(model, indent=2, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )
    model_path.write_bytes(tampered_bytes)

    # --- Re-align manifest SHA so file integrity passes ---
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["weights/model.json"] = _sha256(tampered_bytes)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # --- Verify: should fail at re-derivation ---
    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, "Expected verification to fail after weight mutation"

    failure_codes = " ".join(
        f"{f.reason_code} {f.detail}" for f in result.failures
    ).upper()
    assert "ML_REDERIVATION_MISMATCH" in failure_codes or "ML_REDER_FAIL" in failure_codes, (
        "Expected ML_REDERIVATION_MISMATCH or ML_REDER_FAIL in failures; got: "
        + str([(f.check_name, f.reason_code) for f in result.failures])
    )
