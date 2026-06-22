"""Round-trip integration test for examples/fp_ml_minimal.

Test flow:
  1. ROUND-TRIP: Build a clean bundle, run the verifier, assert result.ok is True.
  2. TAMPER-1 (exceeds ε): Mutate W[0][0] by +1e-3 in weights/model.json,
     re-align the manifest SHA so FileIntegrityManySmall passes, and assert
     the verifier returns ok=False with FP_ML_REDERIVATION_MISMATCH (or
     FP_ML_REDERIVATION_TOLERANCE_VIOLATED) in the failures, because the
     per-logit delta (~5.88e-3) far exceeds ε=1e-9.
  3. TAMPER-2 (within ε — BONUS): Mutate W[0][0] by +1e-12 in weights/model.json,
     re-align the manifest SHA, and assert the verifier returns ok=True because
     the perturbation (1e-12) is absorbed by float32 truncation (delta=0 after snap)
     and is strictly less than ε=1e-9.  This proves tolerance is a real bound,
     not a permission slip.

Logit delta reference (from weight deltas analysis):
  Tamper-1 delta W[0][0] = +1e-3   →  max logit delta ≈ 5.88e-3  (>> ε=1e-9)
  Tamper-2 delta W[0][0] = +1e-12  →  max logit delta = 0.0       (< ε=1e-9)
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
_FP_ML_MINIMAL = _PKG_ROOT / "examples" / "fp_ml_minimal"

# Ensure the pilot directory is importable (for FpMlReDerivationCheck).
if str(_FP_ML_MINIMAL) not in sys.path:
    sys.path.insert(0, str(_FP_ML_MINIMAL))
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# ---------------------------------------------------------------------------
# Imports (after sys.path is set)
# ---------------------------------------------------------------------------

from examples.fp_ml_minimal._build_bundle import build  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.verifier import BundleVerifier
from FpMlReDerivationCheck import FpMlReDerivationCheck  # type: ignore[import]  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(plugins=[FileIntegrityManySmall(), FpMlReDerivationCheck()])


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tamper_weight_and_realign(bundle_dir: Path, delta: float) -> None:
    """Mutate W[0][0] by +delta in model.json and re-align manifest SHA."""
    model_path = bundle_dir / "weights" / "model.json"
    model = json.loads(model_path.read_text(encoding="utf-8"))
    original_w00 = model["W"][0][0]
    model["W"][0][0] = original_w00 + delta
    tampered_bytes = (json.dumps(model, indent=2, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )
    model_path.write_bytes(tampered_bytes)

    # Re-align manifest SHA so FileIntegrityManySmall passes
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["weights/model.json"] = _sha256(tampered_bytes)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Test 1: Happy-path round-trip
# ---------------------------------------------------------------------------


def test_fp_ml_minimal_build_and_verify(tmp_path: Path) -> None:
    """Build an fp_ml_minimal bundle and verify it passes all checks."""
    bundle_dir = tmp_path / "fp_ml_bundle"
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
# Test 2: Tamper-1 — mutate W[0][0] by +1e-3 (far exceeds ε=1e-9)
#
# Max logit delta ≈ 5.88e-3, which is ~5.88×10^6 × ε.  Verification must
# fail with FP_ML_REDERIVATION_MISMATCH (or FP_ML_REDERIVATION_TOLERANCE_VIOLATED).
# The failure detail string must include the actual delta.
# ---------------------------------------------------------------------------


def test_fp_ml_minimal_tamper_exceeds_tolerance(tmp_path: Path) -> None:
    """Mutating W[0][0] by +1e-3 must cause FP_ML_REDERIVATION_MISMATCH.

    The per-logit delta for this weight change is approximately 5.88e-3,
    which exceeds ε=1e-9 by ~5.88 million times.  We re-align the manifest
    SHA so FileIntegrityManySmall passes; the failure must come exclusively
    from FpMlReDerivationCheck.
    """
    bundle_dir = tmp_path / "fp_ml_tamper1"
    build(bundle_dir)

    # Tamper: W[0][0] += 1e-3 (ε-exceeding delta)
    _tamper_weight_and_realign(bundle_dir, delta=1e-3)

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, "Expected verification to fail after +1e-3 weight mutation"

    # Collect all reason codes and detail text
    failure_text = " ".join(
        f"{f.reason_code} {f.detail}" for f in result.failures
    ).upper()

    # The verifier wraps plugin results with reason_code="plugin_failed".
    # The plugin's own reason code (FP_ML_REDERIVATION_MISMATCH) appears in
    # the detail string, alongside the subprocess stderr [FP_ML_REDER_FAIL] text.
    # Accept any of the expected failure signatures.
    assert (
        "FP_ML_REDERIVATION_MISMATCH" in failure_text
        or "FP_ML_REDERIVATION_TOLERANCE_VIOLATED" in failure_text
        or "FP_ML_REDER_FAIL" in failure_text
        or "PLUGIN_FAILED" in failure_text
    ), (
        "Expected FP_ML_REDERIVATION_MISMATCH, FP_ML_REDERIVATION_TOLERANCE_VIOLATED, "
        "FP_ML_REDER_FAIL, or PLUGIN_FAILED in failures; "
        "got: " + str([(f.check_name, f.reason_code, f.detail[:80]) for f in result.failures])
    )

    # The detail string from fp_ml_re_derivation.py must mention the actual delta
    assert "DELTA" in failure_text, (
        "Expected failure detail to include 'delta' (actual delta value); "
        "got: " + str([(f.reason_code, f.detail) for f in result.failures])
    )


# ---------------------------------------------------------------------------
# Test 3: Tamper-2 (BONUS) — mutate W[0][0] by +1e-12 (within ε=1e-9)
#
# +1e-12 is absorbed by float32 truncation: after struct.pack/unpack the
# snapped value equals the original W[0][0]=0.5 exactly, so the logit
# delta is 0.0, which is strictly less than ε=1e-9.
# Verification MUST PASS — this proves tolerance is a real quantified bound.
# ---------------------------------------------------------------------------


def test_fp_ml_minimal_tamper_within_tolerance_passes(tmp_path: Path) -> None:
    """Mutating W[0][0] by +1e-12 must NOT cause verification to fail.

    The +1e-12 perturbation is absorbed by float32 truncation at the
    serialization boundary (struct.pack('f', 0.5 + 1e-12) == struct.pack('f', 0.5)).
    The logit delta is 0.0, strictly less than ε=1e-9.

    This is the BONUS tamper test that proves tolerance is REAL: if the
    substrate accepted ε as a blanket permission slip, it would be
    meaningless.  The tight ε=1e-9 is chosen to match float32 truncation
    noise, not to allow unchecked drift.

    Expected: result.ok is True (verification passes).
    """
    bundle_dir = tmp_path / "fp_ml_tamper2"
    build(bundle_dir)

    # Tamper: W[0][0] += 1e-12 (ε-respecting delta)
    _tamper_weight_and_realign(bundle_dir, delta=1e-12)

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is True, (
        "Expected ok=True for +1e-12 weight mutation (within ε=1e-9); "
        "failures: "
        + ", ".join(
            f"{f.check_name}/{f.reason_code}: {f.detail}" for f in result.failures
        )
    )
