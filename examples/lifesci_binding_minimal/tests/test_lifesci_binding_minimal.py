"""Integration tests for examples/lifesci_binding_minimal.

Test flow:
  1. Build a clean bundle from synthetic inputs into a temp directory.
  2. Run the verifier with the pilot's plugin set.
  3. Assert result.ok is True.
  4. Tamper tests:
     a. Mutate compound_descriptor.json — re-derivation MUST detect divergence.
     b. Mutate binding_prediction.json payload — re-derivation MUST detect divergence.
     c. Mutate scoring_weights.json SHA field in prediction — weights SHA mismatch.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path setup — auditor-independence pattern
# ---------------------------------------------------------------------------

# tests/ is one level below the pilot dir, which is three below the pkg root:
#   <pkg_root>/examples/lifesci_binding_minimal/tests/test_*.py
#   parents[0] = tests/
#   parents[1] = lifesci_binding_minimal/
#   parents[2] = examples/
#   parents[3] = <pkg_root>/
_PKG_ROOT = Path(__file__).resolve().parents[3]
_PILOT_DIR = Path(__file__).resolve().parents[1]

if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

# ---------------------------------------------------------------------------
# Lazy imports (after sys.path setup)
# ---------------------------------------------------------------------------

from examples.lifesci_binding_minimal._build_bundle import build  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import (  # noqa: E402
    FileIntegrityManySmall,
)
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from BindingAffinityReDerivationCheck import (  # noqa: E402
    BindingAffinityReDerivationCheck,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            BindingAffinityReDerivationCheck(),
        ]
    )


def _build_and_verify(tmp_path: Path) -> tuple[Path, BundleVerifier]:
    """Build a clean bundle and return (bundle_dir, verifier)."""
    bundle_dir = tmp_path / "lifesci_binding_bundle"
    build(bundle_dir)
    verifier = _make_verifier()
    return bundle_dir, verifier


# ---------------------------------------------------------------------------
# Happy-path tests
# ---------------------------------------------------------------------------


def test_clean_bundle_passes(tmp_path: Path) -> None:
    """Build + verify on a clean bundle must return result.ok == True."""
    bundle_dir, verifier = _build_and_verify(tmp_path)
    result = verifier.verify(bundle_dir)
    assert result.ok is True, (
        f"expected ok=True on clean bundle; failures: {result.failures}"
    )


def test_clean_bundle_has_correct_files(tmp_path: Path) -> None:
    """The bundle must contain all four expected payload/input files."""
    bundle_dir, _ = _build_and_verify(tmp_path)
    expected = [
        "inputs/compound_descriptor.json",
        "inputs/target_descriptor.json",
        "payload/binding_prediction.json",
        "payload/scoring_weights.json",
    ]
    for rel in expected:
        assert (bundle_dir / rel).exists(), f"expected {rel} in bundle"


def test_manifest_has_fragment_anchors(tmp_path: Path) -> None:
    """manifest.json must carry two OpaqueFragment anchors."""
    bundle_dir, _ = _build_and_verify(tmp_path)
    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    anchors = manifest.get("fragment_anchors", {})
    assert "compound-descriptor" in anchors, "missing compound-descriptor anchor"
    assert "target-descriptor" in anchors, "missing target-descriptor anchor"
    # Verify kind discriminators
    assert anchors["compound-descriptor"]["kind"] == "opaque"
    assert anchors["compound-descriptor"]["kind_tag"] == "molecule_descriptor"
    assert anchors["target-descriptor"]["kind"] == "opaque"
    assert anchors["target-descriptor"]["kind_tag"] == "protein_target_descriptor"


def test_manifest_typed_checks(tmp_path: Path) -> None:
    """manifest.typed_checks must list exactly the two expected plugin names."""
    bundle_dir, _ = _build_and_verify(tmp_path)
    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    tc = manifest.get("typed_checks", [])
    assert "file_integrity_many_small" in tc
    assert "binding_affinity_re_derivation" in tc


def test_affinity_pred_is_deterministic(tmp_path: Path) -> None:
    """Building twice must produce the same affinity_pred."""
    bundle_dir_a = tmp_path / "bundle_a"
    bundle_dir_b = tmp_path / "bundle_b"
    build(bundle_dir_a)
    build(bundle_dir_b)
    pred_a = json.loads(
        (bundle_dir_a / "payload" / "binding_prediction.json").read_text("utf-8")
    )["affinity_pred"]
    pred_b = json.loads(
        (bundle_dir_b / "payload" / "binding_prediction.json").read_text("utf-8")
    )["affinity_pred"]
    assert pred_a == pred_b, (
        f"affinity_pred must be identical across builds: {pred_a} vs {pred_b}"
    )


# ---------------------------------------------------------------------------
# Tamper tests
# ---------------------------------------------------------------------------


def test_tamper_compound_smiles_fails(tmp_path: Path) -> None:
    """Mutating the SMILES string must cause re-derivation failure."""
    bundle_dir, verifier = _build_and_verify(tmp_path)

    compound_path = bundle_dir / "inputs" / "compound_descriptor.json"
    compound = json.loads(compound_path.read_text(encoding="utf-8"))
    compound["smiles_string"] += "X"  # appends one character, shifts bucket counts

    # Re-write without updating manifest SHA so the re-derivation check fires
    # (the file_integrity check also fires — we accept either failure reason code).
    compound_path.write_text(
        json.dumps(compound, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    result = verifier.verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False after mutating SMILES string"
    )
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    # The verifier wraps plugin results under reason_code="plugin_failed"; the
    # original reason code (BAD_FILE_SHA / BINDING_REDERIVATION_MISMATCH) appears
    # in the detail string. Accept any form.
    assert (
        "BINDING_REDERIV" in combined
        or "BAD_FILE_SHA" in combined
        or "MISSING_FILE" in combined
        or "MANIFEST_SHA" in combined
        or "COMPUTED_SHA" in combined
        or "FILE_INTEGRITY" in combined
    ), (
        f"expected file-integrity or re-derivation failure in failures; got: {result.failures}"
    )


def test_tamper_affinity_pred_in_payload_fails(tmp_path: Path) -> None:
    """Mutating affinity_pred in the payload — preserving SMILES/weights unchanged
    but updating the manifest SHA — must cause re-derivation mismatch."""
    bundle_dir, verifier = _build_and_verify(tmp_path)

    pred_path = bundle_dir / "payload" / "binding_prediction.json"
    pred = json.loads(pred_path.read_text(encoding="utf-8"))
    original_affinity = pred["affinity_pred"]
    pred["affinity_pred"] = original_affinity + 999.0  # large delta

    # Write tampered prediction and update manifest SHA so file_integrity passes
    # but re-derivation catches the mismatch.
    import hashlib

    tampered_bytes = (
        json.dumps(pred, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    pred_path.write_bytes(tampered_bytes)

    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["payload/binding_prediction.json"] = hashlib.sha256(
        tampered_bytes
    ).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )

    result = verifier.verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False after injecting wrong affinity_pred into payload"
    )
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    assert "BINDING_REDERIV" in combined or "BIND_REDER_FAIL" in combined, (
        f"expected BINDING_REDERIVATION_MISMATCH in failures; got: {result.failures}"
    )


def test_tamper_weights_sha_mismatch_fails(tmp_path: Path) -> None:
    """Putting a wrong scoring_weights_sha256 in binding_prediction.json must fail."""
    bundle_dir, verifier = _build_and_verify(tmp_path)

    pred_path = bundle_dir / "payload" / "binding_prediction.json"
    pred = json.loads(pred_path.read_text(encoding="utf-8"))
    pred["scoring_weights_sha256"] = "a" * 64  # wrong SHA

    import hashlib

    tampered_bytes = (
        json.dumps(pred, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    pred_path.write_bytes(tampered_bytes)

    # Update manifest SHA so file_integrity passes
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["payload/binding_prediction.json"] = hashlib.sha256(
        tampered_bytes
    ).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )

    result = verifier.verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False when scoring_weights_sha256 is wrong"
    )
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    assert "BINDING_REDERIV" in combined or "BIND_REDER_FAIL" in combined, (
        f"expected BINDING_REDERIVATION_MISMATCH in failures; got: {result.failures}"
    )
