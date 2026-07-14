"""Round-trip integration test for examples/bom_minimal/verify.py.

Test flow:
  1. Build a clean bundle from the synthetic lockfile into a temp directory.
  2. Run the verifier with the pilot's plugin set.
  3. Assert result.ok is True.
  4. Tamper test: mutate one package's hash in lockfile/lockfile.json.
  5. Re-run the verifier.
  6. Assert result.ok is False with BOM_REDERIVATION_MISMATCH in failures.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PKG_ROOT = Path(__file__).resolve().parents[1]  # v-kernel-audit-bundle/
_PILOT_DIR = _PKG_ROOT / "examples" / "bom_minimal"

# Ensure both pkg root and pilot dir are importable
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

# ---------------------------------------------------------------------------
# Lazy imports (after path setup)
# ---------------------------------------------------------------------------

from examples.bom_minimal._build_bundle import build  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from BomReDerivationCheck import BomReDerivationCheck  # noqa: E402


# ---------------------------------------------------------------------------
# Helper: build a fresh bundle and run the verifier
# ---------------------------------------------------------------------------


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(plugins=[
        FileIntegrityManySmall(),
        BomReDerivationCheck(),
    ])


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_clean_bundle_passes(tmp_path: Path) -> None:
    """build + verify on a clean bundle must return result.ok == True."""
    bundle_dir = tmp_path / "bom_bundle"
    build(bundle_dir)
    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is True, (
        f"expected ok=True; failures: {result.failures}"
    )


def test_tamper_lockfile_hash_fails(tmp_path: Path) -> None:
    """Mutating one package's hash in lockfile.json must trigger BOM_REDERIVATION_MISMATCH."""
    bundle_dir = tmp_path / "bom_bundle_tamper"
    build(bundle_dir)

    # Tamper: overwrite lodash's hash in the lockfile
    lockfile_path = bundle_dir / "lockfile" / "lockfile.json"
    lockfile = json.loads(lockfile_path.read_text(encoding="utf-8"))
    lockfile["packages"]["lodash@4.17.21"]["hash"] = "sha256:deadbeefdeadbeefdeadbeef"
    lockfile_path.write_text(json.dumps(lockfile, indent=2), encoding="utf-8")

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "expected ok=False after tampering lockfile hash"
    )
    # The bom_re_derivation plugin failure wraps its reason_code ("BOM_REDERIVATION_MISMATCH")
    # or the [BOM_REDER_FAIL] stderr tag into the detail field of the enclosing PluginFailed
    # VerifyFailure.  Accept either form so the check is robust to wrapping depth.
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    assert "BOM_REDERIV" in combined or "BOM_REDER_FAIL" in combined, (
        f"expected BOM_REDERIVATION_MISMATCH or BOM_REDER_FAIL in failures; got: {result.failures}"
    )
