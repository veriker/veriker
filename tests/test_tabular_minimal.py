"""Round-trip integration test for examples/tabular_minimal/verify.py.

Test flow:
  1. Build a clean bundle from the synthetic sales CSV into a temp directory.
  2. Run the verifier with the pilot's plugin set.
  3. Assert result.ok is True.
  4. Tamper test: mutate one row's revenue value in data/sales.csv, re-align
     the manifest SHA so FileIntegrity passes, assert TABULAR_REDERIVATION_MISMATCH
     (or TABULAR_REDER_FAIL) appears in the failures.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PKG_ROOT = Path(__file__).resolve().parents[1]  # v-kernel-audit-bundle/
_PILOT_DIR = _PKG_ROOT / "examples" / "tabular_minimal"

# Ensure both pkg root and pilot dir are importable
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

# ---------------------------------------------------------------------------
# Lazy imports (after path setup)
# ---------------------------------------------------------------------------

from examples.tabular_minimal._build_bundle import build  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from TabularReDerivationCheck import TabularReDerivationCheck  # noqa: E402

import json  # noqa: E402


# ---------------------------------------------------------------------------
# Helper: build a verifier with the tabular plugin set
# ---------------------------------------------------------------------------


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(plugins=[
        SpecShaPinCheck(),
        FileIntegrityManySmall(),
        TabularReDerivationCheck(),
    ])


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_clean_bundle_passes(tmp_path: Path) -> None:
    """build + verify on a clean bundle must return result.ok == True."""
    bundle_dir = tmp_path / "tabular_bundle"
    build(bundle_dir)
    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is True, (
        f"expected ok=True; failures: {result.failures}"
    )


def test_tamper_sales_revenue_fails(tmp_path: Path) -> None:
    """Mutating one row's revenue in sales.csv (with manifest SHA re-aligned)
    must trigger TABULAR_REDERIVATION_MISMATCH or TABULAR_REDER_FAIL."""
    bundle_dir = tmp_path / "tabular_bundle_tamper"
    build(bundle_dir)

    sales_path = bundle_dir / "data" / "sales.csv"
    original_bytes = sales_path.read_bytes()

    # Tamper: change one revenue value so the re-derived aggregate differs.
    # Row 0: region=NA, product=A, units=1, revenue=100
    # Replace first data-row revenue 100 with 999.
    # Use a targeted replacement that changes exactly one row's revenue field.
    tampered_bytes = original_bytes.replace(b"NA,A,1,100\n", b"NA,A,1,999\n", 1)
    assert tampered_bytes != original_bytes, (
        "Tamper did not modify the file — test setup error"
    )
    sales_path.write_bytes(tampered_bytes)

    # Re-align the manifest SHA so FileIntegrityManySmall passes.
    # The re-derivation check will then catch the mismatch.
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["data/sales.csv"] = hashlib.sha256(tampered_bytes).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "expected ok=False after tampering sales.csv revenue"
    )

    # Accept either the reason_code or the [TABULAR_REDER_FAIL] stderr tag
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    assert "TABULAR_REDERIV" in combined or "TABULAR_REDER_FAIL" in combined, (
        f"expected TABULAR_REDERIVATION_MISMATCH or TABULAR_REDER_FAIL in failures; "
        f"got: {result.failures}"
    )


def test_tamper_spec_query_fails_spec_sha(tmp_path: Path) -> None:
    """Mutate spec/query.json with a SHA-changing-but-semantics-preserving edit
    (trailing whitespace; ignored by json.loads). manifest.spec_files SHA is NOT
    realigned, so SpecShaPinCheck catches the divergence in isolation — re-derivation
    still passes because parsed JSON is identical.
    """
    bundle_dir = tmp_path / "tabular_bundle_spec_tamper"
    build(bundle_dir)

    spec_path = bundle_dir / "spec" / "query.json"
    original = spec_path.read_text(encoding="utf-8")
    spec_path.write_text(original + "\n   \n", encoding="utf-8")

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False after tampering spec/query.json without realigning manifest.spec_files"
    )
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    assert (
        "SPEC_SHA_MISMATCH" in combined
        or "MISSING_SPEC_BLOB" in combined
        or ("SPEC" in combined and "SHA MISMATCH" in combined)
    ), f"expected spec-SHA-mismatch indicator in failures; got: {result.failures}"
