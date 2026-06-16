"""Round-trip integration test for examples/dp_minimal.

Test flow:
  1. Build a clean bundle into a tmp_path.
  2. Run the verifier with the pilot's plugin set.
  3. Assert result.ok is True.
  4. Tamper test: mutate data/dataset.jsonl (flip one row's age_bucket so the
     true_count changes).  Assert verifier returns ok=False with
     DP_REDERIVATION_MISMATCH (or BAD_FILE_SHA from file_integrity) in failures.
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
_DP_MINIMAL = _PKG_ROOT / "examples" / "dp_minimal"

# Ensure the pilot directory is importable (for DpReDerivationCheck).
if str(_DP_MINIMAL) not in sys.path:
    sys.path.insert(0, str(_DP_MINIMAL))
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# ---------------------------------------------------------------------------
# Imports (after sys.path is set)
# ---------------------------------------------------------------------------

from examples.dp_minimal._build_bundle import build  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.verifier import BundleVerifier
from DpReDerivationCheck import DpReDerivationCheck  # type: ignore[import]  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(plugins=[FileIntegrityManySmall(), DpReDerivationCheck()])


# ---------------------------------------------------------------------------
# Happy-path test
# ---------------------------------------------------------------------------


def test_dp_minimal_build_and_verify(tmp_path: Path) -> None:
    """Build a dp_minimal bundle and verify it passes all checks."""
    bundle_dir = tmp_path / "dp_bundle"
    build(bundle_dir)

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is True, (
        f"Expected ok=True; failures: "
        + ", ".join(f"{f.check_name}/{f.reason_code}: {f.detail}" for f in result.failures)
    )


# ---------------------------------------------------------------------------
# Tamper test — mutate dataset so true_count changes
# ---------------------------------------------------------------------------


def test_dp_minimal_tamper_dataset_fails(tmp_path: Path) -> None:
    """Mutating dataset.jsonl must cause DP_REDERIVATION_MISMATCH (or BAD_FILE_SHA)."""
    bundle_dir = tmp_path / "dp_bundle_tampered"
    build(bundle_dir)

    # Flip the age_bucket of the first row whose age_bucket == "30-39" to "18-29"
    # so the predicate count changes.
    dataset_path = bundle_dir / "data" / "dataset.jsonl"
    lines = dataset_path.read_text(encoding="utf-8").splitlines()
    mutated = False
    for i, line in enumerate(lines):
        row = json.loads(line)
        if row.get("age_bucket") == "30-39":
            row["age_bucket"] = "18-29"
            lines[i] = json.dumps(row)
            mutated = True
            break

    assert mutated, "Test setup: expected at least one row with age_bucket='30-39'"
    dataset_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, "Expected verification to fail after dataset mutation"

    # Either file_integrity catches the SHA change, or dp_re_derivation detects the
    # count mismatch.  Accept either failure reason.
    failure_codes = " ".join(
        f"{f.reason_code} {f.detail}" for f in result.failures
    ).upper()
    assert "DP_REDERIVATION_MISMATCH" in failure_codes or "BAD_FILE_SHA" in failure_codes, (
        f"Expected DP_REDERIVATION_MISMATCH or BAD_FILE_SHA in failures; got: "
        + str([(f.check_name, f.reason_code) for f in result.failures])
    )
