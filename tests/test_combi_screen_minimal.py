"""Round-trip integration test for examples/combi_screen_minimal.

Test flow:
  1. Build a clean bundle into a tmp_path.
  2. Run the verifier with the pilot's plugin set.
  3. Assert result.ok is True.
  4. Tamper tests:
     a. Delete a rejected compound from the ledger (the money test) — re-derivation
        re-enumerates the full Cartesian product and finds the ledger one row short,
        firing COMBI_SCREEN_REDERIVATION_MISMATCH (ledger length mismatch).
     b. Mutate a survivor's score in the payload — re-derivation re-scores from the
        committed seed and detects the divergence.

Location convention: this pilot's pytest lives at PRODUCT-ROOT tests/ (mirrors
tests/test_dp_minimal.py), importing build + plugin classes from the example dir.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PKG_ROOT = Path(__file__).resolve().parents[1]  # v-kernel-audit-bundle/
_COMBI_MINIMAL = _PKG_ROOT / "examples" / "combi_screen_minimal"

# Ensure the pilot directory is importable (for CombiScreenReDerivationCheck).
if str(_COMBI_MINIMAL) not in sys.path:
    sys.path.insert(0, str(_COMBI_MINIMAL))
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# ---------------------------------------------------------------------------
# Imports (after sys.path is set)
# ---------------------------------------------------------------------------

from examples.combi_screen_minimal._build_bundle import build  # noqa: E402
from audit_bundle.plugins.dispatch_record_wellformed import (  # noqa: E402
    DispatchRecordWellformedCheck,
)
from audit_bundle.plugins.file_integrity_many_small import (  # noqa: E402
    FileIntegrityManySmall,
)
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from CombiScreenReDerivationCheck import CombiScreenReDerivationCheck  # type: ignore[import]  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            CombiScreenReDerivationCheck(),
            DispatchRecordWellformedCheck(
                op_kinds_admitted=frozenset({"DOCK_SCREEN", "COMPUTE"})
            ),
            StampLatticeCheck(),
        ]
    )


def _build_clean(tmp_path: Path, name: str = "combi_bundle") -> Path:
    bundle_dir = tmp_path / name
    build(bundle_dir)
    return bundle_dir


def _rewrite_payload(bundle_dir: Path, payload: dict, *, realign_sha: bool) -> None:
    """Write the mutated payload back; optionally re-align its manifest SHA so the
    re-derivation check (not file_integrity) is the surface that fires."""
    payload_path = bundle_dir / "payload" / "combi_screen_result.json"
    new_bytes = (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )
    payload_path.write_bytes(new_bytes)
    if realign_sha:
        manifest_path = bundle_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"]["payload/combi_screen_result.json"] = hashlib.sha256(
            new_bytes
        ).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
        )


# ---------------------------------------------------------------------------
# Happy-path tests
# ---------------------------------------------------------------------------


def test_combi_screen_build_and_verify(tmp_path: Path) -> None:
    """Build a combi_screen_minimal bundle and verify it passes all checks."""
    bundle_dir = _build_clean(tmp_path)
    result = _make_verifier().verify(bundle_dir)
    assert result.ok is True, "Expected ok=True; failures: " + ", ".join(
        f"{f.check_name}/{f.reason_code}: {f.detail}" for f in result.failures
    )


def test_combi_screen_ledger_shape(tmp_path: Path) -> None:
    """The payload must carry the full enumerated ledger + advanced set."""
    bundle_dir = _build_clean(tmp_path)
    payload = json.loads(
        (bundle_dir / "payload" / "combi_screen_result.json").read_text("utf-8")
    )
    # 5 scaffolds x 6 R1 x 5 R2 = 150 enumerated compounds.
    assert payload["enumerated_count"] == 150
    assert len(payload["ledger"]) == 150
    assert payload["passed_count"] == sum(
        1 for e in payload["ledger"] if e["filter_status"] == "passed"
    )
    assert payload["advanced_count"] == len(payload["advanced"])
    # Every advanced compound is a survivor (passed the Lipinski filter).
    advanced_ids = {a["compound_id"] for a in payload["advanced"]}
    by_id = {e["compound_id"]: e for e in payload["ledger"]}
    for cid in advanced_ids:
        assert by_id[cid]["filter_status"] == "passed"
        assert by_id[cid]["advanced"] is True
        assert by_id[cid]["score"] is not None


def test_combi_screen_deterministic(tmp_path: Path) -> None:
    """Building twice must produce byte-identical payloads (committed seed)."""
    a = _build_clean(tmp_path, "bundle_a")
    b = _build_clean(tmp_path, "bundle_b")
    pa = (a / "payload" / "combi_screen_result.json").read_bytes()
    pb = (b / "payload" / "combi_screen_result.json").read_bytes()
    assert pa == pb, "combi screen payload must be deterministic across builds"


# ---------------------------------------------------------------------------
# Tamper test — the money test: delete a rejected compound from the ledger
# ---------------------------------------------------------------------------


def test_combi_screen_delete_rejected_compound_fails(tmp_path: Path) -> None:
    """Drop a REJECTED compound from the ledger and re-align the manifest SHA.

    The complete reject ledger is the entire point of the bundle. Re-derivation
    re-enumerates the full Cartesian product, finds the ledger one row short, and
    fires COMBI_SCREEN_REDERIVATION_MISMATCH. You cannot silently disappear a
    compound you looked at and rejected.
    """
    bundle_dir = _build_clean(tmp_path, "bundle_deleted_reject")
    payload = json.loads(
        (bundle_dir / "payload" / "combi_screen_result.json").read_text("utf-8")
    )

    # Find the first rejected compound and remove it from the ledger.
    rejected_idx = next(
        (
            i
            for i, e in enumerate(payload["ledger"])
            if e["filter_status"].startswith("rejected")
        ),
        None,
    )
    assert rejected_idx is not None, (
        "Test setup: expected at least one rejected compound in the ledger"
    )
    removed = payload["ledger"].pop(rejected_idx)
    # Keep enumerated_count honest-looking too — adjust it down so the cheat tries
    # to be self-consistent (re-derivation must still catch it via re-enumeration).
    payload["enumerated_count"] = len(payload["ledger"])

    _rewrite_payload(bundle_dir, payload, realign_sha=True)

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False, (
        f"Expected verification to fail after deleting rejected compound "
        f"{removed['compound_id']}"
    )
    combined = " ".join(f"{f.reason_code} {f.detail}" for f in result.failures).upper()
    assert "COMBI_SCREEN_REDERIVATION_MISMATCH" in combined, (
        "Expected COMBI_SCREEN_REDERIVATION_MISMATCH in failures; got: "
        + str([(f.check_name, f.reason_code) for f in result.failures])
    )


# ---------------------------------------------------------------------------
# Tamper test — mutate a survivor's score in the payload
# ---------------------------------------------------------------------------


def test_combi_screen_mutate_score_fails(tmp_path: Path) -> None:
    """Change a survivor's score and re-align the manifest SHA — re-derivation
    re-scores from the committed seed and detects the divergence."""
    bundle_dir = _build_clean(tmp_path, "bundle_mutated_score")
    payload = json.loads(
        (bundle_dir / "payload" / "combi_screen_result.json").read_text("utf-8")
    )

    mutated = False
    for entry in payload["ledger"]:
        if entry["score"] is not None:
            entry["score"] = round(entry["score"] + 1.0, 6)  # shift by 1 kcal/mol
            mutated = True
            break
    assert mutated, "Test setup: expected at least one scored survivor"

    _rewrite_payload(bundle_dir, payload, realign_sha=True)

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False, "Expected verification to fail after mutating a score"
    combined = " ".join(f"{f.reason_code} {f.detail}" for f in result.failures).upper()
    assert "COMBI_SCREEN_REDERIVATION_MISMATCH" in combined, (
        "Expected COMBI_SCREEN_REDERIVATION_MISMATCH in failures; got: "
        + str([(f.check_name, f.reason_code) for f in result.failures])
    )
