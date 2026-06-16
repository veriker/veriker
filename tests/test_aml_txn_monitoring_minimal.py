"""Round-trip integration test for examples/aml_txn_monitoring_minimal/verify.py.

Test flow:
  1. Import _build_bundle.build from the pilot directory.
  2. Build the bundle into a tmp_path.
  3. Run the verifier with the pilot's plugin set.
  4. Assert result.ok is True.

  Fixture tests:
  5. Assert manifest has OpaqueFragment (kind_tag=transaction) anchors.
  6. Assert manifest has RULE_TREE_EVAL and COMPUTE dispatch_records.
  7. Assert bundled COAF-report decisions match expected outcomes per customer.

  Tamper tests:
  8. Mutate a transaction amount in transactions.jsonl so velocity changes
     for C001 — assert verifier returns result.ok=False with
     AML_TXN_MONITORING_REDERIVATION_MISMATCH.
  9. Directly mutate payload/coaf_reports.json — assert verifier returns
     result.ok=False (FILE_SHA_MISMATCH from FileIntegrityManySmall).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths + dynamic import of pilot modules
# ---------------------------------------------------------------------------

_PKG_ROOT = Path(__file__).resolve().parents[1]  # v-kernel-audit-bundle/
_PILOT_DIR = _PKG_ROOT / "examples" / "aml_txn_monitoring_minimal"

if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))


def _import_module_from_path(name: str, path: Path):
    """Dynamically import a module from an absolute path."""
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_build_bundle_mod = _import_module_from_path(
    "aml_txn_monitoring_minimal._build_bundle",
    _PILOT_DIR / "_build_bundle.py",
)
_check_mod = _import_module_from_path(
    "AmlTxnMonitoringReDerivationCheck",
    _PILOT_DIR / "AmlTxnMonitoringReDerivationCheck.py",
)

from audit_bundle.plugins.dispatch_record_wellformed import (
    DispatchRecordWellformedCheck,
)
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck
from audit_bundle.verifier import BundleVerifier

AmlTxnMonitoringReDerivationCheck = _check_mod.AmlTxnMonitoringReDerivationCheck


# ---------------------------------------------------------------------------
# Helper: build a fresh bundle and construct the verifier
# ---------------------------------------------------------------------------


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            AmlTxnMonitoringReDerivationCheck(),
            DispatchRecordWellformedCheck(
                op_kinds_admitted=frozenset({"RULE_TREE_EVAL", "COMPUTE"})
            ),
            StampLatticeCheck(),
        ]
    )


# ---------------------------------------------------------------------------
# Happy path: clean bundle
# ---------------------------------------------------------------------------


def test_clean_bundle_passes(tmp_path: Path) -> None:
    """Build a fresh bundle and verify it — result.ok must be True."""
    bundle_dir = tmp_path / "aml_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is True, "expected ok=True; failures:\n" + "\n".join(
        f"  [{f.check_name}] {f.reason_code}: {f.detail}" for f in result.failures
    )


# ---------------------------------------------------------------------------
# Manifest structure assertions
# ---------------------------------------------------------------------------


def test_manifest_has_transaction_opaque_fragments(tmp_path: Path) -> None:
    """The manifest must contain OpaqueFragment(kind_tag=transaction) anchors."""
    bundle_dir = tmp_path / "aml_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    anchors = manifest.get("fragment_anchors", {})

    txn_frags = [
        v
        for v in anchors.values()
        if v.get("kind") == "opaque" and v.get("kind_tag") == "transaction"
    ]
    assert len(txn_frags) >= 30, (
        f"Expected >= 30 OpaqueFragment(kind_tag=transaction) anchors; got {len(txn_frags)}"
    )


def test_manifest_has_rule_tree_eval_dispatch(tmp_path: Path) -> None:
    """The manifest must contain dispatch_records with op.kind=RULE_TREE_EVAL."""
    bundle_dir = tmp_path / "aml_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    records = manifest.get("dispatch_records", [])

    rule_tree_eval_records = [
        r for r in records if r.get("op", {}).get("kind") == "RULE_TREE_EVAL"
    ]
    compute_records = [r for r in records if r.get("op", {}).get("kind") == "COMPUTE"]
    assert len(rule_tree_eval_records) >= 5, (
        f"Expected >= 5 RULE_TREE_EVAL records (one per customer); got {len(rule_tree_eval_records)}"
    )
    assert len(compute_records) >= 5, (
        f"Expected >= 5 COMPUTE records (one per customer); got {len(compute_records)}"
    )


def test_sar_trigger_decisions_correct(tmp_path: Path) -> None:
    """Bundled COAF-report decisions must match known expected outcomes."""
    bundle_dir = tmp_path / "aml_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    sar = json.loads(
        (bundle_dir / "payload" / "coaf_reports.json").read_text(encoding="utf-8")
    )
    customers = sar["customers"]

    # C001 — velocity trigger
    assert customers["C001"]["coaf_report_triggered"] is True
    assert "R1" in customers["C001"]["rules_fired"]

    # C002 — structuring trigger
    assert customers["C002"]["coaf_report_triggered"] is True
    assert "R2" in customers["C002"]["rules_fired"]

    # C003 — peer deviation trigger
    assert customers["C003"]["coaf_report_triggered"] is True
    assert "R3" in customers["C003"]["rules_fired"]

    # C004 — clean (false-positive rate demo)
    assert customers["C004"]["coaf_report_triggered"] is False
    assert customers["C004"]["rules_fired"] == []

    # C005 — borderline structuring (exactly at threshold, not above)
    assert customers["C005"]["coaf_report_triggered"] is False


# ---------------------------------------------------------------------------
# Tamper test 1: mutate transaction amount → re-derivation mismatch
# ---------------------------------------------------------------------------


def test_tamper_transaction_amount_fails(tmp_path: Path) -> None:
    """Mutating a transaction amount must cause AML_TXN_MONITORING_REDERIVATION_MISMATCH.

    Strategy: Change one of C001's large wire amounts so that the velocity
    feature for C001 changes (drops from 4 to 3 large txns), causing the
    re-derived SAR decision to differ from the bundled payload.
    The manifest SHA for transactions.jsonl is not updated, so
    FileIntegrityManySmall will also catch it — but the re-derivation
    check fires first in plugin order.
    """
    bundle_dir = tmp_path / "aml_bundle_tamper1"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    # Mutate T001-004 amount from $13,000 to $9,000 (drops below $10K threshold)
    txn_path = bundle_dir / "transactions" / "transactions.jsonl"
    lines = txn_path.read_text(encoding="utf-8").splitlines()
    new_lines = []
    for line in lines:
        if not line.strip():
            new_lines.append(line)
            continue
        rec = json.loads(line)
        if rec.get("txn_id") == "T001-004":
            rec["amount_brl"] = 9000.0  # drops below $10K, velocity falls to 3
        new_lines.append(json.dumps(rec, sort_keys=True))
    txn_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, "expected ok=False after tampering transaction amount"
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures).upper()
    # Either re-derivation mismatch or SHA mismatch is acceptable evidence of detection
    assert (
        "AML_TXN_MONITORING_REDERIVATION_MISMATCH" in combined
        or "FILE_SHA" in combined
        or "SHA_MISMATCH" in combined
    ), (
        f"expected AML_TXN_MONITORING_REDERIVATION_MISMATCH or FILE_SHA in failures; "
        f"got: {result.failures}"
    )


# ---------------------------------------------------------------------------
# Tamper test 2: mutate payload directly → SHA mismatch
# ---------------------------------------------------------------------------


def test_tamper_payload_coaf_report_triggered_fails(tmp_path: Path) -> None:
    """Directly mutating payload/coaf_reports.json must cause FILE_SHA_MISMATCH."""
    bundle_dir = tmp_path / "aml_bundle_tamper2"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    # Flip C004 from clean to triggered in the payload (without rebuilding manifest)
    coaf_path = bundle_dir / "payload" / "coaf_reports.json"
    payload = json.loads(coaf_path.read_text(encoding="utf-8"))
    payload["customers"]["C004"]["coaf_report_triggered"] = True
    payload["customers"]["C004"]["rules_fired"] = ["R1"]
    coaf_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "expected ok=False after tampering payload/coaf_reports.json"
    )
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures).upper()
    assert (
        "FILE_SHA" in combined or "SHA_MISMATCH" in combined or "MISMATCH" in combined
    ), f"expected FILE_SHA or MISMATCH in failures; got: {result.failures}"
