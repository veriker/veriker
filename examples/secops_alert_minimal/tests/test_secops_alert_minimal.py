"""test_secops_alert_minimal.py — pilot tests for secops_alert_minimal.

Coverage:
  1. Happy-path build succeeds and produces expected files.
  2. Happy-path verify passes (exit 0, stdout contains "PASS").
  3. Tamper test: mutate payload/alert_classification.json final_label →
     verify detects mismatch (ALERT_REDERIVATION_MISMATCH).
  4. Dispatch-record wellformedness: tamper op.kind to unknown value →
     verify detects OP_KIND_OUT_OF_ENUM.
  5. Dispatch-record wellformedness: correct ALERT_CLASSIFY op_kind passes
     DispatchRecordWellformedCheck when registered with custom op_kinds_admitted.

Run from v-kernel-audit-bundle root:
    python -m pytest examples/secops_alert_minimal/tests/test_secops_alert_minimal.py -v
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Locate package root and pilot root
# ---------------------------------------------------------------------------

_PKG_ROOT = Path(__file__).resolve().parents[3]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

_PILOT_DIR = Path(__file__).resolve().parents[1]
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_VERIFY_SCRIPT = _PILOT_DIR / "verify.py"


# ---------------------------------------------------------------------------
# Helper: build a fresh bundle into a temp dir
# ---------------------------------------------------------------------------


def _build_bundle(out_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(out_dir)],
        capture_output=True,
        timeout=60,
    )


def _run_verify(bundle_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(_VERIFY_SCRIPT), "--bundle-dir", str(bundle_dir)],
        capture_output=True,
        timeout=60,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def bundle_dir(tmp_path_factory):
    """Build a fresh bundle once for the whole module; reuse across tests."""
    out_dir = tmp_path_factory.mktemp("secops_alert_bundle")
    result = _build_bundle(out_dir)
    assert result.returncode == 0, (
        f"_build_bundle.py exited {result.returncode}; "
        f"stderr={result.stderr.decode(errors='replace')}"
    )
    return out_dir


# ---------------------------------------------------------------------------
# Test 1: Build produces expected files
# ---------------------------------------------------------------------------


def test_build_produces_expected_files(bundle_dir: Path) -> None:
    expected = [
        bundle_dir / "inputs" / "alert_log.txt",
        bundle_dir / "inputs" / "rule_set.json",
        bundle_dir / "payload" / "alert_classification.json",
        bundle_dir / "payload" / "dispatch_records.jsonl",
        bundle_dir / "manifest.json",
    ]
    for p in expected:
        assert p.exists(), f"Expected file missing: {p}"


def test_build_manifest_structure(bundle_dir: Path) -> None:
    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "vcp-v1.1-canary4"
    assert manifest["bundle_id"] == "secops-alert-minimal-rc"
    assert "file_integrity_many_small" in manifest["typed_checks"]
    assert "dispatch_record_wellformed" in manifest["typed_checks"]
    assert "alert_classification_re_derivation" in manifest["typed_checks"]
    # dispatch_records must be in-manifest (not just sidecar)
    assert len(manifest["dispatch_records"]) == 2
    assert manifest["dispatch_records"][0]["op"]["kind"] == "RETRIEVAL"
    assert manifest["dispatch_records"][1]["op"]["kind"] == "ALERT_CLASSIFY"


def test_build_classification_is_true_positive(bundle_dir: Path) -> None:
    cls = json.loads(
        (bundle_dir / "payload" / "alert_classification.json").read_text(encoding="utf-8")
    )
    assert cls["final_label"] == "TRUE_POSITIVE"
    assert cls["aggregate_score"] >= 7
    assert len(cls["matched_rule_ids"]) >= 1


def test_build_fragment_anchors_present(bundle_dir: Path) -> None:
    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    anchors = manifest.get("fragment_anchors", {})
    # At least one fragment anchor per matched rule
    assert len(anchors) >= 1
    # All anchors should be ByteOffsetFragment kind
    for name, anchor in anchors.items():
        assert anchor["kind"] == "byte_offset", f"Anchor {name!r} has unexpected kind {anchor['kind']!r}"


# ---------------------------------------------------------------------------
# Test 2: Happy-path verify passes
# ---------------------------------------------------------------------------


def test_verify_passes(bundle_dir: Path) -> None:
    result = _run_verify(bundle_dir)
    stdout = result.stdout.decode(errors="replace")
    stderr = result.stderr.decode(errors="replace")
    assert result.returncode == 0, (
        f"verify.py exited {result.returncode}; stdout={stdout!r}; stderr={stderr!r}"
    )
    assert "PASS" in stdout, f"'PASS' not found in verify stdout: {stdout!r}"


# ---------------------------------------------------------------------------
# Test 3: Tamper test — mutate final_label → re-derivation fails
# ---------------------------------------------------------------------------


def test_tamper_final_label_fails_verify(tmp_path: Path) -> None:
    """Mutate final_label to 'FALSE_POSITIVE' — verifier must detect mismatch."""
    # Build a fresh bundle into a mutable temp dir
    build_result = _build_bundle(tmp_path)
    assert build_result.returncode == 0

    cls_path = tmp_path / "payload" / "alert_classification.json"
    cls_data = json.loads(cls_path.read_text(encoding="utf-8"))

    original_label = cls_data["final_label"]
    assert original_label == "TRUE_POSITIVE"

    # Tamper: flip label WITHOUT changing the SHA (content change that the
    # re-derivation plugin catches, not the file-integrity plugin).
    cls_data["final_label"] = "FALSE_POSITIVE"
    cls_path.write_text(json.dumps(cls_data, indent=2), encoding="utf-8")

    # Also update manifest.files SHA so FileIntegrityManySmall passes,
    # isolating the test to the re-derivation check.
    import hashlib
    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    new_sha = hashlib.sha256(cls_path.read_bytes()).hexdigest()
    manifest["files"]["payload/alert_classification.json"] = new_sha
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    result = _run_verify(tmp_path)
    assert result.returncode != 0, (
        "verify.py should have failed after tampering final_label but returned 0"
    )
    stderr = result.stderr.decode(errors="replace")
    assert "ALERT_REDERIVATION_MISMATCH" in stderr or "plugin_failed" in stderr, (
        f"Expected ALERT_REDERIVATION_MISMATCH in stderr; got: {stderr!r}"
    )


# ---------------------------------------------------------------------------
# Test 4: Dispatch-record tamper — unknown op.kind → OP_KIND_OUT_OF_ENUM
# ---------------------------------------------------------------------------


def test_tamper_dispatch_record_op_kind_fails_verify(tmp_path: Path) -> None:
    """Mutate dispatch_records[1].op.kind to an unknown value — C15 plugin rejects."""
    build_result = _build_bundle(tmp_path)
    assert build_result.returncode == 0

    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    # Tamper record 1's op.kind
    original_kind = manifest["dispatch_records"][1]["op"]["kind"]
    assert original_kind == "ALERT_CLASSIFY"
    manifest["dispatch_records"][1]["op"]["kind"] = "UNKNOWN_OP_KIND_XYZ"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    result = _run_verify(tmp_path)
    assert result.returncode != 0, (
        "verify.py should fail with unknown op.kind but returned 0"
    )
    stderr = result.stderr.decode(errors="replace")
    assert "OP_KIND_OUT_OF_ENUM" in stderr or "plugin_failed" in stderr, (
        f"Expected OP_KIND_OUT_OF_ENUM in stderr; got: {stderr!r}"
    )


# ---------------------------------------------------------------------------
# Test 5: DispatchRecordWellformedCheck — ALERT_CLASSIFY passes with custom enum
# ---------------------------------------------------------------------------


def test_dispatch_record_wellformed_alert_classify_admitted() -> None:
    """Unit test: DispatchRecordWellformedCheck admits ALERT_CLASSIFY when registered."""
    from audit_bundle.plugins.dispatch_record_wellformed import DispatchRecordWellformedCheck
    from audit_bundle.bundle_manifest import BundleManifest

    check = DispatchRecordWellformedCheck(
        op_kinds_admitted=frozenset({"ALERT_CLASSIFY", "RETRIEVAL", "COMPUTE"})
    )

    manifest = BundleManifest(
        schema_version="vcp-v1.1-canary4",
        bundle_id="test-secops",
        created_at="2026-05-10T00:00:00Z",
        files={},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=["dispatch_record_wellformed"],
        dispatch_records=(
            {
                "schema_version": "0.1",
                "op": {"kind": "RETRIEVAL"},
                "effect": {},
                "predicates": ["R001", "R002"],
                "outputs": [],
            },
            {
                "schema_version": "0.1",
                "op": {"kind": "ALERT_CLASSIFY"},
                "effect": {},
                "predicates": ["TRUE_POSITIVE"],
                "outputs": [],
            },
        ),
    )

    result = check.check(Path("."), manifest)
    assert result.ok, f"Expected PASS; got reason_code={result.reason_code!r} detail={result.detail!r}"
    assert result.reason_code == "PASS"


def test_dispatch_record_wellformed_default_enum_rejects_alert_classify() -> None:
    """Unit test: default enum (no ALERT_CLASSIFY) rejects it with OP_KIND_OUT_OF_ENUM."""
    from audit_bundle.plugins.dispatch_record_wellformed import DispatchRecordWellformedCheck
    from audit_bundle.bundle_manifest import BundleManifest

    # Default constructor — no custom op_kinds_admitted
    check = DispatchRecordWellformedCheck()

    manifest = BundleManifest(
        schema_version="vcp-v1.1-canary4",
        bundle_id="test-secops",
        created_at="2026-05-10T00:00:00Z",
        files={},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=["dispatch_record_wellformed"],
        dispatch_records=(
            {
                "schema_version": "0.1",
                "op": {"kind": "ALERT_CLASSIFY"},
                "effect": {},
                "predicates": ["TRUE_POSITIVE"],
                "outputs": [],
            },
        ),
    )

    result = check.check(Path("."), manifest)
    assert not result.ok, "Expected FAIL; default enum should reject ALERT_CLASSIFY"
    assert result.reason_code == "OP_KIND_OUT_OF_ENUM"
