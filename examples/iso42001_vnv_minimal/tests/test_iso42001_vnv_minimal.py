"""tests/test_iso42001_vnv_minimal.py — tamper + §4a attack tests.

ISO/IEC 42001 A.6 V&V metric re-derivation pilot. Covers four tamper surfaces:

  1. Happy path: build -> verify -> result.ok is True.

  2. Metric-mutation: inflate the claimed AUC in
     outputs/model_validation_auc.json by +0.05 (and re-align manifest SHA so
     only the recompute mismatch fires) -> result.ok is False,
     REDERIVATION_MISMATCH. The headline: you cannot doctor the reported metric.

  3. Test-set tamper: edit a score in inputs/test_set.json so the recomputed
     AUC changes, WITHOUT updating manifest.files -> BAD_FILE_SHA fires; the
     recompute also disagrees, so REDERIVATION_MISMATCH fires too.

  4. Producer-supplied weaker spec rejected (Axis-1 anchor): a weak spec with
     epsilon=1e30 is shipped in the bundle with a tampered claimed AUC the weak
     spec would accept. The auditor SpecAnchor is computed from the COMMITTED
     strong spec (epsilon=1e-9), so the weak spec's SHA is not anchored ->
     AnchorViolation, fail-closed.

Also asserts the honest re-derivability claim boundary in a focused unit test on
compute_roc_auc (known tie-aware AUC value).

Auditor-independence sys.path shim: parents[2] of the test file is the
v-kernel-audit-bundle package root; the pilot's primitive module lives in
parents[1].
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# sys.path setup (auditor-independence: no installed package required)
# ---------------------------------------------------------------------------

_TEST_DIR = Path(__file__).resolve().parent
_PILOT_DIR = _TEST_DIR.parent
_PKG_ROOT = _PILOT_DIR.parents[1]  # …/v-kernel-audit-bundle

if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.rederivation.registry import register_primitive  # noqa: E402
from audit_bundle.rederivation.spec_binding import SpecAnchor  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
import iso42001_auc_recompute as _prim_mod  # noqa: E402

# Register the primitive once per process (idempotent).
register_primitive(_prim_mod.Iso42001AucRecompute())

_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "iso42001_vnv.spec.json"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_CLAIM_REL = "outputs/model_validation_auc.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build(out_dir: Path) -> None:
    """Run the real _build_bundle.py to produce a fresh bundle in out_dir."""
    subprocess.run(
        [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(out_dir)],
        capture_output=True,
        check=True,
    )


def _anchor_from_committed_spec() -> SpecAnchor:
    """Derive the auditor SpecAnchor from the COMMITTED source spec file."""
    raw = _SPEC_SRC.read_bytes()
    doc = json.loads(raw)
    spec_id = doc["spec_id"]
    sha = hashlib.sha256(raw).hexdigest()
    return SpecAnchor(allowed={spec_id: sha})


def _verifier(anchor: SpecAnchor | None = None) -> BundleVerifier:
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()],
        spec_anchor=anchor if anchor is not None else _anchor_from_committed_spec(),
    )


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


# ---------------------------------------------------------------------------
# Unit — compute_roc_auc on a known tie-aware case
# ---------------------------------------------------------------------------


def test_compute_roc_auc_known_value():
    """Perfect separation -> AUC 1.0; one swapped pair drops it predictably."""
    perfect = [
        {"label": 1, "score": 0.9},
        {"label": 1, "score": 0.8},
        {"label": 0, "score": 0.4},
        {"label": 0, "score": 0.3},
    ]
    assert _prim_mod.compute_roc_auc(perfect) == 1.0

    # One positive (0.35) now ranks below one negative (0.40): 1 of 4 pairs
    # mis-ordered -> AUC = 3/4.
    swapped = [
        {"label": 1, "score": 0.9},
        {"label": 1, "score": 0.35},
        {"label": 0, "score": 0.4},
        {"label": 0, "score": 0.3},
    ]
    assert _prim_mod.compute_roc_auc(swapped) == 0.75

    # Tie between a positive and a negative at the SAME score contributes 0.5.
    tie = [
        {"label": 1, "score": 0.5},
        {"label": 0, "score": 0.5},
    ]
    assert _prim_mod.compute_roc_auc(tie) == 0.5


# ---------------------------------------------------------------------------
# Test 1 — Happy path: honest build -> PASS
# ---------------------------------------------------------------------------


def test_honest_pass(tmp_path):
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)
    result = _verifier().verify(bundle_dir)
    assert result.ok, [
        (f.check_name, f.reason_code, f.detail) for f in result.failures
    ]


# ---------------------------------------------------------------------------
# Test 2 — Metric-mutation: claimed AUC inflated by +0.05 -> FAIL
# ---------------------------------------------------------------------------


def test_metric_mutation_fails(tmp_path):
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)

    claim_path = bundle_dir / _CLAIM_REL
    claim_doc = json.loads(claim_path.read_bytes())
    tampered_value = float(claim_doc["value"]) + 0.05  # inflate the reported AUC
    new_claim_bytes = json.dumps({"value": tampered_value}, indent=2).encode("utf-8")
    claim_path.write_bytes(new_claim_bytes)

    # Re-align manifest SHA so file-integrity passes and only the re-derivation
    # mismatch fires.
    manifest_path = bundle_dir / "manifest.json"
    m = json.loads(manifest_path.read_bytes())
    m["files"][_CLAIM_REL] = hashlib.sha256(new_claim_bytes).hexdigest()
    manifest_path.write_bytes(json.dumps(m, indent=2).encode("utf-8"))

    result = _verifier().verify(bundle_dir)
    assert not result.ok, "Expected FAIL after +0.05 inflation of claimed AUC"
    rc = _reason_codes(result)
    assert "REDERIVATION_MISMATCH" in rc, (
        f"Expected REDERIVATION_MISMATCH in reason_codes; got {rc!r}"
    )


# ---------------------------------------------------------------------------
# Test 3 — Test-set tamper: score edit in test_set.json -> FAIL
# ---------------------------------------------------------------------------


def test_test_set_tamper_fails(tmp_path):
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)

    ts_path = bundle_dir / "inputs" / "test_set.json"
    doc = json.loads(ts_path.read_bytes())
    # Drop the top positive item's score below every negative -> AUC falls.
    for ev in doc["evaluations"]:
        if ev["item_id"] == "t01":
            ev["score"] = 0.01
            break
    ts_path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    # Do NOT update manifest.files -> BAD_FILE_SHA fires.

    result = _verifier().verify(bundle_dir)
    assert not result.ok, "Expected FAIL after test-set tamper"
    rc = _reason_codes(result)
    assert "bad_file_sha" in rc or "plugin_failed" in rc, (
        f"Expected bad_file_sha or plugin_failed in reason_codes; got {rc!r}"
    )
    assert "REDERIVATION_MISMATCH" in rc, (
        f"Expected REDERIVATION_MISMATCH also in reason_codes; got {rc!r}"
    )


# ---------------------------------------------------------------------------
# Test 4 — §4a attack (a): producer ships a WEAKER spec -> AnchorViolation
# ---------------------------------------------------------------------------


def test_weak_spec_substitution_fails(tmp_path):
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)

    weak_spec = json.dumps(
        {
            "spec_id": "iso42001.vnv.auc.v1",  # same spec_id
            "types": {
                "model_validation_auc": {
                    "primitive_id": "iso42001_auc_recompute",
                    "comparator": {
                        "kind": "scalar_epsilon",
                        "params": {"epsilon": 1e30},  # accepts ANY value
                    },
                }
            },
        }
    ).encode("utf-8")

    tampered_value = 0.999  # an inflated AUC the weak spec would wave through
    new_claim_bytes = json.dumps({"value": tampered_value}, indent=2).encode("utf-8")
    (bundle_dir / _CLAIM_REL).write_bytes(new_claim_bytes)

    spec_path = bundle_dir / "spec" / "iso42001_vnv.spec.json"
    spec_path.write_bytes(weak_spec)

    manifest_path = bundle_dir / "manifest.json"
    m = json.loads(manifest_path.read_bytes())
    m["files"][_CLAIM_REL] = hashlib.sha256(new_claim_bytes).hexdigest()
    m["spec_files"]["iso42001_vnv.spec.json"] = hashlib.sha256(weak_spec).hexdigest()
    manifest_path.write_bytes(json.dumps(m, indent=2).encode("utf-8"))

    # The AUDITOR's anchor still points to the STRONG spec's SHA.
    result = _verifier(_anchor_from_committed_spec()).verify(bundle_dir)
    assert not result.ok, "Expected FAIL: weak spec should not be authoritative"
    rc = _reason_codes(result)
    assert "AnchorViolation" in rc, (
        f"Expected AnchorViolation in reason_codes; got {rc!r}\n"
        f"Failures: {[(f.check_name, f.reason_code, f.detail) for f in result.failures]}"
    )
