"""tests/test_iso42001_external_reporting_minimal.py — tamper + §4a attack tests.

ISO/IEC 42001 A.8 external-reporting reconciliation. Two disclosed figures, two
comparator kinds (exact count + scalar_epsilon rate). Surfaces:

  0. Unit: the two compute fns on a known input.
  1. Happy path -> PASS.
  2. Count mutation (exact comparator): bump disclosed count by +1 ->
     REDERIVATION_MISMATCH.
  3. Rate mutation (scalar_epsilon): nudge disclosed rate by +0.5 ->
     REDERIVATION_MISMATCH.
  4. Log tamper: flip a human_reviewed flag without updating manifest.files ->
     BAD_FILE_SHA + REDERIVATION_MISMATCH (rate changes).
  5. Weaker-spec substitution -> AnchorViolation.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

_TEST_DIR = Path(__file__).resolve().parent
_PILOT_DIR = _TEST_DIR.parent
_PKG_ROOT = _PILOT_DIR.parents[1]

if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.rederivation.registry import register_primitive  # noqa: E402
from audit_bundle.rederivation.spec_binding import SpecAnchor  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
import iso42001_external_reporting_recompute as _prim_mod  # noqa: E402

register_primitive(_prim_mod.Iso42001DecisionCountRecompute())
register_primitive(_prim_mod.Iso42001OversightRateRecompute())

_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "iso42001_external_reporting.spec.json"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_COUNT_REL = "outputs/disclosed_automated_decision_count.json"
_RATE_REL = "outputs/disclosed_human_oversight_rate_pct.json"


def _build(out_dir: Path) -> None:
    subprocess.run(
        [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(out_dir)],
        capture_output=True,
        check=True,
    )


def _anchor() -> SpecAnchor:
    raw = _SPEC_SRC.read_bytes()
    doc = json.loads(raw)
    return SpecAnchor(allowed={doc["spec_id"]: hashlib.sha256(raw).hexdigest()})


def _verifier(anchor: SpecAnchor | None = None) -> BundleVerifier:
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()],
        spec_anchor=anchor if anchor is not None else _anchor(),
    )


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _retarget_claim(bundle_dir: Path, rel: str, new_value) -> None:
    """Overwrite a claimed-value file and re-align its manifest SHA so only the
    re-derivation comparison fires (not BAD_FILE_SHA)."""
    nb = json.dumps({"value": new_value}, indent=2).encode("utf-8")
    (bundle_dir / rel).write_bytes(nb)
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][rel] = hashlib.sha256(nb).hexdigest()
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))


# ---------------------------------------------------------------------------
# 0. Unit
# ---------------------------------------------------------------------------


def test_compute_fns_known_values():
    recs = [
        {"automated": True, "human_reviewed": True},
        {"automated": True, "human_reviewed": False},
        {"automated": True, "human_reviewed": True},
        {"automated": False, "human_reviewed": True},
    ]
    assert _prim_mod.compute_automated_decision_count(recs) == 3
    # 2 of 3 automated reviewed -> 66.66..%
    assert abs(_prim_mod.compute_human_oversight_rate_pct(recs) - (100.0 * 2 / 3)) < 1e-12


# ---------------------------------------------------------------------------
# 1. Happy path
# ---------------------------------------------------------------------------


def test_honest_pass(tmp_path):
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)
    result = _verifier().verify(bundle_dir)
    assert result.ok, [
        (f.check_name, f.reason_code, f.detail) for f in result.failures
    ]


# ---------------------------------------------------------------------------
# 2. Count mutation (exact comparator)
# ---------------------------------------------------------------------------


def test_count_mutation_fails(tmp_path):
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)
    claimed = json.loads((bundle_dir / _COUNT_REL).read_bytes())["value"]
    _retarget_claim(bundle_dir, _COUNT_REL, int(claimed) + 1)  # over-disclose by 1
    result = _verifier().verify(bundle_dir)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result)


# ---------------------------------------------------------------------------
# 3. Rate mutation (scalar_epsilon comparator)
# ---------------------------------------------------------------------------


def test_rate_mutation_fails(tmp_path):
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)
    claimed = json.loads((bundle_dir / _RATE_REL).read_bytes())["value"]
    _retarget_claim(bundle_dir, _RATE_REL, float(claimed) + 0.5)  # inflate oversight
    result = _verifier().verify(bundle_dir)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result)


# ---------------------------------------------------------------------------
# 4. Log tamper
# ---------------------------------------------------------------------------


def test_log_tamper_fails(tmp_path):
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)
    log = bundle_dir / "inputs" / "decision_log.json"
    doc = json.loads(log.read_bytes())
    # Flip d02 (automated, not reviewed) to reviewed -> oversight rate rises.
    for r in doc["decisions"]:
        if r["decision_id"] == "d02":
            r["human_reviewed"] = True
            break
    log.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    # Do NOT update manifest.files -> BAD_FILE_SHA.
    result = _verifier().verify(bundle_dir)
    assert not result.ok
    rc = _reason_codes(result)
    assert "bad_file_sha" in rc or "plugin_failed" in rc, rc
    assert "REDERIVATION_MISMATCH" in rc, rc


# ---------------------------------------------------------------------------
# 5. Weaker-spec substitution -> AnchorViolation
# ---------------------------------------------------------------------------


def test_weak_spec_substitution_fails(tmp_path):
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)

    weak = json.dumps(
        {
            "spec_id": "iso42001.external_reporting.v1",
            "types": {
                # Weaken the rate to accept anything; keep count as exact.
                "disclosed_automated_decision_count": {
                    "primitive_id": "iso42001_decision_count_recompute",
                    "comparator": {"kind": "exact", "params": {}},
                },
                "disclosed_human_oversight_rate_pct": {
                    "primitive_id": "iso42001_oversight_rate_recompute",
                    "comparator": {"kind": "scalar_epsilon", "params": {"epsilon": 1e30}},
                },
            },
        }
    ).encode("utf-8")

    nb = json.dumps({"value": 100.0}, indent=2).encode("utf-8")
    (bundle_dir / _RATE_REL).write_bytes(nb)
    spec_path = bundle_dir / "spec" / "iso42001_external_reporting.spec.json"
    spec_path.write_bytes(weak)

    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][_RATE_REL] = hashlib.sha256(nb).hexdigest()
    m["spec_files"]["iso42001_external_reporting.spec.json"] = hashlib.sha256(weak).hexdigest()
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))

    result = _verifier(_anchor()).verify(bundle_dir)
    assert not result.ok
    assert "AnchorViolation" in _reason_codes(result)
