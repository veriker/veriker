"""tests/test_healthcare_diagnosis_spec_pinned.py — Axis-2 spec-pinned dispatch tests
for the per-dir migration of examples/healthcare_diagnosis_minimal.

Representative output: the ordered list of icd10_code values in payload/diagnosis.json
(categorical codes only — the per-candidate confidence float is EXCLUDED to keep the
output exact-comparable), recomputed by traversing the committed decision rules
(inputs/rules.json) in sorted rule_id order against the committed symptom set
(inputs/symptoms.json): a rule fires iff every condition's symptom is present and
meets min_severity, and each fired rule contributes its icd10_code in order.
Comparator: `exact` (no params; ordered-list element-wise equality).

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed value (a REORDERED icd10_code list) -> FAIL
     (REDERIVATION_MISMATCH).
  3. Tampered input (lower a symptom severity below a rule's threshold so the
     re-derivation drops a code) -> FAIL (REDERIVATION_MISMATCH); manifest SHA
     re-aligned so FileIntegrity does not fire first.
  4. No auditor anchor while the bundle declares outputs -> fail-closed
     (AnchorViolation).
  5. §4a attack: producer ships a spec the auditor did NOT anchor (same spec_id,
     but a DIFFERENT primitive_id -> different bytes -> different SHA). For an
     `exact` comparator there is no epsilon to weaken, so the anchor defense is
     demonstrated via a substituted-spec SHA the anchor does not list ->
     fail-closed (AnchorViolation).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "healthcare_diagnosis_minimal"
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# The pilot's recompute module + spec-pinned harness are loaded by path so this
# test does not depend on cwd.
_load("healthcare_diagnosis_recompute", _PILOT_DIR / "healthcare_diagnosis_recompute.py")
_spc = _load("healthcare_diagnosis_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a REORDERED icd10_code list (swap first two entries) — a
    # different ordered list than the honest re-derivation.
    honest = _spc._honest_codes(_spc.build_spec_pinned(tmp_path / "honest"))
    assert len(honest) >= 2
    reordered = list(honest)
    reordered[0], reordered[1] = reordered[1], reordered[0]
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle", claimed_override=reordered
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then perturb the COMMITTED symptoms so the rule traversal
    # re-derives a DIFFERENT icd10_code list than the (honest) claimed value.
    # Lower sym-005 severity to 1: rules rule-A49/rule-I20/rule-J18 all require
    # sym-005 >= 2, so they stop firing and their codes drop out — the
    # re-derivation diverges from the honest 4-code claim. Re-align the
    # manifest SHA so FileIntegrity (step-2/3) does not fire first.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    symptoms_path = bundle_dir / "inputs" / "symptoms.json"
    symptoms = json.loads(symptoms_path.read_bytes())
    for s in symptoms:
        if s["symptom_id"] == "sym-005":
            s["severity"] = 1
    new_bytes = (
        json.dumps(symptoms, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
    symptoms_path.write_bytes(new_bytes)

    # symptoms.json is recorded in manifest.files; re-align its SHA so
    # FileIntegrity does not fire first.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["inputs/symptoms.json"] = hashlib.sha256(new_bytes).hexdigest()
    mp.write_text(
        json.dumps(m, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8"
    )

    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_no_anchor_fails_closed(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    result = _spc.make_verifier(anchor=None).verify(bundle_dir)
    assert not result.ok
    assert "AnchorViolation" in _reason_codes(result), _reason_codes(result)


def test_substituted_spec_fails_closed(tmp_path):
    # §4a attack (exact-comparator variant): producer ships a spec the auditor did
    # NOT anchor. Same spec_id, but a DIFFERENT primitive_id -> different bytes ->
    # different SHA. The auditor anchor is computed from the COMMITTED spec, so the
    # substituted spec's SHA is not anchored -> fail-closed (no `exact` epsilon to
    # weaken; the anchor defense is the SHA the anchor does not list).
    other_spec = json.dumps(
        {
            "spec_id": "healthcare_diagnosis.v1",
            "types": {
                "healthcare_diagnosis_codes": {
                    "primitive_id": "some_other_unanchored_primitive",
                    "comparator": {"kind": "exact"},
                }
            },
        }
    ).encode("utf-8")
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        claimed_override=["tampered"],
        spec_bytes_override=other_spec,
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    codes = _reason_codes(result)
    assert "AnchorViolation" in codes, codes
