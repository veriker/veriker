"""tests/test_pandemic_benefit_eligibility_spec_pinned.py — Axis-2 spec-pinned dispatch
tests for the per-dir migration of examples/pandemic_benefit_eligibility_minimal.

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed decision list (APP-001's verdict flipped in the claim) -> FAIL
     (REDERIVATION_MISMATCH).
  3. Tampered input (mutate APP-001's eligibility_period_week so it falls OUTSIDE the
     published window -> re-derived verdict flips APPROVED -> DENIED and the benefit
     amount drops to 0) -> FAIL (REDERIVATION_MISMATCH): re-derivation from the tampered
     evidence no longer agrees with the (honest) claimed list. The manifest SHA is
     re-aligned on the mutated data/applicants.json so FileIntegrity does not fire first.
  4. No auditor anchor while the bundle declares outputs -> fail-closed (AnchorViolation).
  5. §4a attack: producer ships a substituted pinned spec (a SHA the auditor did not
     anchor) with a tampered value -> still fail-closed (the strong committed-spec anchor
     does not list the substituted spec's SHA).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "pandemic_benefit_eligibility_minimal"
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


# The pilot's recompute module + spec-pinned harness are loaded by path so this test does
# not depend on cwd.
_load(
    "pandemic_benefit_eligibility_recompute",
    _PILOT_DIR / "pandemic_benefit_eligibility_recompute.py",
)
_spc = _load(
    "pandemic_benefit_eligibility_spec_pinned_check",
    _PILOT_DIR / "spec_pinned_check.py",
)


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a decision list that flips APP-001 from its honest APPROVED verdict
    # to a fabricated DENIED verdict (amount 0).
    honest = _spc.build_spec_pinned(tmp_path / "honest")
    claimed = json.loads(
        (honest / "outputs" / "pandemic_benefit_eligibility.json").read_text("utf-8")
    )["value"]
    assert claimed[0][0] == "APP-001" and claimed[0][1] == "APPROVED", claimed[0]
    tampered = [list(row) for row in claimed]
    tampered[0] = ["APP-001", "DENIED", 0]

    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle", claimed_override=tampered)
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then mutate APP-001: move eligibility_period_week 5 -> 30, OUTSIDE the
    # published [1, 26] window. The re-derived verdict flips APPROVED -> DENIED and the
    # benefit amount drops to 0; the claimed (honest) decision list no longer matches the
    # re-derivation from the tampered evidence.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    app_path = bundle_dir / "data" / "applicants.json"
    applicants = json.loads(app_path.read_text("utf-8"))
    assert applicants[0]["applicant_id"] == "APP-001"
    assert applicants[0]["eligibility_period_week"] == 5, applicants[0]
    applicants[0]["eligibility_period_week"] = 30
    new_bytes = json.dumps(applicants, indent=2).encode("utf-8")
    app_path.write_bytes(new_bytes)
    # Re-align manifest SHA so FileIntegrity does not fire first — isolate the
    # re-derivation mismatch.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["data/applicants.json"] = hashlib.sha256(new_bytes).hexdigest()
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
    # Producer ships a substituted spec (a different spec_id the auditor did not anchor)
    # AND tampers the claimed value. The auditor anchor is computed from the COMMITTED
    # spec, so the substituted spec's SHA is not anchored -> fail-closed.
    substituted_spec = json.dumps(
        {
            "spec_id": "pandemic_benefit_eligibility.attacker",
            "types": {
                "pandemic_benefit_eligibility": {
                    "primitive_id": "pandemic_benefit_eligibility_recompute",
                    "comparator": {"kind": "exact"},
                }
            },
        }
    ).encode("utf-8")
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        claimed_override=[["APP-001", "DENIED", 0]],
        spec_bytes_override=substituted_spec,
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    codes = _reason_codes(result)
    assert "AnchorViolation" in codes, codes
