"""tests/test_prior_auth_spec_pinned.py — Axis-2 spec-pinned dispatch tests
for the per-dir migration of examples/prior_auth_minimal.

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed list (flip one request's recommendation) -> FAIL
     (REDERIVATION_MISMATCH).
  3. Tampered input (mutate clinical/findings.jsonl request PA-2026-001 to drop
     its "PT-6wk" prior treatment, so rule-MRI-spine no longer matches and the
     re-derived verdict flips approve/rule-MRI-spine -> deny/null) -> FAIL
     (REDERIVATION_MISMATCH): re-derivation from the tampered evidence no longer
     agrees with the (honest) claimed list. The manifest SHA is re-aligned on the
     mutated file so FileIntegrity does not fire first.
  4. No auditor anchor while the bundle declares outputs -> fail-closed
     (AnchorViolation).
  5. §4a attack: producer ships a substituted pinned spec (a SHA the auditor did
     not anchor) with a tampered claimed list -> still fail-closed (the strong
     committed-spec anchor does not list the substituted spec's SHA).
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "prior_auth_minimal"
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
_load("prior_auth_recompute", _PILOT_DIR / "prior_auth_recompute.py")
_spc = _load("prior_auth_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _honest_claimed(bundle_dir: Path) -> list:
    requests, rules = _spc._load_bundle_requests_and_rules(bundle_dir)
    from prior_auth_recompute import compute_decisions

    return compute_decisions(requests, rules)


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a DIFFERENT verdict list than the honest re-derivation:
    # flip PA-2026-001 from its honest approve/rule-MRI-spine to deny/null.
    probe = _spc.build_spec_pinned(tmp_path / "probe")
    tampered = copy.deepcopy(_honest_claimed(probe))
    assert tampered[0]["request_id"] == "PA-2026-001", tampered[0]
    tampered[0]["model_recommendation"] = "deny"
    tampered[0]["matched_rule_id"] = None

    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle", claimed_override=tampered)
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then mutate clinical/findings.jsonl request PA-2026-001 by
    # dropping its "PT-6wk" prior treatment. rule-MRI-spine requires PT-6wk, so it
    # no longer matches and no other rule does -> the re-derived verdict flips from
    # approve/rule-MRI-spine to deny/null, no longer matching the claimed (honest)
    # list.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    findings_path = bundle_dir / "clinical" / "findings.jsonl"
    lines = findings_path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    assert rec["request_id"] == "PA-2026-001" and rec["prior_treatments"] == ["PT-6wk"], rec
    rec["prior_treatments"] = []
    lines[0] = json.dumps(rec, sort_keys=True)
    new_text = "\n".join(lines) + "\n"
    new_bytes = new_text.encode("utf-8")
    findings_path.write_bytes(new_bytes)
    # Re-align manifest SHA so FileIntegrity does not fire first — isolate the
    # re-derivation mismatch.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["clinical/findings.jsonl"] = hashlib.sha256(new_bytes).hexdigest()
    mp.write_text(json.dumps(m, indent=2, sort_keys=True), encoding="utf-8")

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
    # Producer ships a substituted spec (a different spec_id the auditor did not
    # anchor) AND tampers the claimed list. The auditor anchor is computed from the
    # COMMITTED spec, so the substituted spec's SHA is not anchored -> fail-closed.
    substituted_spec = json.dumps(
        {
            "spec_id": "prior_auth.attacker",
            "types": {
                "prior_auth_decisions": {
                    "primitive_id": "prior_auth_recompute",
                    "comparator": {"kind": "exact"},
                }
            },
        }
    ).encode("utf-8")
    probe = _spc.build_spec_pinned(tmp_path / "probe")
    tampered = copy.deepcopy(_honest_claimed(probe))
    tampered[0]["model_recommendation"] = "deny"
    tampered[0]["matched_rule_id"] = None

    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        claimed_override=tampered,
        spec_bytes_override=substituted_spec,
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    codes = _reason_codes(result)
    assert "AnchorViolation" in codes, codes
