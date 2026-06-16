"""tests/test_anticheat_adjudication_spec_pinned.py — Axis-2 spec-pinned dispatch tests
for the per-dir migration of examples/anticheat_adjudication_minimal.

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed list (flip case-001's verdict in the producer claim) -> FAIL
     (REDERIVATION_MISMATCH).
  3. Tampered input (mutate case-001's snap_variance_deg in
     evidence/detection_signals.jsonl so rule-A no longer fires and the verdict
     re-derives ban -> review) -> FAIL (REDERIVATION_MISMATCH). The manifest SHA is
     re-aligned on the mutated file so FileIntegrity does not fire first.
  4. No auditor anchor while the bundle declares outputs -> fail-closed
     (AnchorViolation).
  5. §4a attack: producer ships a substituted pinned spec (a SHA the auditor did
     not anchor) with a tampered claim -> still fail-closed (the strong
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
_PILOT_DIR = _PKG_ROOT / "examples" / "anticheat_adjudication_minimal"
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
_load("anticheat_adjudication_recompute", _PILOT_DIR / "anticheat_adjudication_recompute.py")
_spc = _load(
    "anticheat_adjudication_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py"
)


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a DIFFERENT verdict list than the honest re-derivation: flip
    # case-001 (honest verdict "ban" via rule-A) to "review".
    honest = _spc.compute_verdict_list(
        _spc._load_cases(_spc.build_spec_pinned(tmp_path / "seed")),
        _spc._load_policy(tmp_path / "seed"),
    )
    tampered = copy.deepcopy(honest)
    assert tampered[0] == {"model_recommendation": "ban", "matched_rule_id": "rule-A-aimbot-snap"}, tampered[0]
    tampered[0] = {"model_recommendation": "review", "matched_rule_id": "rule-D-suspicious-review"}

    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle", claimed_override=tampered
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then mutate case-001's snap_variance_deg in the evidence JSONL
    # from 0.3 to 5.0. rule-A (snap_variance_deg<=0.5) no longer fires, so case-001
    # re-derives ban -> review (rule-D) — the claimed (honest "ban") no longer
    # matches the re-derivation from the tampered evidence.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    signals_path = bundle_dir / "evidence" / "detection_signals.jsonl"
    text = signals_path.read_text(encoding="utf-8")
    assert '"snap_variance_deg": 0.3}' in text, text
    new_text = text.replace('"snap_variance_deg": 0.3}', '"snap_variance_deg": 5.0}', 1)
    new_bytes = new_text.encode("utf-8")
    signals_path.write_bytes(new_bytes)
    # Re-align manifest SHA so FileIntegrity does not fire first — isolate the
    # re-derivation mismatch.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["evidence/detection_signals.jsonl"] = hashlib.sha256(new_bytes).hexdigest()
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
    # anchor) AND tampers the claimed value. The auditor anchor is computed from
    # the COMMITTED spec, so the substituted spec's SHA is not anchored ->
    # fail-closed.
    tampered = [{"model_recommendation": "clear", "matched_rule_id": None}]
    substituted_spec = json.dumps(
        {
            "spec_id": "anticheat_adjudication.attacker",
            "types": {
                "anticheat_adjudication_verdict_list": {
                    "primitive_id": "anticheat_adjudication_recompute",
                    "comparator": {"kind": "exact"},
                }
            },
        }
    ).encode("utf-8")
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
