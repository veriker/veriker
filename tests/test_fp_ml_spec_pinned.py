"""tests/test_fp_ml_spec_pinned.py — Axis-2 spec-pinned dispatch tests for the
per-dir migration of examples/fp_ml_minimal.

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed value -> FAIL (REDERIVATION_MISMATCH).
  3. Tampered input (feature[0][0]) -> FAIL (REDERIVATION_MISMATCH): re-derivation
     from the tampered evidence no longer agrees with the (honest) claimed value;
     the manifest SHA is re-aligned so FileIntegrity does not fire first.
  4. No auditor anchor while the bundle declares outputs -> fail-closed
     (AnchorViolation).
  5. §4a attack: producer ships a WEAKER pinned spec (epsilon=1e30) the auditor
     did not anchor, with a tampered value the weak spec WOULD accept -> still
     fail-closed (the strong committed-spec anchor does not list the weak SHA).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "fp_ml_minimal"
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
_load("fp_ml_recompute", _PILOT_DIR / "fp_ml_recompute.py")
_spc = _load("fp_ml_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a value 1.0 off the honest re-derivation.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    model = json.loads((bundle_dir / "weights" / "model.json").read_bytes())
    features = json.loads((bundle_dir / "inputs" / "features.json").read_bytes())
    honest = _spc.compute_rep_logit(model["W"], model["b"], features)
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle2", claimed_override=honest + 1.0
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then perturb feature[0][0] in the bundle's input. The claimed
    # value (honest) no longer matches the re-derivation from tampered evidence;
    # W[0][0]=0.5 so a +1.0 shift moves the rep logit by ~0.5 >> epsilon.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    features_path = bundle_dir / "inputs" / "features.json"
    features = json.loads(features_path.read_bytes())
    features[0][0] = float(features[0][0]) + 1.0
    new_bytes = json.dumps(features, indent=2).encode("utf-8")
    features_path.write_bytes(new_bytes)
    # Re-align manifest SHA so FileIntegrity does not fire first — isolate the
    # re-derivation mismatch.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["inputs/features.json"] = hashlib.sha256(new_bytes).hexdigest()
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


def test_weak_spec_substitution_fails_closed(tmp_path):
    # Producer ships a weak spec (epsilon=1e30 accepts anything) AND tampers the
    # claimed value. The auditor anchor is computed from the COMMITTED strong spec
    # (epsilon=1e-9), so the weak spec's SHA is not anchored -> fail-closed.
    weak_spec = json.dumps(
        {
            "spec_id": "fp_ml.v1",
            "types": {
                "fp_ml_logit": {
                    "primitive_id": "fp_ml_recompute",
                    "comparator": {"kind": "scalar_epsilon", "params": {"epsilon": 1e30}},
                }
            },
        }
    ).encode("utf-8")
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        claimed_override=-1.0,
        spec_bytes_override=weak_spec,
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    codes = _reason_codes(result)
    assert "AnchorViolation" in codes, codes
