"""tests/test_auto_ubi_spec_pinned.py — Axis-2 spec-pinned dispatch tests for the
per-dir migration of examples/auto_ubi_minimal.

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed tier list (PHD-001's tier flipped in the claim)
     -> FAIL (REDERIVATION_MISMATCH).
  3. Tampered input (mutate a PHD-001 trip so its re-derived tier flips
     low_mileage_discount -> high_risk_surcharge by raising hard_brakes)
     -> FAIL (REDERIVATION_MISMATCH): re-derivation from the tampered evidence
     no longer agrees with the (honest) claimed list. The manifest SHA is
     re-aligned on the mutated trips file so FileIntegrity does not fire first.
  4. No auditor anchor while the bundle declares outputs -> fail-closed
     (AnchorViolation).
  5. §4a attack: producer ships a substituted pinned spec (a SHA the auditor did
     not anchor) with a tampered value -> still fail-closed (the strong
     committed-spec anchor does not list the substituted spec's SHA).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "auto_ubi_minimal"
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
_load("auto_ubi_recompute", _PILOT_DIR / "auto_ubi_recompute.py")
_spc = _load("auto_ubi_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a tier list that flips PHD-001 from its honest
    # low_mileage_discount to a fabricated standard tier.
    honest = _spc.build_spec_pinned(tmp_path / "honest")
    claimed = json.loads(
        (honest / "outputs" / "auto_ubi_tier_list.json").read_text("utf-8")
    )["value"]
    assert claimed[0] == {
        "policyholder_id": "PHD-001",
        "tier": "low_mileage_discount",
    }, claimed
    tampered = [dict(row) for row in claimed]
    tampered[0] = {"policyholder_id": "PHD-001", "tier": "standard"}

    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle", claimed_override=tampered
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then mutate one PHD-001 trip (T001-001): raise hard_brakes
    # 0 -> 10. PHD-001's total mileage is ~107.6, so hard_brake_per_mile rises
    # to ~0.093 > the 0.04 surcharge threshold, flipping the re-derived tier
    # low_mileage_discount -> high_risk_surcharge; the claimed (honest) tier
    # list no longer matches the re-derivation from the tampered evidence.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    trips_path = bundle_dir / "telematics" / "trips.jsonl"
    lines = trips_path.read_text("utf-8").splitlines()
    mutated_lines: list[str] = []
    flipped = False
    for line in lines:
        if not line.strip():
            continue
        trip = json.loads(line)
        if trip.get("trip_id") == "T001-001":
            assert trip["hard_brakes"] == 0, trip
            trip["hard_brakes"] = 10
            flipped = True
        mutated_lines.append(json.dumps(trip, sort_keys=True))
    assert flipped, "expected to find trip T001-001 to mutate"
    new_bytes = ("\n".join(mutated_lines) + "\n").encode("utf-8")
    trips_path.write_bytes(new_bytes)
    # Re-align manifest SHA so FileIntegrity does not fire first — isolate the
    # re-derivation mismatch.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["telematics/trips.jsonl"] = hashlib.sha256(new_bytes).hexdigest()
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
    substituted_spec = json.dumps(
        {
            "spec_id": "auto_ubi.attacker",
            "types": {
                "auto_ubi_tier_list": {
                    "primitive_id": "auto_ubi_recompute",
                    "comparator": {"kind": "exact"},
                }
            },
        }
    ).encode("utf-8")
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        claimed_override=[{"policyholder_id": "PHD-001", "tier": "standard"}],
        spec_bytes_override=substituted_spec,
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    codes = _reason_codes(result)
    assert "AnchorViolation" in codes, codes
