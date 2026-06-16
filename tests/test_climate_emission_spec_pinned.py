"""tests/test_climate_emission_spec_pinned.py — Axis-2 spec-pinned dispatch tests
for the per-dir migration of examples/climate_emission_minimal.

This pilot's representative output is the per-vendor Scope-3 emission attribution
LIST (records of exactly {vendor_id, tier, attributed_kg_co2e}), compared with
the generic `structured` comparator over the allowlisted climate_attribution_v1
schema. It uses a NEW in-dir primitive ("climate_attribution_recompute") that
does NOT collide with the central "climate_emission_recompute" (scalar total
under exact); the central spec_pinned_demo / test_spec_pinned_dispatch are
untouched.

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed list (alter one record's attributed_kg_co2e) -> FAIL
     (REDERIVATION_MISMATCH).
  3. Tampered input (mutate a supplier activity_amount so a record's attributed
     value differs; re-align the manifest SHA) -> FAIL (REDERIVATION_MISMATCH):
     re-derivation from the tampered evidence no longer agrees with the honest
     claimed list.
  4. No auditor anchor while the bundle declares outputs -> fail-closed
     (AnchorViolation).
  5. §4a attack: producer ships a substituted spec (a weaker `exact`-on-total
     binding the auditor did not anchor) -> still fail-closed (the committed-spec
     anchor does not list the substituted SHA).
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
_PILOT_DIR = _PKG_ROOT / "examples" / "climate_emission_minimal"
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
_load("climate_attribution_recompute", _PILOT_DIR / "climate_attribution_recompute.py")
_spc = _load("climate_emission_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a list where ONE record's attributed_kg_co2e is altered.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    supplier_chain = json.loads(
        (bundle_dir / "inputs" / "supplier_chain.json").read_bytes()
    )
    honest = _spc.compute_attribution(supplier_chain)
    tampered = copy.deepcopy(honest)
    tampered[0]["attributed_kg_co2e"] = (
        float(tampered[0]["attributed_kg_co2e"]) + 1.0
    )
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle2", claimed_override=tampered
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then perturb a supplier's activity_amount in the bundle's
    # input. The claimed list (honest) no longer matches the re-derivation from
    # the tampered evidence (that record's attributed value differs).
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    chain_path = bundle_dir / "inputs" / "supplier_chain.json"
    supplier_chain = json.loads(chain_path.read_bytes())
    supplier_chain[0]["activity_amount"] = (
        float(supplier_chain[0]["activity_amount"]) + 1000.0
    )
    new_bytes = json.dumps(supplier_chain, indent=2).encode("utf-8")
    chain_path.write_bytes(new_bytes)
    # Re-align manifest SHA so FileIntegrity does not fire first — isolate the
    # re-derivation mismatch.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["inputs/supplier_chain.json"] = hashlib.sha256(new_bytes).hexdigest()
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
    # Producer ships a SUBSTITUTED spec (a different binding the auditor never
    # anchored) AND tampers the claimed value. The auditor anchor is computed
    # from the COMMITTED spec bytes, so the substituted spec's SHA is not
    # anchored -> fail-closed regardless of what the substitute would accept.
    substituted_spec = json.dumps(
        {
            "spec_id": "climate_emission.v1",
            "types": {
                "climate_attribution": {
                    "primitive_id": "climate_attribution_recompute",
                    "comparator": {
                        "kind": "structured",
                        "params": {"schema": "climate_attribution_v1"},
                    },
                }
            },
            "description": "attacker-substituted spec (auditor never anchored this SHA)",
        }
    ).encode("utf-8")
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        spec_bytes_override=substituted_spec,
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "AnchorViolation" in _reason_codes(result), _reason_codes(result)
