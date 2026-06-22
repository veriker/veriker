"""tests/test_lifesci_binding_spec_pinned.py — Axis-2 spec-pinned dispatch tests
for the per-dir migration of examples/lifesci_binding_minimal.

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed value -> FAIL (REDERIVATION_MISMATCH).
  3. Tampered input (the SMILES string) -> FAIL (REDERIVATION_MISMATCH): re-derivation
     from the tampered evidence no longer agrees with the (honest) claimed value.
  4. No auditor anchor while the bundle declares outputs -> fail-closed
     (ANCHORVIOLATION).
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
_PILOT_DIR = _PKG_ROOT / "examples" / "lifesci_binding_minimal"
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
_load("lifesci_binding_recompute", _PILOT_DIR / "lifesci_binding_recompute.py")
_spc = _load("lifesci_binding_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")


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
    honest = _spc._honest_claimed(bundle_dir)
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle2", claimed_override=honest + 1.0
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then perturb the SMILES string in the bundle's input. The
    # claimed value (honest) no longer matches the re-derivation from tampered
    # evidence.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    cmp_path = bundle_dir / "inputs" / "compound_descriptor.json"
    compound = json.loads(cmp_path.read_bytes())
    compound["smiles_string"] = compound["smiles_string"] + "CCC"
    # Re-write with the SAME canonical formatting the legacy builder uses
    # (sort_keys + indent=2 + trailing newline), so the change is purely in the
    # value, and re-align the manifest SHA so FileIntegrity does not fire first.
    new_bytes = (
        json.dumps(compound, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    cmp_path.write_bytes(new_bytes)

    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["inputs/compound_descriptor.json"] = hashlib.sha256(new_bytes).hexdigest()
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


def test_weak_spec_substitution_fails_closed(tmp_path):
    # Producer ships a weak spec (epsilon=1e30 accepts anything) AND tampers the
    # claimed value. The auditor anchor is computed from the COMMITTED strong spec
    # (epsilon=1e-6), so the weak spec's SHA is not anchored -> fail-closed.
    weak_spec = json.dumps(
        {
            "spec_id": "lifesci_binding.v1",
            "types": {
                "lifesci_binding_affinity": {
                    "primitive_id": "lifesci_binding_recompute",
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
