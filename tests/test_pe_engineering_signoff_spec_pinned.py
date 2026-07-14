"""tests/test_pe_engineering_signoff_spec_pinned.py — Axis-2 spec-pinned dispatch tests
for the per-dir migration of examples/pe_engineering_signoff_minimal.

Representative output: the ordered list of per-analysis structural_verdict values (each
'pass'/'fail') for the committed cantilever-beam analyses in inputs/analyses.json,
recomputed from first principles — sigma_max = (P * L) * c / I (c=height/2,
I=width*height^3/12), factor_of_safety = (yield_stress_MPa*1e6)/sigma_max, verdict =
'pass' if FoS >= material.safety_factor else 'fail'. The FoS is a float but the pinned
output is the CATEGORICAL verdict list (exact-safe; fixtures clear the FoS=safety_factor
boundary by wide margins). The bundle's HMAC PE-stamp attestation half is ignored here.
Comparator: `exact` (no params; ordered-list element-wise equality).

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed value (a REORDERED verdict list) -> FAIL (REDERIVATION_MISMATCH).
  3. Tampered input (mutate a load so a verdict flips fail->pass; re-align the manifest
     SHA so FileIntegrity does not fire first) -> FAIL (REDERIVATION_MISMATCH).
  4. No auditor anchor while the bundle declares outputs -> fail-closed (AnchorViolation).
  5. §4a attack: producer ships a spec the auditor did NOT anchor (same spec_id, but a
     DIFFERENT primitive_id -> different bytes -> different SHA). For an `exact`
     comparator there is no epsilon to weaken, so the anchor defense is demonstrated
     via a substituted-spec SHA the anchor does not list -> fail-closed (AnchorViolation).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "pe_engineering_signoff_minimal"
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
_load("pe_engineering_signoff_recompute", _PILOT_DIR / "pe_engineering_signoff_recompute.py")
_spc = _load("pe_engineering_signoff_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a DIFFERENT verdict list (flip one entry's pass<->fail) — a
    # genuinely different ordered list than the honest re-derivation. (The honest
    # fixture is ['pass','pass','fail']; swapping two equal entries would not differ,
    # so flip a verdict to guarantee divergence.)
    honest = _spc._honest_verdicts(_spc.build_spec_pinned(tmp_path / "honest"))
    assert len(honest) >= 1
    tampered = list(honest)
    tampered[-1] = "pass" if tampered[-1] == "fail" else "fail"
    assert tampered != honest, "fixture must produce a genuinely different ordered list"
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle", claimed_override=tampered)
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then perturb a COMMITTED analysis load so the re-derivation flips a
    # verdict (ANL-2026-003 fail -> pass at load_N=5000: FoS 1.25 -> 3.0), diverging
    # from the (honest) claimed verdict list. Re-align the manifest SHA for
    # inputs/analyses.json so FileIntegrity (step-2/3) does not fire first — isolate
    # the re-derivation mismatch.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    analyses_path = bundle_dir / "inputs" / "analyses.json"
    analyses = json.loads(analyses_path.read_bytes())
    flipped = False
    for a in analyses:
        if a["analysis_id"] == "ANL-2026-003":
            a["load_N"] = 5000.0  # FoS 1.25 -> 3.0 : verdict flips fail -> pass
            flipped = True
    assert flipped, "expected ANL-2026-003 in committed analyses"
    # Preserve the legacy builder's serialization (indent=2, sort_keys=True, trailing
    # newline) so the only change to the file is the mutated load value.
    new_bytes = (json.dumps(analyses, indent=2, sort_keys=True) + "\n").encode("utf-8")
    analyses_path.write_bytes(new_bytes)

    # inputs/analyses.json is recorded in manifest.files; re-align its SHA so
    # FileIntegrity does not fire first.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["inputs/analyses.json"] = hashlib.sha256(new_bytes).hexdigest()
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
    # §4a attack (exact-comparator variant): producer ships a spec the auditor did NOT
    # anchor. Same spec_id, but a DIFFERENT primitive_id -> different bytes -> different
    # SHA. The auditor anchor is computed from the COMMITTED spec, so the substituted
    # spec's SHA is not anchored -> fail-closed (no `exact` epsilon to weaken; the
    # anchor defense is the SHA the anchor does not list).
    other_spec = json.dumps(
        {
            "spec_id": "pe_engineering_signoff.v1",
            "types": {
                "pe_engineering_signoff_verdicts": {
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
