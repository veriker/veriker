"""tests/test_combi_screen_spec_pinned.py — Axis-2 spec-pinned dispatch tests for the
per-dir migration of examples/combi_screen_minimal.

Representative output: the advanced (top-K) compound id set in
payload/combi_screen_result.json — the unordered SET of compound_ids advanced after
screening. It is recomputed by re-enumerating the Cartesian product (scaffolds x
r_groups_1 x r_groups_2), re-applying the Lipinski filter, re-scoring survivors with
the committed seeded surrogate scorer, ranking survivors ASCENDING by score (ties by
compound_id), and taking the top-K (= payload advanced_count) — mirroring the legacy
combi_screen_re_derivation / _build_bundle run_screen EXACTLY. Comparator: `set` (no
params, order-independent). NOTE: the set-comparator mismatch surfaces under the
dispatch's REDERIVATION_MISMATCH reason code (the dispatch wraps the comparator result).

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed value (drop an advanced id, add one never advanced) -> FAIL
     (REDERIVATION_MISMATCH).
  3. Tampered input (mutate the committed scoring seed so the ranked top-K set
     differs; re-align manifest SHA so FileIntegrity does not fire first) -> FAIL
     (REDERIVATION_MISMATCH).
  4. No auditor anchor while the bundle declares outputs -> fail-closed
     (AnchorViolation).
  5. §4a attack: producer ships a spec the auditor did NOT anchor (same spec_id,
     but a DIFFERENT primitive_id -> different bytes -> different SHA). The auditor
     anchor is computed from the COMMITTED spec, so the substituted spec's SHA is
     not anchored -> fail-closed (AnchorViolation).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "combi_screen_minimal"
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
_load("combi_screen_recompute", _PILOT_DIR / "combi_screen_recompute.py")
_spc = _load("combi_screen_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a DIFFERENT advanced set than the honest re-derivation: drop a
    # genuinely-advanced compound and add one that never advanced.
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        claimed_override=[
            "SCAF-01__R1-03__R2-02",
            "SCAF-02__R1-02__R2-01",
            "SCAF-02__R1-03__R2-02",
            "SCAF-03__R1-02__R2-05",
            "SCAF-03__R1-03__R2-01",
            "SCAF-03__R1-03__R2-02",
            "SCAF-03__R1-06__R2-05",
            "SCAF-04__R1-06__R2-04",
            "SCAF-05__R1-03__R2-01",
            "SCAF-05__R1-01__R2-01",  # never advanced (replaces SCAF-05__R1-05__R2-02)
        ],
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then perturb a committed scoring input (the seed) so the seeded
    # surrogate scores — and thus the ranked top-K advanced set — differ from the
    # (honest) claimed value frozen in outputs/. Re-align manifest SHA so
    # FileIntegrity does not fire first — isolate the re-derivation mismatch.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    sc_path = bundle_dir / "inputs" / "scoring_config.json"
    sc = json.loads(sc_path.read_text(encoding="utf-8"))
    sc["seed"] = 9999  # honest seed is 8191 -> different ranking -> different top-K set
    new_bytes = (
        json.dumps(sc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    sc_path.write_bytes(new_bytes)

    # inputs/scoring_config.json is a payload file recorded in manifest.files;
    # re-align its SHA so FileIntegrityManySmall (step-2) does not fire before dispatch.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["inputs/scoring_config.json"] = hashlib.sha256(new_bytes).hexdigest()
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
    # §4a attack: producer ships a spec the auditor did NOT anchor. Same spec_id, but
    # a DIFFERENT primitive_id -> different bytes -> different SHA. The auditor anchor
    # is computed from the COMMITTED spec, so the substituted spec's SHA is not
    # anchored -> fail-closed.
    other_spec = json.dumps(
        {
            "spec_id": "combi_screen.v1",
            "types": {
                "combi_screen_advanced_set": {
                    "primitive_id": "some_other_unanchored_primitive",
                    "comparator": {"kind": "set"},
                }
            },
        }
    ).encode("utf-8")
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        claimed_override=[
            "SCAF-01__R1-03__R2-02",
            "SCAF-02__R1-02__R2-01",
        ],
        spec_bytes_override=other_spec,
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    codes = _reason_codes(result)
    assert "AnchorViolation" in codes, codes
