"""tests/test_scrabble_spec_pinned.py — Axis-2 spec-pinned dispatch tests for the
per-dir migration of examples/scrabble_minimal.

Representative output: the ruling object {edition_cited, word, is_legal} in
payload/ruling.json, recomputed by resolving (jurisdiction, timestamp) -> effective
edition via the committed timeline (editions/jurisdiction_timeline.json), then
testing word membership in the resolved edition's wordlist (dictionaries/<edition>.txt).
Comparator: `exact` (no params; element-wise object equality).

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed value (flip is_legal) -> FAIL (REDERIVATION_MISMATCH).
  3. Tampered input (mutate the committed wordlist so membership re-derives a
     DIFFERENT is_legal than the honest claimed value) -> FAIL
     (REDERIVATION_MISMATCH); manifest SHA re-aligned so FileIntegrity does not
     fire first.
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
_PILOT_DIR = _PKG_ROOT / "examples" / "scrabble_minimal"
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
_load("scrabble_recompute", _PILOT_DIR / "scrabble_recompute.py")
_spc = _load("scrabble_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a ruling with the membership verdict FLIPPED — a different
    # object than the honest re-derivation.
    honest = _spc._ruling_from_producer_payload(
        _spc.build_spec_pinned(tmp_path / "honest")
    )
    tampered = dict(honest)
    tampered["is_legal"] = not honest["is_legal"]
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle", claimed_override=tampered)
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then perturb the COMMITTED wordlist the dispute resolves to so
    # membership re-derives a different is_legal than the (honest) claimed value.
    # Re-align the manifest SHA so FileIntegrity does not fire first — isolate the
    # re-derivation mismatch.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    honest = _spc._ruling_from_producer_payload(bundle_dir)
    assert honest["is_legal"] is True  # ZARFY is in synthetic_csw_beta

    # Remove the disputed word from its resolved edition's wordlist -> membership
    # now re-derives is_legal=False, diverging from the honest claim (True).
    edition = honest["edition_cited"]
    word = honest["word"]
    wl_rel = f"dictionaries/{edition}.txt"
    wl_path = bundle_dir / wl_rel
    lines = [
        ln for ln in wl_path.read_text(encoding="utf-8").splitlines() if ln.strip()
    ]
    new_lines = [ln for ln in lines if ln.strip().upper() != word]
    assert len(new_lines) < len(lines), "fixture: disputed word not found in wordlist"
    new_bytes = ("\n".join(new_lines) + "\n").encode("utf-8")
    wl_path.write_bytes(new_bytes)

    # The wordlist is recorded in manifest.files; re-align its SHA so FileIntegrity
    # (step-2/3) does not fire first.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"][wl_rel] = hashlib.sha256(new_bytes).hexdigest()
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
    # §4a attack (exact-comparator variant): producer ships a spec the auditor did
    # NOT anchor. Same spec_id, but a DIFFERENT primitive_id -> different bytes ->
    # different SHA. The auditor anchor is computed from the COMMITTED spec, so the
    # substituted spec's SHA is not anchored -> fail-closed (no `exact` epsilon to
    # weaken; the anchor defense is the SHA the anchor does not list).
    other_spec = json.dumps(
        {
            "spec_id": "scrabble.v1",
            "types": {
                "scrabble_ruling": {
                    "primitive_id": "some_other_unanchored_primitive",
                    "comparator": {"kind": "exact"},
                }
            },
        }
    ).encode("utf-8")
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        claimed_override={"edition_cited": "x", "word": "X", "is_legal": False},
        spec_bytes_override=other_spec,
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    codes = _reason_codes(result)
    assert "AnchorViolation" in codes, codes
