"""tests/test_dp_spec_pinned.py — Axis-2 spec-pinned dispatch tests for the
per-dir migration of examples/dp_minimal.

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed value -> FAIL (REDERIVATION_MISMATCH).
  3. Tampered input (dataset rows) -> FAIL (REDERIVATION_MISMATCH): re-derivation
     from the tampered evidence (a different true_count) no longer agrees with
     the honest claimed noised_count. The manifest SHA for the dataset is
     re-aligned so FileIntegrity does not fire first.
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
_PILOT_DIR = _PKG_ROOT / "examples" / "dp_minimal"
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
_load("dp_recompute", _PILOT_DIR / "dp_recompute.py")
_spc = _load("dp_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")


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
    release = json.loads((bundle_dir / "payload" / "dp_release.json").read_bytes())
    rows = _spc._load_rows(bundle_dir)
    honest = _spc.compute_noised_count(rows, release)
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle2", claimed_override=honest + 1.0
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then flip dataset rows so the re-derived true_count (and thus
    # the noised_count) changes. The claimed value (honest) no longer matches the
    # re-derivation from tampered evidence.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    ds_path = bundle_dir / "data" / "dataset.jsonl"
    rows = _spc._load_rows(bundle_dir)
    # Force every row to match the committed predicate, maximizing true_count drift.
    pred = json.loads((bundle_dir / "payload" / "dp_release.json").read_bytes())[
        "query"
    ]["predicate"]
    for row in rows:
        row.update(pred)
    new_bytes = ("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n").encode(
        "utf-8"
    )
    ds_path.write_bytes(new_bytes)
    # Re-align manifest SHA so FileIntegrity does not fire first — isolate the
    # re-derivation mismatch.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["data/dataset.jsonl"] = hashlib.sha256(new_bytes).hexdigest()
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
    # (epsilon=1e-6), so the weak spec's SHA is not anchored -> fail-closed.
    weak_spec = json.dumps(
        {
            "spec_id": "dp.v1",
            "types": {
                "dp_noised_count": {
                    "primitive_id": "dp_recompute",
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
