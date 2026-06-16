"""tests/test_bom_spec_pinned.py — Axis-2 spec-pinned dispatch tests for the
per-dir migration of examples/bom_minimal.

Representative output: the full resolved dependency tree
(a dict {root, nodes, resolution_order}) in payload/resolved_tree.json,
recomputed by walking the committed lockfile DAG (lockfile/lockfile.json) from
root via BFS, ascending depth, ids sorted alphabetically within each level. Each
node carries {id, hash, depth, deps}. Comparator: `exact` (deep structural
equality on parsed-JSON objects).

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed value (a flipped node hash inside the resolved tree) -> FAIL
     (REDERIVATION_MISMATCH) — exercises a nodes-level field, not just order.
  3. Tampered input (mutate the committed lockfile so the BFS re-derives a
     DIFFERENT tree than the honest claimed value) -> FAIL
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

import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "bom_minimal"
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
_load("bom_recompute", _PILOT_DIR / "bom_recompute.py")
_spc = _load("bom_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a resolved tree with a TAMPERED node hash — a different
    # structure than the honest re-derivation. Exercises a nodes-level field
    # (the part the resolved-tree broadening actually added), not just order.
    honest = _spc._honest_resolved_tree(_spc.build_spec_pinned(tmp_path / "honest"))
    assert honest["nodes"], "expected at least one resolved node"
    tampered = copy.deepcopy(honest)
    tampered["nodes"][0]["hash"] = "sha256:tampered"
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle", claimed_override=tampered)
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then perturb the COMMITTED lockfile so the BFS re-derives a
    # different resolved tree than the (honest) claimed value. Re-align the
    # manifest SHA so FileIntegrity does not fire first — isolate the
    # re-derivation mismatch.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    lockfile_path = bundle_dir / "lockfile" / "lockfile.json"
    lockfile = json.loads(lockfile_path.read_bytes())
    # Add a brand-new direct dependency of root -> changes the resolved id set,
    # node list and resolution_order, so the re-derivation diverges from the
    # honest claim.
    new_pkg = "aaa-injected@1.0.0"
    lockfile["packages"][new_pkg] = {"hash": "sha256:injected", "deps": []}
    lockfile["packages"]["myapp@1.0.0"]["deps"].append(new_pkg)
    new_bytes = json.dumps(lockfile, indent=2, sort_keys=True).encode("utf-8")
    lockfile_path.write_bytes(new_bytes)

    # The lockfile is recorded in manifest.files; re-align its SHA so FileIntegrity
    # (step-2/3) does not fire first.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["lockfile/lockfile.json"] = hashlib.sha256(new_bytes).hexdigest()
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
            "spec_id": "bom.v1",
            "types": {
                "bom_resolved_tree": {
                    "primitive_id": "some_other_unanchored_primitive",
                    "comparator": {"kind": "exact"},
                }
            },
        }
    ).encode("utf-8")
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        spec_bytes_override=other_spec,
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    codes = _reason_codes(result)
    assert "AnchorViolation" in codes, codes
