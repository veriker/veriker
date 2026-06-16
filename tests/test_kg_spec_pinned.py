"""tests/test_kg_spec_pinned.py — Axis-2 spec-pinned dispatch tests for the
per-dir migration of examples/kg_minimal.

Representative output: the answer_nodes collection in payload/query_result.json —
the unordered SET of node ids reachable by the committed path-query. It is
recomputed by a BFS reachability traversal over kg/triples.jsonl from query.start
along query.predicate up to query.max_depth hops (excluding start), mirroring the
legacy kg_re_derivation pack's _bfs_closure EXACTLY. Comparator: `set` (no params,
order-independent). NOTE: the set-comparator mismatch surfaces under the dispatch's
REDERIVATION_MISMATCH reason code (the dispatch wraps the comparator result).

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed value (add/remove a node from the claimed set) -> FAIL
     (REDERIVATION_MISMATCH).
  3. Tampered input (mutate the committed triples so the reachable set differs;
     re-align manifest SHA so FileIntegrity does not fire first) -> FAIL
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
_PILOT_DIR = _PKG_ROOT / "examples" / "kg_minimal"
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
_load("kg_recompute", _PILOT_DIR / "kg_recompute.py")
_spc = _load("kg_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a DIFFERENT answer_nodes set than the honest re-derivation:
    # drop a reachable node (ex:Dave) and add a node never reached (ex:Eve).
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle", claimed_override=["ex:Bob", "ex:Carol", "ex:Eve"]
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then perturb the COMMITTED triple set so the BFS reachable set
    # differs from the (honest) claimed value: append ex:Bob ex:knows ex:Zoe. Bob is
    # reached at depth 1 and expanded (1 < max_depth=3), so ex:Zoe becomes reachable
    # at depth 2 — a node NOT in the honest claimed set. Re-align manifest SHA so
    # FileIntegrity does not fire first — isolate the re-derivation mismatch.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    triples_path = bundle_dir / "kg" / "triples.jsonl"
    text = triples_path.read_text(encoding="utf-8")
    extra = json.dumps(
        {"object": "ex:Zoe", "predicate": "ex:knows", "subject": "ex:Bob"},
        sort_keys=True,
    )
    new_bytes = (text + extra + "\n").encode("utf-8")
    triples_path.write_bytes(new_bytes)

    # kg/triples.jsonl is a payload file recorded in manifest.files; re-align its
    # SHA so FileIntegrityManySmall (step-2) does not fire before dispatch.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["kg/triples.jsonl"] = hashlib.sha256(new_bytes).hexdigest()
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
    # §4a attack: producer ships a spec the auditor did NOT anchor. Same spec_id,
    # but a DIFFERENT primitive_id -> different bytes -> different SHA. The auditor
    # anchor is computed from the COMMITTED spec, so the substituted spec's SHA is
    # not anchored -> fail-closed.
    other_spec = json.dumps(
        {
            "spec_id": "kg.v1",
            "types": {
                "kg_answer_nodes": {
                    "primitive_id": "some_other_unanchored_primitive",
                    "comparator": {"kind": "set"},
                }
            },
        }
    ).encode("utf-8")
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        claimed_override=["ex:Bob", "ex:Carol", "ex:Dave"],
        spec_bytes_override=other_spec,
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    codes = _reason_codes(result)
    assert "AnchorViolation" in codes, codes
