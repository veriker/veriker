"""tests/test_legal_contract_spec_pinned.py — Axis-2 spec-pinned dispatch tests for
the per-dir migration of examples/legal_contract_minimal.

Representative output: the per-clause case_cites structure in
payload/retrieval_result.json — for each clause (in clause_id order), the ordered
list of matching precedent case_cite ids. Recomputed by ranking every precedent in
inputs/precedents.json by keyword-overlap count with the clause's query_keywords
(descending), breaking ties by case_cite ascending, retaining overlap >= 1.
Comparator: `exact` (no params; the per-clause ordered structure compared
element-wise).

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed value (REORDER one clause's case_cites) -> FAIL
     (REDERIVATION_MISMATCH).
  3. Tampered input (mutate a clause's query_keywords so the ranking re-derives a
     DIFFERENT case_cites list than the honest claimed value) -> FAIL
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
_PILOT_DIR = _PKG_ROOT / "examples" / "legal_contract_minimal"
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
_load("legal_contract_recompute", _PILOT_DIR / "legal_contract_recompute.py")
_spc = _load("legal_contract_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a REORDERED case_cites list for the first clause that has at
    # least two cites — a different ordered structure than the honest re-derivation.
    honest = _spc._honest_case_cites(_spc.build_spec_pinned(tmp_path / "honest"))
    tampered = [dict(e) for e in honest]
    target = next(i for i, e in enumerate(tampered) if len(e["case_cites"]) >= 2)
    cites = list(tampered[target]["case_cites"])
    cites[0], cites[1] = cites[1], cites[0]
    tampered[target] = {**tampered[target], "case_cites": cites}
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle", claimed_override=tampered
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then perturb the COMMITTED clause corpus so the re-derivation
    # produces a different case_cites list than the (honest) claimed value: drop a
    # keyword from cl-001 so one precedent that previously overlapped no longer
    # does. Re-align the manifest SHA so FileIntegrity (step-2/3) does not fire
    # first — isolate the re-derivation mismatch.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    clauses_path = bundle_dir / "inputs" / "clauses.json"
    clauses = json.loads(clauses_path.read_bytes())
    for clause in clauses:
        if clause["clause_id"] == "cl-001":
            # Remove every keyword -> cl-001 retrieves zero cites, diverging from
            # the honest claim (which had 3).
            clause["query_keywords"] = []
            break
    new_bytes = (
        json.dumps(clauses, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")
    clauses_path.write_bytes(new_bytes)

    # The clause corpus is recorded in manifest.files; re-align its SHA so
    # FileIntegrity does not fire first.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["inputs/clauses.json"] = hashlib.sha256(new_bytes).hexdigest()
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
            "spec_id": "legal_contract.v1",
            "types": {
                "legal_contract_case_cites": {
                    "primitive_id": "some_other_unanchored_primitive",
                    "comparator": {"kind": "exact"},
                }
            },
        }
    ).encode("utf-8")
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        claimed_override=[{"clause_id": "x", "clause_title": "x", "case_cites": ["tampered"]}],
        spec_bytes_override=other_spec,
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    codes = _reason_codes(result)
    assert "AnchorViolation" in codes, codes
