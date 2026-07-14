"""tests/test_fintech_audit_spec_pinned.py — Axis-2 spec-pinned dispatch tests
for the per-dir migration of examples/fintech_audit_minimal.

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed list (flip one verdict) -> FAIL (REDERIVATION_MISMATCH).
  3. Tampered input (mutate txn-002 counterparty_country IR->US so the
     restricted-jurisdiction verdict flips BLOCKED->NOT_APPLICABLE) -> FAIL
     (REDERIVATION_MISMATCH): re-derivation from the tampered evidence no longer
     agrees with the (honest) claimed list. The manifest SHA is re-aligned on the
     mutated file so FileIntegrity does not fire first.
  4. No auditor anchor while the bundle declares outputs -> fail-closed
     (AnchorViolation).
  5. §4a attack: producer ships a substituted pinned spec (a SHA the auditor did
     not anchor) with a tampered list -> still fail-closed (the strong
     committed-spec anchor does not list the substituted spec's SHA).
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
_PILOT_DIR = _PKG_ROOT / "examples" / "fintech_audit_minimal"
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
_load("fintech_audit_recompute", _PILOT_DIR / "fintech_audit_recompute.py")
_spc = _load("fintech_audit_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _honest_claimed(bundle_dir: Path) -> list:
    return json.loads(
        (bundle_dir / "outputs" / "fintech_audit_policy_verdicts.json").read_bytes()
    )["value"]


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer flips one verdict in the claimed list (the txn-002 /
    # restricted-jurisdiction record claims NOT_APPLICABLE instead of the honest
    # BLOCKED), so the claimed list no longer matches the re-derivation.
    honest = _spc.build_spec_pinned(tmp_path / "honest")
    claimed = copy.deepcopy(_honest_claimed(honest))
    flipped = False
    for rec in claimed:
        if rec["txn_id"] == "txn-002" and rec["rule_id"] == "rule-restricted-jurisdiction":
            assert rec["verdict"] == "BLOCKED", rec
            rec["verdict"] = "NOT_APPLICABLE"
            rec["matched_conditions"] = []
            flipped = True
    assert flipped, "expected a txn-002/restricted-jurisdiction BLOCKED record to flip"

    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle", claimed_override=claimed)
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then mutate txn-002 counterparty_country IR -> US. The
    # restricted-jurisdiction "in [IR,KP]" condition no longer holds, so the
    # re-derived verdict for that pair flips BLOCKED -> NOT_APPLICABLE — the
    # claimed (honest) list no longer matches the re-derivation from tampered
    # evidence.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    txn_path = bundle_dir / "transactions" / "txn-002.json"
    raw = txn_path.read_bytes()
    assert b'"counterparty_country":"IR"' in raw, raw
    new_bytes = raw.replace(b'"counterparty_country":"IR"', b'"counterparty_country":"US"', 1)
    txn_path.write_bytes(new_bytes)
    # Re-align manifest SHA so FileIntegrity does not fire first — isolate the
    # re-derivation mismatch.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["transactions/txn-002.json"] = hashlib.sha256(new_bytes).hexdigest()
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
    # anchor) AND tampers the claimed list. The auditor anchor is computed from
    # the COMMITTED spec, so the substituted spec's SHA is not anchored ->
    # fail-closed.
    substituted_spec = json.dumps(
        {
            "spec_id": "fintech_audit.attacker",
            "types": {
                "fintech_audit_policy_verdicts": {
                    "primitive_id": "fintech_audit_recompute",
                    "comparator": {"kind": "exact"},
                }
            },
        }
    ).encode("utf-8")
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        claimed_override=[{"txn_id": "txn-001", "rule_id": "x", "matched_conditions": [], "verdict": "NOT_APPLICABLE"}],
        spec_bytes_override=substituted_spec,
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    codes = _reason_codes(result)
    assert "AnchorViolation" in codes, codes
