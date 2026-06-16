"""tests/test_pii_redaction_spec_pinned.py — Axis-2 spec-pinned dispatch tests for the
per-dir migration of examples/pii_redaction_minimal.

Representative output: the aggregated redaction spans in payload/redaction_output.json
— the unordered SET of [token_start, token_end, category] span tuples. It is
recomputed by a constrained-Viterbi decode over the committed BIOES logits tensor
(payload/bioes_logits.json) under the committed transition-bias vector
(redaction_output.bias_vector), then aggregated to spans via BIOES grouping, mirroring
the legacy pii_redaction_re_derivation pack's _viterbi + _decode_spans EXACTLY.
Comparator: `set` (no params, order-independent). NOTE: the set-comparator mismatch
surfaces under the dispatch's REDERIVATION_MISMATCH reason code (the dispatch wraps the
comparator result).

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed value (add/remove/alter a span tuple in the claimed set) -> FAIL
     (REDERIVATION_MISMATCH).
  3. Tampered input (mutate the committed BIOES logits so a span changes; re-align
     manifest SHA so FileIntegrity does not fire first) -> FAIL
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
_PILOT_DIR = _PKG_ROOT / "examples" / "pii_redaction_minimal"
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
_load("pii_redaction_recompute", _PILOT_DIR / "pii_redaction_recompute.py")
_spc = _load("pii_redaction_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a DIFFERENT span set than the honest re-derivation: drop the
    # real email span [5, 6, "private_email"] and add a span never decoded
    # [99, 100, "secret"].
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        claimed_override=[
            [1, 3, "private_person"],
            [10, 13, "private_date"],
            [99, 100, "secret"],
        ],
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then perturb the COMMITTED BIOES logits so the Viterbi decode
    # changes: at the email token (index 5, decoded private_email S = state 11),
    # suppress the hot S tag and peak O (state 32). The email span vanishes from the
    # re-derivation, but the (honest) claimed set still lists it -> set mismatch.
    # Re-align manifest SHA so FileIntegrity does not fire first — isolate the
    # re-derivation mismatch.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    logits_path = bundle_dir / "payload" / "bioes_logits.json"
    obj = json.loads(logits_path.read_text(encoding="utf-8"))
    email_tok = 5
    obj["logits"][email_tok][11] = -9.0  # crush the private_email S tag
    obj["logits"][email_tok][32] = 9.0   # peak O so the token decodes outside
    new_bytes = (json.dumps(obj, indent=2) + "\n").encode("utf-8")
    logits_path.write_bytes(new_bytes)

    # payload/bioes_logits.json is recorded in manifest.files; re-align its SHA so
    # FileIntegrityManySmall (step-2) does not fire before dispatch.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["payload/bioes_logits.json"] = hashlib.sha256(new_bytes).hexdigest()
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


def test_substituted_spec_fails_closed(tmp_path):
    # §4a attack: producer ships a spec the auditor did NOT anchor. Same spec_id,
    # but a DIFFERENT primitive_id -> different bytes -> different SHA. The auditor
    # anchor is computed from the COMMITTED spec, so the substituted spec's SHA is
    # not anchored -> fail-closed.
    other_spec = json.dumps(
        {
            "spec_id": "pii_redaction.v1",
            "types": {
                "pii_redaction_spans": {
                    "primitive_id": "some_other_unanchored_primitive",
                    "comparator": {"kind": "set"},
                }
            },
        }
    ).encode("utf-8")
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        claimed_override=[
            [1, 3, "private_person"],
            [5, 6, "private_email"],
            [10, 13, "private_date"],
        ],
        spec_bytes_override=other_spec,
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    codes = _reason_codes(result)
    assert "AnchorViolation" in codes, codes
