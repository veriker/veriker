"""tests/test_recipe_fintech_audit_promoted.py — the `all-pairs policy-verdict
decision list` shape is PROMOTED into the shippable core registry (RECIPE_BOOK.md,
Tier-3 decision-list cluster, all-pairs sub-family).

Two things are proven, deliberately without a tautology:

  GENERIC SAFE PATH. The bundle is verified by a BARE BundleVerifier under an
  auditor SpecAnchor with NO demo-local register_primitive and WITHOUT importing
  the primitive module at all. The only thing that resolves the recompute is the
  core registry auto-registration (run_spec_pinned_dispatch ->
  _ensure_primitives_loaded -> import primitives -> fintech_audit self-registers).
  If fintech_audit were not promoted, the dispatch would fail UNKNOWN_PRIMITIVE.

  PRODUCER-FAITHFULNESS (not f(x)==f(x)). The producer's claimed verdict list is
  read from the producer's OWN payload/policy_verdicts.json — emitted by
  _build_bundle.py's inline (transaction × policy) evaluation, an INDEPENDENT code
  copy from the verifier's primitives/fintech_audit.py (the disjointness is
  enforced structurally by test_recipe_producer_verifier_disjoint.py). The verifier
  re-derives its own verdict list from the committed transactions/ + policies/ and
  the `exact` comparator compares element-wise. An honest PASS therefore proves the
  two independent evaluation paths agree on the shipped fixture — if they ever
  drift, this test FAILS. The claim is never routed through the verifier's own
  compute_policy_verdicts.

Run SOLO — shared bundle basenames collide in one pytest process.

Surfaces:
  1. Honest bundle -> PASS (generic safe path AND producer-faithfulness).
  2. Tampered claimed verdict (flip one verdict in the claimed list) ->
     REDERIVATION_MISMATCH.
  3. Tampered committed input rule (raise the large-tx threshold so the re-derived
     verdict for txn-001 flips to NOT_APPLICABLE) -> REDERIVATION_MISMATCH.
For (2)/(3) the manifest file SHA is re-aligned so FileIntegrity does not fire
first — isolating the re-derivation mismatch from a plain integrity failure.

Stdlib-only orchestration; the build runs the pilot's real producer _build_bundle.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# NOTE: the verifier's recompute primitive (primitives/fintech_audit.py) is
# deliberately NOT imported here. The claim is derived from the producer artifact,
# and the primitive must resolve ONLY via dispatch's core auto-registration.
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from examples._spec_pinned_overlay import apply_overlay, compute_anchor  # noqa: E402

_PILOT_DIR = _PKG_ROOT / "examples" / "fintech_audit_minimal"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "fintech_audit.spec.json"
_PRODUCER_CLAIM_REL = "payload/policy_verdicts.json"
_OUTPUT_ID = "fintech_audit_policy_verdicts"
_TYPE_KEY = "fintech_audit_policy_verdicts"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _build(out_dir: Path, *, claimed_override=None):
    """Build a spec-pinned fintech_audit bundle producer-side. Returns (bundle, anchor).

    The base bundle is produced by the pilot's real _build_bundle.py (transactions/,
    policies/, payload/policy_verdicts.json, manifest). The HONEST claimed verdict
    list is the producer's OWN payload/policy_verdicts.json — emitted by an
    evaluation code copy independent of the verifier primitive. The generic β overlay
    then adds the auditor spec, the producer claimed-value file, and manifest.outputs.
    """
    subprocess.run(
        [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(out_dir)],
        check=True,
        capture_output=True,
    )
    # Producer-side claim: the producer's independently-emitted verdict list.
    claimed = json.loads((out_dir / _PRODUCER_CLAIM_REL).read_bytes())
    if claimed_override is not None:
        claimed = claimed_override
    apply_overlay(
        out_dir,
        spec_src_path=_SPEC_SRC,
        output_id=_OUTPUT_ID,
        type_key=_TYPE_KEY,
        claimed_value=claimed,
    )
    # Match manifest.typed_checks to the minimal plugin set we run (the verifier
    # rejects a typed_checks name with no matching plugin instance).
    mp = out_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["typed_checks"] = ["file_integrity_many_small"]
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))
    return out_dir, compute_anchor(_SPEC_SRC)


def _realign_file_sha(bundle_dir: Path, rel: str) -> None:
    """Recompute and store the manifest SHA for one file so FileIntegrity does not
    fire before the re-derivation dispatch can be observed."""
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][rel] = _sha256((bundle_dir / rel).read_bytes())
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))


def _verify(bundle_dir: Path, anchor):
    # BARE verifier: FileIntegrity + spec-pinned dispatch under the auditor anchor.
    # NO register_primitive — the recompute resolves only via the CORE registry.
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()], spec_anchor=anchor
    ).verify(bundle_dir)


def test_promoted_generic_safe_path_and_faithfulness_pass(tmp_path):
    # Honest PASS proves BOTH: the generic verifier resolves fintech_audit via core
    # auto-registration (no import, no demo registration), AND the verifier's
    # recompute agrees with the producer's independent policy_verdicts.json.
    bundle_dir, anchor = _build(tmp_path / "bundle")
    result = _verify(bundle_dir, anchor)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_promoted_tampered_value_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Flip one verdict in the producer's claimed list to a different valid label.
    claim_path = bundle_dir / "outputs" / f"{_OUTPUT_ID}.json"
    doc = json.loads(claim_path.read_bytes())
    verdicts = doc["value"]
    assert verdicts, "expected a non-empty claimed verdict list"
    original = verdicts[0]["verdict"]
    verdicts[0]["verdict"] = "TAMPERED" if original != "TAMPERED" else "ALSO_TAMPERED"
    claim_path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    _realign_file_sha(bundle_dir, f"outputs/{_OUTPUT_ID}.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert _reason_codes(result) == {"REDERIVATION_MISMATCH"}, _reason_codes(result)


def test_promoted_tampered_input_rule_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Mutate the committed large-transaction rule so its threshold exceeds every
    # transaction amount: the re-derived verdict for the matching pair flips to
    # NOT_APPLICABLE, diverging from the (honest) producer-claimed list.
    rule_path = bundle_dir / "policies" / "rule-large-tx.json"
    rule = json.loads(rule_path.read_bytes())
    rule["conditions"][0]["value"] = 10_000_000
    # The primitive parses the rule with json.loads regardless of serialization,
    # so any valid JSON works; the manifest SHA is realigned below so FileIntegrity
    # does not preempt the re-derivation dispatch under test.
    rule_path.write_bytes(json.dumps(rule, indent=2).encode("utf-8"))
    _realign_file_sha(bundle_dir, "policies/rule-large-tx.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert _reason_codes(result) == {"REDERIVATION_MISMATCH"}, _reason_codes(result)


def _load_producer_module():
    """Load the pilot's producer _build_bundle.py by path (unique module name) so
    we can reach its INDEPENDENT inline _eval_condition. Module-level execution is
    just constants + function defs (build() is guarded by __main__)."""
    import importlib.util as ilu

    spec = ilu.spec_from_file_location(
        "fintech_audit__producer_for_agreement", _BUILD_SCRIPT
    )
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_core_and_producer_condition_eval_agree_across_supported_ops():
    """Faithfulness across ALL supported ops, not just the {gt,in} fixture.

    Import the core primitive's _eval_condition HERE (not at module top — the
    Gate-B surfaces above must resolve the primitive only via core
    auto-registration) and the producer's INDEPENDENT inline _eval_condition, and
    assert they agree element-wise over a matrix covering every supported op, the
    true/false side of each, and an absent field. Also assert both are fail-closed
    on an unknown op (both raise). This proves the promoted recompute mirrors the
    producer's semantics, so the honest-PASS agreement is by construction, not a
    coincidence of the 6-record fixture.
    """
    import pytest

    from audit_bundle.rederivation.primitives.fintech_audit import (
        _eval_condition as core_eval,
    )

    producer = _load_producer_module()
    producer_eval = producer._eval_condition

    txn = {"amount_brl": 95000.0, "country": "IR", "kind": "equity"}
    cases = [
        {"field": "amount_brl", "op": "gt", "value": 50000},  # True
        {"field": "amount_brl", "op": "gt", "value": 100000},  # False
        {"field": "amount_brl", "op": "lt", "value": 100000},  # True
        {"field": "amount_brl", "op": "lt", "value": 50000},  # False
        {"field": "kind", "op": "eq", "value": "equity"},  # True
        {"field": "kind", "op": "eq", "value": "bond"},  # False
        {"field": "kind", "op": "ne", "value": "bond"},  # True
        {"field": "kind", "op": "ne", "value": "equity"},  # False
        {"field": "country", "op": "in", "value": ["IR", "KP"]},  # True
        {"field": "country", "op": "in", "value": ["US", "GB"]},  # False
        {"field": "country", "op": "not_in", "value": ["US", "GB"]},  # True
        {"field": "country", "op": "not_in", "value": ["IR", "KP"]},  # False
        {"field": "missing_field", "op": "gt", "value": 0},  # absent → False
    ]
    for cond in cases:
        assert core_eval(txn, cond) == producer_eval(txn, cond), cond

    # Both are fail-closed on an unknown op (mirror, not silently-False).
    bad = {"field": "amount_brl", "op": "approximately", "value": 1}
    with pytest.raises(ValueError):
        core_eval(txn, bad)
    with pytest.raises(ValueError):
        producer_eval(txn, bad)
