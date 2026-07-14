"""tests/test_recipe_anticheat_adjudication_promoted.py — the `first-match-with-default
decision list` shape, SECOND member (after prior_auth), PROMOTED into the shippable
core registry (RECIPE_BOOK.md, Tier-3 decision-list cluster, first-match sub-family).

Two things are proven, deliberately without a tautology:

  GENERIC SAFE PATH. The bundle is verified by a BARE BundleVerifier under an
  auditor SpecAnchor with NO demo-local register_primitive and WITHOUT importing
  the primitive module at all. The recompute resolves ONLY via core
  auto-registration (run_spec_pinned_dispatch -> _ensure_primitives_loaded ->
  import primitives -> anticheat_adjudication self-registers). If unpromoted,
  dispatch -> UNKNOWN_PRIMITIVE.

  PRODUCER-FAITHFULNESS (not f(x)==f(x)). The producer's claimed verdict list is
  the 2-field {model_recommendation, matched_rule_id} POSITIONAL projection of the
  producer's OWN payload/ban_decisions.json — emitted by _build_bundle.py's inline
  _evaluate_rule / _derive_decision, an INDEPENDENT code copy from the verifier's
  primitives/anticheat_adjudication.py (disjointness enforced structurally by
  test_recipe_producer_verifier_disjoint.py). (The producer records additionally
  carry case_id and final_verdict — the HMAC adjudicator-attestation half — both
  out of scope for this re-derivation and projected out.) The verifier re-derives
  its own verdict list from the committed evidence/ files and the `exact` comparator
  compares element-wise. An honest PASS proves the two independent rule-traversal
  paths agree; the claim is never routed through the verifier's own
  compute_verdict_list.

Run SOLO — shared bundle basenames collide in one pytest process.

Surfaces:
  1. Honest bundle -> PASS (generic safe path AND producer-faithfulness).
  2. Tampered claimed verdict (flip one model_recommendation) -> REDERIVATION_MISMATCH.
  3. Tampered committed input rule (flip rule-C verdict ban->review so case AC-2026-003
     re-derives review, diverging from the honest ban claim) -> REDERIVATION_MISMATCH.
For (2)/(3) the manifest file SHA is re-aligned so FileIntegrity does not fire first.

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

# NOTE: the verifier's recompute primitive (primitives/anticheat_adjudication.py) is
# deliberately NOT imported here. The claim is derived from the producer artifact,
# and the primitive must resolve ONLY via dispatch's core auto-registration.
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.dispatch_record_wellformed import (  # noqa: E402
    DispatchRecordWellformedCheck,
)
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from examples._spec_pinned_overlay import apply_overlay, compute_anchor  # noqa: E402

_PILOT_DIR = _PKG_ROOT / "examples" / "anticheat_adjudication_minimal"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "anticheat_adjudication.spec.json"
_PRODUCER_CLAIM_REL = "payload/ban_decisions.json"
_OUTPUT_ID = "anticheat_adjudication_verdict_list"
_TYPE_KEY = "anticheat_adjudication_verdict_list"
# The re-derivation's 2 representative fields (positional — case_id and final_verdict
# are out of scope).
_REDERIVED_FIELDS = ("model_recommendation", "matched_rule_id")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _producer_claim(out_dir: Path) -> list:
    """The producer's INDEPENDENT decision list, projected to the re-derived fields."""
    producer_decisions = json.loads((out_dir / _PRODUCER_CLAIM_REL).read_bytes())
    return [{k: rec[k] for k in _REDERIVED_FIELDS} for rec in producer_decisions]


def _build(out_dir: Path, *, claimed_override=None):
    """Build a spec-pinned anticheat bundle producer-side. Returns (bundle, anchor).

    The base bundle is produced by the pilot's real _build_bundle.py (evidence/,
    payload/ban_decisions.json, manifest). The HONEST claim is the producer's OWN
    decision list projected to the 2 re-derived fields. The generic β overlay then
    adds the auditor spec, the producer claimed-value file, and manifest.outputs.
    """
    subprocess.run(
        [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(out_dir)],
        check=True,
        capture_output=True,
    )
    claimed = _producer_claim(out_dir) if claimed_override is None else claimed_override
    apply_overlay(
        out_dir,
        spec_src_path=_SPEC_SRC,
        output_id=_OUTPUT_ID,
        type_key=_TYPE_KEY,
        claimed_value=claimed,
    )
    mp = out_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["typed_checks"] = ["file_integrity_many_small"]
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))
    return out_dir, compute_anchor(_SPEC_SRC)


def _realign_file_sha(bundle_dir: Path, rel: str) -> None:
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][rel] = _sha256((bundle_dir / rel).read_bytes())
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))


def _verify(bundle_dir: Path, anchor):
    # BARE verifier: FileIntegrity + spec-pinned dispatch under the auditor anchor.
    # NO register_primitive — the recompute resolves only via the CORE registry.
    return BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            # The bundle carries dispatch_records; verify()'s stamp-claims
            # coverage guard fails closed unless C15 well-formedness and the
            # C14 lattice claim are both evaluated (2026-06-12). Orthogonal
            # to what this test proves (core-registry recompute path).
            DispatchRecordWellformedCheck(
                op_kinds_admitted=frozenset(
                    {"DETECTION_EVAL", "ADJUDICATOR_ATTEST", "COMPUTE"}
                )
            ),
            StampLatticeCheck(),
        ],
        spec_anchor=anchor,
    ).verify(bundle_dir)


def test_promoted_generic_safe_path_and_faithfulness_pass(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    result = _verify(bundle_dir, anchor)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_promoted_tampered_value_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Flip one claimed model_recommendation (AC-2026-001 honest = "ban").
    claim_path = bundle_dir / "outputs" / f"{_OUTPUT_ID}.json"
    doc = json.loads(claim_path.read_bytes())
    verdicts = doc["value"]
    assert verdicts, "expected a non-empty claimed verdict list"
    original = verdicts[0]["model_recommendation"]
    verdicts[0]["model_recommendation"] = "clear" if original != "clear" else "ban"
    claim_path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    _realign_file_sha(bundle_dir, f"outputs/{_OUTPUT_ID}.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert _reason_codes(result) == {"REDERIVATION_MISMATCH"}, _reason_codes(result)


def test_promoted_tampered_input_rule_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Case AC-2026-003 first-matches rule-C-wallhack-prefire (prefire_rate 0.72 >= 0.6)
    # → honest verdict "ban". Flip that committed rule's verdict ban -> review: the
    # recompute now yields "review" for that case, diverging from the honest claim.
    policy_path = bundle_dir / "evidence" / "detection_policy.json"
    policy = json.loads(policy_path.read_bytes())
    for r in policy:
        if r["rule_id"] == "rule-C-wallhack-prefire":
            r["verdict"] = "review"
    policy_path.write_bytes(json.dumps(policy, indent=2).encode("utf-8"))
    _realign_file_sha(bundle_dir, "evidence/detection_policy.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert _reason_codes(result) == {"REDERIVATION_MISMATCH"}, _reason_codes(result)


def _load_producer_module():
    """Load the pilot's producer _build_bundle.py by path (unique module name) so we
    can reach its INDEPENDENT inline _evaluate_rule / _derive_decision. Module-level
    execution is just constants + function defs (build() is guarded by __main__)."""
    import importlib.util as ilu

    spec = ilu.spec_from_file_location(
        "anticheat__producer_for_agreement", _BUILD_SCRIPT
    )
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_core_and_producer_rule_eval_agree_across_condition_branches():
    """Faithfulness across ALL condition branches, not just the 6-case fixture.

    Import the core primitive's _evaluate_rule / _derive_decision HERE (not at module
    top — the Gate-B surfaces above must resolve the primitive only via core
    auto-registration) and the producer's INDEPENDENT inline copies, and assert they
    agree over a matrix covering: >= true/false, <= true/false, multi-condition AND
    (one fails), missing signal, the UNKNOWN-comparator raise (fail-closed on BOTH
    sides since the 2026-06-12 BLOCK-01 hardening), and the no-match clear
    default. Proves the recompute mirrors the producer by construction.
    """
    from audit_bundle.rederivation.primitives.anticheat_adjudication import (
        _derive_decision as core_derive,
    )
    from audit_bundle.rederivation.primitives.anticheat_adjudication import (
        _evaluate_rule as core_eval,
    )

    producer = _load_producer_module()
    prod_eval = producer._evaluate_rule
    prod_derive = producer._derive_decision

    signals = {"a": 0.8, "b": 0.2, "c": 100.0}

    def rule(conditions, verdict="ban", rule_id="r-x"):
        return {"rule_id": rule_id, "conditions": conditions, "verdict": verdict}

    cases = [
        rule([{"signal": "a", "comparator": ">=", "threshold": 0.5}]),  # 0.8>=0.5 True
        rule([{"signal": "a", "comparator": ">=", "threshold": 0.9}]),  # 0.8>=0.9 False
        rule(
            [{"signal": "a", "comparator": ">=", "threshold": 0.8}]
        ),  # 0.8>=0.8 boundary True
        rule([{"signal": "b", "comparator": "<=", "threshold": 0.5}]),  # 0.2<=0.5 True
        rule([{"signal": "b", "comparator": "<=", "threshold": 0.1}]),  # 0.2<=0.1 False
        rule(
            [{"signal": "b", "comparator": "<=", "threshold": 0.2}]
        ),  # 0.2<=0.2 boundary True
        rule(
            [
                {"signal": "a", "comparator": ">=", "threshold": 0.5},
                {
                    "signal": "b",
                    "comparator": "<=",
                    "threshold": 0.5,
                },  # both pass → AND True
            ]
        ),
        rule(
            [
                {"signal": "a", "comparator": ">=", "threshold": 0.5},
                {
                    "signal": "c",
                    "comparator": "<=",
                    "threshold": 50.0,
                },  # 100<=50 False → AND fails
            ]
        ),
        rule(
            [{"signal": "missing", "comparator": ">=", "threshold": 0.0}]
        ),  # absent → False
    ]
    for r in cases:
        assert core_eval(signals, r) == prod_eval(signals, r), r

    # Unknown comparator → ValueError on BOTH sides (fail-closed parity): an
    # unevaluable policy condition is never treated as satisfied — by the
    # verifier (→ RECOMPUTE_ERROR) or by the producer (refuses to build).
    import pytest

    bad = rule([{"signal": "a", "comparator": "~=", "threshold": 0.5}])
    with pytest.raises(ValueError, match="unknown condition comparator"):
        core_eval(signals, bad)
    with pytest.raises(ValueError, match="unknown condition comparator"):
        prod_eval(signals, bad)

    # Type-mismatch (string signal vs numeric threshold): BOTH copies reach the same
    # bare comparison and raise TypeError in py3 — fail-closed parity (core → a dispatch
    # RECOMPUTE_ERROR; producer → a build-time raise). Asserted so the parity is tested,
    # not just asserted in prose.
    import pytest

    type_mismatch = rule([{"signal": "s", "comparator": ">=", "threshold": 0.5}])
    with pytest.raises(TypeError):
        core_eval({"s": "high"}, type_mismatch)
    with pytest.raises(TypeError):
        prod_eval({"s": "high"}, type_mismatch)

    # No-match → clear default (note: producer keeps case_id, core drops it — compare
    # only the re-derived fields), and a first-match path.
    case = {"case_id": "AC-X", "signals": signals}
    no_match_policy = [rule([{"signal": "a", "comparator": ">=", "threshold": 0.99}])]
    fields = ("model_recommendation", "matched_rule_id")
    cd = core_derive(case, no_match_policy)
    pd = prod_derive(case, no_match_policy)
    assert {k: cd[k] for k in fields} == {k: pd[k] for k in fields}
    match_policy = [rule([{"signal": "a", "comparator": ">=", "threshold": 0.5}])]
    cd2 = core_derive(case, match_policy)
    pd2 = prod_derive(case, match_policy)
    assert {k: cd2[k] for k in fields} == {k: pd2[k] for k in fields}
