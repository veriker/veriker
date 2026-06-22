"""tests/test_recipe_prior_auth_promoted.py — the `first-match-with-default
decision list` shape is PROMOTED into the shippable core registry (RECIPE_BOOK.md,
Tier-3 decision-list cluster, first-match sub-family).

Two things are proven, deliberately without a tautology:

  GENERIC SAFE PATH. The bundle is verified by a BARE BundleVerifier under an
  auditor SpecAnchor with NO demo-local register_primitive and WITHOUT importing
  the primitive module at all. The only thing that resolves the recompute is the
  core registry auto-registration (run_spec_pinned_dispatch ->
  _ensure_primitives_loaded -> import primitives -> prior_auth self-registers). If
  prior_auth were not promoted, the dispatch would fail UNKNOWN_PRIMITIVE.

  PRODUCER-FAITHFULNESS (not f(x)==f(x)). The producer's claimed decision list is
  the 3-field {request_id, model_recommendation, matched_rule_id} PROJECTION of the
  producer's OWN payload/prior_auth_decisions.json — emitted by _build_bundle.py's
  inline _evaluate_rule / _derive_decision, an INDEPENDENT code copy from the
  verifier's primitives/prior_auth.py (disjointness enforced structurally by
  test_recipe_producer_verifier_disjoint.py). (The producer file additionally
  carries `final_verdict`, the provider-attestation half, which is NOT part of this
  re-derivation and is projected out.) The verifier re-derives its own decision list
  from the committed clinical/findings.jsonl + plan_rules.json and the `exact`
  comparator compares element-wise. An honest PASS proves the two independent
  rule-traversal paths agree; the claim is never routed through the verifier's own
  compute_decisions.

Run SOLO — shared bundle basenames collide in one pytest process.

Surfaces:
  1. Honest bundle -> PASS (generic safe path AND producer-faithfulness).
  2. Tampered claimed verdict (flip one model_recommendation) -> REDERIVATION_MISMATCH.
  3. Tampered committed input rule (drop a rule's required diagnosis so a denied
     request now first-matches that rule) -> REDERIVATION_MISMATCH.
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

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# NOTE: the verifier's recompute primitive (primitives/prior_auth.py) is
# deliberately NOT imported here. The claim is derived from the producer artifact,
# and the primitive must resolve ONLY via dispatch's core auto-registration.
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.dispatch_record_wellformed import (  # noqa: E402
    DispatchRecordWellformedCheck,
)
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from examples._spec_pinned_overlay import apply_overlay, compute_anchor  # noqa: E402

_PILOT_DIR = _PKG_ROOT / "examples" / "prior_auth_minimal"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "prior_auth.spec.json"
_PRODUCER_CLAIM_REL = "payload/prior_auth_decisions.json"
_OUTPUT_ID = "prior_auth_decisions"
_TYPE_KEY = "prior_auth_decisions"
# The re-derivation's 3 representative fields (final_verdict is the provider-
# attestation half, out of scope for this binding).
_REDERIVED_FIELDS = ("request_id", "model_recommendation", "matched_rule_id")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _producer_claim(out_dir: Path) -> list:
    """The producer's INDEPENDENT decision list, projected to the re-derived fields."""
    producer_decisions = json.loads((out_dir / _PRODUCER_CLAIM_REL).read_bytes())
    return [{k: rec[k] for k in _REDERIVED_FIELDS} for rec in producer_decisions]


def _build(out_dir: Path, *, claimed_override=None):
    """Build a spec-pinned prior_auth bundle producer-side. Returns (bundle, anchor).

    The base bundle is produced by the pilot's real _build_bundle.py
    (clinical/findings.jsonl, clinical/plan_rules.json, payload/prior_auth_decisions.json,
    manifest). The HONEST claim is the producer's OWN decision list projected to the
    3 re-derived fields. The generic β overlay then adds the auditor spec, the
    producer claimed-value file, and manifest.outputs.
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
        plugins=[
            FileIntegrityManySmall(),
            # The bundle carries dispatch_records; verify()'s stamp-claims
            # coverage guard fails closed unless C15 well-formedness and the
            # C14 lattice claim are both evaluated (2026-06-12). Orthogonal
            # to what this test proves (core-registry recompute path).
            DispatchRecordWellformedCheck(
                op_kinds_admitted=frozenset(
                    {"MEDICAL_NECESSITY_EVAL", "PROVIDER_ATTEST", "COMPUTE"}
                )
            ),
            StampLatticeCheck(),
        ],
        spec_anchor=anchor,
    ).verify(bundle_dir)


def test_promoted_generic_safe_path_and_faithfulness_pass(tmp_path):
    # Honest PASS proves BOTH: the generic verifier resolves prior_auth via core
    # auto-registration (no import, no demo registration), AND the verifier's
    # recompute agrees with the producer's independent decision list.
    bundle_dir, anchor = _build(tmp_path / "bundle")
    result = _verify(bundle_dir, anchor)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_promoted_tampered_value_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Flip one claimed model_recommendation to a different label.
    claim_path = bundle_dir / "outputs" / f"{_OUTPUT_ID}.json"
    doc = json.loads(claim_path.read_bytes())
    decisions = doc["value"]
    assert decisions, "expected a non-empty claimed decision list"
    original = decisions[0]["model_recommendation"]
    decisions[0]["model_recommendation"] = "deny" if original != "deny" else "approve"
    claim_path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    _realign_file_sha(bundle_dir, f"outputs/{_OUTPUT_ID}.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert _reason_codes(result) == {"REDERIVATION_MISMATCH"}, _reason_codes(result)


def test_promoted_tampered_input_rule_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Request PA-2026-005 (cosmetic_procedure, no diagnoses/treatments/lab)
    # first-matches rule-deny-all-elective-cosmetic directly, so its honest
    # re-derived verdict is "deny". Flip that committed rule's verdict deny ->
    # approve: the recompute now yields "approve" for PA-2026-005, diverging from
    # the honest producer claim -> REDERIVATION_MISMATCH.
    rules_path = bundle_dir / "clinical" / "plan_rules.json"
    rules = json.loads(rules_path.read_bytes())
    for r in rules:
        if r["rule_id"] == "rule-deny-all-elective-cosmetic":
            r["verdict"] = "approve"
    rules_path.write_bytes(json.dumps(rules, indent=2).encode("utf-8"))
    _realign_file_sha(bundle_dir, "clinical/plan_rules.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert _reason_codes(result) == {"REDERIVATION_MISMATCH"}, _reason_codes(result)


def _load_producer_module():
    """Load the pilot's producer _build_bundle.py by path (unique module name) so
    we can reach its INDEPENDENT inline _evaluate_rule / _derive_decision. Module-
    level execution is just constants + function defs (build() is guarded by
    __main__)."""
    import importlib.util as ilu

    spec = ilu.spec_from_file_location(
        "prior_auth__producer_for_agreement", _BUILD_SCRIPT
    )
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_core_and_producer_rule_eval_agree_across_condition_branches():
    """Faithfulness across ALL rule-condition branches, not just the 5-request fixture.

    Import the core primitive's _evaluate_rule / _derive_decision HERE (not at module
    top — the Gate-B surfaces above must resolve the primitive only via core
    auto-registration) and the producer's INDEPENDENT inline copies, and assert they
    agree over a matrix covering every branch: category mismatch, missing diagnosis,
    missing prior treatment, lab >= true/false, lab <= true/false, missing lab, the
    UNKNOWN-comparator raise (fail-closed on BOTH sides since the 2026-06-12
    BLOCK-01 hardening — see the primitive docstring), and the no-match deny default.
    This proves the promoted recompute mirrors the producer's rule-traversal by
    construction, so the honest-PASS agreement is not a coincidence of the fixture.
    """
    from audit_bundle.rederivation.primitives.prior_auth import (
        _derive_decision as core_derive,
    )
    from audit_bundle.rederivation.primitives.prior_auth import (
        _evaluate_rule as core_eval,
    )

    producer = _load_producer_module()
    prod_eval = producer._evaluate_rule
    prod_derive = producer._derive_decision

    base_req = {
        "request_id": "R-1",
        "procedure_category": "advanced_imaging",
        "diagnoses": ["M54.5"],
        "prior_treatments": ["PT-6wk"],
        "lab_values": {"BMI": 42.0},
    }

    def rule(**over):
        r = {
            "rule_id": "r-x",
            "procedure_category": "advanced_imaging",
            "required_diagnoses": [],
            "required_prior_treatments": [],
            "max_lab_value": None,
            "verdict": "approve",
        }
        r.update(over)
        return r

    cases = [
        rule(procedure_category="other"),  # category mismatch → False
        rule(required_diagnoses=["E66.01"]),  # missing diagnosis → False
        rule(required_diagnoses=["M54.5"]),  # diagnosis present → True
        rule(required_prior_treatments=["diet-6mo"]),  # missing treatment → False
        rule(required_prior_treatments=["PT-6wk"]),  # treatment present → True
        rule(
            max_lab_value={"lab": "BMI", "threshold": 40.0, "comparator": ">="}
        ),  # 42>=40 True
        rule(
            max_lab_value={"lab": "BMI", "threshold": 50.0, "comparator": ">="}
        ),  # 42>=50 False
        rule(
            max_lab_value={"lab": "BMI", "threshold": 50.0, "comparator": "<="}
        ),  # 42<=50 True
        rule(
            max_lab_value={"lab": "BMI", "threshold": 40.0, "comparator": "<="}
        ),  # 42<=40 False
        rule(
            max_lab_value={"lab": "SpO2", "threshold": 92.0, "comparator": "<="}
        ),  # missing lab → False
    ]
    for r in cases:
        assert core_eval(base_req, r) == prod_eval(base_req, r), r

    # Unknown comparator → ValueError on BOTH sides (fail-closed parity): an
    # unevaluable policy condition is never treated as satisfied — by the
    # verifier (→ RECOMPUTE_ERROR) or by the producer (refuses to build).
    bad = rule(max_lab_value={"lab": "BMI", "threshold": 40.0, "comparator": ">"})
    with pytest.raises(ValueError, match="unknown max_lab_value comparator"):
        core_eval(base_req, bad)
    with pytest.raises(ValueError, match="unknown max_lab_value comparator"):
        prod_eval(base_req, bad)

    # No-match → deny default (both copies), and a first-match path.
    no_match_req = dict(base_req, procedure_category="nothing_matches")
    assert core_derive(no_match_req, cases) == prod_derive(no_match_req, cases)
    assert core_derive(base_req, [rule(required_diagnoses=["M54.5"])]) == prod_derive(
        base_req, [rule(required_diagnoses=["M54.5"])]
    )
