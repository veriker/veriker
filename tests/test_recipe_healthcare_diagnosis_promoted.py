"""tests/test_recipe_healthcare_diagnosis_promoted.py — the `fire-and-collect`
decision-list shape (family C), PROMOTED into the shippable core registry
(RECIPE_BOOK.md, Tier-3 decision-list cluster). Fire-and-collect emits a value for
every FIRING rule (no first-match early stop, no default) and collects them in
sorted rule_id order.

Two things are proven, deliberately without a tautology:

  GENERIC SAFE PATH. The bundle is verified by a BARE BundleVerifier under an
  auditor SpecAnchor with NO demo-local register_primitive and WITHOUT importing
  the primitive module at all. The recompute resolves ONLY via core
  auto-registration (run_spec_pinned_dispatch -> _ensure_primitives_loaded ->
  import primitives -> healthcare_diagnosis self-registers). If unpromoted,
  dispatch -> UNKNOWN_PRIMITIVE.

  PRODUCER-FAITHFULNESS (not f(x)==f(x)). The producer's claimed code list is the
  ordered icd10_code projection of the producer's OWN payload/diagnosis.json —
  emitted by _build_bundle.py's inline _eval_condition / _derive_candidates, an
  INDEPENDENT code copy from the verifier's primitives/healthcare_diagnosis.py
  (disjointness enforced structurally by test_recipe_producer_verifier_disjoint.py).
  (The producer candidates additionally carry confidence, description,
  matched_symptom_ids, rule_id, rule_path — all out of scope for this re-derivation
  and projected out; only the categorical icd10_code strings remain so the `exact`
  comparator stays float-free.) The verifier re-derives its own code list from the
  committed inputs/ files and the `exact` comparator compares element-wise. An honest
  PASS proves the two independent rule-traversal paths agree; the claim is never
  routed through the verifier's own compute_icd10_codes.

Run SOLO — shared bundle basenames collide in one pytest process.

Surfaces:
  1. Honest bundle -> PASS (generic safe path AND producer-faithfulness).
  2. Tampered claimed code (flip one icd10_code) -> REDERIVATION_MISMATCH.
  3. Tampered committed input rule (raise rule-J18's sym-001 min_severity above the
     present severity so rule-J18 no longer fires and its J18.9 code drops, diverging
     from the honest claim) -> REDERIVATION_MISMATCH.
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

# NOTE: the verifier's recompute primitive (primitives/healthcare_diagnosis.py) is
# deliberately NOT imported here. The claim is derived from the producer artifact,
# and the primitive must resolve ONLY via dispatch's core auto-registration.
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from examples._spec_pinned_overlay import apply_overlay, compute_anchor  # noqa: E402

_PILOT_DIR = _PKG_ROOT / "examples" / "healthcare_diagnosis_minimal"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "healthcare_diagnosis.spec.json"
_PRODUCER_CLAIM_REL = "payload/diagnosis.json"
_OUTPUT_ID = "healthcare_diagnosis_codes"
_TYPE_KEY = "healthcare_diagnosis_codes"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _producer_claim(out_dir: Path) -> list:
    """The producer's INDEPENDENT candidate list, projected to the ordered
    icd10_code list (the single re-derived value; confidence/description/etc. out)."""
    candidates = json.loads((out_dir / _PRODUCER_CLAIM_REL).read_bytes())
    return [rec["icd10_code"] for rec in candidates]


def _build(out_dir: Path, *, claimed_override=None):
    """Build a spec-pinned healthcare-diagnosis bundle producer-side. Returns
    (bundle, anchor).

    The base bundle is produced by the pilot's real _build_bundle.py (inputs/,
    payload/diagnosis.json, manifest). The HONEST claim is the producer's OWN
    candidate list projected to the ordered icd10_code list. The generic β overlay
    then adds the auditor spec, the producer claimed-value file, and manifest.outputs.
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
        plugins=[FileIntegrityManySmall()], spec_anchor=anchor
    ).verify(bundle_dir)


def test_promoted_generic_safe_path_and_faithfulness_pass(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    result = _verify(bundle_dir, anchor)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]
    # Sanity: the honest claim is the producer's full 4-code fire-and-collect list.
    claim = json.loads((bundle_dir / "outputs" / f"{_OUTPUT_ID}.json").read_bytes())[
        "value"
    ]
    assert claim == ["A49.9", "I20.9", "J18.9", "R51.9"], claim


def test_promoted_tampered_value_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Flip one claimed icd10_code (first entry) — a different ordered list than the
    # honest re-derivation.
    claim_path = bundle_dir / "outputs" / f"{_OUTPUT_ID}.json"
    doc = json.loads(claim_path.read_bytes())
    codes = doc["value"]
    assert codes, "expected a non-empty claimed code list"
    codes[0] = "Z99.9" if codes[0] != "Z99.9" else "Z00.0"
    claim_path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    _realign_file_sha(bundle_dir, f"outputs/{_OUTPUT_ID}.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert _reason_codes(result) == {"REDERIVATION_MISMATCH"}, _reason_codes(result)


def test_promoted_tampered_input_rule_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # rule-J18 fires on the honest fixture (sym-001 sev 3 >= 2, sym-002 sev 4 >= 3,
    # sym-005 sev 3 >= 2) -> J18.9 in the honest claim. Raise its sym-001 condition
    # min_severity to 6 (present severity 3 < 6): rule-J18 stops firing and J18.9
    # drops from the re-derivation, diverging from the honest 4-code claim.
    rules_path = bundle_dir / "inputs" / "rules.json"
    rules = json.loads(rules_path.read_bytes())
    flipped = False
    for r in rules:
        if r["rule_id"] == "rule-J18":
            for c in r["conditions"]:
                if c["symptom_id"] == "sym-001":
                    c["min_severity"] = 6
                    flipped = True
    assert flipped, "expected to flip rule-J18's sym-001 min_severity"
    rules_path.write_bytes(json.dumps(rules, indent=2).encode("utf-8"))
    _realign_file_sha(bundle_dir, "inputs/rules.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    # EXACT set: only REDERIVATION_MISMATCH, nothing else. This holds because the
    # tampered rule still yields a non-empty code list (3 of 4 codes) written to the
    # single declared output, so the coverage check stays inert and FileIntegrity is
    # re-aligned above — the ONLY failing signal is the re-derivation divergence.
    assert _reason_codes(result) == {"REDERIVATION_MISMATCH"}, _reason_codes(result)


def test_promoted_loaders_fail_closed_on_missing_inputs(tmp_path):
    """The recompute loaders must raise (-> RECOMPUTE_ERROR at dispatch), never
    invent a code list, when a committed input file is absent. Exercises the
    FileNotFoundError fail-closed branch the agreement test cannot reach."""
    import pytest

    from audit_bundle.rederivation.primitives.healthcare_diagnosis import (
        _load_rules,
        _load_symptoms,
    )

    empty = tmp_path / "empty_bundle"
    empty.mkdir()
    with pytest.raises(FileNotFoundError):
        _load_symptoms(empty)
    with pytest.raises(FileNotFoundError):
        _load_rules(empty)


def _load_producer_module():
    """Load the pilot's producer _build_bundle.py by path (unique module name) so we
    can reach its INDEPENDENT inline _eval_condition / _derive_candidates. Module-level
    execution is just constants + function defs (build() is guarded by __main__)."""
    import importlib.util as ilu

    spec = ilu.spec_from_file_location(
        "healthcare_diagnosis__producer_for_agreement", _BUILD_SCRIPT
    )
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_core_and_producer_rule_eval_agree_across_condition_branches():
    """Faithfulness across condition branches, not just the 4-code fixture.

    Import the core primitive's _eval_condition / compute_icd10_codes HERE (not at
    module top — the Gate-B surfaces above must resolve the primitive only via core
    auto-registration) and the producer's INDEPENDENT inline copies, and assert they
    agree over a matrix covering: symptom present at/above/below min_severity
    (boundary), absent symptom, single- and multi-condition AND (pass and fail),
    multi-rule fire-and-collect ordering, and no-fire. Proves the recompute mirrors
    the producer by construction.
    """
    from audit_bundle.rederivation.primitives.healthcare_diagnosis import (
        _eval_condition as core_eval,
    )
    from audit_bundle.rederivation.primitives.healthcare_diagnosis import (
        compute_icd10_codes as core_codes,
    )

    producer = _load_producer_module()
    prod_eval = producer._eval_condition
    prod_derive = producer._derive_candidates

    # --- _eval_condition agreement: present above/at/below boundary, absent. ---
    symptom_map = {"sym-x": {"symptom_id": "sym-x", "severity": 3}}

    def cond(sid, min_sev):
        return {"symptom_id": sid, "min_severity": min_sev}

    branches = [
        cond("sym-x", 2),  # 3 >= 2 present-above -> True
        cond("sym-x", 3),  # 3 >= 3 boundary     -> True
        cond("sym-x", 4),  # 3 >= 4 present-below -> False
        cond("sym-missing", 1),  # absent          -> False
    ]
    for c in branches:
        assert core_eval(symptom_map, c) == prod_eval(symptom_map, c), c

    # --- compute_icd10_codes vs producer _derive_candidates (projected). ---
    symptoms = [
        {"symptom_id": "sym-001", "name": "a", "severity": 3},
        {"symptom_id": "sym-002", "name": "b", "severity": 4},
        {"symptom_id": "sym-003", "name": "c", "severity": 1},
    ]

    def rule(rule_id, code, conditions, weight=0.1):
        return {
            "rule_id": rule_id,
            "icd10_code": code,
            "description": code,
            "conditions": conditions,
            "confidence_weight": weight,
        }

    rules = [
        # fires: both conditions pass (single-rule AND pass)
        rule("rule-B", "B00.0", [cond("sym-001", 2), cond("sym-002", 3)]),
        # does NOT fire: sym-003 sev 1 < 2 (multi-condition AND, one fails)
        rule("rule-A", "A00.0", [cond("sym-001", 1), cond("sym-003", 2)]),
        # fires: single condition at boundary
        rule("rule-C", "C00.0", [cond("sym-002", 4)]),
        # does NOT fire: absent symptom
        rule("rule-D", "D00.0", [cond("sym-missing", 1)]),
    ]
    core_out = core_codes(symptoms, rules)
    prod_out = [c["icd10_code"] for c in prod_derive(symptoms, rules)]
    assert core_out == prod_out, (core_out, prod_out)
    # Confirm the shape is exercised: sorted rule_id order, only firing rules,
    # collected (rule-A and rule-D drop; rule-B and rule-C fire).
    assert core_out == ["B00.0", "C00.0"], core_out

    # --- ORDER DISCRIMINATION: rule_id order != icd10_code order. ---
    # The fixtures above all have rule_id sort order == code sort order, so they do
    # NOT discriminate the sort KEY. Here the firing rules sort by rule_id as
    # rule-1 < rule-2, but their codes are Z99.9 then A00.0 — so a recompute that
    # (wrongly) sorted by icd10_code, or by file order, would yield a DIFFERENT list.
    # Both core and producer must agree on rule_id-ordered [Z99.9, A00.0], pinning the
    # sort key and proving the `exact` element-wise comparator is order-load-bearing.
    order_symptoms = [{"symptom_id": "s", "name": "s", "severity": 5}]
    order_rules = [
        rule(
            "rule-2", "A00.0", [cond("s", 1)]
        ),  # later rule_id, alphabetically-first code
        rule(
            "rule-1", "Z99.9", [cond("s", 1)]
        ),  # earlier rule_id, alphabetically-last code
    ]
    order_core = core_codes(order_symptoms, order_rules)
    order_prod = [c["icd10_code"] for c in prod_derive(order_symptoms, order_rules)]
    assert order_core == order_prod == ["Z99.9", "A00.0"], (order_core, order_prod)
    # Guard against a silent switch to code-order or file-order (both would differ).
    assert order_core != sorted(order_core), "must NOT be icd10_code-sorted"
    assert order_core != ["A00.0", "Z99.9"], "must NOT be file/code order"

    # --- no-fire: empty collection on both. ---
    none_fire = [rule("rule-Z", "Z00.0", [cond("sym-missing", 1)])]
    assert (
        core_codes(symptoms, none_fire)
        == [c["icd10_code"] for c in prod_derive(symptoms, none_fire)]
        == []
    )

    # --- fail-closed parity: malformed input raises on BOTH copies. ---
    import pytest

    # Missing "conditions" key -> KeyError on both (core in compute, producer in
    # _eval_rule via _derive_candidates).
    bad_rule = [{"rule_id": "rule-X", "icd10_code": "X00.0"}]
    with pytest.raises(KeyError):
        core_codes(symptoms, bad_rule)
    with pytest.raises(KeyError):
        prod_derive(symptoms, bad_rule)

    # Non-list symptoms -> TypeError on both (core's isinstance guard; producer's
    # `for s in <int>` is not iterable).
    with pytest.raises(TypeError):
        core_codes(5, rules)
    with pytest.raises(TypeError):
        prod_derive(5, rules)
