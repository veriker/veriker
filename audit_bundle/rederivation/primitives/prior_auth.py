"""prior_auth_recompute — verifier-side first-match prior-auth re-derivation.

Axis-2 value-return form, PROMOTED into the shippable core registry (RECIPE_BOOK.md,
shape `deterministic rule/predicate evaluation → ordered categorical decision list`,
control-structure sub-family **first-match rule → verdict + default**). The generic
verifier recomputes the representative output on the SAFE spec-pinned path: no
subprocess, no bundle-supplied code — the rule-traversal lives HERE in verifier-
distribution code and the comparator comes from the auditor-anchored spec.

Re-derivation primitive (one sentence):
    decisions = for each prior-auth request in clinical/findings.jsonl (file order),
        the FIRST plan rule (clinical/plan_rules.json, sorted by rule_id) whose
        procedure_category matches AND every required diagnosis is present AND every
        required prior_treatment is present AND the optional max_lab_value (>= / <=)
        check passes — emitting {request_id, model_recommendation: rule.verdict,
        matched_rule_id: rule.rule_id}; with a default {model_recommendation:
        "deny", matched_rule_id: null} when NO rule matches.

This is the FIRST-MATCH-with-DEFAULT control structure: exactly one decision per
request (the first rule that fires, or the deny default), distinct from the
all-pairs shape (fintech_audit — one record per record×rule pair) and fire-and-
collect (healthcare_diagnosis). Per the recorded 1-vs-N decision (RECIPE_BOOK
Tier-3 #2), the decision-list cluster splits by control structure; this module is
family B's prototype, with exactly ONE member built so far: prior_auth.
anticheat_adjudication is a CANDIDATE second first-match member and
ibm_jurisdictional_routing a candidate first-match SUB-VARIANT (policy-map +
ordered-candidate) — both NOT yet built. Whether ONE first-match primitive serves
all three (records+rules read from committed paths, condition vocabulary from a
committed config) or ibm forces a split is deferred to when those candidates are
built — NOT pre-judged here (don't generalize at N=1).

Scope of this binding. The representative output is the MEDICAL-NECESSITY rule-tree
verdict only; the HMAC provider-attestation half of the legacy pack
(payload/decision_provenance.jsonl / attestation_key.hex) is deliberately OUT OF
SCOPE — that is a trust-mechanics surface, not a re-derived value. The producer's
emitted payload/prior_auth_decisions.json additionally carries a `final_verdict`
field (the provider's adopted verdict); it is NOT part of this re-derivation, and a
claim bound to this primitive is the 3-field {request_id, model_recommendation,
matched_rule_id} projection.

The rule-traversal (rule_id-sorted first-match, condition semantics, deny default)
is FIXED here — the primitive_id ("prior_auth_recompute") IS the rule. The auditor's
SHA-pinned spec binds the output type "prior_auth_decisions" to this primitive_id
and to an `exact` comparator (ordered list of records compared element-wise); a
producer cannot weaken the rule tree without changing the primitive_id, which the
anchor rejects.

Faithfulness (Gate B). The promoted test derives the honest claim from the pilot's
OWN producer (examples/prior_auth_minimal/_build_bundle.py emits
payload/prior_auth_decisions.json from an independent inline copy of _evaluate_rule
/ _derive_decision — enforced disjoint by tests/test_recipe_producer_verifier_
disjoint.py), never from this module. This recompute MIRRORS that producer EXACTLY
across every rule-condition branch — asserted directly by an op/condition-agreement
test (test_recipe_prior_auth_promoted.py) that compares this primitive's
_evaluate_rule / _derive_decision against the producer's inline copies over the full
branch matrix, not just the 5-request fixture. A malformed request/rule (missing
required key) raises KeyError → fail-closed RECOMPUTE_ERROR, exactly as the producer
raises at build time.

Unknown-comparator handling (fail-closed, hardened 2026-06-12 — redteam BLOCK-01).
The supported lab comparators are >= and <=; a missing lab value fails the gate. A
comparator OTHER than >=/<= raises ValueError → fail-closed RECOMPUTE_ERROR: an
unevaluable policy condition must never be treated as satisfied (a typo'd ">" /
"=>" on a medical-necessity threshold would otherwise ride a GREEN verdict with
the condition silently un-asserted). The producer's inline copy raises identically
at build time, preserving Gate-B mirror-the-producer parity — BOTH sides were
tightened together (the promotion-era version no-opped on both sides, disclosed in
prose only; the deferral had no forcing function and an external redteam re-found
it). This now matches fintech_audit_recompute's resolution (raise on unknown op),
and the dispatch-exhaustiveness ratchet (tests/test_dispatch_exhaustiveness_
ratchet.py) holds the whole package to it.

NOTE: the pilot's own examples/prior_auth_minimal/spec_pinned_check.py is a
build→verify roundtrip demo that computes its claim via this shared rule — it is NOT
a producer-disjoint Gate-B proof; the promoted test is.

Stdlib-only (§C5 core verify() path): json is stdlib.
"""

from __future__ import annotations

from pathlib import Path

from ...admission import admit_json_file, admit_jsonl_file
from ...plugin import ParsedInputs, RecomputedValue
from ..registry import register_primitive


# ---------------------------------------------------------------------------
# Rule traversal — MIRRORS _build_bundle.py (the producer "tool") EXACTLY.
# ---------------------------------------------------------------------------


def _evaluate_rule(request: dict, rule: dict) -> bool:
    """Return True if the request satisfies all conditions in the rule.

    Mirrors the producer's _evaluate_rule EXACTLY: procedure_category equality,
    every required diagnosis present, every required prior_treatment present, and
    the optional max_lab_value comparator (>= / <=) gate (a missing lab fails; a
    comparator other than >=/<= raises ValueError — fail-closed, matching the
    producer, which refuses to build a bundle from such a policy).
    """
    if request["procedure_category"] != rule["procedure_category"]:
        return False
    for diag in rule["required_diagnoses"]:
        if diag not in request["diagnoses"]:
            return False
    for tx in rule["required_prior_treatments"]:
        if tx not in request["prior_treatments"]:
            return False
    if rule["max_lab_value"] is not None:
        lab = rule["max_lab_value"]["lab"]
        threshold = rule["max_lab_value"]["threshold"]
        comparator = rule["max_lab_value"]["comparator"]
        value = request["lab_values"].get(lab)
        if value is None:
            return False
        if comparator == ">=":
            if not (value >= threshold):
                return False
        elif comparator == "<=":
            if not (value <= threshold):
                return False
        else:
            raise ValueError(
                f"unknown max_lab_value comparator {comparator!r} "
                "(supported: '>=', '<=') — refusing to treat an unevaluable "
                "policy condition as satisfied"
            )
    return True


def _derive_decision(request: dict, rules: list) -> dict:
    """Walk the rule set (sorted by rule_id) and return the first matching verdict.

    Mirrors the producer's _derive_decision EXACTLY: first rule (rule_id-sorted)
    whose conditions all pass yields {request_id, model_recommendation,
    matched_rule_id}; otherwise the deny / null default.
    """
    for rule in sorted(rules, key=lambda r: r["rule_id"]):
        if _evaluate_rule(request, rule):
            return {
                "request_id": request["request_id"],
                "model_recommendation": rule["verdict"],
                "matched_rule_id": rule["rule_id"],
            }
    return {
        "request_id": request["request_id"],
        "model_recommendation": "deny",
        "matched_rule_id": None,
    }


# ---------------------------------------------------------------------------
# Canonical computation (the verifier's authoritative re-derivation rule)
# ---------------------------------------------------------------------------


def compute_decisions(requests: list, rules: list) -> list:
    """Canonical re-derivation of the ordered per-request verdict list.

    Returns, in clinical/findings.jsonl file order, one {request_id,
    model_recommendation, matched_rule_id} dict per request — the representative
    output. Fail-closed: raises KeyError/TypeError if a request or rule record is
    malformed (the verifier must not invent a decision list).
    """
    if not isinstance(requests, list):
        raise TypeError("requests must be a JSON array")
    if not isinstance(rules, list):
        raise TypeError("rules must be a JSON array")
    return [_derive_decision(request, rules) for request in requests]


def _load_requests(bundle_dir: Path) -> list:
    """Load clinical/findings.jsonl as an ordered list of request dicts (file
    order, skipping blank lines)."""
    p = bundle_dir / "clinical" / "findings.jsonl"
    if not p.is_file():
        raise FileNotFoundError(
            f"clinical/findings.jsonl not found in bundle at {bundle_dir}"
        )
    requests = admit_jsonl_file(p)
    return requests


def _load_rules(bundle_dir: Path) -> list:
    """Load clinical/plan_rules.json as the committed rule set."""
    p = bundle_dir / "clinical" / "plan_rules.json"
    if not p.is_file():
        raise FileNotFoundError(
            f"clinical/plan_rules.json not found in bundle at {bundle_dir}"
        )
    rules = admit_json_file(p)
    if not isinstance(rules, list):
        raise ValueError("clinical/plan_rules.json must be a JSON array")
    return rules


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered at import for the core registry)
# ---------------------------------------------------------------------------


class PriorAuthRecompute:
    """Verifier-side primitive: re-derive the ordered first-match prior-auth
    verdict list from the committed requests + plan rules."""

    primitive_id: str = "prior_auth_recompute"

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        """Recompute the per-request verdict list from clinical/findings.jsonl
        (file order) and clinical/plan_rules.json. Returns the recomputed VALUE
        only; the auditor-anchored `exact` comparator decides agreement against the
        producer's claimed list.
        """
        bundle_dir: Path = inputs.bundle_dir
        requests = _load_requests(bundle_dir)
        rules = _load_rules(bundle_dir)
        value = compute_decisions(requests, rules)
        return RecomputedValue(
            value=value,
            detail=(
                f"re-derived {len(value)} prior-auth verdict(s) "
                f"over {len(rules)} plan rule(s)"
            ),
        )


register_primitive(PriorAuthRecompute())
