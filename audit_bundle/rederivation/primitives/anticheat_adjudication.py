"""anticheat_adjudication_recompute — verifier-side first-match ban-adjudication re-derivation.

Axis-2 value-return form, PROMOTED into the shippable core registry (RECIPE_BOOK.md,
shape `deterministic rule/predicate evaluation → ordered categorical decision list`,
control-structure sub-family **first-match rule → verdict + default**). The generic
verifier recomputes the representative output on the SAFE spec-pinned path: no
subprocess, no bundle-supplied code — the threshold-rule traversal lives HERE in
verifier-distribution code and the comparator comes from the auditor-anchored spec.

Re-derivation primitive (one sentence):
    verdict_list = for each case in evidence/detection_signals.jsonl (file order),
        the FIRST rule (evidence/detection_policy.json, sorted by rule_id) ALL of
        whose AND-conditions (signal {>=,<=} threshold over the case's signals)
        hold — emitting {model_recommendation: rule.verdict, matched_rule_id:
        rule.rule_id}; with a default {model_recommendation: "clear",
        matched_rule_id: null} when NO rule fires.

This is the FIRST-MATCH-with-DEFAULT control structure (the SECOND member of that
family promoted, after prior_auth). The representative output is POSITIONAL — one
2-field {model_recommendation, matched_rule_id} record per case in file order, with
NO case_id (the list position is the case binding; the producer's case_id and the
HMAC adjudicator-attestation half of payload/ban_decisions.json are OUT OF SCOPE —
trust mechanics, not a re-derived value). POSITIONAL-BINDING ASYMMETRY (disclosed):
because case_id is dropped, this binding is weaker on reorder-detection than the
legacy case_id-keyed check — its correctness rests on the producer emitting its
verdict list in the SAME order as evidence/detection_signals.jsonl. The `exact`
comparator still catches any reorder BETWEEN the claim and the file (both are
file-order here); what it cannot catch is a producer that consistently reorders
both. For the committed fixture the producer writes both from the same case list,
so the order is sound.

1-vs-N — the boundary revealed at N=2 (RECIPE_BOOK Tier-3 #2). prior_auth and
anticheat share the first-match CONTROL STRUCTURE but do NOT collapse onto one
generic primitive: their CONDITION VOCABULARIES are different predicate logics
(prior_auth: procedure-category equality + required-list membership ×2 + optional
nested max_lab_value comparator; anticheat: a flat AND of {signal, comparator
(>=/<=), threshold} over a signals dict), their record layouts differ (flat request
vs nested case.signals), their output projections differ (3-field-with-request_id
vs 2-field positional), and their defaults differ (deny vs clear). The shared
first-match loop is the trivial part; the condition vocabulary IS the rule, and it
is domain-specific. Unifying would require a bundle-supplied rule-DSL config
encoding the operator vocabulary + rule-schema field-mappings — the exact construct
rejected at cluster level (it relocates the rule into bundle config, diluting
"primitive_id IS the rule"). So each first-match member is its own primitive; ibm_
jurisdictional_routing (policy-map + ordered-candidate) is further still.

The threshold-rule logic (rule_id sort, AND-of-conditions, first-match-wins, clear
fallback) is FIXED here — the primitive_id ("anticheat_adjudication_recompute") IS
the rule. The auditor's SHA-pinned spec binds the output type
"anticheat_adjudication_verdict_list" to this primitive_id and to an `exact`
comparator; a producer cannot weaken the adjudication logic without changing the
primitive_id, which the anchor rejects.

Faithfulness (Gate B). The promoted test derives the honest claim from the pilot's
OWN producer (examples/anticheat_adjudication_minimal/_build_bundle.py emits
payload/ban_decisions.json from an independent inline copy of _evaluate_rule /
_derive_decision — enforced disjoint by tests/test_recipe_producer_verifier_
disjoint.py), projected to the 2 re-derived fields, never from this module. This
recompute MIRRORS that producer's _evaluate_rule / _derive_decision (modulo the
dropped case_id projection) — asserted directly by a condition-agreement test over
the supported branches: >= and <= true/false AND at the boundary (value==threshold),
single- and multi-condition AND (pass and fail), missing signal, the unknown-
comparator raise, and the no-match default. As with prior_auth (hardened
2026-06-12, redteam BLOCK-01), a missing signal fails its condition and a
comparator OTHER than >=/<= raises ValueError → fail-closed RECOMPUTE_ERROR —
identical on BOTH the producer (refuses to build) and here: an unevaluable
policy condition must never be treated as satisfied. Fail-closed parity on malformed input: a missing
required key raises KeyError and a non-numeric signal vs numeric threshold raises
TypeError — both reach a fail-closed RECOMPUTE_ERROR here exactly as they raise at
the producer's build time (the agreement test asserts the TypeError parity
directly). NOTE: the pilot's own spec_pinned_check.py is a build→verify roundtrip
demo computing its claim via this shared rule — NOT a producer-disjoint Gate-B
proof; the promoted test is.

Stdlib-only (§C5 core verify() path): json is stdlib.
"""

from __future__ import annotations

from pathlib import Path

from ...admission import admit_json_file, admit_jsonl_file
from ...plugin import ParsedInputs, RecomputedValue
from ..registry import register_primitive


# ---------------------------------------------------------------------------
# Threshold-rule traversal — MIRRORS _build_bundle.py (the producer "tool") EXACTLY.
# ---------------------------------------------------------------------------


def _evaluate_rule(signals: dict, rule: dict) -> bool:
    """Return True iff the case signals satisfy every condition in the rule (AND).

    Mirrors the producer's _evaluate_rule EXACTLY: each condition is
    (signal, comparator, threshold); a missing signal value fails the rule; only
    ">=" and "<=" comparators are honoured (any other comparator raises
    ValueError — fail-closed, matching the producer, which refuses to build a
    bundle from such a policy).
    """
    for cond in rule["conditions"]:
        sig = cond["signal"]
        comparator = cond["comparator"]
        threshold = cond["threshold"]
        value = signals.get(sig)
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
                f"unknown condition comparator {comparator!r} "
                "(supported: '>=', '<=') — refusing to treat an unevaluable "
                "policy condition as satisfied"
            )
    return True


def _derive_decision(case: dict, policy: list) -> dict:
    """Walk the rule set (sorted by rule_id) and return the first matching verdict.

    Returns {model_recommendation, matched_rule_id} (the case_id is intentionally
    dropped — the list is positional, matching the producer's decisions order).
    Clear fallback when no rule fires. Mirrors the producer's _derive_decision
    EXACTLY (modulo the dropped case_id projection).
    """
    for rule in sorted(policy, key=lambda r: r["rule_id"]):
        if _evaluate_rule(case["signals"], rule):
            return {
                "model_recommendation": rule["verdict"],
                "matched_rule_id": rule["rule_id"],
            }
    return {"model_recommendation": "clear", "matched_rule_id": None}


# ---------------------------------------------------------------------------
# Canonical computation (the verifier's authoritative re-derivation rule)
# ---------------------------------------------------------------------------


def compute_verdict_list(cases: list, policy: list) -> list:
    """Canonical re-derivation of the ordered per-case verdict list.

    For each case in `cases` (file order) derive {model_recommendation,
    matched_rule_id} against `policy`. Fail-closed: raises KeyError/TypeError if a
    case or rule record is malformed (the verifier must not invent a verdict list).
    """
    if not isinstance(cases, list):
        raise TypeError("cases must be a JSON array")
    if not isinstance(policy, list):
        raise TypeError("policy must be a JSON array")
    return [_derive_decision(case, policy) for case in cases]


def _load_cases(bundle_dir: Path) -> list:
    """Read evidence/detection_signals.jsonl in file order (skipping blank lines)."""
    p = bundle_dir / "evidence" / "detection_signals.jsonl"
    if not p.is_file():
        raise FileNotFoundError(
            f"evidence/detection_signals.jsonl not found in bundle at {bundle_dir}"
        )
    cases = admit_jsonl_file(p)
    return cases


def _load_policy(bundle_dir: Path) -> list:
    """Read evidence/detection_policy.json (the committed threshold rule set)."""
    p = bundle_dir / "evidence" / "detection_policy.json"
    if not p.is_file():
        raise FileNotFoundError(
            f"evidence/detection_policy.json not found in bundle at {bundle_dir}"
        )
    policy = admit_json_file(p)
    if not isinstance(policy, list):
        raise ValueError("evidence/detection_policy.json must be a JSON array")
    return policy


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered at import for the core registry)
# ---------------------------------------------------------------------------


class AnticheatAdjudicationRecompute:
    """Verifier-side primitive: re-derive the ordered first-match ban-adjudication
    verdict list from the committed detection signals + policy."""

    primitive_id: str = "anticheat_adjudication_recompute"

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        """Recompute the per-case verdict list from evidence/detection_signals.jsonl
        (file order) and evidence/detection_policy.json. Returns the recomputed
        VALUE only; the auditor-anchored `exact` comparator decides agreement
        against the producer's claimed list.
        """
        bundle_dir: Path = inputs.bundle_dir
        cases = _load_cases(bundle_dir)
        policy = _load_policy(bundle_dir)
        value = compute_verdict_list(cases, policy)
        return RecomputedValue(
            value=value,
            detail=(
                f"re-derived verdict list over {len(cases)} case(s) "
                f"/ {len(policy)} rule(s)"
            ),
        )


register_primitive(AnticheatAdjudicationRecompute())
