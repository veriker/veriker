"""fintech_audit_recompute — verifier-side all-pairs policy-verdict re-derivation.

Axis-2 value-return form, PROMOTED into the shippable core registry (RECIPE_BOOK.md,
shape `deterministic rule/predicate evaluation → ordered categorical decision list`,
control-structure sub-family **all-pairs predicate → verdict-or-NOT_APPLICABLE**).
The generic verifier recomputes the representative output on the SAFE spec-pinned
path: no subprocess, no bundle-supplied code — the predicate-evaluation rule lives
HERE in verifier-distribution code and the comparator comes from the auditor-
anchored spec.

Re-derivation primitive (one sentence):
    policy_verdicts = [ {txn_id, rule_id, matched_conditions, verdict} for each
        (transaction, policy-rule) pair, in transactions-then-policies file-sorted
        order, where each rule's conditions are AND-ed over the transaction
        (gt/lt/eq/ne/in/not_in), matched_conditions is the list of condition
        fields that held, and verdict is the rule's verdict_if_match when ALL
        conditions hold else "NOT_APPLICABLE" ].

This is the ALL-PAIRS control structure: ONE record is emitted for every
(transaction × policy) pair. The recorded 1-vs-N decision (RECIPE_BOOK Tier-3,
this promotion's window) is that the ~16-pilot decision-list cluster does NOT
collapse onto a single config-driven DSL primitive but splits by CONTROL STRUCTURE.
The other control structures — first-match-with-default (prior_auth / anticheat /
ibm_jurisdictional_routing) and fire-and-collect (healthcare_diagnosis) — are the
RECORDED PLAN for separate shape primitives, NOT yet built. This module promotes
exactly the all-pairs sub-family, whose sole current member is fintech_audit;
generalization is deferred until a second member of each family appears (the
"don't lift at N=1" discipline).

The op semantics, AND-accumulation, the NOT_APPLICABLE mapping, and the per-record
shape are FIXED here — the primitive_id ("fintech_audit_recompute") IS the rule. The
auditor's SHA-pinned spec binds the output type "fintech_audit_policy_verdicts" to
this primitive_id and to an `exact` comparator (ordered list of primitive records
compared element-wise); a producer cannot weaken the predicate logic without
changing the primitive_id, which the anchor rejects.

Record ORDERING (a faithfulness scope limit, fail-closed). The verifier cannot
witness the producer's build iteration order; it reconstructs order as
sorted-filename order over transactions/*.json then policies/*.json (_load_ordered).
For bundles whose filenames encode the canonical id order — as the shipped fixture's
do (transactions/<txn_id>.json, policies/<rule_id>.json) — this equals the producer's
id-sorted iteration order. The comparator is `exact` over the ordered list, so a
producer whose authoring order diverged from filename-sort would be REJECTED
(fail-closed REDERIVATION_MISMATCH, never a false bless). This binding therefore
assumes id-named, id-sortable record/rule files; that assumption is the price of
reconstructing order from the bundle alone.

Faithfulness (Gate B). The promoted test derives the honest claim from the pilot's
OWN producer (examples/fintech_audit_minimal/_build_bundle.py emits
payload/policy_verdicts.json from an independent inline copy of this evaluation
rule — enforced disjoint by tests/test_recipe_producer_verifier_disjoint.py), never
from this module. This recompute MIRRORS the producer's _eval_condition / _eval_policy
EXACTLY across all supported ops {gt,lt,eq,ne,in,not_in} (asserted directly by the
op-agreement test, not just the {gt,in} fixture), and is equally fail-closed: an
unknown op or malformed rule/condition RAISES (→ RECOMPUTE_ERROR) here exactly as it
raises at build time in the producer, so there is no off-distribution bundle the
producer cannot emit that this verifier would nonetheless bless. (NOTE: the pilot's
own examples/fintech_audit_minimal/spec_pinned_check.py is a build→verify roundtrip
demo that computes its claim via this shared rule — it is NOT a producer-disjoint
Gate-B proof; the promoted test is.)

Stdlib-only (§C5 core verify() path): json is stdlib.
"""

from __future__ import annotations

from pathlib import Path

from ...admission import admit_json_file
from ...plugin import ParsedInputs, RecomputedValue
from ..registry import register_primitive

# The verdict assigned to a (txn, rule) pair when the rule's conditions do not all
# hold — MUST match the producer (_build_bundle.py) exactly.
_NOT_APPLICABLE = "NOT_APPLICABLE"


# ---------------------------------------------------------------------------
# Condition / policy evaluation — MIRRORS _build_bundle.py (the producer "tool")
# byte-for-byte in semantics, so the recompute is faithful and fail-closed.
# ---------------------------------------------------------------------------


def _eval_condition(txn: dict, cond: dict) -> bool:
    """Evaluate a single condition against a transaction record.

    Supported ops: gt, lt, eq, ne, in, not_in. A condition over a field ABSENT
    from the transaction yields False (matches the producer: txn.get(field) is
    None → False). Mirrors the producer's _eval_condition EXACTLY, including its
    fail-closed behaviour: a malformed condition (missing field/op/value key)
    raises KeyError and an UNKNOWN op raises ValueError — exactly as the producer
    raises at build time, so a bundle the producer could never honestly emit
    becomes a fail-closed RECOMPUTE_ERROR here rather than a silently-blessed
    NOT_APPLICABLE (threat model: let recompute raise on malformed input).
    """
    field = cond["field"]
    op = cond["op"]
    threshold = cond["value"]
    actual = txn.get(field)
    if actual is None:
        return False
    if op == "gt":
        return float(actual) > float(threshold)
    if op == "lt":
        return float(actual) < float(threshold)
    if op == "eq":
        return actual == threshold
    if op == "ne":
        return actual != threshold
    if op == "in":
        return actual in threshold
    if op == "not_in":
        return actual not in threshold
    raise ValueError(f"Unknown op: {op!r}")


def _eval_policy(txn: dict, policy: dict) -> tuple[bool, list[str]]:
    """Return (all_matched, matched_fields). Conditions are AND-ed: the first
    failing condition short-circuits to (False, []). On full match, returns the
    matched condition field names in condition order. Mirrors the producer: a
    rule missing its "conditions" key raises KeyError (fail-closed)."""
    matched_fields: list[str] = []
    for cond in policy["conditions"]:
        if _eval_condition(txn, cond):
            matched_fields.append(cond["field"])
        else:
            return False, []
    return True, matched_fields


# ---------------------------------------------------------------------------
# Canonical computation (the verifier's authoritative re-derivation rule)
# ---------------------------------------------------------------------------


def compute_policy_verdicts(transactions: list, policies: list) -> list:
    """Canonical re-derivation of the per-(transaction, policy) verdict list.

    For each transaction (outer loop) and each policy (inner loop), in the given
    list order, re-run the policy's conditions over the transaction and emit one
    record {txn_id, rule_id, matched_conditions, verdict}. verdict is the rule's
    verdict_if_match when all conditions hold, else "NOT_APPLICABLE". One record is
    emitted per pair (the all-pairs control structure).

    Fail-closed: raises KeyError if a transaction or policy record is missing its
    id (the verifier must not invent a verdict list from malformed input).
    """
    if not isinstance(transactions, list):
        raise TypeError("transactions must be a JSON array")
    if not isinstance(policies, list):
        raise TypeError("policies must be a JSON array")

    verdicts: list[dict] = []
    for txn in transactions:
        txn_id = txn["txn_id"]
        for policy in policies:
            rule_id = policy["rule_id"]
            matched, matched_fields = _eval_policy(txn, policy)
            verdict_value = policy["verdict_if_match"] if matched else _NOT_APPLICABLE
            verdicts.append(
                {
                    "txn_id": txn_id,
                    "rule_id": rule_id,
                    "matched_conditions": matched_fields,
                    "verdict": verdict_value,
                }
            )
    return verdicts


def _load_ordered(dir_path: Path) -> list:
    """Load every *.json under dir_path in sorted-filename order.

    The producer writes transactions/policies in fixture order, which for the
    shipped fixtures equals sorted id order (txn-001<002<003; rule-large-tx <
    rule-restricted-jurisdiction). Sorting the on-disk files reproduces that
    iteration order deterministically from the bundle alone.
    """
    out: list = []
    for p in sorted(dir_path.glob("*.json")):
        # Admission-bounded load (size/depth/cardinality) per record file — same
        # discipline as manifest.json; InputInadmissible propagates → dispatch
        # records RECOMPUTE_ERROR.
        out.append(admit_json_file(p))
    return out


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered at import for the core registry)
# ---------------------------------------------------------------------------


class FintechAuditRecompute:
    """Verifier-side primitive: re-derive the per-(transaction, policy) verdict
    list by re-running each policy's AND-ed conditions over each transaction."""

    primitive_id: str = "fintech_audit_recompute"

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        """Recompute the policy-verdict list from transactions/*.json and
        policies/*.json. Returns the recomputed VALUE only; the auditor-anchored
        `exact` comparator decides agreement against the producer's claimed list.
        """
        bundle_dir: Path = inputs.bundle_dir
        txn_dir = bundle_dir / "transactions"
        policy_dir = bundle_dir / "policies"
        if not txn_dir.is_dir():
            raise FileNotFoundError(
                f"transactions/ not found in bundle at {bundle_dir}"
            )
        if not policy_dir.is_dir():
            raise FileNotFoundError(f"policies/ not found in bundle at {bundle_dir}")

        transactions = _load_ordered(txn_dir)
        policies = _load_ordered(policy_dir)
        if not transactions:
            raise ValueError("no transactions/*.json found — cannot re-derive verdicts")
        if not policies:
            raise ValueError("no policies/*.json found — cannot re-derive verdicts")

        value = compute_policy_verdicts(transactions, policies)
        return RecomputedValue(
            value=value,
            detail=(
                f"re-derived {len(value)} verdict(s) over "
                f"{len(transactions)} txn(s) x {len(policies)} polic(ies)"
            ),
        )


register_primitive(FintechAuditRecompute())
