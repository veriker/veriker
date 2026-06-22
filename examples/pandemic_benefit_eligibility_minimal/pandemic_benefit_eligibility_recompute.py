"""pandemic_benefit_eligibility_recompute.py — verifier-side eligibility re-derivation primitive.

Axis-2 value-return form (SPEC_PINNED_DISPATCH_ARCHITECTURE §3.3). Self-contained
per-dir migration of the pandemic_benefit_eligibility_minimal pilot onto spec-pinned
dispatch: the recompute primitive lives HERE (verifier-distribution code, registered by
the spec-pinned builder / verify path), NOT in audit_bundle/rederivation/primitives/.

Re-derivation primitive (one sentence):
    decision_list = ordered list, in data/applicants.json array order, of
        [claimant_id, verdict, benefit_amount_cents] where (verdict, benefit) is the
        deterministic evaluation of the published rule set (spec/eligibility_rules.json)
        against the applicant's attested attributes — employment-status admission,
        min-prior-income floor, income-drop threshold, eligibility-period window — and
        the APPROVED weekly benefit is min(max_weekly, round-half-up(prior_weekly *
        replacement_rate_bps / 10000)).

The representative output keeps the benefit amount because it is a DETERMINISTIC INTEGER:
the legacy pack computes weekly_benefit_cents via round-half-up integer division (_rhu),
never a float, so the `exact` comparator is FP-drift-safe. The amount is carried as
integer CENTS (the native, exact unit); the task's "benefit_amount_cad" semantic maps to
this integer-cents value rather than a non-deterministic dollars float.

The replay rule (rule-set order: status -> prior-income floor -> income-drop threshold ->
period window, round-half-up benefit formula, applicants array order) is FIXED in this
primitive — the primitive_id ("pandemic_benefit_eligibility_recompute") IS the rule. The
auditor's SHA-pinned spec binds the output type "pandemic_benefit_eligibility" to this
primitive_id and to an `exact` comparator; a producer cannot weaken the rule set without
changing the primitive_id, which the anchor rejects.

Stdlib-only (§C5 contract). This module is importable WITHOUT audit_bundle on sys.path
(the RecomputedValue import is deferred into recompute()), so the spec-pinned builder can
import compute_decision_list() standalone.
"""

from __future__ import annotations

import json
from pathlib import Path

APPROVED = "APPROVED"
DENIED = "DENIED"

# Employment statuses recognised by the rule set (mirrors the legacy pack EXACTLY).
_VALID_EMPLOYMENT_STATUSES = frozenset({
    "employed",
    "self_employed",
    "gig_worker",
    "unemployed",
})


# ---------------------------------------------------------------------------
# Canonical computation (shared by the builder and the verifier — ONE source)
# Mirrors the legacy pack (_build_bundle.py / pandemic_eligibility_rederivation.py)
# EXACTLY (contract C5): rule order + round-half-up integer benefit formula.
# ---------------------------------------------------------------------------


def _rhu(num: int, den: int) -> int:
    """Round-half-up integer division (mirrors the legacy pack exactly)."""
    if den == 0:
        raise ValueError("division by zero in _rhu")
    return (num + den // 2) // den


def evaluate_eligibility(rules: dict, applicant: dict) -> tuple[str, int]:
    """Deterministically evaluate eligibility under the published rule set.

    Returns (verdict, weekly_benefit_cents); weekly_benefit_cents is 0 when DENIED.
    Rules evaluated in order (all must pass for APPROVED):
      1. employment_status in admitted set
      2. prior_income (annual cents) >= min_prior_income_cents
      3. period_income (weekly cents) <= prior_weekly * income_drop_threshold_bps / 10000
      4. eligibility_period within [period_start_week, period_end_week]
    On APPROVED: weekly_benefit = min(max_weekly,
                                      round-half-up(prior_weekly * replacement_rate_bps / 10000)).
    Mirrors the legacy pack evaluate_eligibility() EXACTLY.
    """
    criteria = rules.get("eligibility_criteria", {})
    min_prior = int(criteria.get("min_prior_income_cents", 0))
    drop_threshold_bps = int(criteria.get("income_drop_threshold_bps", 0))
    replacement_rate_bps = int(criteria.get("replacement_rate_bps", 0))
    max_weekly = int(criteria.get("max_weekly_benefit_cents", 0))
    period_start = int(criteria.get("period_start_week", 0))
    period_end = int(criteria.get("period_end_week", 0))

    prior_income = int(applicant.get("prior_income_cents", 0))
    period_income = int(applicant.get("period_income_cents", 0))
    employment_status = str(applicant.get("employment_status", "")).strip()
    eligibility_period = int(applicant.get("eligibility_period_week", 0))

    if employment_status not in _VALID_EMPLOYMENT_STATUSES:
        return (DENIED, 0)
    if prior_income < min_prior:
        return (DENIED, 0)

    weeks_per_year = int(rules.get("weeks_per_year", 52))
    prior_weekly_cents = _rhu(prior_income, weeks_per_year)
    income_threshold_cents = _rhu(prior_weekly_cents * drop_threshold_bps, 10000)
    if period_income > income_threshold_cents:
        return (DENIED, 0)

    if eligibility_period < period_start or eligibility_period > period_end:
        return (DENIED, 0)

    computed_benefit = _rhu(prior_weekly_cents * replacement_rate_bps, 10000)
    weekly_benefit = min(computed_benefit, max_weekly)
    return (APPROVED, weekly_benefit)


def compute_decision_list(applicants: list[dict], rules: dict) -> list[list]:
    """Canonical re-derivation of the ordered per-claimant decision list.

    `applicants` MUST be in data/applicants.json array order (the builder and the
    verifier both iterate the array as stored). For each: evaluate eligibility, emit
    [claimant_id, verdict, benefit_amount_cents]. The benefit amount is a deterministic
    integer (round-half-up cents) so the list is exact-safe. Builder and verifier share
    this ONE definition so the honest claimed list and the re-derivation cannot drift.
    """
    decisions: list[list] = []
    for app in applicants:
        verdict, weekly_benefit = evaluate_eligibility(rules, app)
        decisions.append([str(app["applicant_id"]), str(verdict), int(weekly_benefit)])
    return decisions


def _load_applicants(applicants_path: Path) -> list[dict]:
    """Load data/applicants.json (a JSON array) in its stored order — the canonical
    claimant order shared by builder and verifier."""
    raw = json.loads(applicants_path.read_bytes())
    if not isinstance(raw, list):
        raise ValueError("data/applicants.json must be a JSON array")
    return raw


def _load_rules(rules_path: Path) -> dict:
    """Load spec/eligibility_rules.json (the published deterministic rule set)."""
    return json.loads(rules_path.read_bytes())


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered before BundleVerifier)
# ---------------------------------------------------------------------------


class PandemicBenefitEligibilityRecompute:
    """Verifier-side primitive for re-deriving the per-claimant decision list."""

    primitive_id: str = "pandemic_benefit_eligibility_recompute"

    def recompute(self, inputs, pack_section: dict):
        """Recompute the decision list from spec/eligibility_rules.json and
        data/applicants.json.

        inputs.bundle_dir is a read-only Path. pack_section carries
        {output_id, type, params} from the auditor's spec binding. Returns a
        RecomputedValue carrying the [claimant_id, verdict, benefit_amount_cents]
        list; the verifier's `exact` comparator compares.
        """
        # Deferred import keeps this module importable standalone (builder use).
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        bundle_dir: Path = inputs.bundle_dir
        rules_path = bundle_dir / "spec" / "eligibility_rules.json"
        applicants_path = bundle_dir / "data" / "applicants.json"
        if not rules_path.is_file():
            raise FileNotFoundError(
                f"spec/eligibility_rules.json not found in bundle at {bundle_dir}"
            )
        if not applicants_path.is_file():
            raise FileNotFoundError(
                f"data/applicants.json not found in bundle at {bundle_dir}"
            )
        rules = _load_rules(rules_path)
        applicants = _load_applicants(applicants_path)
        if not applicants:
            raise ValueError("data/applicants.json is empty — cannot re-derive")
        value = compute_decision_list(applicants, rules)
        return RecomputedValue(
            value=value,
            detail=f"re-derived decision list over {len(applicants)} claimant(s)",
        )
