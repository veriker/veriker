#!/usr/bin/env python3
"""pandemic_eligibility_rederivation.py — stdlib re-derivation engine for pandemic benefit eligibility.

Models the Canadian pandemic-benefit overpayment failure ($4.6B paid to ineligible recipients,
per Auditor General). The narrow, honest claim — stated verbatim in README and in verify.py
PASS output — is:

  "A deterministic benefit-eligibility decision and benefit amount can be independently
  re-derived and signed from the applicant's attested attributes and the published rule set
  BEFORE disbursement — the exact pre-payment check that was skipped. Synthetic rules and
  records; no CRA/Service Canada integration; not a fraud detector."

Re-derivation primitive: re-derive each applicant's eligibility verdict and benefit amount by
evaluating the published deterministic rule set (e.g. minimum prior income $5,000,
income-drop threshold, eligibility period window) against the applicant's attested attributes,
and assert it equals the bundled disbursement decision.

Domain: pandemic-benefit disbursement decisions (approved/denied + amount) for a synthetic
applicant pool. The verifier re-derives the eligibility verdict and weekly amount from the
pinned rule set and the applicant's attested attributes (prior_income, period_income,
employment_status, eligibility_period), then checks it matches the bundled decision.

Fail-closed: a decision is PANDEMIC_ELIGIBILITY_REDERIVED only if (applicant known AND rule
set present AND re-derivation matches both verdict and amount AND signature valid). Any
mismatch => PANDEMIC_ELIGIBILITY_REDERIVATION_MISMATCH.

the audit-bundle contract §C6 (domain-agnostic re-derivation) + §C16 spirit (verifier decides,
never the disbursement system). AB4: stdlib only — argparse, hashlib, hmac, json, sys, pathlib.
No imports from audit_bundle.

Reads:
  spec/eligibility_rules.json          — published deterministic rule set
  spec/disbursement_hmac_key.hex       — bundled synthetic key (SHA-pinned via spec_files)
  data/applicants.json                 — attested applicant attributes
  payload/disbursement_decisions.json  — disbursement decisions being audited
  coverage/disbursement_period.json    — closed-world: n_issued (approved) + n_withheld (denied)

Exits 0 when every bundled decision matches the verifier's independent re-derivation;
1 with [PANDEMIC_ELIGIBILITY_FAIL] <reason>: <detail> on stderr on first violation.

Usage:
    python pandemic_eligibility_rederivation.py --bundle-dir /path/to/bundle [--emit-ledger]
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from pathlib import Path

APPROVED = "APPROVED"
DENIED = "DENIED"

_VALID_VERDICTS = frozenset({APPROVED, DENIED})

# Employment statuses recognised by the rule set.
_VALID_EMPLOYMENT_STATUSES = frozenset({
    "employed",
    "self_employed",
    "gig_worker",
    "unemployed",
})


# ---------------------------------------------------------------------------
# Rule-set evaluation (AB4: duplicated, never imported)
# ---------------------------------------------------------------------------


def _rhu(num: int, den: int) -> int:
    """Round-half-up integer division."""
    if den == 0:
        raise ValueError("division by zero in _rhu")
    return (num + den // 2) // den


def evaluate_eligibility(rules: dict, applicant: dict) -> tuple[str, int]:
    """Deterministically evaluate eligibility under the published rule set.

    Returns (verdict, weekly_benefit_cents) where:
      - verdict is APPROVED or DENIED
      - weekly_benefit_cents is 0 when DENIED

    Rules evaluated in order (all must pass for APPROVED):
      1. employment_status must be in the admitted set
      2. prior_income (annual, cents) >= min_prior_income_cents
      3. period_income (weekly during period, cents) <= prior_weekly_income * income_drop_threshold_bps / 10000
      4. eligibility_period must be within the published window [period_start_week, period_end_week]

    On APPROVED: weekly_benefit = min(max_weekly_benefit_cents,
                                      floor(prior_weekly_income * replacement_rate_bps / 10000))
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

    # 1. Employment status must be in the admitted set.
    if employment_status not in _VALID_EMPLOYMENT_STATUSES:
        return (DENIED, 0)

    # 2. Prior income floor ($5,000 per the Canadian CERB rule; pinned as cents).
    if prior_income < min_prior:
        return (DENIED, 0)

    # 3. Income drop: period income must have dropped below threshold of prior weekly.
    # prior_weekly_income is derived from annual / 52 (period weeks per year from rules).
    weeks_per_year = int(rules.get("weeks_per_year", 52))
    prior_weekly_cents = _rhu(prior_income, weeks_per_year)
    income_threshold_cents = _rhu(prior_weekly_cents * drop_threshold_bps, 10000)
    if period_income > income_threshold_cents:
        return (DENIED, 0)

    # 4. Eligibility period must fall within the published window.
    if eligibility_period < period_start or eligibility_period > period_end:
        return (DENIED, 0)

    # Re-derive weekly benefit.
    computed_benefit = _rhu(prior_weekly_cents * replacement_rate_bps, 10000)
    weekly_benefit = min(computed_benefit, max_weekly)
    return (APPROVED, weekly_benefit)


# ---------------------------------------------------------------------------
# Responsible-actor binding (disbursement system signature)
# ---------------------------------------------------------------------------


def _canonical_decision(record: dict) -> bytes:
    """Canonical bytes of a disbursement decision, excluding its own signature."""
    body = {k: v for k, v in record.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_decision(record: dict, key: bytes) -> str:
    return hmac.new(key, _canonical_decision(record), hashlib.sha256).hexdigest()


def _signature_ok(record: dict, key: bytes) -> bool:
    claimed = record.get("signature")
    if not isinstance(claimed, str):
        return False
    expected = sign_decision(record, key)
    return hmac.compare_digest(expected, claimed)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _verify(bundle_dir: Path) -> tuple[str | None, list[dict]]:
    """Return (error_or_None, ledger). ledger is the verifier's own per-applicant re-derivation."""
    rules_path = bundle_dir / "spec" / "eligibility_rules.json"
    key_path = bundle_dir / "spec" / "disbursement_hmac_key.hex"
    applicants_path = bundle_dir / "data" / "applicants.json"
    decisions_path = bundle_dir / "payload" / "disbursement_decisions.json"
    coverage_path = bundle_dir / "coverage" / "disbursement_period.json"

    for p in (rules_path, key_path, applicants_path, decisions_path, coverage_path):
        if not p.exists():
            return (f"MISSING_INPUT: {p.relative_to(bundle_dir)} absent from bundle", [])

    try:
        rules = json.loads(rules_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return (f"RULES_UNREADABLE: {exc}", [])
    if rules.get("schema") != "pandemic-benefit-rules-v1":
        return (f"RULES_SCHEMA: expected 'pandemic-benefit-rules-v1', got {rules.get('schema')!r}", [])

    try:
        key = bytes.fromhex(key_path.read_text(encoding="utf-8").strip())
    except (ValueError, OSError) as exc:
        return (f"KEY_UNREADABLE: {exc}", [])

    try:
        applicants_raw = json.loads(applicants_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return (f"APPLICANTS_UNREADABLE: {exc}", [])
    if not isinstance(applicants_raw, list):
        return ("APPLICANTS_SCHEMA: data/applicants.json must be a JSON array", [])
    applicants = {str(a["applicant_id"]): a for a in applicants_raw if "applicant_id" in a}

    try:
        decisions = json.loads(decisions_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return (f"DECISIONS_UNREADABLE: {exc}", [])
    if not isinstance(decisions, list):
        return ("DECISIONS_SCHEMA: payload/disbursement_decisions.json must be a JSON array", [])

    ledger: list[dict] = []
    n_approved = 0
    n_denied = 0

    for idx, dec in enumerate(decisions):
        try:
            applicant_id = str(dec["applicant_id"])
            claimed_verdict = dec["verdict"]
            claimed_amount = int(dec["weekly_benefit_cents"])
            disbursement_system_id = dec["disbursement_system_id"]
        except (KeyError, TypeError, ValueError) as exc:
            return (f"DECISION_MALFORMED: decision[{idx}] — {exc}", ledger)

        # 1. Responsible-actor binding — no silent post-hoc edit.
        if not _signature_ok(dec, key):
            return (
                f"SIGNATURE_INVALID: {applicant_id}: HMAC over disbursement decision does not verify "
                f"(system={disbursement_system_id!r})",
                ledger,
            )

        # 2. Applicant must exist in the attested data.
        applicant = applicants.get(applicant_id)
        if applicant is None:
            return (
                f"UNKNOWN_APPLICANT: {applicant_id}: no attested record in data/applicants.json",
                ledger,
            )

        # 3. Verdict must be recognised.
        if claimed_verdict not in _VALID_VERDICTS:
            return (
                f"VERDICT_SCHEMA: {applicant_id}: verdict {claimed_verdict!r} "
                f"not in {sorted(_VALID_VERDICTS)}",
                ledger,
            )

        # 4. Verifier independently re-derives verdict and amount from pinned rules + attested attributes.
        try:
            verifier_verdict, verifier_amount = evaluate_eligibility(rules, applicant)
        except (KeyError, ValueError, TypeError) as exc:
            return (f"REDERIVATION_ERROR: {applicant_id}: {exc} (fail-closed)", ledger)

        # 5. Claimed verdict MUST match verifier re-derivation.
        if claimed_verdict != verifier_verdict:
            return (
                f"PANDEMIC_ELIGIBILITY_REDERIVATION_MISMATCH: {applicant_id}: "
                f"disbursement system claims {claimed_verdict!r} but verifier re-derives "
                f"{verifier_verdict!r} from attested attributes and published rule set "
                f"(pre-payment check failed — this applicant is ineligible under the published rules)",
                ledger,
            )

        # 6. Claimed amount MUST match verifier re-derivation.
        if claimed_amount != verifier_amount:
            return (
                f"PANDEMIC_ELIGIBILITY_REDERIVATION_MISMATCH: {applicant_id}: "
                f"disbursement system claims weekly_benefit_cents={claimed_amount} but verifier "
                f"re-derives {verifier_amount} (amount does not match the published rule set)",
                ledger,
            )

        if verifier_verdict == APPROVED:
            n_approved += 1
        else:
            n_denied += 1

        ledger.append({
            "applicant_id": applicant_id,
            "verifier_verdict": verifier_verdict,
            "verifier_weekly_benefit_cents": verifier_amount,
            "claimed_verdict": claimed_verdict,
            "claimed_amount": claimed_amount,
            "disbursement_system_id": disbursement_system_id,
        })

    # 7. Every attested applicant must have exactly one decision (closed-world).
    decided = {str(d["applicant_id"]) for d in decisions}
    missing = sorted(set(applicants) - decided)
    if missing:
        return (
            f"APPLICANT_UNDECIDED: {len(missing)} attested applicant(s) have no disbursement "
            f"decision: {missing} (closed-world violation)",
            ledger,
        )

    # 8. Coverage cross-check: verifier's counts must match the disbursement period row.
    try:
        cov = json.loads(coverage_path.read_text(encoding="utf-8"))
        cov_approved = int(cov["n_issued"])
        cov_denied = int(cov["n_withheld"])
    except (json.JSONDecodeError, OSError, KeyError, TypeError, ValueError) as exc:
        return (f"COVERAGE_UNREADABLE: {exc}", ledger)
    if cov_approved != n_approved or cov_denied != n_denied:
        return (
            f"COVERAGE_COUNT_MISMATCH: coverage row claims approved={cov_approved}/denied={cov_denied} "
            f"but the verifier computes approved={n_approved}/denied={n_denied}",
            ledger,
        )

    return (None, ledger)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Pandemic benefit eligibility re-derivation verifier — verifier computes the verdict"
    )
    parser.add_argument("--bundle-dir", required=True, type=Path)
    parser.add_argument(
        "--emit-ledger",
        action="store_true",
        help="On success, print the verifier-computed per-applicant ledger to stdout",
    )
    args = parser.parse_args()

    error, ledger = _verify(args.bundle_dir.resolve())
    if error is not None:
        print(f"[PANDEMIC_ELIGIBILITY_FAIL] {error}", file=sys.stderr)
        return 1

    if args.emit_ledger:
        print("verifier-re-derived pandemic benefit eligibility decisions:")
        for row in ledger:
            amt = row["verifier_weekly_benefit_cents"]
            amt_s = f"weekly=${amt / 100:.2f}" if amt > 0 else "no benefit"
            print(f"  {row['applicant_id']:<12} [{row['verifier_verdict']:>8}]  {amt_s}")
        n_app = sum(1 for r in ledger if r["verifier_verdict"] == APPROVED)
        print(
            f"  -> {n_app}/{len(ledger)} approved (benefit issued); "
            f"{len(ledger) - n_app} denied"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
