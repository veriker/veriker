"""_build_bundle.py — build a deterministic pandemic_benefit_eligibility_minimal audit bundle.

Models the Canadian pandemic-benefit overpayment failure ($4.6B paid to ineligible recipients,
per Auditor General of Canada). A synthetic applicant pool with published eligibility rules
(minimum prior income $5,000, income-drop threshold, eligibility period window). The verifier
independently re-derives each applicant's eligibility verdict and weekly benefit amount from
the pinned rule set and attested attributes — the exact pre-payment check that was skipped.

The narrow, honest claim (stated verbatim in README and in verify.py PASS output):
"A deterministic benefit-eligibility decision and benefit amount can be independently
re-derived and signed from the applicant's attested attributes and the published rule set
BEFORE disbursement — the exact pre-payment check that was skipped. Synthetic rules and
records; no CRA/Service Canada integration; not a fraud detector."

Usage (from v-kernel-audit-bundle root):
    python examples/pandemic_benefit_eligibility_minimal/_build_bundle.py \\
        --out-dir /tmp/pandemic_bundle

Outputs:
  <out>/spec/eligibility_rules.json         (published rule set; spec_files)
  <out>/spec/disbursement_hmac_key.hex      (bundled synthetic key; spec_files)
  <out>/data/applicants.json                (attested applicant attributes)
  <out>/payload/disbursement_decisions.json (disbursement decisions being audited)
  <out>/coverage/disbursement_period.json   (closed-world: issued=approved, withheld=denied)
  <out>/manifest.json

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
sys.path.insert(0, str(_HERE))

from audit_bundle.emitter import BundleContent, write_bundle  # noqa: E402
from pandemic_eligibility_rederivation import (  # noqa: E402
    APPROVED,
    DENIED,
    evaluate_eligibility,
    sign_decision,
)

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "pandemic-benefit-eligibility-minimal-rc"
_CREATED_AT = "2026-05-29T00:00:00Z"
_TYPED_CHECKS = [
    "spec_sha_pin",
    "file_integrity_many_small",
    "pandemic_eligibility_rederivation",
    "coverage_sum_invariant",
]

# Disclosed synthetic demo key — written into the bundle so the verifier can re-compute
# every HMAC from first principles (Standing Order #9: NOT real secrets). Production binds
# the disbursement system to an asymmetric identity (C18 / Sigstore) out of band.
_DISBURSEMENT_KEY_HEX = "c3d4e5f607182930a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718"
_DISBURSEMENT_SYSTEM_ID = "system://cra-pandemic-benefit-disbursement-v1"

# Published rule set — mirrors the core CERB eligibility criteria (synthetic, not legal advice).
# income amounts are in cents; thresholds in basis points (bps).
_RULES = {
    "schema": "pandemic-benefit-rules-v1",
    "program": "PANDEMIC_BENEFIT_DEMO",
    "weeks_per_year": 52,
    "eligibility_criteria": {
        "min_prior_income_cents": 500000,       # $5,000 CAD minimum prior earned income
        "income_drop_threshold_bps": 1000,      # period income must be ≤10% of prior weekly
        "replacement_rate_bps": 6000,           # 60% of prior weekly income
        "max_weekly_benefit_cents": 50000,      # $500/week maximum weekly benefit
        "period_start_week": 1,                 # eligibility window: weeks 1–26
        "period_end_week": 26,
    },
    "admitted_employment_statuses": [
        "employed",
        "self_employed",
        "gig_worker",
        "unemployed",
    ],
    "note": (
        "Synthetic rule set modelling core pandemic-benefit eligibility criteria. "
        "Not legal or regulatory advice. No CRA/Service Canada integration."
    ),
}

# Synthetic applicant pool — 8 applicants, a mix of eligible and ineligible cases.
# Attributes: applicant_id, prior_income_cents (annual), period_income_cents (weekly during period),
#             employment_status, eligibility_period_week.
_APPLICANTS = [
    # Eligible cases (APPROVED by the rule set)
    {
        "applicant_id": "APP-001",
        "name": "Alice Tremblay",
        "prior_income_cents": 5200000,      # $52,000/yr (prior_weekly ~$1,000)
        "period_income_cents": 5000,        # $50/wk during period (lost work)
        "employment_status": "employed",
        "eligibility_period_week": 5,
    },
    {
        "applicant_id": "APP-002",
        "name": "Bob Nguyen",
        "prior_income_cents": 2600000,      # $26,000/yr (prior_weekly ~$500)
        "period_income_cents": 0,           # $0/wk (fully stopped)
        "employment_status": "gig_worker",
        "eligibility_period_week": 10,
    },
    {
        "applicant_id": "APP-003",
        "name": "Carmen Diaz",
        "prior_income_cents": 3900000,      # $39,000/yr (prior_weekly ~$750)
        "period_income_cents": 2500,        # $25/wk (income effectively stopped)
        "employment_status": "self_employed",
        "eligibility_period_week": 3,
    },
    {
        "applicant_id": "APP-004",
        "name": "David Kim",
        "prior_income_cents": 7800000,      # $78,000/yr (prior_weekly ~$1,500)
        "period_income_cents": 10000,       # $100/wk (income dropped significantly)
        "employment_status": "employed",
        "eligibility_period_week": 15,
    },
    {
        "applicant_id": "APP-005",
        "name": "Elena Petrov",
        "prior_income_cents": 500000,       # exactly $5,000/yr (the minimum floor)
        "period_income_cents": 0,
        "employment_status": "unemployed",
        "eligibility_period_week": 8,
    },
    # Ineligible cases (DENIED by the rule set)
    {
        "applicant_id": "APP-006",
        "name": "Frank Okafor",
        "prior_income_cents": 400000,       # $4,000/yr — BELOW the $5,000 minimum floor
        "period_income_cents": 0,
        "employment_status": "employed",
        "eligibility_period_week": 6,
    },
    {
        "applicant_id": "APP-007",
        "name": "Grace Leblanc",
        "prior_income_cents": 5200000,      # $52,000/yr (prior_weekly ~$1,000)
        "period_income_cents": 80000,       # $800/wk during period — income did NOT drop below threshold
        "employment_status": "employed",
        "eligibility_period_week": 4,
    },
    {
        "applicant_id": "APP-008",
        "name": "Hamid Rashid",
        "prior_income_cents": 5200000,      # $52,000/yr
        "period_income_cents": 0,
        "employment_status": "employed",
        "eligibility_period_week": 30,      # week 30 — OUTSIDE the eligibility window (1–26)
    },
]


def build(out_dir: Path) -> None:
    # spec/ — published rule set + disclosed synthetic key
    rules_bytes = json.dumps(_RULES, indent=2, sort_keys=True).encode("utf-8")
    key_bytes = (_DISBURSEMENT_KEY_HEX + "\n").encode("utf-8")
    key = bytes.fromhex(_DISBURSEMENT_KEY_HEX)

    # data/ — attested applicant attributes (the inputs to the re-derivation)
    applicants_bytes = json.dumps(_APPLICANTS, indent=2).encode("utf-8")

    # payload/ — disbursement decisions (the outputs being audited)
    decisions: list[dict] = []
    n_approved = 0
    n_denied = 0
    for applicant in _APPLICANTS:
        verdict, weekly_benefit = evaluate_eligibility(_RULES, applicant)
        record = {
            "applicant_id": applicant["applicant_id"],
            "verdict": verdict,
            "weekly_benefit_cents": weekly_benefit,
            "disbursement_system_id": _DISBURSEMENT_SYSTEM_ID,
            "period_week": applicant["eligibility_period_week"],
        }
        record["signature"] = sign_decision(record, key)
        decisions.append(record)
        if verdict == APPROVED:
            n_approved += 1
        else:
            n_denied += 1

    decisions_bytes = json.dumps(decisions, indent=2).encode("utf-8")

    # coverage/ — closed-world: issued=approved, withheld=denied
    coverage_row = {
        "tick_id": "pandemic-benefit-2026-05-A",
        "n_eligible": len(_APPLICANTS),
        "n_issued": n_approved,
        "n_withheld": n_denied,
        "withheld_reason_breakdown": {
            "INELIGIBLE_PER_PUBLISHED_RULE_SET": n_denied,
        },
    }
    coverage_bytes = json.dumps(coverage_row, indent=2, sort_keys=True).encode("utf-8")

    assert n_approved + n_denied == len(_APPLICANTS), "internal accounting drift"

    # --- Emit via the reference-emitter SDK (scaffold + digests + manifest) ---
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "data/applicants.json": applicants_bytes,
            "payload/disbursement_decisions.json": decisions_bytes,
            "coverage/disbursement_period.json": coverage_bytes,
        },
        spec_files={
            "eligibility_rules.json": rules_bytes,
            "disbursement_hmac_key.hex": key_bytes,
        },
        typed_checks=_TYPED_CHECKS,
    )
    manifest = write_bundle(out_dir, content)

    print(f"Bundle written to {out_dir}")
    print(f"  applicants        : {len(_APPLICANTS)}")
    print(f"  approved (issued) : {n_approved}")
    print(f"  denied (withheld) : {n_denied}")
    print(f"  manifest files    : {len(manifest['files'])}")
    print(f"  manifest          : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic pandemic_benefit_eligibility_minimal audit bundle"
    )
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        out_dir = args.out_dir.resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        build(out_dir)
    except AssertionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
