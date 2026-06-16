# pandemic_benefit_eligibility_minimal

V-Kernel audit-bundle pilot demonstrating deterministic benefit-eligibility re-derivation
for a pandemic-benefit disbursement scenario.

## Honest claim (verbatim)

> "A deterministic benefit-eligibility decision and benefit amount can be independently
> re-derived and signed from the applicant's attested attributes and the published rule set
> BEFORE disbursement — the exact pre-payment check that was skipped. Synthetic rules and
> records; no CRA/Service Canada integration; not a fraud detector."

## Motivation

The Canadian pandemic-benefit program (modelled here) paid approximately $4.6B to ineligible
recipients, per the Auditor General of Canada. The root cause: disbursement decisions were
made without a deterministic pre-payment eligibility check against the published rule set.
This pilot demonstrates that such a check is machine-derivable, tamper-evident, and
independently verifiable — and that a check that was skipped could have been automated.

## Re-derivation primitive

Re-derive each applicant's eligibility verdict and benefit amount by evaluating the published
deterministic rule set (minimum prior income $5,000, income-drop threshold, eligibility
period window) against the applicant's attested attributes, and assert it equals the bundled
disbursement decision.

## Eligibility rules (synthetic)

| Rule | Value |
|---|---|
| Minimum prior annual income | $5,000 CAD |
| Income-drop threshold | period income ≤ 10% of prior weekly income |
| Benefit replacement rate | 60% of prior weekly income |
| Maximum weekly benefit | $500/week |
| Eligibility period window | weeks 1–26 |

Admitted employment statuses: employed, self_employed, gig_worker, unemployed.

## Quick start

From the `v-kernel-audit-bundle` root:

```bash
# Gate 1 — build
python examples/pandemic_benefit_eligibility_minimal/_build_bundle.py \
    --out-dir /tmp/pandemic_bundle

# Gate 2 — verify (stdout must contain PASS)
python examples/pandemic_benefit_eligibility_minimal/verify.py \
    --bundle-dir /tmp/pandemic_bundle

# Gate 3 — pilot tests
python -m pytest tests/test_pandemic_benefit_eligibility_minimal.py -v

# Gate 4 — regression
python -m pytest tests/test_fragments.py tests/test_dispatch_record_wellformed.py -q
```

## Tamper flow

The tamper test (`test_ineligible_applicant_approved_is_caught`) mutates APP-006 so the
bundled decision says APPROVED while the applicant's prior_income is below the $5,000 floor.
The verifier re-derives DENIED and returns `result.ok is False` with
`PANDEMIC_ELIGIBILITY_REDERIVATION_MISMATCH` in the failures list.

This is the central thesis: the verifier never trusts the disbursement system's verdict —
it re-derives it from the applicant's attested attributes and the published rule set, then
catches any divergence.

## File layout

```
pandemic_benefit_eligibility_minimal/
├── _build_bundle.py                       # build script (synthetic fixtures + manifest)
├── verify.py                              # verifier entry point (four plugins)
├── pandemic_eligibility_rederivation.py   # stdlib-only re-derivation engine (C5)
├── PandemicEligibilityReDerivationCheck.py # TypedCheck plugin (subprocess wrap)
├── pilot.json                             # pilot metadata (hand-authored, not auto-generated)
└── README.md
```

Tests live at `tests/test_pandemic_benefit_eligibility_minimal.py`.

## Scope and limitations

- **Synthetic data only.** No real applicant data. No CRA/Service Canada integration.
- **Not a fraud detector.** The verifier catches divergence between the bundled decision and
  the rule set — it does not detect identity fraud or fabricated attested attributes.
- **Deterministic rules only.** Rules with interpretive elements (e.g. exceptional
  circumstances, discretionary provisions) are out of scope for this pilot.
- **No legal or regulatory advice.** The rule set models published CERB eligibility criteria
  for demonstration purposes only.
