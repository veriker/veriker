# payroll_reconciliation_minimal — Audit Bundle Quick-Start

A domain pilot modeled on the Government of Canada **Phoenix pay system**
failure. It demonstrates that the question the Auditor General found Phoenix
*could not answer* — **"why was this paycheck computed this way, and can I prove
the amount owed?"** — is independently verifiable when pay is shipped as a
V-Kernel audit bundle.

The Phoenix-relevant facts this pilot is calibrated to (Auditor General of
Canada, Fall 2017 / 2018 reports):

- The government **"does not understand the extent and causes of its pay
  problem"**; to localize errors it needed to analyze ~200 custom programs and
  had analyzed 6.
- When clawing back ~$3.57B in overpayments it **could not reconcile individual
  pay files or substantiate the amount owed**.
- ~40% of acting-/retroactive-pay transactions could not be processed
  automatically — those are exactly the cases in the fixtures here.

This pilot does **not** claim to fix Phoenix (the AG's root cause was governance,
and the live system's pay-rule complexity is a policy problem). It demonstrates
the narrow, real thing V-Kernel provides: per-record re-derivability and
closed-world accounting over a pay population.

## Prerequisites

Python 3.10+. The S2 / C16 leg (below) drives a **real Z3 re-execution**, so a Z3
backend must be present — either the `z3-solver` Python package or the `z3`
binary on `PATH` (`pick_default_invoker()` selects whichever is available). The
S2 discharge status is **verifier-signed**, so the verifier HMAC key must be
exported (disclosed synthetic demo secret — Standing Order #9):

```bash
export VKERNEL_VERIFIER_HMAC_KEY="demo-vkernel-verifier-secret-0123456789abcdef"
```

Run all commands from the **v-kernel-audit-bundle root**.

## Step 1 — Build the bundle

```bash
python examples/payroll_reconciliation_minimal/_build_bundle.py --out-dir <out>
```

Twelve eligible employees: ten paid (plain base pay, acting pay, retro pay,
acting+retro, one overpaid, one underpaid) and two withheld. Net clawback across
the period: 27,500 cents (a $400.00 overpayment minus a $125.00 underpayment).

The build also re-executes Z3 over the **paycheck conservation invariant** (S2 —
see below) and refuses to ship unless it discharges, printing
`Z3 re-run : discharged`.

## Step 2 — Verify

```bash
python examples/payroll_reconciliation_minimal/verify.py --bundle-dir <out>
```

Expected stdout: `PASS`. Exit code 0. The verifier HMAC key must be exported
(see Prerequisites) — without it the C16 check below fails closed
(`DISCHARGE_STATUS_FORGED`). Six TypedCheck plugins run — the four pilot checks
plus the substrate C14/C15/C16 trio (`default_post_w3_plugin_set()`, the **same
wiring `veriker/cli/verify.py` uses**):

| Plugin                       | Contract | What it proves on this domain                                   |
|------------------------------|----------|-----------------------------------------------------------------|
| `spec_sha_pin`               | §C1      | the pay-rules version is pinned and content-addressed           |
| `file_integrity_many_small`  | §C9      | inputs, ledger, coverage row, event log, and proof obligation are untampered |
| `payroll_re_derivation`      | §C6      | every paycheck **and** every clawback amount re-derives from rules+inputs |
| `coverage_sum_invariant`     | §C4      | eligible == issued + withheld (the extent the gov't couldn't quantify) |
| `dispatch_record_wellformed` | §C15     | the discharge record is schema-valid (op-kind, refinement fragment) |
| `refinement_discharge`       | §C16     | the verifier-signed `discharged` status is admitted **and** the verifier re-runs Z3, agreeing the paycheck conservation invariant holds |

### The S2 / C16 leg — verifier-recomputed paycheck conservation

`veriker/cli/verify.py` is **not** an entry point for this pilot: the bundle's
`manifest.typed_checks` legitimately claims the pilot-local `payroll_re_derivation`
and `coverage_sum_invariant` checks, whose plugin instances live next to this
pilot (not in the substrate registry), so `veriker/cli/verify.py` reports
`TypedCheckUnregistered`. The pilot's own `verify.py` is the §C5
auditor-independent entry point (it registers those local packs **and** the C16
trio). The C16 *substrate* leg is identical to what `veriker/cli/verify.py` runs.

The per-paycheck arithmetic — `gross = base + acting_uplift + retro` and
`net = gross − tax − pension` — is exact-integer cents, so it lives natively in
**QF_LIA**. The pilot carries it as an SMT-LIB refinement obligation bound to one
representative paycheck (**E0006**, the acting + retroactive-raise case, whose
base / uplift / retro are all non-zero):

```
(and (= gross (+ base uplift retro)) (= net (- (- gross tax) pension)))
```

The obligation text is pinned by digest at `proofs/payroll_conservation.smt2`;
the integer-cents dispatch context lives in the record's `proof.recheck_context`.
At verify time the C16 plugin re-parses the formula, substitutes the context, and
**re-executes Z3 offline** — only a verifier-key-signed `discharged` status is
admitted (the producer cannot self-sign). On the honest bundle the re-run agrees
(`1 verifier-signed, 1 re-discharged`).

The bundle also ships `status_change_log.jsonl` — an append-only,
timestamped correction/retraction trail (a $400 overpayment correction that is
disputed and retracted, plus a supplementary underpayment payment), the kind of
immutable trail Phoenix lacked. It is SHA-pinned in `manifest.files` (so it is
tamper-evident), but §C7 append-only *enforcement* is a substrate concern
(`audit_bundle/event_stream.py`), not wired as a per-pilot typed_check here —
matching `spectra_minimal` / `tabular_minimal`.

## Step 3 — Tamper-flow demos

**(a) Mutate an input** — change `acting_days` for E0003 in
`data/pay_events.csv`. Re-running the verifier exits `1` with
`FILE_SHA_MISMATCH` (caught by file integrity).

**(b) Forge a clawback, SHA-consistently** — set E0008's `clawback_cents` to 0
in `payload/paychecks.json` (hiding the $400 overpayment) **and** re-stamp the
manifest SHA so file integrity still passes. The verifier still exits `1` with
`PAYROLL_REDERIVATION_MISMATCH … clawback_cents mismatch`. **This is the Phoenix
point:** hashing the output is not enough — only re-deriving the amount owed from
the pinned rules and inputs catches a doctored reconciliation. (See the
`test_tamper_clawback_sha_consistent_caught_by_rederivation` test.)

**(c) Understate the withheld population** — set `n_withheld` to 0 in
`coverage/period_2026_05.json` and re-stamp its SHA. The verifier exits `1` with
`COVERAGE_SUM_MISMATCH`: issued + withheld no longer equals eligible.

**(d) Verifier-vs-claim discharge divergence (S2 "retain-and-still-reject")** —
take the signed discharge record, flip one cents value in
`proof.recheck_context` (e.g. `net += 1`) so the conservation equality no longer
holds, and re-sign `discharged` under the demo key. The C16 plugin's own Z3
re-run finds a counterexample (`FAILED`), contradicting the signed claim: the
verdict fails closed with `DISCHARGE_STATUS_VERIFIER_DIVERGENCE` **and** a signed,
re-verifiable divergence record is retained to `events.jsonl`. The verifier
keeps the evidence even though the verdict is still a hard reject. (See
`test_verifier_vs_claim_divergence_retains_signed_record`; it runs in a temp copy
so the shipped bundle stays clean — no `events.jsonl` is committed.) This is also
why the **build aborts** if you tamper with the context before signing: Z3 returns
`FAILED` and `_build_bundle.py` refuses to ship a dishonest `discharged`.

## File layout

```
examples/payroll_reconciliation_minimal/
├── _build_bundle.py            # synthesizes fixtures, computes the ledger, signs the S2 discharge
├── verify.py                   # registers the four pilot checks + the C14/C15/C16 substrate trio
├── PayrollReDerivationCheck.py # domain plugin (C6 paycheck + clawback re-derivation)
├── payroll_re_derivation.py    # stdlib re-derivation pack (integer-cents pay engine)
├── pilot.json                  # pilot registry entry
├── README.md
└── tests/
    ├── test_payroll_reconciliation_minimal.py   # happy path + 3 tamper tests
    └── test_payroll_s2_discharge.py             # S2 / C16: honest re-discharge + forgery + divergence legs
```

Built artifacts (under `<out>`): `spec/pay_rules.json`, `data/pay_events.csv`,
`payload/paychecks.json`, `coverage/period_2026_05.json`,
`status_change_log.jsonl`, `proofs/payroll_conservation.smt2`, `manifest.json`.

## Scope honesty

The pay engine here is a deliberately small, deterministic integer-cents model
(base + acting + retro, flat tax + pension). A production retrofit onto a real
HR/pay platform (e.g. the Dayforce replacement) would pin the actual rule set and
emit one bundle per pay run; the substrate (re-derivation pack + closed-world
coverage + append-only event log) is unchanged. What scales is the *shape*, not
this fixture's rule count.
