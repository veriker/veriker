# payroll_acting_discretion_minimal — the S2 case re-derivation cannot reach

A government **acting-pay placement** under a collective agreement, built to show
the one situation where verifier-controlled discharge (patent **S2** / contract
**§C16**) is a genuine *upgrade* over re-derivation rather than a weaker echo of
it: **when there is no single correct answer to recompute.**

## Why this pilot exists

`payroll_reconciliation_minimal` proves the Phoenix-relevant claim that *the
amount owed must re-derive from the pinned rules + inputs* (§C6). That works
because each ordinary paycheck has exactly one deterministic answer — and where
re-derivation is available, it strictly dominates any formal property over the
same numbers.

But the transactions that actually sank Phoenix were the **acting and
retroactive** cases (~40% of the volume the automated system could not process,
and the population the Auditor General could not reconcile). Many of those are
**discretionary**: the collective agreement sets the acting rate *at management
discretion within a band*. There is no function `f(rules, inputs) → acting_rate`
to re-run — the rate is a free choice inside a polytope. Re-derivation has
**nothing to recompute**. The only thing a verifier can independently check is
an **admissibility property**, and that is exactly what S2 / C16 discharges.

## The obligation

An AS-03 employee (E2207) acts in a higher classification (PM-04). The
agreement's four-clause band, all in integer cents per pay period (**QF_LIA**):

```
(and (>= acting_rate band_min)         ; (a) at least the PM-04 band minimum
     (<= acting_rate band_max)         ; (b) at most the PM-04 band maximum
     (>= acting_rate raise_floor)      ; (c) >= substantive × 1.04 (min raise)
     (<= acting_rate windfall_ceiling)); (d) <= substantive × 1.40 (anti-windfall)
```

The four bounds are **spec-derived** (re-derivable from the pinned rules + the
substantive rate); the `acting_rate` placed within them is **not**. For E2207
the admissible band is `[326923, 366153]` ¢ and management chose `350000` ¢.

The obligation text is pinned by digest at `proofs/acting_band.smt2`; the
integer-cents context lives in the record's `proof.recheck_context`. At verify
time the C16 plugin re-parses the formula, substitutes the context, and
**re-executes Z3 offline** — only a verifier-key-signed `discharged` status is
admitted (the producer cannot self-sign).

## Prerequisites

Python 3.10+. A Z3 backend (the `z3-solver` package **or** the `z3` binary on
`PATH`). The discharge status is verifier-signed, so export the disclosed
synthetic demo key (Standing Order #9):

```bash
export VKERNEL_VERIFIER_HMAC_KEY="demo-vkernel-verifier-secret-0123456789abcdef"
```

## Run it

```bash
python examples/payroll_acting_discretion_minimal/_build_bundle.py \
    --out-dir examples/payroll_acting_discretion_minimal/bundle
python examples/payroll_acting_discretion_minimal/verify.py \
    --bundle-dir examples/payroll_acting_discretion_minimal/bundle
```

Expected: `PASS`. Because this pilot carries **no pilot-local re-derivation
pack**, the same headline runs through the bare CLI with zero pilot code — and it
PASSes there too (contrast `payroll_reconciliation_minimal`, whose local
`payroll_re_derivation` pack makes `veriker/cli/verify.py` report
`TypedCheckUnregistered`):

```bash
python veriker/cli/verify.py --bundle-dir examples/payroll_acting_discretion_minimal/bundle
```

Four substrate checks run: `spec_sha_pin` (§C1), `file_integrity_many_small`
(§C9), `dispatch_record_wellformed` (§C15), `refinement_discharge` (§C16).

## The fraud it catches — and re-derivation structurally cannot

There is no canonical rate, so there is no "wrong recomputed number" to flag. The
only thing that bites is the band-membership property. Two out-of-band
placements (tests in `tests/`) — a producer signs `discharged` over the bad
context, the verifier's own Z3 re-run returns `FAILED`, the verdict fails closed
with `DISCHARGE_STATUS_VERIFIER_DIVERGENCE`, and a signed, re-verifiable
divergence record is retained to `events.jsonl` (retain-and-still-reject):

| Tamper | Why re-derivation misses it | C16 verdict |
|---|---|---|
| **Windfall over-payment** `370000` — *inside* the raw PM-04 band (`≤373077`) but above the anti-windfall cap (`366153`) | no canonical rate to compare against; the value looks like a legal band placement | `FAILED` → divergence |
| **Below-floor under-payment** `320000` — below the band minimum (`326923`) | same — there is no single right number it differs from | `FAILED` → divergence |

This is the genuine upgrade: it converts a class of cases that `payroll_agent_gate_minimal`
would force to **human review** (no single re-derivable answer) into
**verifier-proven auto-clearance** (the chosen rate is *proven* in-band), without
weakening the gate — raising safe throughput on exactly the discretionary
acting/retro transactions that were ~40% of the Phoenix backlog.

## Scope honesty

- The band edges are spec-derived and *could* also be §C6-re-derived; the point
  is the `acting_rate` itself, which cannot. This pilot deliberately checks only
  the property to keep that contrast sharp.
- The obligation is a **ground** membership check (the chosen rate vs. concrete
  bounds) — the right claim for a single placement decision. The same machinery
  also supports **range proofs** (leave a symbol free via the context's
  `__sorts__`; `unsat` of the negation over a free `(declare-const)` variable is
  universal validity) for policy-level claims like "for all gross in this range,
  tax ≤ gross." Not exercised here.
- Synthetic. The discretionary-within-band clause is a real public-service
  agreement pattern, but E2207 and these numbers are fabricated; this is not a
  customer engagement. It proves re-derivability/admissibility, not the policy.

## File layout

```
examples/payroll_acting_discretion_minimal/
├── _build_bundle.py   # derives the band, signs the in-band S2 discharge (real Z3)
├── verify.py          # FileIntegrity + SpecShaPin + the C14/C15/C16 substrate trio
├── pilot.json
├── README.md
└── tests/
    └── test_payroll_acting_discretion_minimal.py   # honest PASS + forgery + 2 out-of-band divergence legs
```

Built artifacts (under `<out>`): `spec/acting_pay_rules.json`,
`payload/placement.json`, `proofs/acting_band.smt2`, `manifest.json`.
