# payroll_no_cliff_minimal — the S2 case where the verifier searches, not compares

This pilot answers one question directly: **how is verifier-controlled discharge
different from checking `x ∈ [a,b]`?**

The earlier S2 pilots
(`payroll_acting_discretion_minimal`) check that a *single produced value* lands
inside a band — which, honestly, is a bounds check with a signature on it. Z3
isn't doing anything a comparison couldn't. This pilot is the opposite: the
obligation **quantifies over an entire domain**, the verifier leaves the relevant
variables **free**, and Z3 has to **search** for a counterexample. There is no
`x ∈ [a,b]` that expresses it.

## The property

A government withholding schedule (three marginal brackets, integer cents per pay
period). The safety property is **no income cliff**:

> for **all** earnings `g1 ≤ g2` in `[0, cap]`,  take-home(`g1`) ≤ take-home(`g2`)

i.e. earning a dollar more must never *reduce* your take-home pay. This is the
classic marginal-rate / welfare-cliff bug — a bracket coded as "whole income at
the top rate," or a marginal rate above 100%, makes a higher earner net less at a
boundary.

In SMT (QF_LIA), with `g1` and `g2` left **free**:

```
(=> (and (>= g1 0) (<= g1 CAP) (>= g2 0) (<= g2 CAP) (<= g1 g2))
    (<= net100(g1) net100(g2)))
```

The verifier asserts the **negation** and asks Z3 whether *any* pair violates it.
`unsat` ⇒ no cliff exists anywhere ⇒ DISCHARGED. (`net100` is take-home scaled by
100 so the bracket math is exact integer arithmetic — no division, no rounding;
scaling by a positive constant preserves order, so monotonicity is identical.)

## Why this is not `x ∈ [a,b]`, and not re-derivation

- **No single value to bound.** The claim is universal over the whole earnings
  domain. There is nothing to substitute and compare.
- **You can't check it from the paychecks in the bundle.** Those are finitely
  many points; a cliff can hide between any two of them. Re-derivation (recompute
  each paycheck and compare) is blind to a hole it didn't sample.
- **Z3 searches.** Both earnings are `(declare-const)` free variables; the solver
  reasons symbolically over the entire interval, not over enumerated cases.
  `unsat` of the negation is a *proof of universal validity* — something a range
  comparison fundamentally cannot produce.

This is the honest dividing line: a bounds check answers "is this number okay?";
this answers "is the whole schedule okay for every income at once?"

## Prerequisites

Python 3.10+. A Z3 backend (`z3-solver` package **or** the `z3` binary on `PATH`).
The discharge status is verifier-signed, so export the disclosed synthetic demo
key (Standing Order #9):

```bash
export VKERNEL_VERIFIER_HMAC_KEY="demo-vkernel-verifier-secret-0123456789abcdef"
```

## Run it

```bash
python examples/payroll_no_cliff_minimal/_build_bundle.py \
    --out-dir examples/payroll_no_cliff_minimal/bundle
python examples/payroll_no_cliff_minimal/verify.py \
    --bundle-dir examples/payroll_no_cliff_minimal/bundle
# no pilot-local pack, so the bare CLI verifies it directly too:
python veriker/cli/verify.py --bundle-dir examples/payroll_no_cliff_minimal/bundle
```

Expected: `PASS`. Four substrate checks run — `spec_sha_pin` (§C1),
`file_integrity_many_small` (§C9), `dispatch_record_wellformed` (§C15),
`refinement_discharge` (§C16, the Z3 search).

## The fraud it catches — that a range check cannot

`tests/` ships the divergence leg: a producer publishes the same schedule but
with a **130% marginal rate** in the middle bracket — a genuine income cliff —
writes a matching obligation file, and signs it `discharged`. The verifier's own
Z3 search finds an earnings pair where the higher earner takes home *less*
(`FAILED`), contradicting the signed claim. The verdict fails closed with
`DISCHARGE_STATUS_VERIFIER_DIVERGENCE`, and a signed, re-verifiable divergence
record is retained to `events.jsonl` (retain-and-still-reject). No single value
is "wrong" — the violation is a relationship between two incomes that no `a ≤ x ≤
b` check could even express.

## Scope honesty

- The schedule constants are baked into the obligation as literals (the parser's
  linearity rule rejects `variable × variable`, so a rate must be a literal). The
  divergence test therefore swaps in a different schedule formula rather than a
  context value — modelling "someone published a cliffed schedule," which is the
  realistic failure.
- Linear integer arithmetic only (QF_LIA): brackets are piecewise-linear. A
  genuinely nonlinear schedule is out of the v0.1 fragment.
- Synthetic. Real schedules, real `cap`, and real bracket data would come from
  the tax/pay authority; these numbers are fabricated. It proves the *property is
  machine-checkable over the whole domain*, not that this schedule is policy.

## File layout

```
examples/payroll_no_cliff_minimal/
├── _build_bundle.py   # builds the formula, runs the Z3 search, signs the discharge
├── verify.py          # FileIntegrity + SpecShaPin + the C14/C15/C16 substrate trio
├── pilot.json
├── README.md
└── tests/
    └── test_payroll_no_cliff_minimal.py   # honest PASS + no-key + cliff divergence
```

Built artifacts (under `<out>`): `spec/withholding_schedule.json`,
`payload/no_cliff_claim.json`, `proofs/no_cliff.smt2`, `manifest.json`.
