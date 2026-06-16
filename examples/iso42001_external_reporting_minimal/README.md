# iso42001_external_reporting_minimal — ISO/IEC 42001 A.8 External-Reporting Reconciliation

A V-Kernel S0 audit-bundle pilot (Axis-2 spec-pinned dispatch, **two comparator
kinds**) for **ISO/IEC 42001:2023 Annex A.8** *(Information for Interested
Parties)* — External Reporting.

## What it demonstrates

A 42001-conforming AIMS publishes aggregate figures to outside stakeholders
(regulators, users, the public) in transparency reports. Those parties **act** on
the disclosed numbers but cannot check them against the org's internal records.
This pilot reconciles two disclosed figures to one declared internal decision
log:

| disclosed figure (output type) | rule | comparator | fixture value |
|---|---|---|---|
| `disclosed_automated_decision_count` | # records where `automated` is true | **`exact`** | 9 |
| `disclosed_human_oversight_rate_pct` | 100 · (automated ∧ human_reviewed) / automated | `scalar_epsilon` (1e-9) | 66.6667 |

## Why it's distinct from the A.6 / A.7 pilots

It is the first 42001 pilot to bind **two distinct primitives under two distinct
comparator KINDS** in one bundle: a disclosed integer **must match exactly**
(`exact`), while a disclosed rate matches within a pinned epsilon. (Two distinct
primitives → the monotone-strictness invariant is satisfied trivially.) This
shows the substrate handling a heterogeneous disclosure — a count and a rate —
under one auditor anchor.

## Claim boundary (read this)

Proves the externally-disclosed figures **reconcile to / are re-derivable from**
the declared internal log and are tamper-evident under the auditor's pinned
rules — i.e. the public number matches the ledger. It does **NOT** prove the log
is complete or truthful, the disclosure is adequate, or that the org **satisfies**
the A.8 control (which needs the reporting *process* the AIMS owns). 42001
controls are satisfied by process; this is a **record-quality / tamper-evidence
enhancement** on a figure an A.8 program already discloses — not a gap-filler.
Synthetic data; no customer.

## Quick start (from `v-kernel-audit-bundle` root)

```bash
python examples/iso42001_external_reporting_minimal/_build_bundle.py --out-dir /tmp/iso42001_er_bundle
python examples/iso42001_external_reporting_minimal/verify.py --bundle-dir /tmp/iso42001_er_bundle
# -> PASS (both disclosed figures reconcile to the log)
```

## File layout

| File | Purpose |
|---|---|
| `_build_bundle.py` | Writes the log, computes the 2 honest disclosed figures, writes 2 claimed-value files + a 2-output manifest. |
| `iso42001_external_reporting_recompute.py` | Two `ReDerivationPrimitive`s (count → exact, rate → scalar_epsilon) + shared compute fns. |
| `verify.py` | Registers both primitives, anchors the committed spec, runs `BundleVerifier`. |
| `spec_pinned/iso42001_external_reporting.spec.json` | Auditor binding spec: 2 types → 2 primitives, 2 comparators. |
| `inputs/decision_log.json` | Frozen synthetic internal decision log (12 records). |
| `outputs/<figure>.json` | *(built)* the producer's disclosed value per figure. |
| `tests/test_iso42001_external_reporting_minimal.py` | Unit + happy path + 4 tamper/attack surfaces. |

## Tamper / attack surfaces covered

1. **Count mutation (exact)** — over-disclose the automated count by +1 →
   `REDERIVATION_MISMATCH`.
2. **Rate mutation (scalar_epsilon)** — inflate the oversight rate by +0.5 →
   `REDERIVATION_MISMATCH`.
3. **Log tamper** — flip a `human_reviewed` flag without updating the manifest →
   `BAD_FILE_SHA` + `REDERIVATION_MISMATCH`.
4. **Weaker-spec substitution** — producer ships an ε = 1e30 rate spec →
   `AnchorViolation`.

## Substrate exercised

Axis-2 spec-pinned dispatch (`audit_bundle/rederivation/`): `register_primitive`
(×2), `SpecAnchor` from committed spec bytes, the `exact` **and** `scalar_epsilon`
comparators in one bundle, two-output coverage + cardinality. **New domain, not a
new shape** — reuses the recompute-and-compare shape of `climate_emission_minimal`
/ the FEA pilot.
