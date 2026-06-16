# iso42001_impact_fairness_minimal — ISO/IEC 42001 A.5 Disparate-Impact Re-Derivation

A V-Kernel S0 audit-bundle pilot (Axis-2 spec-pinned dispatch) for **ISO/IEC
42001:2023 Annex A.5** *(Assessing Impacts of AI Systems)* — the **quantified**
slice of the impact-assessment process.

## What it demonstrates

A 42001-conforming AIMS discloses a fairness / adverse-impact figure in its
impact assessment. Outside parties act on it but cannot check it against the
underlying outcomes. This pilot re-derives the **disparate-impact ratio** (EEOC
"four-fifths" rule: `min(group approval rate) / max(group approval rate)`) from
the declared per-subject outcomes.

Honest figure for the shipped fixture: **0.5** (group rates 0.75 / 0.50 / 0.375
→ 0.375 / 0.75), below the 0.8 four-fifths threshold → flagged adverse impact.

## Claim boundary (read this)

Proves the disclosed ratio is **re-derivable from the declared outcomes** and
tamper-evident under the auditor's pinned rule. It does **NOT** prove the
groups/outcomes are correctly recorded, that this is the **right** fairness
measure for the context, or that the org **satisfies** the A.5 control (which
needs the impact-assessment *process* the AIMS owns). Only the *quantified* part
of A.5 is pilotable; the qualitative judgement is not. 42001 controls are
satisfied by process; this is a **record-quality / tamper-evidence enhancement**
on a figure an A.5 program already discloses — not a gap-filler. Synthetic data;
no customer.

## Quick start (from `v-kernel-audit-bundle` root)

```bash
python examples/iso42001_impact_fairness_minimal/_build_bundle.py --out-dir /tmp/iso42001_fair_bundle
python examples/iso42001_impact_fairness_minimal/verify.py --bundle-dir /tmp/iso42001_fair_bundle
# -> PASS (the disclosed ratio reconciles to the outcomes)
```

## File layout

| File | Purpose |
|---|---|
| `_build_bundle.py` | Writes the outcomes, computes the honest ratio, writes the claimed-value file + manifest. |
| `iso42001_fairness_recompute.py` | The `ReDerivationPrimitive` (EEOC four-fifths) + shared compute fn. |
| `verify.py` | Registers the primitive, anchors the committed spec, runs `BundleVerifier`. |
| `spec_pinned/iso42001_fairness.spec.json` | Auditor binding spec (type → primitive_id + scalar_epsilon). |
| `inputs/outcomes.json` | Frozen synthetic outcomes (24 subjects, 3 groups). |
| `outputs/disparate_impact_ratio.json` | *(built)* the producer's disclosed value. |
| `tests/test_iso42001_impact_fairness_minimal.py` | Unit + happy path + 3 tamper/attack surfaces. |

## Tamper / attack surfaces covered

1. **Metric mutation** — inflate the disclosed ratio toward 0.8 (cosmetic
   compliance) → `REDERIVATION_MISMATCH`.
2. **Outcomes tamper** — flip a rejection to approval without updating the
   manifest → `BAD_FILE_SHA` + `REDERIVATION_MISMATCH`.
3. **Weaker-spec substitution** — producer ships ε = 1e30 spec → `AnchorViolation`.

## Substrate exercised

Axis-2 spec-pinned dispatch (`audit_bundle/rederivation/`): `register_primitive`,
`SpecAnchor` from committed spec bytes, `scalar_epsilon` comparator. **New domain,
not a new shape** — reuses the recompute-and-compare shape of
`climate_emission_minimal` / the FEA pilot.
