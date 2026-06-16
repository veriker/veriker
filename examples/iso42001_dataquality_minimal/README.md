# iso42001_dataquality_minimal — ISO/IEC 42001 A.7 Data-Quality Re-Derivation

A V-Kernel S0 audit-bundle pilot (Axis-2 spec-pinned dispatch, **multi-output**)
for **ISO/IEC 42001:2023 Annex A.7** *(Data for AI Systems)* — the data-quality
sub-controls.

## What it demonstrates

A 42001-conforming AIMS reports data-quality figures for its training/eval
datasets. Today an auditor takes those figures on the org's word; the dataset
and the statistics are not independently re-checked.

This pilot re-derives **three** quality metrics from one declared dataset, each a
separate spec-pinned output bound to the **same** verifier-side primitive:

| metric (output type) | rule (fixed in the primitive) | fixture value |
|---|---|---|
| `data_completeness_pct` | 100 · (records with every required field non-null) / N | 85.0 |
| `data_duplicate_rate_pct` | 100 · (N − distinct required-field tuples) / N | 10.0 |
| `data_positive_rate_pct` | 100 · (label==1) / (non-null-label records) | 52.631578… |

(Required fields: `feature_a`, `feature_b`, `label`. The synthetic fixture is
seeded with 3 incomplete records and 2 exact duplicates.)

## Why multi-output matters here

All three types bind to one `primitive_id` under an **identical** `scalar_epsilon`
comparator — which is exactly what the substrate's monotone-strictness invariant
requires (a primitive bound by ≥2 types must carry an identical comparator). The
pilot therefore exercises substrate the single-scalar pilots do not:

- the dispatch loop's **per-output cardinality guard** (one result per declared
  output — a doctored metric among three still fails the bundle);
- the **coverage invariant** (`COVERAGE_MISMATCH`): you cannot make a metric
  escape audit by deleting its `manifest.outputs` entry while leaving the file.

## Claim boundary (read this)

Proves the three reported figures are **re-derivable from the declared dataset**
and tamper-evident under the auditor's pinned rules. It does **NOT** prove the
dataset is fit for training, the labels are correct, or that the org **satisfies**
the A.7 control (which needs the data-governance *process* the AIMS owns). 42001
controls are satisfied by process; this is a **record-quality / tamper-evidence
enhancement** on figures an A.7 program already records — not a gap-filler.
Synthetic data; no customer.

## Quick start (from `v-kernel-audit-bundle` root)

```bash
python examples/iso42001_dataquality_minimal/_build_bundle.py --out-dir /tmp/iso42001_dq_bundle
python examples/iso42001_dataquality_minimal/verify.py --bundle-dir /tmp/iso42001_dq_bundle
# -> PASS (all three metrics re-derive and agree)
```

## File layout

| File | Purpose |
|---|---|
| `_build_bundle.py` | Writes the dataset, computes the 3 honest metrics, writes 3 claimed-value files + a 3-output manifest. |
| `iso42001_dataquality_recompute.py` | The type-switching `ReDerivationPrimitive`; shared compute fns so builder/verifier cannot drift. |
| `verify.py` | Registers the primitive, anchors the committed spec, runs `BundleVerifier`. |
| `spec_pinned/iso42001_dataquality.spec.json` | Auditor binding spec: 3 types → 1 primitive, identical comparator. |
| `inputs/dataset.json` | Frozen synthetic dataset (20 records). |
| `outputs/<metric>.json` | *(built)* the producer's claimed value per metric. |
| `tests/test_iso42001_dataquality_minimal.py` | Unit + happy path + 4 tamper/attack surfaces. |

## Tamper / attack surfaces covered

1. **Per-metric mutation** — inflate one claimed metric → `REDERIVATION_MISMATCH`.
2. **Dataset tamper** — edit a record without updating the manifest →
   `BAD_FILE_SHA` + `REDERIVATION_MISMATCH`.
3. **Omit-output coverage attack** — drop a metric's `manifest.outputs` entry →
   `COVERAGE_MISMATCH` (multi-output specific).
4. **Weaker-spec substitution** — producer ships ε = 1e30 spec → `AnchorViolation`.

## Substrate exercised

Axis-2 spec-pinned dispatch (`audit_bundle/rederivation/`), multi-output:
`register_primitive`, `SpecAnchor` from committed spec bytes, a type-switching
primitive, three `scalar_epsilon` outputs, the coverage invariant + cardinality
guard. **New domain, not a new shape** — reuses the recompute-and-compare shape
of `climate_emission_minimal` / the FEA pilot.
