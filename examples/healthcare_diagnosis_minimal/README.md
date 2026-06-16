# healthcare_diagnosis_minimal — Clinical Diagnostic-Suggestion Audit Bundle

Minimal domain pilot: a rule-based ICD-10 diagnostic-suggestion engine bundled
for V-Kernel audit verification (the audit-bundle contract §C5, §C6, §C9).

## The clinical traceability story

Clinical decision-support systems that surface diagnostic candidates must be
**computationally reproducible** end-to-end: the regulator, the payer, and the
clinician all need to confirm that the suggested diagnosis was derived
deterministically from the exact symptom set the model saw, using only
committed artifacts — no proprietary runtime, no black-box re-execution.

The V-Kernel audit bundle is exactly that receipt:

> A clinical-decision-support model surfaces a ranked list of ICD-10 candidate
> codes for a patient. The bundle contains the structured symptom set, the
> decision-tree rule definitions, and the bundled candidate list. A verifier
> re-traverses the same rules over the same symptoms and asserts the predicted
> ICD-10 codes, confidences, evidence anchors, and rule paths match byte-for-byte.

This pilot demonstrates the substrate claim on a synthetic but structurally
realistic rule-based engine. Production integrators replace the rule traversal
with a determinism-mode forward pass over a real clinical knowledge graph or
ontology lookup; the bundle shape and verification protocol are identical.

## Re-derivation primitive

```
for each rule (sorted by rule_id):
    for each condition: symptom must be present AND severity >= min_severity
    if all conditions match:
        confidence = round(sum(severity of matched symptoms) * weight, 6)
        emit candidate { icd10_code, confidence, matched_symptom_ids, rule_path }
```

All arithmetic is integer + float with 6-decimal rounding. Stdlib only
(no numpy/scipy). The verifier re-runs this traversal from committed
inputs and asserts the resulting list is identical to `payload/diagnosis.json`.

## Prerequisites

Python 3.11+. No third-party dependencies.
Run all commands from the **v-kernel-audit-bundle root**.

## Step 1 — Build the bundle

```bash
python examples/healthcare_diagnosis_minimal/_build_bundle.py
```

By default this performs an **in-place build**: it writes manifest.json,
inputs/, payload/, and re_derive/ artifacts into the pilot directory itself
so `cli/verify.py --bundle-dir examples/healthcare_diagnosis_minimal/`
Just Works.

To write the bundle into a fresh out-dir instead:

```bash
python examples/healthcare_diagnosis_minimal/_build_bundle.py --out-dir /tmp/hcd
```

Expected output:

```
Bundle written to .../healthcare_diagnosis_minimal
  symptoms         : 5
  rules            : 4
  candidates       : 4 ICD-10 codes
  evidence anchors : 10 OpaqueFragment
  manifest files   : <N>
  manifest         : .../manifest.json
```

## Step 2 — Verify

Two equivalent verifier routes are supported:

```bash
# Substrate CLI — auto-detects re_derive/healthcare_diagnosis_pack.py
python cli/verify.py --bundle-dir examples/healthcare_diagnosis_minimal/
```

```bash
# Pilot-local wrapper — registers HealthcareDiagnosisReDerivationCheck explicitly
python examples/healthcare_diagnosis_minimal/verify.py \
    --bundle-dir examples/healthcare_diagnosis_minimal/
```

Both must print `PASS` and exit 0. They invoke the same stdlib re-derivation
pack via subprocess — the pilot-local wrapper is a thinner shell for
domain-pilot smoke testing; the substrate CLI is the canonical auditor route.

| Plugin                              | Contract clause                                          |
|-------------------------------------|----------------------------------------------------------|
| `file_integrity_many_small`         | §C9 per-file SHA walk with named reason codes            |
| `re_derivation_invocation` / `healthcare_diagnosis_re_derivation` | §C6 deterministic ICD-10 re-derivation, exact match |

## Step 3 — Tamper-flow demo

Mutate the severity of one symptom — this shifts the rule-fire pattern and the
confidences, and the re-derivation detects the divergence:

```python
import json, pathlib
p = pathlib.Path('examples/healthcare_diagnosis_minimal/inputs/symptoms.json')
d = json.loads(p.read_text())
d[1]['severity'] = 1   # fever severity 4 -> 1; rule-J18 and rule-A49 stop firing
# Write back with the same canonical bytes layout as _build_bundle.py
import json as _j
p.write_bytes((_j.dumps(d, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode('utf-8'))
```

Re-run the verifier:

```bash
python examples/healthcare_diagnosis_minimal/verify.py \
    --bundle-dir examples/healthcare_diagnosis_minimal/
```

Expected exit code: `1`. Stderr includes `BAD_FILE_SHA` (SHA mismatch caught
first) or `HEALTHCARE_REDERIVATION_MISMATCH` (if manifest SHA was re-aligned
to the tampered symptom set).

## Fragment anchors

The bundle uses `OpaqueFragment` (the V-Kernel open-extension fragment type)
to anchor each evidence triplet that contributed to a candidate's confidence:

| Anchor key shape                       | kind_tag                  | Locator fields                            |
|----------------------------------------|---------------------------|-------------------------------------------|
| `<rule_id>-<symptom_id>-<icd10_code>`  | `icd10_evidence_anchor`   | `rule_id`, `symptom_id`, `icd10_code`     |

Substrate validates shape only; semantic validation (rule existence, symptom
existence, code well-formedness) is the responsibility of the
`HealthcareDiagnosisReDerivationCheck` plugin.

## File layout

```
examples/healthcare_diagnosis_minimal/
├── _build_bundle.py                            # synthesizes fixtures + builds audit bundle
├── verify.py                                   # pilot-local TypedCheck wrapper
├── HealthcareDiagnosisReDerivationCheck.py     # TypedCheck plugin (subprocess wrapper)
├── README.md
├── inputs/
│   ├── symptoms.json                           # 5 structured symptoms
│   └── rules.json                              # 4 decision-tree rule definitions
├── payload/
│   └── diagnosis.json                          # 4 ICD-10 candidates (model output)
├── re_derive/
│   └── healthcare_diagnosis_pack.py            # stdlib re-derivation pack (AB4)
└── manifest.json                               # generated; SHA-pinned for every file above
```

Tests live alongside the other domain-pilot tests at
`tests/test_healthcare_diagnosis_minimal.py` (one level up, same place as
test_kg_minimal.py / test_dp_minimal.py / test_bom_minimal.py).
