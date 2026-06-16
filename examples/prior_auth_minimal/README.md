# prior_auth_minimal — Health-Plan AI Prior-Authorization Audit Bundle

Minimal domain pilot: a rules-based medical-necessity decision engine for health-plan
prior-authorization, bundled for V-Kernel audit verification with **provider-responsibility
attestation** binding.

## Regulatory anchor — Colorado Reg 10-1-1 § 5.A.5

Colorado Regulation 10-1-1 (AI Systems in Insurance) § 5.A.5 requires that health
insurers using AI in utilization management (UM) decisions **bind the responsible
licensed provider's identity and sign-off to each adverse or approval determination**.
The provider — not the AI — is the accountable decision-maker. The AI recommendation
is advisory; the provider attestation is the legally operative act.

This pilot demonstrates the V-Kernel substrate claim on that requirement:

> A health-plan AI prior-authorization system evaluates a patient's clinical features
> (ICD-10 diagnoses, prior treatments, lab values) against the plan's committed
> medical-necessity rules and recommends approve or deny. The responsible clinician
> (e.g. medical director) reviews and signs off, producing a cryptographic attestation
> that binds their provider ID, role, and verdict to the specific decision. The audit
> bundle contains the clinical features, the rule set, the AI recommendation, and the
> provider's HMAC-signed attestation. A verifier re-runs the decision tree from the
> committed inputs, recomputes the expected verdict, and re-verifies every HMAC —
> asserting that the provider's attestation genuinely binds to that specific output
> and has not been mutated post-hoc.

**Additional regulatory scope:** CA SB 1120 (UM AI transparency), TX/AZ/MD adverse-
determination laws (provider sign-off on AI-assisted denials), CMS WISER (Medicare
Advantage UM AI traceability), NAIC AI Systems Evaluation Tool (health/UM scope).

## Differentiator vs. `healthcare_diagnosis_minimal`

`healthcare_diagnosis_minimal` covers diagnostic-suggestion (ICD-10 candidate ranking
from symptoms). This pilot covers prior-authorization (approve/deny decisions against
plan rules) and adds the **provider-attestation binding** via `decision_provenance_log`
— a distinct regulatory obligation under § 5.A.5 and CMS WISER that the diagnostic
pilot does not exercise.

## Re-derivation primitive

```
for each prior-auth request (from clinical/findings.jsonl):
    for each plan rule (sorted by rule_id, from clinical/plan_rules.json):
        if procedure_category matches AND all required_diagnoses present AND
           all required_prior_treatments present AND lab_value constraint satisfied:
            emit { model_recommendation: rule.verdict, matched_rule_id: rule.rule_id }
            break
    if no rule matched: emit { model_recommendation: "deny", matched_rule_id: null }

assert derived verdicts == payload/prior_auth_decisions.json (model_recommendation + matched_rule_id)

for each row in payload/decision_provenance.jsonl:
    expected_hmac = HMAC-SHA256(
        key=payload/attestation_key.hex,
        msg="{provider_id}|{decision_id}|{provider_verdict}|{attestation_timestamp}"
    )
    assert expected_hmac == row.attestation_hmac
```

## Prerequisites

Python 3.11+. No third-party dependencies. Run all commands from the
**v-kernel-audit-bundle root**.

## Step 1 — Build the bundle

```bash
python examples/prior_auth_minimal/_build_bundle.py --out-dir /tmp/prior_auth_bundle
```

Expected output:

```
Bundle written to /tmp/prior_auth_bundle
  prior-auth requests  : 5
  plan rules           : 5
  decisions            : 5
  provenance rows      : 5
  fragment anchors     : N OpaqueFragment (kind_tag=clinical_finding)
  dispatch records     : 3 (COMPUTE + MEDICAL_NECESSITY_EVAL + PROVIDER_ATTEST)
  manifest files       : <N>
  manifest             : /tmp/prior_auth_bundle/manifest.json
```

## Step 2 — Verify

```bash
python examples/prior_auth_minimal/verify.py --bundle-dir /tmp/prior_auth_bundle
```

Must print `PASS` and exit 0. Registers three plugins:

| Plugin | Contract clause |
|---|---|
| `file_integrity_many_small` | §C9 per-file SHA walk |
| `prior_auth_re_derivation` | §C6 decision re-derivation + provider HMAC re-verify |
| `dispatch_record_wellformed` | §C15 op-kind + effect well-formedness |

## Step 3 — Tamper-flow demo

**Tamper A — clinical finding content (decision-tree mismatch):**
Mutate a diagnosis in `clinical/findings.jsonl` so the rule no longer fires,
then re-align the manifest SHA so `file_integrity_many_small` does not mask
the re-derivation failure:

```python
import json, hashlib
from pathlib import Path
p = Path('/tmp/prior_auth_bundle/clinical/findings.jsonl')
lines = p.read_text().splitlines()
row = json.loads(lines[0])
row['diagnoses'] = ['Z99.99']        # bogus code; rule-MRI-spine stops firing
lines[0] = json.dumps(row, sort_keys=True)
p.write_text('\n'.join(lines) + '\n')
# re-align SHA
mp = Path('/tmp/prior_auth_bundle/manifest.json')
m = json.loads(mp.read_text())
m['files']['clinical/findings.jsonl'] = hashlib.sha256(p.read_bytes()).hexdigest()
mp.write_text(json.dumps(m, indent=2, sort_keys=True))
```

Re-run `verify.py` — expect exit 1, reason `PRIOR_AUTH_REDERIVATION_MISMATCH`.

**Tamper B — provider verdict (HMAC mismatch):**
Mutate `provider_verdict` in a provenance row without recomputing its HMAC:

```python
import json
from pathlib import Path
p = Path('/tmp/prior_auth_bundle/payload/decision_provenance.jsonl')
lines = p.read_text().splitlines()
row = json.loads(lines[0])
row['provider_verdict'] = 'deny'     # flip approve → deny; HMAC no longer valid
lines[0] = json.dumps(row, sort_keys=True)
p.write_text('\n'.join(lines) + '\n')
# re-align SHA in manifest too so FileIntegrityManySmall passes
import hashlib
mp = Path('/tmp/prior_auth_bundle/manifest.json')
m = json.loads(mp.read_text())
m['files']['payload/decision_provenance.jsonl'] = hashlib.sha256(p.read_bytes()).hexdigest()
mp.write_text(json.dumps(m, indent=2, sort_keys=True))
```

Re-run `verify.py` — expect exit 1, reason `PRIOR_AUTH_PROVIDER_ATTESTATION_INVALID`.
This demonstrates that the provider's identity is cryptographically bound to their
verdict — a post-hoc verdict flip is detectable even when SHA alignment is correct.

## Fragment anchors

| Anchor key shape | kind_tag | Locator fields |
|---|---|---|
| `<request_id>-diag-<icd10_code>` | `clinical_finding` | `finding_id`, `patient_id`, `finding_type="diagnosis"`, `value` |
| `<request_id>-tx-<tx_code>` | `clinical_finding` | `finding_id`, `patient_id`, `finding_type="prior_treatment"`, `value` |
| `<request_id>-lab-<lab_name>` | `clinical_finding` | `finding_id`, `patient_id`, `finding_type="lab_value"`, `value`, `lab` |

## File layout

```
examples/prior_auth_minimal/
├── _build_bundle.py                    # synthesizes fixtures + builds audit bundle
├── verify.py                           # pilot-local TypedCheck wrapper
├── prior_auth_re_derivation.py         # stdlib re-derivation + HMAC re-verify pack (§C6)
├── PriorAuthReDerivationCheck.py       # TypedCheck plugin (subprocess wrapper)
└── README.md

Bundle output (/tmp/prior_auth_bundle/):
  clinical/
  ├── findings.jsonl                    # 5 prior-auth requests (clinical features)
  └── plan_rules.json                   # 5 medical-necessity rules
  payload/
  ├── prior_auth_decisions.json         # approved/denied outcomes (model output)
  ├── decision_provenance.jsonl         # provider attestation log (the differentiator)
  └── attestation_key.hex               # synthetic HMAC key committed to bundle
  manifest.json                         # SHA-pinned for every file above
```

Tests: `tests/test_prior_auth_minimal.py`
