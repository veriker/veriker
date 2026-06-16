# credit_scoring_minimal

Bank consumer-credit decisioning (loan-approval scorecard) pilot for the
V-Kernel S0 audit-bundle integrator, anchored to the **Brazilian** regulatory
surface a digital lender like Banco Inter faces.

**Regulatory anchors** (verified 2026-05-29 — full citations in
`examples/inter_seven_agent_gate_minimal/inter_regulatory_backbone_2026-05-29.md`):

- **LGPD (Lei 13.709/2018) art. 20 — IN FORCE.** A data subject may request review
  of a decision taken *solely* on automated processing that affects their interests
  (expressly including credit profile), and the controller must provide **"clear and
  adequate information on the criteria and procedures"** used (subject to trade-secret
  limits); the ANPD may audit for discriminatory effects.
- **PL 2338/2023 (Marco Legal da IA) — BILL, not enacted** (approved by the Senate
  2024-12-10; under review in the Câmara dos Deputados since 2025-03-17). Classifies
  **credit evaluation / granting as "high-risk"**, triggering algorithmic-impact-
  assessment duties.

This pilot models a **traditional ML scorecard** (logistic-regression-style
coefficient table over a Serasa-style 0–1000 credit score) — a deterministic
decision whose criteria art. 20 requires the lender be able to explain.

## Regulatory Mapping

| Obligation | What this pilot demonstrates |
|---|---|
| LGPD art. 20 — explain the criteria & procedures of an automated credit decision | `credit_scoring_re_derivation.py` replays applicant attributes through the bundled scorecard coefficients, recomputes PD scores and approve/decline + rate-tier verdicts, asserts exact match against the bundled payload — the explanation *is* the re-derivation |
| Auditable model record | `bundle_id`, `created_at`, `model/scorecard.json`, `model/threshold_table.json` constitute the model documentation |
| PL 2338 (pending) — high-risk algorithmic-impact artifact | `source_attributes` on the bureau-snapshot CID carries `publication_class="regulatory"` and `external_status_flags=["lgpd_art20_automated_credit_decision"]`, demonstrating V-Kernel's runtime emission of credit-bureau-data lineage |

## Re-derivation Primitive

Replay each applicant's credit attributes through the bundled scorecard
coefficients (stored in `model/scorecard.json`), recompute the
probability-of-default (PD) via the logistic function
`PD = 1 / (1 + exp(-Σ wᵢxᵢ))`, look up the approve/decline + rate-tier
verdict in `model/threshold_table.json`, and assert the result matches
`payload/credit_decisions.json`.

## V-Kernel Extension Points Exercised

- `OpaqueFragment(kind_tag="credit_attribute")` — one anchor per
  (applicant, bureau attribute) pair; `source_cid` points to the
  bureau-snapshot CID registered in `snapshots`.
- `source_attributes[bureau_cid]` — `publication_class="regulatory"` tags
  the credit-bureau data pull as bureau-sourced (Serasa / Boa Vista / SPC style).
- `DispatchRecordWellformedCheck(op_kinds_admitted=frozenset({"SCORECARD_EVAL", "COMPUTE"}))`
  — admits the new `SCORECARD_EVAL` op kind (one record per applicant) and
  `COMPUTE` (the threshold-lookup pass).

## Synthetic Fixtures

Five applicants spanning the full tier range (Serasa Score is a 0–1000 scale,
higher = lower risk; rate tiers shown in `apr_pct`, % a.a.):

| ID | Serasa Score | Utilization | Tradelines | DTI | Negativações | Expected Tier |
|---|---|---|---|---|---|---|
| APP-001 | 780 | 8% | 15 | 22% | 0 | A (approve) |
| APP-002 | 660 | 45% | 8 | 35% | 1 | B (approve) |
| APP-003 | 610 | 70% | 5 | 48% | 1 | C (approve) |
| APP-004 | 580 | 95% | 3 | 58% | 3 | D (decline) |
| APP-005 | 755 | 15% | 12 | 28% | 0 | A (approve) |

Loan amounts are in **BRL** (`loan_amount_brl`). The scorecard math is unchanged
from the generic scorecard; only the score field and currency are localized.

## Quick Start

```bash
# From v-kernel-audit-bundle root:

# Gate 1 — build
python examples/credit_scoring_minimal/_build_bundle.py --out-dir /tmp/credit_scoring_bundle

# Gate 2 — verify
python examples/credit_scoring_minimal/verify.py --bundle-dir /tmp/credit_scoring_bundle
# stdout: PASS

# Gate 3 — pilot tests
python -m pytest tests/test_credit_scoring_minimal.py -v

# Gate 4 — regression
python -m pytest tests/test_fragments.py tests/test_dispatch_record_wellformed.py -q
```

## Tamper Demo

To observe the verifier catching a manipulated Serasa Score:

```bash
# Build clean bundle
python examples/credit_scoring_minimal/_build_bundle.py --out-dir /tmp/credit_scoring_tamper

# Drop APP-001's score from 780 to 400 (changes tier A → D)
python -c "
import json, hashlib
from pathlib import Path
d = Path('/tmp/credit_scoring_tamper')
app = json.loads((d/'applicants/APP-001.json').read_text())
app['serasa_score'] = 400
(d/'applicants/APP-001.json').write_text(json.dumps(app, indent=2, sort_keys=True))
sha = hashlib.sha256((d/'applicants/APP-001.json').read_bytes()).hexdigest()
m = json.loads((d/'manifest.json').read_text())
m['files']['applicants/APP-001.json'] = sha
(d/'manifest.json').write_text(json.dumps(m, indent=2, sort_keys=True))
"

python examples/credit_scoring_minimal/verify.py --bundle-dir /tmp/credit_scoring_tamper
# stdout/stderr: FAIL ... CREDIT_SCORING_REDERIVATION_MISMATCH
```

## File Layout

```
examples/credit_scoring_minimal/
  _build_bundle.py                 Build script — synthesizes fixtures, writes bundle
  verify.py                        Verifier — registers plugins, runs BundleVerifier
  credit_scoring_re_derivation.py  Stdlib-only re-derivation pack (subprocess CLI)
  CreditScoringReDerivationCheck.py TypedCheck plugin wrapping the subprocess call
  README.md                        This file
tests/
  test_credit_scoring_minimal.py   Happy-path + tamper integration tests
```

## Scope honesty

Synthetic fixtures; no real Serasa/Boa Vista/SPC pull and no real lender model.
The scorecard coefficients are illustrative. PL 2338/2023 is a **pending bill**,
not enacted law — do not present it as current regulation. V-Kernel makes the
credit decision **re-derivable and explainable**; it does not validate that the
scorecard itself is fair or correct (that is the lender's model-governance duty).
```
