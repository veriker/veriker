# aml_txn_monitoring_minimal

V-Kernel audit-bundle pilot: **PLD-FT transaction monitoring (COAF-report rule-tree)**,
anchored to the Brazilian anti-money-laundering surface a bank like Banco Inter faces.

Demonstrates the S0 integrator on a synthetic transaction stream — the shape of
the internal monitoring layer a Brazilian institution operates to meet its
PLD-FT (prevenção à lavagem de dinheiro e financiamento ao terrorismo) duties.

---

## Regulatory mapping

(Verified 2026-05-29 — full citations in
`examples/inter_seven_agent_gate_minimal/inter_regulatory_backbone_2026-05-29.md`.)

**Circular BACEN nº 3.978/2020 — IN FORCE** (underpinned by **Lei nº 9.613/1998**
on money laundering and **Lei nº 13.260/2016** on terrorism financing). Institutions
authorized by the Banco Central must implement risk-based PLD-FT policies, procedures
and internal controls, and **communicate suspicious operations to COAF** (the
Conselho de Controle de Atividades Financeiras) via SISCOAF by the next business day.

- **Internal monitoring** — this pilot demonstrates the re-derivation primitive an
  independent validator (or the BACEN supervisor) would run to confirm the bank's
  COAF-report decisions are reproducible from the bundled feature inputs. The rule
  tree is the bank's **own internal detection logic** — its thresholds are the bank's
  choice, not a statutory number.
- **"COAF report"** is the Brazilian analogue of a suspicious-activity report: the
  flag means "this customer's activity should be communicated to COAF."

**Threshold note (honest framing):** the fixture's structuring rule fires on cash
deposits clustering **just below a ~R$10,000 internal detection threshold**. That is
*illustrative of a bank's internal rule* — it is **not** the statutory figure. Brazil's
statutory cash-operation reporting threshold (Circular 3.978) is **R$50,000**; banks
deliberately monitor *below* the statutory line because structuring is the practice of
staying under reportable thresholds.

---

## Re-derivation primitive

Re-aggregate per-customer transaction features from the bundled raw transaction
stream, then re-evaluate the bundled rule-tree JSON to recompute the COAF-report
flag per customer — assert the bundle's payload matches.

Three features per customer:

| Feature | Definition |
|---|---|
| `velocity_24h_gt_10k` | Max count of transactions > R$10,000 in any 24-hour sliding window |
| `structuring_proxy_7d` | Max count of cash deposits in [R$9,000, R$10,000) in any 7-day window |
| `peer_z_score` | (customer mean txn size − peer mean) / peer stddev |

Rule-tree trigger: `ANY(velocity > 3, structuring_proxy > 2, |peer_z| > 3.0)`.

---

## Synthetic fixture customers

| Customer | COAF report? | Trigger rule | Notes |
|---|---|---|---|
| C001 | YES | R1 velocity | 4 wires > R$10K in a single day |
| C002 | YES | R2 structuring | 3 cash deposits R$9,000–R$9,999 in 7 days |
| C003 | YES | R3 peer deviation | Mean txn ≈ R$6,500 vs peer mean R$2,500 (z ≈ 5) |
| C004 | NO | — | Normal retail activity — false-positive-rate demo |
| C005 | NO | — | 2 near-threshold deposits (structuring_proxy = 2, threshold > 2) |

All amounts are in **BRL** (`amount_brl`); the per-customer flag field is
`coaf_report_triggered` in `payload/coaf_reports.json`.

---

## File layout

```
examples/aml_txn_monitoring_minimal/
  _build_bundle.py                         Build synthetic bundle → /tmp/aml_txn_monitoring_bundle
  verify.py                                Standalone verifier (§C5 auditor independence)
  aml_txn_monitoring_re_derivation.py      Stdlib-only re-derivation pack (subprocess CLI)
  AmlTxnMonitoringReDerivationCheck.py     TypedCheck plugin wrapping the pack
  README.md                                This file
tests/
  test_aml_txn_monitoring_minimal.py       Happy-path + tamper tests
```

---

## Quick start

```bash
# From v-kernel-audit-bundle root:

# Build
python examples/aml_txn_monitoring_minimal/_build_bundle.py \
    --out-dir /tmp/aml_txn_monitoring_bundle

# Verify
python examples/aml_txn_monitoring_minimal/verify.py \
    --bundle-dir /tmp/aml_txn_monitoring_bundle
# → PASS

# Run tests
python -m pytest tests/test_aml_txn_monitoring_minimal.py -v
```

---

## Tamper-flow demo

Mutate the COAF-report payload so a previously-clean customer is flagged:

```python
import json
from pathlib import Path

bundle = Path("/tmp/aml_txn_monitoring_bundle")
payload = json.loads((bundle / "payload" / "coaf_reports.json").read_text())
payload["customers"]["C004"]["coaf_report_triggered"] = True
(bundle / "payload" / "coaf_reports.json").write_text(json.dumps(payload))
```

Then re-run the verifier — it FAILs with `FILE_SHA_MISMATCH` (caught by
`FileIntegrityManySmall`) because the payload SHA changed without rebuilding
the manifest.

Alternatively, mutate a transaction amount in `transactions.jsonl` (leaving the
manifest SHA unchanged) — the verifier FAILs with
`AML_TXN_MONITORING_REDERIVATION_MISMATCH` because the re-derived features no
longer match the bundled payload.

---

## V-Kernel extension surfaces exercised

- `OpaqueFragment(kind_tag="transaction")` — one fragment anchor per raw transaction record
- `DispatchRecordWellformedCheck(op_kinds_admitted=frozenset({"RULE_TREE_EVAL", "COMPUTE"}))`
  — two op kinds per customer (feature aggregation + rule-tree evaluation)

## Scope honesty

Synthetic data; thresholds illustrative. V-Kernel makes the bank's rule-based
monitoring decision **re-derivable** (the deterministic flag is reproducible from
inputs); where a production system adds an **ML risk score**, that score is
*attested* (signed evidence), not re-derived — V-Kernel does not make the
suspicious-or-not *judgment*, and it is not the COAF/SISCOAF filing system.
```
