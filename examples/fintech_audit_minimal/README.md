# fintech_audit_minimal — V-Kernel S0 Pilot: Bank Policy Compliance Audit

## What this demonstrates

A bank's model claims transaction T conforms (or does not conform) to policy P.
The audit-bundle contains the raw transaction record and the policy rule. The
verifier re-runs the rule predicate over the bundled transaction and asserts
the model's verdict is reproducible byte-for-byte from inputs.

Re-derivation primitive: **re-evaluate "policy rule R applies to transaction T →
verdict V" by re-running the rule predicate over the bundled transaction record.**

This is the V-Kernel S0 audit-bundle integrator applied to the financial-compliance
domain, framed for a Brazilian bank's internal transaction-screening controls.

**Regulatory framing** (verified 2026-05-29 — full citations in
`examples/inter_seven_agent_gate_minimal/inter_regulatory_backbone_2026-05-29.md`):
the restricted-jurisdiction rule reflects **Lei nº 13.810/2019**, under which Brazil
enforces **UN Security Council (CSNU) sanctions**; the large-transaction rule is an
illustrative **internal review threshold** (the bank's own number, not a statutory
figure). Amounts are in **BRL** (`amount_brl`).

## Quick start

```bash
# From v-kernel-audit-bundle root:
python examples/fintech_audit_minimal/_build_bundle.py --out-dir /tmp/fintech_bundle
python examples/fintech_audit_minimal/verify.py --bundle-dir /tmp/fintech_bundle
# Expected: PASS
```

## Tamper-flow demo

```bash
# 1. Build a clean bundle
python examples/fintech_audit_minimal/_build_bundle.py --out-dir /tmp/fintech_tamper

# 2. Mutate a transaction's amount to flip a verdict
python -c "
import json, pathlib
p = pathlib.Path('/tmp/fintech_tamper/transactions/txn-001.json')
txn = json.loads(p.read_bytes())
txn['amount_brl'] = 100.0   # was 95000 — drops below the R$50k threshold
p.write_bytes(json.dumps(txn, sort_keys=True, separators=(',',':')).encode())
"

# 3. Re-run verifier — MUST FAIL
python examples/fintech_audit_minimal/verify.py --bundle-dir /tmp/fintech_tamper
# Expected: FAIL with POLICY_REDERIVATION_MISMATCH (verdict flips)
#   OR: FAIL with BAD_FILE_SHA (SHA of txn-001.json no longer matches manifest)
```

## File layout

```
examples/fintech_audit_minimal/
  _build_bundle.py           — synthesize fixtures + emit manifest
  verify.py                  — register plugins, run BundleVerifier, print PASS/FAIL
  policy_re_derivation.py    — stdlib-only re-derivation pack (subprocess target)
  PolicyRuleReDerivationCheck.py  — TypedCheck plugin wrapping the subprocess call
  README.md                  — this file
  tests/
    __init__.py
    test_fintech_audit_minimal.py  — happy-path + tamper tests
```

## Bundle layout (after build)

```
<out-dir>/
  transactions/
    txn-001.json   txn-002.json   txn-003.json
  policies/
    rule-large-tx.json   rule-restricted-jurisdiction.json
  payload/
    policy_verdicts.json
  manifest.json
```

## Synthetic fixtures

**Transactions (3):**
- `txn-001`: R$95,000 equity from US counterparty — matches rule-large-tx (REVIEW_REQUIRED)
- `txn-002`: R$12,500 bond from IR (Iran) counterparty — matches rule-restricted-jurisdiction (BLOCKED)
- `txn-003`: R$500 equity from GB counterparty — no rules match (NOT_APPLICABLE for all)

**Policy rules (2):**
- `rule-large-tx`: `amount_brl > 50000` → `REVIEW_REQUIRED`  (illustrative internal threshold)
- `rule-restricted-jurisdiction`: `counterparty_country in [IR, KP]` → `BLOCKED`  (Lei 13.810/2019 — UN/CSNU sanctions)

**Verdicts (6 total):** 2 matched, 4 NOT_APPLICABLE.

## Plugins registered

| Plugin | Reason codes |
|---|---|
| `FileIntegrityManySmall` | `PASS` / `MISSING_FILE` / `BAD_FILE_SHA` / `EXTRA_FILE_NOT_IN_MANIFEST` |
| `PolicyRuleReDerivationCheck` | `POLICY_REDERIVED` / `POLICY_REDERIVATION_MISMATCH` |
