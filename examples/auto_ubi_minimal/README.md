# auto_ubi_minimal — Usage-Based Auto Insurance (UBI) Telematics Rating Audit Bundle Pilot

Domain pilot: telematics feature aggregation and rate-table rating for usage-based
auto insurance (UBI), bundled for V-kernel audit verification
(the audit-bundle contract §C5, C6, C9, C15).

Regulator scope:
- **NAIC AI Systems Evaluation Tool** (Underwriting / telematics-UBI and Pricing categories)
- **Colorado Reg 10-1-1 § 5.A.11** quantitative-testing requirements for private passenger
  auto, effective 2025-10-15

Re-derivation primitive: re-aggregate telematics features (mileage, hard-brake count,
harsh-acceleration count, late-night driving fraction) from bundled raw trip records
via stdlib-only computation, re-evaluate the bundled rate-table JSON to recompute
the rating tier and discount — assert the bundle payload matches.

Extension surfaces exercised:
- `OpaqueFragment(source_cid, kind_tag="telematics_trip", locator={...})` — one fragment
  anchor per raw trip record bundled in `telematics/trips.jsonl`.
- `DispatchRecordWellformedCheck(op_kinds_admitted=frozenset({"RATE_TABLE_LOOKUP", "COMPUTE"}))` —
  admits the two domain-specific op kinds introduced by this pilot.

## Prerequisites

Python 3.10+. No third-party dependencies.
Run all commands from the **v-kernel-audit-bundle root**.

## Build the bundle

```bash
python examples/auto_ubi_minimal/_build_bundle.py --out-dir /tmp/auto_ubi_bundle
```

Expected output (abbreviated):

```
Bundle written to /tmp/auto_ubi_bundle
  policyholders    : 5
  trip records     : 69
  manifest files   : 3
  fragment anchors : 69 OpaqueFragment (kind_tag=telematics_trip)
  dispatch records : 10 (5 × COMPUTE + RATE_TABLE_LOOKUP)
  rating tiers     : ['high_risk_surcharge', 'low_mileage_discount', 'standard']
  manifest         : /tmp/auto_ubi_bundle/manifest.json
```

## Verify the bundle

```bash
python examples/auto_ubi_minimal/verify.py --bundle-dir /tmp/auto_ubi_bundle
```

Expected stdout: `PASS`. Exit code 0.

Three TypedCheck plugins run in order:

| Plugin                        | Contract clause                                           |
|-------------------------------|-----------------------------------------------------------|
| `file_integrity_many_small`   | §C9 per-file SHA walk                                     |
| `auto_ubi_re_derivation`      | §C6 UBI telematics re-derivation (feature + tier match)   |
| `dispatch_record_wellformed`  | §C15 op-kind + effect well-formedness                     |

## Tamper-flow demo

Mutate a trip record's hard-brake count so its SHA changes — the verifier
catches it via `FileIntegrityManySmall` (§C9 SHA walk):

```bash
python -c "
import json, pathlib
p = pathlib.Path('/tmp/auto_ubi_bundle/telematics/trips.jsonl')
lines = p.read_text().splitlines()
t = json.loads(lines[0])
t['hard_brakes'] = 999
lines[0] = json.dumps(t, sort_keys=True)
p.write_text('\n'.join(lines) + '\n')
"
python examples/auto_ubi_minimal/verify.py --bundle-dir /tmp/auto_ubi_bundle
```

Expected exit code: `1`. Expected stderr contains `bad_file_sha` (from
`FileIntegrityManySmall`) since the trips JSONL SHA no longer matches
`manifest.files`.

## File layout

```
examples/auto_ubi_minimal/
├── _build_bundle.py              # builds the deterministic bundle
├── verify.py                     # runs all three TypedCheck plugins
├── AutoUBIReDerivationCheck.py   # domain plugin (C6 UBI re-derivation)
├── auto_ubi_re_derivation.py     # re-derivation implementation (stdlib only)
└── README.md
tests/
└── test_auto_ubi_minimal.py      # happy-path + tamper test
```

Bundle layout (written to `--out-dir`):

```
<out-dir>/
├── telematics/
│   └── trips.jsonl               # synthetic raw trip records (5 policyholders)
├── payload/
│   ├── rate_table.json           # tier thresholds + discount/surcharge schedule
│   └── rating_decisions.json     # per-policyholder rating decision
└── manifest.json
```
