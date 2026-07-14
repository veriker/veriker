# tabular_minimal — Tabular SQL Aggregate Audit Bundle

Domain pilot: deterministic GROUP BY + SUM aggregate over a committed CSV snapshot
bundled for V-kernel audit verification (the audit-bundle contract §C5, C6, C9).

Demonstrates the domain-agnostic S0 integrator on **tabular SQL aggregation**
— the cloud data-warehouse analytics shape — proving the substrate is not
tied to graph or stochastic operations.

## Prerequisites

Python 3.10+. No third-party dependencies.
Run all commands from the **v-kernel-audit-bundle root**.

## Step 1 — Build the bundle

```bash
python examples/tabular_minimal/_build_bundle.py --out-dir /tmp/tabular_bundle
```

Expected output:

```
Bundle written to /tmp/tabular_bundle
  sales rows       : 50
  result groups    : 4
  manifest files   : 2
  manifest         : /tmp/tabular_bundle/manifest.json
```

## Step 2 — Verify

```bash
python examples/tabular_minimal/verify.py --bundle-dir /tmp/tabular_bundle
```

Expected stdout: `PASS`. Exit code 0.

Two TypedCheck plugins run in order:

| Plugin                      | Contract clause                              |
|-----------------------------|----------------------------------------------|
| `file_integrity_many_small` | §C9 per-file SHA walk                        |
| `tabular_re_derivation`     | §C6 GROUP BY aggregate re-derivation         |

## Step 3 — Tamper-flow demo

Mutate one row's `revenue` value in `data/sales.csv`, then re-align the manifest SHA:

```bash
python -c "
import hashlib, json, pathlib
p = pathlib.Path('/tmp/tabular_bundle/data/sales.csv')
content = p.read_bytes()
# Corrupt: change first '100' occurrence in the data rows
corrupted = content.replace(b'1,100,', b'1,999,', 1)
p.write_bytes(corrupted)
# Re-align SHA in manifest so FileIntegrity passes but re-derivation fails
m = pathlib.Path('/tmp/tabular_bundle/manifest.json')
manifest = json.loads(m.read_text())
manifest['files']['data/sales.csv'] = hashlib.sha256(corrupted).hexdigest()
m.write_text(json.dumps(manifest, indent=2))
"
python examples/tabular_minimal/verify.py --bundle-dir /tmp/tabular_bundle
```

Expected exit code: `1`. The `tabular_re_derivation` plugin will report
`TABULAR_REDERIVATION_MISMATCH` because the re-derived aggregate no longer matches
the committed `payload/result.csv`.

## File layout

```
examples/tabular_minimal/
├── _build_bundle.py              # builds sales.csv + result.csv + manifest
├── verify.py                     # runs FileIntegrityManySmall + TabularReDerivationCheck
├── TabularReDerivationCheck.py   # domain plugin (C6 tabular re-derivation)
├── tabular_re_derivation.py      # re-derivation implementation (stdlib only)
├── README.md                     # this file
├── data/
│   └── sales.csv                 # (generated) 50-row deterministic sales snapshot
├── spec/
│   └── query.json                # GROUP BY query DSL (tabular-query-v1)
└── payload/
    └── result.csv                # (generated) aggregated result rows
```

## Query DSL

`spec/query.json` uses a minimal `tabular-query-v1` schema:

```json
{
  "schema": "tabular-query-v1",
  "table": "data/sales.csv",
  "select": [
    {"kind": "column", "name": "region"},
    {"kind": "agg", "func": "sum", "column": "units", "alias": "total_units"},
    {"kind": "agg", "func": "sum", "column": "revenue", "alias": "total_revenue"}
  ],
  "group_by": ["region"],
  "order_by": ["region"]
}
```

Supported `kind` values: `column`, `agg`. Supported `func` values: `sum`, `count`.
`order_by` sorts result rows alphabetically ascending on the named columns.
