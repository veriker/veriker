# dp_minimal — Audit Bundle Quick-Start

Minimal domain pilot: differential-privacy release bundled for V-kernel audit
verification (the audit-bundle contract §C5, C6, C9).

Demonstrates stochastic-but-seed-pinned re-derivation — the output is a noisy
aggregate, but the noise draw is deterministic given the committed seed and
mechanism parameters.

## Prerequisites

Python 3.10+.  No third-party dependencies.
Run all commands from the **v-kernel-audit-bundle root**.

## Step 1 — Build the bundle

```bash
python examples/dp_minimal/_build_bundle.py --out-dir /tmp/dp_bundle
```

Expected output:

```
Bundle written to /tmp/dp_bundle
  dataset rows     : 100
  true_count       : 6
  noised_count     : 6.404251
  manifest files   : 2
  manifest         : /tmp/dp_bundle/manifest.json
```

## Step 2 — Verify

```bash
python examples/dp_minimal/verify.py --bundle-dir /tmp/dp_bundle
```

Expected stdout: `PASS`.  Exit code 0.

Two TypedCheck plugins run in order:

| Plugin                      | Contract clause                             |
|-----------------------------|---------------------------------------------|
| `file_integrity_many_small` | §C9 per-file SHA walk                       |
| `dp_re_derivation`          | §C6 DP-release re-derivation (seed-pinned)  |

## Step 3 — Tamper-flow demo

Mutate one row in `data/dataset.jsonl` so the `true_count` changes:

```bash
# Linux / macOS
python -c "
import json, pathlib
p = pathlib.Path('/tmp/dp_bundle/data/dataset.jsonl')
lines = p.read_text().splitlines()
# Flip the first row's age_bucket so the predicate count changes
row = json.loads(lines[0])
row['age_bucket'] = '18-29'
lines[0] = json.dumps(row)
p.write_text('\n'.join(lines) + '\n')
"
```

Re-run the verifier:

```bash
python examples/dp_minimal/verify.py --bundle-dir /tmp/dp_bundle
```

Expected exit code: `1`. Expected stderr includes `DP_REDERIVATION_MISMATCH` or
`BAD_FILE_SHA` (file_integrity catches the hash change first).

## File layout

```
examples/dp_minimal/
├── _build_bundle.py          # builds a deployable bundle
├── verify.py                 # runs both TypedCheck plugins
├── DpReDerivationCheck.py    # domain plugin (DP release re-derivation)
├── dp_re_derivation.py       # re-derivation implementation (stdlib only)
└── README.md
```
