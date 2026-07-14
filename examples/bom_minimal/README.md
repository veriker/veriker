# bom_minimal — Supply-Chain BOM Audit Bundle

Domain pilot: deterministic package dependency resolution bundled for V-kernel
audit verification (the audit-bundle contract §C5, C6, C9).

Demonstrates the domain-agnostic S0 integrator on **supply-chain BOM resolution**
— re-derivation where the underlying computation is deterministic graph resolution
from a lockfile, proving the substrate is not tied to numerical or stochastic ops.

## Prerequisites

Python 3.10+.  No third-party dependencies.
Run all commands from the **v-kernel-audit-bundle root**.

## Step 1 — Build the bundle

```bash
python examples/bom_minimal/_build_bundle.py --out-dir /tmp/bom_bundle
```

Expected output:

```
Bundle written to /tmp/bom_bundle
  packages         : 10
  resolved nodes   : 10
  manifest files   : 2
  manifest         : /tmp/bom_bundle/manifest.json
```

## Step 2 — Verify

```bash
python examples/bom_minimal/verify.py --bundle-dir /tmp/bom_bundle
```

Expected stdout: `PASS`.  Exit code 0.

Two TypedCheck plugins run in order:

| Plugin                    | Contract clause                         |
|---------------------------|-----------------------------------------|
| `file_integrity_many_small` | §C9 per-file SHA walk                 |
| `bom_re_derivation`       | §C6 BOM dependency re-derivation        |

## Step 3 — Tamper-flow demo

Mutate one package's hash in the lockfile:

```bash
# Linux / macOS — overwrite lodash entry's hash field
python -c "
import json, pathlib
p = pathlib.Path('/tmp/bom_bundle/lockfile/lockfile.json')
d = json.loads(p.read_text())
d['packages']['lodash@4.17.21']['hash'] = 'sha256:deadbeef'
p.write_text(json.dumps(d, indent=2))
"

# Windows PowerShell equivalent
python -c "import json,pathlib; p=pathlib.Path(r'C:\tmp\bom_bundle\lockfile\lockfile.json'); d=json.loads(p.read_text()); d['packages']['lodash@4.17.21']['hash']='sha256:deadbeef'; p.write_text(json.dumps(d,indent=2))"
```

Re-run the verifier:

```bash
python examples/bom_minimal/verify.py --bundle-dir /tmp/bom_bundle
```

Expected exit code: `1`.  The `bom_re_derivation` plugin will report
`BOM_REDERIVATION_MISMATCH` because the lockfile hash no longer matches the
recorded node hash in `resolved_tree.json`.

## File layout

```
examples/bom_minimal/
├── _build_bundle.py         # builds lockfile + resolved tree + manifest
├── verify.py                # runs FileIntegrityManySmall + BomReDerivationCheck
├── BomReDerivationCheck.py  # domain plugin (C6 BOM re-derivation)
├── bom_re_derivation.py     # re-derivation implementation (stdlib only)
├── README.md                # this file
├── lockfile/
│   └── lockfile.json        # (generated) 10-package deterministic DAG lockfile
└── payload/
    └── resolved_tree.json   # (generated) BFS-resolved dependency tree
```
