# lifesci_binding_minimal — Drug-Binding Affinity Audit Bundle

Minimal domain pilot: a drug-discovery binding-affinity predictor bundled for
V-Kernel audit verification (the audit-bundle contract §C5, C6, C9).

## The regulatory traceability story

Drug-discovery submissions increasingly require **end-to-end computational
traceability**: the regulator must be able to reproduce a model's prediction
from the exact inputs the model saw, using only the committed artifacts —
no proprietary runtime, no black-box re-execution.

The V-Kernel audit bundle is exactly that receipt:

> A drug-discovery model predicts binding-affinity score for compound C
> against target T. The bundle contains the compound descriptor + target
> descriptor + scoring weights. A verifier re-runs the deterministic scoring
> function over the bundled inputs and asserts the predicted affinity matches
> byte-for-byte — exactly the traceability that regulatory submissions need.

This pilot demonstrates the substrate claim on a synthetic (but structurally
realistic) feature-hash linear scorer. Production integrators replace the
scorer with an ONNX-Runtime or PyTorch determinism-mode forward pass; the
bundle shape and verification protocol are identical.

## Re-derivation primitive

Re-compute `compound_features` and `target_features` via stable
character-bucket hashing (zlib.crc32, not Python's randomized `hash()`):

```
for each character c in smiles_string:
    bucket = crc32(c) % 32
    compound_features[bucket] += 1

affinity_pred = dot(compound_features, w_compound)
              + dot(target_features, w_target)
              + bias
```

All arithmetic is integer + float (no numpy/scipy). The verifier re-runs this
function from committed inputs and asserts the result matches `affinity_pred`
in `payload/binding_prediction.json` to 6 decimal places.

## Prerequisites

Python 3.11+. No third-party dependencies.
Run all commands from the **v-kernel-audit-bundle root**.

## Step 1 — Build the bundle

```bash
python examples/lifesci_binding_minimal/_build_bundle.py --out-dir /tmp/lifesci_binding_bundle
```

Expected output:

```
Bundle written to /tmp/lifesci_binding_bundle
  compound         : NEXI-C001 ('c1ccccc1-N(CC)CC=O')
  target           : NEXI-T001 ('MKTAYIAKQRQISFV')
  affinity_pred    : <float>
  confidence_band  : [<lower>, <upper>]
  weights_sha256   : <hex prefix>...
  fragment anchors : 2 OpaqueFragment
  manifest files   : 4
  manifest         : /tmp/lifesci_binding_bundle/manifest.json
```

## Step 2 — Verify

```bash
python examples/lifesci_binding_minimal/verify.py --bundle-dir /tmp/lifesci_binding_bundle
```

Expected stdout: `PASS`. Exit code 0.

Two TypedCheck plugins run in order:

| Plugin                              | Contract clause                                        |
|-------------------------------------|--------------------------------------------------------|
| `file_integrity_many_small`         | §C9 per-file SHA walk with named reason codes          |
| `binding_affinity_re_derivation`    | §C6 feature-hash weighted-sum re-derivation, exact match |

## Step 3 — Tamper-flow demo

Mutate the SMILES string in `compound_descriptor.json` — this changes the
feature buckets, shifts the predicted affinity, and the re-derivation detects
the divergence (file-integrity catches the SHA change first if manifest is not
re-aligned):

```python
import json, pathlib
p = pathlib.Path('/tmp/lifesci_binding_bundle/inputs/compound_descriptor.json')
d = json.loads(p.read_text())
d['smiles_string'] += 'X'    # appends one character, shifts bucket counts
p.write_text(json.dumps(d, indent=2, sort_keys=True) + '\n')
```

Re-run the verifier:

```bash
python examples/lifesci_binding_minimal/verify.py --bundle-dir /tmp/lifesci_binding_bundle
```

Expected exit code: `1`. Stderr includes `BAD_FILE_SHA` (SHA mismatch caught
first) or `BINDING_REDERIVATION_MISMATCH` (if manifest SHA was re-aligned to
tampered input).

## Fragment anchors

The bundle uses `OpaqueFragment` (the V-Kernel open-extension fragment type)
for sub-document addressing:

| Anchor key           | kind_tag                     | Locator fields                            |
|----------------------|------------------------------|-------------------------------------------|
| `compound-descriptor`| `molecule_descriptor`        | `compound_id`, `descriptor_type="smiles"` |
| `target-descriptor`  | `protein_target_descriptor`  | `target_id`, `descriptor_type="amino_acid_sequence"` |

Substrate validates shape only; semantic validation (descriptor format,
SMILES validity) is the responsibility of the `BindingAffinityReDerivationCheck`
plugin.

## File layout

```
examples/lifesci_binding_minimal/
├── _build_bundle.py                      # synthesizes fixtures + builds audit bundle
├── verify.py                             # runs both TypedCheck plugins
├── BindingAffinityReDerivationCheck.py   # TypedCheck plugin (subprocess wrapper)
├── binding_affinity_re_derivation.py     # re-derivation implementation (stdlib only)
├── README.md
└── tests/
    ├── __init__.py
    └── test_lifesci_binding_minimal.py   # happy-path + tamper tests
```
