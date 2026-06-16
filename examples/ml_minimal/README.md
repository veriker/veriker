# ml_minimal — Audit Bundle Quick-Start

Minimal domain pilot: deterministic ML inference bundled for V-kernel audit
verification (the audit-bundle contract §C5, C6, C9).

**Re-derivation primitive**: re-execute an integer-only linear classifier
(`logits = W @ x + b`, predicted class = argmax of logits) using committed
weights and committed inputs, and assert the bundled prediction list matches
exactly.

**Why integer arithmetic**: float arithmetic raises IEEE-754 platform-determinism
concerns that are irrelevant to the substrate claim. Integer-only inference
gives a clean "committed weights + committed input + deterministic compute
→ bit-identical output" proof. Floating-point inference is roadmapped (would
require ONNX-Runtime determinism mode or fixed-point quantization).

## Prerequisites

Python 3.10+. No third-party dependencies.
Run all commands from the **v-kernel-audit-bundle root**.

## Step 1 — Build the bundle

```bash
python examples/ml_minimal/_build_bundle.py --out-dir /tmp/ml_bundle
```

Expected output:

```
Bundle written to /tmp/ml_bundle
  inputs           : 8 feature vectors of dim 4
  n_classes        : 3
  predictions      : [2, 2, 2, 2, 2, 2, 1, 0]
  manifest files   : 3
  manifest         : /tmp/ml_bundle/manifest.json
```

## Step 2 — Verify

```bash
python examples/ml_minimal/verify.py --bundle-dir /tmp/ml_bundle
```

Expected stdout: `PASS`. Exit code 0.

Two TypedCheck plugins run in order:

| Plugin                      | Contract clause                                        |
|-----------------------------|--------------------------------------------------------|
| `file_integrity_many_small` | §C9 per-file SHA walk                                  |
| `ml_re_derivation`          | §C6 integer-linear-classifier re-inference, exact match |

## Step 3 — Tamper-flow demo

Mutate `W[0][0]` in `weights/model.json` from `3` to `2` — a one-element
change that causes the predicted class for input index 6 to flip from `1` to
`2` (the re-derivation detects this; `file_integrity` catches the SHA change
first if the manifest SHA is not re-aligned):

```python
import json, pathlib
p = pathlib.Path('/tmp/ml_bundle/weights/model.json')
m = json.loads(p.read_text())
m['W'][0][0] = 2          # was 3; flips pred at input_idx=6
p.write_text(json.dumps(m, indent=2) + '\n')
```

Re-run the verifier:

```bash
python examples/ml_minimal/verify.py --bundle-dir /tmp/ml_bundle
```

Expected exit code: `1`. Expected stderr includes `BAD_FILE_SHA` (file
integrity catches the manifest SHA mismatch first) or `ML_REDERIVATION_MISMATCH`
(if the manifest SHA was re-aligned to the tampered file).

## File layout

```
examples/ml_minimal/
├── _build_bundle.py          # synthesizes fixtures + builds deployable bundle
├── verify.py                 # runs both TypedCheck plugins
├── MlReDerivationCheck.py    # domain plugin (ML inference re-derivation)
├── ml_re_derivation.py       # re-derivation implementation (stdlib only)
└── README.md
```
