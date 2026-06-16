# fp_ml_minimal — V-Kernel Pilot: Floating-Point ML Inference (Tolerance-Bounded)

## Purpose

Demonstrates V-Kernel re-derivation for a single-precision floating-point
linear classifier.  The substrate question this pilot forces: **bounded-tolerance
match versus bit-exact match for FP inference**.

The integer-only pilot (`examples/ml_minimal/`) proves bit-exact re-derivation.
This pilot proves the honest middle ground: **tolerance-bounded re-derivation
is a real substrate guarantee**, not a permission slip to accept arbitrary drift.

## Substrate Position

> "Re-derivation accepts declared ε" is the honest middle ground until ONNX-Runtime
> determinism mode integration.

**ONNX Runtime CPU inference is bit-identical; GPU is not.**  This pilot models
the CPU-determinism case: the substrate position is that a float32 linear
classifier re-executed in the same float32 discipline (stdlib struct.pack/unpack
round-trip) is reproducible within ε = 1e-9, and the audit bundle HMAC anchors
that promise.

When ONNX Runtime determinism mode (`OrtSessionOptions.execution_mode`) or
fixed-point quantization is integrated in a future version, `examples/onnx_minimal/`
can replace the tolerance with strict bit-exact equality.  Until then, this pilot
defines the production-honest claim.

## Float32 Discipline

Python's native `float` is IEEE-754 double-precision (64-bit).  To model
single-precision inference without NumPy, this pilot applies:

```python
def _f32(x: float) -> float:
    return struct.unpack('f', struct.pack('f', x))[0]
```

at every **serialization boundary**: weights (stored in `weights/model.json`),
input features (stored in `inputs/features.json`), and final logits (stored in
`payload/predictions.json`).  Arithmetic accumulation is done in Python double;
only the final snapped value is what gets written and later re-derived.  This
gives a fully reproducible and documentable float32 discipline using only stdlib.

## Why Tolerance is REAL (not a Permission Slip)

The tolerance ε = 1e-9 is **tight**.  The tamper tests prove this:

- **Tamper 1 (exceeds ε):** Mutate weight W[0][0] by +1e-3 → logit delta ~0.587,
  which is 5.87×10^8 × ε.  Verification FAILS with FP_ML_REDERIVATION_MISMATCH.
- **Tamper 2 (within ε):** Mutate weight W[0][0] by +1e-12 → logit delta < 1e-9.
  Verification PASSES because the perturbation is below the declared tolerance.

Tamper 2 is not a bug — it demonstrates that ε represents a real quantified
uncertainty bound (e.g., numeric truncation at serialization), not an
excuse for unchecked drift.  Any software that produces results more than ε
away from the committed weights is flagged.

## File Layout

```
fp_ml_minimal/
  _build_bundle.py          Build the bundle (synthesize fixtures, compute logits)
  verify.py                 Register plugins + run BundleVerifier
  fp_ml_re_derivation.py    Stdlib-only re-derivation pack (invoked via subprocess)
  FpMlReDerivationCheck.py  TypedCheck plugin wrapping the subprocess call
  README.md                 This file

tests/
  test_fp_ml_minimal.py     Round-trip + tamper-exceeds-ε + tamper-within-ε tests
```

## Quick Start

```bash
cd veriker

# Build a bundle
python examples/fp_ml_minimal/_build_bundle.py --out-dir /tmp/fp_ml_bundle

# Verify it
python examples/fp_ml_minimal/verify.py --bundle-dir /tmp/fp_ml_bundle
# → PASS

# Run the full test suite (3 tests)
python -m pytest tests/test_fp_ml_minimal.py -v
```

## Tamper Flow Demo

```bash
# Build a fresh bundle
python examples/fp_ml_minimal/_build_bundle.py --out-dir /tmp/fp_ml_tamper

# Mutate W[0][0] in weights/model.json: change 0.5 to 0.501
# (delta ~ 1e-3, far exceeds ε = 1e-9)
# Then re-align the manifest SHA for weights/model.json.
# Run verify:
python examples/fp_ml_minimal/verify.py --bundle-dir /tmp/fp_ml_tamper
# → FAIL: [fp_ml_re_derivation] FP_ML_REDERIVATION_MISMATCH: ...delta=...
```

## Bundle Schema Reference

`weights/model.json`:
```json
{
  "schema": "linear-classifier-fp-v1",
  "n_features": 4,
  "n_classes": 3,
  "precision": "float32",
  "tolerance": 1e-09,
  "library": "cpython-3.10-stdlib-math",
  "W": [[...], [...], [...]],
  "b": [...]
}
```

`payload/predictions.json` (one record per input):
```json
[
  {"input_idx": 0, "logits": [f32, f32, f32], "predicted_class": int},
  ...
]
```
