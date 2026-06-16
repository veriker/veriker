"""_build_bundle.py — build a deterministic fp_ml_minimal audit bundle.

Generates 8 synthetic input feature vectors and runs a single-precision
floating-point linear classifier (logits = W @ x + b, predicted_class =
argmax) using committed FP weights, emitting the predictions as a
standards-compliant payload.

Re-derivation primitive (one sentence): re-execute a float32 linear
classifier using committed weights and committed inputs via pure Python
double arithmetic with struct.pack/unpack float32 round-trip at
serialization boundaries, and assert all bundled logits are within the
declared tolerance ε.

Float32 discipline:
  Python's native float is IEEE-754 double (64-bit).  To model single-
  precision (float32) inference without NumPy, we apply
      f32(x) = struct.unpack('f', struct.pack('f', x))[0]
  at every serialization boundary (weights, inputs, and final logits).
  Arithmetic accumulation is done in double; only the serialised values
  are snapped to float32.  This matches "Python-double accumulation with
  float32 snapped values" — a well-defined and reproducible discipline.

Usage (from v-kernel-audit-bundle root):
    python examples/fp_ml_minimal/_build_bundle.py --out-dir /tmp/fp_ml_bundle

Outputs:
  <out-dir>/inputs/features.json        (8 feature vectors, 4 float32 each)
  <out-dir>/weights/model.json          (linear-classifier-fp-v1 schema)
  <out-dir>/payload/predictions.json    (predicted class + float32 logits per input)
  <out-dir>/manifest.json

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.emitter import BundleContent, write_bundle  # noqa: E402

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "fp-ml-minimal-rc"
_CREATED_AT = "2026-05-09T00:00:00Z"
_TYPED_CHECKS = ["file_integrity_many_small", "fp_ml_re_derivation"]

_N_INPUTS = 8
_N_FEATURES = 4
_TOLERANCE = 1.0e-9

# Committed model weights — linear-classifier-fp-v1 schema.
# W shape: [n_classes][n_features].  Small non-integer floats so that
# argmax decisions are unambiguous (gap > 10*ε for all 8 inputs).
# b: [n_classes].
#
# Determinism note — weights are specified in Python source as float literals;
# they are snapped to float32 before writing to the bundle so the on-disk
# representation matches what the re-derivation pack reads.
_MODEL_RAW = {
    "schema": "linear-classifier-fp-v1",
    "n_features": _N_FEATURES,
    "n_classes": 3,
    "precision": "float32",
    "tolerance": _TOLERANCE,
    "library": "cpython-3.10-stdlib-math",
    # W[class][feature]
    "W": [
        [0.5, -0.3, 0.8, 0.2],
        [-0.4, 0.7, -0.2, 0.6],
        [0.1, 0.2, -0.5, -0.3],
    ],
    "b": [0.1, -0.1, 0.05],
}


# ---------------------------------------------------------------------------
# Float32 helpers — struct.pack round-trip
# ---------------------------------------------------------------------------


def _f32(x: float) -> float:
    """Snap a Python float to float32 precision via struct pack/unpack."""
    return struct.unpack("f", struct.pack("f", x))[0]


def _snap_matrix(m: list[list[float]]) -> list[list[float]]:
    return [[_f32(v) for v in row] for row in m]


def _snap_vec(v: list[float]) -> list[float]:
    return [_f32(x) for x in v]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _generate_features(n_inputs: int, n_features: int) -> list[list[float]]:
    """Deterministic synthetic float32 feature vectors — do not change the formula."""
    return [
        [_f32(((i * 13 + j * 7) % 200 - 100) / 17.0) for j in range(n_features)]
        for i in range(n_inputs)
    ]


def _compute_logits(
    W: list[list[float]], b: list[float], x: list[float]
) -> list[float]:
    """Accumulate in double; snap result to float32 at serialization boundary.

    logit[k] = f32( sum(W[k][j]*x[j]) + b[k] )
    """
    n_classes = len(W)
    n_features = len(x)
    return [
        _f32(sum(W[k][j] * x[j] for j in range(n_features)) + b[k])
        for k in range(n_classes)
    ]


def _argmax(values: list[float]) -> int:
    """Argmax with lowest-index tie-break."""
    return values.index(max(values))


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def build(out_dir: Path) -> None:
    # --- Snap committed weights to float32 ---
    model = dict(_MODEL_RAW)
    model["W"] = _snap_matrix(model["W"])
    model["b"] = _snap_vec(model["b"])

    # --- Generate feature vectors (already float32-snapped in helper) ---
    feature_vectors = _generate_features(_N_INPUTS, _N_FEATURES)

    # --- Sanity-check: verify argmax gaps are unambiguous (> 10*ε) for all inputs ---
    W = model["W"]
    b = model["b"]
    for i, x in enumerate(feature_vectors):
        logits = _compute_logits(W, b, x)
        sorted_logits = sorted(logits, reverse=True)
        gap = sorted_logits[0] - sorted_logits[1]
        assert gap > 10 * _TOLERANCE, (
            f"Input {i}: argmax gap {gap} is not > 10*ε={10*_TOLERANCE}; "
            "choose different weights"
        )

    # --- Build features.json ---
    features_bytes = (
        json.dumps(feature_vectors, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    # --- Build model.json ---
    model_bytes = (
        json.dumps(model, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    # --- Compute predictions ---
    predictions = []
    for i, x in enumerate(feature_vectors):
        logits = _compute_logits(W, b, x)
        predicted_class = _argmax(logits)
        predictions.append(
            {
                "input_idx": i,
                "logits": logits,
                "predicted_class": predicted_class,
            }
        )

    predictions_bytes = (
        json.dumps(predictions, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    # --- Emit via the reference-emitter SDK (scaffold + digests + manifest) ---
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "inputs/features.json": features_bytes,
            "weights/model.json": model_bytes,
            "payload/predictions.json": predictions_bytes,
        },
        typed_checks=_TYPED_CHECKS,
    )
    manifest = write_bundle(out_dir, content)

    print(f"Bundle written to {out_dir}")
    print(f"  inputs           : {_N_INPUTS} feature vectors of dim {_N_FEATURES} (float32)")
    print(f"  n_classes        : {model['n_classes']}")
    print(f"  tolerance        : {model['tolerance']}")
    print(f"  predictions      : {[p['predicted_class'] for p in predictions]}")
    print(f"  manifest files   : {len(manifest['files'])}")
    print(f"  manifest         : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic fp_ml_minimal audit bundle"
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        type=Path,
        help="Destination directory (created if absent)",
    )
    args = parser.parse_args()
    try:
        build(args.out_dir.resolve())
    except AssertionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
