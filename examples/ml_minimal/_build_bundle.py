"""_build_bundle.py — build a deterministic ml_minimal audit bundle.

Generates 8 synthetic input feature vectors and runs an integer-only linear
classifier (logits = W @ x + b, predicted_class = argmax) using committed
weights, emitting the predictions as a standards-compliant payload.

Re-derivation primitive (one sentence): re-execute an integer-only linear
classifier using committed weights and committed inputs, and assert the
bundled prediction list matches exactly.

Why integer arithmetic: float arithmetic raises IEEE-754 platform-determinism
concerns irrelevant to the substrate claim. Integer-only inference gives a
clean "committed weights + committed input + deterministic integer compute
→ bit-identical output" proof.  Floating-point inference is roadmapped
(would require ONNX-Runtime determinism mode or fixed-point quantization).

Usage (from v-kernel-audit-bundle root):
    python examples/ml_minimal/_build_bundle.py --out-dir /tmp/ml_bundle

Outputs:
  <out-dir>/inputs/features.json        (8 feature vectors, 4 ints each)
  <out-dir>/weights/model.json          (linear-classifier-v1 schema)
  <out-dir>/payload/predictions.json    (predicted class per input)
  <out-dir>/manifest.json

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import json
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
_BUNDLE_ID = "ml-minimal-rc"
_CREATED_AT = "2026-05-09T00:00:00Z"
_TYPED_CHECKS = ["file_integrity_many_small", "ml_re_derivation"]

_N_INPUTS = 8
_N_FEATURES = 4

# Committed model weights — linear-classifier-v1 schema.
# W shape: [n_classes, n_features].  All integers; bias b: [n_classes].
_MODEL = {
    "schema": "linear-classifier-v1",
    "n_features": _N_FEATURES,
    "n_classes": 3,
    "W": [[3, -2, 1, 4], [-1, 5, -3, 2], [2, 1, -1, -2]],
    "b": [0, 1, -1],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _generate_features(n_inputs: int, n_features: int) -> list[list[int]]:
    """Deterministic synthetic feature vectors — do not change the formula."""
    return [
        [((i * 13 + j * 7) % 200) - 100 for j in range(n_features)]
        for i in range(n_inputs)
    ]


def _compute_logits(W: list[list[int]], b: list[int], x: list[int]) -> list[int]:
    """Integer dot-product: logit[k] = sum(W[k][j]*x[j]) + b[k]."""
    return [sum(W[k][j] * x[j] for j in range(len(x))) + b[k] for k in range(len(W))]


def _argmax(values: list[int]) -> int:
    """Argmax with lowest-index tie-break."""
    return values.index(max(values))


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def build(out_dir: Path) -> None:
    # --- Generate feature vectors ---
    feature_vectors = _generate_features(_N_INPUTS, _N_FEATURES)
    features_bytes = (
        json.dumps(feature_vectors, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    # --- Build model weights ---
    model_bytes = (
        json.dumps(_MODEL, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    # --- Compute predictions ---
    W = _MODEL["W"]
    b = _MODEL["b"]
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
    print(f"  inputs           : {_N_INPUTS} feature vectors of dim {_N_FEATURES}")
    print(f"  n_classes        : {_MODEL['n_classes']}")
    print(f"  predictions      : {[p['predicted_class'] for p in predictions]}")
    print(f"  manifest files   : {len(manifest['files'])}")
    print(f"  manifest         : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic ml_minimal audit bundle"
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
