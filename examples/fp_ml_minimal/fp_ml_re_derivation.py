#!/usr/bin/env python3
"""fp_ml_re_derivation.py — stdlib re-derivation pack for FP ML inference domain.

Demonstrates deterministic re-derivation for floating-point linear classifiers:
committed float32 weights + committed float32 input feature vectors →
float32-snapped logits within declared tolerance ε, and exact argmax match.

the audit-bundle contract §C5 (auditor independence) + AB4 (duplicate-don't-import).
Stdlib only — no numpy, no scipy, no torch.

Float32 discipline (must match _build_bundle.py exactly):
  Python's native float is IEEE-754 double (64-bit).  We snap to float32 via
      f32(x) = struct.unpack('f', struct.pack('f', x))[0]
  at every serialization boundary: weights, inputs, and final logits.
  Arithmetic accumulation is in Python double; only the final snapped value
  is compared against the bundled (also snapped) logit.

Re-derivation steps:
  1. Load weights/model.json; validate schema == "linear-classifier-fp-v1",
     shape constraints, tolerance field.
  2. Load inputs/features.json.
  3. For each input x[i], compute logit[k] = f32(sum(W[k][j]*x[j]) + b[k]).
  4. Compare per-logit: abs(logit_rederived - logit_bundled) <= tolerance.
  5. Compare argmax exactly (integer).
  6. Exit 0 on full match; exit 1 with [FP_ML_REDER_FAIL] <description>
     on stderr on first divergence (includes actual delta).

Exit codes:
  0  full match
  1  first mismatch — [FP_ML_REDER_FAIL] description on stderr
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Float32 round-trip helper
# ---------------------------------------------------------------------------


def _f32(x: float) -> float:
    """Snap a Python float to float32 precision via struct pack/unpack."""
    return struct.unpack("f", struct.pack("f", x))[0]


# ---------------------------------------------------------------------------
# Inference (stdlib only — no numpy/torch)
# ---------------------------------------------------------------------------


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
# Re-derivation
# ---------------------------------------------------------------------------


def _fail(msg: str) -> int:
    print(f"[FP_ML_REDER_FAIL] {msg}", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="FP ML inference re-derivation check for fp_ml_minimal audit bundles"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    # --- Step 1: Load and validate weights ---
    model_path = bundle_dir / "weights" / "model.json"
    if not model_path.exists():
        return _fail(f"weights/model.json not found in {bundle_dir}")

    try:
        model = json.loads(model_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return _fail(f"failed to read weights/model.json: {exc}")

    try:
        schema: str = model["schema"]
        n_features: int = int(model["n_features"])
        n_classes: int = int(model["n_classes"])
        tolerance: float = float(model["tolerance"])
        W: list[list[float]] = model["W"]
        b: list[float] = model["b"]
    except (KeyError, TypeError, ValueError) as exc:
        return _fail(f"malformed weights/model.json: {exc}")

    if schema != "linear-classifier-fp-v1":
        return _fail(
            f"unsupported model schema {schema!r}; only 'linear-classifier-fp-v1' is implemented"
        )

    if len(W) != n_classes:
        return _fail(
            f"W has {len(W)} rows but n_classes={n_classes}; shape mismatch"
        )

    for k, row in enumerate(W):
        if len(row) != n_features:
            return _fail(
                f"W[{k}] has {len(row)} cols but n_features={n_features}; shape mismatch"
            )

    if len(b) != n_classes:
        return _fail(
            f"b has {len(b)} elements but n_classes={n_classes}; shape mismatch"
        )

    # --- Step 2: Load inputs ---
    features_path = bundle_dir / "inputs" / "features.json"
    if not features_path.exists():
        return _fail(f"inputs/features.json not found in {bundle_dir}")

    try:
        feature_vectors: list[list[float]] = json.loads(
            features_path.read_text(encoding="utf-8")
        )
    except (json.JSONDecodeError, OSError) as exc:
        return _fail(f"failed to read inputs/features.json: {exc}")

    # --- Load bundled predictions ---
    predictions_path = bundle_dir / "payload" / "predictions.json"
    if not predictions_path.exists():
        return _fail(f"payload/predictions.json not found in {bundle_dir}")

    try:
        bundled_predictions: list[dict] = json.loads(
            predictions_path.read_text(encoding="utf-8")
        )
    except (json.JSONDecodeError, OSError) as exc:
        return _fail(f"failed to read payload/predictions.json: {exc}")

    if len(bundled_predictions) != len(feature_vectors):
        return _fail(
            f"predictions has {len(bundled_predictions)} entries but "
            f"features has {len(feature_vectors)} vectors; length mismatch"
        )

    # --- Steps 3+4+5: Re-derive and compare each record ---
    for i, x in enumerate(feature_vectors):
        logits_rederived = _compute_logits(W, b, x)
        predicted_class_rederived = _argmax(logits_rederived)

        expected = bundled_predictions[i]
        logits_bundled: list[float] = expected["logits"]
        predicted_class_bundled: int = int(expected["predicted_class"])

        # Per-logit tolerance check
        for k, (lr, lb) in enumerate(zip(logits_rederived, logits_bundled)):
            delta = abs(lr - lb)
            if delta > tolerance:
                return _fail(
                    f"logit tolerance exceeded at input_idx={i} class={k}: "
                    f"rederived={lr!r} bundled={lb!r} "
                    f"delta={delta!r} tolerance={tolerance!r}"
                )

        # Argmax exact-match check
        if predicted_class_rederived != predicted_class_bundled:
            return _fail(
                f"argmax mismatch at input_idx={i}: "
                f"rederived={predicted_class_rederived} bundled={predicted_class_bundled}"
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
