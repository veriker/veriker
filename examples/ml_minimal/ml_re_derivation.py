#!/usr/bin/env python3
"""ml_re_derivation.py — stdlib re-derivation pack for ML inference domain.

Demonstrates deterministic re-derivation: committed model weights + committed
input feature vectors → bit-identical predicted classes via integer-only
linear classifier inference.

the audit-bundle contract §C5 (auditor independence) + AB4 (duplicate-don't-import).
Stdlib only — no numpy, no scipy, no torch.

Re-derivation steps:
  1. Load weights/model.json; validate schema == "linear-classifier-v1",
     shape constraints (len(W)==n_classes, each len(W[k])==n_features,
     len(b)==n_classes).
  2. Load inputs/features.json.
  3. For each input x[i], compute integer logits:
       logit[k] = sum(W[k][j] * x[j] for j in range(n_features)) + b[k]
     Find predicted_class = argmax(logits) with lowest-index tie-break.
  4. Compare against payload/predictions.json exactly (JSON object equality
     after round-trip through Python dicts).
  5. Exit 0 on full match; exit 1 with [ML_REDER_FAIL] <description> on
     stderr on first divergence.

Exit codes:
  0  full match
  1  first mismatch — [ML_REDER_FAIL] description on stderr
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Inference (stdlib only — no numpy/torch)
# ---------------------------------------------------------------------------


def _compute_logits(W: list[list[int]], b: list[int], x: list[int]) -> list[int]:
    """Integer dot-product: logit[k] = sum(W[k][j]*x[j]) + b[k]."""
    n_classes = len(W)
    n_features = len(x)
    return [
        sum(W[k][j] * x[j] for j in range(n_features)) + b[k]
        for k in range(n_classes)
    ]


def _argmax(values: list[int]) -> int:
    """Argmax with lowest-index tie-break."""
    return values.index(max(values))


# ---------------------------------------------------------------------------
# Re-derivation
# ---------------------------------------------------------------------------


def _fail(msg: str) -> int:
    print(f"[ML_REDER_FAIL] {msg}", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="ML inference re-derivation check for ml_minimal audit bundles"
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
        W: list[list[int]] = model["W"]
        b: list[int] = model["b"]
    except (KeyError, TypeError, ValueError) as exc:
        return _fail(f"malformed weights/model.json: {exc}")

    if schema != "linear-classifier-v1":
        return _fail(
            f"unsupported model schema {schema!r}; only 'linear-classifier-v1' is implemented"
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
        feature_vectors: list[list[int]] = json.loads(
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

    # --- Steps 3+4: Re-derive and compare each record ---
    for i, x in enumerate(feature_vectors):
        logits = _compute_logits(W, b, x)
        predicted_class = _argmax(logits)

        expected = bundled_predictions[i]
        recomputed = {
            "input_idx": i,
            "logits": logits,
            "predicted_class": predicted_class,
        }

        if recomputed != expected:
            return _fail(
                f"mismatch at input_idx={i}: "
                f"recomputed={recomputed!r} "
                f"bundled={expected!r}"
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
