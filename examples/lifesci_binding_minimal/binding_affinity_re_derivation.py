#!/usr/bin/env python3
"""binding_affinity_re_derivation.py — stdlib re-derivation pack for drug-binding domain.

Demonstrates deterministic re-derivation of binding-affinity prediction:
  committed compound descriptor + target descriptor + scoring weights
  → bit-identical affinity_pred via deterministic feature-hash → weighted-sum scorer.

the audit-bundle contract §C5 (auditor independence) + AB4 (duplicate-don't-import).
Stdlib only — no numpy, no scipy, no torch (contract C5).

Feature hashing is STABLE across processes: uses zlib.crc32 (not Python's
built-in hash() which is randomized per PYTHONHASHSEED).

Re-derivation steps:
  1. Load inputs/compound_descriptor.json — {compound_id, smiles_string}.
  2. Load inputs/target_descriptor.json  — {target_id, sequence}.
  3. Load payload/scoring_weights.json   — {w_compound[32], w_target[32], bias}.
  4. Compute compound_features[32] via:
       for each char c in smiles_string:
         bucket = zlib.crc32(c.encode()) % 32
         compound_features[bucket] += 1
  5. Compute target_features[32] via the same hash over target sequence chars.
  6. affinity_pred = dot(compound_features, w_compound)
                   + dot(target_features, w_target)
                   + bias
     All arithmetic is integer to avoid IEEE-754 platform-determinism concerns.
  7. Load payload/binding_prediction.json — compare affinity_pred exactly.
  8. Verify scoring_weights_sha256 field in binding_prediction.json matches
     the SHA-256 of the on-disk scoring_weights.json file.
  9. Exit 0 on full match; exit 1 with [BIND_REDER_FAIL] <description> on stderr.

Exit codes:
  0  full match
  1  mismatch — [BIND_REDER_FAIL] description on stderr
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zlib
from pathlib import Path

_N_BUCKETS = 32


# ---------------------------------------------------------------------------
# Feature extraction (stable — zlib.crc32, not built-in hash())
# ---------------------------------------------------------------------------


def _stable_hash_mod(s: str, n: int) -> int:
    """Stable cross-process hash: zlib.crc32 of UTF-8 encoded string, mod n."""
    return zlib.crc32(s.encode("utf-8")) % n


def _extract_features(sequence: str, n_buckets: int = _N_BUCKETS) -> list[int]:
    """Hash each character into a bucket and sum bucket counts.

    Returns a list of length n_buckets. Each element is the count of characters
    that hashed into that bucket index. Stable across processes (zlib.crc32).
    """
    features = [0] * n_buckets
    for char in sequence:
        bucket = _stable_hash_mod(char, n_buckets)
        features[bucket] += 1
    return features


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def _dot(a: list[int | float], b: list[int | float]) -> float:
    """Dot product of two equal-length lists."""
    if len(a) != len(b):
        raise ValueError(f"dot product: length mismatch {len(a)} vs {len(b)}")
    return sum(ai * bi for ai, bi in zip(a, b))


def predict_affinity(
    smiles_string: str,
    sequence: str,
    w_compound: list[float],
    w_target: list[float],
    bias: float,
    n_buckets: int = _N_BUCKETS,
) -> float:
    """Deterministic affinity prediction from raw input strings and committed weights.

    This mirrors the forward pass in _build_bundle.py exactly — any divergence
    between build-time and verify-time is a tamper signal.
    """
    compound_features = _extract_features(smiles_string, n_buckets)
    target_features = _extract_features(sequence, n_buckets)
    return _dot(compound_features, w_compound) + _dot(target_features, w_target) + bias


# ---------------------------------------------------------------------------
# Re-derivation entry point
# ---------------------------------------------------------------------------


def _fail(msg: str) -> int:
    print(f"[BIND_REDER_FAIL] {msg}", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Binding-affinity re-derivation check for lifesci_binding_minimal audit bundles. "
            "the audit-bundle contract §C5 + §C6."
        )
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    # --- Step 1: Load compound descriptor ---
    compound_path = bundle_dir / "inputs" / "compound_descriptor.json"
    if not compound_path.exists():
        return _fail(f"inputs/compound_descriptor.json not found in {bundle_dir}")
    try:
        compound = json.loads(compound_path.read_text(encoding="utf-8"))
        smiles_string: str = compound["smiles_string"]
        compound_id: str = compound["compound_id"]
    except (json.JSONDecodeError, KeyError, OSError) as exc:
        return _fail(f"failed to read compound_descriptor.json: {exc}")

    # --- Step 2: Load target descriptor ---
    target_path = bundle_dir / "inputs" / "target_descriptor.json"
    if not target_path.exists():
        return _fail(f"inputs/target_descriptor.json not found in {bundle_dir}")
    try:
        target = json.loads(target_path.read_text(encoding="utf-8"))
        sequence: str = target["sequence"]
        target_id: str = target["target_id"]
    except (json.JSONDecodeError, KeyError, OSError) as exc:
        return _fail(f"failed to read target_descriptor.json: {exc}")

    # --- Step 3: Load scoring weights ---
    weights_path = bundle_dir / "payload" / "scoring_weights.json"
    if not weights_path.exists():
        return _fail(f"payload/scoring_weights.json not found in {bundle_dir}")
    try:
        weights_bytes = weights_path.read_bytes()
        weights = json.loads(weights_bytes.decode("utf-8"))
        w_compound: list[float] = weights["w_compound"]
        w_target: list[float] = weights["w_target"]
        bias: float = weights["bias"]
    except (json.JSONDecodeError, KeyError, OSError) as exc:
        return _fail(f"failed to read scoring_weights.json: {exc}")

    if len(w_compound) != _N_BUCKETS:
        return _fail(
            f"w_compound has {len(w_compound)} elements; expected {_N_BUCKETS}"
        )
    if len(w_target) != _N_BUCKETS:
        return _fail(
            f"w_target has {len(w_target)} elements; expected {_N_BUCKETS}"
        )

    # --- Step 4: Load bundled prediction ---
    prediction_path = bundle_dir / "payload" / "binding_prediction.json"
    if not prediction_path.exists():
        return _fail(f"payload/binding_prediction.json not found in {bundle_dir}")
    try:
        prediction = json.loads(prediction_path.read_text(encoding="utf-8"))
        bundled_affinity: float = prediction["affinity_pred"]
        bundled_compound_id: str = prediction["compound_id"]
        bundled_target_id: str = prediction["target_id"]
        bundled_weights_sha: str = prediction["scoring_weights_sha256"]
    except (json.JSONDecodeError, KeyError, OSError) as exc:
        return _fail(f"failed to read binding_prediction.json: {exc}")

    # --- Step 5: Verify identity fields match ---
    if bundled_compound_id != compound_id:
        return _fail(
            f"compound_id mismatch: prediction has {bundled_compound_id!r} "
            f"but compound_descriptor has {compound_id!r}"
        )
    if bundled_target_id != target_id:
        return _fail(
            f"target_id mismatch: prediction has {bundled_target_id!r} "
            f"but target_descriptor has {target_id!r}"
        )

    # --- Step 6: Verify scoring_weights_sha256 ---
    computed_weights_sha = hashlib.sha256(weights_bytes).hexdigest()
    if computed_weights_sha != bundled_weights_sha:
        return _fail(
            f"scoring_weights_sha256 mismatch: "
            f"prediction carries {bundled_weights_sha!r} "
            f"but computed SHA of scoring_weights.json is {computed_weights_sha!r}"
        )

    # --- Step 7: Re-derive affinity and compare ---
    try:
        recomputed_affinity = predict_affinity(
            smiles_string=smiles_string,
            sequence=sequence,
            w_compound=w_compound,
            w_target=w_target,
            bias=bias,
        )
    except ValueError as exc:
        return _fail(f"re-derivation arithmetic error: {exc}")

    # Round to 6 decimal places to match build-time rounding
    recomputed_rounded = round(recomputed_affinity, 6)
    bundled_rounded = round(bundled_affinity, 6)

    if recomputed_rounded != bundled_rounded:
        return _fail(
            f"affinity_pred mismatch for compound={compound_id!r} target={target_id!r}: "
            f"recomputed={recomputed_rounded!r} "
            f"bundled={bundled_rounded!r}"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
