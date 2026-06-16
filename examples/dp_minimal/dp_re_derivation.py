#!/usr/bin/env python3
"""dp_re_derivation.py — stdlib re-derivation pack for differential-privacy domain.

Demonstrates stochastic-but-seed-pinned re-derivation: the output is a noisy
aggregate, but the noise draw is deterministic given the committed seed and
mechanism parameters.

the audit-bundle contract §C6 generalization + AB4 (duplicate-don't-import).
Stdlib only — no numpy, no scipy, no opendp.

Reads data/dataset.jsonl and payload/dp_release.json from --bundle-dir.

Re-derivation steps:
  1. Re-compute true_count from the dataset by applying the predicate.
     Assert it matches bundled true_count exactly.
  2. Re-draw the Laplace noise from Random(seed) under the committed mechanism
     (laplace, given epsilon + sensitivity).
     noise = -scale * sign(u - 0.5) * log(1 - 2*|u - 0.5|)
     where scale = sensitivity / epsilon, u = Random(seed).random().
  3. Compute recomputed_noised_count = true_count + noise.
     Assert it matches bundled noised_count within 1e-9 tolerance.

Exit codes:
  0  full match
  1  first mismatch — [DP_REDER_FAIL] description on stderr
"""

from __future__ import annotations

import argparse
import json
import math
import random
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Laplace noise via inverse CDF (stdlib only — no scipy/numpy)
# ---------------------------------------------------------------------------

def _laplace_noise(scale: float, seed: int) -> float:
    """Draw one Laplace(0, scale) variate using inverse-CDF.

    Formula:  noise = -scale * sign(u - 0.5) * log(1 - 2*|u - 0.5|)
    where u = Random(seed).random().  Deterministic given seed.
    """
    u = random.Random(seed).random()
    sign = 1.0 if u >= 0.5 else -1.0
    return -scale * sign * math.log(1.0 - 2.0 * abs(u - 0.5))


# ---------------------------------------------------------------------------
# Re-derivation
# ---------------------------------------------------------------------------

def _fail(msg: str) -> int:
    print(f"[DP_REDER_FAIL] {msg}", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="DP release re-derivation check for dp_minimal audit bundles"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    # --- Load dp_release.json ---
    release_path = bundle_dir / "payload" / "dp_release.json"
    if not release_path.exists():
        return _fail(f"payload/dp_release.json not found in {bundle_dir}")

    try:
        release = json.loads(release_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return _fail(f"failed to read payload/dp_release.json: {exc}")

    try:
        predicate: dict = release["query"]["predicate"]
        bundled_true_count: int = int(release["true_count"])
        bundled_noised_count: float = float(release["noised_count"])
        mechanism: dict = release["mechanism"]
        mech_name: str = mechanism["name"]
        epsilon: float = float(mechanism["epsilon"])
        sensitivity: float = float(mechanism["sensitivity"])
        seed: int = int(mechanism["seed"])
    except (KeyError, TypeError, ValueError) as exc:
        return _fail(f"malformed dp_release.json: {exc}")

    if mech_name != "laplace":
        return _fail(f"unsupported mechanism {mech_name!r}; only 'laplace' is implemented")

    # --- Load dataset.jsonl ---
    dataset_path = bundle_dir / "data" / "dataset.jsonl"
    if not dataset_path.exists():
        return _fail(f"data/dataset.jsonl not found in {bundle_dir}")

    try:
        rows = [
            json.loads(line)
            for line in dataset_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (json.JSONDecodeError, OSError) as exc:
        return _fail(f"failed to read data/dataset.jsonl: {exc}")

    # --- Step 1: re-compute true_count from predicate ---
    def _matches(row: dict, pred: dict) -> bool:
        return all(row.get(k) == v for k, v in pred.items())

    recomputed_true_count: int = sum(1 for row in rows if _matches(row, predicate))
    if recomputed_true_count != bundled_true_count:
        return _fail(
            f"true_count mismatch: bundled={bundled_true_count} "
            f"recomputed={recomputed_true_count} (predicate={predicate})"
        )

    # --- Step 2: re-draw Laplace noise ---
    scale = sensitivity / epsilon
    noise = _laplace_noise(scale=scale, seed=seed)

    # --- Step 3: verify noised_count ---
    recomputed_noised_count = float(recomputed_true_count) + noise
    if abs(recomputed_noised_count - bundled_noised_count) > 1e-9:
        return _fail(
            f"noised_count mismatch: bundled={bundled_noised_count!r} "
            f"recomputed={recomputed_noised_count!r} "
            f"delta={abs(recomputed_noised_count - bundled_noised_count)!r}"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
