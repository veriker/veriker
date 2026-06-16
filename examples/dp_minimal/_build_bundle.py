"""_build_bundle.py — build a deterministic dp_minimal audit bundle.

Generates a synthetic 100-row dataset (age_bucket, income_bucket), applies a
differential-privacy Laplace mechanism to a count query, and emits a
standards-compliant manifest.json.

Usage (from v-kernel-audit-bundle root):
    python examples/dp_minimal/_build_bundle.py --out-dir /tmp/dp_bundle

Outputs:
  <out-dir>/data/dataset.jsonl         (100 deterministic rows)
  <out-dir>/payload/dp_release.json    (noised aggregate)
  <out-dir>/manifest.json

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import json
import math
import random
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
_BUNDLE_ID = "dp-minimal-rc"
_CREATED_AT = "2026-05-08T00:00:00Z"
_TYPED_CHECKS = ["file_integrity_many_small", "dp_re_derivation"]

# Dataset generation seed — deterministic, do not change.
_DATASET_SEED = 42
_AGE_BUCKETS = ["18-29", "30-39", "40-49", "50-64", "65+"]
_INCOME_BUCKETS = ["low", "lower-mid", "upper-mid", "high"]
_N_ROWS = 100

# Query predicate
_PREDICATE = {"age_bucket": "30-39", "income_bucket": "upper-mid"}

# Mechanism parameters — deterministic, do not change.
_MECHANISM_NAME = "laplace"
_EPSILON = 1.0
_SENSITIVITY = 1.0
_NOISE_SEED = 4096


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _laplace_noise(scale: float, seed: int) -> float:
    """Laplace(0, scale) via inverse-CDF.  Deterministic given seed."""
    u = random.Random(seed).random()
    sign = 1.0 if u >= 0.5 else -1.0
    return -scale * sign * math.log(1.0 - 2.0 * abs(u - 0.5))


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def build(out_dir: Path) -> None:
    # --- Generate synthetic dataset (domain logic — what varies per pilot) ---
    rng = random.Random(_DATASET_SEED)
    rows = [
        {
            "age_bucket": rng.choice(_AGE_BUCKETS),
            "income_bucket": rng.choice(_INCOME_BUCKETS),
        }
        for _ in range(_N_ROWS)
    ]
    dataset_jsonl = "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n"
    dataset_bytes = dataset_jsonl.encode("utf-8")

    # --- Compute true count ---
    def _matches(row: dict) -> bool:
        return all(row.get(k) == v for k, v in _PREDICATE.items())

    true_count: int = sum(1 for row in rows if _matches(row))

    # --- Draw Laplace noise ---
    scale = _SENSITIVITY / _EPSILON
    noise = _laplace_noise(scale=scale, seed=_NOISE_SEED)
    noised_count: float = float(true_count) + noise

    # --- Build dp_release.json ---
    release = {
        "query": {"predicate": _PREDICATE},
        "true_count": true_count,
        "noised_count": noised_count,
        "mechanism": {
            "name": _MECHANISM_NAME,
            "epsilon": _EPSILON,
            "sensitivity": _SENSITIVITY,
            "seed": _NOISE_SEED,
        },
    }
    release_bytes = (json.dumps(release, indent=2, ensure_ascii=False) + "\n").encode("utf-8")

    # --- Emit via the reference-emitter SDK (scaffold + digests + manifest) ---
    # Open production-standard hooks (static created_at, no causal chain, no
    # attestation) — dp_minimal carries no dispatch records or time witness.
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "data/dataset.jsonl": dataset_bytes,
            "payload/dp_release.json": release_bytes,
        },
        typed_checks=_TYPED_CHECKS,
    )
    manifest = write_bundle(out_dir, content)

    print(f"Bundle written to {out_dir}")
    print(f"  dataset rows     : {_N_ROWS}")
    print(f"  true_count       : {true_count}")
    print(f"  noised_count     : {noised_count:.6f}")
    print(f"  manifest files   : {len(manifest['files'])}")
    print(f"  manifest         : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic dp_minimal audit bundle"
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
