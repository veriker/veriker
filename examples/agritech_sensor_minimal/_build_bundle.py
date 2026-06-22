"""_build_bundle.py — build a deterministic agritech_sensor_minimal audit bundle.

Synthesises a 48-sample soil-sensor time-series (soil_moisture_pct,
soil_temp_c, npk_ppm, rainfall_mm), computes a yield-score forecast via
a linear-weighted fusion formula, and emits a standards-compliant
audit-bundle manifest.

The bundle captures:
  inputs/sensor_stream.json   — 48 hourly sensor readings (4 channels)
  payload/yield_forecast.json — {field_id, window_start, window_end,
                                  yield_score, confidence_band,
                                  fusion_weights_sha256}
  payload/fusion_weights.json — fixed fusion weights so re-derivation
                                 never needs an out-of-band source

FragmentIDs: one TimestampSampleFragment per sensor reading (48 total),
using sensor_id="composite_field_A" and the reading's ISO timestamp.

Usage (from v-kernel-audit-bundle root):
    python examples/agritech_sensor_minimal/_build_bundle.py --out-dir /tmp/agritech_sensor_bundle

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.emitter import BundleContent, write_bundle
from audit_bundle.fragments.fragment_id import (  # noqa: E402
    TimestampSampleFragment,
    fragment_to_canonical_dict,
)

# ---------------------------------------------------------------------------
# Bundle-level constants
# ---------------------------------------------------------------------------

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "agritech-sensor-minimal-rc"
_CREATED_AT = "2026-05-10T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
    "yield_fusion_re_derivation",
]

# ---------------------------------------------------------------------------
# Fusion formula constants (committed into payload/fusion_weights.json)
# ---------------------------------------------------------------------------

_WEIGHTS: dict = {
    "w_soil_moisture": 0.4,
    "w_soil_temp":    -0.05,
    "w_npk":           0.15,
    "w_rainfall":      0.10,
    "bias":           10.0,
    "confidence_factor_lo": 0.9,
    "confidence_factor_hi": 1.1,
}

# ---------------------------------------------------------------------------
# Synthetic sensor data generation (fixed seed for determinism)
# ---------------------------------------------------------------------------

_FIELD_ID = "field_A_synthetic"
_WINDOW_START = "2026-05-03T00:00:00Z"
_WINDOW_END   = "2026-05-04T23:00:00Z"  # 48 hourly samples
_NUM_SAMPLES  = 48
_SENSOR_ID    = "composite_field_A"


def _lcg(seed: int) -> object:
    """Minimal linear-congruential PRNG (stdlib-safe, no random module state)."""
    state = seed & 0xFFFF_FFFF_FFFF_FFFF
    a = 6364136223846793005
    c = 1442695040888963407
    m = 2 ** 64

    def next_float(lo: float, hi: float) -> float:
        nonlocal state
        state = (a * state + c) % m
        return lo + (state / m) * (hi - lo)

    return next_float


def _generate_sensor_stream() -> list[dict]:
    """Return 48 hourly sensor readings for field_A, using a fixed LCG seed."""
    rng = _lcg(seed=20260503)
    samples: list[dict] = []
    for i in range(_NUM_SAMPLES):
        hour = i % 24
        # Construct an ISO timestamp: 2026-05-03 + 2026-05-04 alternating hours
        day = 3 + (i // 24)
        ts = f"2026-05-{day:02d}T{hour:02d}:00:00Z"
        samples.append({
            "timestamp_iso":    ts,
            "sample_index":     i,
            "soil_moisture_pct": round(rng(20.0, 80.0), 4),
            "soil_temp_c":       round(rng(10.0, 35.0), 4),
            "npk_ppm":           round(rng(50.0, 300.0), 4),
            "rainfall_mm":       round(rng(0.0, 5.0), 4),
        })
    return samples


def _compute_yield_score(samples: list[dict], weights: dict) -> tuple[float, list[float]]:
    """Apply the linear-weighted fusion formula to produce a yield score.

    yield_score = w1 * mean(soil_moisture_pct)
                + w2 * mean(soil_temp_c)
                + w3 * mean(npk_ppm)
                + w4 * sum(rainfall_mm)
                + bias
    """
    n = len(samples)
    mean_moisture = sum(s["soil_moisture_pct"] for s in samples) / n
    mean_temp     = sum(s["soil_temp_c"]       for s in samples) / n
    mean_npk      = sum(s["npk_ppm"]           for s in samples) / n
    total_rain    = sum(s["rainfall_mm"]        for s in samples)

    score = (
        weights["w_soil_moisture"] * mean_moisture
        + weights["w_soil_temp"]   * mean_temp
        + weights["w_npk"]         * mean_npk
        + weights["w_rainfall"]    * total_rain
        + weights["bias"]
    )
    score = round(score, 6)
    band = [
        round(score * weights["confidence_factor_lo"], 6),
        round(score * weights["confidence_factor_hi"], 6),
    ]
    return score, band


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # 1. Synthesise sensor stream bytes
    # ------------------------------------------------------------------
    samples = _generate_sensor_stream()
    sensor_stream = {
        "field_id":    _FIELD_ID,
        "sensor_id":   _SENSOR_ID,
        "window_start": _WINDOW_START,
        "window_end":   _WINDOW_END,
        "samples":     samples,
    }
    stream_bytes = json.dumps(sensor_stream, indent=2).encode("utf-8")

    # ------------------------------------------------------------------
    # 2. Fusion weights bytes
    # ------------------------------------------------------------------
    weights_json = json.dumps(_WEIGHTS, indent=2, sort_keys=True)
    weights_bytes = weights_json.encode("utf-8")
    weights_sha = _sha256(weights_bytes)

    # ------------------------------------------------------------------
    # 3. Compute yield forecast bytes
    # ------------------------------------------------------------------
    yield_score, confidence_band = _compute_yield_score(samples, _WEIGHTS)
    forecast = {
        "field_id":            _FIELD_ID,
        "window_start":        _WINDOW_START,
        "window_end":          _WINDOW_END,
        "yield_score":         yield_score,
        "confidence_band":     confidence_band,
        "fusion_weights_sha256": weights_sha,
        "num_samples":         _NUM_SAMPLES,
        "sensor_id":           _SENSOR_ID,
    }
    forecast_bytes = json.dumps(forecast, indent=2).encode("utf-8")

    # ------------------------------------------------------------------
    # 4. Fragment anchors — one TimestampSampleFragment per sample
    #    (source_cid uses stream_bytes digest computed before writing)
    # ------------------------------------------------------------------
    stream_cid = f"sha256:{_sha256(stream_bytes)}"
    fragment_anchors: dict[str, dict] = {}
    for s in samples:
        frag = TimestampSampleFragment(
            source_cid=stream_cid,
            timestamp_iso=s["timestamp_iso"],
            sensor_id=_SENSOR_ID,
            sample_index=s["sample_index"],
        )
        anchor_name = f"sample-{s['sample_index']:03d}"
        fragment_anchors[anchor_name] = fragment_to_canonical_dict(frag)

    # --- Emit via the reference-emitter SDK (scaffold + digests + manifest). ---
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "inputs/sensor_stream.json":   stream_bytes,
            "payload/fusion_weights.json": weights_bytes,
            "payload/yield_forecast.json": forecast_bytes,
        },
        typed_checks=_TYPED_CHECKS,
        extra_manifest_fields={
            "fragment_anchors": fragment_anchors,
            "source_attributes": {},
        },
    )
    write_bundle(out_dir, content)
    manifest_path = out_dir / "manifest.json"

    print(f"Bundle written to {out_dir}")
    print(f"  samples          : {_NUM_SAMPLES}")
    print(f"  yield_score      : {yield_score}")
    print(f"  confidence_band  : {confidence_band}")
    print(f"  fragment_anchors : {len(fragment_anchors)}")
    print(f"  manifest files   : 3")
    print(f"  manifest         : {manifest_path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic agritech_sensor_minimal audit bundle"
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
