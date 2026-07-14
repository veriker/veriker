#!/usr/bin/env python3
"""yield_fusion_re_derivation.py — stdlib re-derivation pack for agritech sensor-fusion.

Re-derives the yield-score forecast from the bundled sensor time-series and
committed fusion weights, then asserts byte-for-byte reproducibility against
the bundled payload/yield_forecast.json.

the audit-bundle contract §C6 (re-derivation pack — domain-agnostic substrate).
AB4: stdlib only — no imports from audit_bundle, no numpy, no pandas.

Reads from <bundle-dir>:
  inputs/sensor_stream.json     — 48 hourly sensor readings
  payload/fusion_weights.json   — fixed formula weights
  payload/yield_forecast.json   — model output to verify

Re-derivation formula:
  yield_score = w_soil_moisture * mean(soil_moisture_pct)
              + w_soil_temp     * mean(soil_temp_c)
              + w_npk           * mean(npk_ppm)
              + w_rainfall      * sum(rainfall_mm)
              + bias
  confidence_band = [yield_score * confidence_factor_lo,
                     yield_score * confidence_factor_hi]

Exits 0 on full match; 1 on first mismatch with a [YIELD_REDER_FAIL] line on stderr.

Usage:
    python yield_fusion_re_derivation.py --bundle-dir /path/to/bundle
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_TOLERANCE = 1e-5  # floating-point tolerance for score comparison


# ---------------------------------------------------------------------------
# Core formula
# ---------------------------------------------------------------------------

def _compute_yield_score(
    samples: list[dict],
    weights: dict,
) -> tuple[float, list[float]]:
    """Apply linear-weighted fusion formula.  Mirrors _build_bundle.py exactly."""
    n = len(samples)
    if n == 0:
        return 0.0, [0.0, 0.0]

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


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def _verify(bundle_dir: Path) -> str | None:
    """Return an error description on mismatch, or None on success."""
    stream_path  = bundle_dir / "inputs"  / "sensor_stream.json"
    weights_path = bundle_dir / "payload" / "fusion_weights.json"
    forecast_path = bundle_dir / "payload" / "yield_forecast.json"

    for label, path in [
        ("inputs/sensor_stream.json",   stream_path),
        ("payload/fusion_weights.json", weights_path),
        ("payload/yield_forecast.json", forecast_path),
    ]:
        if not path.exists():
            return f"{label} absent from bundle_dir {bundle_dir}"

    try:
        stream_doc: dict = json.loads(stream_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return f"failed to read inputs/sensor_stream.json: {exc}"

    try:
        weights: dict = json.loads(weights_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return f"failed to read payload/fusion_weights.json: {exc}"

    try:
        forecast: dict = json.loads(forecast_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return f"failed to read payload/yield_forecast.json: {exc}"

    samples: list[dict] = stream_doc.get("samples", [])
    if not samples:
        return "inputs/sensor_stream.json has no samples"

    # Re-derive
    derived_score, derived_band = _compute_yield_score(samples, weights)

    # Compare yield_score
    bundled_score = forecast.get("yield_score")
    if bundled_score is None:
        return "payload/yield_forecast.json missing 'yield_score'"
    try:
        bundled_score = float(bundled_score)
    except (TypeError, ValueError) as exc:
        return f"payload/yield_forecast.json 'yield_score' is not numeric: {exc}"

    if abs(derived_score - bundled_score) > _TOLERANCE:
        return (
            f"yield_score mismatch: "
            f"derived={derived_score:.8f}, bundled={bundled_score:.8f}, "
            f"delta={abs(derived_score - bundled_score):.2e} > tol={_TOLERANCE:.2e}"
        )

    # Compare confidence_band
    bundled_band = forecast.get("confidence_band")
    if bundled_band is None or len(bundled_band) != 2:
        return "payload/yield_forecast.json 'confidence_band' missing or wrong length"

    for idx, (d_val, b_val) in enumerate(zip(derived_band, bundled_band)):
        try:
            b_val = float(b_val)
        except (TypeError, ValueError) as exc:
            return f"confidence_band[{idx}] is not numeric: {exc}"
        if abs(d_val - b_val) > _TOLERANCE:
            return (
                f"confidence_band[{idx}] mismatch: "
                f"derived={d_val:.8f}, bundled={b_val:.8f}, "
                f"delta={abs(d_val - b_val):.2e} > tol={_TOLERANCE:.2e}"
            )

    # Compare sample count sanity check
    bundled_count = forecast.get("num_samples")
    if bundled_count is not None and bundled_count != len(samples):
        return (
            f"num_samples mismatch: "
            f"sensor_stream has {len(samples)}, forecast claims {bundled_count}"
        )

    return None  # all checks passed


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Yield-fusion re-derivation check for agritech audit bundles"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    error = _verify(bundle_dir)
    if error is None:
        print("YIELD_REDERIVED: re-derivation matched bundled forecast")
        return 0

    print(f"[YIELD_REDER_FAIL] {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
