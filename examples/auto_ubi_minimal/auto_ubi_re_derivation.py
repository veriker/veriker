#!/usr/bin/env python3
"""auto_ubi_re_derivation.py — stdlib re-derivation pack for the auto_ubi_minimal domain pilot.

Verifies that per-policyholder rating decisions are derivable from the bundled
raw trip records and the bundled rate table.

the audit-bundle contract §C6 (domain generalization) + AB4 (duplicate-don't-import).
Stdlib only (no third-party dependencies) — contract C5.

Reads from --bundle-dir:
  telematics/trips.jsonl           — the bundled raw trip records
  payload/rate_table.json          — the bundled rate-tier threshold schedule
  payload/rating_decisions.json    — the per-policyholder decisions to re-derive

Re-derivation primitive:
  Re-aggregate telematics features (mileage, hard-brake count,
  harsh-acceleration count, late-night driving fraction) from the bundled
  raw trip records, re-evaluate the bundled rate-table JSON to recompute
  the rating tier and adjustment percentage — assert the bundle payload matches.

Three invariants checked:
  1. All policyholders in rating_decisions are covered by trip records.
  2. Re-aggregated features match the bundled decision fields (total_miles,
     annual_mileage_est, hard_brake_per_mile, harsh_accel_per_mile,
     late_night_fraction) within floating-point tolerance.
  3. Re-derived tier and adjustment_pct match the bundled decision exactly.

Exit 0 on full match; exit 1 on first mismatch with [AUTO_UBI_REDERIVATION_MISMATCH]
on stderr.

If telematics/trips.jsonl or payload/rating_decisions.json is absent the bundle
opted out of UBI re-derivation — exits 0.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Observation window used when computing annual mileage projection.
# Must match the value in _build_bundle.py.
_OBSERVATION_DAYS = 7
_DAYS_PER_YEAR = 365.25

# Per-field tolerances for re-derived continuous features.
# Values are stored in the bundle at reduced precision (round(x, N)); the
# tolerance covers that rounding gap with a 2x safety margin.
#   annual_mileage_est  : round(x, 1) → max error 0.05 → tol 0.1
#   total_miles         : round(x, 2) → max error 0.005 → tol 0.01
#   hard_brake_per_mile / harsh_accel_per_mile : round(x, 5) → tol 0.0001
#   late_night_fraction : round(x, 4) → tol 0.0001
_FIELD_TOL: dict[str, float] = {
    "total_miles": 0.01,
    "annual_mileage_est": 0.1,
    "hard_brake_per_mile": 0.0001,
    "harsh_accel_per_mile": 0.0001,
    "late_night_fraction": 0.0001,
}


def _load_trips(bundle_dir: Path) -> list[dict] | None:
    trips_path = bundle_dir / "telematics" / "trips.jsonl"
    if not trips_path.exists():
        return None
    trips: list[dict] = []
    for lineno, line in enumerate(
        trips_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = line.strip()
        if not line:
            continue
        try:
            trips.append(json.loads(line))
        except json.JSONDecodeError as exc:
            print(
                f"[AUTO_UBI_REDERIVATION_MISMATCH] telematics/trips.jsonl line {lineno}: "
                f"JSON parse error: {exc}",
                file=sys.stderr,
            )
            return None
    return trips


def _load_rate_table(bundle_dir: Path) -> dict | None:
    rt_path = bundle_dir / "payload" / "rate_table.json"
    if not rt_path.exists():
        print(
            "[AUTO_UBI_REDERIVATION_MISMATCH] payload/rate_table.json absent",
            file=sys.stderr,
        )
        return None
    try:
        return json.loads(rt_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(
            f"[AUTO_UBI_REDERIVATION_MISMATCH] payload/rate_table.json: JSON parse error: {exc}",
            file=sys.stderr,
        )
        return None


def _load_decisions(bundle_dir: Path) -> list[dict] | None:
    dec_path = bundle_dir / "payload" / "rating_decisions.json"
    if not dec_path.exists():
        return None
    try:
        return json.loads(dec_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(
            f"[AUTO_UBI_REDERIVATION_MISMATCH] payload/rating_decisions.json: "
            f"JSON parse error: {exc}",
            file=sys.stderr,
        )
        return None


def _aggregate_features(trips: list[dict]) -> dict:
    """Aggregate telematics features from a list of trip dicts (stdlib only)."""
    total_miles = sum(float(t["distance_miles"]) for t in trips)
    total_hard_brakes = sum(int(t["hard_brakes"]) for t in trips)
    total_harsh_accels = sum(int(t["harsh_accels"]) for t in trips)
    late_night_count = sum(1 for t in trips if t["late_night"])
    trip_count = len(trips)
    annual_mileage_est = total_miles * (_DAYS_PER_YEAR / _OBSERVATION_DAYS)
    hard_brake_per_mile = total_hard_brakes / total_miles if total_miles > 0 else 0.0
    harsh_accel_per_mile = total_harsh_accels / total_miles if total_miles > 0 else 0.0
    late_night_fraction = late_night_count / trip_count if trip_count > 0 else 0.0
    return {
        "total_miles": total_miles,
        "annual_mileage_est": annual_mileage_est,
        "hard_brake_per_mile": hard_brake_per_mile,
        "harsh_accel_per_mile": harsh_accel_per_mile,
        "late_night_fraction": late_night_fraction,
        "trip_count": trip_count,
    }


def _classify_tier(features: dict, rate_table: dict) -> tuple[str, int]:
    """Apply rate-table thresholds to features. Returns (tier_name, adjustment_pct)."""
    thresholds = rate_table["tier_thresholds"]
    tiers = rate_table["tiers"]

    is_high_risk = (
        features["hard_brake_per_mile"]
        > thresholds["hard_brake_per_mile_surcharge_threshold"]
        or features["harsh_accel_per_mile"]
        > thresholds["harsh_accel_per_mile_surcharge_threshold"]
        or features["late_night_fraction"]
        > thresholds["late_night_fraction_surcharge_threshold"]
    )
    if is_high_risk:
        return ("high_risk_surcharge", -tiers["high_risk_surcharge"]["surcharge_pct"])

    is_low_mileage = (
        features["annual_mileage_est"] <= thresholds["annual_mileage_low_max"]
    )
    if is_low_mileage:
        return ("low_mileage_discount", tiers["low_mileage_discount"]["discount_pct"])

    return ("standard", 0)


def _approx_eq(a: float, b: float, tol: float) -> bool:
    return abs(a - b) <= tol


def main() -> int:
    parser = argparse.ArgumentParser(
        description="UBI telematics re-derivation check for auto_ubi_minimal audit bundles"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    # Optional opt-out — if no trips file present, skip silently
    trips_path = bundle_dir / "telematics" / "trips.jsonl"
    dec_path = bundle_dir / "payload" / "rating_decisions.json"

    if not trips_path.exists() and not dec_path.exists():
        return 0

    trips = _load_trips(bundle_dir)
    if trips is None:
        return 1

    rate_table = _load_rate_table(bundle_dir)
    if rate_table is None:
        return 1

    decisions = _load_decisions(bundle_dir)
    if decisions is None and not dec_path.exists():
        return 0
    if decisions is None:
        return 1

    # Group trips by policyholder
    trips_by_ph: dict[str, list[dict]] = {}
    for trip in trips:
        try:
            ph_id = trip["policyholder_id"]
        except (KeyError, TypeError) as exc:
            print(
                f"[AUTO_UBI_REDERIVATION_MISMATCH] telematics/trips.jsonl: "
                f"malformed trip record (missing policyholder_id): {exc}",
                file=sys.stderr,
            )
            return 1
        trips_by_ph.setdefault(ph_id, []).append(trip)

    # Invariant 1 + 2 + 3 — for each bundled decision, re-derive and compare
    for dec in decisions:
        try:
            ph_id: str = dec["policyholder_id"]
            bundled_tier: str = dec["tier"]
            bundled_adj: int = dec["adjustment_pct"]
            bundled_total_miles: float = float(dec["total_miles"])
            bundled_annual_est: float = float(dec["annual_mileage_est"])
            bundled_hb_per_mile: float = float(dec["hard_brake_per_mile"])
            bundled_ha_per_mile: float = float(dec["harsh_accel_per_mile"])
            bundled_ln_frac: float = float(dec["late_night_fraction"])
        except (KeyError, TypeError, ValueError) as exc:
            print(
                f"[AUTO_UBI_REDERIVATION_MISMATCH] payload/rating_decisions.json: "
                f"malformed decision record: {exc}",
                file=sys.stderr,
            )
            return 1

        # Invariant 1 — policyholder must have trip records
        if ph_id not in trips_by_ph:
            print(
                f"[AUTO_UBI_REDERIVATION_MISMATCH] policyholder {ph_id!r} appears in "
                f"rating_decisions but has no trip records in telematics/trips.jsonl",
                file=sys.stderr,
            )
            return 1

        ph_trips = trips_by_ph[ph_id]
        features = _aggregate_features(ph_trips)

        # Invariant 2 — re-derived continuous features must match within tolerance
        checks: list[tuple[str, float, float]] = [
            ("total_miles", features["total_miles"], bundled_total_miles),
            ("annual_mileage_est", features["annual_mileage_est"], bundled_annual_est),
            (
                "hard_brake_per_mile",
                features["hard_brake_per_mile"],
                bundled_hb_per_mile,
            ),
            (
                "harsh_accel_per_mile",
                features["harsh_accel_per_mile"],
                bundled_ha_per_mile,
            ),
            ("late_night_fraction", features["late_night_fraction"], bundled_ln_frac),
        ]
        for field_name, recomputed, bundled in checks:
            tol = _FIELD_TOL[field_name]
            if not _approx_eq(recomputed, bundled, tol):
                print(
                    f"[AUTO_UBI_REDERIVATION_MISMATCH] {ph_id}: feature {field_name!r} "
                    f"mismatch - recomputed={recomputed:.6f} bundled={bundled:.6f} "
                    f"(delta={abs(recomputed - bundled):.6f} > tol={tol})",
                    file=sys.stderr,
                )
                return 1

        # Invariant 3 — re-derived tier and adjustment must match exactly
        recomputed_tier, recomputed_adj = _classify_tier(features, rate_table)
        if recomputed_tier != bundled_tier:
            print(
                f"[AUTO_UBI_REDERIVATION_MISMATCH] {ph_id}: tier mismatch — "
                f"recomputed={recomputed_tier!r} bundled={bundled_tier!r}",
                file=sys.stderr,
            )
            return 1
        if recomputed_adj != bundled_adj:
            print(
                f"[AUTO_UBI_REDERIVATION_MISMATCH] {ph_id}: adjustment_pct mismatch — "
                f"recomputed={recomputed_adj} bundled={bundled_adj}",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
