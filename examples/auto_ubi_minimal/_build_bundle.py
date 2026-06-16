"""_build_bundle.py — build a deterministic auto_ubi_minimal audit bundle.

Usage-based auto insurance (UBI) telematics rating pilot for the V-Kernel
S0 audit-bundle integrator.

Regulator scope:
  - NAIC AI Systems Evaluation Tool (Underwriting / Pricing categories)
  - Colorado Reg 10-1-1 § 5.A.11 quantitative-testing (private passenger auto,
    effective 2025-10-15)

Writes a bundle into --out-dir:
  telematics/trips.jsonl              (synthetic raw trip records, all policyholders)
  payload/rate_table.json             (tier thresholds + discount/surcharge schedule)
  payload/rating_decisions.json       (per-policyholder rating decision)
  manifest.json

Re-derivation primitive (one sentence):
  Re-aggregate telematics features (mileage, hard-brake count,
  harsh-acceleration count, late-night driving fraction) from bundled raw
  trip records via stdlib-only computation, re-evaluate the bundled rate-table
  JSON to recompute the rating tier and discount — assert the bundle payload
  matches.

Fragment kind:
  OpaqueFragment(kind_tag="telematics_trip") — one fragment per trip record.
  Locator: {"trip_id": "...", "policyholder_id": "..."}

Dispatch records (C15):
  RATE_TABLE_LOOKUP — one per policyholder (rate-tier evaluation step)
  COMPUTE           — one per policyholder (feature-aggregation step)

Usage (from v-kernel-audit-bundle root):
    python examples/auto_ubi_minimal/_build_bundle.py --out-dir /tmp/auto_ubi_bundle

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.emitter import BundleContent, write_bundle
from audit_bundle.fragments.fragment_id import (
    OpaqueFragment,
    fragment_to_canonical_dict,
)

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "auto-ubi-minimal-rc"
_CREATED_AT = "2026-05-19T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
    "auto_ubi_re_derivation",
    "dispatch_record_wellformed",
]

# ---------------------------------------------------------------------------
# Rate table — thresholds and discount/surcharge schedule
# Tier classification is based on annual mileage estimate and risk scores.
# ---------------------------------------------------------------------------
_RATE_TABLE: dict = {
    "schema_version": "ubi-rate-table-v1",
    "tier_thresholds": {
        "annual_mileage_low_max": 7500,
        "annual_mileage_high_min": 15000,
        "hard_brake_per_mile_surcharge_threshold": 0.04,
        "harsh_accel_per_mile_surcharge_threshold": 0.03,
        "late_night_fraction_surcharge_threshold": 0.15,
    },
    "tiers": {
        "low_mileage_discount": {
            "description": "Annual mileage <= 7500 with acceptable risk scores",
            "discount_pct": 15,
        },
        "standard": {
            "description": "Annual mileage between 7500 and 15000, or low-mileage with risk flags",
            "discount_pct": 0,
        },
        "high_risk_surcharge": {
            "description": "Exceeds one or more risk score thresholds",
            "surcharge_pct": 20,
        },
    },
}

# ---------------------------------------------------------------------------
# Synthetic trip records — 5 policyholders, 10-20 trips each
# Trip fields: trip_id, policyholder_id, date, distance_miles, duration_min,
#              hard_brakes, harsh_accels, late_night (bool)
# ---------------------------------------------------------------------------

# PHD-001: low-mileage, safe driver → low_mileage_discount
# PHD-002: moderate mileage, moderate risk → standard
# PHD-003: high mileage, high hard-brake rate → high_risk_surcharge
# PHD-004: low mileage but high late-night fraction → standard (risk flag)
# PHD-005: high mileage, moderate risk → standard (high mileage alone)

_TRIPS: list[dict] = [
    # PHD-001 — 12 trips, low mileage, safe (total: ~4320 miles projected annual)
    {
        "trip_id": "T001-001",
        "policyholder_id": "PHD-001",
        "date": "2026-01-05",
        "distance_miles": 8.2,
        "duration_min": 14,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T001-002",
        "policyholder_id": "PHD-001",
        "date": "2026-01-07",
        "distance_miles": 12.5,
        "duration_min": 22,
        "hard_brakes": 0,
        "harsh_accels": 1,
        "late_night": False,
    },
    {
        "trip_id": "T001-003",
        "policyholder_id": "PHD-001",
        "date": "2026-01-12",
        "distance_miles": 9.1,
        "duration_min": 18,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T001-004",
        "policyholder_id": "PHD-001",
        "date": "2026-01-15",
        "distance_miles": 7.8,
        "duration_min": 13,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T001-005",
        "policyholder_id": "PHD-001",
        "date": "2026-01-20",
        "distance_miles": 11.0,
        "duration_min": 20,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T001-006",
        "policyholder_id": "PHD-001",
        "date": "2026-01-25",
        "distance_miles": 6.3,
        "duration_min": 11,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T001-007",
        "policyholder_id": "PHD-001",
        "date": "2026-02-02",
        "distance_miles": 9.7,
        "duration_min": 17,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T001-008",
        "policyholder_id": "PHD-001",
        "date": "2026-02-08",
        "distance_miles": 8.4,
        "duration_min": 15,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T001-009",
        "policyholder_id": "PHD-001",
        "date": "2026-02-14",
        "distance_miles": 10.2,
        "duration_min": 19,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T001-010",
        "policyholder_id": "PHD-001",
        "date": "2026-02-20",
        "distance_miles": 7.5,
        "duration_min": 13,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T001-011",
        "policyholder_id": "PHD-001",
        "date": "2026-02-25",
        "distance_miles": 8.9,
        "duration_min": 16,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T001-012",
        "policyholder_id": "PHD-001",
        "date": "2026-03-02",
        "distance_miles": 8.0,
        "duration_min": 14,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": False,
    },
    # PHD-002 — 15 trips, moderate mileage/risk → standard
    {
        "trip_id": "T002-001",
        "policyholder_id": "PHD-002",
        "date": "2026-01-03",
        "distance_miles": 22.0,
        "duration_min": 35,
        "hard_brakes": 1,
        "harsh_accels": 1,
        "late_night": False,
    },
    {
        "trip_id": "T002-002",
        "policyholder_id": "PHD-002",
        "date": "2026-01-06",
        "distance_miles": 18.5,
        "duration_min": 30,
        "hard_brakes": 0,
        "harsh_accels": 1,
        "late_night": False,
    },
    {
        "trip_id": "T002-003",
        "policyholder_id": "PHD-002",
        "date": "2026-01-09",
        "distance_miles": 25.0,
        "duration_min": 40,
        "hard_brakes": 1,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T002-004",
        "policyholder_id": "PHD-002",
        "date": "2026-01-14",
        "distance_miles": 20.0,
        "duration_min": 32,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T002-005",
        "policyholder_id": "PHD-002",
        "date": "2026-01-18",
        "distance_miles": 19.5,
        "duration_min": 31,
        "hard_brakes": 0,
        "harsh_accels": 1,
        "late_night": False,
    },
    {
        "trip_id": "T002-006",
        "policyholder_id": "PHD-002",
        "date": "2026-01-22",
        "distance_miles": 23.0,
        "duration_min": 37,
        "hard_brakes": 1,
        "harsh_accels": 0,
        "late_night": True,
    },
    {
        "trip_id": "T002-007",
        "policyholder_id": "PHD-002",
        "date": "2026-01-28",
        "distance_miles": 21.0,
        "duration_min": 34,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T002-008",
        "policyholder_id": "PHD-002",
        "date": "2026-02-03",
        "distance_miles": 24.0,
        "duration_min": 38,
        "hard_brakes": 0,
        "harsh_accels": 1,
        "late_night": False,
    },
    {
        "trip_id": "T002-009",
        "policyholder_id": "PHD-002",
        "date": "2026-02-07",
        "distance_miles": 20.5,
        "duration_min": 33,
        "hard_brakes": 1,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T002-010",
        "policyholder_id": "PHD-002",
        "date": "2026-02-11",
        "distance_miles": 22.5,
        "duration_min": 36,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T002-011",
        "policyholder_id": "PHD-002",
        "date": "2026-02-16",
        "distance_miles": 19.0,
        "duration_min": 30,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T002-012",
        "policyholder_id": "PHD-002",
        "date": "2026-02-21",
        "distance_miles": 21.5,
        "duration_min": 35,
        "hard_brakes": 1,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T002-013",
        "policyholder_id": "PHD-002",
        "date": "2026-02-25",
        "distance_miles": 20.0,
        "duration_min": 32,
        "hard_brakes": 0,
        "harsh_accels": 1,
        "late_night": False,
    },
    {
        "trip_id": "T002-014",
        "policyholder_id": "PHD-002",
        "date": "2026-03-01",
        "distance_miles": 23.5,
        "duration_min": 38,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T002-015",
        "policyholder_id": "PHD-002",
        "date": "2026-03-05",
        "distance_miles": 18.0,
        "duration_min": 29,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": False,
    },
    # PHD-003 — 18 trips, high mileage + high hard-brake rate → high_risk_surcharge
    {
        "trip_id": "T003-001",
        "policyholder_id": "PHD-003",
        "date": "2026-01-02",
        "distance_miles": 45.0,
        "duration_min": 55,
        "hard_brakes": 4,
        "harsh_accels": 2,
        "late_night": False,
    },
    {
        "trip_id": "T003-002",
        "policyholder_id": "PHD-003",
        "date": "2026-01-05",
        "distance_miles": 50.0,
        "duration_min": 62,
        "hard_brakes": 3,
        "harsh_accels": 2,
        "late_night": False,
    },
    {
        "trip_id": "T003-003",
        "policyholder_id": "PHD-003",
        "date": "2026-01-08",
        "distance_miles": 42.0,
        "duration_min": 51,
        "hard_brakes": 2,
        "harsh_accels": 3,
        "late_night": False,
    },
    {
        "trip_id": "T003-004",
        "policyholder_id": "PHD-003",
        "date": "2026-01-11",
        "distance_miles": 48.0,
        "duration_min": 58,
        "hard_brakes": 4,
        "harsh_accels": 1,
        "late_night": False,
    },
    {
        "trip_id": "T003-005",
        "policyholder_id": "PHD-003",
        "date": "2026-01-14",
        "distance_miles": 46.0,
        "duration_min": 56,
        "hard_brakes": 3,
        "harsh_accels": 2,
        "late_night": False,
    },
    {
        "trip_id": "T003-006",
        "policyholder_id": "PHD-003",
        "date": "2026-01-17",
        "distance_miles": 52.0,
        "duration_min": 63,
        "hard_brakes": 3,
        "harsh_accels": 2,
        "late_night": False,
    },
    {
        "trip_id": "T003-007",
        "policyholder_id": "PHD-003",
        "date": "2026-01-20",
        "distance_miles": 44.0,
        "duration_min": 54,
        "hard_brakes": 2,
        "harsh_accels": 2,
        "late_night": False,
    },
    {
        "trip_id": "T003-008",
        "policyholder_id": "PHD-003",
        "date": "2026-01-23",
        "distance_miles": 49.0,
        "duration_min": 60,
        "hard_brakes": 4,
        "harsh_accels": 1,
        "late_night": False,
    },
    {
        "trip_id": "T003-009",
        "policyholder_id": "PHD-003",
        "date": "2026-01-26",
        "distance_miles": 47.0,
        "duration_min": 57,
        "hard_brakes": 3,
        "harsh_accels": 3,
        "late_night": False,
    },
    {
        "trip_id": "T003-010",
        "policyholder_id": "PHD-003",
        "date": "2026-01-29",
        "distance_miles": 43.0,
        "duration_min": 52,
        "hard_brakes": 2,
        "harsh_accels": 2,
        "late_night": False,
    },
    {
        "trip_id": "T003-011",
        "policyholder_id": "PHD-003",
        "date": "2026-02-01",
        "distance_miles": 51.0,
        "duration_min": 62,
        "hard_brakes": 3,
        "harsh_accels": 1,
        "late_night": False,
    },
    {
        "trip_id": "T003-012",
        "policyholder_id": "PHD-003",
        "date": "2026-02-04",
        "distance_miles": 45.5,
        "duration_min": 55,
        "hard_brakes": 2,
        "harsh_accels": 2,
        "late_night": False,
    },
    {
        "trip_id": "T003-013",
        "policyholder_id": "PHD-003",
        "date": "2026-02-07",
        "distance_miles": 48.5,
        "duration_min": 59,
        "hard_brakes": 3,
        "harsh_accels": 3,
        "late_night": False,
    },
    {
        "trip_id": "T003-014",
        "policyholder_id": "PHD-003",
        "date": "2026-02-10",
        "distance_miles": 50.5,
        "duration_min": 61,
        "hard_brakes": 4,
        "harsh_accels": 2,
        "late_night": False,
    },
    {
        "trip_id": "T003-015",
        "policyholder_id": "PHD-003",
        "date": "2026-02-13",
        "distance_miles": 46.5,
        "duration_min": 56,
        "hard_brakes": 2,
        "harsh_accels": 1,
        "late_night": False,
    },
    {
        "trip_id": "T003-016",
        "policyholder_id": "PHD-003",
        "date": "2026-02-16",
        "distance_miles": 44.5,
        "duration_min": 54,
        "hard_brakes": 3,
        "harsh_accels": 2,
        "late_night": False,
    },
    {
        "trip_id": "T003-017",
        "policyholder_id": "PHD-003",
        "date": "2026-02-19",
        "distance_miles": 52.5,
        "duration_min": 64,
        "hard_brakes": 3,
        "harsh_accels": 2,
        "late_night": False,
    },
    {
        "trip_id": "T003-018",
        "policyholder_id": "PHD-003",
        "date": "2026-02-22",
        "distance_miles": 47.5,
        "duration_min": 58,
        "hard_brakes": 4,
        "harsh_accels": 3,
        "late_night": False,
    },
    # PHD-004 — 10 trips, low mileage but high late-night fraction → standard (risk flag)
    {
        "trip_id": "T004-001",
        "policyholder_id": "PHD-004",
        "date": "2026-01-04",
        "distance_miles": 9.0,
        "duration_min": 15,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": True,
    },
    {
        "trip_id": "T004-002",
        "policyholder_id": "PHD-004",
        "date": "2026-01-09",
        "distance_miles": 7.5,
        "duration_min": 12,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": True,
    },
    {
        "trip_id": "T004-003",
        "policyholder_id": "PHD-004",
        "date": "2026-01-13",
        "distance_miles": 8.0,
        "duration_min": 14,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": True,
    },
    {
        "trip_id": "T004-004",
        "policyholder_id": "PHD-004",
        "date": "2026-01-17",
        "distance_miles": 6.5,
        "duration_min": 11,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T004-005",
        "policyholder_id": "PHD-004",
        "date": "2026-01-22",
        "distance_miles": 10.0,
        "duration_min": 17,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": True,
    },
    {
        "trip_id": "T004-006",
        "policyholder_id": "PHD-004",
        "date": "2026-01-28",
        "distance_miles": 8.5,
        "duration_min": 14,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": True,
    },
    {
        "trip_id": "T004-007",
        "policyholder_id": "PHD-004",
        "date": "2026-02-03",
        "distance_miles": 7.0,
        "duration_min": 12,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": True,
    },
    {
        "trip_id": "T004-008",
        "policyholder_id": "PHD-004",
        "date": "2026-02-09",
        "distance_miles": 9.5,
        "duration_min": 16,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T004-009",
        "policyholder_id": "PHD-004",
        "date": "2026-02-15",
        "distance_miles": 8.2,
        "duration_min": 14,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": True,
    },
    {
        "trip_id": "T004-010",
        "policyholder_id": "PHD-004",
        "date": "2026-02-21",
        "distance_miles": 7.8,
        "duration_min": 13,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": True,
    },
    # PHD-005 — 14 trips, high mileage (above 15000 annual projection), moderate risk → standard
    {
        "trip_id": "T005-001",
        "policyholder_id": "PHD-005",
        "date": "2026-01-02",
        "distance_miles": 38.0,
        "duration_min": 48,
        "hard_brakes": 1,
        "harsh_accels": 1,
        "late_night": False,
    },
    {
        "trip_id": "T005-002",
        "policyholder_id": "PHD-005",
        "date": "2026-01-05",
        "distance_miles": 35.0,
        "duration_min": 44,
        "hard_brakes": 0,
        "harsh_accels": 1,
        "late_night": False,
    },
    {
        "trip_id": "T005-003",
        "policyholder_id": "PHD-005",
        "date": "2026-01-08",
        "distance_miles": 40.0,
        "duration_min": 50,
        "hard_brakes": 1,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T005-004",
        "policyholder_id": "PHD-005",
        "date": "2026-01-11",
        "distance_miles": 36.0,
        "duration_min": 45,
        "hard_brakes": 0,
        "harsh_accels": 1,
        "late_night": False,
    },
    {
        "trip_id": "T005-005",
        "policyholder_id": "PHD-005",
        "date": "2026-01-14",
        "distance_miles": 39.0,
        "duration_min": 49,
        "hard_brakes": 1,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T005-006",
        "policyholder_id": "PHD-005",
        "date": "2026-01-17",
        "distance_miles": 37.0,
        "duration_min": 47,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T005-007",
        "policyholder_id": "PHD-005",
        "date": "2026-01-20",
        "distance_miles": 41.0,
        "duration_min": 51,
        "hard_brakes": 1,
        "harsh_accels": 1,
        "late_night": False,
    },
    {
        "trip_id": "T005-008",
        "policyholder_id": "PHD-005",
        "date": "2026-01-23",
        "distance_miles": 36.5,
        "duration_min": 46,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T005-009",
        "policyholder_id": "PHD-005",
        "date": "2026-01-26",
        "distance_miles": 38.5,
        "duration_min": 48,
        "hard_brakes": 1,
        "harsh_accels": 1,
        "late_night": False,
    },
    {
        "trip_id": "T005-010",
        "policyholder_id": "PHD-005",
        "date": "2026-01-29",
        "distance_miles": 37.5,
        "duration_min": 47,
        "hard_brakes": 0,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T005-011",
        "policyholder_id": "PHD-005",
        "date": "2026-02-01",
        "distance_miles": 40.5,
        "duration_min": 51,
        "hard_brakes": 0,
        "harsh_accels": 1,
        "late_night": False,
    },
    {
        "trip_id": "T005-012",
        "policyholder_id": "PHD-005",
        "date": "2026-02-04",
        "distance_miles": 35.5,
        "duration_min": 45,
        "hard_brakes": 1,
        "harsh_accels": 0,
        "late_night": False,
    },
    {
        "trip_id": "T005-013",
        "policyholder_id": "PHD-005",
        "date": "2026-02-07",
        "distance_miles": 39.5,
        "duration_min": 50,
        "hard_brakes": 0,
        "harsh_accels": 1,
        "late_night": False,
    },
    {
        "trip_id": "T005-014",
        "policyholder_id": "PHD-005",
        "date": "2026-02-10",
        "distance_miles": 38.0,
        "duration_min": 48,
        "hard_brakes": 1,
        "harsh_accels": 0,
        "late_night": False,
    },
]

# Observation window in days (used to project annual mileage).
# The synthetic dataset covers 7 days of active driving per policyholder.
_OBSERVATION_DAYS = 7
_DAYS_PER_YEAR = 365.25


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _aggregate_features(trips: list[dict]) -> dict:
    """Aggregate telematics features from a list of trip dicts."""
    total_miles = sum(t["distance_miles"] for t in trips)
    total_hard_brakes = sum(t["hard_brakes"] for t in trips)
    total_harsh_accels = sum(t["harsh_accels"] for t in trips)
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
    """Apply rate-table thresholds to features.  Returns (tier_name, adjustment_pct)."""
    thresholds = rate_table["tier_thresholds"]
    tiers = rate_table["tiers"]

    # High-risk check first (overrides low-mileage discount if triggered)
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

    # Low-mileage discount (safe driver with annual est <= 7500)
    is_low_mileage = (
        features["annual_mileage_est"] <= thresholds["annual_mileage_low_max"]
    )
    if is_low_mileage:
        return ("low_mileage_discount", tiers["low_mileage_discount"]["discount_pct"])

    return ("standard", 0)


def build(out_dir: Path) -> None:
    # ------------------------------------------------------------------
    # Prepare artifact bytes
    # ------------------------------------------------------------------
    trips_text = "\n".join(json.dumps(t, sort_keys=True) for t in _TRIPS) + "\n"
    trips_bytes = trips_text.encode("utf-8")

    rate_table_bytes = (json.dumps(_RATE_TABLE, indent=2, sort_keys=True) + "\n").encode("utf-8")

    # ------------------------------------------------------------------
    # Compute per-policyholder features and rating decisions
    # ------------------------------------------------------------------
    trips_by_ph: dict[str, list[dict]] = {}
    for trip in _TRIPS:
        ph_id = trip["policyholder_id"]
        trips_by_ph.setdefault(ph_id, []).append(trip)

    rating_decisions: list[dict] = []
    for ph_id in sorted(trips_by_ph.keys()):
        ph_trips = trips_by_ph[ph_id]
        features = _aggregate_features(ph_trips)
        tier_name, adjustment_pct = _classify_tier(features, _RATE_TABLE)
        decision = {
            "policyholder_id": ph_id,
            "trip_count": features["trip_count"],
            "total_miles": round(features["total_miles"], 2),
            "annual_mileage_est": round(features["annual_mileage_est"], 1),
            "hard_brake_per_mile": round(features["hard_brake_per_mile"], 5),
            "harsh_accel_per_mile": round(features["harsh_accel_per_mile"], 5),
            "late_night_fraction": round(features["late_night_fraction"], 4),
            "tier": tier_name,
            "adjustment_pct": adjustment_pct,
        }
        rating_decisions.append(decision)

    decisions_bytes = (json.dumps(rating_decisions, indent=2, sort_keys=True) + "\n").encode("utf-8")

    # Verify at least one low-mileage-discount and one high-risk-surcharge tier
    tiers_present = {d["tier"] for d in rating_decisions}
    assert "low_mileage_discount" in tiers_present, (
        f"Expected at least one low_mileage_discount tier; tiers present: {tiers_present}"
    )
    assert "high_risk_surcharge" in tiers_present, (
        f"Expected at least one high_risk_surcharge tier; tiers present: {tiers_present}"
    )

    # ------------------------------------------------------------------
    # OpaqueFragment anchors — one per trip record
    # source_cid = SHA-256 of the bundled trips.jsonl
    # ------------------------------------------------------------------
    trips_cid = f"sha256:{_sha256(trips_bytes)}"
    fragment_anchors: dict[str, dict] = {}
    for trip in _TRIPS:
        frag = OpaqueFragment(
            source_cid=trips_cid,
            kind_tag="telematics_trip",
            locator={
                "trip_id": trip["trip_id"],
                "policyholder_id": trip["policyholder_id"],
            },
        )
        anchor_key = f"trip-{trip['trip_id']}"
        fragment_anchors[anchor_key] = fragment_to_canonical_dict(frag)

    assert len(fragment_anchors) == len(_TRIPS), (
        f"Fragment anchors count mismatch: {len(fragment_anchors)} vs {len(_TRIPS)}"
    )

    # ------------------------------------------------------------------
    # dispatch_records (C15) — RATE_TABLE_LOOKUP + COMPUTE per policyholder
    # ------------------------------------------------------------------
    dispatch_records: list[dict] = []
    for ph_id in sorted(trips_by_ph.keys()):
        # COMPUTE — feature aggregation
        dispatch_records.append(
            {
                "schema_version": "0.1",
                "op": {
                    "kind": "COMPUTE",
                    "name": "ubi_feature_aggregation",
                    "policyholder_id": ph_id,
                },
                "inputs": [],
                "outputs": [],
                "effect": {},
                "locale": "en-US",
                "predicates": [],
                "stamp_declared": "INTERNAL_BENCHMARK",
                "stamp_observed": None,
            }
        )
        # RATE_TABLE_LOOKUP — tier evaluation
        dispatch_records.append(
            {
                "schema_version": "0.1",
                "op": {
                    "kind": "RATE_TABLE_LOOKUP",
                    "name": "ubi_tier_evaluation",
                    "policyholder_id": ph_id,
                },
                "inputs": [],
                "outputs": [],
                "effect": {},
                "locale": "en-US",
                "predicates": [],
                "stamp_declared": "INTERNAL_BENCHMARK",
                "stamp_observed": None,
            }
        )

    # ------------------------------------------------------------------
    # Emit via the reference-emitter SDK
    # ------------------------------------------------------------------
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "telematics/trips.jsonl": trips_bytes,
            "payload/rate_table.json": rate_table_bytes,
            "payload/rating_decisions.json": decisions_bytes,
        },
        typed_checks=_TYPED_CHECKS,
        extra_manifest_fields={
            "fragment_anchors": fragment_anchors,
            "dispatch_records": dispatch_records,
        },
    )
    write_bundle(out_dir, content)

    print(f"Bundle written to {out_dir}")
    print(f"  policyholders    : {len(trips_by_ph)}")
    print(f"  trip records     : {len(_TRIPS)}")
    print(f"  manifest files   : 3")
    print(
        f"  fragment anchors : {len(fragment_anchors)} OpaqueFragment (kind_tag=telematics_trip)"
    )
    print(
        f"  dispatch records : {len(dispatch_records)} ({len(trips_by_ph)} × COMPUTE + RATE_TABLE_LOOKUP)"
    )
    print(f"  rating tiers     : {sorted(tiers_present)}")
    print(f"  manifest         : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic auto_ubi_minimal audit bundle"
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
