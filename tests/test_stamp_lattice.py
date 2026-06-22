"""Tests for audit_bundle/plugins/stamp_lattice.py — C14 stamp provenance lattice.

Covers all three sub-invariants:
  1. stamp_observed shape validation (null OK as UNVERIFIED; out-of-enum HARD-FAIL)
  2. min-rule on aggregate_stamp (roundup above per-row min is HARD-FAIL)
  3. non-min composition rule rejection (sentinel field presence in JSON/dataclass)

Plus lattice rank ordering and legacy empty-records handling.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from audit_bundle.plugins.stamp_lattice import (
    STAMP_ORDER,
    STAMP_RANK,
    StampLatticeCheck,
)


# ---------------------------------------------------------------------------
# Manifest stub
# ---------------------------------------------------------------------------


class _Manifest:
    def __init__(self, dispatch_records=(), aggregate_stamp=None):
        self.dispatch_records = dispatch_records
        self.aggregate_stamp = aggregate_stamp


def _record(stamp_observed):
    return {
        "schema_version": "0.1",
        "op": {"kind": "COMPUTE", "name": "score"},
        "inputs": [],
        "outputs": [],
        "effect": {},
        "locale": "en-US",
        "predicates": [],
        "stamp_declared": stamp_observed or "UNVERIFIED",
        "stamp_observed": stamp_observed,
    }


_PLUGIN = StampLatticeCheck


# ============================================================================
# Test 1 — empty dispatch_records (legacy bundle) — OK
# ============================================================================


def test_empty_dispatch_records_legacy_ok(tmp_path):
    result = _PLUGIN().check(tmp_path, _Manifest())
    assert result.ok is True
    assert result.reason_code == "PASS"
    assert "0 records audited" in result.detail


# ============================================================================
# Test 2 — one record stamp_observed=CONFIRMED_EXTERNAL, aggregate=CONFIRMED_EXTERNAL — OK
# ============================================================================


def test_one_record_confirmed_external_aggregate_matches_ok(tmp_path):
    manifest = _Manifest(
        dispatch_records=(_record("CONFIRMED_EXTERNAL"),),
        aggregate_stamp="CONFIRMED_EXTERNAL",
    )
    result = _PLUGIN().check(tmp_path, manifest)
    assert result.ok is True
    assert result.reason_code == "PASS"


# ============================================================================
# Test 3 — one record stamp_observed=INTERNAL_BENCHMARK, aggregate=CONFIRMED_EXTERNAL — HARD-FAIL
# ============================================================================


def test_one_record_internal_benchmark_aggregate_roundup_fails(tmp_path):
    manifest = _Manifest(
        dispatch_records=(_record("INTERNAL_BENCHMARK"),),
        aggregate_stamp="CONFIRMED_EXTERNAL",
    )
    result = _PLUGIN().check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_AGGREGATE_ROUNDUP_DETECTED"
    assert "CONFIRMED_EXTERNAL" in result.detail
    assert "INTERNAL_BENCHMARK" in result.detail
    assert "offending row index=0" in result.detail


# ============================================================================
# Test 4 — three records min=TARGET, aggregate=TARGET — OK
# ============================================================================


def test_three_records_min_target_aggregate_target_ok(tmp_path):
    records = (
        _record("CONFIRMED_EXTERNAL"),
        _record("TARGET"),
        _record("WEB_SOURCE"),
    )
    manifest = _Manifest(dispatch_records=records, aggregate_stamp="TARGET")
    result = _PLUGIN().check(tmp_path, manifest)
    assert result.ok is True
    assert result.reason_code == "PASS"


# ============================================================================
# Test 5 — three records min=TARGET, aggregate=WEB_SOURCE — HARD-FAIL roundup
# ============================================================================


def test_three_records_min_target_aggregate_web_source_fails(tmp_path):
    records = (
        _record("CONFIRMED_EXTERNAL"),
        _record("TARGET"),
        _record("WEB_SOURCE"),
    )
    manifest = _Manifest(dispatch_records=records, aggregate_stamp="WEB_SOURCE")
    result = _PLUGIN().check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_AGGREGATE_ROUNDUP_DETECTED"
    assert "WEB_SOURCE" in result.detail
    assert "TARGET" in result.detail


# ============================================================================
# Test 6 — three records min=UNVERIFIED, aggregate=null — OK (no HARMONIC claim)
# ============================================================================


def test_three_records_min_unverified_aggregate_null_ok(tmp_path):
    records = (
        _record("CONFIRMED_EXTERNAL"),
        _record("UNVERIFIED"),
        _record("WEB_SOURCE"),
    )
    manifest = _Manifest(dispatch_records=records, aggregate_stamp=None)
    result = _PLUGIN().check(tmp_path, manifest)
    assert result.ok is True
    assert result.reason_code == "PASS"


# ============================================================================
# Test 7 — null stamp_observed treated as UNVERIFIED for aggregation
# ============================================================================


def test_null_stamp_observed_treated_as_unverified(tmp_path):
    # One record has stamp_observed=null, another has WEB_SOURCE.
    # If aggregate_stamp=WEB_SOURCE, that rounds up above UNVERIFIED — FAIL.
    records = (_record(None), _record("WEB_SOURCE"))
    manifest = _Manifest(dispatch_records=records, aggregate_stamp="WEB_SOURCE")
    result = _PLUGIN().check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_AGGREGATE_ROUNDUP_DETECTED"
    assert "UNVERIFIED" in result.detail


# ============================================================================
# Test 8 — stamp_observed='FOO' out-of-enum — HARD-FAIL
# ============================================================================


def test_stamp_observed_out_of_enum_fails(tmp_path):
    record = _record("CONFIRMED_EXTERNAL")
    record["stamp_observed"] = "FOO"
    manifest = _Manifest(dispatch_records=(record,))
    result = _PLUGIN().check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_OBSERVED_OUT_OF_ENUM"
    assert "FOO" in result.detail
    assert "record[0]" in result.detail


# ============================================================================
# Test 9 — sentinel field aggregate_stamp_avg present in JSON — HARD-FAIL
# ============================================================================


def test_sentinel_aggregate_stamp_avg_in_json_fails(tmp_path):
    (tmp_path / "manifest.json").write_text(
        json.dumps({"aggregate_stamp_avg": "CONFIRMED_EXTERNAL"}),
        encoding="utf-8",
    )
    manifest = _Manifest(dispatch_records=())
    result = _PLUGIN().check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_AGGREGATION_RULE_REJECTED"
    assert "aggregate_stamp_avg" in result.detail


# ============================================================================
# Test 10 — sentinel field aggregate_stamp_weighted with null value — HARD-FAIL
# ============================================================================


def test_sentinel_aggregate_stamp_weighted_null_value_fails(tmp_path):
    # Null value does not exempt the field; presence alone is the violation.
    (tmp_path / "manifest.json").write_text(
        json.dumps({"aggregate_stamp_weighted": None}),
        encoding="utf-8",
    )
    manifest = _Manifest(dispatch_records=())
    result = _PLUGIN().check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_AGGREGATION_RULE_REJECTED"
    assert "aggregate_stamp_weighted" in result.detail


# ============================================================================
# Test 11 — three records all stamp_observed=null, aggregate=null — OK
# ============================================================================


def test_three_records_all_null_stamp_observed_aggregate_null_ok(tmp_path):
    records = (_record(None), _record(None), _record(None))
    manifest = _Manifest(dispatch_records=records, aggregate_stamp=None)
    result = _PLUGIN().check(tmp_path, manifest)
    assert result.ok is True
    assert result.reason_code == "PASS"
    assert "3 records audited" in result.detail


# ============================================================================
# Test 12 — lattice rank ordering: CONFIRMED_EXTERNAL > UNVERIFIED
# ============================================================================


def test_lattice_rank_ordering_confirmed_external_strongest(tmp_path):
    assert STAMP_RANK["CONFIRMED_EXTERNAL"] > STAMP_RANK["UNVERIFIED"]
    assert STAMP_RANK["CONFIRMED_EXTERNAL"] == len(STAMP_ORDER) - 1
    assert STAMP_RANK["UNVERIFIED"] == 0
    # Full monotone ordering
    for i in range(len(STAMP_ORDER) - 1):
        assert STAMP_RANK[STAMP_ORDER[i]] < STAMP_RANK[STAMP_ORDER[i + 1]]
