"""Tests for coverage/protocol.py (validate_coverage_row) and
coverage/sum_invariant_plugin.py (CoverageSumInvariantCheck).

Coverage:
  - validate_coverage_row: valid rows, partition-sum tamper, breakdown-sum tamper,
    negative counts, negative breakdown values, edge cases.
  - CoverageSumInvariantCheck.check: missing dir, empty dir, all-valid, each
    reason_code, parse error, multi-file scan order, files_audited contents.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from audit_bundle.coverage.protocol import (
    CoverageInvariantError,
    CoverageRow,
    EligibleTupleSet,
    validate_coverage_row,
)
from audit_bundle.coverage.sum_invariant_plugin import CoverageSumInvariantCheck


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row(
    *,
    tick_id: str = "t-001",
    n_eligible: int = 10,
    n_issued: int = 7,
    n_withheld: int = 3,
    withheld_reason_breakdown: dict[str, int] | None = None,
) -> CoverageRow:
    if withheld_reason_breakdown is None:
        withheld_reason_breakdown = {"missing_data": 2, "below_threshold": 1}
    return CoverageRow(
        tick_id=tick_id,
        n_eligible=n_eligible,
        n_issued=n_issued,
        n_withheld=n_withheld,
        withheld_reason_breakdown=withheld_reason_breakdown,
    )


def _write_coverage_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _valid_payload(
    tick_id: str = "t-001",
    n_eligible: int = 10,
    n_issued: int = 7,
    n_withheld: int = 3,
    breakdown: dict[str, int] | None = None,
) -> dict:
    return {
        "tick_id": tick_id,
        "n_eligible": n_eligible,
        "n_issued": n_issued,
        "n_withheld": n_withheld,
        "withheld_reason_breakdown": breakdown if breakdown is not None else {"a": 2, "b": 1},
    }


class _Manifest:
    """Minimal manifest stub."""


# ============================================================================
# EligibleTupleSet Protocol
# ============================================================================


class TestEligibleTupleSetProtocol:
    """Structural checks: implementations satisfy the Protocol."""

    def test_list_satisfies_protocol(self) -> None:
        sample: list[str] = ["a", "b", "c"]
        assert isinstance(sample, EligibleTupleSet)

    def test_empty_list_satisfies_protocol(self) -> None:
        assert isinstance([], EligibleTupleSet)

    def test_object_without_len_does_not_satisfy_protocol(self) -> None:
        class NoLen:
            def __iter__(self):
                return iter([])

        assert not isinstance(NoLen(), EligibleTupleSet)

    def test_object_without_iter_does_not_satisfy_protocol(self) -> None:
        class NoIter:
            def __len__(self):
                return 0

        assert not isinstance(NoIter(), EligibleTupleSet)

    def test_custom_implementation_satisfies_protocol(self) -> None:
        class MyTupleSet:
            def __init__(self, items):
                self._items = items

            def __iter__(self):
                return iter(self._items)

            def __len__(self):
                return len(self._items)

        assert isinstance(MyTupleSet(["x", "y"]), EligibleTupleSet)


# ============================================================================
# CoverageRow dataclass
# ============================================================================


class TestCoverageRow:
    """Basic dataclass invariants."""

    def test_construction(self) -> None:
        row = _row()
        assert row.tick_id == "t-001"
        assert row.n_eligible == 10
        assert row.n_issued == 7
        assert row.n_withheld == 3

    def test_frozen_rejects_mutation(self) -> None:
        row = _row()
        with pytest.raises((AttributeError, TypeError)):
            row.tick_id = "tampered"  # type: ignore[misc]

    def test_empty_breakdown_allowed(self) -> None:
        row = _row(n_withheld=0, withheld_reason_breakdown={})
        assert row.withheld_reason_breakdown == {}


# ============================================================================
# validate_coverage_row — valid cases
# ============================================================================


class TestValidateCoverageRowValid:
    """validate_coverage_row must not raise on conforming rows."""

    def test_basic_valid_row_passes(self) -> None:
        validate_coverage_row(_row())  # should not raise

    def test_all_issued_no_withheld(self) -> None:
        row = _row(n_eligible=5, n_issued=5, n_withheld=0, withheld_reason_breakdown={})
        validate_coverage_row(row)

    def test_all_withheld_none_issued(self) -> None:
        row = _row(
            n_eligible=4,
            n_issued=0,
            n_withheld=4,
            withheld_reason_breakdown={"low_quality": 4},
        )
        validate_coverage_row(row)

    def test_zero_eligible_zero_everything(self) -> None:
        row = _row(n_eligible=0, n_issued=0, n_withheld=0, withheld_reason_breakdown={})
        validate_coverage_row(row)

    def test_multiple_breakdown_reasons_summing_correctly(self) -> None:
        row = _row(
            n_eligible=100,
            n_issued=60,
            n_withheld=40,
            withheld_reason_breakdown={"a": 10, "b": 20, "c": 10},
        )
        validate_coverage_row(row)

    def test_single_reason_in_breakdown(self) -> None:
        row = _row(
            n_eligible=3,
            n_issued=1,
            n_withheld=2,
            withheld_reason_breakdown={"only_reason": 2},
        )
        validate_coverage_row(row)

    def test_large_counts_pass(self) -> None:
        row = _row(
            n_eligible=1_000_000,
            n_issued=999_999,
            n_withheld=1,
            withheld_reason_breakdown={"rare": 1},
        )
        validate_coverage_row(row)


# ============================================================================
# validate_coverage_row — partition-sum tamper
# ============================================================================


class TestValidateCoverageRowPartitionSumTamper:
    """n_issued + n_withheld != n_eligible → CoverageInvariantError."""

    def test_sum_too_high_raises(self) -> None:
        row = _row(n_eligible=10, n_issued=8, n_withheld=5, withheld_reason_breakdown={"x": 5})
        with pytest.raises(CoverageInvariantError):
            validate_coverage_row(row)

    def test_sum_too_low_raises(self) -> None:
        row = _row(n_eligible=10, n_issued=3, n_withheld=3, withheld_reason_breakdown={"x": 3})
        with pytest.raises(CoverageInvariantError):
            validate_coverage_row(row)

    def test_error_message_contains_tick_id(self) -> None:
        row = _row(
            tick_id="tick-xyz",
            n_eligible=10,
            n_issued=4,
            n_withheld=4,
            withheld_reason_breakdown={"a": 4},
        )
        with pytest.raises(CoverageInvariantError, match="tick-xyz"):
            validate_coverage_row(row)

    def test_error_message_contains_issued_and_withheld(self) -> None:
        row = _row(n_eligible=10, n_issued=4, n_withheld=4, withheld_reason_breakdown={"a": 4})
        with pytest.raises(CoverageInvariantError) as exc_info:
            validate_coverage_row(row)
        msg = str(exc_info.value)
        assert "4" in msg and "10" in msg

    def test_issued_zero_withheld_nonzero_mismatch_raises(self) -> None:
        row = _row(n_eligible=5, n_issued=0, n_withheld=0, withheld_reason_breakdown={})
        with pytest.raises(CoverageInvariantError):
            validate_coverage_row(row)

    def test_off_by_one_too_high_raises(self) -> None:
        row = _row(n_eligible=10, n_issued=7, n_withheld=4, withheld_reason_breakdown={"a": 4})
        with pytest.raises(CoverageInvariantError):
            validate_coverage_row(row)

    def test_off_by_one_too_low_raises(self) -> None:
        row = _row(n_eligible=10, n_issued=7, n_withheld=2, withheld_reason_breakdown={"a": 2})
        with pytest.raises(CoverageInvariantError):
            validate_coverage_row(row)


# ============================================================================
# validate_coverage_row — breakdown sum tamper
# ============================================================================


class TestValidateCoverageRowBreakdownSumTamper:
    """sum(withheld_reason_breakdown) != n_withheld → CoverageInvariantError."""

    def test_breakdown_sum_too_high_raises(self) -> None:
        # Partition sum is correct (7+3=10), but breakdown sums to 4
        row = _row(
            n_eligible=10,
            n_issued=7,
            n_withheld=3,
            withheld_reason_breakdown={"a": 2, "b": 2},
        )
        with pytest.raises(CoverageInvariantError):
            validate_coverage_row(row)

    def test_breakdown_sum_too_low_raises(self) -> None:
        row = _row(
            n_eligible=10,
            n_issued=7,
            n_withheld=3,
            withheld_reason_breakdown={"a": 1},
        )
        with pytest.raises(CoverageInvariantError):
            validate_coverage_row(row)

    def test_error_message_contains_tick_id(self) -> None:
        row = _row(
            tick_id="bd-tick",
            n_eligible=10,
            n_issued=7,
            n_withheld=3,
            withheld_reason_breakdown={"a": 1},
        )
        with pytest.raises(CoverageInvariantError, match="bd-tick"):
            validate_coverage_row(row)

    def test_error_message_contains_sum_info(self) -> None:
        row = _row(
            n_eligible=10,
            n_issued=7,
            n_withheld=3,
            withheld_reason_breakdown={"a": 1},
        )
        with pytest.raises(CoverageInvariantError) as exc_info:
            validate_coverage_row(row)
        msg = str(exc_info.value)
        # breakdown sum (1) and n_withheld (3) should appear
        assert "1" in msg
        assert "3" in msg

    def test_empty_breakdown_with_nonzero_withheld_raises(self) -> None:
        row = _row(
            n_eligible=5,
            n_issued=3,
            n_withheld=2,
            withheld_reason_breakdown={},
        )
        with pytest.raises(CoverageInvariantError):
            validate_coverage_row(row)

    def test_non_empty_breakdown_with_zero_withheld_raises(self) -> None:
        row = _row(
            n_eligible=5,
            n_issued=5,
            n_withheld=0,
            withheld_reason_breakdown={"phantom": 1},
        )
        with pytest.raises(CoverageInvariantError):
            validate_coverage_row(row)

    def test_partition_sum_checked_before_breakdown_sum(self) -> None:
        """If both partition sum AND breakdown sum are wrong, the partition
        error fires first (invariant ordering matches source code)."""
        row = _row(
            n_eligible=10,
            n_issued=4,  # 4+4=8 != 10 → partition error fires
            n_withheld=4,
            withheld_reason_breakdown={"a": 99},  # breakdown also wrong
        )
        with pytest.raises(CoverageInvariantError) as exc_info:
            validate_coverage_row(row)
        # Should contain n_issued + n_withheld language (from partition check)
        msg = str(exc_info.value)
        assert "n_issued" in msg or "n_withheld" in msg or "n_eligible" in msg


# ============================================================================
# validate_coverage_row — negative count tampers
# ============================================================================


class TestValidateCoverageRowNegativeCounts:
    """Negative integers anywhere must be rejected."""

    def test_negative_n_eligible_raises(self) -> None:
        row = _row(n_eligible=-1, n_issued=0, n_withheld=0, withheld_reason_breakdown={})
        with pytest.raises(CoverageInvariantError):
            validate_coverage_row(row)

    def test_negative_n_issued_raises(self) -> None:
        row = CoverageRow(
            tick_id="t",
            n_eligible=5,
            n_issued=-1,
            n_withheld=6,
            withheld_reason_breakdown={"a": 6},
        )
        with pytest.raises(CoverageInvariantError):
            validate_coverage_row(row)

    def test_negative_n_withheld_raises(self) -> None:
        row = CoverageRow(
            tick_id="t",
            n_eligible=5,
            n_issued=6,
            n_withheld=-1,
            withheld_reason_breakdown={"a": -1},
        )
        with pytest.raises(CoverageInvariantError):
            validate_coverage_row(row)

    def test_negative_breakdown_value_raises(self) -> None:
        # Partition sum correct but breakdown has a negative bucket
        row = _row(
            n_eligible=10,
            n_issued=7,
            n_withheld=3,
            withheld_reason_breakdown={"good": 5, "bad": -2},
        )
        with pytest.raises(CoverageInvariantError):
            validate_coverage_row(row)

    def test_negative_counts_error_mentions_counts(self) -> None:
        row = _row(n_eligible=-5, n_issued=0, n_withheld=0, withheld_reason_breakdown={})
        with pytest.raises(CoverageInvariantError) as exc_info:
            validate_coverage_row(row)
        assert "non-negative" in str(exc_info.value) or "-5" in str(exc_info.value)


# ============================================================================
# CoverageSumInvariantCheck — no coverage directory
# ============================================================================


class TestCoverageSumInvariantCheckNoCoverageDir:
    _PLUGIN = CoverageSumInvariantCheck

    def test_absent_coverage_dir_returns_pass(self, tmp_path: Path) -> None:
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is True
        assert result.reason_code == "PASS"

    def test_absent_coverage_dir_detail_mentions_absent(self, tmp_path: Path) -> None:
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert "absent" in result.detail.lower() or "no rows" in result.detail.lower()

    def test_absent_coverage_dir_files_audited_is_empty(self, tmp_path: Path) -> None:
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.files_audited == ()


# ============================================================================
# CoverageSumInvariantCheck — empty coverage directory
# ============================================================================


class TestCoverageSumInvariantCheckEmptyCoverageDir:
    _PLUGIN = CoverageSumInvariantCheck

    def test_empty_dir_returns_pass(self, tmp_path: Path) -> None:
        (tmp_path / "coverage").mkdir()
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is True
        assert result.reason_code == "PASS"

    def test_empty_dir_files_audited_is_empty(self, tmp_path: Path) -> None:
        (tmp_path / "coverage").mkdir()
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.files_audited == ()

    def test_non_json_files_in_coverage_dir_are_skipped(self, tmp_path: Path) -> None:
        cov_dir = tmp_path / "coverage"
        cov_dir.mkdir()
        (cov_dir / "README.txt").write_text("ignore me", encoding="utf-8")
        (cov_dir / "notes.md").write_text("also ignore", encoding="utf-8")
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is True


# ============================================================================
# CoverageSumInvariantCheck — all valid rows
# ============================================================================


class TestCoverageSumInvariantCheckValidRows:
    _PLUGIN = CoverageSumInvariantCheck

    def test_single_valid_row_returns_pass(self, tmp_path: Path) -> None:
        _write_coverage_json(
            tmp_path / "coverage" / "row_001.json",
            _valid_payload(),
        )
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is True
        assert result.reason_code == "PASS"

    def test_multiple_valid_rows_returns_pass(self, tmp_path: Path) -> None:
        cov_dir = tmp_path / "coverage"
        cov_dir.mkdir()
        for i in range(5):
            breakdown = {"reason": i} if i > 0 else {}
            _write_coverage_json(
                cov_dir / f"row_{i:03d}.json",
                _valid_payload(
                    tick_id=f"t-{i:03d}",
                    n_eligible=10,
                    n_issued=10 - i,
                    n_withheld=i,
                    breakdown=breakdown,
                ),
            )
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is True

    def test_pass_detail_mentions_file_count(self, tmp_path: Path) -> None:
        cov_dir = tmp_path / "coverage"
        cov_dir.mkdir()
        for i in range(3):
            _write_coverage_json(
                cov_dir / f"row_{i}.json",
                _valid_payload(tick_id=f"t-{i}", n_eligible=5, n_issued=5, n_withheld=0, breakdown={}),
            )
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert "3" in result.detail

    def test_pass_files_audited_lists_all_json_files(self, tmp_path: Path) -> None:
        cov_dir = tmp_path / "coverage"
        cov_dir.mkdir()
        for i in range(4):
            _write_coverage_json(
                cov_dir / f"r{i}.json",
                _valid_payload(tick_id=f"t{i}", n_eligible=2, n_issued=2, n_withheld=0, breakdown={}),
            )
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert len(result.files_audited) == 4

    def test_valid_row_with_zero_withheld_passes(self, tmp_path: Path) -> None:
        _write_coverage_json(
            tmp_path / "coverage" / "all_issued.json",
            _valid_payload(n_eligible=5, n_issued=5, n_withheld=0, breakdown={}),
        )
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is True


# ============================================================================
# CoverageSumInvariantCheck — COVERAGE_SUM_MISMATCH
# ============================================================================


class TestCoverageSumInvariantCheckPartitionMismatch:
    _PLUGIN = CoverageSumInvariantCheck

    def test_partition_mismatch_returns_coverage_sum_mismatch(self, tmp_path: Path) -> None:
        _write_coverage_json(
            tmp_path / "coverage" / "bad.json",
            {
                "tick_id": "t-bad",
                "n_eligible": 10,
                "n_issued": 5,
                "n_withheld": 7,  # 5+7=12 != 10
                "withheld_reason_breakdown": {"a": 7},
            },
        )
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "COVERAGE_SUM_MISMATCH"

    def test_mismatch_sum_too_low_returns_coverage_sum_mismatch(self, tmp_path: Path) -> None:
        _write_coverage_json(
            tmp_path / "coverage" / "low.json",
            {
                "tick_id": "t-low",
                "n_eligible": 10,
                "n_issued": 3,
                "n_withheld": 3,  # 3+3=6 != 10
                "withheld_reason_breakdown": {"x": 3},
            },
        )
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "COVERAGE_SUM_MISMATCH"

    def test_mismatch_detail_contains_tick_id(self, tmp_path: Path) -> None:
        _write_coverage_json(
            tmp_path / "coverage" / "r.json",
            {
                "tick_id": "sentinel-tick-id",
                "n_eligible": 10,
                "n_issued": 6,
                "n_withheld": 6,
                "withheld_reason_breakdown": {"a": 6},
            },
        )
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert "sentinel-tick-id" in result.detail

    def test_mismatch_detail_contains_file_name(self, tmp_path: Path) -> None:
        _write_coverage_json(
            tmp_path / "coverage" / "distinctive_filename.json",
            {
                "tick_id": "t",
                "n_eligible": 10,
                "n_issued": 6,
                "n_withheld": 6,
                "withheld_reason_breakdown": {"a": 6},
            },
        )
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert "distinctive_filename" in result.detail

    def test_files_audited_includes_bad_file(self, tmp_path: Path) -> None:
        _write_coverage_json(
            tmp_path / "coverage" / "bad.json",
            {
                "tick_id": "t",
                "n_eligible": 10,
                "n_issued": 6,
                "n_withheld": 6,
                "withheld_reason_breakdown": {"a": 6},
            },
        )
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert any("bad.json" in f for f in result.files_audited)


# ============================================================================
# CoverageSumInvariantCheck — WITHHELD_REASON_SUM_MISMATCH
# ============================================================================


class TestCoverageSumInvariantCheckBreakdownMismatch:
    _PLUGIN = CoverageSumInvariantCheck

    def test_breakdown_mismatch_returns_withheld_reason_sum_mismatch(
        self, tmp_path: Path
    ) -> None:
        _write_coverage_json(
            tmp_path / "coverage" / "bd.json",
            {
                "tick_id": "t-bd",
                "n_eligible": 10,
                "n_issued": 7,
                "n_withheld": 3,
                "withheld_reason_breakdown": {"a": 1, "b": 1},  # sums to 2, not 3
            },
        )
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "WITHHELD_REASON_SUM_MISMATCH"

    def test_breakdown_over_count_returns_withheld_reason_sum_mismatch(
        self, tmp_path: Path
    ) -> None:
        _write_coverage_json(
            tmp_path / "coverage" / "over.json",
            {
                "tick_id": "t-over",
                "n_eligible": 10,
                "n_issued": 7,
                "n_withheld": 3,
                "withheld_reason_breakdown": {"a": 3, "b": 3},  # sums to 6, not 3
            },
        )
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "WITHHELD_REASON_SUM_MISMATCH"

    def test_breakdown_mismatch_detail_contains_tick_id(self, tmp_path: Path) -> None:
        _write_coverage_json(
            tmp_path / "coverage" / "r.json",
            {
                "tick_id": "breakdown-tick",
                "n_eligible": 10,
                "n_issued": 7,
                "n_withheld": 3,
                "withheld_reason_breakdown": {"a": 1},
            },
        )
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert "breakdown-tick" in result.detail

    def test_empty_breakdown_with_nonzero_withheld_returns_mismatch(
        self, tmp_path: Path
    ) -> None:
        _write_coverage_json(
            tmp_path / "coverage" / "empty_bd.json",
            {
                "tick_id": "t",
                "n_eligible": 10,
                "n_issued": 7,
                "n_withheld": 3,
                "withheld_reason_breakdown": {},
            },
        )
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "WITHHELD_REASON_SUM_MISMATCH"

    def test_breakdown_absent_from_payload_treated_as_empty_dict(
        self, tmp_path: Path
    ) -> None:
        """withheld_reason_breakdown key missing → defaults to {} → mismatch if n_withheld>0."""
        _write_coverage_json(
            tmp_path / "coverage" / "no_bd_key.json",
            {
                "tick_id": "t",
                "n_eligible": 10,
                "n_issued": 7,
                "n_withheld": 3,
                # withheld_reason_breakdown absent
            },
        )
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "WITHHELD_REASON_SUM_MISMATCH"

    def test_breakdown_absent_zero_withheld_passes(self, tmp_path: Path) -> None:
        """withheld_reason_breakdown absent + n_withheld=0 → {} sums to 0 → PASS."""
        _write_coverage_json(
            tmp_path / "coverage" / "zero_wd.json",
            {
                "tick_id": "t",
                "n_eligible": 5,
                "n_issued": 5,
                "n_withheld": 0,
                # no withheld_reason_breakdown key
            },
        )
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is True
        assert result.reason_code == "PASS"


# ============================================================================
# CoverageSumInvariantCheck — COVERAGE_PARSE_ERROR
# ============================================================================


class TestCoverageSumInvariantCheckParseError:
    _PLUGIN = CoverageSumInvariantCheck

    def test_invalid_json_returns_parse_error(self, tmp_path: Path) -> None:
        cov_dir = tmp_path / "coverage"
        cov_dir.mkdir()
        (cov_dir / "garbage.json").write_text("{not valid json", encoding="utf-8")
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "COVERAGE_PARSE_ERROR"

    def test_missing_tick_id_key_returns_parse_error(self, tmp_path: Path) -> None:
        _write_coverage_json(
            tmp_path / "coverage" / "no_tick.json",
            {"n_eligible": 5, "n_issued": 5, "n_withheld": 0},  # missing tick_id
        )
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "COVERAGE_PARSE_ERROR"

    def test_missing_n_eligible_key_returns_parse_error(self, tmp_path: Path) -> None:
        _write_coverage_json(
            tmp_path / "coverage" / "no_eligible.json",
            {"tick_id": "t", "n_issued": 5, "n_withheld": 0},
        )
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "COVERAGE_PARSE_ERROR"

    def test_non_numeric_count_returns_parse_error(self, tmp_path: Path) -> None:
        _write_coverage_json(
            tmp_path / "coverage" / "string_count.json",
            {
                "tick_id": "t",
                "n_eligible": "ten",  # not an int
                "n_issued": 5,
                "n_withheld": 0,
                "withheld_reason_breakdown": {},
            },
        )
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "COVERAGE_PARSE_ERROR"

    def test_parse_error_detail_contains_file_name(self, tmp_path: Path) -> None:
        cov_dir = tmp_path / "coverage"
        cov_dir.mkdir()
        (cov_dir / "named_bad_file.json").write_text("!!!!", encoding="utf-8")
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert "named_bad_file.json" in result.detail

    def test_empty_json_file_returns_parse_error(self, tmp_path: Path) -> None:
        cov_dir = tmp_path / "coverage"
        cov_dir.mkdir()
        (cov_dir / "empty.json").write_bytes(b"")
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "COVERAGE_PARSE_ERROR"


# ============================================================================
# CoverageSumInvariantCheck — multi-file scan ordering
# ============================================================================


class TestCoverageSumInvariantCheckMultiFileScan:
    """Plugin iterates sorted file names and returns on the first violation."""

    _PLUGIN = CoverageSumInvariantCheck

    def test_valid_before_invalid_still_catches_invalid(self, tmp_path: Path) -> None:
        cov_dir = tmp_path / "coverage"
        cov_dir.mkdir()
        _write_coverage_json(
            cov_dir / "aaa_valid.json",
            _valid_payload(tick_id="ok"),
        )
        _write_coverage_json(
            cov_dir / "zzz_bad.json",
            {
                "tick_id": "bad",
                "n_eligible": 10,
                "n_issued": 5,
                "n_withheld": 7,
                "withheld_reason_breakdown": {"a": 7},
            },
        )
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "COVERAGE_SUM_MISMATCH"

    def test_first_sorted_bad_file_is_reported(self, tmp_path: Path) -> None:
        """With two bad files, the lexicographically-first one is reported."""
        cov_dir = tmp_path / "coverage"
        cov_dir.mkdir()
        _write_coverage_json(
            cov_dir / "a_mismatch.json",
            {
                "tick_id": "first-bad",
                "n_eligible": 10,
                "n_issued": 6,
                "n_withheld": 6,
                "withheld_reason_breakdown": {"a": 6},
            },
        )
        _write_coverage_json(
            cov_dir / "z_mismatch.json",
            {
                "tick_id": "second-bad",
                "n_eligible": 10,
                "n_issued": 6,
                "n_withheld": 6,
                "withheld_reason_breakdown": {"a": 6},
            },
        )
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert "first-bad" in result.detail
        assert "second-bad" not in result.detail

    def test_partition_mismatch_takes_priority_over_breakdown_mismatch(
        self, tmp_path: Path
    ) -> None:
        """Within a single file, partition check fires before breakdown check."""
        cov_dir = tmp_path / "coverage"
        cov_dir.mkdir()
        _write_coverage_json(
            cov_dir / "both_bad.json",
            {
                "tick_id": "both-bad",
                "n_eligible": 10,
                "n_issued": 6,
                "n_withheld": 6,  # 6+6=12 != 10 → partition fires first
                "withheld_reason_breakdown": {"a": 1},  # also wrong
            },
        )
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is False
        assert result.reason_code == "COVERAGE_SUM_MISMATCH"

    def test_files_audited_grows_until_violation_found(self, tmp_path: Path) -> None:
        """files_audited contains all files scanned up to and including the bad one."""
        cov_dir = tmp_path / "coverage"
        cov_dir.mkdir()
        for i in range(3):
            _write_coverage_json(
                cov_dir / f"good_{i:02d}.json",
                _valid_payload(tick_id=f"t{i}", n_eligible=5, n_issued=5, n_withheld=0, breakdown={}),
            )
        _write_coverage_json(
            cov_dir / "zz_bad.json",
            {
                "tick_id": "tb",
                "n_eligible": 10,
                "n_issued": 6,
                "n_withheld": 6,
                "withheld_reason_breakdown": {"a": 6},
            },
        )
        result = self._PLUGIN().check(tmp_path, _Manifest())
        assert result.ok is False
        # Should have 4 files in files_audited (3 good + 1 bad)
        assert len(result.files_audited) == 4


# ============================================================================
# CoverageSumInvariantCheck — plugin contract conformance
# ============================================================================


class TestCoverageSumInvariantPluginContract:
    """Checks that CoverageSumInvariantCheck satisfies the TypedCheck Protocol."""

    def test_plugin_has_name_attribute(self) -> None:
        plugin = CoverageSumInvariantCheck()
        assert isinstance(plugin.name, str)
        assert plugin.name

    def test_plugin_has_applies_to_files_attribute(self) -> None:
        plugin = CoverageSumInvariantCheck()
        assert isinstance(plugin.applies_to_files, frozenset)

    def test_plugin_check_returns_plugin_result(self, tmp_path: Path) -> None:
        from audit_bundle.plugin import PluginResult

        result = CoverageSumInvariantCheck().check(tmp_path, _Manifest())
        assert isinstance(result, PluginResult)

    def test_plugin_result_ok_is_bool(self, tmp_path: Path) -> None:
        result = CoverageSumInvariantCheck().check(tmp_path, _Manifest())
        assert isinstance(result.ok, bool)

    def test_plugin_result_reason_code_is_str(self, tmp_path: Path) -> None:
        result = CoverageSumInvariantCheck().check(tmp_path, _Manifest())
        assert isinstance(result.reason_code, str)

    def test_plugin_result_files_audited_is_tuple(self, tmp_path: Path) -> None:
        result = CoverageSumInvariantCheck().check(tmp_path, _Manifest())
        assert isinstance(result.files_audited, tuple)
