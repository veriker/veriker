"""coverage/protocol.py — EligibleTupleSet protocol + CoverageRow dataclass.

Implements the audit-bundle contract §C4 (coverage component).
Domain pilots implement EligibleTupleSet for their own sample space;
the framework enforces the sum invariant via validate_coverage_row.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CoverageInvariantError(ValueError):
    """Raised when a CoverageRow violates accounting invariants."""


# ---------------------------------------------------------------------------
# EligibleTupleSet Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class EligibleTupleSet(Protocol):
    """Sample space over which coverage is measured.

    Domain pilots implement this for their own population of eligible tuples.
    The protocol is kept deliberately minimal: callers only need to iterate
    and count.
    """

    def __iter__(self) -> Iterator: ...

    def __len__(self) -> int: ...


# ---------------------------------------------------------------------------
# CoverageRow
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CoverageRow:
    """One tick's coverage accounting record."""

    tick_id: str
    n_eligible: int
    n_issued: int
    n_withheld: int
    withheld_reason_breakdown: dict[str, int]


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_coverage_row(row: CoverageRow) -> None:
    """Raise CoverageInvariantError if row violates accounting invariants.

    Invariants checked:
      1. All counts are non-negative.
      2. n_issued + n_withheld == n_eligible  (partition sum).
      3. sum(withheld_reason_breakdown.values()) == n_withheld  (breakdown sum).
    """
    if row.n_eligible < 0 or row.n_issued < 0 or row.n_withheld < 0:
        raise CoverageInvariantError(
            f"tick_id={row.tick_id!r}: counts must be non-negative "
            f"(n_eligible={row.n_eligible}, n_issued={row.n_issued}, "
            f"n_withheld={row.n_withheld})"
        )

    if any(v < 0 for v in row.withheld_reason_breakdown.values()):
        raise CoverageInvariantError(
            f"tick_id={row.tick_id!r}: withheld_reason_breakdown contains "
            "negative values"
        )

    if row.n_issued + row.n_withheld != row.n_eligible:
        raise CoverageInvariantError(
            f"tick_id={row.tick_id!r}: n_issued ({row.n_issued}) + "
            f"n_withheld ({row.n_withheld}) != n_eligible ({row.n_eligible})"
        )

    breakdown_sum = sum(row.withheld_reason_breakdown.values())
    if breakdown_sum != row.n_withheld:
        raise CoverageInvariantError(
            f"tick_id={row.tick_id!r}: sum(withheld_reason_breakdown) "
            f"({breakdown_sum}) != n_withheld ({row.n_withheld})"
        )
