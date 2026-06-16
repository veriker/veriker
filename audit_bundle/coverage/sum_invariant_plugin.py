"""coverage/sum_invariant_plugin.py — TypedCheck: coverage sum invariant (C4).

Implements the audit-bundle contract §C4.
Walks bundle_dir/coverage/*.json, parses each file as a CoverageRow JSON,
and enforces two accounting invariants:
  1. n_issued + n_withheld == n_eligible     → COVERAGE_SUM_MISMATCH
  2. sum(withheld_reason_breakdown) == n_withheld → WITHHELD_REASON_SUM_MISMATCH
Returns on the first violation found.

Schema discriminator: files carrying a top-level "runner" field (positive
marker for runner-output shape — e.g. ES-mode runner outputs like
coverage/<date>_es_mode.json) are skipped. Files that look CoverageRow-shaped
but are missing required fields still fail with COVERAGE_PARSE_ERROR.
"""

from __future__ import annotations

from pathlib import Path

from audit_bundle.admission import admit_json_file
from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult
from audit_bundle.coverage.protocol import CoverageRow


class CoverageSumInvariantCheck:
    name: str = "coverage_sum_invariant"
    # exact-path-only: the former {"coverage/"} trailing-slash pseudo-prefix
    # was inert (consumed by exact match, never matched a real path). Dropped.
    applies_to_files: frozenset[str] = frozenset()

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        coverage_dir = bundle_dir / "coverage"
        files_audited: list[str] = []

        if not coverage_dir.is_dir():
            return PluginResult(
                ok=True,
                reason_code="PASS",
                detail="coverage/ directory absent — no rows to check",
                files_audited=(),
            )

        json_files = sorted(coverage_dir.glob("*.json"))
        rows_checked = 0
        for json_path in json_files:
            try:
                raw = admit_json_file(json_path, check_name="coverage_sum_invariant")
            except (ValueError, OSError) as exc:
                files_audited.append(str(json_path))
                return PluginResult(
                    ok=False,
                    reason_code="COVERAGE_PARSE_ERROR",
                    detail=f"{json_path.name}: failed to parse JSON — {exc}",
                    files_audited=tuple(files_audited),
                )

            # Schema discriminator: skip files carrying the runner-output
            # shape (top-level "runner" field). They are co-located artifacts
            # (e.g. ES-mode runner outputs like 2026_05_01_es_mode.json) and
            # are not CoverageRows.
            if isinstance(raw, dict) and "runner" in raw:
                continue

            files_audited.append(str(json_path))
            try:
                row = CoverageRow(
                    tick_id=raw["tick_id"],
                    n_eligible=int(raw["n_eligible"]),
                    n_issued=int(raw["n_issued"]),
                    n_withheld=int(raw["n_withheld"]),
                    withheld_reason_breakdown=dict(
                        raw.get("withheld_reason_breakdown", {})
                    ),
                )
            except (KeyError, TypeError, ValueError) as exc:
                return PluginResult(
                    ok=False,
                    reason_code="COVERAGE_PARSE_ERROR",
                    detail=f"{json_path.name}: failed to parse as CoverageRow — {exc}",
                    files_audited=tuple(files_audited),
                )
            rows_checked += 1

            # Invariant 1: partition sum
            if row.n_issued + row.n_withheld != row.n_eligible:
                return PluginResult(
                    ok=False,
                    reason_code="COVERAGE_SUM_MISMATCH",
                    detail=(
                        f"{json_path.name} tick_id={row.tick_id!r}: "
                        f"n_issued ({row.n_issued}) + n_withheld ({row.n_withheld}) "
                        f"!= n_eligible ({row.n_eligible})"
                    ),
                    files_audited=tuple(files_audited),
                )

            # Invariant 2: withheld breakdown sum
            breakdown_sum = sum(row.withheld_reason_breakdown.values())
            if breakdown_sum != row.n_withheld:
                return PluginResult(
                    ok=False,
                    reason_code="WITHHELD_REASON_SUM_MISMATCH",
                    detail=(
                        f"{json_path.name} tick_id={row.tick_id!r}: "
                        f"sum(withheld_reason_breakdown) ({breakdown_sum}) "
                        f"!= n_withheld ({row.n_withheld})"
                    ),
                    files_audited=tuple(files_audited),
                )

        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail=(
                f"coverage sum invariant verified across {rows_checked} CoverageRow file(s); "
                f"{len(json_files) - rows_checked} non-CoverageRow file(s) skipped"
            ),
            files_audited=tuple(files_audited),
        )


register_typed_check("coverage_sum_invariant")
