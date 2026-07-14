"""iso42001_external_reporting_recompute.py — verifier-side re-derivation of
externally-disclosed figures (ISO/IEC 42001 A.8).

Axis-2 value-return form (SPEC_PINNED_DISPATCH_ARCHITECTURE §3.3).

Domain: ISO/IEC 42001:2023 Annex A.8 (Information for Interested Parties) —
External Reporting. A 42001-conforming AIMS publishes aggregate figures to
outside stakeholders (regulators, users, the public) in transparency reports.
Those external parties ACT on the disclosed numbers, yet cannot check them
against the org's internal records. This pilot reconciles two disclosed figures
to the declared internal decision log:

  disclosed_automated_decision_count  (an integer, compared EXACT)
      = # records where automated is true
  disclosed_human_oversight_rate_pct  (a rate, compared scalar_epsilon)
      = 100 · (# automated AND human_reviewed) / (# automated)

Two primitives + two comparator KINDS: a disclosed count must match exactly; a
disclosed rate matches within a pinned epsilon. (Two distinct primitives means
the monotone-strictness invariant is satisfied trivially — neither primitive is
bound by >1 type.)

HONEST CLAIM BOUNDARY: proves the EXTERNALLY-DISCLOSED figures are RE-DERIVABLE
from the declared internal log and tamper-evident under the auditor's pinned
rules — i.e. the public number reconciles to the ledger. It does NOT prove the
log itself is complete or truthful, NOT that the disclosure is adequate, and NOT
that the org satisfies the A.8 control (which needs the reporting process the
AIMS owns). Synthetic data; no customer.

Stdlib-only (§C5 contract).
"""

from __future__ import annotations

import json
from pathlib import Path


# ---------------------------------------------------------------------------
# Canonical computations (shared by _build_bundle.py via direct import)
# ---------------------------------------------------------------------------


def _records(doc: dict) -> list:
    recs = doc.get("decisions")
    if not isinstance(recs, list) or not recs:
        raise ValueError("decision log must contain a non-empty 'decisions' array")
    return recs


def compute_automated_decision_count(records: list) -> int:
    """Number of decisions flagged automated (the disclosed denominator)."""
    return sum(1 for r in records if bool(r.get("automated")) is True)


def compute_human_oversight_rate_pct(records: list) -> float:
    """Percent of automated decisions that received human review before action."""
    automated = [r for r in records if bool(r.get("automated")) is True]
    if not automated:
        raise ValueError("no automated decisions — oversight rate undefined")
    reviewed = sum(1 for r in automated if bool(r.get("human_reviewed")) is True)
    return 100.0 * reviewed / len(automated)


# ---------------------------------------------------------------------------
# ReDerivationPrimitive classes (registered by verify.py before BundleVerifier)
# ---------------------------------------------------------------------------


def _load_decisions(inputs) -> list:
    bundle_dir: Path = inputs.bundle_dir
    log_path = bundle_dir / "inputs" / "decision_log.json"
    if not log_path.is_file():
        raise FileNotFoundError(
            f"inputs/decision_log.json not found in bundle at {bundle_dir}"
        )
    return _records(json.loads(log_path.read_bytes()))


class Iso42001DecisionCountRecompute:
    """Re-derives the disclosed automated-decision count (compared EXACT)."""

    primitive_id: str = "iso42001_decision_count_recompute"

    def recompute(self, inputs, pack_section: dict):
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        records = _load_decisions(inputs)
        value = compute_automated_decision_count(records)
        return RecomputedValue(
            value=value,
            detail=f"re-derived automated-decision count over {len(records)} records",
        )


class Iso42001OversightRateRecompute:
    """Re-derives the disclosed human-oversight rate (compared scalar_epsilon)."""

    primitive_id: str = "iso42001_oversight_rate_recompute"

    def recompute(self, inputs, pack_section: dict):
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        records = _load_decisions(inputs)
        value = compute_human_oversight_rate_pct(records)
        n_auto = compute_automated_decision_count(records)
        return RecomputedValue(
            value=value,
            detail=f"re-derived human-oversight rate over {n_auto} automated decisions",
        )
