"""credit_scoring_recompute.py — verifier-side credit-scoring re-derivation primitive.

Axis-2 value-return form (SPEC_PINNED_DISPATCH_ARCHITECTURE §3.3). Self-contained
per-dir migration of the credit_scoring_minimal pilot onto spec-pinned dispatch: the
recompute primitive lives HERE (verifier-distribution code, registered by the
spec-pinned builder / verify path), NOT in audit_bundle/rederivation/primitives/.

Re-derivation primitive (one sentence):
    verdict_list = ordered list, in sorted applicants/*.json file order, of
        [applicant_id, tier, decision] where PD = logistic(intercept + sum over
        feature_order of coef_i * applicant[feature_i]) using the bundled
        model/scorecard.json, and (tier, decision) is the bundled
        model/threshold_table.json tier whose [pd_min, pd_max) interval contains
        PD (last tier as fallback).

The representative output is the CATEGORICAL verdict only — [applicant_id, tier,
decision] triples, NO apr_pct float — so the `exact` comparator is FP-drift-safe:
the logistic PD is a float, but it is consumed only to select a categorical tier
(the threshold lookup), and only the resulting label strings are compared.

The replay rule (logistic PD, threshold-table lookup, sorted applicant order) is
FIXED in this primitive — the primitive_id ("credit_scoring_recompute") IS the
rule. The auditor's SHA-pinned spec binds the output type
"credit_scoring_verdict_list" to this primitive_id and to an `exact` comparator;
a producer cannot weaken the scorecard/threshold logic without changing the
primitive_id, which the anchor rejects.

Stdlib-only (§C5 contract; uses math for the logistic function). This module is
importable WITHOUT audit_bundle on sys.path (the RecomputedValue import is
deferred into recompute()), so the spec-pinned builder can import
compute_verdict_list() standalone.
"""

from __future__ import annotations

import json
import math
from pathlib import Path


# ---------------------------------------------------------------------------
# Canonical computation (shared by the builder and the verifier — ONE source)
# Mirrors the legacy pack (_build_bundle.py / credit_scoring_re_derivation.py)
# EXACTLY (contract C5): logistic PD + half-open [pd_min, pd_max) tier lookup.
# ---------------------------------------------------------------------------


def _compute_pd(applicant: dict, scorecard: dict) -> float:
    """Probability of default via the logistic function.

    linear_combination = intercept + sum(coef_i * feature_i) over coefficients;
    PD = 1 / (1 + exp(-linear_combination)). Mirrors the legacy pack exactly.
    """
    intercept = float(scorecard["intercept"])
    coefficients: dict = scorecard["coefficients"]
    linear_combination = intercept
    for feature, coef in coefficients.items():
        value = float(applicant[feature])
        linear_combination += float(coef) * value
    return 1.0 / (1.0 + math.exp(-linear_combination))


def _lookup_tier(pd: float, threshold_table: dict) -> dict:
    """Return the tier dict whose half-open [pd_min, pd_max) interval contains pd;
    the last tier is the fallback (PD exactly 1.0). Mirrors the legacy pack."""
    for tier in threshold_table["tiers"]:
        if float(tier["pd_min"]) <= pd < float(tier["pd_max"]):
            return tier
    return threshold_table["tiers"][-1]


def compute_verdict_list(
    applicants: list[dict], scorecard: dict, threshold_table: dict
) -> list[list[str]]:
    """Canonical re-derivation of the ordered categorical verdict list.

    `applicants` MUST already be in sorted applicants/*.json file order (the
    builder and the verifier both sort by filename). For each applicant: compute
    PD, look up the tier, emit [applicant_id, tier, decision]. Categorical
    output only (no apr_pct) — exact-safe. Builder and verifier share this ONE
    definition so the honest claimed list and the re-derivation cannot drift.
    """
    verdicts: list[list[str]] = []
    for app in applicants:
        pd = _compute_pd(app, scorecard)
        tier = _lookup_tier(pd, threshold_table)
        verdicts.append([str(app["applicant_id"]), str(tier["tier"]), str(tier["decision"])])
    return verdicts


def _load_sorted_applicants(applicants_dir: Path) -> list[dict]:
    """Load every applicants/*.json in sorted filename order (the canonical
    applicant order shared by builder and verifier)."""
    applicants: list[dict] = []
    for fpath in sorted(applicants_dir.glob("*.json")):
        applicants.append(json.loads(fpath.read_bytes()))
    return applicants


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered before BundleVerifier)
# ---------------------------------------------------------------------------


class CreditScoringRecompute:
    """Verifier-side primitive for re-deriving the per-applicant verdict list."""

    primitive_id: str = "credit_scoring_recompute"

    def recompute(self, inputs, pack_section: dict):
        """Recompute the verdict list from model/scorecard.json,
        model/threshold_table.json, and applicants/*.json.

        inputs.bundle_dir is a read-only Path. pack_section carries
        {output_id, type, params} from the auditor's spec binding. Returns a
        RecomputedValue carrying the [applicant_id, tier, decision] list; the
        verifier's `exact` comparator compares.
        """
        # Deferred import keeps this module importable standalone (builder use).
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        bundle_dir: Path = inputs.bundle_dir
        scorecard_path = bundle_dir / "model" / "scorecard.json"
        threshold_path = bundle_dir / "model" / "threshold_table.json"
        applicants_dir = bundle_dir / "applicants"
        if not scorecard_path.is_file():
            raise FileNotFoundError(
                f"model/scorecard.json not found in bundle at {bundle_dir}"
            )
        if not threshold_path.is_file():
            raise FileNotFoundError(
                f"model/threshold_table.json not found in bundle at {bundle_dir}"
            )
        if not applicants_dir.is_dir():
            raise FileNotFoundError(
                f"applicants/ not found in bundle at {bundle_dir}"
            )
        scorecard = json.loads(scorecard_path.read_bytes())
        threshold_table = json.loads(threshold_path.read_bytes())
        applicants = _load_sorted_applicants(applicants_dir)
        if not applicants:
            raise ValueError("applicants/ directory is empty — cannot re-derive")
        value = compute_verdict_list(applicants, scorecard, threshold_table)
        return RecomputedValue(
            value=value,
            detail=f"re-derived verdict list over {len(applicants)} applicant(s)",
        )
