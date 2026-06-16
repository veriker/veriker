#!/usr/bin/env python3
"""credit_scoring_re_derivation.py — stdlib re-derivation pack for the credit_scoring_minimal domain pilot.

the audit-bundle contract §C6 (domain-agnostic generalization) + AB4 (duplicate-don't-import).
Stdlib only (math, json, argparse, pathlib, sys).

Reads from --bundle-dir:
  model/scorecard.json           — logistic-regression-style coefficient table
  model/threshold_table.json     — PD-to-tier mapping
  applicants/<APP-ID>.json       — one file per applicant (credit attributes)
  payload/credit_decisions.json  — bundled credit decisions to re-derive

Re-derivation primitive:
  Replay each applicant's credit attributes through the bundled scorecard
  coefficients, recompute the probability-of-default (PD) score and the
  approve/decline + APR-tier verdict via the bundled threshold table.
  Assert the re-derived decisions match the bundled payload.

Exit 0 on full match; exit 1 on first mismatch with [CREDIT_SCORING_REDERIVATION_MISMATCH]
on stderr.

If any of the required input files are absent the bundle opted out of
credit-scoring re-derivation — exits 0.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------


def _load_json(path: Path, label: str) -> dict | None:
    """Load JSON from path; print error + return None on failure."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(
            f"[CREDIT_SCORING_REDERIVATION_MISMATCH] {label}: JSON parse error: {exc}",
            file=sys.stderr,
        )
        return None


def _load_applicants(bundle_dir: Path) -> list[dict] | None:
    """Load all applicant JSON files from applicants/."""
    applicants_dir = bundle_dir / "applicants"
    if not applicants_dir.is_dir():
        return None
    applicants: list[dict] = []
    for fpath in sorted(applicants_dir.glob("*.json")):
        data = _load_json(fpath, f"applicants/{fpath.name}")
        if data is None:
            return None
        applicants.append(data)
    return applicants


# ---------------------------------------------------------------------------
# Scoring logic — mirrors _build_bundle.py exactly (stdlib math.exp only)
# ---------------------------------------------------------------------------


def _compute_pd(applicant: dict, scorecard: dict) -> float:
    """Compute probability of default via logistic function.

    linear_combination = intercept + Σ(coef_i * feature_i)
    PD = 1 / (1 + exp(-linear_combination))
    """
    try:
        intercept = float(scorecard["intercept"])
        coefficients: dict = scorecard["coefficients"]
        linear_combination = intercept
        for feature, coef in coefficients.items():
            if feature not in applicant:
                print(
                    f"[CREDIT_SCORING_REDERIVATION_MISMATCH] applicant "
                    f"{applicant.get('applicant_id', '?')!r}: "
                    f"feature {feature!r} missing from applicant record",
                    file=sys.stderr,
                )
                return float("nan")
            value = float(applicant[feature])
            linear_combination += float(coef) * value
        return 1.0 / (1.0 + math.exp(-linear_combination))
    except (KeyError, TypeError, ValueError) as exc:
        print(
            f"[CREDIT_SCORING_REDERIVATION_MISMATCH] PD compute error "
            f"for applicant {applicant.get('applicant_id', '?')!r}: {exc}",
            file=sys.stderr,
        )
        return float("nan")


def _lookup_tier(pd: float, threshold_table: dict) -> dict | None:
    """Return the tier dict matching the given PD value."""
    try:
        for tier in threshold_table["tiers"]:
            if float(tier["pd_min"]) <= pd < float(tier["pd_max"]):
                return tier
        # Fallback: PD exactly at 1.0 falls in last tier
        return threshold_table["tiers"][-1]
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        print(
            f"[CREDIT_SCORING_REDERIVATION_MISMATCH] tier lookup error for pd={pd}: {exc}",
            file=sys.stderr,
        )
        return None


# ---------------------------------------------------------------------------
# Main verification logic
# ---------------------------------------------------------------------------


def _verify_decisions(
    applicants: list[dict],
    scorecard: dict,
    threshold_table: dict,
    bundled_payload: dict,
) -> bool:
    """Re-derive each decision and compare to the bundled payload.

    Returns True on full match, False on any mismatch (error printed to stderr).
    """
    # Index bundled decisions by applicant_id for fast lookup
    try:
        bundled_decisions: dict[str, dict] = {
            d["applicant_id"]: d for d in bundled_payload["decisions"]
        }
    except (KeyError, TypeError) as exc:
        print(
            f"[CREDIT_SCORING_REDERIVATION_MISMATCH] payload/credit_decisions.json: "
            f"malformed structure: {exc}",
            file=sys.stderr,
        )
        return False

    if len(applicants) != len(bundled_decisions):
        print(
            f"[CREDIT_SCORING_REDERIVATION_MISMATCH] applicant count mismatch: "
            f"bundle has {len(applicants)} applicants but payload has "
            f"{len(bundled_decisions)} decisions",
            file=sys.stderr,
        )
        return False

    for app in applicants:
        app_id = app.get("applicant_id", "<unknown>")

        # Re-derive PD
        pd = _compute_pd(app, scorecard)
        if math.isnan(pd):
            return False  # error already printed

        # Re-derive tier
        tier = _lookup_tier(pd, threshold_table)
        if tier is None:
            return False  # error already printed

        # Look up bundled decision for this applicant
        if app_id not in bundled_decisions:
            print(
                f"[CREDIT_SCORING_REDERIVATION_MISMATCH] applicant {app_id!r} "
                f"not found in bundled decisions",
                file=sys.stderr,
            )
            return False

        bundled = bundled_decisions[app_id]

        # Compare tier
        if tier["tier"] != bundled.get("tier"):
            print(
                f"[CREDIT_SCORING_REDERIVATION_MISMATCH] applicant {app_id!r}: "
                f"re-derived tier={tier['tier']!r} but bundled tier={bundled.get('tier')!r} "
                f"(re-derived pd={round(pd, 6)}, bundled pd={bundled.get('pd')})",
                file=sys.stderr,
            )
            return False

        # Compare decision (approve/decline)
        if tier["decision"] != bundled.get("decision"):
            print(
                f"[CREDIT_SCORING_REDERIVATION_MISMATCH] applicant {app_id!r}: "
                f"re-derived decision={tier['decision']!r} but bundled decision={bundled.get('decision')!r}",
                file=sys.stderr,
            )
            return False

        # Compare APR tier value
        apr = tier.get("apr_pct")
        bundled_apr = bundled.get("apr_pct")
        if apr != bundled_apr:
            print(
                f"[CREDIT_SCORING_REDERIVATION_MISMATCH] applicant {app_id!r}: "
                f"re-derived apr_pct={apr!r} but bundled apr_pct={bundled_apr!r}",
                file=sys.stderr,
            )
            return False

    return True


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Credit-scoring re-derivation check for credit_scoring_minimal audit bundles"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    # --- Opt-out check: if required inputs are absent, pass silently ---
    scorecard_path = bundle_dir / "model" / "scorecard.json"
    threshold_path = bundle_dir / "model" / "threshold_table.json"
    applicants_dir = bundle_dir / "applicants"
    payload_path = bundle_dir / "payload" / "credit_decisions.json"

    if not scorecard_path.exists() and not applicants_dir.is_dir():
        # Bundle opted out of credit-scoring re-derivation
        return 0

    # --- Load required inputs ---
    scorecard = _load_json(scorecard_path, "model/scorecard.json")
    if scorecard is None:
        if not scorecard_path.exists():
            return 0  # opted out
        return 1

    threshold_table = _load_json(threshold_path, "model/threshold_table.json")
    if threshold_table is None:
        if not threshold_path.exists():
            return 0  # opted out
        return 1

    applicants = _load_applicants(bundle_dir)
    if applicants is None:
        if not applicants_dir.is_dir():
            return 0  # opted out
        return 1

    if not applicants:
        print(
            "[CREDIT_SCORING_REDERIVATION_MISMATCH] applicants/ directory is empty",
            file=sys.stderr,
        )
        return 1

    bundled_payload = _load_json(payload_path, "payload/credit_decisions.json")
    if bundled_payload is None:
        if not payload_path.exists():
            return 0  # opted out
        return 1

    # --- Run re-derivation ---
    ok = _verify_decisions(applicants, scorecard, threshold_table, bundled_payload)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
