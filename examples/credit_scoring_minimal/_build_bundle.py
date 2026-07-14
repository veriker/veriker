"""_build_bundle.py — build a deterministic credit_scoring_minimal audit bundle.

Bank consumer-credit decisioning (loan-approval scorecard) demonstration,
anchored to the Brazilian regulatory surface a lender like Banco Inter faces.

Brazilian regulatory mapping (verified 2026-05-29 — citations in the deck's
inter_regulatory_backbone_2026-05-29.md):
  LGPD (Lei 13.709/2018) art. 20 — IN FORCE. A data subject may request review of
    a solely-automated decision affecting their interests (incl. credit profile);
    the controller must give "clear and adequate information on the criteria and
    procedures" used. Re-deriving the PD + approve/decline + rate from the bundled
    scorecard + attributes IS that information, produced mechanically.
  PL 2338/2023 (Marco Legal da IA) — BILL, not enacted (Senate-approved 2024-12-10,
    in the Câmara dos Deputados since 2025-03-17). Classifies credit evaluation /
    granting as "high-risk", triggering algorithmic-impact-assessment duties.

This pilot models a traditional ML scorecard (logistic-regression-style
coefficient table over a Serasa-style 0–1000 credit score) — a deterministic
decision whose criteria art. 20 requires the lender be able to explain.

Re-derivation primitive:
  Replay the applicant's credit attributes through the bundled scorecard
  coefficients (scorecard.json), recompute the probability-of-default (PD)
  score and the approve/decline + APR-tier verdict via the bundled threshold
  table (threshold_table.json) — assert the bundled output matches.

Exercises two V-Kernel extension points:
  OpaqueFragment(source_cid, kind_tag="credit_attribute", locator={...})
    — one fragment anchor per credit-bureau-sourced attribute per applicant
  DispatchRecordWellformedCheck(op_kinds_admitted=frozenset({"SCORECARD_EVAL", "COMPUTE"}))
    — admits the new "SCORECARD_EVAL" op kind defined by this domain pilot

source_attributes (vendor-data lineage demo):
  Each credit_attribute snapshot is tagged with publication_class="regulatory"
  to signal credit-bureau (Serasa / Boa Vista / SPC style) provenance.

Usage (from v-kernel-audit-bundle root):
    python examples/credit_scoring_minimal/_build_bundle.py --out-dir /tmp/credit_scoring_bundle

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.emitter import BundleContent, write_bundle
from audit_bundle.fragments.fragment_id import (
    OpaqueFragment,
    fragment_to_canonical_dict,
)
from audit_bundle.snapshots.cid import compute_cid
from audit_bundle.snapshots.snapshot_policy import (
    default_v1_policy,
    policy_to_canonical_dict,
)
from audit_bundle.source_registry.properties import (
    PublicationClass,
    SourceProperties,
    properties_to_canonical_dict,
)

# ---------------------------------------------------------------------------
# Bundle-level constants
# ---------------------------------------------------------------------------

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "credit-scoring-minimal-rc"
_CREATED_AT = "2026-05-19T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
    "credit_scoring_re_derivation",
    "dispatch_record_wellformed",
]

# ---------------------------------------------------------------------------
# Scorecard coefficients (logistic-regression style)
# 5 features: serasa_score, utilization_pct, tradeline_count, dti_pct, derog_marks
#
# Chosen so that:
#   applicant_1 (prime):        PD ≈ 0.04 → approve tier A
#   applicant_2 (near-prime):   PD ≈ 0.14 → approve tier B
#   applicant_3 (subprime):     PD ≈ 0.28 → approve tier C
#   applicant_4 (decline):      PD ≈ 0.52 → decline
#   applicant_5 (marginal-A):   PD ≈ 0.07 → approve tier A
# ---------------------------------------------------------------------------

_SCORECARD: dict = {
    "model_name": "credit_scoring_v1",
    "model_version": "1.0.0",
    "feature_order": [
        "serasa_score",
        "utilization_pct",
        "tradeline_count",
        "dti_pct",
        "derog_marks",
    ],
    "intercept": 4.0,
    "coefficients": {
        "serasa_score": -0.012,
        "utilization_pct": 0.030,
        "tradeline_count": -0.060,
        "dti_pct": 0.045,
        "derog_marks": 0.900,
    },
    "schema": "scorecard-v1",
}

# ---------------------------------------------------------------------------
# Threshold table — maps PD ranges to decision tiers
# ---------------------------------------------------------------------------

_THRESHOLD_TABLE: dict = {
    "schema": "threshold-table-v1",
    "tiers": [
        {
            "tier": "A",
            "pd_min": 0.00,
            "pd_max": 0.10,
            "decision": "approve",
            "apr_pct": 6.99,
        },
        {
            "tier": "B",
            "pd_min": 0.10,
            "pd_max": 0.20,
            "decision": "approve",
            "apr_pct": 12.99,
        },
        {
            "tier": "C",
            "pd_min": 0.20,
            "pd_max": 0.40,
            "decision": "approve",
            "apr_pct": 21.99,
        },
        {
            "tier": "D",
            "pd_min": 0.40,
            "pd_max": 1.00,
            "decision": "decline",
            "apr_pct": None,
        },
    ],
}

# ---------------------------------------------------------------------------
# Synthetic applicants — 5 applicants with realistic-shape credit attributes
# ---------------------------------------------------------------------------

_APPLICANTS: list[dict] = [
    {
        "applicant_id": "APP-001",
        "serasa_score": 780,
        "utilization_pct": 8.0,
        "tradeline_count": 15,
        "dti_pct": 22.0,
        "derog_marks": 0,
        "loan_purpose": "home_improvement",
        "loan_amount_brl": 25000,
    },
    {
        "applicant_id": "APP-002",
        "serasa_score": 660,
        "utilization_pct": 45.0,
        "tradeline_count": 8,
        "dti_pct": 35.0,
        "derog_marks": 1,
        "loan_purpose": "debt_consolidation",
        "loan_amount_brl": 15000,
    },
    {
        "applicant_id": "APP-003",
        "serasa_score": 610,
        "utilization_pct": 70.0,
        "tradeline_count": 5,
        "dti_pct": 48.0,
        "derog_marks": 1,
        "loan_purpose": "auto",
        "loan_amount_brl": 18000,
    },
    {
        "applicant_id": "APP-004",
        "serasa_score": 580,
        "utilization_pct": 95.0,
        "tradeline_count": 3,
        "dti_pct": 58.0,
        "derog_marks": 3,
        "loan_purpose": "personal",
        "loan_amount_brl": 8000,
    },
    {
        "applicant_id": "APP-005",
        "serasa_score": 755,
        "utilization_pct": 15.0,
        "tradeline_count": 12,
        "dti_pct": 28.0,
        "derog_marks": 0,
        "loan_purpose": "home_improvement",
        "loan_amount_brl": 20000,
    },
]

# Credit-bureau-sourced attribute names (these become OpaqueFragment anchors)
_BUREAU_ATTRIBUTES = [
    "serasa_score",
    "utilization_pct",
    "tradeline_count",
    "dti_pct",
    "derog_marks",
]


# ---------------------------------------------------------------------------
# Scoring helpers (must be stdlib-only; matches credit_scoring_re_derivation.py)
# ---------------------------------------------------------------------------


def _compute_pd(applicant: dict, scorecard: dict) -> float:
    """Compute probability of default via logistic function."""
    intercept: float = float(scorecard["intercept"])
    coefficients: dict = scorecard["coefficients"]
    linear_combination = intercept
    for feature, coef in coefficients.items():
        value = float(applicant[feature])
        linear_combination += float(coef) * value
    return 1.0 / (1.0 + math.exp(-linear_combination))


def _lookup_tier(pd: float, threshold_table: dict) -> dict:
    """Return the tier dict matching the given PD."""
    for tier in threshold_table["tiers"]:
        if tier["pd_min"] <= pd < tier["pd_max"]:
            return tier
    # Fallback: highest PD falls in last tier
    return threshold_table["tiers"][-1]


# ---------------------------------------------------------------------------
# SHA helper
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def build(out_dir: Path) -> None:
    """Generate the full credit_scoring_minimal bundle under out_dir."""
    out_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # 1. Compute artifact bytes                                           #
    # ------------------------------------------------------------------ #
    scorecard_bytes = json.dumps(_SCORECARD, indent=2, sort_keys=True).encode("utf-8")

    threshold_bytes = json.dumps(_THRESHOLD_TABLE, indent=2, sort_keys=True).encode(
        "utf-8"
    )

    # ------------------------------------------------------------------ #
    # 2. Applicant bytes                                                  #
    # ------------------------------------------------------------------ #
    applicant_bytes: dict[str, bytes] = {}
    for app in _APPLICANTS:
        applicant_bytes[app["applicant_id"]] = json.dumps(
            app, indent=2, sort_keys=True
        ).encode("utf-8")

    # ------------------------------------------------------------------ #
    # 3. Compute credit decisions                                         #
    # ------------------------------------------------------------------ #
    decisions: list[dict] = []
    for app in _APPLICANTS:
        pd = _compute_pd(app, _SCORECARD)
        tier = _lookup_tier(pd, _THRESHOLD_TABLE)
        decisions.append(
            {
                "applicant_id": app["applicant_id"],
                "pd": round(pd, 6),
                "tier": tier["tier"],
                "decision": tier["decision"],
                "apr_pct": tier["apr_pct"],
            }
        )

    # Invariant check: at least one approve-A, one approve-C, one decline
    tiers_found = {d["tier"] for d in decisions}
    assert "A" in tiers_found, (
        f"Expected at least one Tier-A decision; got tiers={sorted(tiers_found)}"
    )
    assert "C" in tiers_found or "D" in tiers_found, (
        f"Expected at least one Tier-C or decline; got tiers={sorted(tiers_found)}"
    )
    decisions_with_decline = [d for d in decisions if d["decision"] == "decline"]
    assert len(decisions_with_decline) >= 1, (
        f"Expected at least one decline decision; got decisions={decisions}"
    )

    # ------------------------------------------------------------------ #
    # 4. payload/credit_decisions.json bytes                              #
    # ------------------------------------------------------------------ #
    decisions_payload = {
        "schema": "credit-decisions-v1",
        "scorecard_model": _SCORECARD["model_name"],
        "scorecard_version": _SCORECARD["model_version"],
        "decisions": decisions,
    }
    decisions_bytes = json.dumps(decisions_payload, indent=2, sort_keys=True).encode(
        "utf-8"
    )

    # ------------------------------------------------------------------ #
    # 5. snapshots/credit_bureau_attributes.json bytes + CID              #
    # (Represents the credit-bureau data pull — Serasa / Boa Vista / SPC style)            #
    # ------------------------------------------------------------------ #
    bureau_snapshot = {
        "schema": "bureau-snapshot-v1",
        "pull_date": _CREATED_AT,
        "bureau_vendor": "synthetic_bureau",
        "attributes": [
            {
                "applicant_id": app["applicant_id"],
                "serasa_score": app["serasa_score"],
                "utilization_pct": app["utilization_pct"],
                "tradeline_count": app["tradeline_count"],
                "dti_pct": app["dti_pct"],
                "derog_marks": app["derog_marks"],
            }
            for app in _APPLICANTS
        ],
    }
    bureau_bytes = json.dumps(bureau_snapshot, indent=2, sort_keys=True).encode("utf-8")

    # Compute CID for the bureau snapshot
    bureau_cid = compute_cid(bureau_bytes)

    # Write the snapshot file (not in manifest.files — covered by snapshots dict)
    snapshots_dir = out_dir / "snapshots"
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    (snapshots_dir / "credit_bureau_attributes.json").write_bytes(bureau_bytes)

    # ------------------------------------------------------------------ #
    # 6. Snapshots + snapshot_policy                                      #
    # ------------------------------------------------------------------ #
    snapshots: dict[str, str] = {
        bureau_cid: "snapshots/credit_bureau_attributes.json",
    }
    snapshot_policy = policy_to_canonical_dict(default_v1_policy())

    # ------------------------------------------------------------------ #
    # 7. source_attributes — credit-bureau vendor lineage tag (LGPD art. 20 context)     #
    # publication_class="regulatory" — credit bureau data is issued       #
    # under regulatory supervision (BACEN / CMN; LGPD art. 20)                    #
    # ------------------------------------------------------------------ #
    bureau_props = SourceProperties(
        source_cid=bureau_cid,
        issuer_identity_verified=False,  # synthetic: no real bureau verified
        issuer_identifier="synthetic_bureau",
        signed_artifact_present=False,
        signing_key_id=None,
        publication_class=PublicationClass.REGULATORY.value,
        external_status_flags=["lgpd_art20_automated_credit_decision"],
        schema_version="0.1",
    )
    source_attributes: dict[str, dict] = {
        bureau_cid: properties_to_canonical_dict(bureau_props),
    }

    # ------------------------------------------------------------------ #
    # 8. OpaqueFragment anchors — one per (applicant, bureau attribute)   #
    # ------------------------------------------------------------------ #
    fragment_anchors: dict[str, dict] = {}
    for app in _APPLICANTS:
        for attr_name in _BUREAU_ATTRIBUTES:
            frag = OpaqueFragment(
                source_cid=bureau_cid,
                kind_tag="credit_attribute",
                locator={
                    "applicant_id": app["applicant_id"],
                    "attribute_name": attr_name,
                },
            )
            anchor_key = f"{app['applicant_id']}_{attr_name}"
            fragment_anchors[anchor_key] = fragment_to_canonical_dict(frag)

    assert len(fragment_anchors) == len(_APPLICANTS) * len(_BUREAU_ATTRIBUTES), (
        f"Expected {len(_APPLICANTS) * len(_BUREAU_ATTRIBUTES)} fragment anchors; "
        f"got {len(fragment_anchors)}"
    )

    # ------------------------------------------------------------------ #
    # 9. dispatch_records — C15                                           #
    # One SCORECARD_EVAL record per applicant + one COMPUTE record        #
    # for the feature-prep / threshold-lookup pass.                       #
    # ------------------------------------------------------------------ #
    dispatch_records = []
    for app in _APPLICANTS:
        dispatch_records.append(
            {
                "schema_version": "0.1",
                "op": {
                    "kind": "SCORECARD_EVAL",
                    "name": "logistic_scorecard_pd_compute",
                },
                "inputs": [],
                "outputs": [],
                "effect": {},
                "locale": "pt-BR",
                "predicates": [app["applicant_id"]],
                "stamp_declared": "INTERNAL_BENCHMARK",
                "stamp_observed": None,
            }
        )
    # One COMPUTE record for the threshold-lookup pass
    dispatch_records.append(
        {
            "schema_version": "0.1",
            "op": {
                "kind": "COMPUTE",
                "name": "threshold_tier_lookup",
            },
            "inputs": [],
            "outputs": [],
            "effect": {},
            "locale": "pt-BR",
            "predicates": [app["applicant_id"] for app in _APPLICANTS],
            "stamp_declared": "INTERNAL_BENCHMARK",
            "stamp_observed": None,
        }
    )

    # ------------------------------------------------------------------ #
    # 10. Emit via the reference-emitter SDK                              #
    # ------------------------------------------------------------------ #
    bundle_files: dict[str, bytes] = {
        "model/scorecard.json": scorecard_bytes,
        "model/threshold_table.json": threshold_bytes,
        "payload/credit_decisions.json": decisions_bytes,
    }
    for app in _APPLICANTS:
        bundle_files[f"applicants/{app['applicant_id']}.json"] = applicant_bytes[
            app["applicant_id"]
        ]

    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files=bundle_files,
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=_TYPED_CHECKS,
        extra_manifest_fields={
            "snapshots": snapshots,
            "snapshot_policy": snapshot_policy,
            "fragment_anchors": fragment_anchors,
            "source_attributes": source_attributes,
            "dispatch_records": dispatch_records,
        },
    )
    write_bundle(out_dir, content)
    manifest_path = out_dir / "manifest.json"

    print(f"Bundle written to {out_dir}")
    print(f"  applicants            : {len(_APPLICANTS)}")
    decision_summary = [
        d["applicant_id"] + "->" + d["tier"] + "(" + d["decision"] + ")"
        for d in decisions
    ]
    print(f"  decisions             : {decision_summary}")
    print(
        f"  fragment anchors      : {len(fragment_anchors)} OpaqueFragment (kind_tag=credit_attribute)"
    )
    print(
        f"  source_attributes     : bureau_cid={bureau_cid[:20]}... (publication_class=regulatory)"
    )
    print(
        f"  dispatch_records      : {len(dispatch_records)} ({len(_APPLICANTS)} SCORECARD_EVAL + 1 COMPUTE)"
    )
    print(f"  manifest              : {manifest_path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic credit_scoring_minimal audit bundle (LGPD art. 20 / PL 2338)"
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
