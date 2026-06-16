"""_build_bundle.py — build a deterministic aml_txn_monitoring_minimal audit bundle.

Synthesises a 30-day transaction stream for 5 customers (3 COAF-report, 1 clean,
1 borderline-structuring edge case) and re-evaluates a JSON rule-tree to produce
a bundled COAF-report list.

Bundle layout (all written to --out-dir):
  transactions/transactions.jsonl     — raw synthetic transaction records
  rule_tree/rule_tree.json            — deterministic rule-tree spec
  baselines/customer_baselines.json   — peer-group means + stddevs
  payload/coaf_reports.json           — COAF-report decisions per customer

Exercises two V-Kernel extension points mirroring kg_minimal (commit d1d80a5e):
  OpaqueFragment(source_cid, kind_tag="transaction")
    — one fragment anchor per raw transaction record
  DispatchRecordWellformedCheck(op_kinds_admitted=frozenset({"RULE_TREE_EVAL", "COMPUTE"}))
    — one RULE_TREE_EVAL record and one COMPUTE record per customer

Brazilian regulatory surface (verified 2026-05-29 — citations in the deck's
inter_regulatory_backbone_2026-05-29.md):
  Circular BACEN nº 3.978/2020 (IN FORCE) + Lei 9.613/1998 — institutions must
  run risk-based PLD-FT (anti-money-laundering / counter-terrorism-financing)
  monitoring and report suspicious operations to COAF (via SISCOAF) by the next
  business day. The rule tree here is the bank's INTERNAL detection logic (its
  thresholds are the bank's own choice); the "COAF report" flag is the Brazilian
  equivalent of a suspicious-activity report. Statutory backdrop: the R$50,000
  cash-operation reporting threshold sits ABOVE the ~R$10,000 internal
  structuring-detection threshold this fixture illustrates (banks monitor below
  the statutory line precisely because structuring stays under thresholds).

Usage (from v-kernel-audit-bundle root):
    python examples/aml_txn_monitoring_minimal/_build_bundle.py --out-dir /tmp/aml_txn_monitoring_bundle

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone, timedelta
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
_BUNDLE_ID = "aml-txn-monitoring-minimal-rc"
_CREATED_AT = "2026-05-01T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
    "aml_txn_monitoring_re_derivation",
    "dispatch_record_wellformed",
]

# ---------------------------------------------------------------------------
# Rule-tree spec
# ---------------------------------------------------------------------------
# Deterministic rule-tree: three independent trigger conditions.
# Re-derivation pack must produce identical results when it walks these
# thresholds against the bundled transaction stream.
_RULE_TREE = {
    "version": "1.0",
    "description": "PLD-FT internal monitoring rule tree (Circular BACEN 3.978/2020; reports to COAF)",
    "rules": [
        {
            "rule_id": "R1",
            "name": "velocity_high",
            "description": "Count of transactions > R$10,000 in any 24-hour window > threshold",
            "threshold": 3,
            "condition": "velocity_24h_gt_10k > 3",
        },
        {
            "rule_id": "R2",
            "name": "structuring_proxy",
            "description": "Count of cash deposits in the R$9,000–R$9,999 range in any 7-day window > threshold",
            "threshold": 2,
            "condition": "structuring_proxy_7d > 2",
        },
        {
            "rule_id": "R3",
            "name": "peer_deviation",
            "description": "Absolute peer-group z-score of mean transaction size > threshold",
            "threshold": 3.0,
            "condition": "abs(peer_z_score) > 3.0",
        },
    ],
    "trigger": "ANY(R1, R2, R3)",
}

# ---------------------------------------------------------------------------
# Customer baselines (peer-group statistics)
# All five customers share the same peer group for demo purposes.
# ---------------------------------------------------------------------------
_CUSTOMER_BASELINES = {
    "peer_group": "retail_br",
    "mean_txn_size_brl": 2500.0,
    "stddev_txn_size_brl": 800.0,
    "customers": {
        "C001": {"segment": "retail"},
        "C002": {"segment": "retail"},
        "C003": {"segment": "retail"},
        "C004": {"segment": "retail"},
        "C005": {"segment": "retail"},
    },
}

# ---------------------------------------------------------------------------
# Synthetic transaction stream
# Base date: 2026-04-01 00:00:00 UTC.  All timestamps are deterministic.
# ---------------------------------------------------------------------------
_BASE_DATE = datetime(2026, 4, 1, 0, 0, 0, tzinfo=timezone.utc)


def _ts(day: int, hour: int = 10, minute: int = 0) -> str:
    """Return ISO-8601 UTC timestamp for given day-offset from _BASE_DATE."""
    return (_BASE_DATE + timedelta(days=day, hours=hour, minutes=minute)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _txn(
    txn_id: str,
    customer_id: str,
    amount_brl: float,
    txn_type: str,
    timestamp: str,
) -> dict:
    return {
        "txn_id": txn_id,
        "customer_id": customer_id,
        "amount_brl": amount_brl,
        "txn_type": txn_type,  # "cash_deposit" | "wire" | "ach"
        "timestamp": timestamp,
    }


# C001 — COAF report via VELOCITY (4 large wires in a single 24-h window)
_C001_TXNS = [
    _txn("T001-001", "C001", 12000.0, "wire", _ts(0, 9, 0)),
    _txn("T001-002", "C001", 15000.0, "wire", _ts(0, 11, 0)),
    _txn("T001-003", "C001", 11500.0, "wire", _ts(0, 13, 30)),
    _txn("T001-004", "C001", 13000.0, "wire", _ts(0, 16, 0)),
    # Normal activity outside trigger window
    _txn("T001-005", "C001", 2200.0, "ach", _ts(5)),
    _txn("T001-006", "C001", 1800.0, "ach", _ts(10)),
    _txn("T001-007", "C001", 900.0, "ach", _ts(15)),
    _txn("T001-008", "C001", 3100.0, "ach", _ts(20)),
    _txn("T001-009", "C001", 1400.0, "ach", _ts(25)),
]

# C002 — COAF report via STRUCTURING (3 cash deposits just below a R$10,000 internal threshold, 7-day window)
_C002_TXNS = [
    _txn("T002-001", "C002", 9500.0, "cash_deposit", _ts(0)),
    _txn("T002-002", "C002", 9800.0, "cash_deposit", _ts(2)),
    _txn("T002-003", "C002", 9200.0, "cash_deposit", _ts(4)),
    # Normal activity
    _txn("T002-004", "C002", 2000.0, "ach", _ts(8)),
    _txn("T002-005", "C002", 1500.0, "ach", _ts(12)),
    _txn("T002-006", "C002", 2800.0, "ach", _ts(16)),
    _txn("T002-007", "C002", 1200.0, "ach", _ts(20)),
    _txn("T002-008", "C002", 3000.0, "ach", _ts(24)),
    _txn("T002-009", "C002", 1700.0, "ach", _ts(28)),
]

# C003 — COAF report via PEER DEVIATION (mean txn size >> peer mean; z-score ~ +5)
# Peer mean=$2500, stddev=$800. Mean of C003 txns ≈ $6500 → z≈(6500-2500)/800 = 5.0
_C003_TXNS = [
    _txn("T003-001", "C003", 6000.0, "wire", _ts(1)),
    _txn("T003-002", "C003", 7200.0, "wire", _ts(3)),
    _txn("T003-003", "C003", 5800.0, "wire", _ts(6)),
    _txn("T003-004", "C003", 7000.0, "wire", _ts(9)),
    _txn("T003-005", "C003", 6500.0, "wire", _ts(12)),
    _txn("T003-006", "C003", 7500.0, "wire", _ts(15)),
    _txn("T003-007", "C003", 6200.0, "wire", _ts(18)),
    _txn("T003-008", "C003", 6800.0, "wire", _ts(21)),
    _txn("T003-009", "C003", 6400.0, "wire", _ts(24)),
    _txn("T003-010", "C003", 7100.0, "wire", _ts(27)),
]

# C004 — CLEAN customer (no triggers; demonstrates false-positive rate discipline)
_C004_TXNS = [
    _txn("T004-001", "C004", 1500.0, "ach", _ts(0)),
    _txn("T004-002", "C004", 2100.0, "ach", _ts(3)),
    _txn("T004-003", "C004", 1800.0, "ach", _ts(6)),
    _txn("T004-004", "C004", 2400.0, "ach", _ts(9)),
    _txn("T004-005", "C004", 1900.0, "ach", _ts(12)),
    _txn("T004-006", "C004", 2200.0, "ach", _ts(15)),
    _txn("T004-007", "C004", 1600.0, "ach", _ts(18)),
    _txn("T004-008", "C004", 2000.0, "ach", _ts(21)),
    _txn("T004-009", "C004", 2500.0, "ach", _ts(24)),
    _txn("T004-010", "C004", 1700.0, "ach", _ts(27)),
]

# C005 — Borderline structuring (2 just-below-threshold deposits, below the >2 rule)
_C005_TXNS = [
    _txn("T005-001", "C005", 9100.0, "cash_deposit", _ts(1)),
    _txn("T005-002", "C005", 9700.0, "cash_deposit", _ts(5)),
    # Normal activity — total structuring proxy = 2 (threshold is >2, so NOT triggered)
    _txn("T005-003", "C005", 2300.0, "ach", _ts(8)),
    _txn("T005-004", "C005", 1800.0, "ach", _ts(12)),
    _txn("T005-005", "C005", 2100.0, "ach", _ts(16)),
    _txn("T005-006", "C005", 1500.0, "ach", _ts(20)),
    _txn("T005-007", "C005", 2600.0, "ach", _ts(24)),
    _txn("T005-008", "C005", 1900.0, "ach", _ts(28)),
]

_ALL_TXNS = _C001_TXNS + _C002_TXNS + _C003_TXNS + _C004_TXNS + _C005_TXNS


# ---------------------------------------------------------------------------
# Feature computation (mirrors aml_txn_monitoring_re_derivation.py exactly)
# ---------------------------------------------------------------------------


def _parse_ts(ts_str: str) -> datetime:
    return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _compute_velocity_24h(txns: list[dict]) -> int:
    """Max count of transactions > R$10,000 in any 24-hour sliding window."""
    large = [t for t in txns if t["amount_brl"] > 10000.0]
    if not large:
        return 0
    large_sorted = sorted(large, key=lambda t: t["timestamp"])
    max_count = 0
    for i, anchor in enumerate(large_sorted):
        anchor_dt = _parse_ts(anchor["timestamp"])
        window_end = anchor_dt + timedelta(hours=24)
        count = sum(
            1
            for t in large_sorted
            if anchor_dt <= _parse_ts(t["timestamp"]) < window_end
        )
        if count > max_count:
            max_count = count
    return max_count


def _compute_structuring_proxy_7d(txns: list[dict]) -> int:
    """Max count of cash deposits in [$9,000, $10,000) in any 7-day sliding window."""
    near_threshold = [
        t
        for t in txns
        if t["txn_type"] == "cash_deposit" and 9000.0 <= t["amount_brl"] < 10000.0
    ]
    if not near_threshold:
        return 0
    sorted_t = sorted(near_threshold, key=lambda t: t["timestamp"])
    max_count = 0
    for anchor in sorted_t:
        anchor_dt = _parse_ts(anchor["timestamp"])
        window_end = anchor_dt + timedelta(days=7)
        count = sum(
            1 for t in sorted_t if anchor_dt <= _parse_ts(t["timestamp"]) < window_end
        )
        if count > max_count:
            max_count = count
    return max_count


def _compute_peer_z_score(
    txns: list[dict], peer_mean: float, peer_stddev: float
) -> float:
    """(mean txn size - peer mean) / peer stddev."""
    if not txns:
        return 0.0
    mean_size = sum(t["amount_brl"] for t in txns) / len(txns)
    return (mean_size - peer_mean) / peer_stddev


def _evaluate_rule_tree(velocity: int, structuring: int, peer_z: float) -> bool:
    """True if ANY rule fires."""
    return (
        velocity > _RULE_TREE["rules"][0]["threshold"]
        or structuring > _RULE_TREE["rules"][1]["threshold"]
        or abs(peer_z) > _RULE_TREE["rules"][2]["threshold"]
    )


def _compute_coaf_reports(txns: list[dict], baselines: dict) -> dict:
    """Compute COAF-report decisions for all customers. Returns mapping cid -> decision dict."""
    peer_mean = baselines["mean_txn_size_brl"]
    peer_stddev = baselines["stddev_txn_size_brl"]

    by_customer: dict[str, list[dict]] = {}
    for t in txns:
        by_customer.setdefault(t["customer_id"], []).append(t)

    results = {}
    for cid, ctxns in sorted(by_customer.items()):
        velocity = _compute_velocity_24h(ctxns)
        structuring = _compute_structuring_proxy_7d(ctxns)
        peer_z = _compute_peer_z_score(ctxns, peer_mean, peer_stddev)
        triggered = _evaluate_rule_tree(velocity, structuring, peer_z)
        rules_fired = []
        if velocity > _RULE_TREE["rules"][0]["threshold"]:
            rules_fired.append("R1")
        if structuring > _RULE_TREE["rules"][1]["threshold"]:
            rules_fired.append("R2")
        if abs(peer_z) > _RULE_TREE["rules"][2]["threshold"]:
            rules_fired.append("R3")
        results[cid] = {
            "customer_id": cid,
            "coaf_report_triggered": triggered,
            "rules_fired": rules_fired,
            "features": {
                "velocity_24h_gt_10k": velocity,
                "structuring_proxy_7d": structuring,
                "peer_z_score": round(peer_z, 6),
            },
        }
    return results


# ---------------------------------------------------------------------------
# SHA helper
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# build()
# ---------------------------------------------------------------------------


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Prepare artifact bytes
    # ------------------------------------------------------------------
    txn_text = "\n".join(json.dumps(t, sort_keys=True) for t in _ALL_TXNS) + "\n"
    txn_bytes = txn_text.encode("utf-8")

    rt_bytes = (json.dumps(_RULE_TREE, indent=2, sort_keys=True) + "\n").encode("utf-8")

    bl_bytes = (json.dumps(_CUSTOMER_BASELINES, indent=2, sort_keys=True) + "\n").encode("utf-8")

    # ------------------------------------------------------------------
    # Compute COAF reports
    # ------------------------------------------------------------------
    coaf_map = _compute_coaf_reports(_ALL_TXNS, _CUSTOMER_BASELINES)

    coaf_payload = {
        "model_version": _BUNDLE_ID,
        "evaluated_at": _CREATED_AT,
        "customers": coaf_map,
    }
    coaf_bytes = (json.dumps(coaf_payload, indent=2, sort_keys=True) + "\n").encode("utf-8")

    # Sanity assertions on known expected outcomes
    assert coaf_map["C001"]["coaf_report_triggered"] is True, "C001 must trigger a COAF report (velocity)"
    assert "R1" in coaf_map["C001"]["rules_fired"], "C001 must fire R1"
    assert coaf_map["C002"]["coaf_report_triggered"] is True, (
        "C002 must trigger a COAF report (structuring)"
    )
    assert "R2" in coaf_map["C002"]["rules_fired"], "C002 must fire R2"
    assert coaf_map["C003"]["coaf_report_triggered"] is True, (
        "C003 must trigger a COAF report (peer deviation)"
    )
    assert "R3" in coaf_map["C003"]["rules_fired"], "C003 must fire R3"
    assert coaf_map["C004"]["coaf_report_triggered"] is False, "C004 must be clean (no triggers)"
    assert coaf_map["C005"]["coaf_report_triggered"] is False, (
        "C005 must be borderline-clean (structuring<=2)"
    )

    # ------------------------------------------------------------------
    # OpaqueFragment anchors — one per transaction record
    # source_cid is the SHA-256 of the transactions JSONL file
    # ------------------------------------------------------------------
    txn_cid = f"sha256:{_sha256(txn_bytes)}"
    fragment_anchors: dict[str, dict] = {}

    for txn in _ALL_TXNS:
        frag = OpaqueFragment(
            source_cid=txn_cid,
            kind_tag="transaction",
            locator={
                "txn_id": txn["txn_id"],
                "customer_id": txn["customer_id"],
            },
        )
        anchor_key = txn["txn_id"]
        fragment_anchors[anchor_key] = fragment_to_canonical_dict(frag)

    assert len(fragment_anchors) == len(_ALL_TXNS), (
        f"Expected {len(_ALL_TXNS)} fragment anchors; got {len(fragment_anchors)}"
    )

    # ------------------------------------------------------------------
    # dispatch_records — C15 exercise
    # Two op kinds: COMPUTE (feature aggregation) + RULE_TREE_EVAL (rule evaluation)
    # One pair of records per customer.
    # ------------------------------------------------------------------
    dispatch_records = []
    for cid in sorted(coaf_map.keys()):
        # COMPUTE record — feature aggregation step
        dispatch_records.append(
            {
                "schema_version": "0.1",
                "op": {
                    "kind": "COMPUTE",
                    "name": f"aml_feature_aggregation_{cid}",
                },
                "inputs": [],
                "outputs": [],
                "effect": {},
                "locale": "pt-BR",
                "predicates": [],
                "stamp_declared": "INTERNAL_BENCHMARK",
                "stamp_observed": None,
            }
        )
        # RULE_TREE_EVAL record — rule-tree evaluation step
        dispatch_records.append(
            {
                "schema_version": "0.1",
                "op": {
                    "kind": "RULE_TREE_EVAL",
                    "name": f"aml_rule_tree_eval_{cid}",
                },
                "inputs": [],
                "outputs": [],
                "effect": {},
                "locale": "pt-BR",
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
            "transactions/transactions.jsonl": txn_bytes,
            "rule_tree/rule_tree.json": rt_bytes,
            "baselines/customer_baselines.json": bl_bytes,
            "payload/coaf_reports.json": coaf_bytes,
        },
        typed_checks=_TYPED_CHECKS,
        extra_manifest_fields={
            "fragment_anchors": fragment_anchors,
            "dispatch_records": dispatch_records,
        },
    )
    write_bundle(out_dir, content)

    triggered_count = sum(1 for v in coaf_map.values() if v["coaf_report_triggered"])
    print(f"Bundle written to {out_dir}")
    print(f"  transactions     : {len(_ALL_TXNS)}")
    print(f"  customers        : {len(coaf_map)}")
    print(f"  COAF reports     : {triggered_count} / {len(coaf_map)}")
    print(f"  manifest files   : 4")
    print(
        f"  fragment anchors : {len(fragment_anchors)} OpaqueFragment (kind_tag=transaction)"
    )
    print(
        f"  dispatch records : {len(dispatch_records)} (COMPUTE + RULE_TREE_EVAL × {len(coaf_map)} customers)"
    )
    print(f"  manifest         : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic aml_txn_monitoring_minimal audit bundle"
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
