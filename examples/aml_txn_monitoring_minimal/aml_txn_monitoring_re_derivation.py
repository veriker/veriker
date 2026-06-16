#!/usr/bin/env python3
"""aml_txn_monitoring_re_derivation.py — stdlib re-derivation pack for the AML pilot.

Verifies that bundled COAF-report decisions are derivable from the bundled
transaction stream, rule-tree, and customer baselines.

the audit-bundle contract §C6 (domain generalization) + AB4 (duplicate-don't-import).
Stdlib-only (no third-party dependencies); uses `statistics` module for z-score.

Reads from --bundle-dir:
  transactions/transactions.jsonl       — raw transaction stream
  rule_tree/rule_tree.json              — COAF-report rule-tree spec
  baselines/customer_baselines.json     — peer-group mean + stddev
  payload/coaf_reports.json             — bundled COAF-report decisions to verify

Re-derivation primitive (one sentence):
  Re-aggregate per-customer features (velocity, structuring proxy,
  peer-deviation z-score) from the bundled raw transaction stream, then
  re-evaluate the bundled rule-tree JSON to recompute the COAF-report flag
  per customer — assert the bundle's payload matches.

Three invariants checked:
  1. Per-customer velocity_24h_gt_10k feature matches bundled value.
  2. Per-customer structuring_proxy_7d feature matches bundled value.
  3. Per-customer peer_z_score feature matches bundled value (tolerance 1e-4).
  4. Per-customer coaf_report_triggered decision matches bundled value.

Exit 0 on full match; exit 1 on first mismatch with
[AML_TXN_MONITORING_REDERIVATION_MISMATCH] on stderr.

If any required input file is absent the bundle opted out — exits 0.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# File loaders
# ---------------------------------------------------------------------------


def _load_transactions(bundle_dir: Path) -> list[dict] | None:
    path = bundle_dir / "transactions" / "transactions.jsonl"
    if not path.exists():
        return None
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            print(
                f"[AML_TXN_MONITORING_REDERIVATION_MISMATCH] "
                f"transactions.jsonl: JSON parse error: {exc}",
                file=sys.stderr,
            )
            return None
    return records


def _load_rule_tree(bundle_dir: Path) -> dict | None:
    path = bundle_dir / "rule_tree" / "rule_tree.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(
            f"[AML_TXN_MONITORING_REDERIVATION_MISMATCH] "
            f"rule_tree.json: JSON parse error: {exc}",
            file=sys.stderr,
        )
        return None


def _load_baselines(bundle_dir: Path) -> dict | None:
    path = bundle_dir / "baselines" / "customer_baselines.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(
            f"[AML_TXN_MONITORING_REDERIVATION_MISMATCH] "
            f"customer_baselines.json: JSON parse error: {exc}",
            file=sys.stderr,
        )
        return None


def _load_coaf_reports(bundle_dir: Path) -> dict | None:
    path = bundle_dir / "payload" / "coaf_reports.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(
            f"[AML_TXN_MONITORING_REDERIVATION_MISMATCH] "
            f"coaf_reports.json: JSON parse error: {exc}",
            file=sys.stderr,
        )
        return None


# ---------------------------------------------------------------------------
# Feature computation (must mirror _build_bundle.py exactly)
# ---------------------------------------------------------------------------


def _parse_ts(ts_str: str) -> datetime:
    return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _compute_velocity_24h(txns: list[dict]) -> int:
    """Max count of transactions > $10,000 in any 24-hour sliding window."""
    large = [t for t in txns if t["amount_brl"] > 10000.0]
    if not large:
        return 0
    large_sorted = sorted(large, key=lambda t: t["timestamp"])
    max_count = 0
    for anchor in large_sorted:
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
    """(mean txn size - peer mean) / peer stddev. Uses stdlib arithmetic (no numpy)."""
    if not txns:
        return 0.0
    mean_size = sum(t["amount_brl"] for t in txns) / len(txns)
    return (mean_size - peer_mean) / peer_stddev


def _evaluate_rule_tree(
    rule_tree: dict, velocity: int, structuring: int, peer_z: float
) -> bool:
    """True if ANY rule fires. Thresholds read from bundled rule_tree."""
    rules = rule_tree["rules"]
    v_thresh = rules[0]["threshold"]
    s_thresh = rules[1]["threshold"]
    z_thresh = rules[2]["threshold"]
    return velocity > v_thresh or structuring > s_thresh or abs(peer_z) > z_thresh


# ---------------------------------------------------------------------------
# Main re-derivation logic
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="AML transaction monitoring re-derivation check"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    # Graceful opt-out: if key input files are missing, bundle opted out
    txn_path = bundle_dir / "transactions" / "transactions.jsonl"
    payload_path = bundle_dir / "payload" / "coaf_reports.json"
    if not txn_path.exists() and not payload_path.exists():
        return 0

    transactions = _load_transactions(bundle_dir)
    if transactions is None:
        return 1

    rule_tree = _load_rule_tree(bundle_dir)
    if rule_tree is None:
        print(
            "[AML_TXN_MONITORING_REDERIVATION_MISMATCH] rule_tree.json missing or unreadable",
            file=sys.stderr,
        )
        return 1

    baselines = _load_baselines(bundle_dir)
    if baselines is None:
        print(
            "[AML_TXN_MONITORING_REDERIVATION_MISMATCH] customer_baselines.json missing or unreadable",
            file=sys.stderr,
        )
        return 1

    bundled = _load_coaf_reports(bundle_dir)
    if bundled is None:
        print(
            "[AML_TXN_MONITORING_REDERIVATION_MISMATCH] payload/coaf_reports.json missing or unreadable",
            file=sys.stderr,
        )
        return 1

    try:
        bundled_customers: dict = bundled["customers"]
        peer_mean: float = float(baselines["mean_txn_size_brl"])
        peer_stddev: float = float(baselines["stddev_txn_size_brl"])
        rules = rule_tree["rules"]
        v_thresh = rules[0]["threshold"]
        s_thresh = rules[1]["threshold"]
        z_thresh = float(rules[2]["threshold"])
    except (KeyError, TypeError, ValueError) as exc:
        print(
            f"[AML_TXN_MONITORING_REDERIVATION_MISMATCH] malformed input structure: {exc}",
            file=sys.stderr,
        )
        return 1

    # Group transactions by customer
    by_customer: dict[str, list[dict]] = {}
    for txn in transactions:
        cid = txn.get("customer_id")
        if not cid:
            print(
                "[AML_TXN_MONITORING_REDERIVATION_MISMATCH] transaction missing customer_id",
                file=sys.stderr,
            )
            return 1
        by_customer.setdefault(cid, []).append(txn)

    # Verify each bundled customer
    for cid, bundled_rec in sorted(bundled_customers.items()):
        ctxns = by_customer.get(cid, [])

        # Re-derive features
        velocity = _compute_velocity_24h(ctxns)
        structuring = _compute_structuring_proxy_7d(ctxns)
        peer_z = _compute_peer_z_score(ctxns, peer_mean, peer_stddev)

        # Invariant 1: velocity feature match
        bundled_velocity = bundled_rec.get("features", {}).get("velocity_24h_gt_10k")
        if bundled_velocity != velocity:
            print(
                f"[AML_TXN_MONITORING_REDERIVATION_MISMATCH] customer {cid}: "
                f"velocity_24h_gt_10k mismatch: bundled={bundled_velocity} derived={velocity}",
                file=sys.stderr,
            )
            return 1

        # Invariant 2: structuring proxy feature match
        bundled_structuring = bundled_rec.get("features", {}).get(
            "structuring_proxy_7d"
        )
        if bundled_structuring != structuring:
            print(
                f"[AML_TXN_MONITORING_REDERIVATION_MISMATCH] customer {cid}: "
                f"structuring_proxy_7d mismatch: bundled={bundled_structuring} derived={structuring}",
                file=sys.stderr,
            )
            return 1

        # Invariant 3: peer z-score match (tolerance 1e-4)
        bundled_z = bundled_rec.get("features", {}).get("peer_z_score")
        if bundled_z is None or abs(float(bundled_z) - peer_z) > 1e-4:
            print(
                f"[AML_TXN_MONITORING_REDERIVATION_MISMATCH] customer {cid}: "
                f"peer_z_score mismatch: bundled={bundled_z} derived={round(peer_z, 6)}",
                file=sys.stderr,
            )
            return 1

        # Invariant 4: coaf_report_triggered decision match
        derived_triggered = _evaluate_rule_tree(
            rule_tree, velocity, structuring, peer_z
        )
        bundled_triggered = bundled_rec.get("coaf_report_triggered")
        if bundled_triggered is not derived_triggered:
            print(
                f"[AML_TXN_MONITORING_REDERIVATION_MISMATCH] customer {cid}: "
                f"coaf_report_triggered mismatch: bundled={bundled_triggered} derived={derived_triggered}",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
