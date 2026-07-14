"""aml_txn_monitoring_recompute.py — verifier-side COAF-report re-derivation primitive.

Axis-2 value-return form (SPEC_PINNED_DISPATCH_ARCHITECTURE §3.3). Self-contained
per-dir migration of the aml_txn_monitoring_minimal pilot onto spec-pinned dispatch:
the recompute primitive lives HERE (verifier-distribution code, registered by the
spec-pinned builder), NOT in audit_bundle/rederivation/primitives/.

Re-derivation primitive (one sentence):
    For each customer, re-aggregate three features (max count of transactions
    > R$10,000 in any 24h sliding window; max count of cash deposits in
    [R$9,000, R$10,000) in any 7-day sliding window; peer-group z-score of mean
    transaction size) from the committed raw transaction stream + peer baselines,
    evaluate the committed rule tree (trigger = ANY(velocity > t0, structuring > t1,
    abs(peer_z) > t2)), and emit the per-customer coaf_report_triggered decision as a
    deterministic ordered list of {customer_id, coaf_report_triggered} sorted by id.

over the committed inputs in the bundle:
    transactions/transactions.jsonl   — raw transaction stream
    rule_tree/rule_tree.json          — COAF-report rule-tree spec (thresholds)
    baselines/customer_baselines.json — peer-group mean + stddev

The feature computation + rule-tree evaluation rule is FIXED in this primitive —
the primitive_id ("aml_txn_monitoring_recompute") IS the rule. The auditor's
SHA-pinned spec binds the output type "aml_coaf_report_decisions" to this
primitive_id and to an `exact` comparator (no params; an ordered list of
{customer_id, coaf_report_triggered} records compared element-wise). A producer
cannot weaken the rule without changing the primitive_id, which the anchor rejects.

The feature + rule logic below MIRRORS the legacy pack
(aml_txn_monitoring_re_derivation.py) and the builder (_build_bundle.py) EXACTLY,
so the honest claimed decision list and the re-derivation cannot drift.

Stdlib-only (§C5 contract). This module is importable WITHOUT audit_bundle on
sys.path (the RecomputedValue import is deferred into recompute()), so the
spec-pinned builder can import compute_coaf_decisions() standalone.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path


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
    """Max count of cash deposits in [R$9,000, R$10,000) in any 7-day sliding window."""
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
    """True if ANY rule fires. Thresholds read from the bundled rule_tree."""
    rules = rule_tree["rules"]
    v_thresh = rules[0]["threshold"]
    s_thresh = rules[1]["threshold"]
    z_thresh = rules[2]["threshold"]
    return velocity > v_thresh or structuring > s_thresh or abs(peer_z) > z_thresh


# ---------------------------------------------------------------------------
# Canonical computation (shared by the builder and the verifier — ONE source)
# ---------------------------------------------------------------------------


def compute_coaf_decisions(
    transactions: list[dict], rule_tree: dict, baselines: dict
) -> list[dict]:
    """Canonical per-customer COAF-report decision re-derivation.

    Re-aggregates the three features per customer from the raw transaction stream
    + peer baselines, evaluates the bundled rule tree, and returns the per-customer
    coaf_report_triggered decision as a deterministic ordered list of
    {customer_id, coaf_report_triggered} records sorted ascending by customer_id.

    Builder and verifier share this ONE definition so the honest claimed decision
    list and the re-derivation cannot drift.

    Fail-closed: raises KeyError/TypeError/ValueError if inputs are malformed (the
    verifier must not invent a decision).
    """
    peer_mean = float(baselines["mean_txn_size_brl"])
    peer_stddev = float(baselines["stddev_txn_size_brl"])

    by_customer: dict[str, list[dict]] = {}
    for txn in transactions:
        cid = txn["customer_id"]
        if not cid:
            raise ValueError("transaction missing customer_id")
        by_customer.setdefault(cid, []).append(txn)

    decisions: list[dict] = []
    for cid, ctxns in sorted(by_customer.items()):
        velocity = _compute_velocity_24h(ctxns)
        structuring = _compute_structuring_proxy_7d(ctxns)
        peer_z = _compute_peer_z_score(ctxns, peer_mean, peer_stddev)
        triggered = _evaluate_rule_tree(rule_tree, velocity, structuring, peer_z)
        decisions.append(
            {"customer_id": cid, "coaf_report_triggered": triggered}
        )
    return decisions


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered before BundleVerifier)
# ---------------------------------------------------------------------------


class AmlTxnMonitoringRecompute:
    """Verifier-side primitive for re-deriving the per-customer COAF-report
    decision list."""

    primitive_id: str = "aml_txn_monitoring_recompute"

    def recompute(self, inputs, pack_section: dict):
        """Recompute the per-customer coaf_report_triggered decision list from the
        committed transaction stream, rule tree, and peer baselines.

        inputs.bundle_dir is a read-only Path. pack_section carries
        {output_id, type, params} from the auditor's spec binding. Returns a
        RecomputedValue carrying the ordered list of
        {customer_id, coaf_report_triggered} records; the verifier's `exact`
        comparator compares it element-wise to the claimed value.
        """
        # Deferred import keeps this module importable standalone (builder use).
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        bundle_dir: Path = inputs.bundle_dir

        txn_path = bundle_dir / "transactions" / "transactions.jsonl"
        rt_path = bundle_dir / "rule_tree" / "rule_tree.json"
        bl_path = bundle_dir / "baselines" / "customer_baselines.json"
        for p in (txn_path, rt_path, bl_path):
            if not p.is_file():
                raise FileNotFoundError(f"{p} not found in bundle at {bundle_dir}")

        transactions: list[dict] = []
        for line in txn_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            transactions.append(json.loads(line))

        rule_tree = json.loads(rt_path.read_bytes())
        baselines = json.loads(bl_path.read_bytes())
        if not isinstance(rule_tree, dict) or "rules" not in rule_tree:
            raise ValueError("rule_tree/rule_tree.json: missing required 'rules'")
        if not isinstance(baselines, dict):
            raise ValueError("baselines/customer_baselines.json: top-level must be an object")

        value = compute_coaf_decisions(transactions, rule_tree, baselines)
        n_triggered = sum(1 for d in value if d["coaf_report_triggered"])
        return RecomputedValue(
            value=value,
            detail=(
                f"re-derived COAF-report decisions for {len(value)} customers "
                f"({n_triggered} triggered) from transactions + rule_tree + baselines"
            ),
        )
