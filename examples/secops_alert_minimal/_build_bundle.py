"""_build_bundle.py — build a deterministic secops_alert_minimal audit bundle.

Generates a synthetic SOC alert scenario: a raw log line is classified by an
AI security model against a bundled rule set, producing a deterministic
TRUE_POSITIVE / SUSPICIOUS / FALSE_POSITIVE label.  The bundle captures the
log line, matched rule definitions, classification payload, and dispatch records
for the rule-feed fetch and the classification op.

Domain: AI-security alert classification (SOC / SIEM).
Re-derivation primitive: re-run the rule set (regex + severity scoring) against
the bundled raw log line; assert the classification is reproducible byte-for-byte.

Usage (from v-kernel-audit-bundle root):
    python examples/secops_alert_minimal/_build_bundle.py --out-dir /tmp/secops_alert_bundle

Outputs:
  <out-dir>/inputs/alert_log.txt
  <out-dir>/inputs/rule_set.json
  <out-dir>/payload/alert_classification.json
  <out-dir>/payload/dispatch_records.jsonl     (inspection copy — not fed to verifier)
  <out-dir>/manifest.json

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.emitter import BundleContent, write_bundle
from audit_bundle.fragments.fragment_id import ByteOffsetFragment, fragment_to_canonical_dict

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "secops-alert-minimal-rc"
_CREATED_AT = "2026-05-10T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
    "dispatch_record_wellformed",
    "alert_classification_re_derivation",
]

# ---------------------------------------------------------------------------
# Synthetic fixtures
# ---------------------------------------------------------------------------

# Two raw log lines representing a typical SIEM ingest event.
# Line 1: SSH brute-force pattern — should match multiple rules.
# Line 2: Normal auth event — should be FALSE_POSITIVE.
_ALERT_LOG_LINES = [
    "2026-05-10T03:14:07Z host=auth-server-01 pid=1337 user=root src=198.51.100.42 "
    "event=authentication_failure count=52 proto=ssh msg=\"Failed password for root "
    "from 198.51.100.42 port 22 ssh2\"",
    "2026-05-10T08:01:22Z host=auth-server-01 pid=2048 user=alice src=10.0.1.55 "
    "event=authentication_success count=1 proto=ssh msg=\"Accepted publickey for "
    "alice from 10.0.1.55 port 54321 ssh2\"",
]

# Rule set: each rule has id, pattern (Python regex), severity_label, weight.
# Weights sum determines aggregate_score; thresholds: >=7 → TRUE_POSITIVE,
# 3–6 → SUSPICIOUS, <3 → FALSE_POSITIVE.
_RULE_SET = [
    {
        "rule_id": "R001",
        "pattern": r"event=authentication_failure",
        "severity_label": "auth_failure",
        "weight": 3,
    },
    {
        "rule_id": "R002",
        "pattern": r"user=root",
        "severity_label": "root_access_attempt",
        "weight": 4,
    },
    {
        "rule_id": "R003",
        "pattern": r"count=(\d+)",
        "severity_label": "high_frequency",
        "weight": 2,
        "threshold_field": "count",
        "threshold_min": 10,
    },
    {
        "rule_id": "R004",
        "pattern": r"src=(?:198\.51\.100\.|203\.0\.113\.)",
        "severity_label": "suspicious_source_range",
        "weight": 3,
    },
    {
        "rule_id": "R005",
        "pattern": r"event=privilege_escalation",
        "severity_label": "privilege_escalation",
        "weight": 5,
    },
]

# Score thresholds for final_label
_THRESHOLD_TRUE_POSITIVE = 7
_THRESHOLD_SUSPICIOUS = 3


# ---------------------------------------------------------------------------
# Classification logic (mirrors alert_classification_re_derivation.py)
# ---------------------------------------------------------------------------

import re as _re


def _classify_log_line(log_line: str, rule_set: list[dict]) -> dict:
    """Classify a single log line against the rule set.

    Returns:
      {
        "log_line_sha256": <hex>,
        "matched_rule_ids": [...],
        "aggregate_score": <int>,
        "final_label": "TRUE_POSITIVE" | "SUSPICIOUS" | "FALSE_POSITIVE",
        "match_spans": [{"rule_id": ..., "start": ..., "end": ...}, ...]
      }
    """
    log_bytes = log_line.encode("utf-8")
    log_sha = hashlib.sha256(log_bytes).hexdigest()

    matched_rule_ids: list[str] = []
    aggregate_score: int = 0
    match_spans: list[dict] = []

    for rule in rule_set:
        pattern = rule["pattern"]
        rule_id = rule["rule_id"]
        weight = rule["weight"]

        m = _re.search(pattern, log_line)
        if m is None:
            continue

        # Optional threshold check (for count-based rules)
        if "threshold_field" in rule and "threshold_min" in rule:
            # Extract the count from the match group
            try:
                count_val = int(m.group(1))
            except (IndexError, ValueError):
                continue
            if count_val < rule["threshold_min"]:
                continue

        matched_rule_ids.append(rule_id)
        aggregate_score += weight
        # Record the byte span of the match within the UTF-8 log line
        # (byte offsets into log_bytes)
        raw_start = len(log_line[:m.start()].encode("utf-8"))
        raw_end = len(log_line[:m.end()].encode("utf-8"))
        match_spans.append({
            "rule_id": rule_id,
            "start": raw_start,
            "end": raw_end,
        })

    # Determine final label
    if aggregate_score >= _THRESHOLD_TRUE_POSITIVE:
        final_label = "TRUE_POSITIVE"
    elif aggregate_score >= _THRESHOLD_SUSPICIOUS:
        final_label = "SUSPICIOUS"
    else:
        final_label = "FALSE_POSITIVE"

    return {
        "log_line_sha256": log_sha,
        "matched_rule_ids": matched_rule_ids,
        "aggregate_score": aggregate_score,
        "final_label": final_label,
        "match_spans": match_spans,
    }


# ---------------------------------------------------------------------------
# SHA helpers
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return _sha256(text.encode("utf-8"))


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def build(out_dir: Path) -> None:
    """Generate the full secops_alert_minimal bundle under out_dir."""
    out_dir.mkdir(parents=True, exist_ok=True)

    # ---- 1. Prepare artifact bytes ----
    alert_log_text = "\n".join(_ALERT_LOG_LINES) + "\n"
    alert_log_bytes = alert_log_text.encode("utf-8")

    rule_set_text = json.dumps(_RULE_SET, indent=2)
    rule_set_bytes = rule_set_text.encode("utf-8")

    # ---- 2. Classify the FIRST log line (the SSH brute-force alert) ----
    alert_line = _ALERT_LOG_LINES[0]
    classification = _classify_log_line(alert_line, _RULE_SET)

    assert classification["final_label"] == "TRUE_POSITIVE", (
        f"Expected TRUE_POSITIVE for SSH brute-force alert; "
        f"got {classification['final_label']!r} "
        f"(score={classification['aggregate_score']})"
    )

    alert_id = "alert-001"

    # ---- 3. Build payload/alert_classification.json bytes ----
    alert_classification = {
        "alert_id": alert_id,
        "log_line_sha256": classification["log_line_sha256"],
        "matched_rule_ids": classification["matched_rule_ids"],
        "aggregate_score": classification["aggregate_score"],
        "final_label": classification["final_label"],
    }
    classification_bytes = json.dumps(alert_classification, indent=2).encode("utf-8")

    # ---- 4. Build dispatch_records ----
    record_retrieval = {
        "schema_version": "0.1",
        "op": {"kind": "RETRIEVAL"},
        "effect": {},
        "predicates": classification["matched_rule_ids"],
        "outputs": [],
    }
    record_classify = {
        "schema_version": "0.1",
        "op": {"kind": "ALERT_CLASSIFY"},
        "effect": {},
        "predicates": [classification["final_label"]],
        "outputs": [],
    }
    dispatch_records = [record_retrieval, record_classify]

    dr_lines = [json.dumps(r, separators=(",", ":")) for r in dispatch_records]
    dr_text = "\n".join(dr_lines) + "\n"
    dr_bytes = dr_text.encode("utf-8")

    # ---- 5. Build fragment_anchors from match_spans ----
    alert_log_sha = _sha256(alert_log_bytes)
    source_cid = f"sha256:{alert_log_sha}"

    fragment_anchors: dict[str, dict] = {}
    for span in classification["match_spans"]:
        rule_id = span["rule_id"]
        frag = ByteOffsetFragment(
            source_cid=source_cid,
            start=span["start"],
            end=span["end"],
        )
        anchor_name = f"alert-001-match-{rule_id.lower()}"
        fragment_anchors[anchor_name] = fragment_to_canonical_dict(frag)

    # ---- 6. Emit via the reference-emitter SDK ----
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "inputs/alert_log.txt": alert_log_bytes,
            "inputs/rule_set.json": rule_set_bytes,
            "payload/alert_classification.json": classification_bytes,
            "payload/dispatch_records.jsonl": dr_bytes,
        },
        typed_checks=_TYPED_CHECKS,
        extra_manifest_fields={
            "fragment_anchors": fragment_anchors,
            "dispatch_records": dispatch_records,
        },
    )
    write_bundle(out_dir, content)
    manifest_path = out_dir / "manifest.json"

    print(f"Bundle written to {out_dir}")
    print(f"  alert_id         : {alert_id}")
    print(f"  log_line_sha256  : {classification['log_line_sha256'][:16]}...")
    print(f"  matched_rule_ids : {classification['matched_rule_ids']}")
    print(f"  aggregate_score  : {classification['aggregate_score']}")
    print(f"  final_label      : {classification['final_label']}")
    print(f"  fragment_anchors : {len(fragment_anchors)}")
    print(f"  dispatch_records : {len(dispatch_records)} records")
    print(f"  manifest         : {manifest_path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic secops_alert_minimal audit bundle"
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
