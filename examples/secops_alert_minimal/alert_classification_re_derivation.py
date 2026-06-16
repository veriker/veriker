#!/usr/bin/env python3
"""alert_classification_re_derivation.py — stdlib re-derivation pack for AI security alert domain.

Re-derives the alert classification from the committed inputs (alert_log.txt +
rule_set.json), asserts byte-for-byte reproducibility against the bundled
payload/alert_classification.json, and cross-checks dispatch_records.

the audit-bundle contract §C6 (re-derivation pack — domain-agnostic substrate).
AB4: stdlib only — json, re, hashlib, pathlib, argparse; NO third-party deps.

Re-derivation primitive: re-run rule set (regex pattern matching + severity
scoring + threshold checks) against the bundled raw log line; assert the
classification is reproducible byte-for-byte.  Deterministic — no model call
inside re-derivation, just rule replay.

Reads:
  inputs/alert_log.txt                — raw log line(s); re-derives from line 0
  inputs/rule_set.json                — list of rules (rule_id, pattern, weight, ...)
  payload/alert_classification.json   — bundled classification to verify
  manifest.json                       — for dispatch_records cross-check

Re-derivation steps:
  1. Load inputs and parse bundled classification.
  2. Re-run regex rule matching + threshold checks against the raw log line.
  3. Recompute aggregate_score + final_label using committed thresholds.
  4. Assert log_line_sha256 matches (input integrity).
  5. Assert matched_rule_ids matches (same rules fired in same order).
  6. Assert aggregate_score matches.
  7. Assert final_label matches (byte-for-byte reproducibility).
  8. Assert manifest.dispatch_records[0] (RETRIEVAL) predicates == matched_rule_ids.
  9. Assert manifest.dispatch_records[1] (ALERT_CLASSIFY) predicates == [final_label].

Exit 0 on success; exit 1 with [ALERT_REDER_FAIL] <REASON_CODE> <desc> on stderr.

Usage:
    python alert_classification_re_derivation.py --bundle-dir /path/to/bundle
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Score thresholds — MUST match _build_bundle.py exactly (contract C5)
# ---------------------------------------------------------------------------

_THRESHOLD_TRUE_POSITIVE = 7
_THRESHOLD_SUSPICIOUS = 3


# ---------------------------------------------------------------------------
# Classification logic (stdlib re only)
# ---------------------------------------------------------------------------


def _classify_log_line(log_line: str, rule_set: list[dict]) -> dict:
    """Re-derive classification from log_line against rule_set.

    Returns dict with keys:
      log_line_sha256, matched_rule_ids, aggregate_score, final_label
    """
    log_bytes = log_line.encode("utf-8")
    log_sha = hashlib.sha256(log_bytes).hexdigest()

    matched_rule_ids: list[str] = []
    aggregate_score: int = 0

    for rule in rule_set:
        pattern = rule["pattern"]
        rule_id = rule["rule_id"]
        weight = rule["weight"]

        m = re.search(pattern, log_line)
        if m is None:
            continue

        # Optional threshold check (for count-based rules)
        if "threshold_field" in rule and "threshold_min" in rule:
            try:
                count_val = int(m.group(1))
            except (IndexError, ValueError):
                continue
            if count_val < rule["threshold_min"]:
                continue

        matched_rule_ids.append(rule_id)
        aggregate_score += weight

    # Determine final label using committed thresholds
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
    }


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _fail(reason_code: str, description: str) -> int:
    """Print [ALERT_REDER_FAIL] <reason_code> <description> to stderr; return 1."""
    print(f"[ALERT_REDER_FAIL] {reason_code} {description}", file=sys.stderr)
    return 1


def _verify(bundle_dir: Path) -> int:
    """Return 0 on full success; call _fail() and return 1 on first mismatch."""

    # ---- Locate required files ----
    alert_log_path = bundle_dir / "inputs" / "alert_log.txt"
    rule_set_path = bundle_dir / "inputs" / "rule_set.json"
    classification_path = bundle_dir / "payload" / "alert_classification.json"
    manifest_path = bundle_dir / "manifest.json"

    for p, label in [
        (alert_log_path, "inputs/alert_log.txt"),
        (rule_set_path, "inputs/rule_set.json"),
        (classification_path, "payload/alert_classification.json"),
        (manifest_path, "manifest.json"),
    ]:
        if not p.exists():
            return _fail(
                "ALERT_REDERIVATION_MISMATCH",
                f"{label} absent from bundle_dir {bundle_dir}",
            )

    # ---- Parse alert log — use line 0 (alert-001) ----
    try:
        lines = alert_log_path.read_text(encoding="utf-8").splitlines()
        lines = [l for l in lines if l.strip()]
    except OSError as exc:
        return _fail("ALERT_REDERIVATION_MISMATCH", f"failed to read inputs/alert_log.txt: {exc}")

    if not lines:
        return _fail("ALERT_REDERIVATION_MISMATCH", "inputs/alert_log.txt is empty")

    alert_line = lines[0]

    # ---- Parse rule set ----
    try:
        rule_set: list[dict] = json.loads(rule_set_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return _fail("ALERT_REDERIVATION_MISMATCH", f"failed to read inputs/rule_set.json: {exc}")

    if not isinstance(rule_set, list):
        return _fail("ALERT_REDERIVATION_MISMATCH", "inputs/rule_set.json must be a JSON array")

    # ---- Parse bundled classification ----
    try:
        bundled: dict = json.loads(classification_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return _fail(
            "ALERT_REDERIVATION_MISMATCH",
            f"failed to read payload/alert_classification.json: {exc}",
        )

    # ---- Parse manifest ----
    try:
        manifest_data: dict = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return _fail("ALERT_REDERIVATION_MISMATCH", f"failed to read manifest.json: {exc}")

    manifest_dispatch_records: list[dict] = manifest_data.get("dispatch_records") or []

    # ---- Re-derive classification ----
    try:
        rederived = _classify_log_line(alert_line, rule_set)
    except Exception as exc:
        return _fail("ALERT_REDERIVATION_MISMATCH", f"re-derivation error: {exc}")

    # ---- Step 4: SHA integrity of the log line ----
    bundled_sha = bundled.get("log_line_sha256", "")
    if rederived["log_line_sha256"] != bundled_sha:
        return _fail(
            "ALERT_REDERIVATION_MISMATCH",
            f"log_line_sha256 mismatch: re-derived={rederived['log_line_sha256']!r} "
            f"bundled={bundled_sha!r}",
        )

    # ---- Step 5: matched_rule_ids ----
    bundled_rules = bundled.get("matched_rule_ids", [])
    if rederived["matched_rule_ids"] != bundled_rules:
        return _fail(
            "ALERT_REDERIVATION_MISMATCH",
            f"matched_rule_ids mismatch: re-derived={rederived['matched_rule_ids']!r} "
            f"bundled={bundled_rules!r}",
        )

    # ---- Step 6: aggregate_score ----
    bundled_score = bundled.get("aggregate_score")
    if rederived["aggregate_score"] != bundled_score:
        return _fail(
            "ALERT_REDERIVATION_MISMATCH",
            f"aggregate_score mismatch: re-derived={rederived['aggregate_score']!r} "
            f"bundled={bundled_score!r}",
        )

    # ---- Step 7: final_label (byte-for-byte) ----
    bundled_label = bundled.get("final_label", "")
    if rederived["final_label"] != bundled_label:
        return _fail(
            "ALERT_REDERIVATION_MISMATCH",
            f"final_label mismatch: re-derived={rederived['final_label']!r} "
            f"bundled={bundled_label!r}",
        )

    # ---- Step 8: dispatch_records[0] (RETRIEVAL) predicates == matched_rule_ids ----
    if len(manifest_dispatch_records) < 2:
        return _fail(
            "ALERT_REDERIVATION_DISPATCH_MISMATCH",
            f"manifest.dispatch_records has {len(manifest_dispatch_records)} records; expected >= 2",
        )

    dr0 = manifest_dispatch_records[0]
    dr0_preds = dr0.get("predicates", [])
    if list(dr0_preds) != rederived["matched_rule_ids"]:
        return _fail(
            "ALERT_REDERIVATION_DISPATCH_MISMATCH",
            f"dispatch_records[0].predicates={dr0_preds!r} != "
            f"re-derived matched_rule_ids={rederived['matched_rule_ids']!r}",
        )

    # ---- Step 9: dispatch_records[1] (ALERT_CLASSIFY) predicates == [final_label] ----
    dr1 = manifest_dispatch_records[1]
    dr1_preds = dr1.get("predicates", [])
    if list(dr1_preds) != [rederived["final_label"]]:
        return _fail(
            "ALERT_REDERIVATION_DISPATCH_MISMATCH",
            f"dispatch_records[1].predicates={dr1_preds!r} != "
            f"[re-derived final_label]={[rederived['final_label']]!r}",
        )

    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Alert classification re-derivation check (AUDIT_BUNDLE_CONTRACT §C6)"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()
    return _verify(bundle_dir)


if __name__ == "__main__":
    sys.exit(main())
