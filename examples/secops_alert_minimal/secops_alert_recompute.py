"""secops_alert_recompute.py — verifier-side alert-classification re-derivation primitive.

Axis-2 value-return form (SPEC_PINNED_DISPATCH_ARCHITECTURE §3.3). Self-contained
per-dir migration of the secops_alert_minimal pilot onto spec-pinned dispatch: the
recompute primitive lives HERE (verifier-distribution code, registered by the
spec-pinned builder / verify path), NOT in audit_bundle/rederivation/primitives/.

Re-derivation primitive (one sentence):
    final_label = threshold-map( sum over rules (in inputs/rule_set.json list
        order) whose regex matches log line 0 of inputs/alert_log.txt — subject
        to each rule's optional threshold_field/threshold_min check — of that
        rule's weight ), where score>=7 -> TRUE_POSITIVE, score>=3 -> SUSPICIOUS,
        else FALSE_POSITIVE.

The replay rule (regex search in rule_set list order, optional count-threshold
gating, weight accumulation, and the 7 / 3 label thresholds) is FIXED in this
primitive — the primitive_id ("secops_alert_recompute") IS the rule. The auditor's
SHA-pinned spec binds the output type "secops_alert_final_label" to this
primitive_id and to an `exact` comparator; a producer cannot weaken the
classification logic without changing the primitive_id, which the anchor rejects.

Stdlib-only (§C5 contract). This module is importable WITHOUT audit_bundle on
sys.path (the RecomputedValue import is deferred into recompute()), so the
spec-pinned builder can import compute_final_label() standalone.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

# Score thresholds — MUST match the legacy pack (_build_bundle.py /
# alert_classification_re_derivation.py) exactly (contract C5).
_THRESHOLD_TRUE_POSITIVE = 7
_THRESHOLD_SUSPICIOUS = 3


# ---------------------------------------------------------------------------
# Canonical computation (shared by the builder and the verifier — ONE source)
# ---------------------------------------------------------------------------


def compute_final_label(log_line: str, rule_set: list) -> str:
    """Canonical re-derivation of the final classification label for one log line.

    Mirrors the legacy pack's _classify_log_line EXACTLY: for each rule in
    rule_set (in list order) re.search() the rule's pattern against log_line; if
    a rule declares threshold_field+threshold_min, gate the match on
    int(match.group(1)) >= threshold_min; on a surviving match add the rule's
    weight to the aggregate score. Map the score to a label with the fixed
    thresholds (>=7 TRUE_POSITIVE, >=3 SUSPICIOUS, else FALSE_POSITIVE).

    Returns the label string only (the representative output). Builder and
    verifier share this ONE definition so the honest claimed label and the
    re-derivation cannot drift.
    """
    aggregate_score = 0
    for rule in rule_set:
        pattern = rule["pattern"]
        weight = rule["weight"]

        m = re.search(pattern, log_line)
        if m is None:
            continue

        # Optional threshold check (for count-based rules).
        if "threshold_field" in rule and "threshold_min" in rule:
            try:
                count_val = int(m.group(1))
            except (IndexError, ValueError):
                continue
            if count_val < rule["threshold_min"]:
                continue

        aggregate_score += weight

    if aggregate_score >= _THRESHOLD_TRUE_POSITIVE:
        return "TRUE_POSITIVE"
    if aggregate_score >= _THRESHOLD_SUSPICIOUS:
        return "SUSPICIOUS"
    return "FALSE_POSITIVE"


def _first_log_line(alert_log_text: str) -> str:
    """The bundle classifies alert-001 = line index 0 (skipping blank lines),
    matching the legacy pack's line-selection rule."""
    lines = [ln for ln in alert_log_text.splitlines() if ln.strip()]
    if not lines:
        raise ValueError("inputs/alert_log.txt is empty — cannot classify")
    return lines[0]


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered before BundleVerifier)
# ---------------------------------------------------------------------------


class SecopsAlertRecompute:
    """Verifier-side primitive for re-deriving the final alert classification label."""

    primitive_id: str = "secops_alert_recompute"

    def recompute(self, inputs, pack_section: dict):
        """Recompute the final_label from inputs/alert_log.txt (line 0) and
        inputs/rule_set.json.

        inputs.bundle_dir is a read-only Path. pack_section carries
        {output_id, type, params} from the auditor's spec binding. Returns a
        RecomputedValue carrying the label string; the verifier's `exact`
        comparator compares.
        """
        # Deferred import keeps this module importable standalone (builder use).
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        bundle_dir: Path = inputs.bundle_dir
        log_path = bundle_dir / "inputs" / "alert_log.txt"
        rule_path = bundle_dir / "inputs" / "rule_set.json"
        if not log_path.is_file():
            raise FileNotFoundError(
                f"inputs/alert_log.txt not found in bundle at {bundle_dir}"
            )
        if not rule_path.is_file():
            raise FileNotFoundError(
                f"inputs/rule_set.json not found in bundle at {bundle_dir}"
            )
        rule_set = json.loads(rule_path.read_bytes())
        if not isinstance(rule_set, list):
            raise ValueError("inputs/rule_set.json must be a JSON array")
        alert_line = _first_log_line(log_path.read_text(encoding="utf-8"))
        value = compute_final_label(alert_line, rule_set)
        return RecomputedValue(
            value=value,
            detail=f"re-derived final_label over {len(rule_set)} rule(s)",
        )
