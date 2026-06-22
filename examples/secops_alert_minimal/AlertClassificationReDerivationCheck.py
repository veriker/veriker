"""AlertClassificationReDerivationCheck — TypedCheck plugin for AI security alert re-derivation.

Wraps alert_classification_re_derivation.py via subprocess, mirroring the
re_derivation_invocation pattern established by SpanReDerivationCheck and
RagReDerivationCheck.

the audit-bundle contract §C6 (domain-agnostic re-derivation substrate).
name='alert_classification_re_derivation'

Domain: AI security / SOC alert classification.
Re-derivation primitive: re-run regex rule set against the committed log line;
assert TRUE_POSITIVE / SUSPICIOUS / FALSE_POSITIVE label is byte-for-byte
reproducible.

Reason codes emitted:
  ALERT_REDERIVED                     — success
  ALERT_REDERIVATION_MISMATCH         — re-derived label != bundled label
                                        (log_line_sha256, matched_rule_ids,
                                        aggregate_score, or final_label diverged)
  ALERT_REDERIVATION_DISPATCH_MISMATCH — dispatch_records predicates diverged
  ALERT_REDERIVATION_TIMEOUT          — subprocess exceeded 60 s

Stdlib only (subprocess, sys, pathlib) — contract C5.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult

# Map from stderr substring to reason code; first match wins.
_STDERR_REASON_MAP: tuple[tuple[str, str], ...] = (
    ("ALERT_REDERIVATION_DISPATCH_MISMATCH", "ALERT_REDERIVATION_DISPATCH_MISMATCH"),
    ("ALERT_REDERIVATION_MISMATCH", "ALERT_REDERIVATION_MISMATCH"),
)


def _map_stderr_to_reason(stderr_text: str) -> str:
    for substring, reason_code in _STDERR_REASON_MAP:
        if substring in stderr_text:
            return reason_code
    return "ALERT_REDERIVATION_MISMATCH"


class AlertClassificationReDerivationCheck:
    name: str = "alert_classification_re_derivation"
    applies_to_files: frozenset[str] = frozenset({
        "inputs/",
        "payload/alert_classification.json",
        "payload/dispatch_records.jsonl",
    })

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "alert_classification_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "alert_classification_re_derivation.py not found alongside "
                    "AlertClassificationReDerivationCheck.py; domain pilot opted out"
                ),
                files_audited=(),
            )

        classification_path = bundle_dir / "payload" / "alert_classification.json"
        alert_log_path = bundle_dir / "inputs" / "alert_log.txt"

        if not classification_path.exists() or not alert_log_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail=(
                    "payload/alert_classification.json or inputs/alert_log.txt absent "
                    "— no alert classification to re-derive"
                ),
                files_audited=(),
            )

        try:
            result = subprocess.run(
                [sys.executable, str(pack_path), "--bundle-dir", str(bundle_dir)],
                capture_output=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            return PluginResult(
                ok=False,
                reason_code="ALERT_REDERIVATION_TIMEOUT",
                detail="alert_classification_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(classification_path), str(alert_log_path)),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="ALERT_REDERIVED",
                detail=(
                    "alert_classification_re_derivation.py exited 0 — "
                    "log_line_sha256, matched_rule_ids, aggregate_score, "
                    "final_label, and dispatch_records predicates all verified"
                ),
                files_audited=(str(classification_path), str(alert_log_path)),
            )

        stderr_text = (result.stderr or b"").decode("utf-8", errors="replace")
        reason_code = _map_stderr_to_reason(stderr_text)
        stderr_snippet = stderr_text[:512]
        return PluginResult(
            ok=False,
            reason_code=reason_code,
            detail=stderr_snippet,
            files_audited=(str(classification_path), str(alert_log_path)),
        )


register_typed_check("alert_classification_re_derivation")
