"""AmlTxnMonitoringReDerivationCheck — TypedCheck plugin for AML re-derivation (C6).

Wraps aml_txn_monitoring_re_derivation.py via subprocess, mirroring the
re_derivation_invocation pattern in audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C6 (domain-agnostic generalization).
name='aml_txn_monitoring_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class AmlTxnMonitoringReDerivationCheck:
    name: str = "aml_txn_monitoring_re_derivation"
    applies_to_files: frozenset[str] = frozenset(
        {
            "transactions/",
            "rule_tree/",
            "baselines/",
            "payload/coaf_reports.json",
        }
    )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "aml_txn_monitoring_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "aml_txn_monitoring_re_derivation.py not found alongside "
                    "AmlTxnMonitoringReDerivationCheck.py; "
                    "domain pilot opted out of AML re-derivation"
                ),
                files_audited=(),
            )

        coaf_path = bundle_dir / "payload" / "coaf_reports.json"
        if not coaf_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail="payload/coaf_reports.json absent — no AML payload to re-derive",
                files_audited=(),
            )

        try:
            result = subprocess.run(
                [
                    sys.executable,
                    str(pack_path),
                    "--bundle-dir",
                    str(bundle_dir),
                ],
                capture_output=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            return PluginResult(
                ok=False,
                reason_code="AML_TXN_MONITORING_REDERIVATION_TIMEOUT",
                detail="aml_txn_monitoring_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(coaf_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="AML_TXN_MONITORING_REDERIVED",
                detail=(
                    "aml_txn_monitoring_re_derivation.py exited 0 — "
                    "all COAF-report invariants verified"
                ),
                files_audited=(str(coaf_path),),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="AML_TXN_MONITORING_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(coaf_path),),
        )


register_typed_check("aml_txn_monitoring_re_derivation")
