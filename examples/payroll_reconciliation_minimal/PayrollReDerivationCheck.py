"""PayrollReDerivationCheck — TypedCheck plugin for payroll re-derivation (C6).

Wraps payroll_re_derivation.py via subprocess, mirroring the
re_derivation_invocation pattern in audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C6 (domain-agnostic re-derivation substrate).
name='payroll_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class PayrollReDerivationCheck:
    name: str = "payroll_re_derivation"
    applies_to_files: frozenset[str] = frozenset({"data/", "payload/paychecks.json"})

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "payroll_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "payroll_re_derivation.py not found alongside "
                    "PayrollReDerivationCheck.py; domain pilot opted out"
                ),
                files_audited=(),
            )

        events_path = bundle_dir / "data" / "pay_events.csv"
        ledger_path = bundle_dir / "payload" / "paychecks.json"
        if not events_path.exists() or not ledger_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail="data/pay_events.csv or payload/paychecks.json absent — nothing to re-derive",
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
                reason_code="PAYROLL_REDERIVATION_TIMEOUT",
                detail="payroll_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(events_path), str(ledger_path)),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="PAYROLL_REDERIVED",
                detail="payroll_re_derivation.py exited 0 — every paycheck and clawback re-derived",
                files_audited=(str(events_path), str(ledger_path)),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="PAYROLL_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(events_path), str(ledger_path)),
        )


register_typed_check("payroll_re_derivation")
