"""TabularReDerivationCheck — TypedCheck plugin for tabular SQL aggregate re-derivation.

Wraps tabular_re_derivation.py via subprocess, mirroring the re_derivation_invocation
pattern in audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C6 (domain-agnostic re-derivation substrate).
name='tabular_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class TabularReDerivationCheck:
    name: str = "tabular_re_derivation"
    applies_to_files: frozenset[str] = frozenset({"data/", "payload/result.csv"})

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "tabular_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "tabular_re_derivation.py not found alongside TabularReDerivationCheck.py; "
                    "domain pilot opted out"
                ),
                files_audited=(),
            )

        sales_path = bundle_dir / "data" / "sales.csv"
        result_path = bundle_dir / "payload" / "result.csv"

        if not sales_path.exists() or not result_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail="data/sales.csv or payload/result.csv absent — no tabular data to re-derive",
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
                reason_code="TABULAR_REDERIVATION_TIMEOUT",
                detail="tabular_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(sales_path), str(result_path)),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="TABULAR_REDERIVED",
                detail="tabular_re_derivation.py exited 0 — aggregate result verified byte-identical",
                files_audited=(str(sales_path), str(result_path)),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="TABULAR_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(sales_path), str(result_path)),
        )


register_typed_check("tabular_re_derivation")
