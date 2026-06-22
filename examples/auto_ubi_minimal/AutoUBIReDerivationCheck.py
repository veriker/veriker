"""AutoUBIReDerivationCheck — TypedCheck plugin for UBI telematics re-derivation (C6).

Wraps auto_ubi_re_derivation.py via subprocess, mirroring the re_derivation_invocation
pattern in audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C6 (domain-agnostic generalization).
name='auto_ubi_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class AutoUBIReDerivationCheck:
    name: str = "auto_ubi_re_derivation"
    applies_to_files: frozenset[str] = frozenset(
        {"telematics/", "payload/rating_decisions.json", "payload/rate_table.json"}
    )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "auto_ubi_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "auto_ubi_re_derivation.py not found alongside "
                    "AutoUBIReDerivationCheck.py; domain pilot opted out of "
                    "UBI re-derivation"
                ),
                files_audited=(),
            )

        dec_path = bundle_dir / "payload" / "rating_decisions.json"
        if not dec_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail=(
                    "payload/rating_decisions.json absent — no UBI rating "
                    "decisions to re-derive"
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
                reason_code="AUTO_UBI_REDERIVATION_TIMEOUT",
                detail="auto_ubi_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(dec_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="AUTO_UBI_REDERIVED",
                detail=(
                    "auto_ubi_re_derivation.py exited 0 — all UBI telematics "
                    "rating invariants verified"
                ),
                files_audited=(str(dec_path),),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="AUTO_UBI_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(dec_path),),
        )


register_typed_check("auto_ubi_re_derivation")
