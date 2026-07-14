"""CombiScreenReDerivationCheck — TypedCheck plugin for combinatorial screening re-derivation (C6).

Wraps combi_screen_re_derivation.py via subprocess, mirroring the re_derivation_invocation
pattern in audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C6 (domain-agnostic generalization).
name='combi_screen_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class CombiScreenReDerivationCheck:
    name: str = "combi_screen_re_derivation"
    applies_to_files: frozenset[str] = frozenset(
        {"inputs/", "payload/combi_screen_result.json"}
    )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "combi_screen_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "combi_screen_re_derivation.py not found alongside "
                    "CombiScreenReDerivationCheck.py; domain pilot opted out of "
                    "combinatorial screen re-derivation"
                ),
                files_audited=(),
            )

        result_path = bundle_dir / "payload" / "combi_screen_result.json"
        if not result_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail=(
                    "payload/combi_screen_result.json absent — no screen result to re-derive"
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
                reason_code="COMBI_SCREEN_REDERIVATION_TIMEOUT",
                detail="combi_screen_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(result_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="COMBI_SCREEN_REDERIVED",
                detail=(
                    "combi_screen_re_derivation.py exited 0 — full ledger and "
                    "advanced set verified"
                ),
                files_audited=(str(result_path),),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="COMBI_SCREEN_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(result_path),),
        )


register_typed_check("combi_screen_re_derivation")
