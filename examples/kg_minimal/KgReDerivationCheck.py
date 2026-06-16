"""KgReDerivationCheck — TypedCheck plugin for KG path-query re-derivation (C6).

Wraps kg_re_derivation.py via subprocess, mirroring the re_derivation_invocation
pattern in audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C6 (domain-agnostic generalization).
name='kg_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class KgReDerivationCheck:
    name: str = "kg_re_derivation"
    applies_to_files: frozenset[str] = frozenset({"kg/", "payload/query_result.json"})

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "kg_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "kg_re_derivation.py not found alongside KgReDerivationCheck.py; "
                    "domain pilot opted out of KG re-derivation"
                ),
                files_audited=(),
            )

        qr_path = bundle_dir / "payload" / "query_result.json"
        if not qr_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail="payload/query_result.json absent — no KG query result to re-derive",
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
                reason_code="KG_REDERIVATION_TIMEOUT",
                detail="kg_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(qr_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="KG_REDERIVED",
                detail="kg_re_derivation.py exited 0 — all KG path invariants verified",
                files_audited=(str(qr_path),),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="KG_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(qr_path),),
        )


register_typed_check("kg_re_derivation")
