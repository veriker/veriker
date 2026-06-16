"""CreditScoringReDerivationCheck — TypedCheck plugin for credit-scoring re-derivation (C6).

Wraps credit_scoring_re_derivation.py via subprocess, mirroring the re_derivation_invocation
pattern in audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C6 (domain-agnostic generalization).
name='credit_scoring_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class CreditScoringReDerivationCheck:
    name: str = "credit_scoring_re_derivation"
    applies_to_files: frozenset[str] = frozenset(
        {"model/", "applicants/", "payload/credit_decisions.json"}
    )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "credit_scoring_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "credit_scoring_re_derivation.py not found alongside "
                    "CreditScoringReDerivationCheck.py; domain pilot opted out of "
                    "credit-scoring re-derivation"
                ),
                files_audited=(),
            )

        payload_path = bundle_dir / "payload" / "credit_decisions.json"
        if not payload_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail="payload/credit_decisions.json absent — no credit decisions to re-derive",
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
                reason_code="CREDIT_SCORING_REDERIVATION_TIMEOUT",
                detail="credit_scoring_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(payload_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="CREDIT_SCORING_REDERIVED",
                detail=(
                    "credit_scoring_re_derivation.py exited 0 — all PD scores, "
                    "tier decisions, and APR values re-derived successfully"
                ),
                files_audited=(str(payload_path),),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="CREDIT_SCORING_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(payload_path),),
        )


register_typed_check("credit_scoring_re_derivation")
