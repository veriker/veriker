"""LegalContractReDerivationCheck — TypedCheck plugin for legal contract re-derivation.

This plugin is used by the pilot-local verify.py wrapper (examples/legal_contract_minimal/
verify.py). The top-level cli/verify.py instead auto-detects re_derive/*_pack.py inside the
bundle and runs the substrate's ReDerivationInvocationCheck against it — same pack, different
plugin shell. Both routes exercise the same stdlib re-derivation pack at
re_derive/legal_contract_pack.py.

Wraps legal_contract_pack.py via subprocess, mirroring the
re_derivation_invocation pattern from audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C5 (auditor independence) + §C6 (deterministic re-derivation).
name='legal_contract_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class LegalContractReDerivationCheck:
    name: str = "legal_contract_re_derivation"
    applies_to_files: frozenset[str] = frozenset(
        {
            "inputs/clauses.json",
            "inputs/precedents.json",
            "payload/retrieval_result.json",
            "re_derive/legal_contract_pack.py",
        }
    )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = bundle_dir / "re_derive" / "legal_contract_pack.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "re_derive/legal_contract_pack.py not found in bundle; "
                    "pilot opted out of re-derivation"
                ),
                files_audited=(),
            )

        result_path = bundle_dir / "payload" / "retrieval_result.json"
        if not result_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail="payload/retrieval_result.json absent — no retrieval result to re-derive",
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
                reason_code="LEGAL_CONTRACT_REDERIVATION_TIMEOUT",
                detail="legal_contract_pack.py exceeded 60 s timeout",
                files_audited=(str(result_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="LEGAL_CONTRACT_REDERIVED",
                detail=(
                    "legal_contract_pack.py exited 0 — every clause's case_cite list "
                    "re-derived via deterministic keyword-overlap retrieval from bundled inputs"
                ),
                files_audited=(str(result_path),),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="LEGAL_CONTRACT_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(result_path),),
        )


register_typed_check("legal_contract_re_derivation")
