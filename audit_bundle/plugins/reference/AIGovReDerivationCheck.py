"""AIGovReDerivationCheck — TypedCheck plugin for AI-governance control re-derivation.

Wraps aigov_rederivation.py via subprocess. The same re-derivation plumbing shipped
for span (C6), SMT (C16), and SOC 2 controls (control_rederivation), pointed at
EU AI Act / ISO 42001 high-risk-AI obligations.

Implements the audit-bundle contract §C6 (domain-agnostic re-derivation) and the §C16
principle that the verifier — never the dispatcher/collector — sets the verdict.
name='aigov_rederivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class AIGovReDerivationCheck:
    name: str = "aigov_rederivation"
    applies_to_files: frozenset[str] = frozenset({"payload/control_attestations.json"})

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        # SAFE-BY-ORIGIN: __file__-rooted = verifier-distribution code, NOT
        # bundle-supplied, so this runs ungated by design (unlike
        # re_derivation_invocation's bundle pack, which requires permit_execution).
        # Relocating this to a bundle_dir path REQUIRES adding the gate —
        # tests/test_bundle_exec_gate_structural.py enforces it.
        pack_path = Path(__file__).parent / "aigov_rederivation.py"
        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail="aigov_rederivation.py not found alongside plugin; pilot opted out",
                files_audited=(),
            )

        attestations_path = bundle_dir / "payload" / "control_attestations.json"
        if not attestations_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail="payload/control_attestations.json absent — no control verdicts to re-derive",
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
                reason_code="AIGOV_REDERIVE_TIMEOUT",
                detail="aigov_rederivation.py exceeded 60 s timeout",
                files_audited=(str(attestations_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="AIGOV_REDERIVED",
                detail="every AI-governance verdict signed, control+test_fn pinned, evidence-bound, and re-derived",
                files_audited=(str(attestations_path),),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="AIGOV_REDERIVE_VIOLATION",
            detail=stderr_snippet,
            files_audited=(str(attestations_path),),
        )


register_typed_check("aigov_rederivation")
