"""PolicyRuleReDerivationCheck — TypedCheck plugin for policy-rule verdict re-derivation.

Wraps policy_re_derivation.py via subprocess, mirroring the re_derivation_invocation
pattern in audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C6 (domain-agnostic re-derivation substrate).
name='policy_rule_re_derivation'
Stdlib only (subprocess, sys, pathlib).

Emits:
  POLICY_REDERIVED             — all verdicts match
  POLICY_REDERIVATION_MISMATCH — at least one verdict does not match
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class PolicyRuleReDerivationCheck:
    name: str = "policy_rule_re_derivation"
    applies_to_files: frozenset[str] = frozenset({
        "payload/policy_verdicts.json",
        "transactions/",
        "policies/",
    })

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "policy_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "policy_re_derivation.py not found alongside "
                    "PolicyRuleReDerivationCheck.py; domain pilot opted out"
                ),
                files_audited=(),
            )

        verdicts_path = bundle_dir / "payload" / "policy_verdicts.json"
        if not verdicts_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail=(
                    "payload/policy_verdicts.json absent — "
                    "no policy verdicts to re-derive"
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
                reason_code="POLICY_REDERIVATION_TIMEOUT",
                detail="policy_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(verdicts_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="POLICY_REDERIVED",
                detail="policy_re_derivation.py exited 0 — all policy verdicts verified",
                files_audited=(str(verdicts_path),),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="POLICY_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(verdicts_path),),
        )


register_typed_check("policy_rule_re_derivation")
