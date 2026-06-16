"""PriorAuthReDerivationCheck — TypedCheck plugin for prior-auth re-derivation (C6).

Wraps prior_auth_re_derivation.py via subprocess.

Two checks in one plugin:
  1. Medical-necessity rule re-derivation: re-evaluates the decision tree from
     bundled clinical findings + plan rules and asserts the verdicts + rule IDs
     match payload/prior_auth_decisions.json.
  2. Provider attestation HMAC re-verification: for every row in
     payload/decision_provenance.jsonl, re-computes HMAC-SHA256 of
     (provider_id || decision_id || provider_verdict || attestation_timestamp)
     under the bundle's committed attestation key and asserts it matches the
     stored attestation_hmac.

Reason codes:
  PRIOR_AUTH_REDERIVED                    — both invariants passed
  PRIOR_AUTH_REDERIVATION_MISMATCH        — decision-tree mismatch
  PRIOR_AUTH_PROVIDER_ATTESTATION_INVALID — HMAC verification failure

the audit-bundle contract §C6 (domain-agnostic re-derivation).
name='prior_auth_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class PriorAuthReDerivationCheck:
    name: str = "prior_auth_re_derivation"
    applies_to_files: frozenset[str] = frozenset(
        {
            "clinical/",
            "payload/prior_auth_decisions.json",
            "payload/decision_provenance.jsonl",
            "payload/attestation_key.hex",
        }
    )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "prior_auth_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "prior_auth_re_derivation.py not found alongside "
                    "PriorAuthReDerivationCheck.py; domain pilot opted out"
                ),
                files_audited=(),
            )

        decisions_path = bundle_dir / "payload" / "prior_auth_decisions.json"
        if not decisions_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail=(
                    "payload/prior_auth_decisions.json absent — "
                    "no prior-auth decisions to re-derive"
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
                reason_code="PRIOR_AUTH_REDERIVATION_TIMEOUT",
                detail="prior_auth_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(decisions_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="PRIOR_AUTH_REDERIVED",
                detail=(
                    "prior_auth_re_derivation.py exited 0 — all prior-auth "
                    "decision-tree invariants verified and all provider "
                    "attestation HMACs validated"
                ),
                files_audited=(str(decisions_path),),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]

        # Distinguish HMAC failure from decision-tree mismatch based on stderr tag
        if "PRIOR_AUTH_PROVIDER_ATTESTATION_INVALID" in stderr_snippet:
            return PluginResult(
                ok=False,
                reason_code="PRIOR_AUTH_PROVIDER_ATTESTATION_INVALID",
                detail=stderr_snippet,
                files_audited=(str(decisions_path),),
            )

        return PluginResult(
            ok=False,
            reason_code="PRIOR_AUTH_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(decisions_path),),
        )


register_typed_check("prior_auth_re_derivation")
