"""AnticheatReDerivationCheck — TypedCheck plugin for anti-cheat ban-adjudication re-derivation (C6).

Wraps anticheat_re_derivation.py via subprocess.

Two checks in one plugin:
  1. Detection-policy re-derivation: re-evaluates the threshold rule set from
     bundled detection signals + committed policy and asserts the verdicts +
     rule IDs match payload/ban_decisions.json.
  2. Adjudicator attestation HMAC re-verification: for every row in
     payload/adjudication_provenance.jsonl, re-computes HMAC-SHA256 of
     (adjudicator_id || case_id || final_verdict || attestation_timestamp)
     under the bundle's committed attestation key and asserts it matches the
     stored attestation_hmac.

Reason codes:
  ANTICHEAT_REDERIVED                       — both invariants passed
  ANTICHEAT_REDERIVATION_MISMATCH           — decision-policy mismatch
  ANTICHEAT_ADJUDICATOR_ATTESTATION_INVALID — HMAC verification failure

the audit-bundle contract §C6 (domain-agnostic re-derivation).
name='anticheat_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class AnticheatReDerivationCheck:
    name: str = "anticheat_re_derivation"
    applies_to_files: frozenset[str] = frozenset(
        {
            "evidence/",
            "payload/ban_decisions.json",
            "payload/adjudication_provenance.jsonl",
            "payload/attestation_key.hex",
        }
    )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "anticheat_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "anticheat_re_derivation.py not found alongside "
                    "AnticheatReDerivationCheck.py; domain pilot opted out"
                ),
                files_audited=(),
            )

        decisions_path = bundle_dir / "payload" / "ban_decisions.json"
        if not decisions_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail=(
                    "payload/ban_decisions.json absent — "
                    "no ban-adjudication verdicts to re-derive"
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
                reason_code="ANTICHEAT_REDERIVATION_TIMEOUT",
                detail="anticheat_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(decisions_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="ANTICHEAT_REDERIVED",
                detail=(
                    "anticheat_re_derivation.py exited 0 — all ban-adjudication "
                    "verdicts re-derived from committed policy and all adjudicator "
                    "attestation HMACs validated"
                ),
                files_audited=(str(decisions_path),),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]

        # Distinguish HMAC failure from decision-policy mismatch based on stderr tag
        if "ANTICHEAT_ADJUDICATOR_ATTESTATION_INVALID" in stderr_snippet:
            return PluginResult(
                ok=False,
                reason_code="ANTICHEAT_ADJUDICATOR_ATTESTATION_INVALID",
                detail=stderr_snippet,
                files_audited=(str(decisions_path),),
            )

        return PluginResult(
            ok=False,
            reason_code="ANTICHEAT_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(decisions_path),),
        )


register_typed_check("anticheat_re_derivation")
