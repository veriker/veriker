"""PIIRedactionReDerivationCheck — TypedCheck plugin for PII re-derivation (C6).

Wraps pii_redaction_re_derivation.py via subprocess, mirroring the pattern in
KgReDerivationCheck.py.

name='pii_redaction_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class PIIRedactionReDerivationCheck:
    name: str = "pii_redaction_re_derivation"
    applies_to_files: frozenset[str] = frozenset(
        {
            "payload/bioes_logits.json",
            "payload/tokens.json",
            "payload/redaction_output.json",
        }
    )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "pii_redaction_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail="pii_redaction_re_derivation.py not found; pilot opted out",
                files_audited=(),
            )

        output_path = bundle_dir / "payload" / "redaction_output.json"
        if not output_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail="payload/redaction_output.json absent — no PII output to re-derive",
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
                reason_code="PII_REDACTION_REDERIVATION_TIMEOUT",
                detail="pii_redaction_re_derivation.py exceeded 60s timeout",
                files_audited=(str(output_path),),
            )

        stdout = (result.stdout or b"").decode("utf-8", errors="replace").strip()

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="PII_REDACTION_REDERIVED",
                detail=stdout or "all PII span and redacted-text invariants verified",
                files_audited=(str(output_path),),
            )

        # Parse structured JSON error from stdout if present
        detail = (
            stdout or (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        )
        try:
            err_obj = json.loads(stdout)
            detail = err_obj.get("reason", detail)
        except (json.JSONDecodeError, ValueError):
            pass

        return PluginResult(
            ok=False,
            reason_code="PII_REDACTION_REDERIVATION_MISMATCH",
            detail=f"PII_REDACTION_REDERIVATION_MISMATCH: {detail}",
            files_audited=(str(output_path),),
        )


register_typed_check("pii_redaction_re_derivation")
