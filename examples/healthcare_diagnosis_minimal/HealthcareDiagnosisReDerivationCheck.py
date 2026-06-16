"""HealthcareDiagnosisReDerivationCheck — TypedCheck plugin for ICD-10 diagnostic re-derivation.

This plugin is used by the pilot-local verify.py wrapper (examples/healthcare_diagnosis_minimal/
verify.py). The top-level cli/verify.py instead auto-detects re_derive/*_pack.py inside the
bundle and runs the substrate's ReDerivationInvocationCheck against it — same pack, different
plugin shell. Both routes exercise the same stdlib re-derivation pack at
re_derive/healthcare_diagnosis_pack.py.

Wraps healthcare_diagnosis_pack.py via subprocess, mirroring the
re_derivation_invocation pattern from audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C5 (auditor independence) + §C6 (deterministic re-derivation).
name='healthcare_diagnosis_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class HealthcareDiagnosisReDerivationCheck:
    name: str = "healthcare_diagnosis_re_derivation"
    applies_to_files: frozenset[str] = frozenset(
        {
            "inputs/symptoms.json",
            "inputs/rules.json",
            "payload/diagnosis.json",
            "re_derive/healthcare_diagnosis_pack.py",
        }
    )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        # Pack lives inside the bundle (re_derive/) so the bundle is self-
        # contained — same convention as cli/verify.py's auto-detected
        # ReDerivationInvocationCheck (substrate plugin).
        pack_path = bundle_dir / "re_derive" / "healthcare_diagnosis_pack.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "re_derive/healthcare_diagnosis_pack.py not found in bundle; "
                    "pilot opted out of re-derivation"
                ),
                files_audited=(),
            )

        diagnosis_path = bundle_dir / "payload" / "diagnosis.json"
        if not diagnosis_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail="payload/diagnosis.json absent — no diagnosis to re-derive",
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
                reason_code="HEALTHCARE_REDERIVATION_TIMEOUT",
                detail="healthcare_diagnosis_pack.py exceeded 60 s timeout",
                files_audited=(str(diagnosis_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="HEALTHCARE_REDERIVED",
                detail=(
                    "healthcare_diagnosis_pack.py exited 0 — every ICD-10 candidate "
                    "re-derived via deterministic rule-engine traversal of bundled symptoms"
                ),
                files_audited=(str(diagnosis_path),),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="HEALTHCARE_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(diagnosis_path),),
        )


register_typed_check("healthcare_diagnosis_re_derivation")
