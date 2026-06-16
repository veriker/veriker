"""MlReDerivationCheck — TypedCheck plugin for ML inference re-derivation.

Wraps ml_re_derivation.py via subprocess, mirroring the re_derivation_invocation
pattern in audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C5 (auditor independence) + §C6 (deterministic re-derivation).
name='ml_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class MlReDerivationCheck:
    name: str = "ml_re_derivation"
    applies_to_files: frozenset[str] = frozenset(
        {"inputs/", "weights/", "payload/predictions.json"}
    )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "ml_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "ml_re_derivation.py not found alongside MlReDerivationCheck.py; "
                    "domain pilot opted out of ML re-derivation"
                ),
                files_audited=(),
            )

        predictions_path = bundle_dir / "payload" / "predictions.json"
        if not predictions_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail="payload/predictions.json absent — no ML predictions to re-derive",
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
                reason_code="ML_REDERIVATION_TIMEOUT",
                detail="ml_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(predictions_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="ML_REDERIVED",
                detail=(
                    "ml_re_derivation.py exited 0 — all predictions verified "
                    "via integer-only linear classifier re-inference"
                ),
                files_audited=(str(predictions_path),),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="ML_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(predictions_path),),
        )


register_typed_check("ml_re_derivation")
