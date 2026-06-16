"""FpMlReDerivationCheck — TypedCheck plugin for FP ML inference re-derivation.

Wraps fp_ml_re_derivation.py via subprocess, mirroring the re_derivation_invocation
pattern in audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C5 (auditor independence) + §C6 (deterministic re-derivation).
name='fp_ml_re_derivation'
Stdlib only (subprocess, sys, pathlib).

Reason codes:
  FP_ML_REDERIVED                  — success (all logits within tolerance, argmax matches)
  FP_ML_REDERIVATION_MISMATCH      — delta exceeds tolerance OR argmax mismatch
  FP_ML_REDERIVATION_TIMEOUT       — subprocess exceeded timeout
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class FpMlReDerivationCheck:
    name: str = "fp_ml_re_derivation"
    applies_to_files: frozenset[str] = frozenset(
        {"inputs/", "weights/", "payload/predictions.json"}
    )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "fp_ml_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "fp_ml_re_derivation.py not found alongside FpMlReDerivationCheck.py; "
                    "domain pilot opted out of FP ML re-derivation"
                ),
                files_audited=(),
            )

        predictions_path = bundle_dir / "payload" / "predictions.json"
        if not predictions_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail="payload/predictions.json absent — no FP ML predictions to re-derive",
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
                reason_code="FP_ML_REDERIVATION_TIMEOUT",
                detail="fp_ml_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(predictions_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="FP_ML_REDERIVED",
                detail=(
                    "fp_ml_re_derivation.py exited 0 — all logits within declared tolerance ε "
                    "and all argmaxes match exactly (float32 struct.pack/unpack discipline)"
                ),
                files_audited=(str(predictions_path),),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="FP_ML_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(predictions_path),),
        )


register_typed_check("fp_ml_re_derivation")
