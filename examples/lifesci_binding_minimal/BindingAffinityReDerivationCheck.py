"""BindingAffinityReDerivationCheck — TypedCheck plugin for drug-binding affinity re-derivation.

Wraps binding_affinity_re_derivation.py via subprocess, following the
re_derivation_invocation pattern from audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C5 (auditor independence) + §C6 (deterministic re-derivation).
name='binding_affinity_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class BindingAffinityReDerivationCheck:
    name: str = "binding_affinity_re_derivation"
    applies_to_files: frozenset[str] = frozenset(
        {
            "inputs/compound_descriptor.json",
            "inputs/target_descriptor.json",
            "payload/scoring_weights.json",
            "payload/binding_prediction.json",
        }
    )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "binding_affinity_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "binding_affinity_re_derivation.py not found alongside "
                    "BindingAffinityReDerivationCheck.py; pilot opted out of re-derivation"
                ),
                files_audited=(),
            )

        prediction_path = bundle_dir / "payload" / "binding_prediction.json"
        if not prediction_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail=(
                    "payload/binding_prediction.json absent — "
                    "no binding prediction to re-derive"
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
                reason_code="BINDING_REDERIVATION_TIMEOUT",
                detail="binding_affinity_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(prediction_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="BINDING_REDERIVED",
                detail=(
                    "binding_affinity_re_derivation.py exited 0 — affinity_pred verified "
                    "via deterministic feature-hash weighted-sum scorer re-execution"
                ),
                files_audited=(str(prediction_path),),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="BINDING_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(prediction_path),),
        )


register_typed_check("binding_affinity_re_derivation")
