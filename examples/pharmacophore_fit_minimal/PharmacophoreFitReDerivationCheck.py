"""PharmacophoreFitReDerivationCheck — TypedCheck plugin for spatial-fit RMSD re-derivation (C6).

Wraps pharmacophore_fit_re_derivation.py via subprocess, mirroring the
re_derivation_invocation pattern in audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C6 (domain-agnostic generalization).
name='pharmacophore_fit_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class PharmacophoreFitReDerivationCheck:
    name: str = "pharmacophore_fit_re_derivation"
    applies_to_files: frozenset[str] = frozenset(
        {"inputs/", "payload/spatial_fit_result.json"}
    )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "pharmacophore_fit_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "pharmacophore_fit_re_derivation.py not found alongside "
                    "PharmacophoreFitReDerivationCheck.py; domain pilot opted "
                    "out of pharmacophore-fit re-derivation"
                ),
                files_audited=(),
            )

        result_path = bundle_dir / "payload" / "spatial_fit_result.json"
        if not result_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail=(
                    "payload/spatial_fit_result.json absent — no fit result to re-derive"
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
                reason_code="PHARMACOPHORE_FIT_REDERIVATION_TIMEOUT",
                detail="pharmacophore_fit_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(result_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="PHARMACOPHORE_FIT_REDERIVED",
                detail=(
                    "pharmacophore_fit_re_derivation.py exited 0 — full per-candidate "
                    "RMSD ledger, ranked list, and advanced set verified"
                ),
                files_audited=(str(result_path),),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="PHARMACOPHORE_FIT_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(result_path),),
        )


register_typed_check("pharmacophore_fit_re_derivation")
