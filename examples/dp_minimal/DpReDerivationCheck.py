"""DpReDerivationCheck — TypedCheck plugin for differential-privacy release re-derivation.

Wraps dp_re_derivation.py via subprocess, mirroring the re_derivation_invocation
pattern in audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C6 (probabilistic-output generalization).
name='dp_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class DpReDerivationCheck:
    name: str = "dp_re_derivation"
    applies_to_files: frozenset[str] = frozenset({"data/", "payload/dp_release.json"})

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "dp_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "dp_re_derivation.py not found alongside DpReDerivationCheck.py; "
                    "domain pilot opted out of DP re-derivation"
                ),
                files_audited=(),
            )

        release_path = bundle_dir / "payload" / "dp_release.json"
        if not release_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail="payload/dp_release.json absent — no DP release to re-derive",
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
                reason_code="DP_REDERIVATION_TIMEOUT",
                detail="dp_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(release_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="DP_REDERIVED",
                detail="dp_re_derivation.py exited 0 — true_count and noised_count verified",
                files_audited=(str(release_path),),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="DP_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(release_path),),
        )


register_typed_check("dp_re_derivation")
