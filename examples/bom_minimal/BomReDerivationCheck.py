"""BomReDerivationCheck — TypedCheck plugin for supply-chain BOM re-derivation.

Wraps bom_re_derivation.py via subprocess, mirroring the re_derivation_invocation
pattern in audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C6 (domain-agnostic re-derivation substrate).
name='bom_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class BomReDerivationCheck:
    name: str = "bom_re_derivation"
    applies_to_files: frozenset[str] = frozenset({"lockfile/", "payload/resolved_tree.json"})

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "bom_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "bom_re_derivation.py not found alongside BomReDerivationCheck.py; "
                    "domain pilot opted out"
                ),
                files_audited=(),
            )

        lockfile_path = bundle_dir / "lockfile" / "lockfile.json"
        tree_path = bundle_dir / "payload" / "resolved_tree.json"

        if not lockfile_path.exists() or not tree_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail="lockfile/lockfile.json or payload/resolved_tree.json absent — no BOM to re-derive",
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
                reason_code="BOM_REDERIVATION_TIMEOUT",
                detail="bom_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(lockfile_path), str(tree_path)),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="BOM_REDERIVED",
                detail="bom_re_derivation.py exited 0 — all BOM nodes verified",
                files_audited=(str(lockfile_path), str(tree_path)),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="BOM_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(lockfile_path), str(tree_path)),
        )


register_typed_check("bom_re_derivation")
