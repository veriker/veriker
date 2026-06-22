"""RasterReDerivationCheck — TypedCheck plugin for geospatial raster re-derivation.

Wraps raster_re_derivation.py via subprocess, mirroring the re_derivation_invocation
pattern in audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C6 (domain-agnostic re-derivation substrate).
name='raster_re_derivation'
Stdlib only (subprocess, sys, pathlib).

Reason codes:
  RASTER_REDERIVED           — subprocess exited 0, all checks passed
  RASTER_REDERIVATION_MISMATCH — subprocess exited 1, mismatch detected
  RASTER_REDERIVATION_TIMEOUT  — subprocess exceeded 60 s timeout
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class RasterReDerivationCheck:
    name: str = "raster_re_derivation"
    applies_to_files: frozenset[str] = frozenset(
        {"raster/", "spec/", "payload/zonal_result.json"}
    )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "raster_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "raster_re_derivation.py not found alongside "
                    "RasterReDerivationCheck.py; domain pilot opted out"
                ),
                files_audited=(),
            )

        grid_path = bundle_dir / "raster" / "grid.bin"
        result_path = bundle_dir / "payload" / "zonal_result.json"

        if not grid_path.exists() or not result_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail=(
                    "raster/grid.bin or payload/zonal_result.json absent "
                    "— no raster to re-derive"
                ),
                files_audited=(),
            )

        try:
            proc = subprocess.run(
                [sys.executable, str(pack_path), "--bundle-dir", str(bundle_dir)],
                capture_output=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            return PluginResult(
                ok=False,
                reason_code="RASTER_REDERIVATION_TIMEOUT",
                detail="raster_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(grid_path), str(result_path)),
            )

        if proc.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="RASTER_REDERIVED",
                detail=(
                    "raster_re_derivation.py exited 0 — "
                    "zonal aggregate verified via ray-casting"
                ),
                files_audited=(str(grid_path), str(result_path)),
            )

        stderr_snippet = (proc.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="RASTER_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(grid_path), str(result_path)),
        )


register_typed_check("raster_re_derivation")
