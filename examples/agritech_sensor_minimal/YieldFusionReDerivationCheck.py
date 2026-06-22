"""YieldFusionReDerivationCheck — TypedCheck plugin for agritech yield-score re-derivation.

Wraps yield_fusion_re_derivation.py via subprocess, following the
re_derivation_invocation pattern from audit_bundle/plugins/.

the audit-bundle contract §C6 (domain-agnostic re-derivation substrate).
name='yield_fusion_re_derivation'
Stdlib only (subprocess, sys, pathlib).

Emit codes:
  YIELD_REDERIVED             — ok path, subprocess exited 0
  YIELD_REDERIVATION_MISMATCH — fail path, subprocess exited non-zero
  YIELD_REDERIVATION_TIMEOUT  — fail path, subprocess exceeded 60 s
  NO_PACK                     — skip, pack not found (ok=True, advisory)
  NO_INPUTS                   — skip, bundle inputs absent (ok=True, advisory)
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class YieldFusionReDerivationCheck:
    name: str = "yield_fusion_re_derivation"
    applies_to_files: frozenset[str] = frozenset({
        "inputs/sensor_stream.json",
        "payload/fusion_weights.json",
        "payload/yield_forecast.json",
    })

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "yield_fusion_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "yield_fusion_re_derivation.py not found alongside "
                    "YieldFusionReDerivationCheck.py; pilot opted out of C6"
                ),
                files_audited=(),
            )

        stream_path   = bundle_dir / "inputs"  / "sensor_stream.json"
        forecast_path = bundle_dir / "payload" / "yield_forecast.json"
        weights_path  = bundle_dir / "payload" / "fusion_weights.json"

        if not stream_path.exists() or not forecast_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_INPUTS",
                detail=(
                    "inputs/sensor_stream.json or payload/yield_forecast.json "
                    "absent — no sensor records to re-derive"
                ),
                files_audited=(),
            )

        files_audited = (str(stream_path), str(forecast_path), str(weights_path))

        try:
            result = subprocess.run(
                [sys.executable, str(pack_path), "--bundle-dir", str(bundle_dir)],
                capture_output=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            return PluginResult(
                ok=False,
                reason_code="YIELD_REDERIVATION_TIMEOUT",
                detail="yield_fusion_re_derivation.py exceeded 60 s timeout",
                files_audited=files_audited,
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="YIELD_REDERIVED",
                detail="yield_fusion_re_derivation.py exited 0 — yield forecast verified",
                files_audited=files_audited,
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="YIELD_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=files_audited,
        )


register_typed_check("yield_fusion_re_derivation")
