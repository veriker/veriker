"""SensorReDerivationCheck — TypedCheck plugin for sensor-output re-derivation (C6).

Wraps energy_score_pack.py via subprocess, mirroring the re_derivation_invocation
pattern in audit_bundle/plugins/re_derivation_invocation.py.

Reference implementation for sensor-output re-derivation.
name='sensor_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class SensorReDerivationCheck:
    name: str = "sensor_re_derivation"
    # exact-path-only: dropped the inert {"raw_traces/"} trailing-slash
    # pseudo-prefix (consumed by exact match, never matched a real path); the
    # two exact-path entries are retained.
    applies_to_files: frozenset[str] = frozenset(
        {"energy_score.json", "sleep_stages.json"}
    )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        # SAFE-BY-ORIGIN: __file__-rooted = verifier-distribution code, NOT
        # bundle-supplied, so this runs ungated by design (unlike
        # re_derivation_invocation's bundle pack, which requires permit_execution).
        # Relocating this to a bundle_dir path REQUIRES adding the gate —
        # tests/test_bundle_exec_gate_structural.py enforces it.
        pack_path = Path(__file__).parent / "energy_score_pack.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "energy_score_pack.py not found alongside SensorReDerivationCheck.py; "
                    "domain pilot opted out of C6"
                ),
                files_audited=(),
            )

        raw_traces_dir = bundle_dir / "raw_traces"
        if not raw_traces_dir.exists() or not any(raw_traces_dir.iterdir()):
            return PluginResult(
                ok=True,
                reason_code="NO_TRACES",
                detail="raw_traces/ absent or empty — no sensor records to re-derive",
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
                reason_code="RE_DERIVATION_TIMEOUT",
                detail="energy_score_pack.py exceeded 60 s timeout",
                files_audited=(str(raw_traces_dir),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="RE_DERIVED",
                detail="energy_score_pack.py exited 0 — sensor re-derivation verified",
                files_audited=(str(raw_traces_dir),),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="RE_DERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(raw_traces_dir),),
        )


register_typed_check("sensor_re_derivation")
