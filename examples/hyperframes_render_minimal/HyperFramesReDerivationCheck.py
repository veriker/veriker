"""HyperFramesReDerivationCheck — TypedCheck plugin for HyperFrames render re-derivation.

Wraps hyperframes_re_derivation.py via subprocess, mirroring the AudioReDerivationCheck
and BuildPyReDerivationCheck patterns. Distinguishes toolchain mismatch
(HYPERFRAMES_TOOLCHAIN_MISMATCH) from re-derivation mismatch
(HYPERFRAMES_REDERIVATION_MISMATCH) so the two failure modes don't get conflated
in failure detail.

the audit-bundle contract §C6 (domain-agnostic re-derivation substrate).
name='hyperframes_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class HyperFramesReDerivationCheck:
    name: str = "hyperframes_re_derivation"
    applies_to_files: frozenset[str] = frozenset({
        "source/index.html",
        "source/hyperframes.json",
        "source/package.json",
        "payload/output.mp4",
        "spec/tooling.json",
    })

    # Re-render budget: blank scaffold renders ~8s; we allow up to 120s to absorb
    # cold-cache npx package resolution + first-run Chrome download cycles.
    _TIMEOUT_SECONDS = 120

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "hyperframes_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "hyperframes_re_derivation.py not found alongside "
                    "HyperFramesReDerivationCheck.py; domain pilot opted out"
                ),
                files_audited=(),
            )

        mp4_path = bundle_dir / "payload" / "output.mp4"
        index_path = bundle_dir / "source" / "index.html"
        spec_path = bundle_dir / "spec" / "tooling.json"
        if not (mp4_path.exists() and index_path.exists() and spec_path.exists()):
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail=(
                    "payload/output.mp4, source/index.html, or spec/tooling.json "
                    "absent — no HyperFrames render to re-derive"
                ),
                files_audited=(),
            )

        try:
            result = subprocess.run(
                [sys.executable, str(pack_path), "--bundle-dir", str(bundle_dir)],
                capture_output=True,
                timeout=self._TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return PluginResult(
                ok=False,
                reason_code="HYPERFRAMES_REDERIVATION_TIMEOUT",
                detail=(
                    f"hyperframes_re_derivation.py exceeded "
                    f"{self._TIMEOUT_SECONDS} s timeout"
                ),
                files_audited=(str(mp4_path), str(index_path), str(spec_path)),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="HYPERFRAMES_REDERIVED",
                detail=(
                    "hyperframes_re_derivation.py exited 0 — re-rendered MP4 "
                    "sha256 matches committed sha256"
                ),
                files_audited=(str(mp4_path), str(index_path), str(spec_path)),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        # Surface toolchain-mismatch vs re-derivation-mismatch via reason_code
        if "HYPERFRAMES_TOOLCHAIN_MISMATCH" in stderr_snippet:
            reason = "HYPERFRAMES_TOOLCHAIN_MISMATCH"
        elif "HYPERFRAMES_TOOLCHAIN_MISSING" in stderr_snippet:
            reason = "HYPERFRAMES_TOOLCHAIN_MISSING"
        else:
            reason = "HYPERFRAMES_REDERIVATION_MISMATCH"
        return PluginResult(
            ok=False,
            reason_code=reason,
            detail=stderr_snippet,
            files_audited=(str(mp4_path), str(index_path), str(spec_path)),
        )


register_typed_check("hyperframes_re_derivation")
