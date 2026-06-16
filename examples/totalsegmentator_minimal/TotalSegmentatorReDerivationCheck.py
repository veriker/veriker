"""TotalSegmentatorReDerivationCheck — TypedCheck plugin for TotalSegmentator inference re-derivation.

Wraps totalsegmentator_re_derivation.py via subprocess, mirroring the
HyperFramesReDerivationCheck and BuildPyReDerivationCheck patterns. Distinguishes
toolchain mismatch (TOTALSEGMENTATOR_TOOLCHAIN_MISMATCH) from re-derivation
mismatch (TOTALSEGMENTATOR_REDERIVATION_MISMATCH) so the two failure modes
don't get conflated in the failure detail — toolchain drift and model-output
drift are very different operator-facing problems.

the audit-bundle contract §C6 (domain-agnostic re-derivation substrate).
name='totalsegmentator_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class TotalSegmentatorReDerivationCheck:
    name: str = "totalsegmentator_re_derivation"
    applies_to_files: frozenset[str] = frozenset({
        "source/",
        "payload/segmentation.nii.gz",
        "spec/tooling.json",
    })

    # CPU inference budget. Phantom + task_id=297 (3mm fast) measured at ~15-25 s on
    # an 8-core CPU; allow up to 300 s for slower laptops, real-CT inputs via
    # --ct-path, or first-run weight-download warmup. The brief specifies 300.
    _TIMEOUT_SECONDS = 300

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "totalsegmentator_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "totalsegmentator_re_derivation.py not found alongside "
                    "TotalSegmentatorReDerivationCheck.py; domain pilot opted out"
                ),
                files_audited=(),
            )

        seg_path = bundle_dir / "payload" / "segmentation.nii.gz"
        src_dir = bundle_dir / "source"
        spec_path = bundle_dir / "spec" / "tooling.json"
        if not (seg_path.exists() and src_dir.exists() and spec_path.exists()):
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail=(
                    "payload/segmentation.nii.gz, source/, or spec/tooling.json "
                    "absent — no TotalSegmentator inference to re-derive"
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
                reason_code="TOTALSEGMENTATOR_REDERIVATION_TIMEOUT",
                detail=(
                    f"totalsegmentator_re_derivation.py exceeded "
                    f"{self._TIMEOUT_SECONDS} s timeout"
                ),
                files_audited=(str(seg_path), str(src_dir), str(spec_path)),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="TOTALSEGMENTATOR_REDERIVED",
                detail=(
                    "totalsegmentator_re_derivation.py exited 0 — re-derived "
                    "segmentation sha256 matches committed sha256"
                ),
                files_audited=(str(seg_path), str(src_dir), str(spec_path)),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        # Surface toolchain-mismatch vs re-derivation-mismatch via reason_code
        if "TOTALSEGMENTATOR_TOOLCHAIN_MISMATCH" in stderr_snippet:
            reason = "TOTALSEGMENTATOR_TOOLCHAIN_MISMATCH"
        elif "TOTALSEGMENTATOR_TOOLCHAIN_MISSING" in stderr_snippet:
            reason = "TOTALSEGMENTATOR_TOOLCHAIN_MISSING"
        else:
            reason = "TOTALSEGMENTATOR_REDERIVATION_MISMATCH"
        return PluginResult(
            ok=False,
            reason_code=reason,
            detail=stderr_snippet,
            files_audited=(str(seg_path), str(src_dir), str(spec_path)),
        )


register_typed_check("totalsegmentator_re_derivation")
