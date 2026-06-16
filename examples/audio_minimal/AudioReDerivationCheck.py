"""AudioReDerivationCheck — TypedCheck plugin for VAD audio segment re-derivation.

Wraps audio_re_derivation.py via subprocess, mirroring the re_derivation_invocation
pattern in audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C6 (domain-agnostic re-derivation substrate).
name='audio_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class AudioReDerivationCheck:
    name: str = "audio_re_derivation"
    applies_to_files: frozenset[str] = frozenset({"audio/", "payload/transcript.json"})

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "audio_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "audio_re_derivation.py not found alongside AudioReDerivationCheck.py; "
                    "domain pilot opted out"
                ),
                files_audited=(),
            )

        audio_path = bundle_dir / "audio" / "samples.bin"
        transcript_path = bundle_dir / "payload" / "transcript.json"

        if not audio_path.exists() or not transcript_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail=(
                    "audio/samples.bin or payload/transcript.json absent "
                    "— no audio VAD output to re-derive"
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
                reason_code="AUDIO_REDERIVATION_TIMEOUT",
                detail="audio_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(audio_path), str(transcript_path)),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="AUDIO_REDERIVED",
                detail="audio_re_derivation.py exited 0 — all VAD segment boundaries verified",
                files_audited=(str(audio_path), str(transcript_path)),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="AUDIO_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(audio_path), str(transcript_path)),
        )


register_typed_check("audio_re_derivation")
