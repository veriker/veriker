"""StreamingReDerivationCheck — TypedCheck plugin for event-time tumbling-window re-derivation.

Wraps streaming_re_derivation.py via subprocess, mirroring the re_derivation_invocation
pattern in audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C6 (domain-agnostic re-derivation substrate).
name='streaming_re_derivation'
Stdlib only (subprocess, sys, pathlib).

Reason codes emitted:
  STREAMING_REDERIVED                  — re-derivation matched checkpoint exactly
  STREAMING_REDERIVATION_MISMATCH      — per-window aggregate or count differs from checkpoint
  STREAMING_LATE_EVENT_POLICY_VIOLATED — late_event_policy in spec is not "drop"
  STREAMING_REDERIVATION_TIMEOUT       — subprocess exceeded 60 s timeout
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class StreamingReDerivationCheck:
    name: str = "streaming_re_derivation"
    applies_to_files: frozenset[str] = frozenset({"events/", "payload/checkpoint.json"})

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "streaming_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "streaming_re_derivation.py not found alongside "
                    "StreamingReDerivationCheck.py; domain pilot opted out"
                ),
                files_audited=(),
            )

        stream_path = bundle_dir / "events" / "stream.jsonl"
        checkpoint_path = bundle_dir / "payload" / "checkpoint.json"

        if not stream_path.exists() or not checkpoint_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail=(
                    "events/stream.jsonl or payload/checkpoint.json absent "
                    "— no streaming output to re-derive"
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
                reason_code="STREAMING_REDERIVATION_TIMEOUT",
                detail="streaming_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(stream_path), str(checkpoint_path)),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="STREAMING_REDERIVED",
                detail=(
                    "streaming_re_derivation.py exited 0 — all per-window aggregate "
                    "states verified against bundled checkpoint"
                ),
                files_audited=(str(stream_path), str(checkpoint_path)),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]

        # Distinguish late-event-policy violation from general mismatch
        if "STREAMING_LATE_EVENT_POLICY_VIOLATED" in stderr_snippet:
            reason_code = "STREAMING_LATE_EVENT_POLICY_VIOLATED"
        else:
            reason_code = "STREAMING_REDERIVATION_MISMATCH"

        return PluginResult(
            ok=False,
            reason_code=reason_code,
            detail=stderr_snippet,
            files_audited=(str(stream_path), str(checkpoint_path)),
        )


register_typed_check("streaming_re_derivation")
