"""ScrabbleReDerivationCheck — TypedCheck plugin for Scrabble adjudication re-derivation (C6).

Wraps scrabble_re_derivation.py via subprocess, mirroring the
re_derivation_invocation pattern in audit_bundle/plugins/re_derivation_invocation.py.

the audit-bundle contract §C6 (domain-agnostic generalization).
name='scrabble_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class ScrabbleReDerivationCheck:
    name: str = "scrabble_re_derivation"
    applies_to_files: frozenset[str] = frozenset(
        {"dictionaries/", "editions/", "disputes/", "payload/ruling.json"}
    )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "scrabble_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "scrabble_re_derivation.py not found alongside "
                    "ScrabbleReDerivationCheck.py; domain pilot opted out of "
                    "Scrabble re-derivation"
                ),
                files_audited=(),
            )

        ruling_path = bundle_dir / "payload" / "ruling.json"
        if not ruling_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail="payload/ruling.json absent — no Scrabble ruling to re-derive",
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
                reason_code="SCRABBLE_REDERIVATION_TIMEOUT",
                detail="scrabble_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(ruling_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="SCRABBLE_REDERIVED",
                detail=(
                    "scrabble_re_derivation.py exited 0 — timeline resolves, "
                    "edition matches, window matches, membership lookup matches ruling"
                ),
                files_audited=(str(ruling_path),),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="SCRABBLE_REDERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(ruling_path),),
        )


register_typed_check("scrabble_re_derivation")
