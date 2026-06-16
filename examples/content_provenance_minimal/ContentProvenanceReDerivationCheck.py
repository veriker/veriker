"""ContentProvenanceReDerivationCheck — TypedCheck plugin for content provenance domain.

Wraps content_provenance_re_derivation.py via subprocess (AB4 — duplicate-don't-import).
Emits CONTENT_PROVENANCE_VERIFIED on pass, CONTENT_PROVENANCE_ALTERED on failure.

The check:
  1. Re-hashes artifact/content.txt and asserts the SHA matches the producer-signed
     manifest and the payload's committed content_sha.
  2. Re-computes the producer HMAC over the content bytes and asserts it matches
     the hmac field in artifact/provenance.json.
  3. Asserts the provenance chain (producer_id + generation_inputs) is intact.

SCOPE BOUNDARY:
This proves WHAT a system produced and that the content has NOT been altered since
it was signed by its stated producer.  It is NOT truth-detection and NOT a
disinformation classifier.  A factually FALSE but unaltered, correctly-signed piece
of content PASSES this check — that is by design and out of scope.

the audit-bundle contract §C6 (re-derivation) + §C5 (auditor independence).
name='content_provenance_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult

# §C5 auditor-independence: locate pkg root relative to this file.
# Layout: examples/content_provenance_minimal/ContentProvenanceReDerivationCheck.py
#         → parents[2] = pkg root
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))


class ContentProvenanceReDerivationCheck:
    name: str = "content_provenance_re_derivation"
    applies_to_files: frozenset[str] = frozenset({"payload/"})

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "content_provenance_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "content_provenance_re_derivation.py not found alongside "
                    "ContentProvenanceReDerivationCheck.py; domain pilot opted out"
                ),
                files_audited=(),
            )

        payload_path = bundle_dir / "payload" / "provenance_result.json"
        if not payload_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail="payload/provenance_result.json absent — no provenance result to re-derive",
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
                reason_code="CONTENT_PROVENANCE_ALTERED",
                detail="content_provenance_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(payload_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="CONTENT_PROVENANCE_VERIFIED",
                detail=(
                    "content_provenance_re_derivation.py exited 0 — "
                    "content_sha, provenance_sha, producer_hmac, and provenance chain all verified"
                ),
                files_audited=(str(payload_path),),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="CONTENT_PROVENANCE_ALTERED",
            detail=stderr_snippet,
            files_audited=(str(payload_path),),
        )


register_typed_check("content_provenance_re_derivation")
