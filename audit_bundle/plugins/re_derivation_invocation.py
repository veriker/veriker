"""audit_bundle/plugins/re_derivation_invocation.py — TypedCheck: re-derivation invocation (C6).

Implements the audit-bundle contract §C6 (generic shape).
Invokes a domain-specific re-derivation pack script (e.g. energy_score_pack.py
or span_re_derivation.py) from the bundle's re_derive/ directory.  The pack is
responsible for recomputing values from raw inputs and asserting they match the
bundled outputs; this plugin only invokes it.

⚠️  SECURITY — this check runs BUNDLE-SUPPLIED Python in the verifier process.
A re-derivation pack ships inside the (potentially untrusted) bundle; invoking
it is arbitrary local code execution. For untrusted bundles this is unsafe — a
malicious pack can read/write files, spawn subprocesses, or simply `exit(0)`
without re-deriving anything (the producer would be grading its own homework).
The SAFE re-derivation path is spec-pinned dispatch (audit_bundle/rederivation/):
recompute primitives are verifier-distribution code, registry-resident, never
bundle-supplied — see that package's THREAT_MODEL.md.

Because of that, `permit_execution` is a REQUIRED keyword with no default: every
construction site must state the trust decision explicitly. veriker/cli/verify.py wires
it to the opt-in `--unsafe-run-bundle-pack` flag (default OFF), so the default
verify path NEVER executes a bundle pack. See SECURITY.md
"Code execution in the verify path".

If no pack is present the domain pilot opted out of C6 → ok, NO_PACK.
Stdlib only.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult

# Emitted when a pack is present but execution was not permitted (the safe
# default). COULD-NOT-CONCLUDE semantics: the result carries incomplete=True
# (never a silent RE_DERIVED), so verify() records a clean-ERROR leg — the core
# property is unverified, not passed. This is NOT a REJECT (the artifact is not
# shown bad); it composes ERROR (exit 2). Mirrors the register_receipt_verifier
# "NOT_EVALUATED" posture.
NOT_EXECUTED_REASON: str = "RE_DERIVATION_NOT_EXECUTED"


class ReDerivationInvocationCheck:
    name: str = "re_derivation_invocation"
    # exact-path-only: the former {"re_derive/"} trailing-slash pseudo-prefix
    # was inert (consumed by exact match, never matched a real path). Dropped.
    applies_to_files: frozenset[str] = frozenset()

    def __init__(self, pack_filename: str, *, permit_execution: bool) -> None:
        # permit_execution is REQUIRED (no default): invoking a bundle-supplied
        # pack runs arbitrary local code in the verifier process, so the trust
        # decision must be stated at every call site rather than inherited.
        self.pack_filename = pack_filename
        self.permit_execution = permit_execution

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = bundle_dir / "re_derive" / self.pack_filename

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    f"re-derivation pack {self.pack_filename!r} not found in "
                    f"re_derive/; domain pilot opted out of C6"
                ),
                files_audited=(),
            )

        if not self.permit_execution:
            return PluginResult(
                ok=True,
                # incomplete=True: present-but-unverified is COULD-NOT-CONCLUDE,
                # not a pass. verify() records a clean-ERROR leg so a LIBRARY
                # consumer (not just the CLI) sees the bundle's core property was
                # left unverified — closes the verdict-laundering seam (ADV-01):
                # ok=True alone made BundleVerifier.verify() return OK while the
                # CLI gated exit 2. The CLI's RE_DERIVATION_NOT_EXECUTED gate now
                # derives from this verdict (one semantics, not two).
                incomplete=True,
                reason_code=NOT_EXECUTED_REASON,
                detail=(
                    f"re-derivation pack {self.pack_filename!r} present but NOT "
                    f"executed (safe default): invoking it runs bundle-supplied "
                    f"Python in the verifier process, unsafe for untrusted "
                    f"bundles. Re-derivation was NOT verified — do not read a "
                    f"PASS verdict as covering it. Use spec-pinned dispatch "
                    f"(manifest.outputs + auditor SpecAnchor) for safe "
                    f"re-derivation, or pass --unsafe-run-bundle-pack to execute "
                    f"on a trusted producer / disposable host."
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
                reason_code="RE_DERIVATION_TIMEOUT",
                detail=(
                    f"re-derivation pack {self.pack_filename!r} exceeded 60 s timeout"
                ),
                files_audited=(str(pack_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="RE_DERIVED",
                detail=(f"re-derivation pack {self.pack_filename!r} exited 0"),
                files_audited=(str(pack_path),),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]
        return PluginResult(
            ok=False,
            reason_code="RE_DERIVATION_MISMATCH",
            detail=stderr_snippet,
            files_audited=(str(pack_path),),
        )


register_typed_check("re_derivation_invocation")
