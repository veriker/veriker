"""audit_bundle/plugins/file_integrity_many_small.py — TypedCheck: file integrity (C9 many-small).

Implements the audit-bundle contract §C9 (generic reference implementation).
Typed counterpart to verifier.py step-1 file_integrity walk.  Domain pilots
can list this plugin in manifest.typed_checks to receive per-failure naming
in the failure log rather than the generic step-1 bucket.

Three-pass walk order (first failure wins):
  Pass 1 — MISSING_FILE              listed in manifest.files, absent on disk
  Pass 2 — BAD_FILE_SHA              present but SHA-256 does not match manifest
  Pass 3 — EXTRA_FILE_NOT_IN_MANIFEST present on disk, absent from manifest.files

Pass 3 is SUPERSEDED by the core conservation gate: surplus membership is
decided once, inside ``BundleVerifier.verify()`` (audit_bundle.conservation),
and this plugin consumes only that finalized result via the FS-free shim
(``pass3_conservation_shim``). verify() binds the result before dispatching
plugins; a direct ``check()`` invocation without a bound result hard-errors
(``ConservationResultAbsent``) instead of recomputing membership — never two
sources of the same decision.

No try/except catch-all per §C9 contract (a targeted catch for a path-escape
is the one exception — see UNSAFE_FILE_PATH below).
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING

from audit_bundle.bundle_manifest import (
    UnsafeBundlePath,
    _safe_bundle_path,
    register_typed_check,
)
from audit_bundle.plugin import PluginResult
from audit_bundle.plugins.pass3_conservation_shim import pass3_from_conservation

# NOTE: this module no longer imports the integrity-ownership map at all —
# Pass 3's membership decision moved wholesale into the conservation gate.

if TYPE_CHECKING:
    from audit_bundle.conservation import ConservationResult


class FileIntegrityManySmall:
    name: str = "file_integrity_many_small"
    applies_to_files: frozenset[str] = frozenset()

    def __init__(self) -> None:
        self._conservation: "ConservationResult | None" = None

    def bind_conservation(self, result: "ConservationResult | None") -> None:
        """Bind (or clear) the finalized conservation result Pass 3 consumes.

        Called by ``BundleVerifier.verify()`` around plugin dispatch; callers
        driving the plugin directly must bind a result computed by
        ``audit_bundle.conservation.run_conservation`` themselves. The shim
        cross-checks the result's bundle root, so a stale or cross-bundle
        binding fails closed rather than silently applying.
        """
        self._conservation = result

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        """Walk manifest.files with per-file reason codes; three-pass ordered walk."""

        # ------------------------------------------------------------------
        # Pass 1: MISSING_FILE — manifest-listed files absent from bundle_dir
        # ------------------------------------------------------------------
        for rel_path in sorted(manifest.files):
            # manifest.files keys are bundle-controlled; route through the shared
            # containment helper (parallel to the hardened
            # verifier._step_file_integrity). A path that escapes the bundle or
            # names a directory fails closed as a REJECT — not an arbitrary
            # host-file read, and not an uncaught crash.
            try:
                fpath = _safe_bundle_path(bundle_dir, rel_path)
            except UnsafeBundlePath as exc:
                return PluginResult(
                    ok=False,
                    reason_code="UNSAFE_FILE_PATH",
                    detail=f"{rel_path!r}: {exc}",
                    files_audited=(),
                )
            if not fpath.exists():
                return PluginResult(
                    ok=False,
                    reason_code="MISSING_FILE",
                    detail=f"{rel_path!r}: listed in manifest.files but absent from bundle_dir",
                    files_audited=(str(fpath),),
                )

        # ------------------------------------------------------------------
        # Pass 2: BAD_FILE_SHA — present but hash mismatch
        # ------------------------------------------------------------------
        files_audited: list[str] = []
        for rel_path, expected_sha in sorted(manifest.files.items()):
            try:
                fpath = _safe_bundle_path(bundle_dir, rel_path)
            except UnsafeBundlePath as exc:
                return PluginResult(
                    ok=False,
                    reason_code="UNSAFE_FILE_PATH",
                    detail=f"{rel_path!r}: {exc}",
                    files_audited=tuple(files_audited),
                )
            files_audited.append(str(fpath))
            # Belt-and-braces residual from the path-containment fix: a
            # special file (FIFO / socket) passes _safe_bundle_path's is_dir
            # check and exists(), but read_bytes() raises OSError. Mirror the
            # handler in verifier._step_file_integrity — fail closed as a
            # REJECT, never an escaping exception.
            try:
                file_bytes = fpath.read_bytes()
            except OSError as exc:
                return PluginResult(
                    ok=False,
                    reason_code="BAD_FILE_SHA",
                    detail=(
                        f"{rel_path!r}: exists but could not be read ({exc}); "
                        "unreadable bytes cannot match the manifest SHA"
                    ),
                    files_audited=tuple(files_audited),
                )
            computed = hashlib.sha256(file_bytes).hexdigest()
            if computed.lower() != expected_sha.lower():
                return PluginResult(
                    ok=False,
                    reason_code="BAD_FILE_SHA",
                    detail=(
                        f"{rel_path!r}: manifest_sha={expected_sha!r} "
                        f"computed_sha={computed!r}"
                    ),
                    files_audited=tuple(files_audited),
                )

        # ------------------------------------------------------------------
        # Pass 3: EXTRA_FILE_NOT_IN_MANIFEST — superseded by the core
        # conservation gate (one source of the surplus decision). The shim
        # consumes ONLY the bound, finalized ConservationResult: no
        # filesystem access, no recomputed membership, and a hard error
        # (ConservationResultAbsent) when nothing is bound or the bound
        # result belongs to a different bundle root. verify() binds the
        # result around plugin dispatch; the auditor-facing D4 scaffold
        # warning and the fs_ignore disclosure ride the PASS detail exactly
        # as before, now sourced from the conservation record.
        # ------------------------------------------------------------------
        return pass3_from_conservation(
            self._conservation,
            bundle_dir_resolved=bundle_dir.resolve().as_posix(),
            manifest_files_sorted=tuple(sorted(manifest.files)),
        )


register_typed_check("file_integrity_many_small")
