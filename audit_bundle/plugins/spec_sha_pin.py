"""audit_bundle/plugins/spec_sha_pin.py — TypedCheck: spec-file SHA pinning.

Implements the audit-bundle contract §C1 (generic reference implementation).
Verifies that every spec_files entry in the manifest matches the on-disk
SHA-256 of the corresponding file under bundle_dir/spec/.


"""

from __future__ import annotations

import hashlib
from pathlib import Path

from audit_bundle.bundle_manifest import (
    UnsafeBundlePath,
    _safe_bundle_path,
    register_typed_check,
)
from audit_bundle.plugin import PluginResult


class SpecShaPinCheck:
    name: str = "spec_sha_pin"
    # exact-path-only: the former {"spec/"} trailing-slash pseudo-prefix was
    # inert (consumed by exact match, never matched a real path). spec/ files
    # are owned by the SPEC class via tree segment, not via this entry. Dropped.
    applies_to_files: frozenset[str] = frozenset()

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        """Walk manifest.spec_files; assert each file's SHA-256 matches."""
        files_audited: list[str] = []

        for spec_path, expected_sha in manifest.spec_files.items():
            # Path-safety: the "spec" literal anchors the path under
            # bundle/spec/, but a .. in spec_path can still escape (verify:
            # ``(bundle_dir / "spec" / "../../../etc/hostname").resolve()``
            # lands outside bundle_dir). _safe_bundle_path fail-closes on
            # path-escape and directory targets (atheris finding 2026-05-26
            # sibling in plugin surface).
            try:
                full_path = _safe_bundle_path(bundle_dir, "spec/" + spec_path)
            except UnsafeBundlePath as exc:
                # files_audited records the offending input so the failure
                # detail is reproducible from the manifest alone.
                files_audited.append(f"spec/{spec_path}")
                return PluginResult(
                    ok=False,
                    reason_code="SPEC_PATH_UNSAFE",
                    detail=(
                        f"spec_sha_pin rejected unsafe spec_files entry "
                        f"{spec_path!r}: {exc}"
                    ),
                    files_audited=tuple(files_audited),
                )
            files_audited.append(str(full_path))

            if not full_path.exists():
                return PluginResult(
                    ok=False,
                    reason_code="SPEC_SHA_MISMATCH",
                    detail=f"spec file {spec_path!r} listed in manifest is missing from bundle_dir/spec/",
                    files_audited=tuple(files_audited),
                )

            # Sibling of the file_integrity_many_small residual: a special
            # file (FIFO / socket) passes the containment + exists() checks
            # but read_bytes() raises OSError — fail closed as a REJECT,
            # never an escaping exception.
            try:
                spec_bytes = full_path.read_bytes()
            except OSError as exc:
                return PluginResult(
                    ok=False,
                    reason_code="SPEC_SHA_MISMATCH",
                    detail=(
                        f"spec file {spec_path!r} exists but could not be "
                        f"read ({exc}); unreadable bytes cannot match the "
                        "manifest SHA"
                    ),
                    files_audited=tuple(files_audited),
                )
            computed = hashlib.sha256(spec_bytes).hexdigest()
            if computed.lower() != expected_sha.lower():
                return PluginResult(
                    ok=False,
                    reason_code="SPEC_SHA_MISMATCH",
                    detail=(
                        f"spec file {spec_path!r} SHA mismatch: "
                        f"manifest={expected_sha!r} computed={computed!r}"
                    ),
                    files_audited=tuple(files_audited),
                )

        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail="all spec_files SHA-256 digests verified",
            files_audited=tuple(files_audited),
        )


register_typed_check("spec_sha_pin")
