"""audit_bundle/plugins/pass3_conservation_shim.py — Pass-3 over conservation.

The ``file_integrity_many_small`` Pass-3 surplus sweep is superseded by the
core conservation gate (``audit_bundle.conservation``): once the surplus
decision is made ONCE inside ``BundleVerifier.verify()``, the plugin may not
make it a second time. This module is the supersession shim — it consumes
ONLY the finalized ``ConservationResult`` and re-expresses it in the plugin's
historical per-file reporting shape (same reason codes, same first-flagged
path, same PASS-detail scaffold warning).

Fail-closed contract: if no conservation result was bound — the plugin was
invoked directly, outside ``verify()``'s orchestration — or the bound result
was computed for a DIFFERENT bundle root, the shim raises
``ConservationResultAbsent`` (a hard error, never a PASS and never a silent
recomputation). Re-running the walk here would re-fork the membership
decision the conservation gate just unified.

STRUCTURAL CONTRACT — NO FILESYSTEM ACCESS. This module must never import an
OS/filesystem-bearing module or call a filesystem method: the shim consumes a
finalized result, full stop. Enforced by an AST lint
(``tests/test_pass3_shim_no_fs_lint.py``), the widened anti-re-fork guard —
the predecessor guard only banned the inline skip-set frozensets.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from audit_bundle.plugin import PluginResult

if TYPE_CHECKING:
    from audit_bundle.conservation import ConservationResult

__all__ = ["ConservationResultAbsent", "pass3_from_conservation"]


class ConservationResultAbsent(RuntimeError):
    """No (or a stale) conservation result was bound before the Pass-3 shim ran.

    The surplus decision lives in the core conservation gate; a plugin
    invocation that bypasses ``BundleVerifier.verify()`` has no finalized
    result to consume and must hard-error rather than silently recompute
    membership or silently pass.
    """


def pass3_from_conservation(
    conservation: "ConservationResult | None",
    *,
    bundle_dir_resolved: str,
    manifest_files_sorted: tuple[str, ...],
) -> PluginResult:
    """Re-express the finalized conservation result as the Pass-3 verdict.

    ``bundle_dir_resolved`` is the resolved POSIX string of the bundle root
    the CALLER is checking — compared against the result's own root so a
    stale or cross-bundle binding can never be consumed.
    """
    if conservation is None:
        raise ConservationResultAbsent(
            "file_integrity_many_small Pass 3 is a shim over the core "
            "conservation gate: no ConservationResult is bound. Run the "
            "plugin via BundleVerifier.verify(), or bind one explicitly "
            "with bind_conservation(run_conservation(...))."
        )
    if conservation.bundle_dir != bundle_dir_resolved:
        raise ConservationResultAbsent(
            f"bound ConservationResult is for bundle root "
            f"{conservation.bundle_dir!r}, but Pass 3 was invoked for "
            f"{bundle_dir_resolved!r} — refusing to consume a cross-bundle "
            "or stale result."
        )

    if conservation.unowned:
        first = conservation.unowned[0]
        return PluginResult(
            ok=False,
            reason_code="EXTRA_FILE_NOT_IN_MANIFEST",
            detail=f"{first!r}: present in bundle_dir but absent from manifest.files",
            files_audited=(f"{bundle_dir_resolved}/{first}",),
        )

    detail = (
        "all manifest.files verified: no missing, no SHA mismatches, no extra files"
    )
    if conservation.tolerated_scaffolds:
        detail += (
            " — WARNING: tolerated undeclared top-level scaffold file(s) "
            f"{sorted(conservation.tolerated_scaffolds)} under the "
            "pilot.json/README.md allowance (committed-removal direction; "
            "declare these in manifest.files to keep the bundle valid after "
            "removal)"
        )
    if conservation.ignored:
        detail += (
            " — NOTE: UNOWNED path(s) tolerated by auditor fs_ignore: "
            + ", ".join(
                f"{rel!r} (pattern {pattern!r})"
                for rel, pattern in conservation.ignored
            )
        )
    return PluginResult(
        ok=True,
        reason_code="PASS",
        detail=detail,
        files_audited=tuple(
            f"{bundle_dir_resolved}/{rel}" for rel in manifest_files_sorted
        ),
    )
