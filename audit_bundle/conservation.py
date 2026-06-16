"""audit_bundle/conservation.py — the core file-space conservation gate.

Every bundle path must be claimed by exactly one integrity-owner class whose
checker actually runs in ``BundleVerifier.verify()``; anything UNOWNED fails
closed. This is the gate that closes the unsealed-library conservation gap:
before it, a library consumer calling ``BundleVerifier(plugins=()).verify()``
on a sidecar-absent bundle got NO surplus sweep at all — undeclared on-disk
files rode a green verdict. Conservation now runs UNCONDITIONALLY inside
``verify()`` regardless of the configured plugin set, and the Pass-3 sweep of
``file_integrity_many_small`` is a shim over this result (one source of the
surplus decision — see ``plugins.pass3_conservation_shim``).

The universe and the predicate
------------------------------
The conservation universe is the union of the on-disk paths under the bundle
root and every declared path set (``manifest.files``, ``manifest.snapshots``
values, the flat spec-pinned offline copies, ``append_only_files``). Each
member is classified by the one integrity-ownership map
(``integrity_ownership.classify_path``); the gate's reject condition is:

* ``UNOWNED`` on-disk path → REJECT (``EXTRA_FILE_NOT_IN_MANIFEST`` — the
  same artifact-bad class the Pass-3 sweep and the sealed set-closure walk
  already enforce). Declared paths can never classify UNOWNED (declaration
  determines class), so the reject condition only ever fires on disk.
* non-regular, non-directory on-disk object (FIFO / socket / device node) →
  REJECT regardless of declaration. A non-regular object can never satisfy a
  byte-equality or record-shape contract, and reading one can block the
  verifier (a declared FIFO would hang the strict-SHA walk's ``read_bytes``)
  — so the gate rejects BEFORE any content step opens it. The walk here
  ``lstat``s every entry and never opens file contents.
* symlinks are classified by their bundle-relative NAME, exactly like the
  Pass-3 sweep: an undeclared symlink is UNOWNED (rejected), a declared one
  is owned by its declared class, whose checker resolves it through the
  ``_safe_bundle_path`` containment guard (escaping links fail closed there).
  Symlinked directories are never descended.

Per-lane ENVELOPE semantics ("whose checker ran")
-------------------------------------------------
The ENVELOPE class's checker differs by lane, and the gate records it
honestly rather than pretending one rule covers all three:

* sealed (sidecar present + DSSE context): the DSSE gate IS the envelope
  checker — reaching conservation at all means it ran and passed.
* sidecar present, no DSSE context: fail-closed reject in the pre-gate;
  conservation is never reached on this lane (that IS the lane's semantics).
* sidecar absent (unsealed): ``manifest.json``'s checker is the parse
  validator + admission bounds. Parse-validated is NOT byte-integrity-owned;
  the gate disclures that residual on the verdict face
  (``envelope_residual``) instead of silently passing it.

Auditor ``fs_ignore`` view
--------------------------
An OPTIONAL, default-EMPTY, construction-time-only tolerance for UNOWNED
paths (never sourced from the manifest):

* exact-path or anchored-glob patterns only — a pattern may not begin with a
  wildcard, may not contain ``**`` or ``..``, and is matched against the full
  bundle-relative path (``validate_fs_ignore_patterns``);
* a pattern may NEVER match a declared or ENVELOPE path — that is an auditor
  configuration conflict and raises ``VerifierError`` (verdict ERROR, not a
  reject: the artifact was not proven bad, the configuration is unusable);
* every ignored path is reported verbosely on the verdict face;
* sealed bundles ignore NOTHING — under seal the patterns are inert;
* non-regular objects are never ignorable.

Mitigating a planted-file denial-of-verification against a SHARED bundle
store is the caller's job (present the bundle in an isolated context), never
a verifier weakening — ``fs_ignore`` exists so an auditor can make a
deliberate, disclosed tolerance decision, not so a producer can.

Pure stdlib (``os``, ``stat``, ``fnmatch``, ``dataclasses``). Imports only
``integrity_ownership`` (the map) and ``verdict`` (VerifierError).
"""

from __future__ import annotations

import os
import stat as stat_module
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Sequence

from .integrity_ownership import (
    ENVELOPE_PATHS,
    Guarantee,
    OwnerKind,
    _spec_pinned_offline_paths,
    append_only_declared_paths,
    classify_path,
)
from .verdict import VerifierError

__all__ = [
    "VERIFIER_FS_IGNORE_CONFLICT",
    "ConservationResult",
    "run_conservation",
    "validate_fs_ignore_patterns",
]

# Auditor fs_ignore pattern collides with a declared/ENVELOPE path: the
# configuration is unusable, the artifact is not thereby proven bad → the
# verdict is a VERIFIER_* ERROR, never a REJECT and never a silent ignore.
VERIFIER_FS_IGNORE_CONFLICT = "VERIFIER_FS_IGNORE_CONFLICT"

_WILDCARD_CHARS = ("*", "?", "[")


@dataclass(frozen=True, slots=True)
class ConservationResult:
    """The finalized conservation/classification result for one bundle.

    ``bundle_dir`` is the resolved bundle root (POSIX string) the walk ran
    over — consumers (the Pass-3 shim) compare it against their own target so
    a stale or cross-bundle result can never be silently consumed.

    Path tuples are in Pass-3 walk order (pathlib sorts by path PARTS, which
    differs from plain string order — mirrored here so the shim's
    first-flagged path is byte-identical to the historical sweep).
    """

    bundle_dir: str
    sealed: bool
    # On-disk paths whose owner class is UNOWNED (after fs_ignore), incl.
    # non-regular objects (which classify UNOWNED regardless of declaration).
    unowned: tuple[str, ...]
    # (rel_path, object-type) for non-regular, non-directory on-disk objects.
    # Never ignorable; the verifier rejects on these before any content step.
    nonregular: tuple[tuple[str, str], ...]
    # Top-level scaffold basenames tolerated under the (committed-removal)
    # allowance — surfaced to the auditor by the Pass-3 shim's PASS detail.
    tolerated_scaffolds: tuple[str, ...]
    # (rel_path, pattern) for UNOWNED paths tolerated by auditor fs_ignore.
    ignored: tuple[tuple[str, str], ...]
    # ENVELOPE paths that are only parse-validated on this lane (the unsealed
    # sidecar-absent residual): disclosed, never silently passed.
    envelope_residual: tuple[str, ...]
    # Universe census: (kind value, count) over on-disk ∪ declared paths,
    # in OwnerKind declaration order (deterministic, insertion-ordered).
    kind_counts: tuple[tuple[str, int], ...] = ()
    # Paths inside the spec/ and snapshots/ trees that carry NO per-file
    # check (tree-membership-only classes): (top segment, count).
    unchecked_tree_counts: tuple[tuple[str, int], ...] = field(default=())


def _parts_key(rel_path: str) -> list[str]:
    """Sort key reproducing pathlib's parts-wise ordering for rel-POSIX paths."""
    return rel_path.split("/")


def validate_fs_ignore_patterns(patterns: Sequence[str]) -> tuple[str, ...]:
    """Validate auditor fs_ignore patterns at construction time (fail early).

    Accepted: exact bundle-relative paths, or globs anchored at the bundle
    root (the first character is a literal, no ``**``). Rejected: empty or
    non-string entries, absolute paths, trailing slashes, backslashes,
    ``..`` segments, unanchored wildcards (``*.pyc``), recursive globs.
    Raises ``ValueError`` — this is auditor-side configuration, so a bad
    pattern is a programming error at construction, not a verdict.
    """
    validated: list[str] = []
    for pattern in patterns:
        if not isinstance(pattern, str) or not pattern:
            raise ValueError(
                f"fs_ignore entries must be non-empty strings, got {pattern!r}"
            )
        if "\\" in pattern:
            raise ValueError(f"fs_ignore pattern {pattern!r} must use forward slashes")
        if pattern.startswith("/") or pattern.endswith("/"):
            raise ValueError(
                f"fs_ignore pattern {pattern!r} must be a bundle-relative "
                "file pattern (no leading or trailing slash)"
            )
        if ".." in pattern.split("/"):
            raise ValueError(
                f"fs_ignore pattern {pattern!r} must not contain '..' segments"
            )
        if "**" in pattern:
            raise ValueError(
                f"fs_ignore pattern {pattern!r}: recursive globs ('**') are "
                "not permitted — exact paths or root-anchored globs only"
            )
        if pattern[0] in _WILDCARD_CHARS:
            raise ValueError(
                f"fs_ignore pattern {pattern!r} is not anchored — the first "
                "character must be a literal (no bare-substring or "
                "basename-wildcard matching)"
            )
        validated.append(pattern)
    return tuple(validated)


def _walk_lstat(root: Path) -> tuple[list[str], list[str], list[tuple[str, str]]]:
    """lstat-only walk of *root*: (regular_files, symlinks, nonregular).

    Never opens file contents (a FIFO must not block the gate) and never
    descends a symlinked directory. An unreadable directory or unstattable
    entry fails closed into the nonregular bucket. All paths are relative
    POSIX strings under *root*.
    """
    regular: list[str] = []
    symlinks: list[str] = []
    nonregular: list[tuple[str, str]] = []
    stack: list[Path] = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                entries = list(it)
        except OSError as exc:
            rel = current.relative_to(root).as_posix()
            nonregular.append((rel, f"unreadable directory ({type(exc).__name__})"))
            continue
        for entry in entries:
            entry_path = Path(entry.path)
            rel = entry_path.relative_to(root).as_posix()
            try:
                lst = os.lstat(entry.path)
            except OSError as exc:
                nonregular.append((rel, f"unstattable ({type(exc).__name__})"))
                continue
            mode = lst.st_mode
            if stat_module.S_ISLNK(mode):
                # Classified by NAME like every other path; never followed
                # here (the owning checker resolves it under containment).
                symlinks.append(rel)
            elif stat_module.S_ISDIR(mode):
                stack.append(entry_path)
            elif stat_module.S_ISREG(mode):
                regular.append(rel)
            else:
                kind = (
                    "fifo"
                    if stat_module.S_ISFIFO(mode)
                    else "socket"
                    if stat_module.S_ISSOCK(mode)
                    else "device"
                    if stat_module.S_ISBLK(mode) or stat_module.S_ISCHR(mode)
                    else "non-regular"
                )
                nonregular.append((rel, kind))
    return regular, symlinks, nonregular


def _declared_paths(manifest: Any) -> frozenset[str]:
    """Every path the manifest (or the verifier statically) claims an owner
    for: files keys, snapshot values, flat spec-pinned copies, append-only
    declarations, and the structural envelope names. getattr-defensive so
    duck-typed manifest stand-ins without optional fields still work."""
    files = getattr(manifest, "files", {}) or {}
    snapshots = getattr(manifest, "snapshots", {}) or {}
    spec_files = getattr(manifest, "spec_files", {}) or {}
    declared = set(files)
    declared.update(snapshots.values())
    if spec_files:
        declared.update(_spec_pinned_offline_paths(manifest))
    declared.update(append_only_declared_paths(manifest))
    declared.update(ENVELOPE_PATHS)
    return frozenset(declared)


def run_conservation(
    bundle_dir: Path,
    manifest: Any,
    plugin_files: frozenset[str],
    *,
    sealed: bool,
    fs_ignore: tuple[str, ...] = (),
) -> ConservationResult:
    """Walk the bundle, classify the conservation universe, apply the auditor
    fs_ignore view, and return the finalized ``ConservationResult``.

    Raises ``VerifierError`` (→ verdict ERROR) when an fs_ignore pattern
    matches a declared/ENVELOPE path — auditor configuration conflict, never
    silently resolved in either direction.
    """
    root = bundle_dir.resolve()
    regular, symlinks, nonregular = _walk_lstat(root)

    declared = _declared_paths(manifest)

    # fs_ignore discipline: sealed bundles ignore NOTHING; a pattern may
    # never match a declared/ENVELOPE path (checked against the declared
    # universe whether or not those paths exist on disk today).
    active_ignore: tuple[str, ...] = () if sealed else fs_ignore
    for pattern in active_ignore:
        conflicts = [p for p in sorted(declared) if fnmatchcase(p, pattern)]
        if conflicts:
            raise VerifierError(
                VERIFIER_FS_IGNORE_CONFLICT,
                f"auditor fs_ignore pattern {pattern!r} matches declared/"
                f"ENVELOPE path(s) {conflicts!r}; an ignore view may only "
                "tolerate UNOWNED surplus, never weaken a declared owner",
            )

    unowned: list[str] = []
    scaffolds: list[str] = []
    ignored: list[tuple[str, str]] = []
    kind_counts: dict[str, int] = {kind.value: 0 for kind in OwnerKind}
    unchecked_tree: dict[str, int] = {}

    # Non-regular objects classify UNOWNED regardless of declaration (they
    # can never satisfy a content contract) and are never ignorable.
    for rel, _kind in nonregular:
        kind_counts[OwnerKind.UNOWNED.value] += 1
        unowned.append(rel)

    for rel in regular + symlinks:
        owner = classify_path(rel, manifest, plugin_files)
        kind_counts[owner.kind.value] += 1
        if owner.kind is OwnerKind.UNOWNED:
            matched = next((p for p in active_ignore if fnmatchcase(rel, p)), None)
            if matched is not None:
                ignored.append((rel, matched))
            else:
                unowned.append(rel)
        elif owner.kind is OwnerKind.SCAFFOLD:
            scaffolds.append(rel)
        elif (
            owner.kind in (OwnerKind.SNAPSHOT, OwnerKind.SPEC)
            and owner.guarantee is Guarantee.NONE
        ):
            top = rel.split("/")[0]
            unchecked_tree[top] = unchecked_tree.get(top, 0) + 1

    # Declared-but-absent universe members: counted for the census record.
    # They can never classify UNOWNED (declaration determines class), and
    # their owning checker runs unconditionally in verify() and surfaces the
    # absence itself (missing file / missing snapshot / missing spec copy).
    on_disk = frozenset(regular) | frozenset(symlinks)
    for rel in sorted(declared - on_disk):
        owner = classify_path(rel, manifest, plugin_files)
        kind_counts[owner.kind.value] += 1

    # The unsealed sidecar-absent residual: manifest.json's checker on this
    # lane is the parse validator + admission bounds — parse-validated is not
    # byte-integrity-owned, and the gate says so instead of passing silently.
    envelope_residual: tuple[str, ...] = ()
    if not sealed:
        envelope_residual = tuple(
            sorted(frozenset({"manifest.json"}) & (on_disk | declared))
        )

    nonregular_sorted = tuple(sorted(nonregular, key=lambda t: _parts_key(t[0])))
    return ConservationResult(
        bundle_dir=root.as_posix(),
        sealed=sealed,
        unowned=tuple(sorted(unowned, key=_parts_key)),
        nonregular=nonregular_sorted,
        tolerated_scaffolds=tuple(sorted(scaffolds, key=_parts_key)),
        ignored=tuple(sorted(ignored, key=lambda t: _parts_key(t[0]))),
        envelope_residual=envelope_residual,
        kind_counts=tuple(
            (kind.value, kind_counts[kind.value])
            for kind in OwnerKind
            if kind_counts[kind.value]
        ),
        unchecked_tree_counts=tuple(sorted(unchecked_tree.items())),
    )
