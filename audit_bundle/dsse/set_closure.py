"""audit_bundle.dsse.set_closure — DSSE bundle set-closure immutable-snapshot helper.

This module provides ``snapshot_and_compare``, which takes a live directory
(``bundle_root``) and a caller-supplied expected file set, walks every regular
file under the directory with O_NOFOLLOW / inode-stability hardening, and
returns a ``SetClosureResult`` reporting surplus/missing/unstable files.

Design notes
------------
DSSE bundles are LIVE directories at rest (not content-addressed archives).
The canonical safety approach is a hardened live-walk, not a sealed tar.

TOCTOU hardening (impl-scoping §15.3, option (c)):

  1. Each directory descent uses ``os.scandir`` and REJECTS any entry whose
     ``is_symlink()`` check returns True — symlinked directories are never
     followed.

  2. Each regular file is opened with ``os.O_NOFOLLOW | os.O_RDONLY`` so a
     symlink swapped in after ``lstat`` but before ``open`` raises ``OSError``
     (ELOOP) rather than silently following.  The file is marked unstable on
     any ``OSError`` raised by ``os.open``.

  3. After opening, ``os.fstat(fd)`` is compared against ``os.lstat(path)``:
     if ``st_ino`` or ``st_dev`` diverge the file is marked unstable (a swap
     happened between ``lstat`` and ``open``).

  4. A trivial read (1 byte) drains nothing meaningful but exercises the fd;
     we then ``fstat`` again and compare ``st_ino``, ``st_dev``, ``st_size``,
     and ``st_mtime_ns`` to the pre-read fstat.  Any divergence marks the
     file unstable (mid-read swap).

Path-normalization contract (shared verbatim with WS-2 sealer + WS-5a verifier):

  - ``expected_files`` entries AND the on-disk walk both use RELATIVE POSIX
    paths under ``bundle_root`` (forward slashes, no leading ``./``, no
    trailing slash).
  - Sets are compared as ``frozenset[str]`` of those canonical relative-POSIX
    strings.
  - Any ordered output is sorted by plain lexical order of the relative-POSIX
    path string.

Platform note
-------------
O_NOFOLLOW / inode semantics are a Linux target for v0.4.  Tests that depend
on them are marked ``@pytest.mark.skipif(sys.platform != "linux", ...)``.

Pure stdlib: ``os``, ``pathlib``, ``dataclasses``, ``stat``.  NO ``cryptography``
or ``jcs`` imports.
"""

from __future__ import annotations

import os
import stat as stat_module
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from audit_bundle.bundle_manifest import UnsafeBundlePath, _safe_bundle_path

__all__ = ["SetClosureResult", "snapshot_and_compare"]


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SetClosureResult:
    """Immutable result of a set-closure snapshot comparison.

    Attributes
    ----------
    ok:
        True iff the on-disk set exactly equals ``expected_files`` AND every
        file passed the symlink / fstat-vs-lstat / inode-stability checks.
    missing:
        Files that were in ``expected_files`` but absent on disk.
    surplus:
        Files that were on disk but absent in ``expected_files``.
        Non-empty ⇒ ``reason_code == "UNLISTED_FILE_IN_SEALED_ROOT"``.
    unstable:
        Files that failed the symlink-rejection, ``O_NOFOLLOW`` open, or
        inode-stability checks (sorted, relative-POSIX paths).
    unsafe_expected:
        Entries in ``expected_files`` (the SIGNED set) that resolve outside
        ``bundle_root`` or to a non-regular-file target — i.e. the sealed
        manifest itself declared a path that can never legitimately be a
        bundle member. Non-empty ⇒ hard reject (``ok`` is False); these are
        NEVER silently dropped from the comparison.
    reason_code:
        Machine-readable failure code, or None when ``ok`` is True.

        Precedence (when multiple conditions fire simultaneously):
          1. ``"SEALED_ROOT_FILE_UNSTABLE"``  — any unstable file
          2. ``"UNSAFE_EXPECTED_PATH_IN_SEALED_MANIFEST"`` — signed manifest
             declared a path-escape / non-file target
          3. ``"UNLISTED_FILE_IN_SEALED_ROOT"`` — surplus files present
          4. ``"SEALED_ROOT_FILE_MISSING"``  — expected files absent

        ``unstable`` ranks above ``unsafe_expected`` because an expected entry
        can resolve outside the root precisely *because* of an on-disk symlink
        (``_safe_bundle_path`` resolves through links) — that is the same root
        cause the walk already flags as unstable, and naming the symlink is the
        more precise diagnosis.  ``unsafe_expected`` therefore surfaces when the
        signed path is defective independent of any on-disk instability — e.g. a
        lexical ``../evil`` — which must never be silently dropped.  In all
        cases a non-empty ``unsafe_expected`` forces ``ok=False``.
    """

    ok: bool
    missing: frozenset[str]
    surplus: frozenset[str]
    unstable: tuple[str, ...]
    reason_code: Optional[str]
    unsafe_expected: frozenset[str] = frozenset()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _to_posix_rel(bundle_root: Path, abs_path: Path) -> str:
    """Return the relative POSIX path string for *abs_path* under *bundle_root*.

    Result has forward slashes, no leading ``./``, no trailing slash.
    """
    return abs_path.relative_to(bundle_root).as_posix()


def _walk_regular_files(
    bundle_root: Path,
) -> tuple[frozenset[str], tuple[str, ...]]:
    """Walk *bundle_root* recursively, returning (on_disk_rel_paths, unstable).

    - Symlinked entries (files or directories) are REJECTED as unstable.
    - Each regular file is opened with O_NOFOLLOW; inode stability is
      verified pre- and post-read (see module docstring).
    - ``_safe_bundle_path`` is called for every file path to guard against
      any traversal that could escape the root.

    Returns
    -------
    on_disk : frozenset[str]
        Relative-POSIX paths of all non-symlink regular files found.
        Symlink entries are excluded from this set (and added to unstable).
    unstable : tuple[str, ...]
        Relative-POSIX paths (sorted) of files that triggered any instability
        check (symlink, O_NOFOLLOW failure, or inode-divergence).
    """
    on_disk: set[str] = set()
    unstable: set[str] = set()
    resolved_root = bundle_root.resolve()

    # We use an explicit stack rather than os.walk to control symlink
    # rejection at every directory level.
    dir_stack: list[Path] = [resolved_root]

    while dir_stack:
        current_dir = dir_stack.pop()

        try:
            with os.scandir(current_dir) as it:
                entries = list(it)
        except OSError:
            # Unreadable directory — treat as unstable; record the dir path
            rel = _to_posix_rel(resolved_root, current_dir)
            unstable.add(rel)
            continue

        for entry in entries:
            entry_path = Path(entry.path)
            rel_posix = _to_posix_rel(resolved_root, entry_path)

            # ── Guard: reject symlinks (files and directories) ────────────
            # Use lstat so we see the symlink itself, not its target.
            try:
                lstat_result = os.lstat(entry.path)
            except OSError:
                unstable.add(rel_posix)
                continue

            if stat_module.S_ISLNK(lstat_result.st_mode):
                unstable.add(rel_posix)
                continue

            if stat_module.S_ISDIR(lstat_result.st_mode):
                # Real directory — path-escape guard via relative_to.
                # (We do NOT call _safe_bundle_path here because it raises
                # on directories; we guard purely via resolved-path containment.)
                try:
                    entry_path.relative_to(resolved_root)
                except ValueError:
                    unstable.add(rel_posix)
                    continue
                dir_stack.append(entry_path)
                continue

            if not stat_module.S_ISREG(lstat_result.st_mode):
                # FIFO, socket, device node — not a regular file. Fail closed
                # (same bucket as symlinks): a non-regular object cannot be
                # content-hashed or set-closed, and silently skipping it left a
                # blind spot where a planted FIFO was invisible to sealed
                # set-closure (it was neither added to on_disk nor flagged).
                # Mark unstable so the seal cannot ride a green verdict.
                unstable.add(rel_posix)
                continue

            # ── Guard: path must not escape bundle_root (file path) ───────
            # _safe_bundle_path also rejects directories, so only call for
            # entries we have already confirmed are regular files.
            try:
                _safe_bundle_path(resolved_root, rel_posix)
            except UnsafeBundlePath:
                unstable.add(rel_posix)
                continue

            # ── Open with O_NOFOLLOW (TOCTOU: symlink-swap guard) ─────────
            fd: int | None = None
            try:
                fd = os.open(entry.path, os.O_RDONLY | os.O_NOFOLLOW)
            except OSError:
                # ELOOP (or equivalent) if a symlink was swapped in.
                unstable.add(rel_posix)
                continue

            try:
                # ── fstat vs lstat inode check ────────────────────────────
                fstat_pre = os.fstat(fd)
                if (
                    fstat_pre.st_ino != lstat_result.st_ino
                    or fstat_pre.st_dev != lstat_result.st_dev
                ):
                    unstable.add(rel_posix)
                    continue

                # ── Trivial read + post-read fstat for mid-read swap ──────
                os.read(fd, 1)  # read 1 byte (may read 0 if file is empty)
                fstat_post = os.fstat(fd)
                if (
                    fstat_post.st_ino != fstat_pre.st_ino
                    or fstat_post.st_dev != fstat_pre.st_dev
                    or fstat_post.st_size != fstat_pre.st_size
                    or fstat_post.st_mtime_ns != fstat_pre.st_mtime_ns
                ):
                    unstable.add(rel_posix)
                    continue

                on_disk.add(rel_posix)

            finally:
                os.close(fd)

    return frozenset(on_disk), tuple(sorted(unstable))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def snapshot_and_compare(
    bundle_root: Path,
    expected_files: frozenset[str],
) -> SetClosureResult:
    """Snapshot all regular files under *bundle_root* and compare to *expected_files*.

    Parameters
    ----------
    bundle_root:
        The root directory of the DSSE bundle.  Must be an existing directory.
    expected_files:
        The caller-supplied set of relative-POSIX file paths that are expected
        to be present (e.g. from the sealed manifest).  Entries use forward
        slashes, no leading ``./``, no trailing slash.

    Returns
    -------
    SetClosureResult
        Immutable result with ``ok``, ``missing``, ``surplus``, ``unstable``,
        and ``reason_code`` fields.

    Notes
    -----
    - The caller (WS-5a) decides what goes into *expected_files*.  This
      function performs pure set + stability comparison without special-casing
      any file names (e.g. ``bundle.dsse.json``).
    - *expected_files* is the SIGNED set (it is built from the DSSE payload's
      ``files`` array after envelope + manifest-binding verification).  Any
      entry that resolves outside *bundle_root*, or to a non-regular-file
      target (via ``_safe_bundle_path``), is therefore an attested path the
      verifier cannot validate.  Such an entry is a HARD REJECT
      (``ok=False``, ``reason_code="UNSAFE_EXPECTED_PATH_IN_SEALED_MANIFEST"``,
      reported in ``unsafe_expected``) — it is NEVER silently dropped from the
      comparison.  Silently shrinking the signed set would let a manifest
      declaring e.g. ``../evil`` normalize to a smaller set and pass closure
      (fail-open); set-closure means the on-disk set exactly equals the
      *signed* set, so the signed set must be honored verbatim or refused.
    """
    resolved_root = bundle_root.resolve()

    # Validate expected_files entries against path-escape / non-file targets.
    # The signed set must be honored verbatim: an entry the verifier cannot
    # safely resolve is collected and hard-rejects below (fail-closed), never
    # dropped.
    safe_expected: set[str] = set()
    unsafe_expected_set: set[str] = set()
    for rel in expected_files:
        try:
            _safe_bundle_path(resolved_root, rel)
            safe_expected.add(rel)
        except UnsafeBundlePath:
            unsafe_expected_set.add(rel)

    unsafe_expected = frozenset(unsafe_expected_set)

    on_disk, unstable = _walk_regular_files(resolved_root)

    missing = frozenset(safe_expected - on_disk)
    surplus = frozenset(on_disk - safe_expected)

    # Determine reason_code.
    # Precedence: unstable > unsafe_expected > surplus > missing.
    # unstable ranks first because an unsafe-resolving expected entry is often
    # the SAME on-disk symlink the walk already flags (resolution follows the
    # link); naming the symlink is the more precise diagnosis. unsafe_expected
    # surfaces for signed-path defects independent of disk state (lexical
    # ../evil). Either way a non-empty unsafe_expected forces ok=False below.
    if unstable:
        reason_code: str | None = "SEALED_ROOT_FILE_UNSTABLE"
    elif unsafe_expected:
        reason_code = "UNSAFE_EXPECTED_PATH_IN_SEALED_MANIFEST"
    elif surplus:
        reason_code = "UNLISTED_FILE_IN_SEALED_ROOT"
    elif missing:
        reason_code = "SEALED_ROOT_FILE_MISSING"
    else:
        reason_code = None

    ok = not unsafe_expected and not unstable and not missing and not surplus

    return SetClosureResult(
        ok=ok,
        missing=missing,
        surplus=surplus,
        unstable=unstable,
        reason_code=reason_code,
        unsafe_expected=unsafe_expected,
    )
