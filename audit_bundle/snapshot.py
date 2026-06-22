"""audit_bundle/snapshot.py — sealed-snapshot materialization for verify().

Closes the mixed-snapshot verdict class (ChatGPT BLOCK-01, 2026-06-11): a
verdict is a CONJUNCTION of checks that each read bundle files at separate
instants, and the verifier does not assume ``bundle_dir`` is quiescent. Before
this module, per-read pin binding covered the checks whose claims NAME a
digest (spec_sha_pin, refinement_discharge, fragment_attestation), but the
spec-pinned dispatch primitives and the .jsonl content checks re-read live
paths at a different instant than the integrity walk — and the append-only
file class deliberately carries NO byte pin, so read-site binding can never
cover it. The only whole-class closure is whole-tree coherence: materialize a
verifier-private copy of the bundle BEFORE any verdict-influencing read, then
run every step against that copy.

Soundness argument: after materialization, every read targets a tree only the
verifier can write. The strict-SHA walk over the snapshot then binds the
snapshot's bytes to the manifest pins *in that same snapshot* — so a mutation
racing the copy either produced a snapshot that satisfies the pins (in which
case it IS the pinned artifact) or one that mismatches (REJECT). The final
verdict is therefore a conjunction over ONE immutable byte-set, by
construction, with zero per-primitive changes.

Replication rules (node-type vocabulary):

* **regular file** — copied via ``open_regular_fd_nofollow`` (the BLOCK-01
  no-follow/no-block primitive: a swap to a symlink/FIFO between the scan and
  the open is refused at open time, never followed or hung on). Destination
  is created ``O_EXCL`` in the private tree; permission bits (``0o777`` mask)
  are preserved. Byte content is the only verdict-bearing property — no check
  in the package reads mtime/inode/xattr semantics (the DSSE set-closure walk
  compares its OWN pre/post fstats for swap detection, never absolute
  metadata), so the copy normalizing those is in-contract.
* **directory** — recreated.
* **symlink** — replicated by ``readlink``/``symlink``, with one
  semantics-preserving transform: an ABSOLUTE target inside ``bundle_dir``
  is re-anchored onto the snapshot root, so it keeps naming the same
  in-tree (pinned, walked) bytes and the strict-walk's as-built
  contained-symlink tolerance survives relocation. Every other target —
  relative links, true escapes — is replicated VERBATIM and re-adjudicated
  by the containment guards on the snapshot (escapes still reject).
* **FIFO** — replicated via ``mkfifo`` then ``chmod 0``, never opened, so the
  conservation gate's existing non-regular rejection face is byte-identical
  to in-place verification (and an accidental open fails fast with EACCES
  instead of hanging).
* **socket / device / unknown** — fail closed (``SnapshotUnsupportedNode``):
  unreplicable node types cannot ride into a sealed artifact silently.

Failure split (REJECT vs could-not-conclude):

* Source-side failure — a path that vanishes between scan and open, an
  ``ELOOP`` from a swapped-in link, an unreadable entry, or a post-copy
  re-walk that observes a different (path, kind) set than the first pass
  (the readdir/rename race) — raises ``SnapshotNonQuiescent``: the bundle
  could not be read as ONE stable artifact, which is fail-closed REJECT
  evidence, exactly like a hash mismatch.
* Destination-side failure — tempdir creation, ENOSPC, a write error —
  raises ``SnapshotMaterializationError``: a verifier-side resource problem,
  surfaced as a clean could-not-conclude ERROR, never blamed on the bundle.

The snapshot lives in a fresh ``tempfile.mkdtemp`` directory (mode ``0o700``
by construction — verifier-private). Operators verifying very large bundles
point ``TMPDIR`` at a scratch volume with capacity; the copy transiently
doubles the bundle's disk footprint (operator-capacity concern, same scope
boundary as the admission loaders' size doctrine in SECURITY.md).

Stdlib-only (core verify() path).
"""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .bundle_manifest import open_regular_fd_nofollow

__all__ = [
    "SnapshotNonQuiescent",
    "SnapshotUnsupportedNode",
    "SnapshotMaterializationError",
    "materialize_sealed_snapshot",
    "sealed_snapshot",
]

_COPY_CHUNK = 1 << 20  # 1 MiB

# Windows opens descriptors in CRT *text* mode by default, translating
# os.write's b"\n" -> b"\r\n" on the way to disk. The snapshot copy is a
# bytes-exact replica whose SHA must match the manifest, so the destination
# fd must be binary. The read fds are immune (their callers wrap them in
# os.fdopen(..., "rb"), and io.FileIO _setmode's the fd to binary on Windows);
# this bare os.open + os.write path is the only one that needs the flag set
# explicitly. O_BINARY is Windows-only, so default to 0 elsewhere.
_O_BINARY = getattr(os, "O_BINARY", 0)


class SnapshotNonQuiescent(Exception):
    """Source-side instability while materializing: the bundle could not be
    read as one stable artifact (vanished/swapped entry, unreadable node, or
    the post-copy re-walk saw a different path set). Fail-closed REJECT."""


class SnapshotUnsupportedNode(Exception):
    """A node type the snapshot cannot faithfully replicate (socket, device,
    unknown). Fail-closed REJECT — it cannot ride into a sealed artifact."""


class SnapshotMaterializationError(Exception):
    """Destination-side failure (tempdir creation, ENOSPC, write error):
    a verifier-side resource problem → clean could-not-conclude ERROR."""


def _classify(entry_path: Path) -> str:
    """Classify a node by lstat without opening it: 'dir' | 'regular' |
    'symlink' | 'fifo' | anything else returned as the stat kind name."""
    st = os.lstat(entry_path)
    mode = st.st_mode
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISBLK(mode) or stat.S_ISCHR(mode):
        return "device"
    return "unknown"


def _scan_tree(root: Path) -> dict[str, str]:
    """One pass over the source tree: bundle-relative POSIX path → node kind.
    ``follow_symlinks=False`` throughout — a link is an entry, never a
    traversal edge. Raises SnapshotNonQuiescent on any source-side OSError."""
    found: dict[str, str] = {}
    stack: list[Path] = [root]
    while stack:
        d = stack.pop()
        try:
            entries = list(os.scandir(d))
        except OSError as exc:
            raise SnapshotNonQuiescent(
                f"could not scan {d!s} while materializing the sealed snapshot "
                f"({type(exc).__name__}: {exc}) — bundle_dir is not readable as "
                "one stable artifact"
            ) from exc
        for entry in entries:
            p = Path(entry.path)
            try:
                kind = _classify(p)
            except OSError as exc:
                raise SnapshotNonQuiescent(
                    f"entry {p!s} vanished or became unreadable during the "
                    f"snapshot scan ({type(exc).__name__}: {exc}) — evidence of "
                    "mid-run mutation"
                ) from exc
            rel = p.relative_to(root).as_posix()
            found[rel] = kind
            if kind == "dir":
                stack.append(p)
    return found


def _copy_regular(src: Path, dst: Path) -> None:
    """Copy one regular file src→dst with the BLOCK-01 no-follow/no-block
    source open and an O_EXCL destination create. Preserves the 0o777
    permission-bit mask (so e.g. an opt-in re-derivation pack keeps its
    mode); all other metadata is deliberately normalized (bytes-only
    semantics). Source-side OSError → SnapshotNonQuiescent; destination-side
    OSError → SnapshotMaterializationError."""
    try:
        src_fd = open_regular_fd_nofollow(src)
    except OSError as exc:
        raise SnapshotNonQuiescent(
            f"{src!s}: could not open for snapshot copy "
            f"({type(exc).__name__}: {exc}) — vanished, swapped to a "
            "non-regular object, or unreadable mid-run"
        ) from exc
    try:
        mode = stat.S_IMODE(os.fstat(src_fd).st_mode) & 0o777
        try:
            dst_fd = os.open(
                dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY, mode
            )
        except OSError as exc:
            raise SnapshotMaterializationError(
                f"could not create snapshot file {dst!s} ({type(exc).__name__}: {exc})"
            ) from exc
        try:
            while True:
                try:
                    chunk = os.read(src_fd, _COPY_CHUNK)
                except OSError as exc:
                    raise SnapshotNonQuiescent(
                        f"{src!s}: read failed mid-copy ({type(exc).__name__}: {exc})"
                    ) from exc
                if not chunk:
                    break
                try:
                    os.write(dst_fd, chunk)
                except OSError as exc:
                    raise SnapshotMaterializationError(
                        f"write failed materializing {dst!s} "
                        f"({type(exc).__name__}: {exc})"
                    ) from exc
        finally:
            os.close(dst_fd)
    finally:
        os.close(src_fd)


def materialize_sealed_snapshot(bundle_dir: Path, snapshot_root: Path) -> None:
    """Materialize ``bundle_dir`` into the (existing, empty, verifier-private)
    ``snapshot_root``. Two source passes: copy, then re-walk and compare the
    (path, kind) sets — a concurrent rename can slip through a single readdir
    pass without any per-file open failing (readdir is not atomic), and a
    drifted set is exactly the non-quiescence this snapshot exists to refuse.
    """
    first = _scan_tree(bundle_dir)

    # Fail-closed by COMPLEMENT of the replicable kinds, not by enumerating the
    # known-bad ones: a denylist here goes stale the day _classify learns a new
    # kind name, and a kind the copy loop below doesn't handle would then be
    # silently dropped — a snapshot verifying a different tree than the source.
    unsupported = sorted(
        rel
        for rel, kind in first.items()
        if kind not in ("dir", "regular", "symlink", "fifo")
    )
    if unsupported:
        raise SnapshotUnsupportedNode(
            "bundle contains node types a sealed snapshot cannot replicate: "
            + ", ".join(f"{rel!r} ({first[rel]})" for rel in unsupported)
        )

    # Parents before children: sort by path depth (dict order from the stack
    # walk is not parent-first).
    for rel in sorted(first, key=lambda r: r.count("/")):
        kind = first[rel]
        src = bundle_dir / rel
        dst = snapshot_root / rel
        if kind == "dir":
            try:
                os.mkdir(dst)
            except OSError as exc:
                raise SnapshotMaterializationError(
                    f"could not create snapshot directory {dst!s} "
                    f"({type(exc).__name__}: {exc})"
                ) from exc
        elif kind == "regular":
            _copy_regular(src, dst)
        elif kind == "symlink":
            try:
                target = os.readlink(src)
            except OSError as exc:
                raise SnapshotNonQuiescent(
                    f"{src!s}: symlink vanished or became unreadable mid-copy "
                    f"({type(exc).__name__}: {exc})"
                ) from exc
            # Re-anchor an ABSOLUTE target that stays inside bundle_dir onto
            # the snapshot root: the link keeps naming the same in-tree
            # (pinned, walked) bytes, preserving the strict-walk's as-built
            # contained-symlink tolerance under relocation. Anything else —
            # a true escape, or an absolute path that only reaches the tree
            # through an unresolved alias — is replicated VERBATIM and
            # re-adjudicated by the containment guards on the snapshot
            # (where it resolves outside the tree and rejects).
            if os.path.isabs(target):
                norm = os.path.normpath(target)
                root_s = str(bundle_dir)
                if norm == root_s or norm.startswith(root_s + os.sep):
                    target = str(snapshot_root / os.path.relpath(norm, root_s))
            try:
                os.symlink(target, dst)
            except OSError as exc:
                raise SnapshotMaterializationError(
                    f"could not replicate symlink {dst!s} ({type(exc).__name__}: {exc})"
                ) from exc
        elif kind == "fifo":
            # Replicated so the conservation gate's non-regular face is
            # byte-identical to in-place verification; chmod 0 so an
            # accidental open fails fast (EACCES) instead of hanging.
            try:
                os.mkfifo(dst)
                os.chmod(dst, 0)
            except (OSError, AttributeError) as exc:
                raise SnapshotMaterializationError(
                    f"could not replicate FIFO {dst!s} ({type(exc).__name__}: {exc})"
                ) from exc
        else:
            # Unreachable today: the complement pre-filter above raises
            # SnapshotUnsupportedNode for every kind outside the four arms.
            # Kept as an invariant assertion so a future edit that decouples
            # the filter from this chain fails loudly instead of silently
            # dropping the node from the snapshot.
            raise SnapshotMaterializationError(
                f"copy loop reached unhandled node kind {kind!r} at {rel!r} "
                "— pre-filter and copy chain have drifted apart"
            )

    second = _scan_tree(bundle_dir)
    if second != first:
        added = sorted(set(second) - set(first))
        removed = sorted(set(first) - set(second))
        changed = sorted(
            rel for rel in set(first) & set(second) if first[rel] != second[rel]
        )
        raise SnapshotNonQuiescent(
            "bundle_dir changed while the sealed snapshot was being "
            f"materialized (appeared={added!r} vanished={removed!r} "
            f"kind-changed={changed!r}) — refusing to certify a moving target"
        )


@contextmanager
def sealed_snapshot(bundle_dir: Path) -> Iterator[Path]:
    """Context manager: yield a verifier-private sealed copy of
    ``bundle_dir``; best-effort cleanup on exit (a cleanup failure must never
    mask the verdict computed from the snapshot)."""
    try:
        root = Path(tempfile.mkdtemp(prefix="vkab-sealed-"))
    except OSError as exc:
        raise SnapshotMaterializationError(
            f"could not create the sealed-snapshot directory "
            f"({type(exc).__name__}: {exc})"
        ) from exc
    try:
        materialize_sealed_snapshot(bundle_dir, root)
        yield root
    finally:
        # rmtree does not follow symlinks for the tree it removes; FIFOs are
        # unlinked, never opened. Errors are swallowed: cleanup is best-effort
        # and must not replace the verdict.
        shutil.rmtree(root, ignore_errors=True)
