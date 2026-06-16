"""Sealed-snapshot regression tests (BLOCK-01 mixed-snapshot closure, 2026-06-11).

The class under test: verify() is a CONJUNCTION of checks that each read
bundle files at separate instants. Before the sealed snapshot, a mid-run swap
of a bundle file could yield a verdict whose legs each honestly passed on
DIFFERENT bytes — certifying an artifact that never existed. The fix: verify()
materializes a verifier-private copy of bundle_dir before any
verdict-influencing read and runs every step against it, so the verdict is
computed over ONE immutable byte-set by construction.

The coherence test drives the seam directly: a plugin (running AFTER the
strict-SHA integrity walk, BEFORE deep manifest validation) swaps a
CID-pinned snapshot file in the ORIGINAL directory. In-place verification
splits — integrity passed over bytes A, the deep snapshot-CID validator sees
bytes B → REJECT (the racy conjunction made visible). Default-lane
verification is unmoved: every leg read the sealed copy.
"""

from __future__ import annotations

import errno
import json
import os
import socket
import sys
import tempfile
from hashlib import sha256
from pathlib import Path

import pytest

import audit_bundle.snapshot as snapshot_mod
from audit_bundle.snapshot import (
    SnapshotNonQuiescent,
    materialize_sealed_snapshot,
)
from audit_bundle.snapshots.cid import compute_cid
from audit_bundle.verdict import VerdictState
from audit_bundle.verifier import BundleVerifier


def _sha(data: bytes) -> str:
    return sha256(data).hexdigest()


def _write_snapshot_bundle(bundle_dir: Path) -> tuple[Path, bytes]:
    """A minimal green bundle carrying one CID-pinned snapshot file: the deep
    snapshot-CID validator (which runs AFTER plugin dispatch) re-reads it, so
    a mid-run swap is observable on the in-place lane."""
    bundle_dir.mkdir()
    (bundle_dir / "snapshots").mkdir()
    payload = b"the pinned snapshot bytes\n"
    cid = compute_cid(payload)
    snap_rel = "snapshots/doc.txt"
    (bundle_dir / snap_rel).write_bytes(payload)
    manifest = {
        "schema_version": "vcp-v1.1-canary4",
        "bundle_id": "sealed-snapshot-coherence",
        "created_at": "2026-06-11T00:00:00Z",
        "files": {snap_rel: _sha(payload)},
        "spec_files": {},
        "cross_refs": {},
        "snapshots": {cid: snap_rel},
        "snapshot_policy": {
            "policy_version": "0.1",
            "normalization_version": "0.1",
            "rendered_text_extractor": "identity",
            "raw_bytes_kept": True,
        },
    }
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return bundle_dir / snap_rel, payload


class _MidRunSwapper:
    """A 'plugin' that mutates the ORIGINAL bundle directory mid-verify —
    the concurrent producer / active adversary from the threat model. It runs
    after the strict-SHA walk and before deep manifest validation."""

    name = "mid_run_swapper"
    applies_to_files: frozenset[str] = frozenset()

    def __init__(self, original_file: Path) -> None:
        self._original_file = original_file

    def check(self, bundle_dir: Path, manifest) -> object:
        self._original_file.write_bytes(b"SWAPPED bytes the pins never named\n")
        from audit_bundle.plugin import PluginResult

        return PluginResult(ok=True, reason_code="PASS", detail="", files_audited=())


def test_mid_run_swap_cannot_split_the_verdict(tmp_path):
    """Default lane: the swap in the original directory is INERT — every leg
    read the sealed copy, so the verdict is the one-artifact conjunction."""
    target, _ = _write_snapshot_bundle(tmp_path / "b")
    verifier = BundleVerifier(plugins=(_MidRunSwapper(target),))

    verdict = verifier.verify(tmp_path / "b")

    assert verdict.ok, [(f.reason_code, f.detail) for f in verdict.failures]
    # The swap really happened — in the original, which no leg consulted.
    assert target.read_bytes().startswith(b"SWAPPED")


@pytest.mark.skipif(sys.platform == "win32", reason="posix lanes")
def test_in_place_lane_exhibits_the_split_and_stamps_disclosure(tmp_path):
    """unsafe_in_place=True restores the live-directory read: integrity
    passed over bytes A, the deep snapshot-CID validator sees bytes B —
    the racy conjunction REJECTS, and the verdict face carries the in-place
    disclosure stamp."""
    target, _ = _write_snapshot_bundle(tmp_path / "b")
    verifier = BundleVerifier(plugins=(_MidRunSwapper(target),), unsafe_in_place=True)

    verdict = verifier.verify(tmp_path / "b")

    assert not verdict.ok
    assert verdict.completeness is not None
    assert any("verified IN PLACE" in d for d in verdict.completeness.disclosures)


def test_in_place_disclosure_on_green_face(tmp_path):
    _write_snapshot_bundle(tmp_path / "b")
    verdict = BundleVerifier(unsafe_in_place=True).verify(tmp_path / "b")
    assert verdict.ok
    assert any("verified IN PLACE" in d for d in verdict.completeness.disclosures)


def test_default_lane_face_carries_no_in_place_stamp(tmp_path):
    _write_snapshot_bundle(tmp_path / "b")
    verdict = BundleVerifier().verify(tmp_path / "b")
    assert verdict.ok
    assert not any("IN PLACE" in d for d in verdict.completeness.disclosures)


# ---------------------------------------------------------------------------
# Node-type vocabulary
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "linux", reason="AF_UNIX socket files")
def test_socket_node_is_structured_snapshot_reject(tmp_path):
    """An unreplicable node type (socket) fails closed at the snapshot, with
    a structured face naming the path — never copied, never opened."""
    _write_snapshot_bundle(tmp_path / "b")
    # AF_UNIX paths are length-capped (~108 bytes); bind via a short cwd hop.
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    cwd = os.getcwd()
    try:
        os.chdir(tmp_path / "b")
        sock.bind("stray.sock")
    finally:
        os.chdir(cwd)
        sock.close()

    verdict = BundleVerifier().verify(tmp_path / "b")

    assert verdict.state is VerdictState.REJECT
    assert any(
        f.reason_code == "SNAPSHOT_UNSUPPORTED_NODE" and "stray.sock" in f.detail
        for f in verdict.failures
    )


@pytest.mark.skipif(sys.platform != "linux", reason="mkfifo")
def test_fifo_face_is_unchanged_by_the_snapshot_lane(tmp_path):
    """A FIFO is replicated (mkfifo, chmod 0, never opened) so the
    conservation gate's existing non-regular rejection face is identical to
    in-place verification."""
    _write_snapshot_bundle(tmp_path / "b")
    os.mkfifo(tmp_path / "b" / "stray.pipe")

    verdict = BundleVerifier().verify(tmp_path / "b")

    assert not verdict.ok
    assert any(
        f.reason_code == "EXTRA_FILE_NOT_IN_MANIFEST"
        and "non-regular file object (fifo)" in f.detail
        for f in verdict.failures
    )


@pytest.mark.skipif(sys.platform != "linux", reason="symlink semantics")
def test_absolute_in_tree_symlink_tolerance_survives_relocation(tmp_path):
    """The as-built tolerance for a DECLARED in-tree symlink with an ABSOLUTE
    target: re-anchored onto the snapshot root, it keeps naming the same
    pinned bytes (the conservation-gate suite asserts the same end-to-end;
    this pins the snapshot-layer transform directly)."""
    bundle_dir = tmp_path / "b"
    bundle_dir.mkdir()
    (bundle_dir / "real.txt").write_bytes(b"linked payload")
    (bundle_dir / "alias.txt").symlink_to(bundle_dir / "real.txt")
    snap_root = tmp_path / "snap"
    snap_root.mkdir()

    materialize_sealed_snapshot(bundle_dir.resolve(), snap_root)

    link_target = os.readlink(snap_root / "alias.txt")
    assert link_target == str(snap_root / "real.txt")
    assert (snap_root / "alias.txt").read_bytes() == b"linked payload"


@pytest.mark.skipif(sys.platform != "linux", reason="symlink semantics")
def test_escaping_symlink_replicated_verbatim(tmp_path):
    """A target outside bundle_dir is NOT rewritten — the containment guards
    re-adjudicate it on the snapshot and reject, exactly as in place."""
    bundle_dir = tmp_path / "b"
    bundle_dir.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"host bytes")
    (bundle_dir / "escape.txt").symlink_to(outside)
    snap_root = tmp_path / "snap"
    snap_root.mkdir()

    materialize_sealed_snapshot(bundle_dir.resolve(), snap_root)

    assert os.readlink(snap_root / "escape.txt") == str(outside)


# ---------------------------------------------------------------------------
# Non-quiescence and failure split
# ---------------------------------------------------------------------------


def test_vanishing_file_mid_copy_is_source_unstable_reject(tmp_path, monkeypatch):
    _write_snapshot_bundle(tmp_path / "b")
    real_open = snapshot_mod.open_regular_fd_nofollow
    state = {"armed": True}

    def vanishing_open(path: Path) -> int:
        if state["armed"] and path.name == "doc.txt":
            state["armed"] = False
            os.unlink(path)
        return real_open(path)

    monkeypatch.setattr(snapshot_mod, "open_regular_fd_nofollow", vanishing_open)

    verdict = BundleVerifier().verify(tmp_path / "b")

    assert verdict.state is VerdictState.REJECT
    assert any(f.reason_code == "SNAPSHOT_SOURCE_UNSTABLE" for f in verdict.failures)


def test_post_copy_rewalk_catches_concurrent_rename(tmp_path, monkeypatch):
    """The readdir/rename race: no per-file open fails, but the second source
    walk observes a different path set → non-quiescence REJECT."""
    bundle = tmp_path / "b"
    _write_snapshot_bundle(bundle)
    real_scan = snapshot_mod._scan_tree
    state = {"calls": 0}

    def racing_scan(root: Path):
        state["calls"] += 1
        result = real_scan(root)
        if state["calls"] == 1:
            # Mutate AFTER the copy pass's scan, without starving any copy
            # (an added file is invisible to the copy loop — only the
            # re-walk can see it).
            (bundle / "snapshots" / "late.txt").write_bytes(b"slipped in")
        return result

    monkeypatch.setattr(snapshot_mod, "_scan_tree", racing_scan)
    (tmp_path / "snap_x").mkdir()

    with pytest.raises(SnapshotNonQuiescent, match="moving target"):
        materialize_sealed_snapshot(bundle.resolve(), tmp_path / "snap_x")


def test_dest_side_failure_is_clean_error_not_reject(tmp_path, monkeypatch):
    """ENOSPC-class destination failure is a verifier-side could-not-conclude
    ERROR — never blamed on the bundle."""
    _write_snapshot_bundle(tmp_path / "b")

    def no_space(*args, **kwargs):
        raise OSError(errno.ENOSPC, "no space left on device")

    monkeypatch.setattr(snapshot_mod.tempfile, "mkdtemp", no_space)

    verdict = BundleVerifier().verify(tmp_path / "b")

    assert verdict.state is VerdictState.ERROR
    assert any(
        f.reason_code == "SNAPSHOT_MATERIALIZATION_FAILED" for f in verdict.failures
    )


def test_snapshot_dirs_are_cleaned_up(tmp_path, monkeypatch):
    """No vkab-sealed-* residue after green AND reject verifies."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path / "scratch"))
    (tmp_path / "scratch").mkdir()
    _write_snapshot_bundle(tmp_path / "b")

    assert BundleVerifier().verify(tmp_path / "b").ok
    # Reject path too: break the pinned file.
    (tmp_path / "b" / "snapshots" / "doc.txt").write_bytes(b"broken")
    assert not BundleVerifier().verify(tmp_path / "b").ok

    assert list((tmp_path / "scratch").glob("vkab-sealed-*")) == []


def test_missing_bundle_dir_keeps_canonical_face(tmp_path):
    verdict = BundleVerifier().verify(tmp_path / "never_created")
    assert verdict.state is VerdictState.REJECT
    assert any(
        f.reason_code == "malformed_manifest" and "manifest.json not found" in f.detail
        for f in verdict.failures
    )
