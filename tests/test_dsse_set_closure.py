"""tests/test_dsse_set_closure.py — Set-closure immutable-snapshot helper tests.

Linux-gated tests (O_NOFOLLOW / inode semantics) are marked with
``@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only O_NOFOLLOW")``.

Coverage targets
----------------
1. Happy path: exact match → ok=True, reason_code=None.
2. Surplus: extra on-disk file not in expected → UNLISTED_FILE_IN_SEALED_ROOT.
3. Missing: expected file absent on disk → SEALED_ROOT_FILE_MISSING.
4. Symlink TOCTOU: symlinked file and symlinked directory → detected unstable.
5. Inode instability (mid-read swap): monkeypatched post-read fstat diverges →
   SEALED_ROOT_FILE_UNSTABLE.
6. Path escape: ``../evil`` entry in expected_files (the SIGNED set) → hard
   reject (UNSAFE_EXPECTED_PATH_IN_SEALED_MANIFEST), never silently dropped,
   and never propagated as a crash.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from audit_bundle.dsse.set_closure import SetClosureResult, snapshot_and_compare

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_bundle(tmp_path: Path, files: dict[str, str]) -> Path:
    """Create a temporary bundle directory with the given file contents.

    Parameters
    ----------
    files:
        Mapping of relative-POSIX path → file content string.
    """
    root = tmp_path / "bundle"
    root.mkdir()
    for rel, content in files.items():
        fpath = root / rel
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(content)
    return root


# ---------------------------------------------------------------------------
# Test 1: Happy path
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only O_NOFOLLOW")
def test_happy_path_exact_match(tmp_path: Path) -> None:
    """Exact set match with nested file → ok=True, no missing/surplus/unstable."""
    bundle = _make_bundle(
        tmp_path,
        {
            "a.txt": "hello",
            "sub/b.txt": "world",
        },
    )
    expected = frozenset({"a.txt", "sub/b.txt"})
    result = snapshot_and_compare(bundle, expected)

    assert isinstance(result, SetClosureResult)
    assert result.ok is True
    assert result.missing == frozenset()
    assert result.surplus == frozenset()
    assert result.unstable == ()
    assert result.reason_code is None


# ---------------------------------------------------------------------------
# Test 2: Surplus file
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only O_NOFOLLOW")
def test_surplus_file(tmp_path: Path) -> None:
    """Extra on-disk file not in expected → UNLISTED_FILE_IN_SEALED_ROOT."""
    bundle = _make_bundle(
        tmp_path,
        {
            "a.txt": "hello",
            "sub/b.txt": "world",
            "extra.txt": "surplus",
        },
    )
    expected = frozenset({"a.txt", "sub/b.txt"})
    result = snapshot_and_compare(bundle, expected)

    assert result.ok is False
    assert result.reason_code == "UNLISTED_FILE_IN_SEALED_ROOT"
    assert "extra.txt" in result.surplus
    assert result.missing == frozenset()
    assert result.unstable == ()


# ---------------------------------------------------------------------------
# Test 3: Missing file
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only O_NOFOLLOW")
def test_missing_file(tmp_path: Path) -> None:
    """Expected file absent on disk → SEALED_ROOT_FILE_MISSING."""
    bundle = _make_bundle(
        tmp_path,
        {
            "a.txt": "hello",
        },
    )
    # expected includes sub/b.txt which does not exist on disk
    expected = frozenset({"a.txt", "sub/b.txt"})
    result = snapshot_and_compare(bundle, expected)

    assert result.ok is False
    assert result.reason_code == "SEALED_ROOT_FILE_MISSING"
    assert "sub/b.txt" in result.missing
    assert result.surplus == frozenset()
    assert result.unstable == ()


# ---------------------------------------------------------------------------
# Test 4a: Symlinked file detected as unstable
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only O_NOFOLLOW")
def test_symlink_file_rejected(tmp_path: Path) -> None:
    """A symlinked file under bundle_root is detected and marked unstable."""
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    # Create a real file outside the bundle
    outside = tmp_path / "outside.txt"
    outside.write_text("external")

    # Create a symlink inside the bundle pointing outside
    link = bundle / "linked.txt"
    link.symlink_to(outside)

    expected = frozenset({"linked.txt"})
    result = snapshot_and_compare(bundle, expected)

    assert result.ok is False
    assert result.reason_code == "SEALED_ROOT_FILE_UNSTABLE"
    assert "linked.txt" in result.unstable


# ---------------------------------------------------------------------------
# Test 4b: Symlinked directory detected as unstable
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only O_NOFOLLOW")
def test_symlink_dir_rejected(tmp_path: Path) -> None:
    """A symlinked sub-directory under bundle_root is detected and marked unstable."""
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    # Create a real sub-directory with a file outside the bundle
    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir()
    (outside_dir / "secret.txt").write_text("secret")

    # Create a symlink to the outside dir inside the bundle
    link_dir = bundle / "subdir"
    link_dir.symlink_to(outside_dir)

    # The symlinked dir is not traversed; nothing in it appears in on_disk.
    # The symlink itself appears as unstable.
    expected = frozenset({"subdir/secret.txt"})
    result = snapshot_and_compare(bundle, expected)

    assert result.ok is False
    # symlink dir is unstable; subdir/secret.txt is also missing since the dir
    # was not traversed — either unstable or missing reason is acceptable, but
    # the call must not crash.
    assert result.reason_code in (
        "SEALED_ROOT_FILE_UNSTABLE",
        "SEALED_ROOT_FILE_MISSING",
    )
    # The symlinked directory entry itself should be in unstable
    assert "subdir" in result.unstable


# ---------------------------------------------------------------------------
# Test 5: Inode instability — monkeypatched post-read fstat diverges
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only O_NOFOLLOW")
def test_inode_instability_detected(tmp_path: Path) -> None:
    """Simulated mid-read inode swap is caught and marked unstable."""
    bundle = _make_bundle(tmp_path, {"file.txt": "content"})
    expected = frozenset({"file.txt"})

    original_fstat = os.fstat

    call_count: list[int] = [0]

    def patched_fstat(fd: int) -> os.stat_result:
        result = original_fstat(fd)
        call_count[0] += 1
        # On the second fstat call (post-read), return a fake result with a
        # different st_ino to simulate a mid-read inode swap.
        if call_count[0] % 2 == 0:
            # Build a fake stat_result tuple — st_ino is index 1 in os.stat_result.
            # We use os.stat_result constructor via a sequence.
            vals = list(result)
            vals[1] = result.st_ino ^ 0xDEADBEEF  # corrupt st_ino
            return os.stat_result(vals)
        return result

    with patch("audit_bundle.dsse.set_closure.os.fstat", side_effect=patched_fstat):
        result = snapshot_and_compare(bundle, expected)

    assert result.ok is False
    assert result.reason_code == "SEALED_ROOT_FILE_UNSTABLE"
    assert "file.txt" in result.unstable


# ---------------------------------------------------------------------------
# Test 6: Path escape in expected_files
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only O_NOFOLLOW")
def test_path_escape_in_expected_is_hard_reject(tmp_path: Path) -> None:
    """A '../evil' entry in the SIGNED expected set is a hard reject, not a drop.

    Regression for the fail-open where an unsafe (path-escaping) entry in the
    signed expected set was silently excluded, letting the remaining files
    match on disk and return ok=True. The signed set must be honored verbatim:
    an attested path the verifier cannot validate hard-rejects.
    """
    bundle = _make_bundle(tmp_path, {"legit.txt": "ok"})

    # Create the "evil" file outside the bundle so it genuinely exists on disk.
    evil = tmp_path / "evil"
    evil.write_text("evil")

    # Pass a traversal path in expected_files. Every other file matches on disk;
    # only the unsafe entry is anomalous — exactly the case the old code passed.
    expected = frozenset({"legit.txt", "../evil"})

    # Must not raise UnsafeBundlePath or any other exception (fail-closed, not crash).
    result = snapshot_and_compare(bundle, expected)

    assert result.ok is False
    assert result.reason_code == "UNSAFE_EXPECTED_PATH_IN_SEALED_MANIFEST"
    assert "../evil" in result.unsafe_expected
    # The unsafe entry must NOT be laundered into "missing" or simply dropped.
    assert "../evil" not in result.missing


# ---------------------------------------------------------------------------
# Test 7: Result is immutable (frozen dataclass)
# ---------------------------------------------------------------------------


def test_result_is_frozen() -> None:
    """SetClosureResult is a frozen dataclass — mutation must raise."""
    r = SetClosureResult(
        ok=True,
        missing=frozenset(),
        surplus=frozenset(),
        unstable=(),
        reason_code=None,
    )
    with pytest.raises((AttributeError, TypeError)):
        r.ok = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Test 8: Reason code precedence (unstable beats surplus beats missing)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only O_NOFOLLOW")
def test_reason_code_precedence_unstable_wins(tmp_path: Path) -> None:
    """When unstable, surplus, AND missing all fire, reason_code is UNSTABLE."""
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    # Create a real file (will become surplus — not in expected)
    (bundle / "surplus.txt").write_text("extra")

    # Create a symlink (will be unstable)
    outside = tmp_path / "outside.txt"
    outside.write_text("ext")
    (bundle / "linked.txt").symlink_to(outside)

    # expected_files includes a missing file + surplus.txt is not in expected
    expected = frozenset({"missing.txt"})
    result = snapshot_and_compare(bundle, expected)

    # unstable (symlink) takes precedence
    assert result.reason_code == "SEALED_ROOT_FILE_UNSTABLE"
    assert "linked.txt" in result.unstable
    assert "surplus.txt" in result.surplus
    assert "missing.txt" in result.missing
    assert result.ok is False


# ---------------------------------------------------------------------------
# Test 6: Non-regular file (FIFO) detected as unstable — fail closed
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only os.mkfifo + O_NOFOLLOW")
def test_fifo_rejected_as_unstable(tmp_path: Path) -> None:
    """A planted FIFO (non-regular, non-directory) under bundle_root is marked
    unstable, not silently skipped. Before the fix it was invisible to sealed
    set-closure — neither hashed into on_disk nor flagged — so a seal could
    ride a green verdict over an un-attested special file."""
    bundle = tmp_path / "bundle"
    bundle.mkdir()

    fifo = bundle / "pipe"
    os.mkfifo(fifo)

    # The seal lists the FIFO as an expected member; it must still fail closed
    # (the object cannot be content-hashed or set-closed).
    expected = frozenset({"pipe"})
    result = snapshot_and_compare(bundle, expected)

    assert result.ok is False
    assert result.reason_code == "SEALED_ROOT_FILE_UNSTABLE"
    assert "pipe" in result.unstable
    # Crucially, it is NOT laundered into the on-disk (verified) set.
    assert "pipe" not in result.surplus
