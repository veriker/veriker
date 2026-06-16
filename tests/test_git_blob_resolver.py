"""Tests for audit_bundle.git_blob_resolver — walk git history and return blob bytes."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from audit_bundle.git_blob_resolver import BlobNotFound, resolve_blob_at_sha

# Skip all tests in this module if git is not available in PATH.
pytestmark = pytest.mark.skipif(
    shutil.which("git") is None,
    reason="git not found in PATH",
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


def _git(args: list[str], cwd: Path) -> None:
    subprocess.run(["git"] + args, cwd=str(cwd), check=True, capture_output=True)


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


@pytest.fixture()
def git_repo(tmp_path: Path) -> Path:
    """Initialise a throwaway git repository."""
    _git(["init"], tmp_path)
    _git(["config", "user.email", "ci@test.local"], tmp_path)
    _git(["config", "user.name", "CI Test"], tmp_path)
    return tmp_path


@pytest.fixture(autouse=True)
def _clear_lru_cache():
    """Wipe the LRU cache before every test to prevent cross-test hits."""
    resolve_blob_at_sha.cache_clear()
    yield
    resolve_blob_at_sha.cache_clear()


# ---------------------------------------------------------------------------
# Single-commit resolution
# ---------------------------------------------------------------------------


def test_resolve_blob_single_commit(git_repo: Path) -> None:
    content = b"version one of the file"
    (git_repo / "file.txt").write_bytes(content)
    _git(["add", "file.txt"], git_repo)
    _git(["commit", "-m", "initial"], git_repo)

    sha = _sha256(content)
    result = resolve_blob_at_sha(git_repo, "file.txt", sha)
    assert result == content


def test_resolve_blob_returns_exact_bytes(git_repo: Path) -> None:
    content = b"\x00\x01\x02binary\xff\xfe"
    (git_repo / "blob.bin").write_bytes(content)
    _git(["add", "blob.bin"], git_repo)
    _git(["commit", "-m", "binary blob"], git_repo)

    sha = _sha256(content)
    assert resolve_blob_at_sha(git_repo, "blob.bin", sha) == content


# ---------------------------------------------------------------------------
# Two-commit resolution — both versions recoverable
# ---------------------------------------------------------------------------


def test_resolve_both_versions(git_repo: Path) -> None:
    content_v1 = b"first version - stable"
    content_v2 = b"second version - revised with more data"

    (git_repo / "report.md").write_bytes(content_v1)
    _git(["add", "report.md"], git_repo)
    _git(["commit", "-m", "v1"], git_repo)

    (git_repo / "report.md").write_bytes(content_v2)
    _git(["add", "report.md"], git_repo)
    _git(["commit", "-m", "v2"], git_repo)

    sha_v1 = _sha256(content_v1)
    sha_v2 = _sha256(content_v2)

    assert resolve_blob_at_sha(git_repo, "report.md", sha_v1) == content_v1
    assert resolve_blob_at_sha(git_repo, "report.md", sha_v2) == content_v2


def test_resolve_first_version_after_many_commits(git_repo: Path) -> None:
    """Oldest blob remains recoverable through an arbitrary number of commits."""
    original = b"original content - must survive"
    (git_repo / "doc.txt").write_bytes(original)
    _git(["add", "doc.txt"], git_repo)
    _git(["commit", "-m", "origin"], git_repo)

    for i in range(5):
        (git_repo / "doc.txt").write_bytes(f"revision {i}".encode())
        _git(["add", "doc.txt"], git_repo)
        _git(["commit", "-m", f"rev-{i}"], git_repo)

    sha_original = _sha256(original)
    assert resolve_blob_at_sha(git_repo, "doc.txt", sha_original) == original


# ---------------------------------------------------------------------------
# BlobNotFound on fabricated SHA
# ---------------------------------------------------------------------------


def test_blob_not_found_fabricated_sha(git_repo: Path) -> None:
    (git_repo / "data.txt").write_bytes(b"real content here")
    _git(["add", "data.txt"], git_repo)
    _git(["commit", "-m", "commit"], git_repo)

    fake_sha = "a" * 64
    with pytest.raises(BlobNotFound):
        resolve_blob_at_sha(git_repo, "data.txt", fake_sha)


def test_blob_not_found_message_contains_sha_prefix(git_repo: Path) -> None:
    (git_repo / "x.txt").write_bytes(b"xyz")
    _git(["add", "x.txt"], git_repo)
    _git(["commit", "-m", "x"], git_repo)

    fake_sha = "b" * 64
    with pytest.raises(BlobNotFound, match="bbbbbbbb"):
        resolve_blob_at_sha(git_repo, "x.txt", fake_sha)


def test_blob_not_found_no_commits_for_file(git_repo: Path) -> None:
    """File was never committed — no history, so BlobNotFound immediately."""
    fake_sha = "c" * 64
    with pytest.raises(BlobNotFound):
        resolve_blob_at_sha(git_repo, "never_committed.txt", fake_sha)
