"""git_blob_resolver.py — C8 helper: file path + SHA-256 -> blob bytes."""

from __future__ import annotations

import hashlib
import subprocess
from functools import lru_cache
from pathlib import Path


class BlobNotFound(Exception):
    """Raised when no commit in git history yields a blob matching target_sha."""


@lru_cache(maxsize=256)
def resolve_blob_at_sha(repo_root: Path, file_path: str, target_sha: str) -> bytes:
    """Walk git history for file_path; return bytes whose SHA-256 equals target_sha.

    Fast path: probe HEAD's blob first via `git show HEAD:<file_path>`.  Audit
    bundles built from current state hit this path on the very first call and
    skip the O(N) `git log --all` walk entirely.  Falls back to the full-history
    walk only when HEAD's blob does not match (file modified post-bundle, deleted,
    or the bundle pins a historical revision).

    Args:
        repo_root:  Absolute path to the git repository root.
        file_path:  Repo-relative file path (forward slashes).
        target_sha: SHA-256 hex digest to match (64 hex chars).

    Returns:
        Raw bytes of the matching blob.

    Raises:
        BlobNotFound: No commit yields a blob matching target_sha.
        subprocess.CalledProcessError: git subprocess exits non-zero on the
            history walk (HEAD-probe failures are absorbed and fall through).
    """
    head_result = subprocess.run(
        ["git", "show", f"HEAD:{file_path}"],
        cwd=str(repo_root),
        capture_output=True,
        check=False,
    )
    if head_result.returncode == 0:
        head_content: bytes = head_result.stdout
        if hashlib.sha256(head_content).hexdigest() == target_sha:
            return head_content

    log_result = subprocess.run(
        ["git", "log", "--all", "--pretty=format:%H", "--", file_path],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=True,
    )
    commits = [c.strip() for c in log_result.stdout.splitlines() if c.strip()]

    for commit in commits:
        show_result = subprocess.run(
            ["git", "show", f"{commit}:{file_path}"],
            cwd=str(repo_root),
            capture_output=True,
            check=True,
        )
        content: bytes = show_result.stdout
        if hashlib.sha256(content).hexdigest() == target_sha:
            return content

    raise BlobNotFound(
        f"SHA-256 {target_sha[:8]}... not found in git history for {file_path!r}"
    )
