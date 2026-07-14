"""Path-safety regression suite — atheris finding 2026-05-26.

Coverage-guided fuzz of BundleVerifier.verify() (atheris harness:
tests/fuzz/atheris_verify_manifest.py) discovered that
``{"files":{"/":"a"}}`` made pathlib's ``bundle_dir / "/"`` absolutize to
``/``, then ``fpath.read_bytes()`` raised ``IsADirectoryError`` — a fail-stop
DoS that breaks the §C9 "verify never raises" contract.

The same path-handling bug had two siblings:

  (a) ``{"files":{"/etc/hostname":"a"}}`` — no crash, but the verifier
      SHA-256'd an attacker-chosen file outside the bundle and echoed the
      computed hash back through the failure detail (probe oracle).
  (b) ``{"cross_refs":{"x":"/"}}`` — would have crashed the same way once
      ``_step_cross_refs``'s ``(bundle_dir / target).exists()`` probe
      reached a non-existent absolute target whose parent it could not stat.

All three are now closed by ``_safe_bundle_path`` (bundle_manifest.py),
which fail-closes on (i) any resolved path escaping ``bundle_dir.resolve()``
and (ii) any resolved path that exists but is not a regular file. The
single-source-of-truth pattern mirrors ``_validate_field_shapes`` — both
verifier.py and validate_manifest() route through the same helper so the
two paths cannot drift.

This suite codifies the threat model so the breaks cannot silently
regress. The crash corpus seed lives at
``tests/fuzz/crashes/manifest/crash-518e93f9fb35e9a281375818869d7ca5ef1dab46``;
the atheris harness will replay it on every coverage-guided run.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import threading

from audit_bundle.bundle_manifest import (
    BundleManifest,
    UnsafeBundlePath,
    _safe_bundle_path,
    open_regular_fd_nofollow,
    validate_manifest,
)
from audit_bundle.verifier import BundleVerifier, VerifyResult


def _run_with_timeout(fn, timeout: float = 5.0):
    """Run ``fn`` on a daemon thread; return (finished, box). A regression that
    reaches a blocking open()/read() leaves the thread alive and finished=False,
    so the assert fails instead of hanging the whole suite."""
    box: dict = {}
    done = threading.Event()

    def go() -> None:
        try:
            box["result"] = fn()
        except BaseException as exc:  # noqa: BLE001 — record, don't hang
            box["exc"] = exc
        done.set()

    threading.Thread(target=go, daemon=True).start()
    return done.wait(timeout), box


# ---------------------------------------------------------------------------
# (rel_path, label) — every entry MUST be rejected without raising on the
# BundleVerifier path, and MUST raise UnsafeBundlePath on the
# validate_manifest path. ``None`` for SHA forces dict[str, str] shape.
# ---------------------------------------------------------------------------
EVIL_PATHS: list[tuple[str, str]] = [
    ("/", "filesystem_root"),
    (".", "bundle_self_dir"),
    ("/etc/hostname", "absolute_outside_bundle"),
    ("/dev/null", "device_special_file"),
    ("../../etc/hostname", "dotdot_traversal"),
    ("../../..", "dotdot_only"),
]


def _bundle_with_manifest(tmp_path: Path, payload: dict) -> Path:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "manifest.json").write_text(json.dumps(payload))
    return bundle


@pytest.mark.parametrize("rel_path,label", EVIL_PATHS, ids=[p[1] for p in EVIL_PATHS])
def test_files_evil_path_rejected_not_crashed(
    tmp_path: Path, rel_path: str, label: str
) -> None:
    """files entry with an unsafe path: ok=False, reason=path_escape, no raise."""
    bundle = _bundle_with_manifest(tmp_path, {"files": {rel_path: "deadbeef"}})
    result = BundleVerifier().verify(bundle)  # must not raise
    assert isinstance(result, VerifyResult)
    assert result.ok is False, f"{label}: evil path accepted"
    assert any(f.reason_code == "path_escape" for f in result.failures), (
        f"{label}: expected path_escape reason, got {[f.reason_code for f in result.failures]}"
    )


@pytest.mark.parametrize("rel_path,label", EVIL_PATHS, ids=[p[1] for p in EVIL_PATHS])
def test_cross_refs_evil_target_not_reachable(
    tmp_path: Path, rel_path: str, label: str
) -> None:
    """cross_refs target with an unsafe path is treated as not-reachable.

    The cross_refs walk does not surface path_escape as its own reason
    (the entry isn't claiming bytes-on-disk, just reachability), so the
    helper's UnsafeBundlePath is downgraded to ``not in_files`` and the
    existing ``broken_cross_ref`` reason fires.
    """
    bundle = _bundle_with_manifest(
        tmp_path,
        {
            "files": {rel_path: "deadbeef"},  # also evil — file_integrity rejects
            "cross_refs": {"self": rel_path},
        },
    )
    result = BundleVerifier().verify(bundle)  # must not raise
    assert result.ok is False
    codes = {f.reason_code for f in result.failures}
    assert "path_escape" in codes, f"{label}: file_integrity must flag path_escape"
    assert "broken_cross_ref" in codes, (
        f"{label}: cross_refs target outside bundle must be unreachable"
    )


@pytest.mark.parametrize("rel_path,label", EVIL_PATHS, ids=[p[1] for p in EVIL_PATHS])
def test_validate_manifest_raises_unsafe_bundle_path(
    tmp_path: Path, rel_path: str, label: str
) -> None:
    """validate_manifest is the strict twin: every evil path must raise."""
    m = BundleManifest(
        schema_version="legacy",
        bundle_id="b",
        created_at="2026-01-01T00:00:00Z",
        files={rel_path: "deadbeef" * 8},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
    )
    with pytest.raises(UnsafeBundlePath):
        validate_manifest(m, tmp_path)


def test_safe_path_accepts_legitimate_relative(tmp_path: Path) -> None:
    """Sanity: the helper must NOT over-reject normal relative paths."""
    (tmp_path / "data.txt").write_text("hi")
    resolved = _safe_bundle_path(tmp_path, "data.txt")
    assert resolved == (tmp_path / "data.txt").resolve()
    assert resolved.is_file()


def test_safe_path_accepts_missing_relative(tmp_path: Path) -> None:
    """Helper guards path-escape + wrong-file-type ONLY — missing files
    must still pass through so the integrity walk surfaces 'file missing'
    via its existing ``fpath.exists()`` check."""
    resolved = _safe_bundle_path(tmp_path, "no_such_file.txt")
    assert not resolved.exists()


def test_safe_path_accepts_nested_relative(tmp_path: Path) -> None:
    """Nested-but-contained paths must be allowed."""
    sub = tmp_path / "sub" / "deeper"
    sub.mkdir(parents=True)
    (sub / "data.txt").write_text("hi")
    resolved = _safe_bundle_path(tmp_path, "sub/deeper/data.txt")
    assert resolved.is_file()


def test_safe_path_rejects_dotdot_escape(tmp_path: Path) -> None:
    """The .. case directly: confirms the resolve()+relative_to() guard."""
    with pytest.raises(UnsafeBundlePath, match="resolves outside bundle_dir"):
        _safe_bundle_path(tmp_path, "../escaped.txt")


def test_safe_path_rejects_directory_target(tmp_path: Path) -> None:
    """The IsADirectoryError finding: directory target must fail-close."""
    sub = tmp_path / "sub"
    sub.mkdir()
    with pytest.raises(UnsafeBundlePath, match="directory"):
        _safe_bundle_path(tmp_path, "sub")


def test_safe_path_rejects_symlink_escape(tmp_path: Path) -> None:
    """A symlink whose target is outside bundle_dir must fail-close.

    resolve() follows symlinks; relative_to() then sees the real (external)
    location and raises ValueError → UnsafeBundlePath.
    """
    outside = tmp_path.parent / "outside_target.txt"
    outside.write_text("outside")
    try:
        link = tmp_path / "evil_link"
        link.symlink_to(outside)
        with pytest.raises(UnsafeBundlePath, match="resolves outside bundle_dir"):
            _safe_bundle_path(tmp_path, "evil_link")
    finally:
        if outside.exists():
            outside.unlink()


# ---------------------------------------------------------------------------
# BLOCK-01 — the chokepoint must reject non-regular objects (FIFO/socket),
# not just directories. A FIFO at a manifest-declared path used to slip past
# the old is_dir()-only guard and then BLOCK the verifier on a blocking read
# (a DoS landing BEFORE any verdict). The docstring already claimed clause
# (ii) "any resolved path that exists but is not a regular file"; these
# regressions hold the implementation to it.
# ---------------------------------------------------------------------------


def test_safe_path_rejects_fifo_no_hang(tmp_path: Path) -> None:
    """A FIFO at a declared path must fail-close via lstat, never reach a
    blocking open(). lstat classifies the node without opening it, so this
    test cannot hang even though a real read of the FIFO would block forever.
    """
    os.mkfifo(tmp_path / "trace.jsonl")
    with pytest.raises(UnsafeBundlePath, match="non-regular file"):
        _safe_bundle_path(tmp_path, "trace.jsonl")


def test_safe_path_accepts_contained_symlink_to_regular(tmp_path: Path) -> None:
    """As-built tolerance: an IN-TREE symlink whose target is a contained
    regular file is allowed — the strict-SHA walk SHA-pins the dereferenced
    bytes (test_declared_in_tree_symlink_keeps_as_built_tolerance). Only the
    append-only read, which is not SHA-pinned, layers O_NOFOLLOW to refuse it.
    """
    (tmp_path / "real.txt").write_text("hi")
    (tmp_path / "alias.txt").symlink_to(tmp_path / "real.txt")
    resolved = _safe_bundle_path(tmp_path, "alias.txt")
    assert resolved == (tmp_path / "real.txt").resolve()


def test_safe_path_rejects_symlink_to_contained_dir(tmp_path: Path) -> None:
    """A contained symlink whose target is NOT a regular file (here a
    directory) still fails closed — tolerance is for regular-file targets only.
    """
    (tmp_path / "sub").mkdir()
    (tmp_path / "dirlink").symlink_to(tmp_path / "sub")
    with pytest.raises(UnsafeBundlePath, match="non-regular object"):
        _safe_bundle_path(tmp_path, "dirlink")


# ---------------------------------------------------------------------------
# BLOCK-01 (review follow-up) — TOCTOU-robust no-follow/no-block READ primitive.
#
# _safe_bundle_path classifies the object WITHOUT opening it (it cannot hang),
# but the read that follows is not atomic with that stat. open_regular_fd_nofollow
# is the shared guard both _safe_bundle_path users rely on (the strict-SHA walk's
# read_bytes-equivalent AND the append-only stream): it refuses a FIFO/socket
# (O_NONBLOCK + fstat) and a final-component symlink (O_NOFOLLOW) AT OPEN TIME,
# so a regular→FIFO/symlink swap landing exactly at the read cannot hang or
# follow. Opening a FIFO directly is the deterministic stand-in for that race.
# ---------------------------------------------------------------------------


def test_open_primitive_fifo_raises_no_hang(tmp_path: Path) -> None:
    """A FIFO at open time (the regular→FIFO TOCTOU case) must raise, not hang."""
    os.mkfifo(tmp_path / "f")
    finished, box = _run_with_timeout(lambda: open_regular_fd_nofollow(tmp_path / "f"))
    assert finished, "open_regular_fd_nofollow HUNG on a FIFO"
    assert isinstance(box.get("exc"), OSError)


def test_open_primitive_symlink_to_regular_raises(tmp_path: Path) -> None:
    """O_NOFOLLOW refuses a final-component symlink (the regular→symlink TOCTOU
    case), even when the target is a perfectly good regular file."""
    (tmp_path / "real").write_text("hi")
    (tmp_path / "link").symlink_to(tmp_path / "real")
    finished, box = _run_with_timeout(lambda: open_regular_fd_nofollow(tmp_path / "link"))
    assert finished
    assert isinstance(box.get("exc"), OSError)


def test_open_primitive_symlink_to_fifo_raises_no_hang(tmp_path: Path) -> None:
    """Symlink whose target is a FIFO: O_NOFOLLOW rejects the link before the
    FIFO can be opened — no hang on either layer."""
    os.mkfifo(tmp_path / "f")
    (tmp_path / "link").symlink_to(tmp_path / "f")
    finished, box = _run_with_timeout(lambda: open_regular_fd_nofollow(tmp_path / "link"))
    assert finished, "open_regular_fd_nofollow HUNG on a symlink-to-FIFO"
    assert isinstance(box.get("exc"), OSError)


def test_open_primitive_accepts_regular(tmp_path: Path) -> None:
    """A plain regular file opens and reads through the primitive."""
    (tmp_path / "real").write_bytes(b"payload")

    def _read() -> bytes:
        with os.fdopen(open_regular_fd_nofollow(tmp_path / "real"), "rb") as fh:
            return fh.read()

    finished, box = _run_with_timeout(_read)
    assert finished and box.get("result") == b"payload"


def test_safe_path_rejects_symlink_to_contained_fifo(tmp_path: Path) -> None:
    """_safe_bundle_path itself rejects a contained symlink whose target is a
    FIFO (not a regular file) — the chokepoint stat-layer, no open involved."""
    os.mkfifo(tmp_path / "f")
    (tmp_path / "link").symlink_to(tmp_path / "f")
    with pytest.raises(UnsafeBundlePath, match="non-regular object"):
        _safe_bundle_path(tmp_path, "link")


# ---------------------------------------------------------------------------
# Strict-SHA walk (the OTHER _safe_bundle_path user) — full reject + no-hang
# matrix through BundleVerifier.verify() with a manifest.files entry.
# ---------------------------------------------------------------------------

import hashlib  # noqa: E402


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _verify_files_bundle(tmp_path: Path, setup) -> "VerifyResult":
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    files = setup(bundle)
    (bundle / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "vcp-v1.1-canary4",
                "bundle_id": "block01",
                "created_at": "2026-01-01T00:00:00Z",
                "files": files,
                "spec_files": {},
                "cross_refs": {},
            }
        )
    )
    return BundleVerifier(plugins=()).verify(bundle)


def test_strictsha_direct_fifo_rejects_no_hang(tmp_path: Path) -> None:
    def setup(bundle: Path) -> dict:
        os.mkfifo(bundle / "trace.jsonl")
        return {"trace.jsonl": _sha(b"x")}

    finished, box = _run_with_timeout(lambda: _verify_files_bundle(tmp_path, setup))
    assert finished, "verify() HUNG on a FIFO declared in manifest.files"
    assert box["result"].ok is False


def test_strictsha_symlink_to_fifo_rejects_no_hang(tmp_path: Path) -> None:
    def setup(bundle: Path) -> dict:
        os.mkfifo(bundle / "real.fifo")
        (bundle / "trace.jsonl").symlink_to(bundle / "real.fifo")
        return {"trace.jsonl": _sha(b"x")}

    finished, box = _run_with_timeout(lambda: _verify_files_bundle(tmp_path, setup))
    assert finished, "verify() HUNG on a symlink-to-FIFO in manifest.files"
    assert box["result"].ok is False


def test_strictsha_external_symlink_rejects(tmp_path: Path) -> None:
    def setup(bundle: Path) -> dict:
        ext = tmp_path / "host_state.txt"
        ext.write_text("host bytes")
        (bundle / "trace.jsonl").symlink_to(ext)
        return {"trace.jsonl": _sha(b"host bytes")}

    result = _verify_files_bundle(tmp_path, setup)
    assert result.ok is False
    assert "path_escape" in {f.reason_code for f in result.failures}
