"""tests/test_extension_receipt_exit_code.py — a PRESENT-but-UNVERIFIED extension
receipt must not ride a green exit code.

An extension_receipt with no registered handler in this build is NOT_EVALUATED:
the claim is present in the (integrity-checked) manifest but the verifier could
NOT conclude on it. Per ADR D8 the CLI gates this as ERROR / exit 2
("could not conclude"), the same class as a claimed-but-NOT-RUN re-derivation —
NOT exit 0 with a prose caveat, which a consumer keying on the exit code would
read as covered (trust laundering; cf. S1 "the verifier itself is forbidden from
short-cutting").

These run main() end-to-end via subprocess so the assertion is on the real
process exit code, not an in-process helper return.

  1. Unknown-kind extension receipt  -> exit 2 + EXTENSION_RECEIPT_NOT_EVALUATED
  2. No extension receipts (control) -> exit 0 (the gate is specific, not a
     blanket non-zero on every bundle)
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[1]


def _write_bundle(tmp_path: Path, *, extension_receipts: dict | None) -> Path:
    """Minimal integrity-clean bundle; optionally inject extension_receipts."""
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    corpus_dir = bundle_dir / "corpus"
    corpus_dir.mkdir()
    content = b"synthetic corpus entry for extension-receipt exit-code test"
    (corpus_dir / "entry0.txt").write_bytes(content)
    file_sha = hashlib.sha256(content).hexdigest()

    manifest = {
        "schema_version": "legacy",
        "bundle_id": "ext-receipt-exit-test",
        "created_at": "2026-01-01T00:00:00Z",
        "files": {"corpus/entry0.txt": file_sha},
        "spec_files": {},
        "cross_refs": {},
        "payload": {},
        "typed_checks": [],
        "per_output_manifests": [],
    }
    if extension_receipts is not None:
        manifest["extension_receipts"] = extension_receipts
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return bundle_dir


def _run_cli(bundle_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(_PKG_ROOT / "veriker" / "cli" / "verify.py"),
            "--bundle-dir",
            str(bundle_dir),
        ],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )


def test_unknown_extension_receipt_is_could_not_conclude(tmp_path: Path) -> None:
    bundle_dir = _write_bundle(
        tmp_path,
        extension_receipts={"some_unregistered_kind": {"opaque": "assembly"}},
    )
    result = _run_cli(bundle_dir)
    assert result.returncode == 2, (
        f"Expected exit 2 (could-not-conclude) for a present-but-unverified "
        f"extension receipt; got {result.returncode}\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    assert "EXTENSION_RECEIPT_NOT_EVALUATED" in result.stderr, result.stderr


def test_no_extension_receipts_stays_green(tmp_path: Path) -> None:
    # Control: the gate is specific. A bundle with no extension receipts (and
    # nothing else wrong) verifies clean at exit 0.
    bundle_dir = _write_bundle(tmp_path, extension_receipts=None)
    result = _run_cli(bundle_dir)
    assert result.returncode == 0, (
        f"Expected exit 0 for a clean bundle with no extension receipts; got "
        f"{result.returncode}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
