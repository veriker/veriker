"""tests/test_verdict_out_artifact.py — the --verdict-out machine-readable face.

`veriker/cli/verify.py --verdict-out PATH` writes the verdict face as JSON so a
consumer never parses console prose or infers coverage from an exit code
alone. The artifact reuses the CANONICAL verdict vocabulary (state / reasons
.code / completeness.layers / completeness.disclosures — same names as
audit_bundle.verdict), plus the CLI-level gates that live outside the library
verdict (DSSE sidecar guard, C18/C19 structural checks, extension receipts,
re-derivation execution posture).

It is an UNSIGNED operational artifact: trust derives from deterministic
re-execution of the verifier, not from this file (per-verdict signing remains
gate-path-only). The `note` field states this so the file cannot be quietly
promoted to a trust object.

Locked here:
  1. Clean bundle      -> exit 0; artifact state=OK, exit_code=0, manifest
                          sha256 matches, canonical verdict embedded.
  2. Unhandled receipt -> exit 2; artifact state=ERROR with
                          EXTENSION_RECEIPT_NOT_EVALUATED in reason_codes and
                          the gate entry present.
  3. DSSE-sealed       -> non-zero; DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO in
                          reason_codes (artifact agrees with the exit code).
  4. Early REJECT      -> artifact is still written (missing manifest.json).
  5. No flag (control) -> no artifact appears.
  6. Artifact/exit-code agreement is exact: artifact.exit_code == process
     exit code on every path above.

Stdlib only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[1]


def _b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _write_bundle(
    tmp_path: Path,
    *,
    extension_receipts: dict | None = None,
    dsse_sealed: bool = False,
) -> Path:
    """Minimal integrity-clean bundle (same shape as the import-boundary and
    extension-receipt exit-code fixtures)."""
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    corpus_dir = bundle_dir / "corpus"
    corpus_dir.mkdir()
    content = b"synthetic corpus entry for verdict-out artifact test"
    (corpus_dir / "entry0.txt").write_bytes(content)

    manifest = {
        "schema_version": "legacy",
        "bundle_id": "verdict-out-artifact-test",
        "created_at": "2026-01-01T00:00:00Z",
        "files": {"corpus/entry0.txt": hashlib.sha256(content).hexdigest()},
        "spec_files": {},
        "cross_refs": {},
        "payload": {},
        "typed_checks": [],
        "per_output_manifests": [],
    }
    if extension_receipts is not None:
        manifest["extension_receipts"] = extension_receipts
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    if dsse_sealed:
        payload = _b64url_nopad(
            json.dumps({"schema_version": "vcp-v1.2-dsse"}).encode("utf-8")
        )
        sidecar = {
            "payloadType": "application/vnd.vkernel.bundle+json",
            "payload": payload,
            "signatures": [{"keyid": "synthetic", "sig": _b64url_nopad(b"\x00" * 64)}],
        }
        (bundle_dir / "bundle.dsse.json").write_text(
            json.dumps(sidecar), encoding="utf-8"
        )
    return bundle_dir


def _run_cli(bundle_dir: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(_PKG_ROOT / "veriker" / "cli" / "verify.py"),
            "--bundle-dir",
            str(bundle_dir),
            *extra,
        ],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )


def test_clean_bundle_artifact_ok(tmp_path: Path) -> None:
    bundle_dir = _write_bundle(tmp_path)
    out = tmp_path / "verdict.json"
    result = _run_cli(bundle_dir, "--verdict-out", str(out))
    assert result.returncode == 0, result.stdout + result.stderr
    face = json.loads(out.read_text(encoding="utf-8"))

    assert face["state"] == "OK"
    assert face["exit_code"] == 0
    assert face["assurance_mode"] == "offline_stdlib"
    assert "Unsigned" in face["note"]
    manifest_sha = hashlib.sha256(
        (bundle_dir / "manifest.json").read_bytes()
    ).hexdigest()
    assert face["input_manifest_sha256"] == manifest_sha
    # Canonical verdict embedded with the canonical vocabulary:
    assert face["verdict"]["state"] == "OK"
    assert "completeness" in face["verdict"]
    # The always-on CLI gates report even on the green path:
    gates = {g["gate"]: g["status"] for g in face["cli_gates"]}
    assert gates.get("dsse_sidecar_guard") == "PASS"
    assert gates.get("c19_cross_host") == "PASS"


def test_unhandled_receipt_artifact_error(tmp_path: Path) -> None:
    bundle_dir = _write_bundle(
        tmp_path,
        extension_receipts={"some_unregistered_kind": {"opaque": "assembly"}},
    )
    out = tmp_path / "verdict.json"
    result = _run_cli(bundle_dir, "--verdict-out", str(out))
    face = json.loads(out.read_text(encoding="utf-8"))

    assert result.returncode == 2, result.stdout + result.stderr
    assert face["exit_code"] == 2
    assert face["state"] == "ERROR"
    assert "EXTENSION_RECEIPT_NOT_EVALUATED" in face["reason_codes"]
    receipt_gates = [
        g for g in face["cli_gates"] if g["gate"].startswith("extension_receipt:")
    ]
    assert receipt_gates and receipt_gates[0]["status"] == "NOT_EVALUATED"


def test_dsse_sealed_artifact_fails_closed(tmp_path: Path) -> None:
    bundle_dir = _write_bundle(tmp_path, dsse_sealed=True)
    out = tmp_path / "verdict.json"
    result = _run_cli(bundle_dir, "--verdict-out", str(out))
    face = json.loads(out.read_text(encoding="utf-8"))

    assert result.returncode != 0, result.stdout + result.stderr
    assert face["exit_code"] == result.returncode
    assert face["state"] in ("REJECT", "ERROR")
    assert "DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO" in face["reason_codes"]


def test_early_reject_still_writes_artifact(tmp_path: Path) -> None:
    # Bundle dir exists but has no manifest.json — the earliest REJECT path.
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    out = tmp_path / "verdict.json"
    result = _run_cli(bundle_dir, "--verdict-out", str(out))
    assert result.returncode == 1
    face = json.loads(out.read_text(encoding="utf-8"))
    assert face["state"] == "REJECT"
    assert face["exit_code"] == 1
    assert "MANIFEST_MISSING" in face["reason_codes"]


def test_no_flag_writes_nothing(tmp_path: Path) -> None:
    bundle_dir = _write_bundle(tmp_path)
    before = set(tmp_path.iterdir())
    result = _run_cli(bundle_dir)
    assert result.returncode == 0
    after = set(tmp_path.iterdir())
    assert before == after, "CLI wrote files without --verdict-out"
