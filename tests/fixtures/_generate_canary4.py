"""Canary4 fixture generator for BundleVerifier tamper-detection tests.

Run as a script to materialise fixtures under tests/fixtures/canary4_valid/
and write 5 tampered manifest JSON files alongside it.

    python tests/fixtures/_generate_canary4.py

Import build_canary4_bundle() in pytest fixtures for in-memory construction.
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


# ---------------------------------------------------------------------------
# Fixed payload / spec content (deterministic across runs)
# ---------------------------------------------------------------------------

SPEC_CONTENT: bytes = (
    b"# Example Spec\n\n"
    b"This document defines the canary4 audit-bundle contract.\n"
    b"It is committed to git so that BundleVerifier can use git_blob_resolver\n"
    b"as a verifier-in-a-box fallback when the offline copy is absent.\n"
)

PAYLOAD_CONTENT: bytes = (
    b'{"result": "canary4 output", "status": "ok", "n_samples": 42}\n'
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git(args: list[str], cwd: Path) -> None:
    subprocess.run(["git"] + args, cwd=str(cwd), check=True, capture_output=True)


# ---------------------------------------------------------------------------
# Bundle dataclass
# ---------------------------------------------------------------------------


@dataclass
class CanaryBundle:
    """Paths and metadata for a generated canary4 bundle."""
    bundle_dir: Path
    valid_manifest: dict
    payload_sha: str
    spec_sha: str


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def build_canary4_bundle(
    dest_dir: Path,
    git_repo: Path | None = None,
) -> CanaryBundle:
    """Build a valid canary4 bundle in dest_dir.

    Creates:
      dest_dir/manifest.json        — complete, correct manifest
      dest_dir/payload/output.txt   — payload file
      dest_dir/spec/example_spec.md — offline spec copy

    If git_repo is provided the spec is committed there so that
    git_blob_resolver can serve as a verifier-in-a-box fallback.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    (dest_dir / "payload").mkdir(exist_ok=True)
    (dest_dir / "spec").mkdir(exist_ok=True)

    # Payload
    (dest_dir / "payload" / "output.txt").write_bytes(PAYLOAD_CONTENT)
    payload_sha = _sha256(PAYLOAD_CONTENT)

    # Spec — offline copy inside bundle
    (dest_dir / "spec" / "example_spec.md").write_bytes(SPEC_CONTENT)
    spec_sha = _sha256(SPEC_CONTENT)

    # Optionally commit spec to a git repo for fallback resolution
    if git_repo is not None:
        (git_repo / "spec").mkdir(exist_ok=True)
        (git_repo / "spec" / "example_spec.md").write_bytes(SPEC_CONTENT)
        _git(["add", "spec/example_spec.md"], git_repo)
        _git(["commit", "-m", "canary4: add spec doc for blob-resolver tests"], git_repo)

    valid_manifest: dict = {
        "schema_version": "vcp-v1.1-canary4",
        "bundle_id": "canary4-test-001",
        "created_at": "2026-04-30T00:00:00Z",
        "files": {
            "payload/output.txt": payload_sha,
        },
        "spec_files": {
            "spec/example_spec.md": spec_sha,
        },
        "cross_refs": {
            "main_output": "payload/output.txt",
        },
        "payload": {
            "result": "payload/output.txt",
        },
        "typed_checks": [],
    }
    (dest_dir / "manifest.json").write_text(
        json.dumps(valid_manifest, indent=2), encoding="utf-8"
    )

    return CanaryBundle(
        bundle_dir=dest_dir,
        valid_manifest=valid_manifest,
        payload_sha=payload_sha,
        spec_sha=spec_sha,
    )


# ---------------------------------------------------------------------------
# Tampered manifest factories
# ---------------------------------------------------------------------------


def make_tampered_file_manifest(bundle: CanaryBundle) -> dict:
    """manifest.files carries a wrong SHA for payload/output.txt.

    Attack vector: attacker silently modified the payload bytes; the manifest
    SHA was not updated (still records the original, now-stale hash).
    Detected by: file_integrity / bad_file_sha.
    """
    m = copy.deepcopy(bundle.valid_manifest)
    m["files"]["payload/output.txt"] = "0" * 64
    return m


def make_tampered_spec_substitution_manifest(bundle: CanaryBundle) -> dict:
    """manifest.spec_files carries a different SHA for the spec doc.

    Attack vector: spec was substituted for a different version; the manifest
    spec_files entry was not updated and now points at an absent blob.
    Detected by: spec_sha_pinning / missing_spec_blob.
    """
    m = copy.deepcopy(bundle.valid_manifest)
    m["spec_files"]["spec/example_spec.md"] = "a" * 64
    return m


def make_tampered_cross_ref_manifest(bundle: CanaryBundle) -> dict:
    """cross_refs entry points to a target absent from manifest.files and spec_files.

    Attack vector: cross-reference was edited to point at an unreachable path.
    Detected by: cross_refs / broken_cross_ref.
    """
    m = copy.deepcopy(bundle.valid_manifest)
    m["cross_refs"]["main_output"] = "nonexistent/missing_file.txt"
    return m


def make_tampered_silent_drop_manifest(bundle: CanaryBundle) -> dict:
    """Valid manifest — the attack is silently deleting payload/output.txt from disk.

    The manifest still records the file with its correct SHA, but the file
    is gone.  Tests using this manifest must also remove the file from the
    copied bundle directory.
    Detected by: file_integrity / bad_file_sha (missing-file branch).
    """
    return copy.deepcopy(bundle.valid_manifest)


def make_tampered_sum_invariant_manifest(bundle: CanaryBundle) -> dict:
    """Manifest where coverage row violates n_eligible == n_issued + n_withheld.

    Attack vector: coverage summary was falsified (5 + 3 = 8 ≠ 10).
    Will be detected by: typed_check_plugins:coverage-sum-v1 / plugin_failed.
    Until the coverage-sum-v1 TypedCheck plugin ships (vab-021/022) this
    invariant is NOT enforced and BundleVerifier returns ok=True.
    """
    m = copy.deepcopy(bundle.valid_manifest)
    m["payload"]["coverage_summary"] = {
        "n_eligible": 10,
        "n_issued": 5,
        "n_withheld": 3,  # 5 + 3 = 8 ≠ 10 — invariant violation
    }
    m["typed_checks"] = ["coverage-sum-v1"]
    return m


# ---------------------------------------------------------------------------
# Standalone materialisation
# ---------------------------------------------------------------------------


def generate_all(fixtures_dir: Path) -> CanaryBundle:
    """Write canary4_valid/ bundle and 5 tampered manifest JSON files to fixtures_dir."""
    bundle = build_canary4_bundle(fixtures_dir / "canary4_valid")
    tampered: dict[str, dict] = {
        "tampered_file.json": make_tampered_file_manifest(bundle),
        "tampered_spec_substitution.json": make_tampered_spec_substitution_manifest(bundle),
        "tampered_cross_ref.json": make_tampered_cross_ref_manifest(bundle),
        "tampered_silent_drop.json": make_tampered_silent_drop_manifest(bundle),
        "tampered_sum_invariant.json": make_tampered_sum_invariant_manifest(bundle),
    }
    for filename, manifest in tampered.items():
        (fixtures_dir / filename).write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )
    return bundle


if __name__ == "__main__":
    here = Path(__file__).parent
    b = generate_all(here)
    print(f"Generated canary4 fixtures in {here}")
    print(f"  payload_sha = {b.payload_sha[:16]}...")
    print(f"  spec_sha    = {b.spec_sha[:16]}...")
