"""Regression suite — spec_sha_pinning ambient-git fallback: disclosed + structured.

ChatGPT review follow-up (2026-06-11), two seams in
``BundleVerifier._step_spec_sha_pinning`` (audit_bundle/verifier.py):

1. PROVENANCE was silent. The git fallback is integrity-safe — any blob it
   yields must hash to the manifest-pinned SHA-256 before use, so it cannot
   launder content — but the bytes come from whatever repository
   ``_discover_repo_root`` finds above bundle_dir (ambient verifier-host
   state), not from the bundle the producer shipped. A GREEN verdict through
   that path looked identical to one verified from the bundle's own spec/
   copy. Now: disclosed on the verdict face (Completeness.disclosures),
   absent when the offline copy is used. Disclosed-not-silently-passed.

2. A git subprocess failure ESCAPED. ``resolve_blob_at_sha`` runs the
   history walk with ``check=True``; a corrupt repo raised
   ``subprocess.CalledProcessError`` (and a missing git binary ``OSError``)
   past the step's except clauses — a crash-ERROR whose verdict face named
   neither the spec nor the cause. Now: structured ``git_resolution_error``
   reject, never an escaping exception (§C9 collect-don't-propagate).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from audit_bundle.bundle_manifest import BundleManifest
from audit_bundle.verifier import BundleVerifier, VerifyFailure


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _repo_with_committed_spec(tmp_path: Path) -> tuple[Path, str]:
    """git repo containing one committed spec file; returns (repo, pinned sha)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    spec_bytes = b"# anchored spec text\n"
    (repo / "policy.md").write_bytes(spec_bytes)
    _git(repo, "add", "policy.md")
    _git(
        repo,
        "-c",
        "user.email=t@test",
        "-c",
        "user.name=t",
        "commit",
        "-q",
        "-m",
        "spec",
    )
    return repo, _sha(spec_bytes)


def _unsealed_bundle(bundle_dir: Path, spec_files: dict[str, str]) -> None:
    """Minimal sidecar-absent bundle: one declared file + the given spec pins."""
    bundle_dir.mkdir(parents=True, exist_ok=True)
    data = b"git fallback disclosure payload"
    (bundle_dir / "data.txt").write_bytes(data)
    manifest = {
        "schema_version": "vcp-v1.1-canary4",
        "bundle_id": "spec-git-fallback-test",
        "created_at": "2026-06-11T00:00:00Z",
        "files": {"data.txt": _sha(data)},
        "spec_files": spec_files,
        "cross_refs": {},
    }
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def _manifest_with_spec(spec_path: str, expected_sha: str) -> BundleManifest:
    return BundleManifest(
        schema_version="legacy",
        bundle_id="b",
        created_at="2026-01-01T00:00:00Z",
        files={},
        spec_files={spec_path: expected_sha},
        cross_refs={},
        payload={},
        typed_checks=[],
    )


def _run_step(
    bundle_dir: Path, manifest: BundleManifest
) -> tuple[list[VerifyFailure], list[str]]:
    failures: list[VerifyFailure] = []
    disclosures: list[str] = []
    # Must not raise — §C9 "verify never raises", collect-don't-propagate.
    BundleVerifier()._step_spec_sha_pinning(
        bundle_dir, manifest, failures, disclosures, sealed=False
    )
    return failures, disclosures


# ---------------------------------------------------------------------------
# Seam 1 — provenance disclosure
# ---------------------------------------------------------------------------


def test_git_fallback_pass_is_disclosed_on_verdict_face(tmp_path: Path) -> None:
    """Offline copy absent + blob found in ambient git history: the verdict is
    GREEN (bytes match the pin) but Completeness.disclosures says where the
    bytes came from."""
    repo, pinned = _repo_with_committed_spec(tmp_path)
    bundle_dir = repo / "bundle"
    _unsealed_bundle(bundle_dir, {"policy.md": pinned})

    verdict = BundleVerifier(plugins=()).verify(bundle_dir)

    assert verdict.ok, [(f.reason_code, f.detail) for f in verdict.failures]
    assert any(
        "'policy.md'" in d and "ambient git history" in d
        for d in verdict.completeness.disclosures
    )


def test_offline_copy_pass_is_not_disclosed(tmp_path: Path) -> None:
    """The bundle's own spec/ copy satisfies the pin: no provenance disclosure
    — the disclosure is specific to the ambient-git path."""
    repo, pinned = _repo_with_committed_spec(tmp_path)
    bundle_dir = repo / "bundle"
    bundle_dir.mkdir()
    spec_dir = bundle_dir / "spec"
    spec_dir.mkdir()
    (spec_dir / "policy.md").write_bytes(b"# anchored spec text\n")

    failures, disclosures = _run_step(
        bundle_dir, _manifest_with_spec("policy.md", pinned)
    )

    assert failures == []
    assert disclosures == []


def test_git_fallback_sha_mismatch_still_rejects_without_disclosure(
    tmp_path: Path,
) -> None:
    """A pin no commit satisfies: the failure stands (missing_spec_blob) and
    no provenance disclosure rides a rejected check."""
    repo, _pinned = _repo_with_committed_spec(tmp_path)
    bundle_dir = repo / "bundle"
    bundle_dir.mkdir()
    wrong_pin = _sha(b"bytes never committed")

    failures, disclosures = _run_step(
        bundle_dir, _manifest_with_spec("policy.md", wrong_pin)
    )

    assert [f.reason_code for f in failures] == ["missing_spec_blob"]
    assert disclosures == []


# ---------------------------------------------------------------------------
# Seam 2 — git subprocess failure is a structured reject, not a crash
# ---------------------------------------------------------------------------


def test_corrupt_repo_is_structured_git_resolution_error(tmp_path: Path) -> None:
    """An empty .git directory satisfies _discover_repo_root but every git
    command fails (exit 128). Previously: CalledProcessError escaped the step.
    Now: one structured git_resolution_error naming the spec."""
    (tmp_path / ".git").mkdir()  # discovered as a repo root; not a valid repo
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()

    failures, disclosures = _run_step(
        bundle_dir, _manifest_with_spec("policy.md", _sha(b"whatever"))
    )

    assert [f.reason_code for f in failures] == ["git_resolution_error"]
    assert "'policy.md'" in failures[0].detail
    assert disclosures == []


def test_missing_git_binary_is_structured_git_resolution_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """git binary unavailable on the verifier host: subprocess.run raises
    FileNotFoundError (an OSError) at the resolve seam — structured reject,
    never an escaping exception."""
    import audit_bundle.verifier as verifier_mod

    def _no_git(repo_root: Path, file_path: str, target_sha: str) -> bytes:
        raise FileNotFoundError("No such file or directory: 'git'")

    monkeypatch.setattr(verifier_mod, "resolve_blob_at_sha", _no_git)
    (tmp_path / ".git").mkdir()
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()

    failures, disclosures = _run_step(
        bundle_dir, _manifest_with_spec("policy.md", _sha(b"whatever"))
    )

    assert [f.reason_code for f in failures] == ["git_resolution_error"]
    assert "FileNotFoundError" in failures[0].detail
    assert disclosures == []


# ---------------------------------------------------------------------------
# Seam 3 — sealed bundles never consult ambient git (host-independence)
# ---------------------------------------------------------------------------


def _dsse_ctx_for(key):
    import time
    from types import SimpleNamespace

    from audit_bundle.dsse.pae import kid_from_raw32
    from audit_bundle.revocation import RevocationList

    pub_raw32 = key.public_key().public_bytes_raw()
    now = int(time.time())
    return SimpleNamespace(
        allowlist={kid_from_raw32(pub_raw32): pub_raw32},
        verifier_now=now,
        revocation_list=RevocationList(
            entries={}, issued_at=now, expires=now + 3600, revocation_list_hash=""
        ),
        require_dsse=True,
        allow_legacy=False,
    )


def _sealed_bundle_with_spec(bundle_dir: Path, *, with_offline_copy: bool):
    """Emitter-sealed bundle pinning one spec; optionally re-signed WITHOUT
    its offline copy (the emitter always ships copies, so the no-copy shape
    must be produced the way a non-emitter producer would: sign a payload
    whose files set omits spec/ — manifest pins intact)."""
    import rfc8785
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from audit_bundle.dsse.envelope import PINNED_URI, sign_envelope
    from audit_bundle.dsse.pae import b64url_nopad_decode
    from audit_bundle.emitter.pipeline import BundleContent, write_bundle

    key = Ed25519PrivateKey.generate()
    write_bundle(
        bundle_dir,
        BundleContent(
            bundle_id="sealed-spec-offline-test",
            created_at="2026-06-11T00:00:00Z",
            files={"data/x.txt": b"sealed spec-pin payload"},
            spec_files={"policy.md": b"# anchored spec text\n"},
        ),
        dsse_signing_key=key,
    )
    if not with_offline_copy:
        (bundle_dir / "spec" / "policy.md").unlink()
        (bundle_dir / "spec").rmdir()
        sidecar_path = bundle_dir / "bundle.dsse.json"
        envelope = json.loads(sidecar_path.read_text(encoding="utf-8"))
        payload = json.loads(b64url_nopad_decode(envelope["payload"]))
        payload["files"] = [
            e for e in payload["files"] if not e["path"].startswith("spec/")
        ]
        resigned = sign_envelope(rfc8785.dumps(payload), key, payload_type=PINNED_URI)
        sidecar_path.write_text(
            json.dumps(resigned, ensure_ascii=False), encoding="utf-8"
        )
    return key


def test_sealed_with_signed_offline_copy_is_green_and_undisclosed(
    tmp_path: Path,
) -> None:
    """The emitter-shipped shape: spec copy signed into the DSSE set — GREEN,
    and no ambient-git disclosure (bytes came from the bundle)."""
    bundle_dir = tmp_path / "sealed"
    key = _sealed_bundle_with_spec(bundle_dir, with_offline_copy=True)

    verdict = BundleVerifier(plugins=()).verify(bundle_dir, dsse=_dsse_ctx_for(key))

    assert verdict.ok, [(f.reason_code, f.detail) for f in verdict.failures]
    assert not any("ambient git" in d for d in verdict.completeness.disclosures)


def test_sealed_pin_without_offline_copy_rejects_even_when_git_could_satisfy_it(
    tmp_path: Path,
) -> None:
    """A sealed bundle pinning a spec with no signed offline copy REJECTS —
    even though a repository above bundle_dir holds the exact pinned blob.
    Compliance state must be a function of the bundle, not the verifier host."""
    repo, _pinned = _repo_with_committed_spec(tmp_path)  # matching blob upstairs
    bundle_dir = repo / "sealed"
    key = _sealed_bundle_with_spec(bundle_dir, with_offline_copy=False)

    verdict = BundleVerifier(plugins=()).verify(bundle_dir, dsse=_dsse_ctx_for(key))

    assert not verdict.ok
    assert any(
        f.reason_code == "sealed_spec_offline_copy_missing"
        and "'policy.md'" in f.detail
        for f in verdict.failures
    )
    # The pinned-SHA-equivalent blob was sitting in ambient git and must NOT
    # have been consulted: no provenance disclosure, no GREEN.
    assert not any("ambient git" in d for d in verdict.completeness.disclosures)


def test_unsealed_fallback_disabled_by_policy_is_structured_reject(
    tmp_path: Path,
) -> None:
    """allow_spec_git_fallback=False: an unsealed bundle whose pin git could
    satisfy rejects with spec_git_fallback_disabled — bundle-determined
    verdicts on demand, no host probing."""
    repo, pinned = _repo_with_committed_spec(tmp_path)
    bundle_dir = repo / "bundle"
    _unsealed_bundle(bundle_dir, {"policy.md": pinned})

    verdict = BundleVerifier(plugins=(), allow_spec_git_fallback=False).verify(
        bundle_dir
    )

    assert not verdict.ok
    assert any(
        f.reason_code == "spec_git_fallback_disabled" and "'policy.md'" in f.detail
        for f in verdict.failures
    )
    assert not any("ambient git" in d for d in verdict.completeness.disclosures)
