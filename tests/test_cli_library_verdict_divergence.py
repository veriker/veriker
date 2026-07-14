"""tests/test_cli_library_verdict_divergence.py — the CLI-vs-library verdict seam.

Security property under test (red-team ADV-01 + systemic sweep, 2026-06-10):
a direct ``BundleVerifier.verify()`` consumer must reach the SAME verdict the
``veriker/cli/verify.py`` wrapper reaches. Several gates historically lived ONLY in the
CLI wrapper (they mutated ``overall_ok`` / forced exit 2 AFTER ``verify()``
returned), so a library consumer keying on ``result.ok`` / ``VerdictState`` got
a green verdict the CLI would have refused — trust laundering on the verifier's
core properties.

Three instances of the seam, all asserted at the LIBRARY level here:

  #5 re_derivation NOT_EXECUTED   — pack present, not run (safe default). The
     plugin returns ok=True; the CLI gates it to ERROR (exit 2). Library
     consumers MUST also see could-not-conclude (NOT OK).  [== ADV-01]

  #4 extension_receipt NOT_EVALUATED — a receipt of a kind with no registered
     handler is present-but-unverified. CLI gates it ERROR (exit 2). Library
     consumers MUST also see could-not-conclude (NOT OK).

  #3 cross_host_authenticators present — the A1 red-team fix fails closed in the
     CLI when a bundle carries cross-host edges this open tier cannot verify.
     The substrate CC2 cross-check only fires for names *listed in*
     manifest.typed_checks, which an attacker omits. Library consumers MUST also
     fail closed (NOT OK).

These assert the DESIRED post-fix behavior: each is RED until the gate is moved
into the verdict-producing core (BundleVerifier.verify()).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.verdict import VerdictState  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from veriker.cli.verify import _build_plugins, _load_manifest  # noqa: E402

# A clean, OK-passing base bundle with NO re_derive pack — so the only reason a
# verdict turns non-OK in the injection tests below is the field we inject.
from examples.streaming_minimal._build_bundle import build as _build_streaming  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck  # noqa: E402

sys.path.insert(0, str(_PKG_ROOT / "examples" / "streaming_minimal"))
from StreamingReDerivationCheck import StreamingReDerivationCheck  # noqa: E402

_CLIMATE_BUNDLE = _PKG_ROOT / "examples" / "climate_emission_minimal"


def _streaming_plugins() -> list:
    return [SpecShaPinCheck(), FileIntegrityManySmall(), StreamingReDerivationCheck()]


def _rehash_manifest_after_edit(bundle_dir: Path, manifest: dict) -> None:
    """Persist an edited manifest dict (unsealed bundle — no self-hash to fix)."""
    (bundle_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )


def _build_clean_streaming(tmp_path: Path) -> Path:
    bundle_dir = tmp_path / "streaming_bundle"
    _build_streaming(bundle_dir)
    return bundle_dir


# ---------------------------------------------------------------------------
# Baseline: the clean base bundle really does pass OK at the library level.
# (If this regresses, the injection tests below would be meaningless.)
# ---------------------------------------------------------------------------


def test_baseline_clean_streaming_is_ok(tmp_path: Path) -> None:
    bundle_dir = _build_clean_streaming(tmp_path)
    result = BundleVerifier(plugins=_streaming_plugins()).verify(bundle_dir)
    assert result.ok is True, f"base bundle must be OK; failures: {result.failures}"


# ---------------------------------------------------------------------------
# #5 — re_derivation NOT_EXECUTED (== ADV-01)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not _CLIMATE_BUNDLE.is_dir(), reason="climate example bundle absent"
)
def test_library_rederivation_not_executed_is_not_ok() -> None:
    """ADV-01: climate bundle claims re_derivation_invocation; the default
    (safe) path does NOT execute the pack. The CLI returns exit 2 here. A direct
    library verify() must NOT return OK — re-derivation is the core property and
    it was not concluded."""
    manifest = _load_manifest(_CLIMATE_BUNDLE)
    plugins = _build_plugins(_CLIMATE_BUNDLE, manifest, permit_pack_execution=False)
    result = BundleVerifier(plugins=plugins).verify(_CLIMATE_BUNDLE)

    assert result.ok is False, (
        "ADV-01: library verify() returned OK on an UNEXECUTED re-derivation "
        "pack — the CLI gates this to exit 2 but the library verdict launders it"
    )
    # Present-but-unverified is could-not-conclude (ERROR), not REJECT.
    assert result.state is VerdictState.ERROR, (
        f"expected ERROR (could-not-conclude), got {result.state}"
    )


# ---------------------------------------------------------------------------
# #4 — extension_receipt NOT_EVALUATED
# ---------------------------------------------------------------------------


def test_library_unhandled_extension_receipt_is_not_ok(tmp_path: Path) -> None:
    """A receipt of a kind with no registered handler is present-but-unverified.
    The CLI gates it to exit 2; a library verify() must also fail closed."""
    bundle_dir = _build_clean_streaming(tmp_path)
    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    manifest["extension_receipts"] = {
        "totally_unregistered_kind": {"claim": "trust me", "sig": "AAAA"}
    }
    _rehash_manifest_after_edit(bundle_dir, manifest)

    result = BundleVerifier(plugins=_streaming_plugins()).verify(bundle_dir)
    assert result.ok is False, (
        "library verify() returned OK on a present-but-UNVERIFIED extension "
        "receipt (no handler) — laundering, the CLI returns exit 2"
    )
    assert result.state is VerdictState.ERROR, (
        f"expected ERROR (could-not-conclude), got {result.state}"
    )


# ---------------------------------------------------------------------------
# #3 — cross_host_authenticators present (A1 red-team fix is CLI-only)
# ---------------------------------------------------------------------------


def test_library_cross_host_edges_fail_closed(tmp_path: Path) -> None:
    """A1: a bundle carrying cross_host_authenticators edges this open tier
    cannot verify must fail closed. The CLI hard-FAILs (no opt-out); the substrate
    CC2 cross-check only fires for names listed in manifest.typed_checks (which an
    attacker omits). A library verify() must NOT return OK."""
    bundle_dir = _build_clean_streaming(tmp_path)
    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    cc = manifest.get("causal_chain")
    if not isinstance(cc, dict):
        cc = {}
    cc["cross_host_authenticators"] = [
        {
            "from_host": "attacker-chosen-a",
            "to_host": "attacker-chosen-b",
            "cose_sign1": "ZmFrZQ==",
            "ack": "never-produced",
        }
    ]
    manifest["causal_chain"] = cc
    _rehash_manifest_after_edit(bundle_dir, manifest)

    result = BundleVerifier(plugins=_streaming_plugins()).verify(bundle_dir)
    assert result.ok is False, (
        "library verify() returned OK on a bundle carrying UNVERIFIED cross-host "
        "edges — A1 laundering; the CLI fails closed but the library verdict does not"
    )


# ---------------------------------------------------------------------------
# Durable parity guard: CLI and library must CONVERGE on present-but-unverified
# bundles. This is the regression backstop — if a FUTURE gate is added to
# veriker/cli/verify.py without a core-verdict counterpart, the library leg of one of
# these cases goes OK while the CLI leg stays non-zero, and this fails. It
# generalizes the three holes above into the invariant they all violated.
# ---------------------------------------------------------------------------

import subprocess  # noqa: E402


def _run_cli(bundle_dir: Path, *args: str) -> subprocess.CompletedProcess:
    import os

    return subprocess.run(
        [
            sys.executable,
            str(_PKG_ROOT / "veriker" / "cli" / "verify.py"),
            "--bundle-dir",
            str(bundle_dir),
            *args,
        ],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
        env={**os.environ, "PYTHONPATH": str(_PKG_ROOT)},
    )


def _inject_unhandled_receipt(bundle_dir: Path) -> None:
    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    manifest["extension_receipts"] = {"totally_unregistered_kind": {"claim": "x"}}
    _rehash_manifest_after_edit(bundle_dir, manifest)


def _inject_cross_host(bundle_dir: Path) -> None:
    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    cc = manifest.get("causal_chain")
    cc = cc if isinstance(cc, dict) else {}
    cc["cross_host_authenticators"] = [
        {"from_host": "a", "to_host": "b", "cose_sign1": "ZmFrZQ=="}
    ]
    manifest["causal_chain"] = cc
    _rehash_manifest_after_edit(bundle_dir, manifest)


@pytest.mark.parametrize("inject", [_inject_unhandled_receipt, _inject_cross_host])
def test_cli_and_library_converge_on_present_but_unverified(
    tmp_path: Path, inject
) -> None:
    """For a bundle carrying a present-but-unverified claim, the library verdict
    (result.ok) and the CLI exit code MUST agree on refusal. Catches a future
    CLI-only gate that would re-open the divergence."""
    bundle_dir = _build_clean_streaming(tmp_path)
    inject(bundle_dir)

    lib_ok = BundleVerifier(plugins=_streaming_plugins()).verify(bundle_dir).ok
    cli_rc = _run_cli(bundle_dir).returncode

    assert lib_ok is False, "library leg laundered a present-but-unverified claim to OK"
    assert cli_rc != 0, "CLI leg accepted a present-but-unverified claim"
    # Convergence: neither path certifies (both refuse).
    assert (lib_ok is False) and (cli_rc != 0), (
        f"CLI/library divergence: library.ok={lib_ok}, cli.returncode={cli_rc}"
    )


# ---------------------------------------------------------------------------
# #2 (follow-up, 2026-06-11) — C18 verifier_identity structural gate was
# CLI-only (ARCH-02). Library verify() must REJECT a malformed block at BOTH
# documented locations: the top-level manifest key (the production builder
# path, e.g. eidas) and raw evidence.verifier_identity (the offline-CLI
# extension's documented location). A structurally VALID block must not
# disturb an otherwise-OK verdict.
# ---------------------------------------------------------------------------

_VALID_VERIFIER_IDENTITY = {
    "verifier_release_id": "v0.3.0",
    "verifier_oci_digest": "sha256:" + "a" * 64,
    "verifier_self_check_status": "passed",
    "release_manifest_url": "https://manifest.vkernel.dev/v0.3.0.json",
    "release_manifest_hash": "sha256:" + "0" * 64,
    "scitt_statement_hash": "sha256:" + "1" * 64,
    "sigstore_bundle_hash": "sha256:" + "2" * 64,
    "rekor_inclusion_proof": {
        "leaf_index": 100,
        "tree_size": 200,
        "hashes": ["aa" * 32, "bb" * 32],
        "root_hash": "deadbeef" * 8,
    },
}

# Malformed: all 8 fields present but the OCI digest fails the
# sha256:<64hex> shape — exercises a structural check past field presence.
_MALFORMED_VERIFIER_IDENTITY = {
    **_VALID_VERIFIER_IDENTITY,
    "verifier_oci_digest": "sha256:not-a-digest",
}


def _inject_malformed_vi_toplevel(bundle_dir: Path) -> None:
    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    manifest["verifier_identity"] = dict(_MALFORMED_VERIFIER_IDENTITY)
    _rehash_manifest_after_edit(bundle_dir, manifest)


def _inject_malformed_vi_evidence(bundle_dir: Path) -> None:
    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    manifest["evidence"] = {"verifier_identity": dict(_MALFORMED_VERIFIER_IDENTITY)}
    _rehash_manifest_after_edit(bundle_dir, manifest)


@pytest.mark.parametrize(
    "inject", [_inject_malformed_vi_toplevel, _inject_malformed_vi_evidence]
)
def test_library_malformed_verifier_identity_is_rejected(
    tmp_path: Path, inject
) -> None:
    """ARCH-02: the C18 structural evaluator ran only in veriker/cli/verify.py's
    post-verify() loop, so a library verify() returned OK on a malformed
    verifier_identity block. Core must REJECT (artifact-bad), matching the
    CLI's exit-1 class."""
    bundle_dir = _build_clean_streaming(tmp_path)
    inject(bundle_dir)

    result = BundleVerifier(plugins=_streaming_plugins()).verify(bundle_dir)
    assert result.ok is False, (
        "library verify() returned OK on a MALFORMED verifier_identity block — "
        "the C18 structural gate is still CLI-only (laundering)"
    )
    codes = {r.code for r in result.reasons}
    assert "VERIFIER_IDENTITY_OCI_DIGEST_MALFORMED" in codes, (
        f"expected VERIFIER_IDENTITY_OCI_DIGEST_MALFORMED on the face, got {codes}"
    )


def test_library_valid_verifier_identity_stays_ok(tmp_path: Path) -> None:
    """A structurally valid C18 block must not flip an otherwise-OK bundle —
    the core gate is presence-gated and structural-only (the tripwire
    DISCLOSURE signal stays plugin-side)."""
    bundle_dir = _build_clean_streaming(tmp_path)
    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    manifest["verifier_identity"] = dict(_VALID_VERIFIER_IDENTITY)
    _rehash_manifest_after_edit(bundle_dir, manifest)

    result = BundleVerifier(plugins=_streaming_plugins()).verify(bundle_dir)
    assert result.ok is True, (
        f"valid verifier_identity block flipped an OK bundle: {result.reasons}"
    )


@pytest.mark.parametrize(
    "inject", [_inject_malformed_vi_toplevel, _inject_malformed_vi_evidence]
)
def test_cli_and_library_converge_on_malformed_verifier_identity(
    tmp_path: Path, inject
) -> None:
    """Parity backstop for the C18 gate: library verdict and CLI exit code must
    agree on refusal at both block locations. (Before the fix the TOP-LEVEL
    location escaped BOTH faces: the CLI's auto-on probe read only
    evidence.verifier_identity.)"""
    bundle_dir = _build_clean_streaming(tmp_path)
    inject(bundle_dir)

    lib_ok = BundleVerifier(plugins=_streaming_plugins()).verify(bundle_dir).ok
    cli_rc = _run_cli(bundle_dir).returncode

    assert lib_ok is False, "library leg laundered a malformed verifier_identity"
    assert cli_rc != 0, "CLI leg accepted a malformed verifier_identity"
