"""Host-side container-image digest verification for the audit-bundle verifier.

Wrapper around `cosign manifest` + `crane digest` that verifies the running
verifier image's identity from the HOST, outside any compromised container
runtime. A malicious container runtime (e.g. a tampered containerd / dockerd
runtime API sitting below the verifier's trust boundary) can return a spoofed
self-reported digest, so the in-container self-check is treated as a logging-
only tripwire signal. The actual trust mechanism is this host-side comparison
of the registry-reported digest (via cosign + crane) against the expected
digest pinned in the TUF-fetched release manifest.

Status (v0.1.0, pre-ceremony) — READ THIS BEFORE RELYING ON THE PASS BELOW:
the C18 TUF roots shipped in this tree are still synthetic (bootstrap root with
empty signatures + ``TBD-*`` placeholder digests) and no hardware-signed release
has been cut, so the host-side PASS flow below is NOT yet runnable end-to-end
against a genuine release — the TUF fetch fail-closes (exit 4) on the bootstrap
root. This wrapper becomes live at the C18 key ceremony + first signed release.
The shipped, working verifier today is the offline ``veriker/cli/verify.py`` (bundle
validity); this host-side identity check is the future ceremony deliverable.
See SECURITY.md -> "Verifier-identity trust boundary (C18)".

User-facing output deliberately avoids asserting trust via the in-container
self-check (the self-check is a signal, not a verdict); the strings below are
phrased as 'Reported' vs 'Official' and PASS / DIVERGENCE:

  - 'Reported (cosign): sha256:<...>'
  - 'Reported (crane):  sha256:<...>'
  - 'Official (TUF):     sha256:<...>'
  - 'HOST-SIDE DIGEST VERIFICATION: PASS — running image identity bound to
     TUF-pinned release manifest'
  - 'DIVERGENCE — investigate.' on mismatch

This is the consumer-side host wrapper. The substrate TUF client it invokes
is not stdlib-only; this wrapper drives it via subprocess against the cosign +
crane binaries, which are user prerequisites provisioned by the consumer
environment.

Exit codes:
  0 — match
  2 — any pair differs (cosign vs crane vs TUF)
  3 — cosign or crane missing on PATH
  4 — TUF fetch failed / release manifest unavailable
  5 — STH gossip structural divergence detected (--sth-gossip extension)
  6 — STH gossip requested but could NOT be cryptographically verified
      (structural pre-check only; signature/witness verification is v0.4)
  7 — Rekor inclusion verification requested (--rekor-bundle) and FAILED, or
      could not be cryptographically evaluated (fail-closed)
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess  # noqa: S404 — invoked only against cosign + crane binaries
import sys
from pathlib import Path

# Default image registry pin (the published verifier image repository).
DEFAULT_IMAGE_REPO = "ghcr.io/nexiverify/veriker"

EXIT_OK = 0
EXIT_DIGEST_MISMATCH = 2
EXIT_PREREQ_MISSING = 3
EXIT_TUF_FETCH_FAILED = 4
EXIT_STH_GOSSIP_FAILED = 5
EXIT_STH_GOSSIP_NOT_VERIFIED = 6
EXIT_REKOR_INCLUSION_FAILED = 7


def _which(binary: str) -> str | None:
    """Locate `binary` on PATH; return None if absent."""
    return shutil.which(binary)


def _run_cosign_manifest(cosign: str, image_tag: str) -> tuple[bool, str, str]:
    """Run `cosign manifest <image_tag>`; return (ok, digest_or_empty, stderr).

    cosign manifest emits the JSON OCI manifest; we extract the manifest's
    SHA-256 digest from the registry-side `Docker-Content-Digest` header
    or from cosign's output line `Digest: sha256:...`.
    """
    try:
        result = subprocess.run(  # noqa: S603
            [cosign, "manifest", image_tag],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return False, "", str(exc)
    if result.returncode != 0:
        return False, "", result.stderr
    # cosign manifest emits the manifest JSON to stdout. Some cosign versions
    # also emit the digest on a header line. Try both.
    for line in result.stdout.splitlines():
        if line.startswith("Digest:") and "sha256:" in line:
            return True, line.split("sha256:", 1)[1].strip().split()[0].rstrip(), ""
        if line.startswith("sha256:"):
            return True, line.strip(), ""
    # Fall back: hash the manifest JSON itself (this is what crane digest does).
    # We don't reimplement that here — return failure with a useful message.
    return (
        False,
        "",
        "cosign manifest output did not contain a 'Digest:' or 'sha256:' line",
    )


def _run_crane_digest(crane: str, image_tag: str) -> tuple[bool, str, str]:
    """Run `crane digest <image_tag>`; return (ok, digest_or_empty, stderr).

    crane digest emits the content-addressed image digest to stdout (single
    line: `sha256:<hex>`).
    """
    try:
        result = subprocess.run(  # noqa: S603
            [crane, "digest", image_tag],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return False, "", str(exc)
    if result.returncode != 0:
        return False, "", result.stderr
    digest = result.stdout.strip()
    if digest.startswith("sha256:") and len(digest) == 7 + 64:
        return True, digest, ""
    return False, "", f"crane digest returned unexpected output: {digest!r}"


def _fetch_tuf_expected_digest(release: str, trust_dir: Path) -> tuple[bool, str, str]:
    """Fetch the expected OCI image digest via the substrate TUF client.

    Returns (ok, digest_or_empty, err). The substrate-verifier path is not
    stdlib-only — this wrapper accepts that dependency boundary.
    """
    try:
        from audit_bundle.extensions.c18_tuf_client import (
            TUFClientError,
            fetch_release_manifest,
        )
    except ImportError as exc:
        return (
            False,
            "",
            f"substrate TUF client unavailable: {exc}",
        )
    try:
        result = fetch_release_manifest(
            release_version=release,
            trust_dir=trust_dir,
        )
    except TUFClientError as exc:
        return False, "", f"TUF fetch failed: {exc}"
    except Exception as exc:  # noqa: BLE001 — surface any unexpected error
        return False, "", f"TUF fetch unexpected error: {exc}"

    # MANIFEST.txt is a text key=value file; parse for image_digest.
    target_path = result.get("target_path")
    if not target_path or not Path(target_path).is_file():
        return False, "", "TUF target file missing"
    try:
        content = Path(target_path).read_text(encoding="utf-8")
    except OSError as exc:
        return False, "", f"cannot read TUF target: {exc}"
    for line in content.splitlines():
        if line.startswith("image_digest="):
            digest = line.split("=", 1)[1].strip()
            if digest.startswith("sha256:") and len(digest) == 7 + 64:
                return True, digest, ""
    return False, "", "TUF release manifest does not contain image_digest=sha256:<...>"


def _print_side_by_side(
    cosign_digest: str,
    crane_digest: str,
    tuf_digest: str,
    *,
    match: bool,
) -> None:
    """Render the side-by-side Reported/Official digest comparison.

    User-facing language is consistently 'Reported' / 'Official' / 'PASS' /
    'DIVERGENCE' so the output never asserts trust via the in-container
    self-check.
    """
    print(f"Reported (cosign): {cosign_digest or '(unavailable)'}")
    print(f"Reported (crane):  {crane_digest or '(unavailable)'}")
    print(f"Official (TUF):    {tuf_digest or '(unavailable)'}")
    if match:
        print()
        print(
            "HOST-SIDE DIGEST VERIFICATION: PASS — running image identity "
            "bound to TUF-pinned release manifest"
        )
    else:
        print()
        print("DIVERGENCE — investigate.", file=sys.stderr)


def _check_sth_gossip_structure(
    sth_gossip_path: Path,
    *,
    release: str,
    trust_dir: Path,
) -> tuple[list[str], bool, str]:
    """Run the STH-gossip structural pre-check.

    Returns (reason_codes, cryptographically_verified, err).

    IMPORTANT: ``cryptographically_verified`` is always False at v0.3 — the
    underlying helper performs no signature/witness/consistency cryptographic
    verification (see c18_tuf_client.check_sth_gossip_structure). This wrapper
    has no inclusion-proof source wired, so it passes an empty proof and the
    helper runs the signature-PRESENCE check only. An empty reason-set therefore
    means "no structural divergence detected", NOT "verified" — the caller
    must surface that distinction and must not report a cryptographic PASS.
    """
    try:
        from audit_bundle.extensions.c18_tuf_client import check_sth_gossip_structure  # type: ignore[attr-defined]
    except ImportError:
        # Extension absent: we verified nothing. Report not-verified, no err.
        return [], False, "check_sth_gossip_structure extension not available"

    try:
        sth_json = json.loads(sth_gossip_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [], False, f"cannot read gossiped STH at {sth_gossip_path}: {exc}"

    # No bundle rekor_inclusion_proof is available to this host wrapper, so the
    # structural cross-check is skipped and only the signature-presence shape
    # check runs. This is NOT cryptographic verification.
    try:
        result = check_sth_gossip_structure(sth_json, {})
    except Exception as exc:  # noqa: BLE001
        return [], False, f"check_sth_gossip_structure raised: {exc}"
    return list(result.reasons), bool(result.cryptographically_verified), ""


def _verify_rekor_inclusion(rekor_bundle_path: Path) -> tuple[bool, list[str], str]:
    """Cryptographically verify the release's Rekor transparency-log inclusion.

    Consumes the cosign ``.sigstore-bundle.json`` (the
    ``application/vnd.dev.sigstore.bundle.v0.3+json`` format emitted by the
    release sigstore-sign job), extracts its embedded Rekor tlog entry, and runs
    BOTH real legs (``audit_bundle.extensions.rekor_anchor.verify_anchor``):

      1. re-derive the RFC 6962 inclusion proof for the entry's canonicalized
         body — binds the logged leaf to the checkpoint's root; AND
      2. verify the checkpoint's ECDSA P-256 signature against the PINNED
         ``rekor.sigstore.dev`` log key and bind that signed root to the proof
         root — only this leg ties the root to Rekor's genuine tree head.

    Returns ``(ok, reasons, err)``. ``ok`` is True ONLY when BOTH legs pass.
    This is the consumer-side crypto lane (deferred import of ``cryptography``-
    bearing ``rekor_anchor``), kept off the stdlib-only core per the two-verifier
    boundary. A missing extension or a malformed bundle returns ``ok=False`` with
    a non-empty ``err`` — fail-closed, never a silent pass.
    """
    try:
        from audit_bundle.extensions.rekor_anchor import (
            RekorAnchorError,
            load_rekor_log_public_key,
            rekor_anchor_from_sigstore_bundle,
            verify_anchor,
        )
    except ImportError as exc:
        return False, [], f"rekor_anchor extension unavailable ({exc})"

    try:
        bundle = json.loads(rekor_bundle_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return False, [], f"cannot read sigstore bundle at {rekor_bundle_path}: {exc}"

    try:
        anchor, leaf_preimage = rekor_anchor_from_sigstore_bundle(bundle)
        rekor_key = load_rekor_log_public_key()
        verdict = verify_anchor(anchor, leaf_preimage, rekor_log_pubkey=rekor_key)
    except RekorAnchorError as exc:
        return False, [], f"malformed Rekor anchor: {exc}"

    return verdict.ok, list(verdict.reasons), ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Host-side digest verification for v-kernel-audit-bundle. "
            "This is the actual trust mechanism for verifier identity; the "
            "in-container self-check is a tripwire signal only."
        ),
    )
    parser.add_argument(
        "--release",
        required=True,
        help="Release version, e.g. v0.3.0",
    )
    parser.add_argument(
        "--tuf-trust-bundle",
        type=Path,
        required=True,
        dest="trust_dir",
        help="Path to local TUF trust dir (contains bundled root.json)",
    )
    parser.add_argument(
        "--image-repo",
        default=DEFAULT_IMAGE_REPO,
        help=("OCI image repo (default: ghcr.io/nexiverify/veriker)."),
    )
    parser.add_argument(
        "--sth-gossip",
        type=Path,
        default=None,
        help=(
            "Optional path to a gossiped STH JSON. When provided, the verifier "
            "additionally cross-checks the bundle's Rekor inclusion proof "
            "against the gossiped STH."
        ),
    )
    parser.add_argument(
        "--rekor-bundle",
        type=Path,
        default=None,
        help=(
            "Optional path to the release's cosign .sigstore-bundle.json. When "
            "provided, the verifier cryptographically re-derives the release "
            "entry's RFC 6962 Rekor inclusion proof and verifies the log "
            "checkpoint signature against the pinned rekor.sigstore.dev key "
            "(fail-closed; exit 7 on failure)."
        ),
    )
    args = parser.parse_args(argv)

    image_tag = f"{args.image_repo}:{args.release}"

    # Locate cosign + crane.
    cosign = _which("cosign")
    crane = _which("crane")
    if cosign is None or crane is None:
        missing = [b for b, p in [("cosign", cosign), ("crane", crane)] if p is None]
        print(
            f"ERROR: required binaries missing on PATH: {missing}. "
            f"Install per receipts.vkernel.dev/c18_install_prereqs.md.",
            file=sys.stderr,
        )
        return EXIT_PREREQ_MISSING

    # Run cosign manifest.
    cosign_ok, cosign_digest, cosign_err = _run_cosign_manifest(cosign, image_tag)
    if not cosign_ok:
        print(f"ERROR: cosign manifest failed: {cosign_err}", file=sys.stderr)
        return EXIT_DIGEST_MISMATCH

    # Run crane digest.
    crane_ok, crane_digest, crane_err = _run_crane_digest(crane, image_tag)
    if not crane_ok:
        print(f"ERROR: crane digest failed: {crane_err}", file=sys.stderr)
        return EXIT_DIGEST_MISMATCH

    # Fetch TUF expected digest.
    tuf_ok, tuf_digest, tuf_err = _fetch_tuf_expected_digest(
        args.release,
        args.trust_dir,
    )
    if not tuf_ok:
        print(f"ERROR: TUF fetch failed: {tuf_err}", file=sys.stderr)
        _print_side_by_side(cosign_digest, crane_digest, "", match=False)
        return EXIT_TUF_FETCH_FAILED

    # Normalize digests for comparison (cosign may emit 'sha256:' prefix or
    # bare hex; crane always emits 'sha256:' prefix).
    def _norm(d: str) -> str:
        return d if d.startswith("sha256:") else f"sha256:{d}"

    c_norm = _norm(cosign_digest)
    cr_norm = _norm(crane_digest)
    t_norm = _norm(tuf_digest)

    match = c_norm == cr_norm == t_norm
    _print_side_by_side(c_norm, cr_norm, t_norm, match=match)

    if not match:
        return EXIT_DIGEST_MISMATCH

    # Optional STH gossip cross-check.
    if args.sth_gossip is not None:
        reasons, crypto_verified, sth_err = _check_sth_gossip_structure(
            args.sth_gossip,
            release=args.release,
            trust_dir=args.trust_dir,
        )
        if reasons:
            # A real structural divergence was detected.
            print(
                f"ERROR: STH-gossip structural divergence detected: "
                f"reasons={reasons} err={sth_err}",
                file=sys.stderr,
            )
            return EXIT_STH_GOSSIP_FAILED
        if not crypto_verified:
            # No divergence found, but nothing was cryptographically verified.
            # Do NOT report a PASS — that would launder an unverified state
            # through exit 0. Surface the unverified status and exit non-zero
            # because the user explicitly requested the gossip check.
            detail = f" ({sth_err})" if sth_err else ""
            print(
                "STH-gossip: NOT CRYPTOGRAPHICALLY VERIFIED — structural "
                "pre-check only; no signature, witness co-signature, or "
                "consistency-proof verification is performed at v0.3"
                f"{detail}. No structural divergence was detected.",
                file=sys.stderr,
            )
            return EXIT_STH_GOSSIP_NOT_VERIFIED
        print("STH-gossip cross-check: VERIFIED")

    # Optional Rekor transparency-log inclusion verification (real, cryptographic).
    if args.rekor_bundle is not None:
        rekor_ok, rekor_reasons, rekor_err = _verify_rekor_inclusion(args.rekor_bundle)
        if rekor_err:
            # Could not evaluate (extension absent / unreadable bundle). Do NOT
            # launder an unverified state through exit 0 — the user asked for it.
            print(
                f"Rekor inclusion: NOT VERIFIED — {rekor_err}. Fail-closed: the "
                "release entry's transparency-log inclusion could not be "
                "cryptographically checked.",
                file=sys.stderr,
            )
            return EXIT_REKOR_INCLUSION_FAILED
        if not rekor_ok:
            print(
                f"Rekor inclusion: FAILED — reasons={rekor_reasons}. The release "
                "entry is NOT provably included in the transparency log under the "
                "pinned rekor.sigstore.dev log key.",
                file=sys.stderr,
            )
            return EXIT_REKOR_INCLUSION_FAILED
        print(
            "Rekor inclusion cross-check: VERIFIED — release entry included in the "
            "Sigstore transparency log (RFC 6962 inclusion proof re-derived) and "
            "the log checkpoint is signed by the pinned rekor.sigstore.dev key"
        )

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
