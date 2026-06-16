"""C18 — Verifier supply chain.

Establishes the supply-chain identity of the verifier release itself, so a
consumer can confirm the verifier they ran is the one the publisher built and
released. The release ships:
  - Hermetic Nix-flake CI (apko/melange/Wolfi documented fallback)
  - CycloneDX SBOM from the Nix derivation
  - A Sigstore bundle carrying offline Rekor inclusion-proof material in the
    artifact tree
  - SLSA-3 provenance (SLSA L4 honestly deferred to a later release)
  - A SCITT-statement-shaped release manifest with a fail-closed payload_type
    validator
  - A TUF-distributed trust bundle (a separate `sigstore-trust-root` TUF role,
    following the Sigstore BYO-TUF convention)
  - python-tuf >= 6.0 vendored at compile time
  - An offline-only verifier extending the existing verify.py
  - A self-check tripwire plugin (logging-only signal, NEVER a trust assertion)
  - A 4-step consumer verification UX hosted at receipts.vkernel.dev
  - A subtree-split mirror script + release workflow (release-tag-only cadence)
  - STH-gossip that observes an existing public Rekor monitor

Fulcio claim policy: the keyless release signature is verified against the
release workflow identity (SAN) and the GitHub-Actions OIDC issuer
'https://token.actions.githubusercontent.com', pinned to the release tag and
commit SHA.

Scope boundary: this work is PRE-DSSE. DSSE envelope wrapping and SCITT
receipts are later substrate work, not shipped here. The "stdlib-only" framing
applies ONLY to the offline-only verify.py tool, NOT to the substrate verifier
(which takes JCS + crypto + python-tuf deps).


"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Literal, TypedDict


# =============================================================================
# TRIPWIRE-VS-TRUST-ASSERTION CONSTANT (load-bearing)
# =============================================================================

#: Module-level constant read by external-copy linting that guards against
#: overclaim. The in-container self-check is a LOGGING-ONLY signal. Trust
#: assertion is HOST-SIDE via cosign manifest / crane digest reading the
#: TUF-fetched expected digest (veriker/cli/host_digest_verify.py).
TRIPWIRE_IS_NOT_TRUST_ASSERTION = True


# =============================================================================
# VerifierIdentity TypedDict (bundle.evidence.verifier_identity shape)
# =============================================================================


class VerifierIdentity(TypedDict, total=False):
    """C18 verifier_identity block — bundle.evidence.verifier_identity shape.

    `total=False` because legacy (pre-C18) bundles omit the block entirely; the
    structural verifier (verify_verifier_identity_structural below) handles
    that case with a clean PASS (no reason codes).

    Field semantics:

      verifier_release_id        — semver string, e.g. 'v0.3.0'
      verifier_oci_digest        — canonical identity primitive 'sha256:<64hex>'
      verifier_self_check_status — TRIPWIRE signal, NOT a trust assertion.
                                   Values: 'passed', 'failed', 'skipped'.
                                   Unknown values fail with
                                   VerifierSelfCheckUnknownStatus — the verifier
                                   refuses to silently accept a status it does
                                   not recognize (mode-from-producer hardening).
      release_manifest_url       — where the release manifest is published
      release_manifest_hash      — sha256 of the manifest at verification time
      scitt_statement_hash       — hash of the SCITT-statement-shaped release
                                   manifest
      sigstore_bundle_hash       — hash of the Sigstore bundle shipped with
                                   the release
      rekor_inclusion_proof      — INLINE inclusion proof; the consumer verifies
                                   offline against the bundled proof body.
                                   Shape: dict with
                                   {leaf_index, tree_size, hashes, root_hash}.
    """

    verifier_release_id: str
    verifier_oci_digest: str
    verifier_self_check_status: Literal["passed", "failed", "skipped"]
    release_manifest_url: str
    release_manifest_hash: str
    scitt_statement_hash: str
    sigstore_bundle_hash: str
    rekor_inclusion_proof: dict


# =============================================================================
# Exception classes (caught + reason-code-emitted by the tripwire plugin)
# =============================================================================


class VerifierIdentityError(Exception):
    """Base class for all verifier_identity structural errors."""


class VerifierIdentityFieldMissing(VerifierIdentityError):
    """Required field absent from bundle.evidence.verifier_identity."""


class VerifierIdentityOCIDigestMalformed(VerifierIdentityError):
    """`verifier_oci_digest` does not match 'sha256:<64hex>' shape."""


class VerifierIdentityRekorInclusionProofMalformed(VerifierIdentityError):
    """`rekor_inclusion_proof` malformed — missing required keys, wrong types,
    or non-hex root_hash."""


class VerifierIdentityReleaseManifestMismatch(VerifierIdentityError):
    """`release_manifest_hash` does not match recomputation against bundled
    release_manifest.json (when file present)."""


class VerifierSelfCheckUnknownStatus(VerifierIdentityError):
    """`verifier_self_check_status` value outside {'passed', 'failed', 'skipped'}.
    Mode-from-producer hardening — the verifier refuses to silently accept a
    status it does not recognize."""


# =============================================================================
# Reason codes (emitted by the tripwire plugin)
# =============================================================================


REASON_FIELD_MISSING = "VERIFIER_IDENTITY_FIELD_MISSING"
REASON_OCI_DIGEST_MALFORMED = "VERIFIER_IDENTITY_OCI_DIGEST_MALFORMED"
REASON_REKOR_INCLUSION_PROOF_MALFORMED = (
    "VERIFIER_IDENTITY_REKOR_INCLUSION_PROOF_MALFORMED"
)
REASON_RELEASE_MANIFEST_MISMATCH = "VERIFIER_IDENTITY_RELEASE_MANIFEST_MISMATCH"
REASON_SELF_CHECK_UNKNOWN_STATUS = "VERIFIER_SELF_CHECK_UNKNOWN_STATUS"


_OCI_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_ALLOWED_SELF_CHECK_STATUS = frozenset({"passed", "failed", "skipped"})

# Required field names in the verifier_identity block. The schema lists 8
# fields, all optional in the TypedDict (legacy bundles omit the entire block);
# however when the block IS present, each field below is required.
_REQUIRED_FIELDS_WHEN_PRESENT = (
    "verifier_release_id",
    "verifier_oci_digest",
    "verifier_self_check_status",
    "release_manifest_url",
    "release_manifest_hash",
    "scitt_statement_hash",
    "sigstore_bundle_hash",
    "rekor_inclusion_proof",
)

# Required keys in the rekor_inclusion_proof body.
_REQUIRED_REKOR_KEYS = ("leaf_index", "tree_size", "hashes", "root_hash")


# =============================================================================
# verify_verifier_identity_structural()
# =============================================================================


def verify_verifier_identity_structural(
    bundle_dir: Path,
    manifest: object,
) -> list[str]:
    """Structural-integrity check on bundle.evidence.verifier_identity.

    NO network. NO TUF fetch. Returns a list of reason codes — empty list
    means PASS. Does NOT raise on failure (the caller — the veriker/cli/verify.py
    extension OR audit_bundle/verifier.py in the substrate plugin path —
    decides fail-vs-warn shape).

    Validates:
      - field shapes per TypedDict (presence of all 8 fields when the block
        is present at all)
      - verifier_oci_digest matches 'sha256:<64hex>' shape
      - rekor_inclusion_proof structural shape (presence of {leaf_index,
        tree_size, hashes, root_hash}; leaf_index + tree_size are ints;
        hashes is list of str; root_hash is hex string)
      - release_manifest_hash matches a recomputation against
        bundle_dir/release_manifest.json if the file is present (relaxed
        skip if file absent — legacy bundles)
      - verifier_self_check_status ∈ {'passed', 'failed', 'skipped'}
        (mode-from-producer hardening)

    Does NOT validate (host-side / TUF-side / cosign-side):
      - OCI digest matches a TUF-fetched expected digest (host-side, via
        veriker/cli/host_digest_verify.py)
      - Sigstore bundle signature verifies (cosign-side)
      - SLSA provenance binds to the correct commit-SHA (slsa-verifier-side)

    Reason codes emitted:
      VERIFIER_IDENTITY_FIELD_MISSING
      VERIFIER_IDENTITY_OCI_DIGEST_MALFORMED
      VERIFIER_IDENTITY_REKOR_INCLUSION_PROOF_MALFORMED
      VERIFIER_IDENTITY_RELEASE_MANIFEST_MISMATCH
      VERIFIER_SELF_CHECK_UNKNOWN_STATUS
    """
    reasons: list[str] = []

    # Locate the verifier_identity block on the manifest. We accept either
    # attribute access (`manifest.evidence.verifier_identity`) or dict
    # navigation depending on which shape the substrate verifier hands us.
    block = _extract_verifier_identity_block(manifest)
    if block is None:
        # Legacy / pre-C18 bundle — no block present. Clean PASS.
        return reasons

    # 1. All required fields present when the block IS present.
    for field in _REQUIRED_FIELDS_WHEN_PRESENT:
        if field not in block:
            reasons.append(f"{REASON_FIELD_MISSING}:{field}")

    if reasons:
        # If basics are missing, skip the deeper structural checks (would
        # double-fail on missing-field reason codes).
        return reasons

    # 2. OCI digest shape.
    oci = block.get("verifier_oci_digest", "")
    if not isinstance(oci, str) or not _OCI_DIGEST_PATTERN.match(oci):
        reasons.append(REASON_OCI_DIGEST_MALFORMED)

    # 3. Rekor inclusion proof — STRUCTURAL SHAPE ONLY.
    # This validates that rekor_inclusion_proof carries the expected keys/types
    # (leaf_index:int, tree_size:int, hashes:list[str], root_hash:hex). It does
    # NOT verify the proof: no Merkle-inclusion fold of the leaf against
    # root_hash, no signed-tree-head (STH) consistency compare, no freshness.
    # A shape-valid proof here is NOT cryptographic evidence of log inclusion;
    # real Rekor inclusion verification is performed out-of-band by the
    # receipts.vkernel.dev consumer flow (cosign verify-blob + monitor) and is a
    # later roadmap item. Do not present this check as
    # "transparency-log inclusion verified."
    proof = block.get("rekor_inclusion_proof")
    if not isinstance(proof, dict):
        reasons.append(REASON_REKOR_INCLUSION_PROOF_MALFORMED)
    else:
        for key in _REQUIRED_REKOR_KEYS:
            if key not in proof:
                reasons.append(REASON_REKOR_INCLUSION_PROOF_MALFORMED)
                break
        else:
            if not (
                isinstance(proof.get("leaf_index"), int)
                and isinstance(proof.get("tree_size"), int)
                and isinstance(proof.get("hashes"), list)
                and all(isinstance(h, str) for h in proof.get("hashes", []))
                and isinstance(proof.get("root_hash"), str)
                and _is_hex(proof.get("root_hash", ""))
            ):
                reasons.append(REASON_REKOR_INCLUSION_PROOF_MALFORMED)

    # 4. verifier_self_check_status ∈ allowed values (mode-from-producer hardening).
    status = block.get("verifier_self_check_status")
    if status not in _ALLOWED_SELF_CHECK_STATUS:
        reasons.append(REASON_SELF_CHECK_UNKNOWN_STATUS)

    # 5. Release manifest hash recomputation (when the file is bundled).
    release_manifest_path = bundle_dir / "release_manifest.json"
    if release_manifest_path.is_file():
        try:
            actual_hash = _file_sha256(release_manifest_path)
            declared = block.get("release_manifest_hash", "")
            if declared != f"sha256:{actual_hash}" and declared != actual_hash:
                reasons.append(REASON_RELEASE_MANIFEST_MISMATCH)
        except OSError:
            # Cannot read — treat as mismatch to fail-CLOSED.
            reasons.append(REASON_RELEASE_MANIFEST_MISMATCH)

    return reasons


# =============================================================================
# self_check_tripwire()
# =============================================================================


def self_check_tripwire(
    running_oci_digest: str | None,
    bundled_oci_digest: str,
) -> dict[str, object]:
    """Logging-only tripwire signal.

    Returns a dict with shape:

      {
        'reported_digest': <str | None>,       # what the running container said
        'official_digest': <str>,              # what the bundle says is canonical
        'divergence':      <bool>,              # True iff reported != official
        'note':            <str>,               # human-readable explanation
      }

    The CALLER (the veriker/cli/verify.py extension, OR the tripwire plugin) is
    responsible for LOGGING the divergence as a VERIFIER_IDENTITY_DIVERGENCE
    event in the bundle event log.

    This function NEVER decides trust. The TRIPWIRE_IS_NOT_TRUST_ASSERTION
    constant at module top is the linting beacon for the external-copy
    overclaim sweep.

    Actual trust assertion is HOST-SIDE (cosign manifest / crane digest
    against the TUF-fetched expected digest; veriker/cli/host_digest_verify.py). The
    in-container self-check is a SIGNAL surfacing identity divergence into the
    bundle log; consumers use the 4-step receipts.vkernel.dev flow to derive
    trust.
    """
    if running_oci_digest is None:
        return {
            "reported_digest": None,
            "official_digest": bundled_oci_digest,
            "divergence": False,
            "note": (
                "Running OCI digest unavailable — tripwire signal SKIPPED. "
                "This is NOT a trust assertion either way; consumer-side "
                "host digest verification (veriker/cli/host_digest_verify.py) is "
                "the actual trust mechanism."
            ),
        }
    divergence = running_oci_digest != bundled_oci_digest
    if divergence:
        note = (
            "Reported running digest does NOT match bundled official "
            "digest. TRIPWIRE FIRED — investigate via 4-step consumer "
            "flow. This is NOT proof of compromise OR of integrity on "
            "its own."
        )
    else:
        note = (
            "Reported running digest matches bundled official digest. "
            "Tripwire is GREEN — but this is NOT a trust assertion. Run "
            "the 4-step consumer flow at receipts.vkernel.dev to assert "
            "trust."
        )
    return {
        "reported_digest": running_oci_digest,
        "official_digest": bundled_oci_digest,
        "divergence": divergence,
        "note": note,
    }


# =============================================================================
# Helpers
# =============================================================================


def _extract_verifier_identity_block(manifest: object) -> dict | None:
    """Pull bundle.evidence.verifier_identity off `manifest`.

    Handles both attribute-access (BundleManifest dataclass) and dict-access
    (raw JSON bundle manifest) styles. Returns None if the block is absent
    (legacy / pre-C18 bundle).
    """
    # Attribute style.
    evidence = getattr(manifest, "evidence", None)
    if evidence is not None:
        vi = getattr(evidence, "verifier_identity", None)
        if vi is not None:
            return vi if isinstance(vi, dict) else None

    # Dict style.
    if isinstance(manifest, dict):
        evidence = manifest.get("evidence")
        if isinstance(evidence, dict):
            vi = evidence.get("verifier_identity")
            if isinstance(vi, dict):
                return vi

    # Top-level dict-style attribute on bundle.
    vi = getattr(manifest, "verifier_identity", None)
    if isinstance(vi, dict):
        return vi

    return None


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_hex(s: str) -> bool:
    if not isinstance(s, str) or not s:
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


# =============================================================================
# Public surface
# =============================================================================


__all__ = [
    "REASON_FIELD_MISSING",
    "REASON_OCI_DIGEST_MALFORMED",
    "REASON_REKOR_INCLUSION_PROOF_MALFORMED",
    "REASON_RELEASE_MANIFEST_MISMATCH",
    "REASON_SELF_CHECK_UNKNOWN_STATUS",
    "TRIPWIRE_IS_NOT_TRUST_ASSERTION",
    "VerifierIdentity",
    "VerifierIdentityError",
    "VerifierIdentityFieldMissing",
    "VerifierIdentityOCIDigestMalformed",
    "VerifierIdentityRekorInclusionProofMalformed",
    "VerifierIdentityReleaseManifestMismatch",
    "VerifierSelfCheckUnknownStatus",
    "self_check_tripwire",
    "verify_verifier_identity_structural",
]
