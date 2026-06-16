"""DSSE v0.4 envelope: Ed25519 sign/verify over the DSSE PAE preimage.

This module is the **only** place in the dsse package that imports
``cryptography``.  The pure preimage layer (pae.py, version_map.py) and the
strict header parser (header.py) are intentionally crypto-free.

Public surface
--------------
sign_envelope(payload_bytes, signing_key, *, payload_type) -> dict
    Build and sign a DSSE sidecar dict (ready to JSON-serialise to
    ``bundle.dsse.json``).

verify_envelope(raw_sidecar_bytes, allowlist, *, payload_type) -> VerifyEnvelopeResult
    Parse, validate and verify a ``bundle.dsse.json`` sidecar.  Always
    returns a structured result; never raises on malformed input.

VerifyEnvelopeResult
    Frozen dataclass: ok, reason_code, payload_bytes, kid, detail.

PINNED_URI
    The locked payloadType URI for the v0.4 envelope seam.

Locked envelope seam (v0.4)
----------------------------
Sidecar JSON shape:
    {
        "payloadType": "https://vkernel.dev/types/bundle.v1",
        "payload":     "<base64url-no-pad(payload_bytes)>",
        "signatures":  [{"keyid": "<kid>", "sig": "<base64url-no-pad(sig)>"}]
    }

PAE preimage: pae(payloadType, payload_bytes)
Signature: Ed25519 over PAE bytes (EdDSA / COSE alg -8 pin; never serialised).
kid: kid_from_raw32(pubkey_raw32) — sha256 of raw 32-byte public key, b64url.
allowlist: caller-injected Mapping[kid -> pubkey_raw32] (C18-distributed).
Exactly one signature in every produced/verified sidecar.

Rejection codes (VerifyEnvelopeResult.reason_code when ok=False)
-----------------------------------------------------------------
DSSE_MALFORMED_ENVELOPE   — JSON parse error or structural violation
DSSE_HEADER_DUPLICATE_KEY — duplicate JSON key
DSSE_HEADER_UNKNOWN_FIELD — unknown top-level or signature field
DSSE_PAYLOADTYPE_MISMATCH — payloadType does not match pinned URI
DSSE_MULTIPLE_SIGNATURES  — sidecar carries != 1 signature
DSSE_SIGNATURE_INVALID    — sig bytes fail Ed25519 verify (or 0 sigs)
DSSE_UNKNOWN_KID          — kid not in allowlist
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from audit_bundle.dsse.header import (
    DSSE_HEADER_DUPLICATE_KEY,
    DSSE_HEADER_UNKNOWN_FIELD,
    DSSE_MALFORMED_ENVELOPE,
    DSSE_PAYLOADTYPE_MISMATCH,
    DSSEHeaderError,
    parse_strict_envelope,
)
from audit_bundle.dsse.pae import (
    b64url_nopad_decode,
    b64url_nopad_encode,
    kid_from_raw32,
    pae,
    payload_type_nfc,
)

__all__ = [
    "sign_envelope",
    "verify_envelope",
    "VerifyEnvelopeResult",
    "PINNED_URI",
    # Re-export rejection codes for callers who import from here.
    "DSSE_MALFORMED_ENVELOPE",
    "DSSE_HEADER_DUPLICATE_KEY",
    "DSSE_HEADER_UNKNOWN_FIELD",
    "DSSE_PAYLOADTYPE_MISMATCH",
    "DSSE_MULTIPLE_SIGNATURES",
    "DSSE_SIGNATURE_INVALID",
    "DSSE_UNKNOWN_KID",
]

# ---------------------------------------------------------------------------
# Pinned payloadType URI.
# ---------------------------------------------------------------------------

PINNED_URI: str = payload_type_nfc("https://vkernel.dev/types/bundle.v1")

# Additional rejection codes (envelope-layer, not header-layer).
DSSE_MULTIPLE_SIGNATURES: str = "DSSE_MULTIPLE_SIGNATURES"
DSSE_SIGNATURE_INVALID: str = "DSSE_SIGNATURE_INVALID"
DSSE_UNKNOWN_KID: str = "DSSE_UNKNOWN_KID"


# ---------------------------------------------------------------------------
# Structured verify result.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerifyEnvelopeResult:
    """Result of verify_envelope().

    Attributes
    ----------
    ok:
        True iff the envelope passed all validation and the signature verified.
    reason_code:
        Machine-readable rejection code (one of the DSSE_* constants), or
        None when ok=True.
    payload_bytes:
        The decoded payload bytes when ok=True; None on failure.
    kid:
        The key-id of the verifying signer when ok=True; None on failure.
    detail:
        Human-readable description of the outcome (always populated).
    """

    ok: bool
    reason_code: str | None
    payload_bytes: bytes | None
    kid: str | None
    detail: str


# ---------------------------------------------------------------------------
# Sign.
# ---------------------------------------------------------------------------


def sign_envelope(
    payload_bytes: bytes,
    signing_key: Ed25519PrivateKey,
    *,
    payload_type: str = PINNED_URI,
) -> dict:  # type: ignore[type-arg]
    """Build and sign a DSSE v0.4 sidecar envelope dict.

    Parameters
    ----------
    payload_bytes:
        The raw payload bytes (e.g. RFC 8785 canonical JSON of the manifest
        claim set).  Must be non-empty.
    signing_key:
        An ``Ed25519PrivateKey`` (from ``cryptography``).
    payload_type:
        The payloadType URI.  Defaults to the pinned v0.4 URI.  The value is
        NFC-normalised before use.

    Returns
    -------
    dict
        A Python dict ready to be serialised to ``bundle.dsse.json``::

            {
                "payloadType": "<uri>",
                "payload":     "<base64url-no-pad(payload_bytes)>",
                "signatures":  [{"keyid": "<kid>", "sig": "<base64url-no-pad(sig)>"}]
            }

    Raises
    ------
    ValueError
        If ``payload_bytes`` is empty.
    """
    if not payload_bytes:
        raise ValueError("payload_bytes must not be empty")

    pt = payload_type_nfc(payload_type)

    # Build PAE preimage and sign.
    preimage: bytes = pae(pt, payload_bytes)
    sig_bytes: bytes = signing_key.sign(preimage)

    # Derive kid from raw public-key material.
    pub: Ed25519PublicKey = signing_key.public_key()
    pubkey_raw32: bytes = pub.public_bytes_raw()
    kid: str = kid_from_raw32(pubkey_raw32)

    return {
        "payloadType": pt,
        "payload": b64url_nopad_encode(payload_bytes),
        "signatures": [
            {
                "keyid": kid,
                "sig": b64url_nopad_encode(sig_bytes),
            }
        ],
    }


# ---------------------------------------------------------------------------
# Verify.
# ---------------------------------------------------------------------------


def verify_envelope(
    raw_sidecar_bytes: bytes,
    allowlist: Mapping[str, bytes],
    *,
    payload_type: str = PINNED_URI,
) -> VerifyEnvelopeResult:
    """Parse, validate, and cryptographically verify a DSSE sidecar.

    The verification pipeline is ordered: each step only runs if the
    previous step passed.  The function NEVER raises on malformed input;
    every error path returns a VerifyEnvelopeResult with ok=False.

    Parameters
    ----------
    raw_sidecar_bytes:
        The raw bytes of ``bundle.dsse.json``.
    allowlist:
        Mapping of ``kid -> pubkey_raw32`` (the C18-distributed pinned
        allowlist).  The allowlist is never bundle-resident; it is injected
        by the caller.
    payload_type:
        The payloadType URI to pin.  Defaults to the v0.4 pinned URI.

    Returns
    -------
    VerifyEnvelopeResult
        Always returned (never raises).  Check ``.ok``.

    Rejection codes (reason_code when ok=False)
    -------------------------------------------
    DSSE_MALFORMED_ENVELOPE   — JSON / structural error
    DSSE_HEADER_DUPLICATE_KEY — duplicate JSON key
    DSSE_HEADER_UNKNOWN_FIELD — unknown envelope/signature field
    DSSE_PAYLOADTYPE_MISMATCH — payloadType mismatch
    DSSE_MULTIPLE_SIGNATURES  — not exactly one signature (incl. zero)
    DSSE_UNKNOWN_KID          — kid not found in allowlist
    DSSE_SIGNATURE_INVALID    — Ed25519 verification failure or 0 sigs
    """
    pt = payload_type_nfc(payload_type)

    # ------------------------------------------------------------------
    # Step 1: Strict header parse.
    # ------------------------------------------------------------------
    try:
        envelope = parse_strict_envelope(raw_sidecar_bytes)
    except DSSEHeaderError as exc:
        return VerifyEnvelopeResult(
            ok=False,
            reason_code=exc.code,
            payload_bytes=None,
            kid=None,
            detail=exc.detail,
        )

    # ------------------------------------------------------------------
    # Step 2: Exactly one signature.
    # ------------------------------------------------------------------
    n_sigs = len(envelope.signatures)
    if n_sigs == 0:
        # parse_strict_envelope already rejects empty signatures list,
        # but be defensive.
        return VerifyEnvelopeResult(
            ok=False,
            reason_code=DSSE_SIGNATURE_INVALID,
            payload_bytes=None,
            kid=None,
            detail="Envelope carries zero signatures",
        )
    if n_sigs > 1:
        return VerifyEnvelopeResult(
            ok=False,
            reason_code=DSSE_MULTIPLE_SIGNATURES,
            payload_bytes=None,
            kid=None,
            detail=f"Envelope carries {n_sigs} signatures; exactly 1 is required",
        )

    sig_entry = envelope.signatures[0]

    # ------------------------------------------------------------------
    # Step 3: kid must be in the allowlist.
    # ------------------------------------------------------------------
    kid = sig_entry.keyid
    if kid not in allowlist:
        return VerifyEnvelopeResult(
            ok=False,
            reason_code=DSSE_UNKNOWN_KID,
            payload_bytes=None,
            kid=None,
            detail=f"kid {kid!r} is not in the allowlist",
        )

    pubkey_raw32 = allowlist[kid]

    # ------------------------------------------------------------------
    # Step 4: Decode payload bytes.
    # ------------------------------------------------------------------
    try:
        payload_bytes = b64url_nopad_decode(envelope.payload_bytes_b64)
    except Exception as exc:
        return VerifyEnvelopeResult(
            ok=False,
            reason_code=DSSE_MALFORMED_ENVELOPE,
            payload_bytes=None,
            kid=None,
            detail=f"Failed to decode payload base64url: {exc}",
        )

    # ------------------------------------------------------------------
    # Step 5: Ed25519 verify over PAE(payloadType, payload_bytes).
    # ------------------------------------------------------------------
    try:
        sig_bytes = b64url_nopad_decode(sig_entry.sig)
    except Exception as exc:
        return VerifyEnvelopeResult(
            ok=False,
            reason_code=DSSE_SIGNATURE_INVALID,
            payload_bytes=None,
            kid=None,
            detail=f"Failed to decode sig base64url: {exc}",
        )

    preimage = pae(pt, payload_bytes)

    try:
        pub = Ed25519PublicKey.from_public_bytes(pubkey_raw32)
    except (ValueError, TypeError) as exc:
        return VerifyEnvelopeResult(
            ok=False,
            reason_code=DSSE_SIGNATURE_INVALID,
            payload_bytes=None,
            kid=None,
            detail=f"Cannot construct Ed25519 public key from allowlist entry: {exc}",
        )

    try:
        pub.verify(sig_bytes, preimage)
    except InvalidSignature:
        return VerifyEnvelopeResult(
            ok=False,
            reason_code=DSSE_SIGNATURE_INVALID,
            payload_bytes=None,
            kid=None,
            detail="Ed25519 signature verification failed",
        )
    except Exception as exc:
        return VerifyEnvelopeResult(
            ok=False,
            reason_code=DSSE_SIGNATURE_INVALID,
            payload_bytes=None,
            kid=None,
            detail=f"Ed25519 verify raised unexpected error: {exc}",
        )

    # ------------------------------------------------------------------
    # Success.
    # ------------------------------------------------------------------
    return VerifyEnvelopeResult(
        ok=True,
        reason_code=None,
        payload_bytes=payload_bytes,
        kid=kid,
        detail="Signature verified",
    )
