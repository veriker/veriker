"""DSSE PAE (Pre-Authentication Encoding) preimage builder.

Pure stdlib — NO import of `cryptography`, `jcs`, or `rfc8785`.

Specification
-------------
PAE is defined by the in-toto Dead Simple Signing Envelope (DSSE) spec
(https://github.com/in-toto/dsse/blob/master/spec.md) and used by
securesystemslib as the canonical reference implementation:

    PAE(type, body) = "DSSEv1" SP DEC(LEN(type)) SP type SP DEC(LEN(body)) SP body

where:
  - SP is a single ASCII space byte (0x20).
  - LEN(x) is the number of *bytes* in x (UTF-8 encoded for text).
  - DEC(n) is the ASCII decimal representation of the integer n.
  - "type" (payloadType) is the UTF-8 encoding of the payload-type URI,
    with no BOM and no trailing NUL.
  - "body" (payload) is the raw bytes of the payload.
  - The output is bytes; there is no trailing newline.

kid derivation
--------------
    kid = base64url_nopad(sha256(raw32))

where `raw32` is the *raw 32-byte* Ed25519 public key (NOT SPKI/DER/JWK/PEM).
Only the bare 32-byte key material is hashed — no prefix, no encoding wrapper.

payloadType normalization
-------------------------
The envelope payloadType comparison is bytewise-exact over UTF-8 NFC.  Call
`payload_type_nfc(s)` before storing or comparing a payloadType string.
URI normalization (scheme-case, percent-encoding) is NOT performed here; the
caller supplies a canonical URI.

Import safety
-------------
This module imports only: base64, hashlib, unicodedata.
Importing `cryptography`, `jcs`, or `rfc8785` is FORBIDDEN in this file.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import unicodedata

__all__ = [
    "pae",
    "b64url_nopad_encode",
    "b64url_nopad_decode",
    "kid_from_raw32",
    "payload_type_nfc",
]

# The DSSE framing prefix, exactly as specified.
_DSSE_PREFIX: bytes = b"DSSEv1"
_SP: bytes = b" "


def pae(payload_type: str, payload: bytes) -> bytes:
    """Build the DSSE PAE preimage bytes.

    Parameters
    ----------
    payload_type:
        The payloadType URI string.  Must be non-empty.  The byte length of
        its UTF-8 encoding is used in the framing (NOT the character count).
        Callers should normalize to NFC first via ``payload_type_nfc``.
    payload:
        The raw payload bytes.  May be empty.

    Returns
    -------
    bytes
        The PAE preimage:
        ``DSSEv1 <len(type_bytes)> <type_bytes> <len(payload)> <payload>``
        with no trailing newline.

    Raises
    ------
    ValueError
        If ``payload_type`` is empty.

    Examples
    --------
    >>> # From the DSSE spec / securesystemslib reference test suite:
    >>> pae("http://example.com/HelloWorld", b"hello world")
    b'DSSEv1 29 http://example.com/HelloWorld 11 hello world'
    """
    if not payload_type:
        raise ValueError("payload_type must not be empty")

    type_bytes: bytes = payload_type.encode("utf-8")
    len_type: bytes = str(len(type_bytes)).encode("ascii")
    len_body: bytes = str(len(payload)).encode("ascii")

    return (
        _DSSE_PREFIX
        + _SP
        + len_type
        + _SP
        + type_bytes
        + _SP
        + len_body
        + _SP
        + payload
    )


def b64url_nopad_encode(b: bytes) -> str:
    """Encode bytes as base64url with no padding characters ('=').

    Uses ``base64.urlsafe_b64encode`` then strips trailing '=' characters.

    Parameters
    ----------
    b:
        The bytes to encode.

    Returns
    -------
    str
        The base64url-encoded string without any '=' padding.
    """
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64url_nopad_decode(s: str) -> bytes:
    """Decode a base64url string that has no padding characters.

    Parameters
    ----------
    s:
        A base64url-encoded string with no '=' padding.

    Returns
    -------
    bytes
        The decoded bytes.

    Raises
    ------
    ValueError
        If the string length is invalid (would require more than 1 padding
        character beyond what base64url's standard padding demands, which
        indicates a corrupt or truncated input).

        Specifically, a remainder of 1 when ``len(s) % 4 == 1`` is always
        invalid in base64 (no valid 4-byte group can produce a 1-character
        leftover after stripping padding).
    binascii.Error
        If the string contains characters outside the base64url alphabet.
    """
    remainder = len(s) % 4
    if remainder == 1:
        raise ValueError(
            f"Invalid base64url-nopad string: length {len(s)} has remainder 1 "
            "mod 4, which is never valid in base64."
        )
    # Strict: reject any character outside the base64url alphabet. The stdlib
    # urlsafe_b64decode does NOT validate — it silently discards non-alphabet
    # characters, so two distinct sidecar strings could decode to identical
    # bytes (envelope malleability) and the docstring's strict-parse promise
    # would be a lie. Validate explicitly before re-padding.
    if re.fullmatch(r"[A-Za-z0-9_-]*", s) is None:
        raise binascii.Error(
            "Invalid base64url-nopad string: contains characters outside the "
            "base64url alphabet [A-Za-z0-9_-]."
        )
    # Re-pad to a multiple of 4 for the stdlib decoder.
    padding = (4 - remainder) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


def kid_from_raw32(pubkey_raw32: bytes) -> str:
    """Derive the key ID (kid) for a raw 32-byte Ed25519 public key.

    Specification
    -------------
    ``kid = base64url_nopad(sha256(raw32))``

    The preimage is the **raw 32-byte** key material only — NOT SPKI, NOT
    DER, NOT JWK, NOT PEM.  No prefix or encoding wrapper is included.

    This is the canonical kid derivation used by the DSSE v0.4 envelope:
    the full public key lives in the C18-distributed allowlist; the envelope
    header carries only this fingerprint, avoiding embedding raw key material
    in a public header.

    Parameters
    ----------
    pubkey_raw32:
        The raw 32-byte Ed25519 public key.  Must be exactly 32 bytes.

    Returns
    -------
    str
        The kid string: base64url-no-pad encoding of sha256(pubkey_raw32).

    Raises
    ------
    ValueError
        If ``pubkey_raw32`` is not exactly 32 bytes.
    """
    if len(pubkey_raw32) != 32:
        raise ValueError(
            f"pubkey_raw32 must be exactly 32 bytes; got {len(pubkey_raw32)}"
        )
    digest = hashlib.sha256(pubkey_raw32).digest()
    return b64url_nopad_encode(digest)


def payload_type_nfc(s: str) -> str:
    """Normalize a payloadType string to Unicode NFC form.

    Envelope payloadType comparison is bytewise-exact over UTF-8 NFC.  Two
    strings that are canonically equivalent under Unicode (e.g. NFD 'e' +
    combining-acute vs NFC precomposed 'é') will differ at the byte level
    unless normalized.  This function ensures the NFC-normalized form is
    used consistently.

    URI normalization (scheme case, percent-encoding normalization) is NOT
    performed.  The caller must supply a canonical URI before normalization.

    Parameters
    ----------
    s:
        The payloadType string to normalize.

    Returns
    -------
    str
        The NFC-normalized form of ``s``.

    Examples
    --------
    >>> # NFD 'e' + combining acute (2 code points) → NFC 'é' (1 code point):
    >>> payload_type_nfc('application/te\\u0301st') == 'application/tést'
    True
    """
    return unicodedata.normalize("NFC", s)
