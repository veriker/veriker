"""audit_bundle/vkernel_key_loader.py — Ed25519 key indirection for DSSE sealing.

Substrate-tier (open) module that bridges the environment-based key distribution
model (C18) to the cryptography.hazmat Ed25519 types consumed by
``audit_bundle.dsse.envelope.sign_envelope``.

Public surface
--------------
KeyLoaderError
    Raised (fail-closed) on absent, malformed, or wrong-size key material.

load_signing_key(*, env_var) -> Ed25519PrivateKey
    Read a 32-byte Ed25519 seed from an environment variable.
    Accepts **base64url-no-pad** (e.g. ``AAEC...``) OR **lowercase hex**
    (e.g. ``0001...``).  Exactly 32 bytes of seed material must decode.
    Raises KeyLoaderError on absent env var, wrong encoding, or wrong length.

signing_key_from_seed(seed32) -> Ed25519PrivateKey
    Construct a key from a raw 32-byte seed — test-injection helper so that
    tests can inject a deterministic key without touching the environment.

load_pinned_allowlist(*, env_var) -> dict[str, bytes]
    Load the C18-distributed ``{kid: pubkey_raw32}`` verifier allowlist.
    The env var must contain a JSON object mapping kid strings to
    **base64url-no-pad** encoded 32-byte public keys, e.g.::

        {"<kid>": "<b64url-nopad pubkey_raw32>"}

    The allowlist is injected by the caller; it is NEVER bundle-resident.
    Raises KeyLoaderError on absent env var, JSON parse failure, or any
    entry that fails to decode to exactly 32 bytes.

Key format contract
-------------------
``VKERNEL_DSSE_SIGNING_KEY`` (default env var for load_signing_key):
    A 32-byte Ed25519 seed encoded as either:
      * **base64url-no-pad** — URL-safe base64 without ``=`` padding
        (``[A-Za-z0-9_-]{43}``), OR
      * **lowercase hex** — 64 lower-case hex characters.
    Both encodings produce exactly 32 seed bytes.  The loader tries
    base64url first, then hex; an ambiguous 64-char lowercase hex string
    that is also valid base64url will be interpreted as base64url.
    To force hex, ensure the value is 64 characters of ``[0-9a-f]``.

``VKERNEL_DSSE_ALLOWLIST`` (default env var for load_pinned_allowlist):
    A JSON object: ``{"<kid>": "<b64url-nopad-pubkey_raw32>", ...}``.
    Each value must decode to exactly 32 bytes.  Intended for tests and
    C18-orchestrated injection (e.g. mounted from a secret store); not
    for manual human editing.

OSS boundary
------------
This module imports ``cryptography`` — that is intentional and load-bearing
(the key type is the ``Ed25519PrivateKey`` produced here).  It does NOT
import anything from ``audit_bundle.emitter_premium``.
"""

from __future__ import annotations

import base64
import json
import os
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

if TYPE_CHECKING:
    pass  # No extra imports needed for type hints here.

__all__ = [
    "KeyLoaderError",
    "load_signing_key",
    "load_pinned_allowlist",
    "signing_key_from_seed",
]

# ---------------------------------------------------------------------------
# Error type.
# ---------------------------------------------------------------------------


class KeyLoaderError(Exception):
    """Raised when key material is absent, malformed, or the wrong size.

    Always fail-closed: the DSSE seal step is disabled until a valid key
    is provided rather than silently producing an unsigned sidecar.
    """


# ---------------------------------------------------------------------------
# Internal seed-decode helpers (one source-of-truth, mirrors verifier_signing).
# ---------------------------------------------------------------------------


def _decode_seed(raw: str) -> bytes:
    """Decode a 32-byte Ed25519 seed from a base64url-no-pad or hex string.

    Tries base64url first (non-padded URL-safe base64), then lowercase hex.
    Raises ``KeyLoaderError`` if neither decoding yields exactly 32 bytes.
    """
    raw = raw.strip()
    # --- Try base64url-no-pad first. ---
    # A 32-byte value encodes to exactly 43 base64url chars (ceil(32*8/6) = 43).
    # We attempt decode regardless of length to produce a good error message.
    try:
        # Re-add padding for stdlib decoder.
        padding = (4 - len(raw) % 4) % 4
        candidate = base64.urlsafe_b64decode(raw + "=" * padding)
        if len(candidate) == 32:
            return candidate
    except Exception:
        pass

    # --- Try lowercase hex (64 chars). ---
    if len(raw) == 64 and all(c in "0123456789abcdef" for c in raw):
        return bytes.fromhex(raw)

    raise KeyLoaderError(
        f"Cannot decode Ed25519 seed: expected base64url-no-pad (43 chars → 32 bytes) "
        f"or lowercase hex (64 chars → 32 bytes); got {len(raw)!r}-char string."
    )


def _decode_pubkey_raw32(raw_b64: str, kid: str) -> bytes:
    """Decode a 32-byte public key from a base64url-no-pad string in the allowlist."""
    try:
        padding = (4 - len(raw_b64) % 4) % 4
        candidate = base64.urlsafe_b64decode(raw_b64 + "=" * padding)
    except Exception as exc:
        raise KeyLoaderError(
            f"Allowlist entry for kid {kid!r}: base64url decode failed: {exc}"
        ) from exc
    if len(candidate) != 32:
        raise KeyLoaderError(
            f"Allowlist entry for kid {kid!r}: expected 32 bytes after decode; "
            f"got {len(candidate)} bytes."
        )
    return candidate


# ---------------------------------------------------------------------------
# Public API.
# ---------------------------------------------------------------------------


def signing_key_from_seed(seed32: bytes) -> Ed25519PrivateKey:
    """Construct an Ed25519 private key from a raw 32-byte seed.

    This is the test-injection helper — callers that have a deterministic
    seed in hand (e.g. tests using a fixed ``b'\\x01' * 32``) use this
    function directly rather than going through the environment.

    Parameters
    ----------
    seed32:
        Exactly 32 bytes of Ed25519 seed material.

    Returns
    -------
    Ed25519PrivateKey
        The corresponding ``cryptography`` private key object.

    Raises
    ------
    KeyLoaderError
        If ``seed32`` is not exactly 32 bytes.
    """
    if not isinstance(seed32, (bytes, bytearray)):
        raise KeyLoaderError("seed32 must be bytes or bytearray")
    if len(seed32) != 32:
        raise KeyLoaderError(
            f"Ed25519 seed must be exactly 32 bytes; got {len(seed32)} bytes."
        )
    return Ed25519PrivateKey.from_private_bytes(bytes(seed32))


def load_signing_key(
    *,
    env_var: str = "VKERNEL_DSSE_SIGNING_KEY",
) -> Ed25519PrivateKey:
    """Read an Ed25519 signing key from an environment variable.

    The env var must contain a 32-byte seed encoded as either
    base64url-no-pad (43 chars) or lowercase hex (64 chars).
    This is the single source-of-truth for env-based key loading;
    all error paths raise ``KeyLoaderError`` (fail-closed).

    Parameters
    ----------
    env_var:
        Name of the environment variable to read.
        Default: ``VKERNEL_DSSE_SIGNING_KEY``.

    Returns
    -------
    Ed25519PrivateKey

    Raises
    ------
    KeyLoaderError
        If the env var is absent/empty, cannot be decoded, or does not
        yield exactly 32 bytes of seed material.
    """
    raw = os.environ.get(env_var)
    if not raw:
        raise KeyLoaderError(
            f"Missing or empty environment variable {env_var!r}; "
            "an Ed25519 seed (base64url-no-pad or hex, 32 bytes) is required "
            "for DSSE bundle sealing."
        )
    try:
        seed32 = _decode_seed(raw)
    except KeyLoaderError:
        raise
    except Exception as exc:
        raise KeyLoaderError(
            f"Failed to decode Ed25519 seed from {env_var!r}: {exc}"
        ) from exc
    return signing_key_from_seed(seed32)


def load_pinned_allowlist(
    *,
    env_var: str = "VKERNEL_DSSE_ALLOWLIST",
) -> dict[str, bytes]:
    """Load the C18-distributed DSSE allowlist from an environment variable.

    The env var must contain a JSON object whose keys are kid strings and
    whose values are base64url-no-pad-encoded 32-byte Ed25519 public keys::

        {"<kid>": "<b64url-nopad pubkey_raw32>", ...}

    The allowlist is **never** bundle-resident; it is injected by the
    caller from a C18-controlled distribution channel (e.g. a mounted
    secret, CI environment variable, or operator config).  Every value
    must decode to exactly 32 bytes.

    Parameters
    ----------
    env_var:
        Name of the environment variable to read.
        Default: ``VKERNEL_DSSE_ALLOWLIST``.

    Returns
    -------
    dict[str, bytes]
        ``{kid: pubkey_raw32}`` mapping.

    Raises
    ------
    KeyLoaderError
        If the env var is absent/empty, the value is not valid JSON, it is
        not a JSON object, or any value fails to decode to exactly 32 bytes.
    """
    raw = os.environ.get(env_var)
    if not raw:
        raise KeyLoaderError(
            f"Missing or empty environment variable {env_var!r}; "
            "a JSON allowlist {{kid: b64url_pubkey_raw32}} is required "
            "for DSSE bundle verification."
        )

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise KeyLoaderError(
            f"Environment variable {env_var!r} is not valid JSON: {exc}"
        ) from exc

    if not isinstance(parsed, dict):
        raise KeyLoaderError(
            f"Environment variable {env_var!r} must be a JSON object "
            f"{{kid: b64url_pubkey_raw32}}; got {type(parsed).__name__}."
        )

    result: dict[str, bytes] = {}
    for kid, raw_b64 in parsed.items():
        if not isinstance(raw_b64, str):
            raise KeyLoaderError(
                f"Allowlist entry for kid {kid!r}: value must be a base64url string; "
                f"got {type(raw_b64).__name__}."
            )
        result[kid] = _decode_pubkey_raw32(raw_b64, kid)

    return result
