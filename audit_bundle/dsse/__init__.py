"""audit_bundle.dsse — pure, crypto-free DSSE preimage layer.

This package MUST remain importable by a stdlib-only offline tool.  It has
NO import of `cryptography`, `jcs`, or `rfc8785`.  The signing/envelope
layer (WS-1b) wraps this package and may import `cryptography`.

Public API
----------
pae(payload_type, payload) -> bytes
    Build the DSSE PAE (Pre-Authentication Encoding) preimage.

b64url_nopad_encode(b) -> str
b64url_nopad_decode(s) -> bytes
    Base64url helpers with no padding characters.

kid_from_raw32(pubkey_raw32) -> str
    Compute kid = base64url_nopad(sha256(raw32)) for a 32-byte Ed25519 pubkey.

payload_type_nfc(s) -> str
    Normalize a payloadType string to Unicode NFC form.

VERSION_MAP
    Compile-time constant: dsse_envelope_version -> (envelope_pae, manifest_canon).

canonicalization_for(version) -> tuple[str, str]
    Look up the canonicalization tuple for a version; raises on unknown version.
"""

from audit_bundle.dsse.pae import (
    b64url_nopad_decode,
    b64url_nopad_encode,
    kid_from_raw32,
    pae,
    payload_type_nfc,
)
from audit_bundle.dsse.version_map import VERSION_MAP, canonicalization_for

__all__ = [
    "pae",
    "b64url_nopad_encode",
    "b64url_nopad_decode",
    "kid_from_raw32",
    "payload_type_nfc",
    "VERSION_MAP",
    "canonicalization_for",
]
