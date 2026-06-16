"""Ed25519 cryptographic signature verifier for Property 2.

Property 2 (signed artifact present) is implemented as key-cache-backed
Ed25519 verification at v1. Callers register public keys by key_id and
then call verify() with the raw artifact bytes and detached signature bytes.

ECDSA / RSA signature support is W4 scope; v1 supports Ed25519 only.

No network calls. No key fetching from external services at v1. Domain pilots
register their own keys (e.g., a device-mesh pilot registers a synthesized
firmware-key for its mesh integration).

SCOPE (v1) — this is a BUILD-TIME / SDK helper, NOT a core-verdict check. The
generic verifier does not re-run source signatures: `signed_artifact_present`
is a PRODUCER-DECLARED source property, and the verifier-side plugin
(source_attributes_consistency) checks only its structural consistency
(present => a signing_key_id is named), never the cryptographic signature. A
caller wanting the signature to actually constrain provenance must establish
the source_cid<->bytes binding itself — pilots do this via content-addressing
(source_cid = CID(canonical signed bytes), re-checked by snapshot CID
integrity), so the binding holds OUT OF BAND of this verify() rather than
through it. That is why `source_cid` is accepted but unused here at v1.

v2 / W4 — when this graduates to a verifier-ENFORCED check, verifying raw bytes
under a key is insufficient: a bare detached signature leaves source_cid,
key_id, issuer, algorithm, and purpose unbound (admitting transplant,
key/issuer confusion, algorithm downgrade, and cross-protocol reuse). v2 must
verify over a DOMAIN-SEPARATED canonical envelope binding all of
{source_cid/artifact_digest, key_id, issuer, algorithm, purpose}, with the
verifier — not the bundle — selecting the key and admitted algorithm set.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key


class SignatureVerifier:
    """Ed25519 signature verifier for Property 2 (signed artifact present).

    Callers register public keys by key_id (arbitrary string label) and
    verify detached Ed25519 signatures over raw artifact bytes.

    Usage::

        verifier = SignatureVerifier()
        verifier.register_key("device-fw-v2", pem_bytes)
        ok, key_id = verifier.verify(source_cid, artifact_bytes, sig_bytes, "device-fw-v2")
    """

    def __init__(self) -> None:
        self._key_cache: dict[str, bytes] = {}

    def register_key(self, key_id: str, public_key_pem_bytes: bytes) -> None:
        """Store a PEM-encoded Ed25519 public key under key_id.

        Args:
            key_id: arbitrary label used to reference the key in verify().
            public_key_pem_bytes: DER-inside-PEM encoded Ed25519 public key.
        """
        self._key_cache[key_id] = public_key_pem_bytes

    def verify(
        self,
        source_cid: str,
        raw_bytes: bytes,
        signature_bytes: bytes,
        key_id: str,
    ) -> tuple[bool, str | None]:
        """Verify an Ed25519 detached signature over raw_bytes.

        Args:
            source_cid: content-addressed ID of the source snapshot (accepted
                but unused at v1 — see the module SCOPE note: the binding holds
                out of band via content-addressing; reserved as a bound field of
                the v2 canonical-envelope verification).
            raw_bytes: the artifact bytes that were signed.
            signature_bytes: the detached Ed25519 signature (64 bytes).
            key_id: key label previously registered via register_key().

        Returns:
            ``(True, key_id)`` if the signature is valid under the registered key.
            ``(False, None)`` if key_id is unknown or the signature is invalid.
        """
        pem_bytes = self._key_cache.get(key_id)
        if pem_bytes is None:
            return False, None

        try:
            public_key = load_pem_public_key(pem_bytes)
        except (ValueError, TypeError, UnsupportedAlgorithm):
            return False, None

        if not isinstance(public_key, Ed25519PublicKey):
            return False, None

        try:
            public_key.verify(signature_bytes, raw_bytes)
        except InvalidSignature:
            return False, None
        except (TypeError, ValueError):
            # Off-contract input (non-bytes / wrong-length signature_bytes) must
            # return the documented (False, None), not escape as an uncaught
            # TypeError/ValueError the caller sees as a crash.
            return False, None

        return True, key_id


def default_v1_signature_verifier() -> SignatureVerifier:
    """Return a SignatureVerifier with no keys registered.

    Domain pilots register their own keys after construction:
    - A device-mesh pilot registers a synthesized firmware-key for its mesh integration.
    - A span-provenance pilot registers signing keys per its provenance standard.
    """
    return SignatureVerifier()
