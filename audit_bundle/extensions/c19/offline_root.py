"""C19.D — Emergency offline-root signature verification (break-glass path).

When old host signing key is FULLY compromised (cannot produce co_signed_old),
rotation MUST carry emergency_offline_root_signature signed by a verifier-binary-
pinned offline root-of-host key. This is a BREAK-GLASS path; the operational
runbook is documented alongside the audit-bundle contract §C19.D — code without
a documented invocation procedure does NOT ship.

Standards bound (v0.4): the offline-root signature is **Ed25519 / COSE_Sign1**
(RFC 9052), signing the SAME canonical rotation preimage the in-band co-signatures
sign, but under a verifier-binary-pinned PUBLIC key. This is the C19.D HMAC→
asymmetric migration:
the offline root signs with a private key held in escrow; the verifier holds only
the public key and can check but not forge. For the single most trust-critical
path in C19 (full-compromise recovery), shared-secret HMAC collapsed the guarantee
to "we both hold the key" — Ed25519 closes that.

Hard cutover: no HMAC dual-path remains (a dual path is itself a downgrade-
attack surface). Single algorithm pinned: EdDSA only; an unexpected COSE
`alg` fails closed with OFFLINE_ROOT_ALG_UNSUPPORTED.

Dep posture: this verify is on the SUBSTRATE-verifier path, which already
carries `cryptography` + `cbor2` — no new dependency, and
the stdlib-only veriker/cli/verify.py is untouched (two-verifier boundary). The COSE
Sig_structure is built with `cbor2` (not hand-rolled).

C17 seam (reserved, NOT a prerequisite): the public key is verifier-binary-pinned
today; its provenance upgrades to TEE-attested escrow when C17 lands. The forward
field `offline_root_attestation_ref` is reserved as `not_applicable` until then —
the signature check does not wait on it.


"""

from __future__ import annotations

import enum
from dataclasses import dataclass

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from audit_bundle.extensions.c19.layer_a_counter import (
    LayerAVerificationError,
    ReasonCode,
)

#: COSE algorithm id for EdDSA (RFC 9053 §2.2). The single pinned alg.
OFFLINE_ROOT_COSE_ALG_EDDSA = -8

#: Per-protocol COSE domain-separation tag for the offline-root rotation path.
#: Carried as the COSE Sig_structure external_aad — NOT
#: transmitted in the message; the verifier supplies its own protocol's constant.
#: A signature minted under this tag cannot be replayed as a cross-host
#: authenticator (which uses CROSS_HOST_COSE_DOMAIN_AAD), and vice versa.
OFFLINE_ROOT_COSE_DOMAIN_AAD = b"nexi:c19:offline-root-rotation:v0.4"

#: COSE protected header {1: alg} — alg=EdDSA. Encoded once, canonical (the
#: same bytes the producer signs over and the verifier reconstructs).
_OFFLINE_ROOT_PROTECTED_BSTR = cbor2.dumps({1: OFFLINE_ROOT_COSE_ALG_EDDSA})

#: Ed25519 raw public/private key length and signature length.
_ED25519_SIG_LEN = 64

#: Hard cap on `protected_bstr` size flowing into expensive operations
#: (cbor2.loads → cbor2.dumps(canonical=True) re-encode equality check). Real
#: protected headers in this protocol are 3 bytes (`a1 01 27` = {1: EdDSA});
#: with a kid label the worst-case legitimate size is well under 40 bytes.
#: A 256-byte cap is generous for legit, tight against algorithmic-DoS via the
#: canonical-encoder path: the atheris differential harness (2026-05-26)
#: surfaced a single input that wedged the verifier for >300 s inside
#: `cbor2.dumps(decoded, canonical=True)` from `is_canonical_cose_protected_
#: header`. Both verifiers (cross_host + offline_root) enforce the cap BEFORE
#: any cbor2.loads / canonical re-encode; the helper itself also rejects
#: oversized as defense-in-depth.
COSE_PROTECTED_HEADER_MAX_BYTES = 256


class OfflineRootReasonCode(str, enum.Enum):
    """Module-local reason codes — also mirrored into the shared ReasonCode enum."""

    MISSING_EMERGENCY_OFFLINE_ROOT_SIGNATURE = (
        "MISSING_EMERGENCY_OFFLINE_ROOT_SIGNATURE"
    )
    OFFLINE_ROOT_KEY_NOT_PINNED = "OFFLINE_ROOT_KEY_NOT_PINNED"
    OFFLINE_ROOT_SIGNATURE_INVALID = "OFFLINE_ROOT_SIGNATURE_INVALID"
    OFFLINE_ROOT_ALG_UNSUPPORTED = "OFFLINE_ROOT_ALG_UNSUPPORTED"


# ---------------------------------------------------------------------------
# Shared COSE_Sign1 construction (single source of truth — producers, the
# re-derivation check, and tests all build the signed bytes via these helpers
# so the encoding cannot drift). Detached payload: the rotation preimage is
# external (already canonical), so it is NOT carried inside the COSE message.
# ---------------------------------------------------------------------------


def offline_root_cose_sig_structure(
    preimage: bytes,
    *,
    external_aad: bytes,
    protected_bstr: bytes = _OFFLINE_ROOT_PROTECTED_BSTR,
) -> bytes:
    """RFC 9052 §4.4 Sig_structure for a COSE_Sign1 with a detached payload.

    Shared C19 COSE primitive — elevated from the offline-root
    path to a primitive both offline-root and cross-host build through, so the
    encoding cannot drift / fork a second encoder.

    `external_aad` is a REQUIRED per-protocol domain-separation tag (C1/C1a). It
    is NOT carried in the COSE message — the verifier supplies its own protocol's
    constant — so a signature minted under one protocol's external_aad cannot be
    replayed under another's. There is deliberately NO default: a `b""` default
    would silently re-open the cross-protocol replay window for any future caller
    that forgets the argument. Empty external_aad is rejected for the same reason.

    Sig_structure = [ "Signature1", protected, external_aad, payload ].
    """
    if not isinstance(external_aad, (bytes, bytearray)) or len(external_aad) == 0:
        raise ValueError(
            "external_aad must be a non-empty per-protocol domain-separation tag "
            "(C1a: no empty-aad fallback)"
        )
    return cbor2.dumps(["Signature1", protected_bstr, bytes(external_aad), preimage])


def is_canonical_cose_protected_header(protected_bstr: bytes, decoded: dict) -> bool:
    """Red-team A4 — True iff `protected_bstr` is the canonical (RFC 8949 §4.2 /
    RFC 9052 §3) encoding of `decoded`: definite-length map, no duplicate keys,
    shortest-form integer encodings.

    The COSE verifiers read ``alg = cbor2.loads(protected_bstr).get(1)``, and
    cbor2 silently tolerates non-canonical input (last-wins on duplicate keys,
    accepts indefinite-length and non-shortest ints). That is a parser
    differential: ``{1:-7, 1:-8}`` (a2 01 26 01 27) shows ES256 to a first-wins
    consumer but EdDSA to cbor2 here, defeating the D5 single-alg pin across a
    heterogeneous deployment; indefinite-length and non-shortest-int variants
    are pure message malleability (multiple valid encodings of the same edge,
    breaking any dedup keyed on authenticator bytes).

    A single canonical re-encode equality check subsumes all three: a canonical
    re-encode collapses duplicate keys (fewer bytes), emits definite-length, and
    uses shortest-form ints — so any non-canonical input differs from its
    canonical form. Callers MUST reject when this returns False (alg-absent /
    empty headers are handled by the caller's alg-pin and are out of scope here).
    """
    if not isinstance(decoded, dict):
        return False
    # Defense-in-depth: cap the size before the canonical re-encode. Callers
    # SHOULD reject oversized protected_bstr at their verifier entry with a
    # specific reason code (COSE_PROTECTED_HEADER_OVERSIZED), but the helper
    # itself also short-circuits so any future call site automatically gets
    # the DoS guard. atheris differential (2026-05-26) hit a >300 s hang
    # inside `cbor2.dumps(decoded, canonical=True)` on a single mutated
    # input; the cap closes that surface.
    if len(protected_bstr) > COSE_PROTECTED_HEADER_MAX_BYTES:
        return False
    try:
        return cbor2.dumps(decoded, canonical=True) == bytes(protected_bstr)
    except Exception:  # noqa: BLE001 — any encode failure is non-canonical
        return False


def sign_emergency_offline_root_signature(
    private_key: Ed25519PrivateKey, rotation_preimage: bytes
) -> bytes:
    """Produce the COSE_Sign1 message (CBOR bytes) for an emergency offline-root
    signature over `rotation_preimage`. Detached payload (nil in slot 3).

    COSE_Sign1 = [ protected_bstr, unprotected_map, payload(nil), signature ].
    """
    sig = private_key.sign(
        offline_root_cose_sig_structure(
            rotation_preimage, external_aad=OFFLINE_ROOT_COSE_DOMAIN_AAD
        )
    )
    return cbor2.dumps([_OFFLINE_ROOT_PROTECTED_BSTR, {}, None, sig])


@dataclass(frozen=True)
class OfflineRootPolicy:
    """Policy frozen at verifier-binary build time.

    Key material is shipped via the verifier OCI image under OS-level code
    signing (mirrors the nexi-c19-ts-log TUF role pattern). v0.4 pins
    Ed25519 PUBLIC keys (raw 32-byte) — verify-only, not forgeable. The C17
    TEE-attested escrow upgrade governs the key's provenance, not this check.
    """

    pinned_offline_root_key_ids: frozenset[bytes]
    pinned_offline_root_verifying_keys: (
        dict  # key_id (bytes) -> 32-byte Ed25519 raw public key
    )


def verify_emergency_offline_root_signature(
    *,
    rotation_preimage: bytes,
    emergency_offline_root_signature: bytes | None,
    offline_root_key_id: bytes | None,
    policy,
) -> None:
    """Verify the emergency_offline_root_signature (Ed25519 / COSE_Sign1) against
    the pinned offline-root keyring. Invoked ONLY when rotation_reason ==
    'emergency' OR co_signed_old is absent / failed.

    Emits:
      MISSING_EMERGENCY_OFFLINE_ROOT_SIGNATURE — signature absent on emergency path
      OFFLINE_ROOT_KEY_NOT_PINNED              — offline_root_key_id not in pinned set
      OFFLINE_ROOT_ALG_UNSUPPORTED             — COSE protected alg != pinned EdDSA
      OFFLINE_ROOT_SIGNATURE_INVALID           — malformed COSE, bad sig length, or
                                                 Ed25519 verification failure

    `policy` may be an OfflineRootPolicy or any duck-typed object exposing
    `pinned_offline_root_key_ids` and `pinned_offline_root_verifying_keys`
    attributes — the layer_a_counter dispatcher passes a lightweight view
    object to avoid an import cycle.
    """
    if emergency_offline_root_signature is None or offline_root_key_id is None:
        raise LayerAVerificationError(
            ReasonCode.MISSING_EMERGENCY_OFFLINE_ROOT_SIGNATURE,
            detail=(
                "emergency rotation path requires emergency_offline_root_signature "
                "+ offline_root_key_id"
            ),
        )
    if offline_root_key_id not in policy.pinned_offline_root_key_ids:
        raise LayerAVerificationError(
            ReasonCode.OFFLINE_ROOT_KEY_NOT_PINNED,
            detail=f"offline_root_key_id={offline_root_key_id!r} not in pinned set",
        )
    if not isinstance(emergency_offline_root_signature, (bytes, bytearray)):
        raise LayerAVerificationError(
            ReasonCode.OFFLINE_ROOT_SIGNATURE_INVALID,
            detail=(
                "signature must be a COSE_Sign1 CBOR message (bytes); got "
                f"{type(emergency_offline_root_signature).__name__}"
            ),
        )

    # Decode the COSE_Sign1 envelope: [protected_bstr, unprotected, payload, sig].
    try:
        cose = cbor2.loads(bytes(emergency_offline_root_signature))
    except Exception as exc:  # cbor2 raises various decode errors
        raise LayerAVerificationError(
            ReasonCode.OFFLINE_ROOT_SIGNATURE_INVALID,
            detail=f"offline-root signature is not decodable COSE_Sign1 CBOR: {exc}",
        ) from exc
    if not isinstance(cose, (list, tuple)) or len(cose) != 4:
        raise LayerAVerificationError(
            ReasonCode.OFFLINE_ROOT_SIGNATURE_INVALID,
            detail="COSE_Sign1 must be a 4-element array",
        )
    protected_bstr, _unprotected, _payload, signature = cose

    # Algorithmic-DoS guard: bound protected_bstr BEFORE the cbor2.loads + the
    # downstream canonical re-encode equality check. Real protected headers in
    # this protocol are <= 40 bytes; anything beyond the cap is rejected as
    # malformed without any expensive parsing work. See module-level constant
    # COSE_PROTECTED_HEADER_MAX_BYTES for the atheris finding that motivated
    # this. Sister check in cross_host_peerreview.verify_cross_host_authenticator_cose.
    if (
        isinstance(protected_bstr, (bytes, bytearray))
        and len(protected_bstr) > COSE_PROTECTED_HEADER_MAX_BYTES
    ):
        raise LayerAVerificationError(
            ReasonCode.OFFLINE_ROOT_SIGNATURE_INVALID,
            detail=(
                f"COSE protected header oversized: {len(protected_bstr)} bytes "
                f"(cap {COSE_PROTECTED_HEADER_MAX_BYTES}); only alg-pin "
                f"{{1: EdDSA}} is admitted"
            ),
        )

    # Read alg from the protected header; fail closed on anything but pinned EdDSA
    # (D5 single-alg pin — never down/upgrade).
    try:
        protected = cbor2.loads(protected_bstr) if protected_bstr else {}
        alg = protected.get(1) if isinstance(protected, dict) else None
    except Exception:
        alg = None
    if alg != OFFLINE_ROOT_COSE_ALG_EDDSA:
        raise LayerAVerificationError(
            ReasonCode.OFFLINE_ROOT_ALG_UNSUPPORTED,
            detail=(
                f"COSE protected alg={alg!r}; only pinned EdDSA "
                f"({OFFLINE_ROOT_COSE_ALG_EDDSA}) accepted"
            ),
        )

    # A4 — reject non-canonical protected headers (dup-key / indefinite-length /
    # non-shortest int) BEFORE trusting the decoded alg, closing the parser
    # differential against any first-wins / canonical-only sibling consumer.
    if protected_bstr and not is_canonical_cose_protected_header(
        protected_bstr, protected
    ):
        raise LayerAVerificationError(
            ReasonCode.OFFLINE_ROOT_SIGNATURE_INVALID,
            detail=(
                "non-canonical COSE protected header (RFC 9052 §3 forbids "
                "duplicate keys / indefinite-length / non-shortest-int encodings)"
            ),
        )

    # Reject unknown protected-header labels (incl. `crit`) — parity with the
    # cross-host verifier's CROSS_HOST_COSE_HEADER_UNSUPPORTED check. The only
    # admissible protected label is alg {1}; anything else is a non-conformant
    # COSE message (the signature covers it, so this is strictness not a forgery
    # gate, but the two shared-encoder consumers must agree on what they accept).
    extra_labels = set(protected.keys()) - {1}
    if extra_labels:
        # `key=repr`: see cross_host_peerreview.py same-named check for the
        # §C9 rationale — attacker-controlled CBOR protected headers can
        # contain non-int map keys (bytes / tuple / None), and `sorted()` on
        # the resulting mixed set raises TypeError out of the detail
        # formatter. Identical bug class to that one and to the unprotected-
        # slot fix; sister verifier, sister fix.
        raise LayerAVerificationError(
            ReasonCode.OFFLINE_ROOT_SIGNATURE_INVALID,
            detail=(
                f"unsupported COSE protected-header labels "
                f"{sorted(extra_labels, key=repr)}; "
                "only alg {1} is admitted on the offline-root path"
            ),
        )

    if (
        not isinstance(signature, (bytes, bytearray))
        or len(signature) != _ED25519_SIG_LEN
    ):
        actual = len(signature) if isinstance(signature, (bytes, bytearray)) else "n/a"
        raise LayerAVerificationError(
            ReasonCode.OFFLINE_ROOT_SIGNATURE_INVALID,
            detail=f"Ed25519 signature must be {_ED25519_SIG_LEN} bytes; got len={actual}",
        )

    pub_raw = policy.pinned_offline_root_verifying_keys[offline_root_key_id]
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes(pub_raw))
    except Exception as exc:
        raise LayerAVerificationError(
            ReasonCode.OFFLINE_ROOT_SIGNATURE_INVALID,
            detail=f"pinned offline-root key is not a valid Ed25519 public key: {exc}",
        ) from exc

    # Reconstruct the Sig_structure over the TRANSMITTED protected header + the
    # external rotation preimage, then verify.
    sig_input = offline_root_cose_sig_structure(
        rotation_preimage,
        external_aad=OFFLINE_ROOT_COSE_DOMAIN_AAD,
        protected_bstr=protected_bstr,
    )
    try:
        pub.verify(bytes(signature), sig_input)
    except InvalidSignature as exc:
        raise LayerAVerificationError(
            ReasonCode.OFFLINE_ROOT_SIGNATURE_INVALID,
            detail="Ed25519/COSE_Sign1 verification failed under pinned offline-root key",
        ) from exc


__all__ = [
    "OFFLINE_ROOT_COSE_ALG_EDDSA",
    "OFFLINE_ROOT_COSE_DOMAIN_AAD",
    "OfflineRootPolicy",
    "OfflineRootReasonCode",
    "offline_root_cose_sig_structure",
    "sign_emergency_offline_root_signature",
    "verify_emergency_offline_root_signature",
]
