"""C19 cross-host — PeerReview authenticator pairing (reference implementation).

v0.3 scope (reference-implementation grade, soak-then-harden):
  - PeerReview (Haeberlen SOSP 2007) f+1 authenticator pairing
  - Full cbor-encoded preimage
  - Profile-gated to single-organization HMAC at v0.3

v0.4 update:
  - Cross-org COSE_Sign1 / Ed25519 (RFC 9052) IMPLEMENTED (was deferred). The
    `CROSS_HOST_COSE_AUTH_RESERVED_FOR_V0_4` refusal is deprecated (emit-never).
    Cross-org edges verify under a verifier-side `CrossOrgKeyPolicy` keyed on a
    primitive-partitioned pinned `kid` (route-on-kid); single-org HMAC is
    retained. Reuses the shared COSE encoder
    `offline_root.offline_root_cose_sig_structure` with a per-protocol
    `external_aad` domain tag (`CROSS_HOST_COSE_DOMAIN_AAD`) so signatures cannot
    replay across the offline-root / cross-host paths. Single-alg EdDSA pin.
  - The inline deterministic-CBOR subset was deleted in favour of `cbor2` (now a
    declared substrate dep); preimage bytes are byte-identical (frozen vectors).
  - Ack timeliness witnessed via `ack_timestamp_evidence` discriminated union.
  - Profile-bound `(min, max)` ack_timeout ceilings
  - DISPUTED_EDGE / UNVERIFIABLE_EDGE reduction

Standards bound: Haeberlen et al. "PeerReview: Practical Accountability for
Distributed Systems" SOSP 2007 + RFC 8949 deterministic CBOR + RFC 2104 HMAC
+ RFC 5869 HKDF + RFC 9052 COSE_Sign1.

This substrate module takes JCS + crypto deps (cryptography.hazmat.primitives.hmac
+ .kdf.hkdf + cbor2). The offline-only verify.py tool keeps the "stdlib-only"
framing; this substrate module does not.


"""

from __future__ import annotations

import enum
import hashlib
import hmac as _stdlib_hmac
import io
from dataclasses import dataclass, field
from pathlib import Path

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.extensions.c19.offline_root import (
    COSE_PROTECTED_HEADER_MAX_BYTES,
    OFFLINE_ROOT_COSE_ALG_EDDSA,
    is_canonical_cose_protected_header,
    offline_root_cose_sig_structure,
)
from audit_bundle.plugin import PluginResult


# ---------------------------------------------------------------------------
# Enums (sb-001 API surface)
# ---------------------------------------------------------------------------


class CrossHostEdgeState(enum.Enum):
    TRUSTED = "trusted"
    DISPUTED_EDGE = "DISPUTED_EDGE"
    UNVERIFIABLE_EDGE = "UNVERIFIABLE_EDGE"
    ACK_TIMELINESS_VIOLATION = "ACK_TIMELINESS_VIOLATION"


class AckTimestampEvidenceKind(enum.Enum):
    ROUGHTIME_QUORUM = "roughtime_quorum"
    RFC3161_TSA = "rfc3161_tsa"


class CrossHostAuthenticatorKind(enum.Enum):
    HMAC = "hmac"
    COSE_SIGN1 = "cose_sign1"


class DeploymentScope(enum.Enum):
    SINGLE_ORG = "single_org"
    CROSS_ORG = "cross_org"


class AssuranceProfile(enum.Enum):
    OFFLINE_AUDITOR_MINIMAL = "offline-auditor-minimal"
    PRODUCTION_STANDARD = "production-standard"
    REGULATED_HIGH_ASSURANCE = "regulated-high-assurance"


# ---------------------------------------------------------------------------
# Profile-bound (min, max) ack_timeout ceilings, mirroring the per-profile
# anchor-window ceilings. Bundle-supplied override is IGNORED.
# ---------------------------------------------------------------------------

ACK_TIMEOUT_BOUNDS_MS: dict[AssuranceProfile, tuple[int, int]] = {
    AssuranceProfile.OFFLINE_AUDITOR_MINIMAL: (1_000, 86_400_000),
    AssuranceProfile.PRODUCTION_STANDARD: (500, 60_000),
    AssuranceProfile.REGULATED_HIGH_ASSURANCE: (100, 5_000),
}


# ---------------------------------------------------------------------------
# Deterministic CBOR for the preimage tuples (RFC 8949 §4.2.1).
#
# Migration note: the hand-rolled `_cbor_head`/`_cbor_encode_*` subset
# was deleted once `cbor2>=5.6` became a declared substrate dep (`pyproject.toml`).
# It only existed "because cbor2 is not yet a top-level dep" — that constraint is
# gone. The preimage tuples are scalar-only definite-length arrays (str / int /
# bytes / null), so `cbor2.dumps` produces byte-identical output; a frozen
# test-vector + the original equivalence gate (over length-encoding boundaries)
# proved this before deletion. Definite-length, shortest-form by default.
# ---------------------------------------------------------------------------


def _cbor_encode_array(items: list) -> bytes:
    """Definite-length deterministic CBOR array (RFC 8949 §4.2.1) via cbor2."""
    return cbor2.dumps(items)


# ---------------------------------------------------------------------------
# Preimage constructors
# ---------------------------------------------------------------------------


_CTX_SENDER = "nexi/audit/v0.3/cross-host-receipt"
_CTX_ACK = "nexi/audit/v0.3/cross-host-receipt-ack"


def construct_sender_signature_preimage(
    *,
    sender_host_id: str,
    receiver_host_id: str,
    channel_id: str,
    message_id: str,
    message_hash: bytes,
    sender_local_counter: int,
    ack_timeout_ms: int,
    bundle_id: str,
    receiver_challenge_token: bytes,
    protocol_version: str = "v0.3",
) -> bytes:
    """Deterministic-CBOR encoding of the sender_signature preimage tuple in
    this EXACT field order:

        [context_label, protocol_version, sender_host_id, receiver_host_id,
         channel_id, message_id, message_hash, sender_local_counter,
         ack_timeout_ms, bundle_id, receiver_challenge_token]
    """
    tuple_items = [
        _CTX_SENDER,
        protocol_version,
        sender_host_id,
        receiver_host_id,
        channel_id,
        message_id,
        message_hash,
        sender_local_counter,
        ack_timeout_ms,
        bundle_id,
        receiver_challenge_token,
    ]
    return _cbor_encode_array(tuple_items)


def construct_ack_preimage(
    *,
    sender_host_id: str,
    receiver_host_id: str,
    channel_id: str,
    message_id: str,
    message_hash: bytes,
    receiver_local_counter: int,
    kind: str,
    reason_code_if_nack: str | None,
    bundle_id: str,
    ack_timeout_ms: int,
    sender_local_counter: int,
    receiver_challenge_token: bytes,
    protocol_version: str = "v0.3",
) -> bytes:
    """Deterministic-CBOR encoding of the ack/nack preimage tuple.

        [context_label, protocol_version, sender_host_id, receiver_host_id,
         channel_id, message_id, message_hash, receiver_local_counter, kind,
         reason_code_if_nack, bundle_id, ack_timeout_ms, sender_local_counter,
         receiver_challenge_token]

    Red-team A5 fix: the original tuple (SCOPING line 569-573) omitted
    bundle_id, ack_timeout_ms, sender_local_counter, and crucially
    receiver_challenge_token (the anti-replay nonce the receiver must prove it
    saw). Without those an otherwise-legit ack verifies when transplanted onto
    a DIFFERENT edge/bundle that shares the bound fields — the ack was not
    bound to the specific challenged send. These four are now appended (and are
    required) so the ack binds the exact send it acknowledges. This is a
    preimage-format change: builders and verifiers re-derive in lockstep, and
    the frozen ack vector was re-pinned in the same change.
    """
    if kind not in ("ack", "nack"):
        raise ValueError(f"ack/nack kind must be 'ack' or 'nack', got {kind!r}")
    tuple_items = [
        _CTX_ACK,
        protocol_version,
        sender_host_id,
        receiver_host_id,
        channel_id,
        message_id,
        message_hash,
        receiver_local_counter,
        kind,
        reason_code_if_nack,
        bundle_id,
        ack_timeout_ms,
        sender_local_counter,
        receiver_challenge_token,
    ]
    return _cbor_encode_array(tuple_items)


# ---------------------------------------------------------------------------
# HKDF + HMAC (RFC 5869 §2.2-§2.3 + RFC 2104 §2)
# HKDF output USED AS KEY, NOT concatenated as message prefix.
# ---------------------------------------------------------------------------


def derive_cross_host_receipt_key(
    *,
    sender_signing_key_material: bytes,
    info_label: str = _CTX_SENDER,
) -> bytes:
    """HKDF-Extract-then-Expand. salt=0x00*32, IKM=signing_key_material,
    info=info_label (UTF-8 bytes), L=32. Returns 32-byte derived key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"\x00" * 32,
        info=info_label.encode("utf-8"),
    )
    return hkdf.derive(sender_signing_key_material)


def sign_cross_host_authenticator(*, K: bytes, preimage: bytes) -> bytes:
    """HMAC-SHA256(K, preimage) per RFC 2104 §2."""
    return _stdlib_hmac.new(K, preimage, hashlib.sha256).digest()


def verify_cross_host_authenticator(*, K: bytes, preimage: bytes, sig: bytes) -> bool:
    """Constant-time HMAC verification (single-org path)."""
    expected = sign_cross_host_authenticator(K=K, preimage=preimage)
    return _stdlib_hmac.compare_digest(expected, sig)


# ---------------------------------------------------------------------------
# Cross-org COSE_Sign1 / Ed25519 authenticator (v0.4 migration).
#
# Reuses the SHARED C19 COSE primitive (offline_root_cose_sig_structure, the
# alg pin OFFLINE_ROOT_COSE_ALG_EDDSA) — no second encoder. The
# per-protocol domain tag CROSS_HOST_COSE_DOMAIN_AAD is supplied as the COSE
# external_aad and is NOT transmitted: a signature minted for the offline-root
# rotation path (OFFLINE_ROOT_COSE_DOMAIN_AAD) cannot be replayed as a cross-host
# authenticator, and vice versa (cross-protocol replay closure).
# ---------------------------------------------------------------------------

#: Per-protocol COSE domain-separation tag for cross-host receipts.
CROSS_HOST_COSE_DOMAIN_AAD = b"nexi:c19:cross-host-receipt:v0.4"

#: Canonical protected header {1: EdDSA}. Distinct *bytes object* from the
#: offline-root constant, but cross-protocol separation rides external_aad, not
#: this header (the protected_bstr is byte-identical across protocols).
_CROSS_HOST_COSE_PROTECTED_BSTR = cbor2.dumps({1: OFFLINE_ROOT_COSE_ALG_EDDSA})

_ED25519_SIG_LEN = 64


def cross_host_cose_kid(public_key_raw: bytes) -> bytes:
    """Canonical cross-org `kid`: the raw 32-byte Ed25519 public key
    itself. Bytes only, one encoding — no hex/base64 ambiguity, no truncation."""
    raw = bytes(public_key_raw)
    if len(raw) != 32:
        raise ValueError("Ed25519 raw public key (canonical kid) must be 32 bytes")
    return raw


def sign_cross_host_authenticator_cose(
    *, private_key: Ed25519PrivateKey, preimage: bytes
) -> bytes:
    """Produce a detached-payload COSE_Sign1 (CBOR bytes) over `preimage` under
    the cross-host domain tag. Protected header = {1: EdDSA}; `kid` is carried
    out-of-band in the edge record, NOT inside the COSE message.

    COSE_Sign1 = [ protected_bstr, unprotected_map, payload(nil), signature ].
    """
    sig = private_key.sign(
        offline_root_cose_sig_structure(
            preimage,
            external_aad=CROSS_HOST_COSE_DOMAIN_AAD,
            protected_bstr=_CROSS_HOST_COSE_PROTECTED_BSTR,
        )
    )
    return cbor2.dumps([_CROSS_HOST_COSE_PROTECTED_BSTR, {}, None, sig])


def verify_cross_host_authenticator_cose(
    *, public_key_raw: bytes, preimage: bytes, cose_bytes, role: str = "sender"
) -> tuple[bool, str, str]:
    """Verify a detached COSE_Sign1 cross-host authenticator under a pinned raw
    Ed25519 public key. Returns (ok, reason_code, detail).

    Fail-closed: alg ≠ pinned EdDSA → CROSS_HOST_ALG_UNSUPPORTED; unknown
    protected-header labels → CROSS_HOST_COSE_HEADER_UNSUPPORTED; the alg is read
    from the SAME protected_bstr fed into the Sig_structure (C7, no re-encode).
    """
    sig_fail_code = (
        "ACK_SIGNATURE_VERIFICATION_FAILED"
        if role == "ack"
        else "SENDER_SIGNATURE_VERIFICATION_FAILED"
    )
    if isinstance(cose_bytes, str):
        try:
            cose_bytes = bytes.fromhex(cose_bytes)
        except ValueError:
            return (
                False,
                "CROSS_HOST_COSE_MALFORMED",
                "authenticator hex is undecodable",
            )
    if not isinstance(cose_bytes, (bytes, bytearray)):
        return (
            False,
            "CROSS_HOST_COSE_MALFORMED",
            f"authenticator must be COSE_Sign1 CBOR bytes; got {type(cose_bytes).__name__}",
        )
    # Streaming decode so we can detect trailing bytes — cbor2.loads consumes
    # the first complete CBOR data item and silently ignores the rest, which
    # Layer-2 atheris fuzz (2026-05-26, finding #2) exploited: appending
    # arbitrary garbage to a valid envelope yielded byte-different but
    # verify-passing envelopes (same signature, different SHA-256). RFC 8949
    # §5.1 explicitly identifies trailing-data-after-item as non-conforming.
    _stream = io.BytesIO(bytes(cose_bytes))
    try:
        cose = cbor2.load(_stream)
    except Exception as exc:  # cbor2 raises various decode errors
        return False, "CROSS_HOST_COSE_MALFORMED", f"undecodable COSE_Sign1 CBOR: {exc}"
    # Structural shape FIRST — if the decoded value isn't a 4-element array,
    # the user wants to hear "this isn't even a COSE_Sign1" (CROSS_HOST_COSE_MALFORMED),
    # not "trailing bytes" (which is true but less informative for pure garbage
    # inputs like `\xff\xff\xff` where cbor2 yields a break-sentinel + extras).
    if not isinstance(cose, (list, tuple)) or len(cose) != 4:
        return (
            False,
            "CROSS_HOST_COSE_MALFORMED",
            "COSE_Sign1 must be a 4-element array",
        )
    # Stream-completeness check (RFC 8949 §5.1 — trailing data after a valid
    # CBOR data item is non-conforming) — only meaningful after we know the
    # decoded value itself was structurally credible.
    if _stream.tell() != len(cose_bytes):
        return (
            False,
            "COSE_TRAILING_BYTES",
            f"COSE_Sign1 envelope has {len(cose_bytes) - _stream.tell()} trailing "
            f"byte(s) after the CBOR data item (RFC 8949 §5.1)",
        )
    protected_bstr, _unprotected, _payload, signature = cose

    # Slot-type validation per RFC 9052 §4.2 + the cross-host detached-payload
    # contract. Layer-2 atheris fuzz (2026-05-26) found that the verifier
    # accepted `[protected, 1, 0, sig]` — slots 1 and 2 unchecked — because
    # both protected_bstr and signature were byte-identical to a real valid
    # envelope and the Sig_structure therefore matched. No forgery power
    # (the signature still cryptographically verifies over the unchanged
    # preimage), but a two-verifier differential against any strict RFC 9052
    # consumer — same class as Stream A's A4 non-canonical-header finding.
    if not isinstance(_unprotected, dict):
        return (
            False,
            "COSE_UNPROTECTED_MALFORMED",
            f"COSE_Sign1 unprotected slot must be a CBOR map per RFC 9052 §4.2; "
            f"got {type(_unprotected).__name__}",
        )
    # Tight contract: the cross-host signer (sign_cross_host_authenticator_cose)
    # always emits {} in the unprotected slot — kid is carried out-of-band
    # in the edge record. A non-empty unprotected map (e.g. {1:-8} fake alg,
    # {4:b"fake_kid"} fake kid) is no crypto forge, but it is a two-verifier
    # differential against strict RFC 9052 consumers (which forbid
    # alg-in-unprotected) AND a latent break for any future consumer that
    # mistakenly reads unprotected.get(4). Symmetric with the
    # protected-header strict-allow-list below.
    if _unprotected:
        # Don't sort() the key list: a CBOR unprotected map can mix int and
        # None keys (e.g., `{None: 0, 0: 0}`), which Python 3 refuses to
        # compare, raising TypeError out of sorted() and breaking the
        # never-raise contract from inside the very check meant to reject the
        # non-empty map. Insertion-order listing avoids the comparison entirely.
        key_summary = ", ".join(repr(k) for k in _unprotected.keys())
        return (
            False,
            "COSE_UNPROTECTED_NOT_EMPTY",
            f"COSE_Sign1 unprotected slot must be empty for cross-host (kid is "
            f"carried out-of-band); got {len(_unprotected)} entr"
            f"{'y' if len(_unprotected) == 1 else 'ies'} with keys [{key_summary}]",
        )
    if _payload is not None:
        return (
            False,
            "COSE_PAYLOAD_NOT_DETACHED",
            f"cross-host COSE_Sign1 uses detached payload (slot 2 = nil) per the "
            f"signer contract; got payload of type {type(_payload).__name__}",
        )

    # Algorithmic-DoS guard: bound protected_bstr BEFORE the cbor2.loads + the
    # downstream canonical re-encode equality check (is_canonical_cose_
    # protected_header). atheris differential (2026-05-26) hit a >300 s hang
    # inside `cbor2.dumps(decoded, canonical=True)` on a single mutated input
    # — the verifier never returned, completely starving the fuzzer. Real
    # protected headers are <= 40 bytes; the cap is well above legit and
    # below DoS-causing. See COSE_PROTECTED_HEADER_MAX_BYTES in offline_root.
    if (
        isinstance(protected_bstr, (bytes, bytearray))
        and len(protected_bstr) > COSE_PROTECTED_HEADER_MAX_BYTES
    ):
        return (
            False,
            "COSE_PROTECTED_HEADER_OVERSIZED",
            f"COSE protected header oversized: {len(protected_bstr)} bytes "
            f"(cap {COSE_PROTECTED_HEADER_MAX_BYTES}); only alg-pin "
            f"{{1: EdDSA}} is admitted",
        )

    # Protected header: single pinned alg + reject unknown labels. Read alg from
    # the exact transmitted bytes that will be fed into the Sig_structure.
    try:
        protected = cbor2.loads(protected_bstr) if protected_bstr else {}
    except Exception as exc:
        return (
            False,
            "COSE_PROTECTED_HEADER_MALFORMED",
            f"undecodable protected header: {exc}",
        )
    if not isinstance(protected, dict):
        return False, "COSE_PROTECTED_HEADER_MALFORMED", "protected header is not a map"
    # A4 — reject non-canonical protected headers (dup-key / indefinite-length /
    # non-shortest int) BEFORE trusting the decoded alg. cbor2 last-wins on
    # `{1:-7, 1:-8}` shows EdDSA here but ES256 to a first-wins consumer; this
    # closes that parser differential and the message-malleability variants.
    if protected_bstr and not is_canonical_cose_protected_header(
        protected_bstr, protected
    ):
        return (
            False,
            "COSE_PROTECTED_HEADER_NONCANONICAL",
            "non-canonical COSE protected header (RFC 9052 §3 forbids duplicate "
            "keys / indefinite-length / non-shortest-int encodings)",
        )
    alg = protected.get(1)
    if alg != OFFLINE_ROOT_COSE_ALG_EDDSA:
        return (
            False,
            "CROSS_HOST_ALG_UNSUPPORTED",
            f"COSE protected alg={alg!r}; only pinned EdDSA "
            f"({OFFLINE_ROOT_COSE_ALG_EDDSA}) accepted",
        )
    extra_labels = set(protected.keys()) - {1}
    if extra_labels:
        # `key=repr` matches the §C9 detail-formatter pattern (same class as the
        # unprotected-slot fix at ~line 405): cbor2 admits non-int map keys
        # (bytes / tuple / None) and `sorted({0, (0,)})` raises TypeError —
        # breaks the never-raise contract from inside the very check that
        # rejects the malformed header. atheris differential surfaced this on
        # iter 6.69M with protected header {0:-17, 1:-8, 32:0, (0,):0}.
        return (
            False,
            "CROSS_HOST_COSE_HEADER_UNSUPPORTED",
            f"unsupported protected-header labels "
            f"{sorted(extra_labels, key=repr)}; "
            "kid is carried out-of-band in the edge record, not in COSE",
        )

    if (
        not isinstance(signature, (bytes, bytearray))
        or len(signature) != _ED25519_SIG_LEN
    ):
        actual = len(signature) if isinstance(signature, (bytes, bytearray)) else "n/a"
        return (
            False,
            "CROSS_HOST_COSE_MALFORMED",
            f"Ed25519 signature must be {_ED25519_SIG_LEN} bytes; got len={actual}",
        )

    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes(public_key_raw))
    except Exception as exc:
        return (
            False,
            "CROSS_HOST_KEY_NOT_PINNED",
            f"pinned cross-org key is not a valid Ed25519 public key: {exc}",
        )

    # Outer-envelope canonical-encoding check — A4-style, lifted from the inner
    # protected header to the outer 4-element array. Layer-3 atheris fuzz
    # (2026-05-27, finding #1) found that `9f <protected_bstr> <unprotected_map>
    # <payload> <signature> ff` (indefinite-length outer array, RFC 8949 §3.2.2)
    # decodes to the same 4-tuple as the canonical envelope, so the Sig_structure
    # check passed verbatim — yet the envelope bytes differ. Same message-
    # malleability class as Layer-2 finding #2 (trailing-bytes): an attacker can
    # mint arbitrarily many byte-different envelopes that all verify under the
    # same (pubkey, preimage), breaking audit-trail uniqueness / dedup. RFC 9052
    # §3 forbids indefinite-length / non-shortest-length array headers on COSE
    # messages; the same check generalizes to non-canonical inner CBOR fragments
    # (unprotected map header, payload-null encoding, signature-bstr length).
    #
    # Placement matters: this fires AFTER the slot-shape checks (protected is
    # bytes, unprotected is exactly `{}`, payload is None, signature is 64-byte
    # bytes), so cbor2's canonical re-encode is fully deterministic — no
    # float-16 compression or map-key reordering surprises that would conflict
    # with the upstream COSE_PAYLOAD_NOT_DETACHED / COSE_UNPROTECTED_NOT_EMPTY
    # reason codes. The single load-bearing degree of freedom remaining is the
    # outer-array length-encoding form.
    canonical_envelope = cbor2.dumps(
        [protected_bstr, _unprotected, _payload, bytes(signature)],
        canonical=True,
    )
    if canonical_envelope != bytes(cose_bytes):
        return (
            False,
            "COSE_OUTER_NONCANONICAL",
            "non-canonical COSE_Sign1 outer encoding (RFC 9052 §3 / RFC 8949 §4.2 "
            "forbid indefinite-length and non-shortest-length encodings on the "
            "outer envelope)",
        )

    sig_input = offline_root_cose_sig_structure(
        preimage,
        external_aad=CROSS_HOST_COSE_DOMAIN_AAD,
        protected_bstr=protected_bstr,
    )
    try:
        pub.verify(bytes(signature), sig_input)
    except InvalidSignature:
        return (
            False,
            sig_fail_code,
            "Ed25519/COSE_Sign1 verification failed under the pinned cross-org "
            "public key (tampered preimage/header, wrong key, or cross-protocol "
            "replay rejected by the domain tag)",
        )
    return True, "PASS", ""


@dataclass(frozen=True)
class CrossOrgKeyPolicy:
    """Verifier-side pinned cross-host key policy, frozen at verifier-binary build
    time (mirrors `OfflineRootPolicy`; provenance upgrades to the C18 TUF role
    `nexi-c19-host-roots` later — reserved-not-blocking).

    **kid-namespace partition (load-bearing):** each `kid` is bound to EXACTLY
    ONE primitive. The verifier routes on the pinned `kid` alone; the bundle's
    `authenticator_kind` is cross-checked but is NOT authoritative for routing
    (it is attacker-influenceable). A `kid` appearing under both primitives is a
    construction error, rejected here — without the partition an attacker holding
    a single-org HMAC key whose kid collides with a cross-org COSE pin could
    present an HMAC under that kid and be routed to HMAC verification.

    **kid->host binding (closes a single-host ack-forgery):** each pinned
    COSE `kid` is also bound to EXACTLY ONE owning `host_id`. Without this bind a
    single dishonest host could sign BOTH the sender authenticator AND the
    `receiver_acknowledgment` of an edge under its own (pinned) key — manufacturing
    a counterparty acknowledgment the named receiver never produced (the verifier
    only ever checked "valid sig under SOME pinned kid", never "the receiver's
    kid"). `verify_cross_host_edge_authenticator` now requires `expected_host_id`
    and rejects an authenticator whose kid is not the one bound to that host. The
    constructor enforces a host binding for every COSE kid so the verifier cannot
    silently fall back to the unbound (forgeable) path.
    """

    #: kid (bytes, = raw 32-byte Ed25519 pub) -> 32-byte raw Ed25519 pub
    pinned_cose_keys: dict
    #: kid (bytes) -> HMAC IKM (single-org org signing-key material)
    pinned_hmac_ikm: dict
    #: kid (bytes) -> owning host_id (str). MUST cover every COSE kid.
    pinned_cose_key_hosts: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        overlap = set(self.pinned_cose_keys) & set(self.pinned_hmac_ikm)
        if overlap:
            raise ValueError(
                "kid-partition violation: kid(s) bound to >1 primitive: "
                f"{sorted(overlap)}"
            )
        cose_kids = set(self.pinned_cose_keys)
        bound_kids = set(self.pinned_cose_key_hosts)
        if cose_kids != bound_kids:
            raise ValueError(
                "host-binding violation: every pinned COSE kid MUST carry "
                "exactly one host binding (no unbound / over-bound kids). "
                f"keys-without-host={sorted(cose_kids - bound_kids)} "
                f"host-without-key={sorted(bound_kids - cose_kids)}"
            )
        # Host values must be non-empty strings: a kid bound to None/"" would let
        # an edge whose host field is also None/"" pass the kid->host bind as a
        # tautology. Reject the sentinel at construction so the verifier never has
        # to defend against a degenerate pin.
        bad_hosts = [
            kid
            for kid, host in self.pinned_cose_key_hosts.items()
            if not isinstance(host, str) or not host
        ]
        if bad_hosts:
            raise ValueError(
                "host-binding violation: pinned COSE kid(s) bound to an "
                f"empty/non-string host_id: {sorted(bad_hosts)}"
            )

    def primitive_for_kid(self, kid: bytes) -> str | None:
        """Return 'cose_sign1' | 'hmac' | None (kid not pinned)."""
        if kid in self.pinned_cose_keys:
            return "cose_sign1"
        if kid in self.pinned_hmac_ikm:
            return "hmac"
        return None

    def host_for_kid(self, kid: bytes) -> str | None:
        """Return the host_id a COSE kid is bound to, or None."""
        return self.pinned_cose_key_hosts.get(kid)


def verify_cross_host_edge_authenticator(
    *,
    kid: bytes,
    presented_kind: str | None,
    preimage: bytes,
    authenticator,
    policy: CrossOrgKeyPolicy,
    info_label: str,
    expected_host_id: str,
    role: str = "sender",
) -> tuple[bool, str, str]:
    """Route on the PINNED `kid`, never on the bundle-supplied
    `authenticator_kind`. Returns (ok, reason_code, detail).

    Order: (1) kid must be pinned (else CROSS_HOST_KEY_NOT_PINNED, fail-closed);
    (2) presented kind must match the kid's policy-bound primitive (else
    CROSS_HOST_AUTH_MECHANISM_POLICY_VIOLATION — the distinguishable downgrade-
    attempt error); (3) for COSE, the kid MUST be the one bound to
    `expected_host_id` (the kid->host binding — the sender authenticator under
    sender_host_id's kid, the ack under receiver_host_id's kid; else
    CROSS_HOST_KEY_HOST_BINDING_VIOLATION); (4) verify under the pinned primitive.

    `expected_host_id` is REQUIRED (no default — mirrors the `external_aad`
    no-default rule): a caller that forgets it cannot silently re-open the
    ack-forgery window. For the sender authenticator pass
    `sender_host_id`; for the ack pass `receiver_host_id`.
    """
    # Defensive API boundary: never deref a missing policy —
    # decouples this fn's safety from the caller's step-(1) policy guard.
    if policy is None:
        return (
            False,
            "CROSS_HOST_KEY_NOT_PINNED",
            "no verifier-pinned cross-org policy (fail-closed)",
        )
    primitive = policy.primitive_for_kid(kid)
    if primitive is None:
        return (
            False,
            "CROSS_HOST_KEY_NOT_PINNED",
            "cross-org kid not in the verifier-pinned policy (fail-closed)",
        )
    if presented_kind is not None and presented_kind != primitive:
        return (
            False,
            "CROSS_HOST_AUTH_MECHANISM_POLICY_VIOLATION",
            f"presented authenticator_kind={presented_kind!r} ≠ policy-bound "
            f"primitive={primitive!r} for this kid (routing ignores the "
            "bundle field; mismatch is a hard fail, not a silent downgrade)",
        )
    if primitive == "cose_sign1":
        # `expected_host_id` selects WHICH pinned kid must have signed; an empty
        # / non-string value would collapse the bind. Reject it
        # before the comparison so a malformed edge field can never degenerate
        # the kid->host check into a tautology against a None/"" host pin.
        if not isinstance(expected_host_id, str) or not expected_host_id:
            return (
                False,
                "CROSS_HOST_KEY_HOST_BINDING_VIOLATION",
                f"expected_host_id must be a non-empty host string; got "
                f"{expected_host_id!r} (the kid->host bind cannot be "
                "evaluated against an empty/None host)",
            )
        bound_host = policy.host_for_kid(kid)
        if bound_host is None or bound_host != expected_host_id:
            return (
                False,
                "CROSS_HOST_KEY_HOST_BINDING_VIOLATION",
                f"kid is bound to host {bound_host!r} but this authenticator must "
                f"be signed by {expected_host_id!r}'s pinned key (closes the "
                "single-host ack-forgery — a sender cannot sign the receiver's "
                "acknowledgment under its own key)",
            )
        return verify_cross_host_authenticator_cose(
            public_key_raw=policy.pinned_cose_keys[kid],
            preimage=preimage,
            cose_bytes=authenticator,
            role=role,
        )
    # primitive == "hmac": single-org path, verifier holds the org IKM by kid.
    # NOTE: the kid->host bind is COSE-only, by design. HMAC is
    # gated to single_org (cross_org HMAC is rejected upstream as
    # CROSS_HOST_AUTH_PROFILE_MISMATCH), where send/ack non-repudiation rests on
    # per-host K_send/K_ack separation (distinct info_label + per-host IKM)
    # delegated to the production key-distribution layer (e.g. TUF,
    # out-of-substrate). Within-org ack-forgery is the accepted single-org trust
    # boundary. If single-org HMAC ever needs the same bind,
    # add a symmetric pinned_hmac_key_hosts map and apply the check here.
    K = derive_cross_host_receipt_key(
        sender_signing_key_material=policy.pinned_hmac_ikm[kid],
        info_label=info_label,
    )
    sig = (
        bytes.fromhex(authenticator)
        if isinstance(authenticator, str)
        else authenticator
    )
    sig_fail_code = (
        "ACK_SIGNATURE_VERIFICATION_FAILED"
        if role == "ack"
        else "SENDER_SIGNATURE_VERIFICATION_FAILED"
    )
    if verify_cross_host_authenticator(K=K, preimage=preimage, sig=sig):
        return True, "PASS", ""
    return False, sig_fail_code, "HMAC-SHA256 verification failed under pinned org key"


# ---------------------------------------------------------------------------
# Discriminated-union sub-key write helper (J1)
# ---------------------------------------------------------------------------


def compute_causal_chain_update(*, per_edge_verifier_outputs) -> dict:
    """Return the partial-update dict the bundler merges into
    manifest.causal_chain at build time. Exactly one top-level key
    'cross_host_authenticators'; order of per_edge_verifier_outputs preserved.
    """
    return {"cross_host_authenticators": list(per_edge_verifier_outputs)}


# ---------------------------------------------------------------------------
# Per-edge verifier helpers
# ---------------------------------------------------------------------------


_PROFILE_MAX_RADIUS_MS: dict[AssuranceProfile, int] = {
    AssuranceProfile.OFFLINE_AUDITOR_MINIMAL: 60_000,
    AssuranceProfile.PRODUCTION_STANDARD: 1_000,
    AssuranceProfile.REGULATED_HIGH_ASSURANCE: 200,
}


def _parse_profile(name: str | None) -> AssuranceProfile:
    if name is None:
        return AssuranceProfile.PRODUCTION_STANDARD
    for p in AssuranceProfile:
        if p.value == name:
            return p
    return AssuranceProfile.PRODUCTION_STANDARD


def _check_timestamp_evidence_shape(
    ev: dict, evidence_role: str
) -> tuple[bool, str, str]:
    """Validate discriminated-union shape.

    Returns (ok, reason_code, detail). evidence_role in {'send', 'ack'} —
    determines the SEND_/ACK_ error code prefix.
    """
    kind = ev.get("kind")
    code_prefix = (
        "ACK_TIMESTAMP_EVIDENCE"
        if evidence_role == "ack"
        else "SEND_TIMESTAMP_EVIDENCE"
    )
    if kind == "roughtime_quorum":
        rq = ev.get("roughtime_quorum") or {}
        if not isinstance(rq.get("responses"), list) or len(rq["responses"]) == 0:
            return False, f"{code_prefix}_MALFORMED", "empty roughtime_quorum.responses"
        return True, "", ""
    if kind == "rfc3161_tsa":
        tsa = ev.get("rfc3161_tsa") or {}
        imprint_algo = tsa.get("imprint_algorithm", "").lower()
        if imprint_algo == "sha1":
            return (
                False,
                "TSA_WEAK_ALGORITHM",
                "RFC 3161 messageImprint algorithm 'sha1' is rejected; allowlist is sha256 | sha384",
            )
        if imprint_algo not in ("sha256", "sha384"):
            return (
                False,
                "TSA_WEAK_ALGORITHM",
                f"RFC 3161 messageImprint algorithm {imprint_algo!r} not in allowlist {{sha256, sha384}}",
            )
        if not tsa.get("rfc3161_token"):
            return False, f"{code_prefix}_MALFORMED", "rfc3161_token missing"
        if not tsa.get("nonce"):
            return (
                False,
                "TSA_NONCE_MISSING",
                "RFC 3161 nonce required per verifier policy (anti-replay)",
            )
        return True, "", ""
    # Unknown / missing kind → RFC 2119 MUST hard-fail.
    return (
        False,
        f"{code_prefix}_UNKNOWN_KIND",
        f"discriminated union kind={kind!r} not in allowlist {{roughtime_quorum, rfc3161_tsa}}",
    )


def _extract_send_bound_ms(ev: dict) -> tuple[int, int]:
    """Return (midp_ms, radi_ms) extracted from VALIDATED server responses
    (informational mirror fields are ignored).
    """
    kind = ev.get("kind")
    if kind == "roughtime_quorum":
        rq = ev["roughtime_quorum"]
        resp = rq["responses"][0]
        return int(resp["midp_ms"]), int(resp.get("radi_ms", 0))
    if kind == "rfc3161_tsa":
        # RFC 3161 genTime is point-in-time; no RADI. Parse iso8601 to ms.
        tsa = ev["rfc3161_tsa"]
        gentime = tsa.get("send_timestamp_gentime") or tsa.get("ack_timestamp_gentime")
        from datetime import datetime, timezone

        dt = datetime.fromisoformat(gentime.replace("Z", "+00:00"))
        ms = int(dt.replace(tzinfo=timezone.utc).timestamp() * 1000)
        return ms, 0
    raise ValueError(f"cannot extract bound from kind={kind!r}")


# ---------------------------------------------------------------------------
# Cross-edge stateful walk (flat-schema path)
# ---------------------------------------------------------------------------


def check_cross_host_edge_set_stateful(edges) -> tuple[bool, str, str]:
    """Stateful walk over a FLAT cross-host edge list — the schema the builder
    emits and the pilot re-derivation checks consume (keys: sender_host_id,
    receiver_host_id, channel_id, message_id, sender_local_counter,
    receiver_local_counter, receiver_challenge_token, sender_authenticator,
    ack_authenticator, ...).

    Root cause it closes: the per-edge re-derivation
    checks (the C19.B cross-host-receipt re-derivation check) verify each
    edge's signature in ISOLATION and hold no cross-edge state, so triplicating
    one legit COSE edge made all three verify → the bundle PASSed. The
    substrate's own stateful walk (`CrossHostPeerReviewAuthenticatorCheck.
    _check_edge` steps (3)-(4)) never ran on this path because it reads the
    richer `edge['sender_signature']` dict and KeyErrors on the flat schema.
    This function supplies the missing replay / counter-monotonicity /
    challenge-token-reuse discipline for the flat path, mirroring that logic.

    Returns (ok, reason_code, detail); ok=True / reason_code='PASS' when clean.
    Scope: replay + counter-monotonicity + challenge-token-reuse only.
    Ack-timeliness (needs crypto-verified edge timestamps)
    is NOT enforced here; per-edge timestamp evidence stays shape-only.
    """
    seen_edge_identity: set[tuple] = set()
    sender_counter_high: dict[tuple, int] = {}
    receiver_counter_high: dict[tuple, int] = {}
    # Hardening: widened from per-channel `dict[tuple, set]` to a single
    # bundle-wide set. receiver_challenge_token is supposed to be a
    # globally-unpredictable nonce the receiver issues per request; any reuse
    # anywhere in the bundle is evidence of bad randomness, a
    # malicious/equivocating receiver, or operator error. The earlier
    # per-channel scoping caught the in-channel reuse class but silently
    # accepted cross-channel and cross-receiver reuse. Bundle-wide subsumes
    # per-channel.
    challenge_tokens_seen: set = set()

    for idx, edge in enumerate(edges):
        try:
            sender_host_id = edge["sender_host_id"]
            receiver_host_id = edge["receiver_host_id"]
            channel_id = edge["channel_id"]
            message_id = edge["message_id"]
            sender_local_counter = edge["sender_local_counter"]
            receiver_local_counter = edge["receiver_local_counter"]
            rct_hex = edge["receiver_challenge_token"]
        except KeyError as exc:
            return (
                False,
                "CROSS_HOST_EDGE_FIELD_MISSING",
                f"edge[{idx}]: stateful walk requires field {exc}",
            )

        # (a) Replay / duplicate edge. A message_id is single-use within a
        # channel, so a repeated (sender, receiver, channel, message_id)
        # identity is a replayed/triplicated edge — rejected regardless of how
        # many times its per-edge signature re-verifies in isolation.
        identity = (sender_host_id, receiver_host_id, channel_id, message_id)
        if identity in seen_edge_identity:
            return (
                False,
                "CROSS_HOST_EDGE_REPLAY_DETECTED",
                (
                    f"edge[{idx}]: duplicate cross-host edge identity "
                    f"(sender={sender_host_id!r}, receiver={receiver_host_id!r}, "
                    f"channel={channel_id!r}, message_id={message_id!r}); a "
                    "message_id is single-use within a channel — replayed/"
                    "triplicated edge rejected (a per-edge signature verifying "
                    "in isolation does not license re-use)"
                ),
            )
        seen_edge_identity.add(identity)

        # (b) Counter monotonicity per (sender, channel) and (receiver, channel).
        sender_key = (sender_host_id, channel_id)
        if (
            sender_key in sender_counter_high
            and sender_local_counter <= sender_counter_high[sender_key]
        ):
            return (
                False,
                "COUNTER_GAP_DETECTED",
                (
                    f"edge[{idx}]: sender_local_counter={sender_local_counter} "
                    f"not strictly increasing on (sender={sender_host_id!r}, "
                    f"channel={channel_id!r}); previous high="
                    f"{sender_counter_high[sender_key]}"
                ),
            )
        sender_counter_high[sender_key] = sender_local_counter

        receiver_key = (receiver_host_id, channel_id)
        if (
            receiver_key in receiver_counter_high
            and receiver_local_counter <= receiver_counter_high[receiver_key]
        ):
            return (
                False,
                "COUNTER_GAP_DETECTED",
                (
                    f"edge[{idx}]: receiver_local_counter={receiver_local_counter} "
                    f"not strictly increasing on (receiver={receiver_host_id!r}, "
                    f"channel={channel_id!r}); previous high="
                    f"{receiver_counter_high[receiver_key]}"
                ),
            )
        receiver_counter_high[receiver_key] = receiver_local_counter

        # (c) Challenge-token reuse — bundle-wide scope (Tier 7b widening,
        # 2026-05-26). RCT is supposed to be a fresh nonce; any reuse anywhere
        # in the bundle indicates bad RNG, malicious/equivocating receiver, or
        # operator error. Pre-7b the scope was per (sender, receiver, channel),
        # which silently accepted cross-channel and cross-receiver reuse.
        if rct_hex in challenge_tokens_seen:
            return (
                False,
                "CHALLENGE_TOKEN_REPLAY_DETECTED",
                (
                    f"edge[{idx}]: receiver_challenge_token reused within "
                    f"bundle (sender={sender_host_id!r}, "
                    f"receiver={receiver_host_id!r}, channel={channel_id!r}); "
                    f"bundle-wide nonce uniqueness (Tier 7b — RCT must be a "
                    f"globally-fresh receiver-issued nonce, any reuse is "
                    f"evidence of RNG failure or equivocation)"
                ),
            )
        challenge_tokens_seen.add(rct_hex)

    return (True, "PASS", f"{len(edges)} cross-host edge(s) pass stateful walk")


def _crypto_verify_edge_timestamp_evidence(
    ev: dict, *, role: str, preimage: bytes, assurance_profile: str
) -> tuple[bool, str, str]:
    """Strict crypto verification of one edge's send/ack timestamp evidence
    (gated by CrossHostPeerReviewAuthenticatorCheck.require_verified_edge_timestamps).

    By default the verifier only SHAPE-checks edge
    timestamps (responses-list non-empty; see _check_timestamp_evidence_shape),
    so a single host can back-date its own legitimately-signed edge — a
    bilateral-collusion attack PASSes with an attacker-chosen timestamp and no
    signature material at all. This
    binds the timestamp to verified crypto: a roughtime SREP MUST carry a real
    Ed25519 signature under a PINNED Roughtime root over a NONC that binds to
    THIS edge's send/ack preimage. A pinned root will not sign a 2009 MIDP
    today, and the preimage-bound nonce stops an SREP minted for another edge
    being transplanted onto this one.

    Returns (ok, reason_code, detail); reason_code='PASS' when ok.
    Scope: roughtime_quorum only. rfc3161_tsa edge-timestamp crypto wiring is
    deferred to v0.4 — under strict mode it is rejected as unverified rather
    than silently shape-accepted.
    """
    # Lazy import — keep the layer-A/cross-host path free of a hard layer-B dep.
    from audit_bundle.extensions.c19.tsa_roughtime_bls import (
        C19LayerBError,
        _expected_roughtime_nonce,
        _verify_srep,
    )

    code_prefix = (
        "ACK_TIMESTAMP_EVIDENCE" if role == "ack" else "SEND_TIMESTAMP_EVIDENCE"
    )
    kind = ev.get("kind")
    if kind != "roughtime_quorum":
        return (
            False,
            "EDGE_TIMESTAMP_UNVERIFIED",
            (
                f"{code_prefix}: strict edge-timestamp verification requires a "
                f"crypto-verifiable roughtime_quorum; kind={kind!r} carries no "
                "verifiable clock binding (rfc3161 edge-timestamp crypto is v0.4)"
            ),
        )
    responses = (ev.get("roughtime_quorum") or {}).get("responses") or []
    if not responses:
        return (
            False,
            "EDGE_TIMESTAMP_UNVERIFIED",
            f"{code_prefix}: empty roughtime_quorum.responses",
        )
    expected_nonce = _expected_roughtime_nonce(role, preimage)
    verified = 0
    for r_idx, srep in enumerate(responses):
        if not srep.get("srep_bytes_b64"):
            return (
                False,
                "EDGE_TIMESTAMP_UNVERIFIED",
                (
                    f"{code_prefix}: response[{r_idx}] carries no srep_bytes_b64 — "
                    "MIDP is attacker-asserted, not a signed Roughtime attestation "
                    "(shape-only timestamps are not a trusted clock)"
                ),
            )
        try:
            _verify_srep(
                srep,
                assurance_profile=assurance_profile,
                expected_nonce=expected_nonce,
            )
        except C19LayerBError as exc:
            return (
                False,
                type(exc).__name__,
                f"{code_prefix}: response[{r_idx}] SREP verification failed: {exc}",
            )
        verified += 1
    return (True, "PASS", f"{code_prefix}: {verified} SREP(s) crypto-verified")


# ---------------------------------------------------------------------------
# Plugin — real implementation
# ---------------------------------------------------------------------------


class CrossHostPeerReviewAuthenticatorCheck:
    """C19.B Cross-host PeerReview authenticator-pairing plugin.

    Reads cross-host edges from `manifest.causal_chain['cross_host_authenticators']`.
    Validates each edge against the cross-host attack model (replay,
    counter-monotonicity, key-substitution, mechanism-downgrade, ack-forgery,
    back-dating); returns first-failure-wins PluginResult with a specific message.

    External framing: reference implementation,
    soak-then-harden — NOT production-Byzantine-safe at v0.3. Full bilateral
    host collusion controlling M-of-N TS quorum remains a FORMAL DOCUMENTED
    LIMITATION; v0.4 may add a trusted third-party notary.
    """

    name: str = "cross_host_peerreview_authenticator"
    applies_to_files: frozenset[str] = frozenset()

    def __init__(
        self,
        cross_org_policy: "CrossOrgKeyPolicy | None" = None,
        *,
        require_verified_edge_timestamps: bool = False,
    ) -> None:
        """`cross_org_policy` is the verifier-side pinned key policy.
        It is supplied at verifier-binary build time (mirrors how
        DispatchRecordWellformedCheck takes op_kinds_admitted). When absent,
        cose_sign1 edges fail closed (CROSS_HOST_KEY_NOT_PINNED) — the verifier
        cannot route a cross-org COSE edge without a pinned kid policy.

        `require_verified_edge_timestamps`: when True, edge
        send/ack timestamp evidence is CRYPTO-verified — each roughtime SREP
        must carry a real Ed25519 signature under a pinned root over a NONC
        bound to the edge preimage (shape-only / back-dated evidence is rejected
        EDGE_TIMESTAMP_UNVERIFIED). Default False preserves the v0.3 behavior
        where edge timestamps are shape-checked ordering inputs only, NOT a
        trusted clock (the audit-bundle contract §OF-4)."""
        self.cross_org_policy = cross_org_policy
        self.require_verified_edge_timestamps = require_verified_edge_timestamps

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        # Backward compat: legacy bundles (pre-C19) carry causal_chain=None.
        if manifest.causal_chain is None:
            return PluginResult(
                ok=True,
                reason_code="PASS",
                detail="no causal_chain present (legacy bundle)",
                files_audited=(),
            )

        cc = manifest.causal_chain
        edges = cc.get("cross_host_authenticators")
        if edges is None:
            return PluginResult(
                ok=True,
                reason_code="PASS",
                detail="no cross_host_authenticators sub-key (single-host bundle)",
                files_audited=(),
            )
        if not isinstance(edges, list):
            return PluginResult(
                ok=False,
                reason_code="CROSS_HOST_AUTHENTICATORS_NOT_A_LIST",
                detail=f"manifest.causal_chain['cross_host_authenticators'] must be a list, got {type(edges).__name__}",
                files_audited=(),
            )
        if len(edges) == 0:
            return PluginResult(
                ok=True,
                reason_code="PASS",
                detail="cross_host_authenticators list is empty (no cross-host edges)",
                files_audited=(),
            )

        profile = _parse_profile(cc.get("assurance_profile"))
        min_ts, max_ts = ACK_TIMEOUT_BOUNDS_MS[profile]

        # Walk edges in order — counter monotonicity, challenge-token replay,
        # signature verification, edge-state reduction.
        sender_counter_high: dict[tuple, int] = {}
        receiver_counter_high: dict[tuple, int] = {}
        # Tier 7(b) hardening (2026-05-26): bundle-wide nonce uniqueness.
        # See check_cross_host_edge_set_stateful for the equivalent change on
        # the flat-schema path + rationale.
        challenge_tokens_seen: set = set()

        for idx, edge in enumerate(edges):
            res = self._check_edge(
                edge=edge,
                idx=idx,
                profile=profile,
                min_ts=min_ts,
                max_ts=max_ts,
                sender_counter_high=sender_counter_high,
                receiver_counter_high=receiver_counter_high,
                challenge_tokens_seen=challenge_tokens_seen,
            )
            if res is not None:
                return res

        # All edges TRUSTED — honest-disclosure surface. The same residuals the
        # prose detail carries are emitted as machine-readable disclosures so
        # they reach Completeness.disclosures on the LIBRARY verdict face
        # (assurance-labeling follow-up, 2026-06-10): a passing plugin's detail
        # is otherwise dropped by verify(), leaving a green verdict with no
        # trace of the reference-grade limitation. Downstream policy can key on
        # the "cross_host_peerreview:" prefix to refuse reference-grade
        # cross-host evidence; profile-level ENFORCEMENT (refusing it outright
        # under a regulated declared profile) remains the C19 completeness-
        # policy machinery's job.
        plugin_disclosures = [
            "cross_host_peerreview: v0.3 reference implementation — full "
            "bilateral host collusion controlling an M-of-N TS quorum is a "
            "formal documented limitation (soak-then-harden)",
        ]
        if not self.require_verified_edge_timestamps:
            plugin_disclosures.append(
                "cross_host_peerreview: edge send/ack timestamps are "
                "SHAPE-CHECKED ordering inputs only, NOT crypto-verified clock "
                "attestations (a host can back-date its own edge; enable "
                "require_verified_edge_timestamps to bind the clock)"
            )
        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail=(
                f"all {len(edges)} cross-host edge(s) TRUSTED under v0.3 "
                "reference implementation; "
                + (
                    "edge send/ack timestamps CRYPTO-VERIFIED against pinned "
                    "Roughtime roots (require_verified_edge_timestamps); "
                    if self.require_verified_edge_timestamps
                    else "edge send/ack timestamps are SHAPE-CHECKED ordering "
                    "inputs only, NOT crypto-verified clock attestations "
                    "(a host can back-date its own edge; enable "
                    "require_verified_edge_timestamps to bind the clock); "
                )
                + "full bilateral host collusion "
                "controlling M-of-N TS quorum is a formal documented limitation — "
                "v0.4 may add a trusted third-party notary; soak-then-harden"
            ),
            files_audited=(),
            disclosures=tuple(plugin_disclosures),
        )

    def _verify_cose_sig(
        self, *, sig_field, preimage, role, idx, expected_host_id
    ) -> PluginResult | None:
        """Verify a cose_sign1 sender/ack authenticator via the verifier-pinned
        cross-org policy, routing on the edge's kid and binding the kid to
        `expected_host_id` (sender kid↔sender_host, ack kid↔receiver_host).
        Returns None on PASS, PluginResult on failure."""
        kid_hex = sig_field.get("kid") if isinstance(sig_field, dict) else None
        if kid_hex is None:
            return PluginResult(
                ok=False,
                reason_code="CROSS_HOST_KEY_ID_MISSING",
                detail=f"edge[{idx}]: cose_sign1 {role} authenticator missing 'kid'",
                files_audited=(),
            )
        try:
            kid = bytes.fromhex(kid_hex)
        except (ValueError, TypeError):
            return PluginResult(
                ok=False,
                reason_code="CROSS_HOST_KEY_ID_FORMAT_INVALID",
                detail=f"edge[{idx}]: cose_sign1 {role} 'kid' is not valid hex",
                files_audited=(),
            )
        ok, code, detail = verify_cross_host_edge_authenticator(
            kid=kid,
            presented_kind="cose_sign1",
            preimage=preimage,
            authenticator=sig_field.get("cose"),
            policy=self.cross_org_policy,
            info_label=_CTX_SENDER if role == "sender" else _CTX_ACK,
            expected_host_id=expected_host_id,
            role=role,
        )
        if ok:
            return None
        return PluginResult(
            ok=False,
            reason_code=code,
            detail=f"edge[{idx}]: {detail}",
            files_audited=(),
        )

    def _check_edge(
        self,
        *,
        edge,
        idx,
        profile,
        min_ts,
        max_ts,
        sender_counter_high,
        receiver_counter_high,
        challenge_tokens_seen,
    ) -> PluginResult | None:
        """Validate one edge; return None on TRUSTED, PluginResult on failure."""
        # (1) Authenticator-kind gating.
        # cose_sign1 is now a real verified path (v0.4 migration); it fails
        # CLOSED if no verifier-pinned cross-org policy is available — the
        # signature steps (5/7) route on the pinned kid, never on this
        # bundle-supplied field.
        auth_kind = edge.get("authenticator_kind", "hmac")
        deployment_scope = edge.get("deployment_scope", "single_org")
        if auth_kind == "cose_sign1" and self.cross_org_policy is None:
            return PluginResult(
                ok=False,
                reason_code="CROSS_HOST_KEY_NOT_PINNED",
                detail=(
                    f"edge[{idx}]: cose_sign1 authenticator but no verifier-pinned "
                    "cross-org key policy is available; fails closed (the "
                    "verifier cannot route a COSE edge without a pinned kid)"
                ),
                files_audited=(),
            )
        if auth_kind == "hmac" and deployment_scope == "cross_org":
            return PluginResult(
                ok=False,
                reason_code="CROSS_HOST_AUTH_PROFILE_MISMATCH",
                detail=(
                    f"edge[{idx}]: HMAC cross-host authenticator is verifier-non-portable "
                    "outside the issuing organization; cross-organization deployments "
                    "MUST use COSE_Sign1 (RFC 9052 §4.2)."
                ),
                files_audited=(),
            )

        # (2) ack_timeout_ms within profile bounds.
        ack_timeout_ms = edge.get("ack_timeout_ms")
        if (
            not isinstance(ack_timeout_ms, int)
            or ack_timeout_ms < min_ts
            or ack_timeout_ms > max_ts
        ):
            return PluginResult(
                ok=False,
                reason_code="ACK_TIMEOUT_OUT_OF_PROFILE_BOUNDS",
                detail=(
                    f"edge[{idx}]: ack_timeout_ms={ack_timeout_ms!r} outside "
                    f"hardcoded profile bounds ({min_ts}, {max_ts}) for "
                    f"profile={profile.value}; bundle-supplied override is ignored"
                ),
                files_audited=(),
            )

        # (3) Counter monotonicity per (sender_host, channel) and (receiver_host, channel).
        sender_host_id = edge["sender_host_id"]
        receiver_host_id = edge["receiver_host_id"]
        channel_id = edge["channel_id"]
        sender_local_counter = edge["sender_local_counter"]
        receiver_local_counter = edge["receiver_local_counter"]
        sender_key = (sender_host_id, channel_id)
        if (
            sender_key in sender_counter_high
            and sender_local_counter <= sender_counter_high[sender_key]
        ):
            return PluginResult(
                ok=False,
                reason_code="COUNTER_GAP_DETECTED",
                detail=(
                    f"edge[{idx}]: sender_local_counter={sender_local_counter} "
                    f"not strictly increasing on (sender={sender_host_id!r}, "
                    f"channel={channel_id!r}); previous high="
                    f"{sender_counter_high[sender_key]}"
                ),
                files_audited=(),
            )
        sender_counter_high[sender_key] = sender_local_counter

        receiver_key = (receiver_host_id, channel_id)
        if (
            receiver_key in receiver_counter_high
            and receiver_local_counter <= receiver_counter_high[receiver_key]
        ):
            return PluginResult(
                ok=False,
                reason_code="COUNTER_GAP_DETECTED",
                detail=(
                    f"edge[{idx}]: receiver_local_counter={receiver_local_counter} "
                    f"not strictly increasing on (receiver={receiver_host_id!r}, "
                    f"channel={channel_id!r}); previous high="
                    f"{receiver_counter_high[receiver_key]}"
                ),
                files_audited=(),
            )
        receiver_counter_high[receiver_key] = receiver_local_counter

        # (4) Challenge-token replay — bundle-wide scope (Tier 7b widening,
        # 2026-05-26). Pre-7b scope was per (sender, receiver, channel); see
        # check_cross_host_edge_set_stateful for rationale.
        rct_hex = edge["receiver_challenge_token"]
        if rct_hex in challenge_tokens_seen:
            return PluginResult(
                ok=False,
                reason_code="CHALLENGE_TOKEN_REPLAY_DETECTED",
                detail=(
                    f"edge[{idx}]: receiver_challenge_token reused within "
                    f"bundle (sender={sender_host_id!r}, "
                    f"receiver={receiver_host_id!r}, channel={channel_id!r}); "
                    f"bundle-wide nonce uniqueness (Tier 7b — RCT must be a "
                    f"globally-fresh receiver-issued nonce)"
                ),
                files_audited=(),
            )
        challenge_tokens_seen.add(rct_hex)

        # (5) Sender_signature verification (PeerReview send-intent authenticator).
        try:
            sender_preimage = construct_sender_signature_preimage(
                sender_host_id=sender_host_id,
                receiver_host_id=receiver_host_id,
                channel_id=channel_id,
                message_id=edge["message_id"],
                message_hash=bytes.fromhex(edge["message_hash"]),
                sender_local_counter=sender_local_counter,
                ack_timeout_ms=ack_timeout_ms,
                bundle_id=edge["bundle_id"],
                receiver_challenge_token=bytes.fromhex(rct_hex),
            )
        except (KeyError, ValueError) as exc:
            return PluginResult(
                ok=False,
                reason_code="SENDER_PREIMAGE_MALFORMED",
                detail=f"edge[{idx}]: cannot construct sender preimage: {exc}",
                files_audited=(),
            )
        sig_field = edge["sender_signature"]
        if auth_kind == "cose_sign1":
            res = self._verify_cose_sig(
                sig_field=sig_field,
                preimage=sender_preimage,
                role="sender",
                idx=idx,
                expected_host_id=sender_host_id,
            )
            if res is not None:
                return res
        else:
            K_send_hex = sig_field.get("_test_only_K_send_hex")
            if K_send_hex is None:
                return PluginResult(
                    ok=False,
                    reason_code="SENDER_KEY_MATERIAL_UNAVAILABLE",
                    detail=(
                        f"edge[{idx}]: sender HMAC key material not available to "
                        "verifier; production deployments distribute K_send via "
                        "TUF (out-of-substrate scope)"
                    ),
                    files_audited=(),
                )
            K_send = bytes.fromhex(K_send_hex)
            sender_sig = bytes.fromhex(sig_field["sig"])
            if not verify_cross_host_authenticator(
                K=K_send, preimage=sender_preimage, sig=sender_sig
            ):
                return PluginResult(
                    ok=False,
                    reason_code="SENDER_SIGNATURE_VERIFICATION_FAILED",
                    detail=(
                        f"edge[{idx}]: HMAC-SHA256 verification of sender_signature "
                        "failed against recomputed deterministic-CBOR preimage; "
                        "common causes: tampered receiver_challenge_token, swapped "
                        "channel_id, mutated message_hash"
                    ),
                    files_audited=(),
                )

        # (6) Receiver_acknowledgment / timeout_witness — DISPUTED_EDGE vs UNVERIFIABLE_EDGE.
        ack = edge.get("receiver_acknowledgment")
        if ack is None:
            timeout_witness = edge.get("timeout_witness")
            if timeout_witness is not None:
                return PluginResult(
                    ok=False,
                    reason_code="UNVERIFIABLE_EDGE",
                    detail=(
                        f"edge[{idx}]: receiver_acknowledgment absent; "
                        "timeout_witness present (auditor-attested non-responsiveness); "
                        "non-advancement rule — downstream events MUST NOT "
                        "advance receiver's causal frontier"
                    ),
                    files_audited=(),
                )
            return PluginResult(
                ok=False,
                reason_code="DISPUTED_EDGE",
                detail=(
                    f"edge[{idx}]: receiver_acknowledgment absent within "
                    f"ack_timeout_ms={ack_timeout_ms}; no timeout_witness; "
                    "non-advancement rule"
                ),
                files_audited=(),
            )

        # (7) Ack signature verification (Haeberlen §5 symmetric authenticator).
        try:
            ack_preimage = construct_ack_preimage(
                sender_host_id=sender_host_id,
                receiver_host_id=receiver_host_id,
                channel_id=channel_id,
                message_id=edge["message_id"],
                message_hash=bytes.fromhex(edge["message_hash"]),
                receiver_local_counter=receiver_local_counter,
                kind=ack["kind"],
                reason_code_if_nack=ack.get("reason_code_if_nack"),
                bundle_id=edge["bundle_id"],
                ack_timeout_ms=ack_timeout_ms,
                sender_local_counter=sender_local_counter,
                receiver_challenge_token=bytes.fromhex(rct_hex),
            )
        except (KeyError, ValueError) as exc:
            return PluginResult(
                ok=False,
                reason_code="ACK_PREIMAGE_MALFORMED",
                detail=f"edge[{idx}]: cannot construct ack preimage: {exc}",
                files_audited=(),
            )
        if auth_kind == "cose_sign1":
            res = self._verify_cose_sig(
                sig_field=ack,
                preimage=ack_preimage,
                role="ack",
                idx=idx,
                expected_host_id=receiver_host_id,
            )
            if res is not None:
                return res
            ack_sig_ok = True
        else:
            ack_sig_ok = False
        K_ack_hex = None if ack_sig_ok else ack.get("_test_only_K_ack_hex")
        if not ack_sig_ok and K_ack_hex is None:
            return PluginResult(
                ok=False,
                reason_code="RECEIVER_KEY_MATERIAL_UNAVAILABLE",
                detail=f"edge[{idx}]: receiver HMAC key material not available",
                files_audited=(),
            )
        if not ack_sig_ok and not verify_cross_host_authenticator(
            K=bytes.fromhex(K_ack_hex),
            preimage=ack_preimage,
            sig=bytes.fromhex(ack["sig"]),
        ):
            return PluginResult(
                ok=False,
                reason_code="ACK_SIGNATURE_VERIFICATION_FAILED",
                detail=(
                    f"edge[{idx}]: HMAC-SHA256 verification of "
                    "receiver_acknowledgment.sig failed against recomputed "
                    "deterministic-CBOR preimage; per Haeberlen §5 symmetric "
                    "authenticator design, sender cannot forge ack without "
                    "receiver's K_cross_host_receipt_ack"
                ),
                files_audited=(),
            )

        # (8) Send/ack timestamp evidence shape.
        send_ev = edge.get("send_timestamp_evidence")
        if send_ev is None:
            return PluginResult(
                ok=False,
                reason_code="UNVERIFIABLE_EDGE",
                detail=(
                    f"edge[{idx}]: send_timestamp_evidence absent at "
                    f"profile={profile.value}"
                ),
                files_audited=(),
            )
        ok_shape, code, detail = _check_timestamp_evidence_shape(send_ev, "send")
        if not ok_shape:
            return PluginResult(
                ok=False,
                reason_code=code,
                detail=f"edge[{idx}]: {detail}",
                files_audited=(),
            )

        ack_ev = edge.get("ack_timestamp_evidence")
        if ack_ev is None:
            return PluginResult(
                ok=False,
                reason_code="UNVERIFIABLE_EDGE",
                detail=(
                    f"edge[{idx}]: ack_timestamp_evidence absent at "
                    f"profile={profile.value}"
                ),
                files_audited=(),
            )
        ok_shape, code, detail = _check_timestamp_evidence_shape(ack_ev, "ack")
        if not ok_shape:
            return PluginResult(
                ok=False,
                reason_code=code,
                detail=f"edge[{idx}]: {detail}",
                files_audited=(),
            )

        # (8b) Strict edge-timestamp crypto verification.
        # Opt-in via require_verified_edge_timestamps. When off, edge timestamps
        # remain shape-checked ordering inputs, NOT crypto-verified clock
        # attestations (a host can back-date its own edge) — see the audit-bundle
        # contract §OF-4. When on, the SREP signature + nonce
        # binding to this edge's preimage are verified against pinned roots.
        if self.require_verified_edge_timestamps:
            for ts_ev, ts_role, ts_pre in (
                (send_ev, "send", sender_preimage),
                (ack_ev, "ack", ack_preimage),
            ):
                ok_ts, ts_code, ts_detail = _crypto_verify_edge_timestamp_evidence(
                    ts_ev,
                    role=ts_role,
                    preimage=ts_pre,
                    assurance_profile=profile.value,
                )
                if not ok_ts:
                    return PluginResult(
                        ok=False,
                        reason_code=ts_code,
                        detail=f"edge[{idx}]: {ts_detail}",
                        files_audited=(),
                    )

        # (9) Conservative RADI-bounded timeliness inequality.
        try:
            send_midp, send_radi = _extract_send_bound_ms(send_ev)
            ack_midp, ack_radi = _extract_send_bound_ms(ack_ev)
        except (KeyError, ValueError) as exc:
            return PluginResult(
                ok=False,
                reason_code="UNVERIFIABLE_EDGE",
                detail=(
                    f"edge[{idx}]: cannot extract MIDP/RADI from timestamp_evidence: "
                    f"{exc}"
                ),
                files_audited=(),
            )
        send_lower = send_midp - send_radi
        ack_upper = ack_midp + ack_radi
        deadline = send_lower + ack_timeout_ms
        if ack_upper > deadline:
            return PluginResult(
                ok=False,
                reason_code="ACK_TIMELINESS_VIOLATION",
                detail=(
                    f"edge[{idx}]: ack_upper_bound={ack_upper} > "
                    f"send_lower_bound + ack_timeout_ms = {deadline}; "
                    "conservative RADI bounds applied; non-advancement rule"
                ),
                files_audited=(),
            )

        # Edge TRUSTED — fall through to caller's all-trusted PASS.
        return None


register_typed_check("cross_host_peerreview_authenticator")
