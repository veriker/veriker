"""C19 Layer A — SCITT-bound counter substrate (reference implementation).

v0.3 scope (reference-implementation grade, soak-then-harden):
  - SCITT statement issuance + receipt verification
  - Per-chain monotonic counter chain (per-chain, not HLC)
  - Hash-chain per RFC 8949 §4.2.1 deterministic CBOR
  - CDDL schema gate per RFC 8610 (verify-then-parse pipeline)
  - Receipt-bytes binding assertion
  - HKDF-derive-then-HMAC event signatures
  - Event-signature preimage canonical order: prev_event_hash between event_id
    and bundle_id

Standards bound: IETF SCITT `draft-ietf-scitt-architecture-22` + RFC 8949 +
RFC 8610 + RFC 5869 HKDF + RFC 2104 HMAC + RFC 9052 COSE_Sign1.

Sibling sub-modules: cross_host_peerreview.py, tsa_roughtime_bls.py.


"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any, Final

import cbor2

PROTOCOL_VERSION: Final[str] = "v0.3"


# ---------------------------------------------------------------------------
# Error code enumeration + LayerAVerificationError
# ---------------------------------------------------------------------------


class ReasonCode(str, Enum):
    # SCITT family
    SCITT_TS_KEY_MISMATCH = "SCITT_TS_KEY_MISMATCH"
    SCITT_RECEIPT_VERIFICATION_FAILED = "SCITT_RECEIPT_VERIFICATION_FAILED"
    SCITT_RECEIPT_PAYLOAD_MISMATCH = "SCITT_RECEIPT_PAYLOAD_MISMATCH"
    # Red-team B-3: the notarized statement content must equal the event's
    # leaf-bound payload_hash, else the SCITT receipt and the tree disagree on
    # what was decided (notary "DENY" vs leaf-bound "APPROVE" both verify green).
    SCITT_STATEMENT_PAYLOAD_DECOUPLED = "SCITT_STATEMENT_PAYLOAD_DECOUPLED"
    # CBOR-processing layer
    CBOR_DUPLICATE_KEY = "CBOR_DUPLICATE_KEY"
    CBOR_INDEFINITE_LENGTH = "CBOR_INDEFINITE_LENGTH"
    CBOR_TAG_NOT_ALLOWED = "CBOR_TAG_NOT_ALLOWED"
    CBOR_NOT_DETERMINISTIC = "CBOR_NOT_DETERMINISTIC"
    # CDDL
    CDDL_VALIDATION_FAILED = "CDDL_VALIDATION_FAILED"
    # Chain integrity
    COUNTER_GAP_DETECTED = "COUNTER_GAP_DETECTED"
    HASH_CHAIN_BROKEN = "HASH_CHAIN_BROKEN"
    EVENT_ID_DUPLICATE = "EVENT_ID_DUPLICATE"
    EVENT_KIND_UNKNOWN = "EVENT_KIND_UNKNOWN"
    # Signature
    EVENT_SIGNATURE_INVALID = "EVENT_SIGNATURE_INVALID"
    # Merkle
    MERKLE_ROOT_MISMATCH = "MERKLE_ROOT_MISMATCH"
    # Manifest header integrity (honest-anchor closure)
    MANIFEST_HEADER_LEAF_MISMATCH = "MANIFEST_HEADER_LEAF_MISMATCH"
    # Size guard
    BUNDLE_TOO_LARGE = "BUNDLE_TOO_LARGE"
    # Key rotation
    KEY_ROTATION_EVENT_SIGNED_BY_EXPIRED_KEY = (
        "KEY_ROTATION_EVENT_SIGNED_BY_EXPIRED_KEY"
    )
    KEY_ROTATION_CO_SIGNATURE_INVALID = "KEY_ROTATION_CO_SIGNATURE_INVALID"
    MISSING_PRE_COMMITMENT_SCITT_ID = "MISSING_PRE_COMMITMENT_SCITT_ID"
    PRE_COMMIT_WINDOW_VIOLATION = "PRE_COMMIT_WINDOW_VIOLATION"
    PRE_COMMIT_WINDOW_OUT_OF_PROFILE_BOUNDS = "PRE_COMMIT_WINDOW_OUT_OF_PROFILE_BOUNDS"
    MISSING_EMERGENCY_OFFLINE_ROOT_SIGNATURE = (
        "MISSING_EMERGENCY_OFFLINE_ROOT_SIGNATURE"
    )
    OFFLINE_ROOT_KEY_NOT_PINNED = "OFFLINE_ROOT_KEY_NOT_PINNED"
    OFFLINE_ROOT_SIGNATURE_INVALID = "OFFLINE_ROOT_SIGNATURE_INVALID"
    # C19.D v0.4 — offline root migrated to Ed25519/COSE_Sign1: fail-closed if
    # the COSE protected header carries an alg other than the pinned EdDSA.
    OFFLINE_ROOT_ALG_UNSUPPORTED = "OFFLINE_ROOT_ALG_UNSUPPORTED"


class LayerAVerificationError(Exception):
    """Raised by every Layer A verifier stage; each carries a distinct ReasonCode
    so the verify-then-parse pipeline does not collapse multiple
    failure modes into one error path."""

    def __init__(self, code: ReasonCode, detail: str = ""):
        self.code = code
        self.detail = detail
        super().__init__(f"{code.value}: {detail}")


# ---------------------------------------------------------------------------
# Deterministic-CBOR encoder (RFC 8949 §4.2.1)
# ---------------------------------------------------------------------------


_CANONICAL_ENCODER_KWARGS: Final = dict(
    canonical=True,
    timezone=None,
    date_as_datetime=False,
    string_referencing=False,
)


def deterministic_cbor_encode(obj: Any) -> bytes:
    """RFC 8949 §4.2.1 deterministic encode.

    Maps sorted by bytewise-lex of deterministic-encoded keys; integers in
    shortest form; no indefinite-length items emitted. cbor2's ``canonical=True``
    implements §4.2.1.
    """
    return cbor2.dumps(obj, **_CANONICAL_ENCODER_KWARGS)


# ---------------------------------------------------------------------------
# CBOR-processing-layer policy scanner (RFC 8949 §3.1)
# Runs BEFORE CDDL grammar validation to catch attack classes cbor2.loads()
# silently absorbs (duplicate keys, indefinite-length, unexpected tags).
# ---------------------------------------------------------------------------


_ALLOWED_CBOR_TAGS: Final[frozenset[int]] = frozenset({18})  # 18 = COSE_Sign1


def scan_cbor_for_policy_violations(blob: bytes) -> None:
    """Walk the CBOR byte stream BEFORE cbor2.loads and reject:
      - duplicate map keys per RFC 8949 §3.1 (cbor2 silently overwrites)
      - indefinite-length items per RFC 8949 §4.2.1
      - CBOR tags outside _ALLOWED_CBOR_TAGS

    Raises LayerAVerificationError with the matching ReasonCode.

    Bounded recursive descent over the major-type / additional-info byte pairs
    of the CBOR stream — sufficient for the bundle schema's depth (<= 6 levels).
    NOT a general-purpose CBOR parser; only the subset needed to identify these
    three policy violations.
    """
    pos = [0]

    def _read_uint(ai: int) -> int:
        # additional info 0..23 -> value is ai itself
        if ai < 24:
            return ai
        if ai == 24:
            v = blob[pos[0]]
            pos[0] += 1
            return v
        if ai == 25:
            v = int.from_bytes(blob[pos[0] : pos[0] + 2], "big")
            pos[0] += 2
            return v
        if ai == 26:
            v = int.from_bytes(blob[pos[0] : pos[0] + 4], "big")
            pos[0] += 4
            return v
        if ai == 27:
            v = int.from_bytes(blob[pos[0] : pos[0] + 8], "big")
            pos[0] += 8
            return v
        if ai == 31:
            # Indefinite-length marker (only valid for major types 2..5,7).
            raise LayerAVerificationError(
                ReasonCode.CBOR_INDEFINITE_LENGTH,
                detail=f"indefinite-length item at byte {pos[0] - 1}",
            )
        raise LayerAVerificationError(
            ReasonCode.CBOR_NOT_DETERMINISTIC,
            detail=f"reserved additional-info {ai} at byte {pos[0] - 1}",
        )

    def _walk() -> None:
        if pos[0] >= len(blob):
            raise LayerAVerificationError(
                ReasonCode.CBOR_NOT_DETERMINISTIC, detail="unexpected EOF"
            )
        ib = blob[pos[0]]
        pos[0] += 1
        mt = ib >> 5
        ai = ib & 0x1F
        if mt in (0, 1):
            _read_uint(ai)
            return
        if mt in (2, 3):
            length = _read_uint(ai)
            pos[0] += length
            return
        if mt == 4:
            length = _read_uint(ai)
            for _ in range(length):
                _walk()
            return
        if mt == 5:
            length = _read_uint(ai)
            seen_key_bytes: set[bytes] = set()
            for _ in range(length):
                key_start = pos[0]
                _walk()
                key_bytes = blob[key_start : pos[0]]
                if key_bytes in seen_key_bytes:
                    raise LayerAVerificationError(
                        ReasonCode.CBOR_DUPLICATE_KEY,
                        detail=f"duplicate map key bytes at {key_start}",
                    )
                seen_key_bytes.add(key_bytes)
                _walk()  # value
            return
        if mt == 6:
            tag = _read_uint(ai)
            if tag not in _ALLOWED_CBOR_TAGS:
                raise LayerAVerificationError(
                    ReasonCode.CBOR_TAG_NOT_ALLOWED,
                    detail=f"CBOR tag {tag} not in allowlist",
                )
            _walk()
            return
        if mt == 7:
            # major type 7: simple values (false/true/null/undef) + floats.
            # ai 20..23 are simple values; 24 = one-byte simple; 25..27 = floats.
            # No special policy on these for v0.3 (none appear in our schema
            # except false/true/null which we accept silently).
            if ai == 31:
                raise LayerAVerificationError(
                    ReasonCode.CBOR_INDEFINITE_LENGTH,
                    detail=f"indefinite-length break at byte {pos[0] - 1}",
                )
            if ai >= 24 and ai != 24:
                pos[0] += {25: 2, 26: 4, 27: 8}.get(ai, 0)
            elif ai == 24:
                pos[0] += 1
            return

    _walk()


# ---------------------------------------------------------------------------
# RFC 5869 HKDF (Extract + Expand) — salt=0x00*32 + SHA-256 PRF (RFC 6234).
# ---------------------------------------------------------------------------


_HKDF_HASH = hashlib.sha256
_HKDF_HASH_LEN: Final[int] = 32  # SHA-256 output length


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 §2.2: PRK = HMAC-Hash(salt, IKM).

    Per §2.2 step 1, if salt is empty, substitute HashLen zero octets.
    """
    if len(salt) == 0:
        salt = b"\x00" * _HKDF_HASH_LEN
    return _hmac.new(salt, ikm, _HKDF_HASH).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 §2.3: OKM = HKDF-Expand(PRK, info, L).

    T(0) = empty;
    T(i) = HMAC-Hash(PRK, T(i-1) || info || i)  for i = 1..N
    OKM  = T(1) || T(2) || ... || T(N)  truncated to L bytes.
    """
    if length > 255 * _HKDF_HASH_LEN:
        raise ValueError("requested length exceeds 255*HashLen")
    t = b""
    okm = b""
    counter = 1
    while len(okm) < length:
        t = _hmac.new(prk, t + info + bytes([counter]), _HKDF_HASH).digest()
        okm += t
        counter += 1
    return okm[:length]


# Per-context HKDF key-derivation labels. These exact byte strings are
# load-bearing: bytewise identity across implementations is the security
# property, so never paraphrase them.
_CTX_EVENT: Final[bytes] = b"nexi/audit/v0.3/event"
_CTX_CROSS_HOST_RECEIPT: Final[bytes] = b"nexi/audit/v0.3/cross-host-receipt"
_CTX_CROSS_HOST_RECEIPT_ACK: Final[bytes] = b"nexi/audit/v0.3/cross-host-receipt-ack"
_CTX_KEY_ROTATION: Final[bytes] = b"nexi/audit/v0.3/key-rotation"
_CTX_MANIFEST_DAG: Final[bytes] = b"nexi/audit/v0.3/manifest-dag"


def derive_event_signature_key(host_signing_key_material: bytes) -> bytes:
    """HKDF-derive the per-event signing key.

      PRK     = HKDF-Extract(salt=0x00*32, IKM=host_signing_key_material)
      K_event = HKDF-Expand(PRK, info="nexi/audit/v0.3/event", L=32)

    Returns K_event — a 32-byte HMAC KEY. NOT a message prefix.
    """
    prk = _hkdf_extract(salt=b"", ikm=host_signing_key_material)
    return _hkdf_expand(prk, info=_CTX_EVENT, length=32)


def canonical_event_preimage(
    *,
    host_id: str,
    event_id: str,
    prev_event_hash: bytes,
    bundle_id: str,
    monotonic_counter: int,
    payload_hash: bytes,
) -> bytes:
    """Canonical event-signature preimage tuple.

    `prev_event_hash` sits BETWEEN `event_id` and `bundle_id`.

    ORDER IS LOAD-BEARING — any other ordering produces distinct HMAC output
    and fails test_preimage_canonical_order_locked.

    Tuple shape:
      [context_label, protocol_version, host_id, event_id, prev_event_hash,
       bundle_id, monotonic_counter, payload_hash]
    """
    preimage_tuple = [
        _CTX_EVENT.decode("ascii"),
        PROTOCOL_VERSION,
        host_id,
        event_id,
        prev_event_hash,
        bundle_id,
        monotonic_counter,
        payload_hash,
    ]
    return deterministic_cbor_encode(preimage_tuple)


def compute_event_signature(k_event: bytes, preimage: bytes) -> bytes:
    """event_sig = HMAC-SHA256(K_event, deterministic_cbor(preimage_tuple)).

    Caller passes the output of canonical_event_preimage() as `preimage`.
    Returns 32-byte HMAC digest.
    """
    return _hmac.new(k_event, preimage, hashlib.sha256).digest()


def verify_event_signature(k_event: bytes, preimage: bytes, sig: bytes) -> bool:
    """Constant-time HMAC compare (RFC 2104 §5 implementation guidance)."""
    return _hmac.compare_digest(
        _hmac.new(k_event, preimage, hashlib.sha256).digest(),
        sig,
    )


# ---------------------------------------------------------------------------
# Key rotation primitives. Reuses the _CTX_KEY_ROTATION HKDF context label
# allocated above.
# ---------------------------------------------------------------------------


def derive_key_rotation_subkey_old(host_signing_key_material_old: bytes) -> bytes:
    """K_key_rotation_old = HKDF-Expand(PRK_old, info=_CTX_KEY_ROTATION, L=32).

    Same construction as derive_event_signature_key(); distinct info label.
    Caller supplies the OLD host signing key material IKM; returns the
    32-byte HMAC key the old key uses to co-sign the rotation preimage.
    """
    prk = _hkdf_extract(salt=b"", ikm=host_signing_key_material_old)
    return _hkdf_expand(prk, info=_CTX_KEY_ROTATION, length=32)


def derive_key_rotation_subkey_new(host_signing_key_material_new: bytes) -> bytes:
    """K_key_rotation_new — symmetric to derive_key_rotation_subkey_old over
    the NEW host signing key material."""
    prk = _hkdf_extract(salt=b"", ikm=host_signing_key_material_new)
    return _hkdf_expand(prk, info=_CTX_KEY_ROTATION, length=32)


def canonical_rotation_preimage(
    *,
    host_id: str,
    old_key_id: str,
    new_key_id: str,
    new_key_pre_commitment_scitt_id: str,
    valid_not_before: str,
    valid_not_after: str | None,
    rotation_reason: str,
) -> bytes:
    """Deterministic-CBOR canonical preimage for the rotation co-signatures
    AND the emergency offline-root signature.

    Tuple shape (ORDER IS LOAD-BEARING):

      [context_label_str, protocol_version, host_id,
       old_key_id, new_key_id,
       new_key_pre_commitment_scitt_id,
       valid_not_before, valid_not_after_or_null,
       rotation_reason]

    rotation_reason must be one of {'scheduled', 'compromise',
    'scheduled-then-compromise', 'emergency'}.
    """
    return deterministic_cbor_encode(
        [
            _CTX_KEY_ROTATION.decode("ascii"),
            PROTOCOL_VERSION,
            host_id,
            old_key_id,
            new_key_id,
            new_key_pre_commitment_scitt_id,
            valid_not_before,
            valid_not_after,
            rotation_reason,
        ]
    )


def compute_rotation_co_signature(k_rotation: bytes, preimage: bytes) -> bytes:
    """HMAC-SHA256(K_key_rotation_{old|new}, deterministic_cbor(preimage))."""
    return _hmac.new(k_rotation, preimage, hashlib.sha256).digest()


def verify_rotation_co_signatures(
    *,
    k_rotation_old: bytes,
    k_rotation_new: bytes,
    preimage: bytes,
    co_signed_old: bytes,
    co_signed_new: bytes,
) -> None:
    """Verify both co-signatures using constant-time HMAC compare.

    Raises LayerAVerificationError(KEY_ROTATION_CO_SIGNATURE_INVALID) on
    either old or new co-signature failure. Emergency-path callers supply
    co_signed_old=b"" (zero-length) and dispatch to
    verify_emergency_offline_root_signature() instead — this function is
    NOT for emergency paths.
    """
    expected_old = _hmac.new(k_rotation_old, preimage, hashlib.sha256).digest()
    if not _hmac.compare_digest(expected_old, co_signed_old):
        raise LayerAVerificationError(
            ReasonCode.KEY_ROTATION_CO_SIGNATURE_INVALID,
            detail="co_signed_old does not verify under K_key_rotation_old",
        )
    expected_new = _hmac.new(k_rotation_new, preimage, hashlib.sha256).digest()
    if not _hmac.compare_digest(expected_new, co_signed_new):
        raise LayerAVerificationError(
            ReasonCode.KEY_ROTATION_CO_SIGNATURE_INVALID,
            detail="co_signed_new does not verify under K_key_rotation_new",
        )


def detect_and_verify_rotation_event(
    *,
    event: dict,
    assurance_profile: str,
    pinned_ts_key_ids: frozenset[bytes],
    pinned_ts_verifying_keys: dict,
    pinned_offline_root_key_ids: frozenset[bytes],
    pinned_offline_root_verifying_keys: dict,
    host_signing_keys_by_kid: dict,
) -> dict:
    """Verify a key_rotation event. Returns a dict with the (key_id ->
    validity-window) entry the chain walker will use to enforce B10 pre-rotation
    forge rejection.

    Designated handler for events with event_kind == 'key_rotation'. NOT YET
    wired into the live path: verify_bundle_layer_a / _verify_layer_a_pipeline
    do not dispatch to it (the live path admits the rotation event SHAPE via
    validate_event_keys_str but does not enforce rotation windows). Exercised
    by tests/extensions/c19/test_key_rotation.py + test_m7_crypto_extension_did
    only — pre-ceremony keel, pending a rotation stage in the pipeline.
    Raises LayerAVerificationError with the matching ReasonCode on any failure.
    """
    from audit_bundle.extensions.c19.offline_root import (
        verify_emergency_offline_root_signature,
    )
    from audit_bundle.extensions.c19.pre_commit_log import (
        verify_pre_commit_predates_rotation,
        verify_pre_commit_scitt_statement,
    )

    def _g(key: str):
        bk = key.encode("ascii") if isinstance(key, str) else key
        if bk in event:
            return event[bk]
        if key in event:
            return event[key]
        return None

    host_id_v = _g("host_id")
    old_key_id_v = _g("old_key_id")
    new_key_id_v = _g("new_key_id")
    pre_commit_scitt_id_v = _g("new_key_pre_commitment_scitt_id")
    valid_not_before_v = _g("valid_not_before")
    valid_not_after_v = _g("valid_not_after")
    rotation_reason_v = _g("rotation_reason")
    rotation_at_v = _g("rotation_at")
    co_signed_old_v = _g("co_signed_old_key")
    co_signed_new_v = _g("co_signed_new_key")
    offline_sig_v = _g("emergency_offline_root_signature")
    offline_kid_v = _g("offline_root_key_id")
    pre_commit_receipt_v = _g("new_key_pre_commitment_scitt_receipt")

    if not isinstance(rotation_reason_v, str) or rotation_reason_v not in {
        "scheduled",
        "compromise",
        "scheduled-then-compromise",
        "emergency",
    }:
        raise LayerAVerificationError(
            ReasonCode.CDDL_VALIDATION_FAILED,
            detail=f"rotation_reason invalid: {rotation_reason_v!r}",
        )

    if not pre_commit_scitt_id_v:
        raise LayerAVerificationError(
            ReasonCode.MISSING_PRE_COMMITMENT_SCITT_ID,
            detail="new_key_pre_commitment_scitt_id is absent or empty",
        )

    preimage = canonical_rotation_preimage(
        host_id=host_id_v,
        old_key_id=old_key_id_v,
        new_key_id=new_key_id_v,
        new_key_pre_commitment_scitt_id=pre_commit_scitt_id_v,
        valid_not_before=valid_not_before_v,
        valid_not_after=valid_not_after_v,
        rotation_reason=rotation_reason_v,
    )

    is_emergency = rotation_reason_v == "emergency" or not co_signed_old_v

    if not is_emergency:
        ikm_old = host_signing_keys_by_kid.get(old_key_id_v)
        ikm_new = host_signing_keys_by_kid.get(new_key_id_v)
        if ikm_old is None or ikm_new is None:
            raise LayerAVerificationError(
                ReasonCode.KEY_ROTATION_CO_SIGNATURE_INVALID,
                detail="host signing-key material not supplied for old or new key_id",
            )
        k_old = derive_key_rotation_subkey_old(ikm_old)
        k_new = derive_key_rotation_subkey_new(ikm_new)
        verify_rotation_co_signatures(
            k_rotation_old=k_old,
            k_rotation_new=k_new,
            preimage=preimage,
            co_signed_old=bytes(co_signed_old_v),
            co_signed_new=bytes(co_signed_new_v) if co_signed_new_v else b"",
        )
    else:
        verify_emergency_offline_root_signature(
            rotation_preimage=preimage,
            emergency_offline_root_signature=offline_sig_v,
            offline_root_key_id=offline_kid_v,
            policy=_OfflineRootPolicyView(
                pinned_offline_root_key_ids=pinned_offline_root_key_ids,
                pinned_offline_root_verifying_keys=pinned_offline_root_verifying_keys,
            ),
        )

    if pre_commit_receipt_v is None:
        raise LayerAVerificationError(
            ReasonCode.MISSING_PRE_COMMITMENT_SCITT_ID,
            detail="new_key_pre_commitment_scitt_receipt bytes absent",
        )
    # The event field carries raw COSE_Sign1 envelope bytes (bytes or hex);
    # verify_pre_commit_scitt_statement expects a ScittReceipt. The old code
    # passed the raw value straight through, which could only AttributeError —
    # decode into a ScittReceipt here (mirrors the stage-1.5 pipeline shape).
    if isinstance(pre_commit_receipt_v, ScittReceipt):
        pre_commit_receipt = pre_commit_receipt_v
    else:
        if isinstance(pre_commit_receipt_v, (bytes, bytearray)):
            receipt_blob = bytes(pre_commit_receipt_v)
        elif isinstance(pre_commit_receipt_v, str):
            try:
                receipt_blob = bytes.fromhex(pre_commit_receipt_v)
            except ValueError as exc:
                raise LayerAVerificationError(
                    ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
                    detail=f"new_key_pre_commitment_scitt_receipt not hex: {exc}",
                ) from exc
        else:
            raise LayerAVerificationError(
                ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
                detail=(
                    "new_key_pre_commitment_scitt_receipt must be COSE_Sign1 "
                    f"bytes/hex or ScittReceipt; got {type(pre_commit_receipt_v).__name__}"
                ),
            )
        _, _, pre_commit_payload, _ = _decode_cose_sign1(receipt_blob)
        pre_commit_receipt = ScittReceipt(
            statement_id=hashlib.sha256(receipt_blob).digest(),
            statement_content_sha256=hashlib.sha256(pre_commit_payload).digest(),
            cose_payload_bytes=pre_commit_payload,
            receipt_bytes=receipt_blob,
            ts_key_id=_ts_key_id_from_receipt(receipt_blob),
        )
    # Exogenous binding to the co-signed rotation preimage: when the co-signed
    # new_key_pre_commitment_scitt_id is a sha256 hex, the receipt must BE the
    # pre-committed statement (id == sha256 of the envelope or of its payload).
    # Opaque (non-hex-64) ids carry no recomputable binding — disclosed gap;
    # the receipt is still TS-signature-verified and host/new-key checked.
    if isinstance(pre_commit_scitt_id_v, str) and len(pre_commit_scitt_id_v) == 64:
        try:
            id_bytes = bytes.fromhex(pre_commit_scitt_id_v)
        except ValueError:
            id_bytes = None
        if id_bytes is not None and id_bytes not in (
            hashlib.sha256(pre_commit_receipt.receipt_bytes).digest(),
            hashlib.sha256(pre_commit_receipt.cose_payload_bytes).digest(),
            pre_commit_receipt.statement_content_sha256,
        ):
            raise LayerAVerificationError(
                ReasonCode.SCITT_RECEIPT_PAYLOAD_MISMATCH,
                detail=(
                    "new_key_pre_commitment_scitt_receipt does not match the "
                    "co-signed new_key_pre_commitment_scitt_id (receipt is not "
                    "the pre-committed statement)"
                ),
            )
    verify_pre_commit_scitt_statement(
        receipt=pre_commit_receipt,
        pinned_ts_key_ids=pinned_ts_key_ids,
        pinned_ts_verifying_keys=pinned_ts_verifying_keys,
        expected_host_id=host_id_v,
        expected_new_key_id=new_key_id_v,
    )

    pre_commit_issuance = _g("pre_commit_issuance_iso8601") or _g("issuance_at")
    if pre_commit_issuance is None:
        raise LayerAVerificationError(
            ReasonCode.MISSING_PRE_COMMITMENT_SCITT_ID,
            detail="pre_commit issuance timestamp not supplied",
        )
    verify_pre_commit_predates_rotation(
        pre_commit_issuance_iso8601=pre_commit_issuance,
        rotation_at_iso8601=rotation_at_v or valid_not_before_v,
        assurance_profile=assurance_profile,
    )

    return {
        old_key_id_v: (
            None,
            valid_not_before_v,
        ),
        new_key_id_v: (valid_not_before_v, valid_not_after_v),
    }


class _OfflineRootPolicyView:
    """Lightweight adapter passed from detect_and_verify_rotation_event so the
    offline_root verifier sees the same shape as OfflineRootPolicy without an
    import cycle here. Mirrors the OfflineRootPolicy dataclass attributes.
    """

    def __init__(
        self,
        *,
        pinned_offline_root_key_ids: frozenset[bytes],
        pinned_offline_root_verifying_keys: dict,
    ):
        self.pinned_offline_root_key_ids = pinned_offline_root_key_ids
        self.pinned_offline_root_verifying_keys = pinned_offline_root_verifying_keys


# ---------------------------------------------------------------------------
# CDDL schema gate (RFC 8610) — structural validation on TRUSTED bytes only.
# Runs AFTER scan_cbor_for_policy_violations (CBOR-layer policy precedes the
# CDDL grammar check).
# Hash fields carry raw 32-byte SHA-256 digests at this layer (bytes), not hex.
# ---------------------------------------------------------------------------


from audit_bundle.bundle_manifest import V0_3_EVENT_KINDS  # noqa: E402


# v0.3 bounded-list ceilings.
MAX_EVENTS_PER_BUNDLE: Final[int] = 100_000
MAX_CAUSAL_DEPS_PER_EVENT: Final[int] = 16


_EVENT_REQUIRED_KEYS_BYTES: Final[frozenset[bytes]] = frozenset(
    {
        b"event_id",
        b"prev_event_id",
        b"prev_event_hash",
        b"monotonic_counter",
        b"counter_log_index",
        b"scitt_statement_id",
        b"scitt_statement_content_sha256",
        b"scitt_inclusion_proof",
        b"event_kind",
        b"payload_hash",
        b"event_signature",
        b"causal_dependencies",
    }
)

_EVENT_OPTIONAL_KEYS_BYTES: Final[frozenset[bytes]] = frozenset(
    {
        b"timestamp_evidence",  # populated by the TSA/Roughtime path
        b"cross_host_edge",  # populated by the cross-host path
    }
)


def validate_event_cddl(event: dict) -> None:
    """Structural CDDL gate on a CBOR-decoded event map (bytes-keyed).

    Contract reference for the bytes-keyed CDDL rules. The live JSON path
    does NOT call this — it enforces the mirrored rules via the str-keyed
    validate_event_keys_str (deliberate, M7: divergences from this contract
    are documented at that mirror, not silently absorbed here).

    Distinct error codes:
      * EVENT_KIND_UNKNOWN     — event_kind not in V0_3_EVENT_KINDS (fail-closed
                                 forward-incompat; mirrors TIMESTAMP_EVIDENCE_UNKNOWN_KIND)
      * CDDL_VALIDATION_FAILED — every other structural failure
    """
    if not isinstance(event, dict):
        raise LayerAVerificationError(
            ReasonCode.CDDL_VALIDATION_FAILED,
            detail=f"event must be CBOR map; got {type(event).__name__}",
        )
    keys = set(event.keys())
    missing = _EVENT_REQUIRED_KEYS_BYTES - keys
    if missing:
        raise LayerAVerificationError(
            ReasonCode.CDDL_VALIDATION_FAILED,
            detail=f"missing required keys: {sorted(k.decode() for k in missing)}",
        )
    unknown = keys - _EVENT_REQUIRED_KEYS_BYTES - _EVENT_OPTIONAL_KEYS_BYTES
    if unknown:
        raise LayerAVerificationError(
            ReasonCode.CDDL_VALIDATION_FAILED,
            detail=f"unknown keys: {sorted(_decode_keys(unknown))}",
        )

    # event_kind first — its own distinct error code per fail-closed property.
    if event[b"event_kind"] not in V0_3_EVENT_KINDS:
        raise LayerAVerificationError(
            ReasonCode.EVENT_KIND_UNKNOWN,
            detail=f"event_kind={event[b'event_kind']!r} not in V0_3_EVENT_KINDS",
        )

    if not isinstance(event[b"event_id"], str):
        raise LayerAVerificationError(
            ReasonCode.CDDL_VALIDATION_FAILED, detail="event_id must be str"
        )
    if event[b"prev_event_id"] is not None and not isinstance(
        event[b"prev_event_id"], str
    ):
        raise LayerAVerificationError(
            ReasonCode.CDDL_VALIDATION_FAILED,
            detail="prev_event_id must be str or None",
        )
    for raw_field in (
        b"prev_event_hash",
        b"scitt_statement_id",
        b"scitt_statement_content_sha256",
        b"payload_hash",
    ):
        v = event[raw_field]
        if not isinstance(v, (bytes, bytearray)) or len(v) != 32:
            raise LayerAVerificationError(
                ReasonCode.CDDL_VALIDATION_FAILED,
                detail=f"{raw_field.decode()} must be 32 raw bytes",
            )
    if (
        not isinstance(event[b"monotonic_counter"], int)
        or event[b"monotonic_counter"] < 1
    ):
        raise LayerAVerificationError(
            ReasonCode.CDDL_VALIDATION_FAILED,
            detail="monotonic_counter must be int >= 1",
        )
    if not isinstance(event[b"counter_log_index"], int):
        raise LayerAVerificationError(
            ReasonCode.CDDL_VALIDATION_FAILED, detail="counter_log_index must be int"
        )
    if not isinstance(event[b"scitt_inclusion_proof"], (bytes, bytearray)):
        raise LayerAVerificationError(
            ReasonCode.CDDL_VALIDATION_FAILED,
            detail="scitt_inclusion_proof must be bytes (COSE_Sign1)",
        )
    deps = event[b"causal_dependencies"]
    if not isinstance(deps, list) or len(deps) > MAX_CAUSAL_DEPS_PER_EVENT:
        raise LayerAVerificationError(
            ReasonCode.CDDL_VALIDATION_FAILED,
            detail=f"causal_dependencies must be list with len <= {MAX_CAUSAL_DEPS_PER_EVENT}",
        )
    sig = event[b"event_signature"]
    if not isinstance(sig, dict):
        raise LayerAVerificationError(
            ReasonCode.CDDL_VALIDATION_FAILED, detail="event_signature must be dict"
        )
    sig_key_id = (
        sig.get("key_id") if isinstance(sig.get("key_id"), str) else sig.get(b"key_id")
    )
    sig_value = (
        sig.get("sig")
        if isinstance(sig.get("sig"), (bytes, bytearray))
        else sig.get(b"sig")
    )
    if not isinstance(sig_key_id, str):
        raise LayerAVerificationError(
            ReasonCode.CDDL_VALIDATION_FAILED,
            detail="event_signature.key_id must be str",
        )
    if not isinstance(sig_value, (bytes, bytearray)) or len(sig_value) != 32:
        raise LayerAVerificationError(
            ReasonCode.CDDL_VALIDATION_FAILED,
            detail="event_signature.sig must be 32 raw bytes",
        )


def _decode_keys(keys: set) -> list:
    out = []
    for k in keys:
        if isinstance(k, (bytes, bytearray)):
            try:
                out.append(k.decode())
            except UnicodeDecodeError:
                out.append(repr(bytes(k)))
        else:
            out.append(str(k))
    return sorted(out)


# Str-keyed twin of the bytes-keyed CDDL sets above, for the LIVE manifest
# path (`causal_chain['layer_a']` arrives JSON-decoded, so events are
# str-keyed). Divergences from the bytes contract, both deliberate:
#   * causal_dependencies is OPTIONAL here (validated when present) — the
#     deployed str contract never required it, and retroactively requiring it
#     would invalidate previously-valid bundles.
#   * host_id is ADMITTED (typed, non-empty str) — stage 6 reads it to select
#     the per-event issuer key, so it must be in the validated key set rather
#     than ride as an arbitrary unvalidated extra.
_EVENT_REQUIRED_KEYS_STR: Final[frozenset[str]] = frozenset(
    {
        "event_id",
        "prev_event_id",
        "prev_event_hash",
        "monotonic_counter",
        "counter_log_index",
        "scitt_statement_id",
        "scitt_statement_content_sha256",
        "scitt_inclusion_proof",
        "event_kind",
        "payload_hash",
        "event_signature",
    }
)

_EVENT_OPTIONAL_KEYS_STR: Final[frozenset[str]] = frozenset(
    {
        "causal_dependencies",
        "host_id",
        "timestamp_evidence",  # populated by the TSA/Roughtime path
        "cross_host_edge",  # populated by the cross-host path
        "scitt_inclusion_proof_bytes",  # hex-serialized alias (_extract_receipt_bytes)
    }
)

# key_rotation events additionally carry the S19d rotation surface consumed by
# detect_and_verify_rotation_event (each field is bound by the rotation
# co-signature preimage or checked there).
_ROTATION_EVENT_EXTRA_KEYS_STR: Final[frozenset[str]] = frozenset(
    {
        "old_key_id",
        "new_key_id",
        "rotation_reason",
        "new_key_pre_commitment_scitt_id",
        "new_key_pre_commitment_scitt_receipt",
        "pre_commit_issuance_iso8601",
        "issuance_at",
        "rotation_at",
        "valid_not_before",
        "valid_not_after",
        "co_signed_old_key",
        "co_signed_new_key",
        "emergency_offline_root_signature",
        "offline_root_key_id",
    }
)


def validate_event_keys_str(event: dict, *, idx: int) -> None:
    """Strict key gate for a str-keyed (JSON-decoded) live-path event.

    The looser shape validator in bundle_manifest checks required keys + field
    formats but does NOT reject extra keys; this gate closes that (mirrors the
    bytes-keyed validate_event_cddl's unknown-key rejection on the path that
    actually runs). Runs AFTER validate_causal_chain_layer_a_shape, so
    required-key presence and hex formats are already established.
    """
    allowed = _EVENT_REQUIRED_KEYS_STR | _EVENT_OPTIONAL_KEYS_STR
    if event.get("event_kind") == "key_rotation":
        allowed = allowed | _ROTATION_EVENT_EXTRA_KEYS_STR
    unknown = set(event.keys()) - allowed
    if unknown:
        raise LayerAVerificationError(
            ReasonCode.CDDL_VALIDATION_FAILED,
            detail=f"events[{idx}]: unknown keys: {sorted(_decode_keys(unknown))}",
        )
    host_id = event.get("host_id")
    if host_id is not None and (not isinstance(host_id, str) or not host_id):
        raise LayerAVerificationError(
            ReasonCode.CDDL_VALIDATION_FAILED,
            detail=f"events[{idx}]: host_id must be a non-empty str when present",
        )
    deps = event.get("causal_dependencies")
    if deps is not None and (
        not isinstance(deps, list) or len(deps) > MAX_CAUSAL_DEPS_PER_EVENT
    ):
        raise LayerAVerificationError(
            ReasonCode.CDDL_VALIDATION_FAILED,
            detail=(
                f"events[{idx}]: causal_dependencies must be list with "
                f"len <= {MAX_CAUSAL_DEPS_PER_EVENT}"
            ),
        )


# ---------------------------------------------------------------------------
# SCITT statement issuance + receipt verification per
#   draft-ietf-scitt-architecture-22 §4 + RFC 9052 §4.2 (COSE_Sign1)
# ---------------------------------------------------------------------------


# COSE label conventions per RFC 9052 §3.1.
_COSE_LABEL_ALG: Final[int] = 1
_COSE_LABEL_KID: Final[int] = 4

# alg allowlist: EdDSA (-8), ES256 (-7). alg=none PROHIBITED.
_ALLOWED_COSE_ALG: Final[frozenset[int]] = frozenset({-8, -7})


@dataclass(frozen=True)
class ScittReceipt:
    """SCITT receipt per draft-ietf-scitt-architecture-22 §4. COSE_Sign1
    envelope; the COSE payload bytes equal the bytes whose SHA-256
    statement_content_sha256 hashes.
    """

    statement_id: bytes
    statement_content_sha256: bytes
    cose_payload_bytes: bytes
    receipt_bytes: bytes
    ts_key_id: bytes


def issue_scitt_statement(
    *,
    issuer_signing_key,
    issuer_kid: bytes,
    payload: Any,
    alg: int = -8,
) -> tuple[bytes, bytes]:
    """Issue a Signed Statement per SCITT §4 + RFC 9052 §4.2.

    Returns (statement_bytes, statement_content_sha256). statement_bytes is the
    full COSE_Sign1 envelope; statement_content_sha256 is sha256 over the
    payload bytes ACTUALLY signed (the bstr payload of the COSE_Sign1).

    alg MUST be in _ALLOWED_COSE_ALG; alg=none REJECTED. alg + kid land in the
    PROTECTED header (not unprotected) per the SCITT shape lock.
    """
    if alg not in _ALLOWED_COSE_ALG:
        raise LayerAVerificationError(
            ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
            detail=f"alg {alg} not in allowlist {sorted(_ALLOWED_COSE_ALG)}",
        )
    from pycose.headers import KID, Algorithm
    from pycose.messages import Sign1Message

    if alg == -8:
        from pycose.algorithms import EdDSA as _Alg
    else:
        from pycose.algorithms import Es256 as _Alg

    payload_bytes = deterministic_cbor_encode(payload)
    statement_content_sha256 = hashlib.sha256(payload_bytes).digest()
    msg = Sign1Message(
        phdr={Algorithm: _Alg, KID: issuer_kid},
        uhdr={},
        payload=payload_bytes,
    )
    msg.key = issuer_signing_key
    statement_bytes = msg.encode()
    return statement_bytes, statement_content_sha256


def _decode_cose_sign1(blob: bytes) -> tuple[bytes, dict, bytes, bytes]:
    """Return (protected_bstr, unprotected_map, payload, signature) from a
    COSE_Sign1 envelope. Tag 18 may be implicit at the COSE_Sign1 layer.
    Raises LayerAVerificationError(SCITT_RECEIPT_VERIFICATION_FAILED) on
    malformed envelopes, or a CBOR_* code on a CBOR-layer policy violation.
    """
    # CBOR-layer policy scan on the ATTACKER'S wire bytes BEFORE cbor2.loads
    # absorbs duplicate keys / indefinite lengths / unexpected tags. This is
    # the bytes-level gate the verify-then-parse contract promises; running it
    # on a canonical re-encode of already-parsed data (the old stage-3a scan)
    # could never fire.
    scan_cbor_for_policy_violations(blob)
    try:
        decoded = cbor2.loads(blob)
    except Exception as exc:  # noqa: BLE001
        raise LayerAVerificationError(
            ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
            detail=f"receipt cbor decode error: {exc}",
        ) from exc
    if isinstance(decoded, cbor2.CBORTag):
        if decoded.tag != 18:
            raise LayerAVerificationError(
                ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
                detail=f"unexpected COSE tag {decoded.tag}; expected 18 (Sign1)",
            )
        decoded = decoded.value
    if not isinstance(decoded, (list, tuple)) or len(decoded) != 4:
        raise LayerAVerificationError(
            ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
            detail="COSE_Sign1 must be a 4-element CBOR array",
        )
    protected_bstr, unprotected_map, payload, signature = decoded
    if not isinstance(protected_bstr, (bytes, bytearray)):
        raise LayerAVerificationError(
            ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
            detail="protected header must be bstr",
        )
    if not isinstance(unprotected_map, Mapping):
        raise LayerAVerificationError(
            ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
            detail="unprotected header must be map",
        )
    if not isinstance(payload, (bytes, bytearray)):
        raise LayerAVerificationError(
            ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
            detail="payload must be bstr",
        )
    if not isinstance(signature, (bytes, bytearray)):
        raise LayerAVerificationError(
            ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
            detail="signature must be bstr",
        )
    return bytes(protected_bstr), unprotected_map, bytes(payload), bytes(signature)


def verify_scitt_receipt(
    *,
    receipt: ScittReceipt,
    pinned_ts_key_ids: frozenset[bytes],
    pinned_ts_verifying_keys: dict,
) -> None:
    """Verify a SCITT-shaped notary receipt's signature + payload binding.

    Steps:
      1. receipt.ts_key_id in pinned_ts_key_ids  → SCITT_TS_KEY_MISMATCH
      2. Decode receipt_bytes; assert alg in PROTECTED + in allowlist;
         assert alg NOT in unprotected; assert kid in PROTECTED matches
         receipt.ts_key_id                       → SCITT_RECEIPT_VERIFICATION_FAILED
      3. Verify COSE_Sign1 signature via pinned key  → SCITT_RECEIPT_VERIFICATION_FAILED
      4. Recompute sha256(receipt.cose_payload_bytes); assert equality with
         receipt.statement_content_sha256        → SCITT_RECEIPT_PAYLOAD_MISMATCH

    SCOPE — what this DOES NOT verify (an honest-downgrade caveat): this is a
    notary-signature + payload-binding check only. It performs NO
    transparency-log inclusion verification — no Merkle-inclusion-proof fold, no
    signed-tree-head (STH) consistency compare, no log-index check, no
    freshness/recency bound. A receipt that verifies here proves only "a pinned
    TS key signed this statement content," NOT "this statement is included in an
    append-only transparency log." v0.3 ships a SCITT-*shaped* receipt; the real
    SCITT envelope + transparency-log inclusion are roadmap items (DSSE envelope
    v0.4, SCITT v0.5 — see c18_verifier_identity.py module docstring). External
    copy MUST NOT describe v0.3 as verifying log inclusion or being "anchored"
    in a transparency log on the strength of this function.
    """
    # 1. TUF-pinned TS key gate (the nexi-c19-ts-log role).
    if receipt.ts_key_id not in pinned_ts_key_ids:
        raise LayerAVerificationError(
            ReasonCode.SCITT_TS_KEY_MISMATCH,
            detail=f"ts_key_id={receipt.ts_key_id!r} not in pinned set",
        )

    protected_bstr, unprotected_map, payload, signature = _decode_cose_sign1(
        receipt.receipt_bytes
    )

    # Empty protected bstr decodes to an empty map (per RFC 9052 §3 — empty
    # bstr is the canonical empty header). Otherwise decode the inner map.
    # The inner header bytes are attacker wire bytes too (opaque bstr to the
    # outer envelope scan) — policy-scan them before cbor2.loads.
    if protected_bstr == b"":
        protected_map: dict = {}
    else:
        scan_cbor_for_policy_violations(protected_bstr)
        try:
            protected_map = cbor2.loads(protected_bstr)
        except Exception as exc:  # noqa: BLE001
            raise LayerAVerificationError(
                ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
                detail=f"protected header decode error: {exc}",
            ) from exc
        if not isinstance(protected_map, dict):
            raise LayerAVerificationError(
                ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
                detail="protected header must decode to map",
            )

    # alg presence + allowlist + protected-only enforcement.
    if _COSE_LABEL_ALG not in protected_map:
        raise LayerAVerificationError(
            ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
            detail="alg missing from protected header (alg=none / alg-absent rejected)",
        )
    if _COSE_LABEL_ALG in unprotected_map:
        raise LayerAVerificationError(
            ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
            detail="alg MUST live ONLY in protected headers per RFC 9052 §3.1",
        )
    alg = protected_map[_COSE_LABEL_ALG]
    if alg not in _ALLOWED_COSE_ALG:
        raise LayerAVerificationError(
            ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
            detail=f"alg {alg} not in allowlist {sorted(_ALLOWED_COSE_ALG)}",
        )

    # kid binding.
    kid = protected_map.get(_COSE_LABEL_KID)
    if kid != receipt.ts_key_id:
        raise LayerAVerificationError(
            ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
            detail="protected kid does not match receipt.ts_key_id",
        )

    # Signature verification via pycose Algorithm class.
    if alg == -8:
        from pycose.algorithms import EdDSA as _Alg
    else:
        from pycose.algorithms import Es256 as _Alg

    sig_structure = ["Signature1", protected_bstr, b"", payload]
    to_be_signed = cbor2.dumps(sig_structure)
    try:
        verifying_key = pinned_ts_verifying_keys[receipt.ts_key_id]
        ok = _Alg.verify(verifying_key, to_be_signed, signature)
    except KeyError as exc:
        raise LayerAVerificationError(
            ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
            detail=f"no verifying key pinned for ts_key_id={receipt.ts_key_id!r}",
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise LayerAVerificationError(
            ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
            detail=f"signature verify raised: {exc}",
        ) from exc
    if not ok:
        raise LayerAVerificationError(
            ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
            detail="COSE_Sign1 signature verification returned False",
        )

    # The caller-supplied cose_payload_bytes MUST be the very bytes the COSE
    # signature just verified. Without this, the signature leg attests the
    # envelope's payload while the content leg below hashes a DIFFERENT
    # caller-supplied byte string — a receipt whose statement_content_sha256
    # was minted over substitute bytes would carry a valid signature AND a
    # "matching" hash without the two ever referring to the same statement.
    if bytes(payload) != bytes(receipt.cose_payload_bytes):
        raise LayerAVerificationError(
            ReasonCode.SCITT_RECEIPT_PAYLOAD_MISMATCH,
            detail=(
                "receipt.cose_payload_bytes != COSE_Sign1 payload actually "
                "signed in receipt_bytes — the signature and content checks "
                "must cover the same bytes"
            ),
        )

    # Receipt-bytes binding. The cose_payload_bytes the
    # CALLER supplies MUST match what statement_content_sha256 hashes; this
    # is checked after signature verify so an attacker cannot probe this
    # path with malformed signatures. `compare_digest` is the digest-equality
    # primitive — SHA-256 preimage resistance already makes a timing leak
    # unexploitable here, but raw `!=` on digest bytes is the wrong primitive.
    if not _hmac.compare_digest(
        hashlib.sha256(receipt.cose_payload_bytes).digest(),
        receipt.statement_content_sha256,
    ):
        raise LayerAVerificationError(
            ReasonCode.SCITT_RECEIPT_PAYLOAD_MISMATCH,
            detail="sha256(cose_payload_bytes) != statement_content_sha256",
        )


# ---------------------------------------------------------------------------
# Per-chain monotonic counter + hash chain + event-hash Merkle tree.
# Per-chain monotonic counter, NOT HLC — wall-clock claims are forgeable in
# an adversarial substrate.
# ---------------------------------------------------------------------------


# RFC 6962-style domain separation prevents second-preimage attacks where an
# internal node hash with leaf-shaped inputs could collide with a leaf hash.
_MERKLE_LEAF_PREFIX: Final[bytes] = b"\x01"
_MERKLE_NODE_PREFIX: Final[bytes] = b"\x00"


def compute_event_hash(event_canonical_cbor: bytes) -> bytes:
    """sha256(deterministic_cbor(event)) — the per-event hash that feeds the
    bundle Merkle tree AND becomes the prev_event_hash for the next chain link.
    """
    return hashlib.sha256(event_canonical_cbor).digest()


def compute_bundle_merkle_root(event_hashes: list[bytes]) -> bytes:
    """Per-bundle event-hash Merkle root with RFC 6962-style domain separation.

    Leaves:   H(0x01 || event_hash)
    Internal: H(0x00 || left || right)

    Returns 32-byte root. Empty bundle returns the empty-sentinel
    sha256(0x01). The root binds `causal_chain.layer_a.event_dag_merkle_root`
    AND is what the manifest-header-integrity leaf anchors against.
    """
    if not event_hashes:
        return hashlib.sha256(_MERKLE_LEAF_PREFIX).digest()
    # Hash leaves once with leaf prefix.
    level = [hashlib.sha256(_MERKLE_LEAF_PREFIX + h).digest() for h in event_hashes]
    while len(level) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left  # odd-tail duplicate
            next_level.append(
                hashlib.sha256(_MERKLE_NODE_PREFIX + left + right).digest()
            )
        level = next_level
    return level[0]


def compute_manifest_header_leaf(
    *,
    bundle_id: str,
    created_at: str,
    dispatch_records: tuple | list,
    assurance_profile: str | None = None,
    schema_version: str | None = None,
) -> bytes:
    """Manifest header Merkle leaf.

    Binds the manifest header (bundle_id + created_at + sorted
    dispatch_records_index) into a 32-byte sha256 digest. When emitted under
    `causal_chain.layer_a.manifest_header_merkle_leaf` AND prepended at leaf
    position 0 of the Merkle tree, this leaf participates in the same
    `event_dag_merkle_root` the Layer B Roughtime / TSA path anchors —
    turning an honest-sealer trust assumption into an honest-anchor one.

    Back-compat covered fields: when ``assurance_profile`` and/or
    ``schema_version`` are supplied (non-None) they are folded into the covered
    header — so the declared assurance profile and the declared bundle-manifest
    schema (format) version become digest-bound (tamper-evident) and
    canonicalization-closed (JCS/canonical-json admits exactly one parse of each
    value). When ``None`` (every legacy caller) the key is **omitted**, so the leaf
    is byte-identical to the legacy computation and no existing bundle re-mints.
    ``schema_version`` coverage closes the manifest-format-substitution surface: a
    producer cannot claim conformance to a different ``schema_version`` (and thus a
    different validation rule-set, see ``bundle_manifest._VALID_SCHEMA_VERSIONS``)
    than the one sealed. The *downgrade* protection (a producer cannot select below
    the floor) is the verifier-held OOB floor, not this leaf — covering a field only
    makes the producer's claim tamper-evident; see
    ``profile_completeness_policy.resolve_effective_profile``.

    Composition:
        dispatch_records_index = sorted(
            [(idx, sha256_hex(canonical_json(record))) for idx, record in
             enumerate(dispatch_records)],
            key=lambda t: t[0],
        )
        header = {"bundle_id": ..., "created_at": ...,
                  "dispatch_records_index": [[idx, sha], ...]}
        leaf = sha256(canonical_json(header))  # 32 raw bytes

    canonical_json matches the snapshot_policy convention at
    bundle_manifest.py:553-558 — json.dumps with sort_keys=True,
    separators=(',', ':'), ensure_ascii=False, UTF-8 encoded.

    Idx-keyed sort (not record_sha-keyed) so that unauthorized record
    permutation is detected: a swap of records at idx 0 ↔ idx 1 leaves
    different (idx, record_sha) pairs at the same indices, producing a
    different leaf.
    """
    index_pairs = sorted(
        (
            (
                idx,
                hashlib.sha256(
                    json.dumps(
                        record,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ).encode("utf-8")
                ).hexdigest(),
            )
            for idx, record in enumerate(dispatch_records)
        ),
        key=lambda t: t[0],
    )
    header = {
        "bundle_id": bundle_id,
        "created_at": created_at,
        "dispatch_records_index": [[idx, sha] for idx, sha in index_pairs],
    }
    # Fold the declared profile into the covered header ONLY when
    # present, so the None path stays byte-identical (sort_keys + omitted key).
    if assurance_profile is not None:
        header["assurance_profile"] = assurance_profile
    # Fold the declared bundle-manifest schema_version the same way —
    # binds the manifest FORMAT version the bundle claims conformance to into the
    # digest, so a producer cannot swap schema_version (and thus the validation
    # rule-set it asserts) post-seal without breaking the leaf. Same back-compat
    # contract: omitted when None, so every legacy / non-supplying caller — incl.
    # the generic validate_manifest() path — stays byte-identical.
    if schema_version is not None:
        header["schema_version"] = schema_version
    return hashlib.sha256(
        json.dumps(
            header,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).digest()


def compute_manifest_header_leaf_from_manifest(
    *,
    bundle_id: str,
    created_at: str,
    dispatch_records: tuple | list,
    assurance_profile: str | None = None,
    schema_version: str | None = None,
) -> bytes:
    """OF1 CANONICAL leaf — the ONE covered-field convention.

    This is the single source of truth for the OF1 manifest-header leaf. It folds
    the manifest-declared ``assurance_profile`` and ``schema_version`` into the
    covered header WHEN each is present as a string (else omits it — preserving
    ``compute_manifest_header_leaf``'s byte-identity for a field the manifest
    genuinely lacks). Every OF1 leaf computation in the substrate routes through
    here so the covered-field set can never diverge across producer and verifier:

      - the generic ``bundle_manifest.validate_manifest`` step 20 (folds
        ``m.assurance_profile`` + ``m.schema_version``);
      - the ``of1_manifest_header_re_derivation`` plugin (folds the top-level
        ``raw["assurance_profile"]`` + ``raw["schema_version"]``);
      - the ``seal_of1_manifest_anchor`` sealer (below); and
      - the example builders (e.g. eidas).

    The substrate unifies on the FOLDED convention rather than carrying two
    divergent leaf computations. Because ``schema_version`` is required on every
    manifest, any bundle carrying an OF1 leaf now binds its declared
    schema_version (closing the manifest-format-substitution surface), and binds
    ``assurance_profile`` too when declared. The earlier BARE leaf (which folded
    neither field) is no longer the generic-path convention; the only producers
    of a bare leaf were test fixtures + fuzz harnesses, which mint their own leaf
    and do not run the generic validator. The *downgrade floor* remains the
    verifier-held OOB profile floor
    (``profile_completeness_policy.resolve_effective_profile``), not this leaf —
    covering a field only makes the producer's claim tamper-evident.

    The str-guard lives HERE (one place) so a caller cannot accidentally re-create
    the historical divergence by passing a non-string profile/version through.
    """
    return compute_manifest_header_leaf(
        bundle_id=bundle_id,
        created_at=created_at,
        dispatch_records=dispatch_records,
        assurance_profile=(
            assurance_profile if isinstance(assurance_profile, str) else None
        ),
        schema_version=(schema_version if isinstance(schema_version, str) else None),
    )


def seal_of1_manifest_anchor(
    *,
    event_hashes: list[bytes],
    bundle_id: str,
    created_at: str,
    dispatch_records: tuple | list,
    assurance_profile: str | None = None,
    schema_version: str | None = None,
) -> dict:
    """OF1S — sealer-side helper for OF1 manifest header anchor.

    Computes both OF1 outputs in one call and returns them as hex strings
    ready to drop into `causal_chain.layer_a` on the sealing side:

        sealed = seal_of1_manifest_anchor(...)
        layer_a = {..., **sealed}  # spreads event_dag_merkle_root +
                                   #         manifest_header_merkle_leaf

    Closes the OF1 adoption gap: pre-OF1S, emitters had to call
    compute_manifest_header_leaf, then know to prepend its bytes at leaf 0
    when computing event_dag_merkle_root. OF1S bundles both steps so the
    sealer cannot mismatch the leaf composition the verifier
    (validate_manifest check 20 + _verify_layer_a_pipeline) recomputes
    against.

    Argument shape:
      event_hashes        — list of 32-byte event-hash digests (the same
                            values verify_chain_integrity accumulates from
                            deterministic_cbor_encode(event)). The caller
                            is responsible for computing these in canonical
                            order before invoking the sealer.
      bundle_id           — manifest.bundle_id (str).
      created_at          — manifest.created_at (str, ISO-8601 UTC with 'Z').
      dispatch_records    — manifest.dispatch_records (tuple | list of dicts).
      assurance_profile   — manifest.assurance_profile (str | None). Folded into
                            the canonical leaf when declared.
      schema_version      — manifest.schema_version (str | None). Folded into the
                            canonical leaf when declared. Pass the SAME value
                            stored on the manifest, else the verifier's recompute
                            (which folds the stored value) will MISMATCH. A sealer
                            that omits both stays byte-identical to a legacy
                            bare leaf — back-compat for non-generic-validator
                            callers (fuzz harnesses); but any bundle that
                            runs the generic validator MUST seal with its declared
                            schema_version (the canonical convention).

    Returns dict with two keys, both 64-char lowercase hex strings:
      event_dag_merkle_root          — Merkle root over [leaf, *event_hashes]
      manifest_header_merkle_leaf    — sha256 over canonical-JSON(header)
    """
    header_leaf = compute_manifest_header_leaf_from_manifest(
        bundle_id=bundle_id,
        created_at=created_at,
        dispatch_records=dispatch_records,
        assurance_profile=assurance_profile,
        schema_version=schema_version,
    )
    root = compute_bundle_merkle_root([header_leaf, *event_hashes])
    return {
        "event_dag_merkle_root": root.hex(),
        "manifest_header_merkle_leaf": header_leaf.hex(),
    }


def verify_chain_integrity(
    events_in_canonical_order: list[dict],
    *,
    manifest_header_leaf: bytes | None = None,
) -> bytes:
    """Verify monotonic-counter strict-increment + counter_log_index binding +
    hash-chain linkage + event_id uniqueness. Returns the recomputed
    event_dag_merkle_root.

    Implements the C19 plugin verification steps 4-7 + 9.
    Per-chain monotonic counter, NOT HLC.

    Checks run in two passes so adversarial bundles surface the strongest
    failure class:
      Pass 1 — event_id uniqueness + monotonic counter + counter_log_index
               across ALL events
      Pass 2 — hash-chain linkage (and Merkle leaf computation)

    OF1: when `manifest_header_leaf` is supplied as 32 raw bytes,
    it is prepended at leaf position 0 BEFORE the event-hash leaves, so that
    the returned root binds the manifest header. When None (the default),
    behavior is byte-identical to the pre-OF1 surface — legacy v0.2 bundles
    verify unchanged.
    """
    if not events_in_canonical_order:
        if manifest_header_leaf is None:
            return hashlib.sha256(_MERKLE_LEAF_PREFIX).digest()
        return compute_bundle_merkle_root([manifest_header_leaf])

    # Pass 1: identity + counter discipline.
    seen_ids: set[str] = set()
    prev_counter = 0
    for idx, ev in enumerate(events_in_canonical_order):
        if ev["event_id"] in seen_ids:
            raise LayerAVerificationError(
                ReasonCode.EVENT_ID_DUPLICATE,
                detail=f"event_id {ev['event_id']!r} duplicated at index {idx}",
            )
        seen_ids.add(ev["event_id"])
        if ev["monotonic_counter"] != prev_counter + 1:
            raise LayerAVerificationError(
                ReasonCode.COUNTER_GAP_DETECTED,
                detail=(
                    f"index {idx}: expected monotonic_counter "
                    f"{prev_counter + 1}, got {ev['monotonic_counter']}"
                ),
            )
        if ev["counter_log_index"] != ev["monotonic_counter"]:
            raise LayerAVerificationError(
                ReasonCode.COUNTER_GAP_DETECTED,
                detail=(
                    f"index {idx}: counter_log_index "
                    f"{ev['counter_log_index']} != monotonic_counter "
                    f"{ev['monotonic_counter']}"
                ),
            )
        prev_counter = ev["monotonic_counter"]

    # Pass 2: hash-chain linkage + Merkle leaf accumulation.
    # OF1: when manifest_header_leaf is supplied, prepend at leaf 0
    # so the recomputed root binds the manifest header alongside event hashes.
    leaf_hashes: list[bytes] = []
    if manifest_header_leaf is not None:
        leaf_hashes.append(manifest_header_leaf)
    prev_hash = b"\x00" * 32  # root sentinel; only consulted at idx > 0
    for idx, ev in enumerate(events_in_canonical_order):
        if idx > 0 and ev["prev_event_hash"] != prev_hash:
            raise LayerAVerificationError(
                ReasonCode.HASH_CHAIN_BROKEN,
                detail=f"index {idx}: prev_event_hash does not match sha256(prev_event)",
            )
        canonical = deterministic_cbor_encode(ev)
        h = compute_event_hash(canonical)
        leaf_hashes.append(h)
        prev_hash = h
    return compute_bundle_merkle_root(leaf_hashes)


# Pipeline + plugin land in sc19a-008. Placeholder symbols keep the import
# surface stable.


MAX_BUNDLE_BYTES: Final[int] = 64 * 1024 * 1024  # 64 MiB v0.3 cap (sc19a-005)


# ---------------------------------------------------------------------------
# Verify-then-parse pipeline orchestrator.
#
# PIPELINE ORDER IS LOAD-BEARING. NEVER PARSE BEFORE VERIFY.
#
#   1. [VERIFY] size guard               → BUNDLE_TOO_LARGE
#   1.5 [VERIFY] minimal extraction       (locate COSE_Sign1 envelopes per event;
#                                          no full schema parse / CDDL yet)
#   2. [VERIFY] SCITT receipt + COSE sig → SCITT_TS_KEY_MISMATCH
#                                          SCITT_RECEIPT_VERIFICATION_FAILED
#   2b.[VERIFY] receipt-bytes binding    → SCITT_RECEIPT_PAYLOAD_MISMATCH
#   3a.[PARSE]  CBOR-policy (trusted)    → CBOR_DUPLICATE_KEY / INDEFINITE_LENGTH
#                                          / TAG_NOT_ALLOWED
#   3b.[PARSE]  CDDL grammar (trusted)   → CDDL_VALIDATION_FAILED
#                                          EVENT_KIND_UNKNOWN
#   4. [PARSE]  chain integrity          → COUNTER_GAP_DETECTED
#                                          HASH_CHAIN_BROKEN
#                                          EVENT_ID_DUPLICATE
#   5. [PARSE]  Merkle recompute         → MERKLE_ROOT_MISMATCH
#   6. [PARSE]  per-event signature      → EVENT_SIGNATURE_INVALID
# ---------------------------------------------------------------------------


def _hex_to_bytes(s: object, *, what: str, reason: ReasonCode) -> bytes:
    if isinstance(s, (bytes, bytearray)):
        return bytes(s)
    if not isinstance(s, str):
        raise LayerAVerificationError(reason, detail=f"{what} must be hex str or bytes")
    try:
        return bytes.fromhex(s)
    except ValueError as exc:
        raise LayerAVerificationError(reason, detail=f"{what} not hex: {exc}") from exc


def _extract_receipt_bytes(event: dict) -> bytes:
    """Minimal extraction — locate the COSE_Sign1 receipt blob for an event.

    Canonical field: `scitt_inclusion_proof` (str hex or base64). Tolerates
    `scitt_inclusion_proof_bytes` for substrates that serialize hex-encoded.
    """
    raw = event.get("scitt_inclusion_proof")
    if raw is None:
        raw = event.get("scitt_inclusion_proof_bytes")
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    if isinstance(raw, str):
        try:
            return bytes.fromhex(raw)
        except ValueError:
            import base64

            try:
                return base64.b64decode(raw)
            except Exception as exc:  # noqa: BLE001
                raise LayerAVerificationError(
                    ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
                    detail=f"scitt_inclusion_proof not hex/base64: {exc}",
                ) from exc
    raise LayerAVerificationError(
        ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
        detail="scitt_inclusion_proof missing on event",
    )


def _ts_key_id_from_receipt(receipt_bytes: bytes) -> bytes:
    """Decode the COSE_Sign1 protected header to extract the kid
    (source-of-truth ts_key_id)."""
    protected_bstr, _, _, _ = _decode_cose_sign1(receipt_bytes)
    if protected_bstr == b"":
        return b""
    # Attacker wire bytes (opaque bstr to the envelope scan) — policy-scan
    # before cbor2.loads.
    scan_cbor_for_policy_violations(protected_bstr)
    try:
        protected_map = cbor2.loads(protected_bstr)
    except Exception as exc:  # noqa: BLE001
        raise LayerAVerificationError(
            ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
            detail=f"protected header decode error: {exc}",
        ) from exc
    kid = (
        protected_map.get(_COSE_LABEL_KID) if isinstance(protected_map, dict) else None
    )
    return kid if isinstance(kid, (bytes, bytearray)) else b""


def _scitt_statement_commits_to_payload(
    *, statement_sha: bytes, cose_payload_bytes: bytes, payload_hash: bytes
) -> bool:
    """Red-team B-3 — True iff the notarized SCITT statement commits to the
    event's leaf-bound `payload_hash`. Accepts either in-tree issuance
    convention (see caller); the canonical-schema lock is tracked as B-6.

      (1) raw-payload receipt: statement_content_sha256 == payload_hash.
      (2) statement-envelope receipt: the COSE payload decodes to a CBOR map
          carrying a `payload_hash` field equal to the event's payload_hash
          (value may be raw bytes or a hex string).
    """
    if statement_sha == payload_hash:
        return True
    try:
        # Statement bytes are attacker wire bytes: policy-scan before
        # cbor2.loads so a duplicate-key statement (two payload_hash entries,
        # one checked here, the other consumed by a later parser) cannot be
        # silently collapsed. A policy violation commits to nothing -> False.
        scan_cbor_for_policy_violations(cose_payload_bytes)
        statement = cbor2.loads(cose_payload_bytes)
    except Exception:  # noqa: BLE001 — undecodable statement commits to nothing
        return False
    if not isinstance(statement, dict):
        return False
    declared = statement.get("payload_hash")
    if isinstance(declared, (bytes, bytearray)):
        return bytes(declared) == payload_hash
    if isinstance(declared, str):
        try:
            return bytes.fromhex(declared) == payload_hash
        except ValueError:
            return False
    return False


def _verify_layer_a_pipeline(
    layer_a: dict,
    *,
    pinned_ts_key_ids: frozenset[bytes],
    pinned_ts_verifying_keys: dict,
    pinned_issuer_keys: dict[str, bytes],
) -> bytes:
    """Stages 1.5–6 of the verify-then-parse pipeline."""
    events = layer_a.get("events")
    if not isinstance(events, list):
        raise LayerAVerificationError(
            ReasonCode.CDDL_VALIDATION_FAILED,
            detail="layer_a.events must be list",
        )

    # Stage 1.5 + 2 + 2b: per-event SCITT receipt verify on TRUSTED bytes.
    for idx, ev in enumerate(events):
        if not isinstance(ev, dict):
            raise LayerAVerificationError(
                ReasonCode.CDDL_VALIDATION_FAILED,
                detail=f"events[{idx}] must be dict",
            )
        receipt_bytes = _extract_receipt_bytes(ev)
        ts_key_id = _ts_key_id_from_receipt(receipt_bytes)
        _, _, cose_payload, _ = _decode_cose_sign1(receipt_bytes)
        statement_sha = _hex_to_bytes(
            ev.get("scitt_statement_content_sha256", ""),
            what=f"events[{idx}].scitt_statement_content_sha256",
            reason=ReasonCode.SCITT_RECEIPT_PAYLOAD_MISMATCH,
        )
        receipt = ScittReceipt(
            statement_id=statement_sha,
            statement_content_sha256=statement_sha,
            cose_payload_bytes=cose_payload,
            receipt_bytes=receipt_bytes,
            ts_key_id=ts_key_id,
        )
        verify_scitt_receipt(
            receipt=receipt,
            pinned_ts_key_ids=pinned_ts_key_ids,
            pinned_ts_verifying_keys=pinned_ts_verifying_keys,
        )

        # Red-team B-3 fix: bind the notarized statement to the leaf-bound
        # payload. verify_scitt_receipt only proves the receipt is internally
        # consistent (sha256(cose_payload_bytes) == statement_content_sha256);
        # it never ties that statement to the payload that enters the Merkle
        # leaf. Without this check a bundle whose receipt notarizes statement_X
        # ("DENY") while the leaf-bound payload_hash covers payload_Y
        # ("APPROVE") verifies GREEN — the attestation says PASS while the
        # signed decision and the tree-bound decision disagree.
        #
        # The notarized statement MUST commit to the event's payload_hash. Two
        # issuance conventions coexist in-tree (the canonical-schema lock is a
        # separate decision, tracked as B-6), so the check accepts either and
        # rejects anything that commits to neither:
        #   (1) raw-payload receipts (eidas pilot): the COSE payload IS the
        #       payload bytes, so statement_content_sha256 == payload_hash.
        #   (2) statement-envelope receipts (issue_scitt_statement): the COSE
        #       payload is a CBOR map carrying a `payload_hash` field whose
        #       value equals the event's payload_hash.
        payload_hash = _hex_to_bytes(
            ev.get("payload_hash", ""),
            what=f"events[{idx}].payload_hash",
            reason=ReasonCode.SCITT_STATEMENT_PAYLOAD_DECOUPLED,
        )
        if not _scitt_statement_commits_to_payload(
            statement_sha=statement_sha,
            cose_payload_bytes=cose_payload,
            payload_hash=payload_hash,
        ):
            raise LayerAVerificationError(
                ReasonCode.SCITT_STATEMENT_PAYLOAD_DECOUPLED,
                detail=(
                    f"events[{idx}]: SCITT receipt does not commit to the "
                    f"leaf-bound payload_hash ({payload_hash.hex()}); neither "
                    "statement_content_sha256 == payload_hash nor a "
                    "payload_hash field in the notarized statement matches — "
                    "the receipt notarizes a different statement than the tree"
                ),
            )

    # Stage 3a: CBOR-policy scanning runs on the ATTACKER'S wire bytes at the
    # points where CBOR actually enters this pipeline — the COSE_Sign1 receipt
    # envelope, its protected header, and the notarized statement payload (see
    # _decode_cose_sign1 / verify_scitt_receipt /
    # _scitt_statement_commits_to_payload). layer_a itself arrives as a
    # JSON-decoded dict; the previous re-encode-then-scan here was tautological
    # (a deterministic re-encode of parsed data can never carry duplicate keys,
    # indefinite lengths, or stray tags) and is deliberately gone.

    # Stage 3b: CDDL gate at the manifest-dict layer (matches the bytes-keyed
    # validate_event_cddl taxonomy; uses the str-keyed shape validator with
    # EVENT_KIND_UNKNOWN distinct from generic CDDL_VALIDATION_FAILED).
    from audit_bundle.bundle_manifest import (
        CausalChainLayerAEventKindUnknown,
        validate_causal_chain_layer_a_shape,
    )

    try:
        validate_causal_chain_layer_a_shape(layer_a)
    except CausalChainLayerAEventKindUnknown as exc:
        raise LayerAVerificationError(
            ReasonCode.EVENT_KIND_UNKNOWN, detail=str(exc)
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise LayerAVerificationError(
            ReasonCode.CDDL_VALIDATION_FAILED, detail=str(exc)
        ) from exc

    # Stage 3c: strict per-event key gate (unknown-key rejection + typed
    # host_id) — the live-path mirror of the bytes-keyed validate_event_cddl,
    # which can never see these JSON-decoded events. Plus the v0.3
    # bounded-list ceiling, enforced where events enter the pipeline.
    if len(events) > MAX_EVENTS_PER_BUNDLE:
        raise LayerAVerificationError(
            ReasonCode.CDDL_VALIDATION_FAILED,
            detail=f"len(events)={len(events)} > {MAX_EVENTS_PER_BUNDLE}",
        )
    for idx, ev in enumerate(events):
        validate_event_keys_str(ev, idx=idx)

    # Stage 4: chain integrity. Normalize hex→bytes for verify_chain_integrity.
    normalized: list[dict] = []
    for idx, ev in enumerate(events):
        normalized.append(
            {
                "event_id": ev["event_id"],
                "prev_event_id": ev["prev_event_id"],
                "prev_event_hash": _hex_to_bytes(
                    ev["prev_event_hash"],
                    what=f"events[{idx}].prev_event_hash",
                    reason=ReasonCode.HASH_CHAIN_BROKEN,
                ),
                "monotonic_counter": ev["monotonic_counter"],
                "counter_log_index": ev["counter_log_index"],
                "event_kind": ev["event_kind"],
                "payload_hash": _hex_to_bytes(
                    ev["payload_hash"],
                    what=f"events[{idx}].payload_hash",
                    reason=ReasonCode.CDDL_VALIDATION_FAILED,
                ),
            }
        )
    # OF1: if the manifest header leaf is bound into the Merkle
    # tree, decode it here so verify_chain_integrity prepends it at leaf 0.
    # Field-absent → legacy path (verify_chain_integrity behavior byte-identical
    # to pre-OF1). The leaf-vs-manifest-fields binding check lives in
    # validate_manifest (check 10) and LayerACounterPlugin.check — this pipeline
    # only checks that the stored root binds the stored leaf.
    header_leaf_hex = layer_a.get("manifest_header_merkle_leaf")
    header_leaf: bytes | None = None
    if header_leaf_hex is not None:
        header_leaf = _hex_to_bytes(
            header_leaf_hex,
            what="layer_a.manifest_header_merkle_leaf",
            reason=ReasonCode.MANIFEST_HEADER_LEAF_MISMATCH,
        )
    recomputed_root = verify_chain_integrity(
        normalized, manifest_header_leaf=header_leaf
    )

    # Stage 5: Merkle recompute compare.
    manifest_root = _hex_to_bytes(
        layer_a["event_dag_merkle_root"],
        what="layer_a.event_dag_merkle_root",
        reason=ReasonCode.MERKLE_ROOT_MISMATCH,
    )
    if recomputed_root != manifest_root:
        raise LayerAVerificationError(
            ReasonCode.MERKLE_ROOT_MISMATCH,
            detail="recomputed event_dag_merkle_root != manifest value",
        )

    # Stage 6: per-event signature verify.
    #
    # host_id integrity note: host_id selects the per-event verification key.
    # It is NOT folded into the Merkle leaf or hash chain (changing the leaf
    # shape would re-mint every attested artifact — deferred by design); its
    # binding is the HMAC preimage below, which includes host_id — so renaming
    # an event's host_id forces verification under the NAMED host's key, and
    # forging that requires the named host's key material. The stage-3c gate
    # types the field; key selection itself fails closed here: an absent
    # host_id is only resolvable when exactly ONE issuer key is pinned —
    # silently picking the "first" of several would let omission choose the
    # attacker's preferred key.
    for idx, ev in enumerate(events):
        host_id = ev.get("host_id")
        if not host_id:
            if len(pinned_issuer_keys) == 1:
                host_id = next(iter(pinned_issuer_keys))
            else:
                raise LayerAVerificationError(
                    ReasonCode.EVENT_SIGNATURE_INVALID,
                    detail=(
                        f"events[{idx}]: host_id absent and "
                        f"{len(pinned_issuer_keys)} issuer keys pinned — "
                        "ambiguous key selection, failing closed (events must "
                        "carry host_id unless exactly one issuer key is pinned)"
                    ),
                )
        host_ikm = pinned_issuer_keys.get(host_id)
        if host_ikm is None:
            raise LayerAVerificationError(
                ReasonCode.EVENT_SIGNATURE_INVALID,
                detail=f"events[{idx}]: no pinned issuer key for host {host_id!r}",
            )
        k_event = derive_event_signature_key(host_ikm)
        preimage = canonical_event_preimage(
            host_id=host_id,
            event_id=ev["event_id"],
            prev_event_hash=normalized[idx]["prev_event_hash"],
            bundle_id=layer_a.get("bundle_id", ""),
            monotonic_counter=ev["monotonic_counter"],
            payload_hash=normalized[idx]["payload_hash"],
        )
        sig_field = ev["event_signature"]
        sig_raw = sig_field.get("sig")
        if isinstance(sig_raw, str):
            try:
                import base64

                if all(c in "0123456789abcdefABCDEF" for c in sig_raw):
                    sig_bytes = bytes.fromhex(sig_raw)
                else:
                    sig_bytes = base64.b64decode(sig_raw)
            except Exception as exc:  # noqa: BLE001
                raise LayerAVerificationError(
                    ReasonCode.EVENT_SIGNATURE_INVALID,
                    detail=f"events[{idx}].event_signature.sig decode: {exc}",
                ) from exc
        elif isinstance(sig_raw, (bytes, bytearray)):
            sig_bytes = bytes(sig_raw)
        else:
            raise LayerAVerificationError(
                ReasonCode.EVENT_SIGNATURE_INVALID,
                detail=f"events[{idx}].event_signature.sig missing or wrong type",
            )
        if len(sig_bytes) != 32:
            raise LayerAVerificationError(
                ReasonCode.EVENT_SIGNATURE_INVALID,
                detail=(
                    f"events[{idx}].event_signature.sig must decode to 32 "
                    f"bytes (HMAC-SHA256); got {len(sig_bytes)}"
                ),
            )
        if not verify_event_signature(k_event, preimage, sig_bytes):
            raise LayerAVerificationError(
                ReasonCode.EVENT_SIGNATURE_INVALID,
                detail=f"events[{idx}]: HMAC verify returned False",
            )

    return recomputed_root


def verify_bundle_layer_a(
    *,
    bundle_bytes: bytes,
    layer_a: dict | None = None,
    pinned_ts_key_ids: frozenset[bytes] = frozenset(),
    pinned_ts_verifying_keys: dict | None = None,
    pinned_issuer_keys: dict[str, bytes] | None = None,
) -> bytes:
    """Top-level verify-then-parse entry point.

    Stage 1 (size guard) runs FIRST on raw bundle_bytes. Subsequent stages run
    on the trusted layer_a structure. Returns recomputed event_dag_merkle_root
    on success.
    """
    if len(bundle_bytes) > MAX_BUNDLE_BYTES:
        raise LayerAVerificationError(
            ReasonCode.BUNDLE_TOO_LARGE,
            detail=f"{len(bundle_bytes)} > {MAX_BUNDLE_BYTES}",
        )
    if layer_a is None:
        return hashlib.sha256(_MERKLE_LEAF_PREFIX).digest()
    return _verify_layer_a_pipeline(
        layer_a,
        pinned_ts_key_ids=pinned_ts_key_ids,
        pinned_ts_verifying_keys=pinned_ts_verifying_keys or {},
        pinned_issuer_keys=pinned_issuer_keys or {},
    )


# ---------------------------------------------------------------------------
# LayerACounterPlugin — TypedCheck integration. Registered at module import
# (see register_typed_check call at module bottom).
# ---------------------------------------------------------------------------


from audit_bundle.bundle_manifest import register_typed_check  # noqa: E402
from audit_bundle.causal_chain_coverage import subkey_coverage  # noqa: E402
from audit_bundle.plugin import PluginResult  # noqa: E402


class LayerACounterPlugin:
    """C19 Layer A SCITT-bound counter substrate plugin (verify-then-parse).

    Operates on `manifest.causal_chain['layer_a']` when present; bundles with
    no causal_chain or no layer_a sub-key continue to verify cleanly
    (backward-compat invariant).
    """

    name: str = "c19_layer_a_counter"
    applies_to_files: frozenset[str] = frozenset()

    def __init__(
        self,
        *,
        pinned_ts_key_ids: frozenset[bytes],
        pinned_ts_verifying_keys: dict,
        pinned_issuer_keys: dict[str, bytes],
    ):
        self.pinned_ts_key_ids = pinned_ts_key_ids
        self.pinned_ts_verifying_keys = pinned_ts_verifying_keys
        self.pinned_issuer_keys = pinned_issuer_keys

    def check(self, bundle_dir, manifest) -> PluginResult:
        if (
            manifest.causal_chain is None
            or manifest.causal_chain.get("layer_a") is None
        ):
            return PluginResult(
                ok=True,
                reason_code="PASS",
                detail="no causal_chain.layer_a present (legacy / Layer-A-not-emitted bundle)",
                files_audited=(),
            )
        try:
            _verify_layer_a_pipeline(
                manifest.causal_chain["layer_a"],
                pinned_ts_key_ids=self.pinned_ts_key_ids,
                pinned_ts_verifying_keys=self.pinned_ts_verifying_keys,
                pinned_issuer_keys=self.pinned_issuer_keys,
            )
        except LayerAVerificationError as exc:
            return PluginResult(
                ok=False,
                reason_code=exc.code.value,
                detail=exc.detail,
                files_audited=(),
            )
        # OF1: leaf-vs-manifest-fields binding step. The pipeline
        # already confirmed the stored Merkle root binds the stored leaf bytes;
        # this additional check confirms the stored leaf bytes are the leaf
        # recomputed from manifest.bundle_id + manifest.created_at +
        # manifest.dispatch_records. Field-absent → legacy bundle, skip.
        layer_a = manifest.causal_chain["layer_a"]
        header_leaf_hex = layer_a.get("manifest_header_merkle_leaf")
        if header_leaf_hex is not None:
            expected_leaf = compute_manifest_header_leaf(
                bundle_id=manifest.bundle_id,
                created_at=manifest.created_at,
                dispatch_records=manifest.dispatch_records,
            )
            if expected_leaf.hex() != header_leaf_hex.lower():
                return PluginResult(
                    ok=False,
                    reason_code=ReasonCode.MANIFEST_HEADER_LEAF_MISMATCH.value,
                    detail=(
                        "stored layer_a.manifest_header_merkle_leaf does not "
                        "match the leaf recomputed from manifest.bundle_id + "
                        "manifest.created_at + manifest.dispatch_records"
                    ),
                    files_audited=(),
                )
        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail="C19 Layer A verify-then-parse pipeline green",
            files_audited=(),
            # Coverage report: the verify-then-parse pipeline above
            # cryptographically re-derived this layer_a (SCITT receipts, HMAC
            # event signatures, Merkle root). Satisfies the causal_chain
            # coverage guard so the verified counter chain does not read as
            # could-not-conclude (BLOCK-02).
            verified_causal_chain_subkeys=subkey_coverage("layer_a", layer_a),
        )


register_typed_check("c19_layer_a_counter")
