"""C19.D — Pre-commitment SCITT log (reference implementation).

Reserves a NEW SCITT `payload_type` value under C18's enum-extension hook.
Does NOT invent a parallel envelope — reuses the counter substrate's
issue_scitt_statement() API with a new payload_type. Forward-compat: the same
envelope shape accepts any future payload_type (e.g., a future
`multi_party_attestation_statement`) without code change in this module.

PRE_COMMIT_WINDOW_BOUNDS_MS is a hardcoded profile-bound (min, max) ceiling table
— a bundle-supplied window override is IGNORED. Mirrors ACK_TIMEOUT_BOUNDS_MS in
cross_host_peerreview.py.

verify_pre_commit_predates_rotation() asserts the pre-commitment SCITT statement
was issued ≥ Δ before the rotation event (Δ inside profile bounds), so a rotation
cannot be back-dated under a freshly minted pre-commitment.

Standards bound: SCITT draft-ietf-scitt-architecture-22 §4 + RFC 9052
COSE_Sign1 + RFC 8949 §4.2.1 deterministic CBOR.


"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Final

from audit_bundle.extensions.c19.layer_a_counter import (
    LayerAVerificationError,
    ReasonCode,
    ScittReceipt,
    issue_scitt_statement,
    verify_scitt_receipt,
)


# C18 payload_type registry value reserved for the pre-commitment SCITT statement.
# The C18 allowlist registry is TUF-distributed; this value is the reserved entry
# the verifier expects for pre-commit statements.
PRE_COMMIT_PAYLOAD_TYPE: Final[str] = "nexi/audit/v0.3/key-rotation-pre-commit"


# Profile-bound (min, max) pre-commitment window ceilings in ms.
# Mirrors ACK_TIMEOUT_BOUNDS_MS in cross_host_peerreview.py. Bundle-supplied
# window overrides are IGNORED — verifier uses ONLY this table.
PRE_COMMIT_WINDOW_BOUNDS_MS: Final[dict[str, tuple[int, int]]] = {
    "offline-auditor-minimal": (60_000, 86_400_000),  # 1 min – 1 day
    "production-standard": (3_600_000, 604_800_000),  # 1 hour – 1 week
    "regulated-high-assurance": (86_400_000, 2_592_000_000),  # 1 day – 30 days
}


class PreCommitReasonCode(str, enum.Enum):
    """Module-local reason codes — also mirrored into the shared ReasonCode enum
    so the chain walker error surface is unified."""

    MISSING_PRE_COMMITMENT_SCITT_ID = "MISSING_PRE_COMMITMENT_SCITT_ID"
    PRE_COMMIT_WINDOW_VIOLATION = "PRE_COMMIT_WINDOW_VIOLATION"
    PRE_COMMIT_WINDOW_OUT_OF_PROFILE_BOUNDS = "PRE_COMMIT_WINDOW_OUT_OF_PROFILE_BOUNDS"
    PRE_COMMIT_PAYLOAD_TYPE_UNKNOWN = "PRE_COMMIT_PAYLOAD_TYPE_UNKNOWN"


@dataclass(frozen=True)
class KeyProvisionStatement:
    """Pre-commitment SCITT statement payload — declares that host_id intends to
    activate new_key_id at or after activation_at_iso8601, witnessed at issuance.

    Pure structural shape — does NOT carry the SCITT receipt. The receipt is
    issued via issue_pre_commit_statement() and verified via
    verify_pre_commit_scitt_statement().
    """

    host_id: str
    new_key_id: str
    activation_at_iso8601: str
    issuance_at_iso8601: str

    def to_payload_dict(self) -> dict:
        return {
            "payload_type": PRE_COMMIT_PAYLOAD_TYPE,
            "host_id": self.host_id,
            "new_key_id": self.new_key_id,
            "activation_at": self.activation_at_iso8601,
            "issuance_at": self.issuance_at_iso8601,
        }


class PreCommitSCITTLog:
    """Thin wrapper around the SCITT statement issuance/verification API.

    Carries the forward-compat property: any payload_type in the
    TUF-distributed allowlist — including future values such as
    `multi_party_attestation_statement` — is accepted
    by the envelope shape contract WITHOUT modification to this module.
    """

    def __init__(self, *, allowlist_payload_types: frozenset[str]):
        if PRE_COMMIT_PAYLOAD_TYPE not in allowlist_payload_types:
            raise LayerAVerificationError(
                ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
                detail=(
                    f"payload_type {PRE_COMMIT_PAYLOAD_TYPE!r} not in C18 allowlist"
                ),
            )
        self._allowlist: frozenset[str] = allowlist_payload_types

    def envelope_accepts(self, payload_type: str) -> bool:
        """Forward-compat hook. Returns True for any payload_type in the
        TUF-distributed allowlist — open-set under signed-metadata extension."""
        return payload_type in self._allowlist


def issue_pre_commit_statement(
    *,
    statement: KeyProvisionStatement,
    issuer_signing_key,
    issuer_kid: bytes,
    alg: int = -8,
) -> tuple[bytes, bytes]:
    """Issue the pre-commitment SCITT Signed Statement.

    Returns (statement_bytes, statement_content_sha256). Reuses the counter
    substrate's issue_scitt_statement(); the only delta is the payload_type
    field inside the payload dict.
    """
    return issue_scitt_statement(
        issuer_signing_key=issuer_signing_key,
        issuer_kid=issuer_kid,
        payload=statement.to_payload_dict(),
        alg=alg,
    )


def verify_pre_commit_scitt_statement(
    *,
    receipt: ScittReceipt,
    pinned_ts_key_ids: frozenset[bytes],
    pinned_ts_verifying_keys: dict,
    expected_host_id: str,
    expected_new_key_id: str,
) -> KeyProvisionStatement:
    """Verify the SCITT receipt via verify_scitt_receipt + parse the
    payload + assert host_id / new_key_id match the caller's expectations.

    Returns the parsed KeyProvisionStatement on success.
    Raises LayerAVerificationError on any verification or shape failure.
    """
    verify_scitt_receipt(
        receipt=receipt,
        pinned_ts_key_ids=pinned_ts_key_ids,
        pinned_ts_verifying_keys=pinned_ts_verifying_keys,
    )
    import cbor2 as _cbor2

    # Safe to parse receipt.cose_payload_bytes here: verify_scitt_receipt
    # ENFORCES that these bytes equal the COSE_Sign1 payload the signature
    # verified (not an unchecked caller convention).
    payload = _cbor2.loads(receipt.cose_payload_bytes)
    if not isinstance(payload, dict):
        raise LayerAVerificationError(
            ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
            detail="pre-commit payload not a CBOR map",
        )
    ptype = payload.get("payload_type")
    if ptype != PRE_COMMIT_PAYLOAD_TYPE:
        raise LayerAVerificationError(
            ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
            detail=f"payload_type {ptype!r} != {PRE_COMMIT_PAYLOAD_TYPE!r}",
        )
    if payload.get("host_id") != expected_host_id:
        raise LayerAVerificationError(
            ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
            detail="pre-commit host_id mismatch",
        )
    if payload.get("new_key_id") != expected_new_key_id:
        raise LayerAVerificationError(
            ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
            detail="pre-commit new_key_id mismatch",
        )
    return KeyProvisionStatement(
        host_id=payload["host_id"],
        new_key_id=payload["new_key_id"],
        activation_at_iso8601=payload["activation_at"],
        issuance_at_iso8601=payload["issuance_at"],
    )


def _parse_iso8601_utc_ms(s: str) -> int:
    """Parse iso8601 (with 'Z' or '+00:00') into a UTC millisecond epoch int."""
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def verify_pre_commit_predates_rotation(
    *,
    pre_commit_issuance_iso8601: str,
    rotation_at_iso8601: str,
    assurance_profile: str,
) -> None:
    """Pre-commitment issuance MUST predate rotation by a window inside the
    profile-bound (min, max). Bundle-supplied window override is NOT consulted —
    verifier uses ONLY PRE_COMMIT_WINDOW_BOUNDS_MS.

    Raises:
      LayerAVerificationError(PRE_COMMIT_WINDOW_VIOLATION) on non-positive window
        (pre-commit not strictly before rotation)
      LayerAVerificationError(PRE_COMMIT_WINDOW_OUT_OF_PROFILE_BOUNDS) on
        out-of-bounds window for the profile (covers both Δ=0 and ∞-stale)
    """
    bounds = PRE_COMMIT_WINDOW_BOUNDS_MS.get(assurance_profile)
    if bounds is None:
        raise LayerAVerificationError(
            ReasonCode.PRE_COMMIT_WINDOW_OUT_OF_PROFILE_BOUNDS,
            detail=f"unknown assurance_profile {assurance_profile!r}",
        )
    min_ms, max_ms = bounds
    pre_ms = _parse_iso8601_utc_ms(pre_commit_issuance_iso8601)
    rot_ms = _parse_iso8601_utc_ms(rotation_at_iso8601)
    window_ms = rot_ms - pre_ms
    if window_ms <= 0:
        raise LayerAVerificationError(
            ReasonCode.PRE_COMMIT_WINDOW_VIOLATION,
            detail=(
                f"pre-commit issuance not strictly before rotation "
                f"(window_ms={window_ms})"
            ),
        )
    if window_ms < min_ms or window_ms > max_ms:
        raise LayerAVerificationError(
            ReasonCode.PRE_COMMIT_WINDOW_OUT_OF_PROFILE_BOUNDS,
            detail=(
                f"pre-commit window {window_ms}ms outside profile bounds "
                f"({min_ms}..{max_ms})ms for {assurance_profile!r}"
            ),
        )


__all__ = [
    "PRE_COMMIT_PAYLOAD_TYPE",
    "PRE_COMMIT_WINDOW_BOUNDS_MS",
    "KeyProvisionStatement",
    "PreCommitReasonCode",
    "PreCommitSCITTLog",
    "issue_pre_commit_statement",
    "verify_pre_commit_scitt_statement",
    "verify_pre_commit_predates_rotation",
]
