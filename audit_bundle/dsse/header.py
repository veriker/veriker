"""DSSE sidecar-envelope strict header parser (crypto-free).

This module validates the on-disk JSON shape of the DSSE sidecar file
(``bundle.dsse.json``) against the locked v0.4 envelope seam.  It is
intentionally **crypto-free**: ``cryptography`` must NOT be imported here
so this module can be used by the stdlib-only offline tool (veriker/cli/verify.py).

Public surface
--------------
parse_strict_envelope(raw_bytes) -> StrictEnvelope
    Parses and strictly validates the sidecar JSON.  Raises DSSEHeaderError
    (with a machine-readable ``code`` attribute) on any violation.

StrictEnvelope
    Frozen dataclass carrying validated fields; payload_bytes_b64 is the
    raw base64url-no-pad string (decoding is done here to confirm format;
    the caller may decode again if needed).

DSSEHeaderError
    Structured error carrying a machine ``code`` from the DSSE_* constants.

DSSE_* error codes (string constants exported for downstream use)
    DSSE_MALFORMED_ENVELOPE
    DSSE_HEADER_DUPLICATE_KEY
    DSSE_HEADER_UNKNOWN_FIELD
    DSSE_PAYLOADTYPE_MISMATCH

Constraints enforced (P1c strictness)
--------------------------------------
1. Duplicate JSON keys are rejected at parse time (object_pairs_hook).
   Never last-key-wins.
2. Top-level allowed keys: exactly {payloadType, payload, signatures}.
   Any extra key is fatal (DSSE_HEADER_UNKNOWN_FIELD).
3. Each signature object: allowed keys exactly {keyid, sig}.
   Any extra key is fatal (DSSE_HEADER_UNKNOWN_FIELD).
4. ``payloadType`` must equal the pinned URI NFC bytewise-exact.
5. ``payload`` must be a non-empty base64url-no-pad string.
6. ``signatures`` must be a non-empty list.
7. Each ``sig`` and ``keyid`` must be decodable base64url-no-pad strings.
8. JSON numbers where strings are required → rejected.  Floats → rejected.

Import safety
-------------
This module imports: json, unicodedata, base64, binascii, dataclasses.
Importing ``cryptography`` is FORBIDDEN here.
Importing ``rfc8785`` is permitted but not currently needed.
"""

from __future__ import annotations

import binascii
import json
from dataclasses import dataclass
from typing import Any

from audit_bundle.dsse.pae import b64url_nopad_decode, payload_type_nfc

__all__ = [
    "parse_strict_envelope",
    "StrictEnvelope",
    "StrictSignature",
    "DSSEHeaderError",
    "DSSE_MALFORMED_ENVELOPE",
    "DSSE_HEADER_DUPLICATE_KEY",
    "DSSE_HEADER_UNKNOWN_FIELD",
    "DSSE_PAYLOADTYPE_MISMATCH",
    "PINNED_PAYLOAD_TYPE",
]

# ---------------------------------------------------------------------------
# Pinned payloadType URI (NFC-normalized canonical form).
# ---------------------------------------------------------------------------

PINNED_PAYLOAD_TYPE: str = payload_type_nfc("https://vkernel.dev/types/bundle.v1")

# ---------------------------------------------------------------------------
# Error codes (machine-readable strings).
# ---------------------------------------------------------------------------

DSSE_MALFORMED_ENVELOPE: str = "DSSE_MALFORMED_ENVELOPE"
DSSE_HEADER_DUPLICATE_KEY: str = "DSSE_HEADER_DUPLICATE_KEY"
DSSE_HEADER_UNKNOWN_FIELD: str = "DSSE_HEADER_UNKNOWN_FIELD"
DSSE_PAYLOADTYPE_MISMATCH: str = "DSSE_PAYLOADTYPE_MISMATCH"

# Allowed top-level keys and per-signature keys.
_TOPLEVEL_KEYS: frozenset[str] = frozenset({"payloadType", "payload", "signatures"})
_SIG_KEYS: frozenset[str] = frozenset({"keyid", "sig"})


# ---------------------------------------------------------------------------
# Structured error.
# ---------------------------------------------------------------------------


class DSSEHeaderError(ValueError):
    """Raised when the envelope JSON fails strict P1c validation.

    Attributes
    ----------
    code:
        Machine-readable error code; one of the DSSE_* module constants.
    detail:
        Human-readable description of the specific violation.
    """

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"[{code}] {detail}")
        self.code: str = code
        self.detail: str = detail


# ---------------------------------------------------------------------------
# Output dataclasses (frozen / immutable).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StrictSignature:
    """A single validated signature entry."""

    keyid: str
    """Base64url-no-pad key identifier (kid derivation per pae.kid_from_raw32)."""

    sig: str
    """Base64url-no-pad Ed25519 signature over the PAE preimage."""


@dataclass(frozen=True)
class StrictEnvelope:
    """Validated, canonical DSSE sidecar envelope.

    All fields are already validated; re-encoding is deterministic (key order
    follows the canonical seam definition, independent of input key order).
    """

    payload_type: str
    """The NFC-normalized payloadType URI (equal to PINNED_PAYLOAD_TYPE)."""

    payload_bytes_b64: str
    """Base64url-no-pad encoding of the payload bytes."""

    signatures: tuple[StrictSignature, ...]
    """Validated signature entries (non-empty tuple)."""


# ---------------------------------------------------------------------------
# Internal helpers.
# ---------------------------------------------------------------------------


def _reject_duplicates_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """object_pairs_hook that raises on duplicate keys."""
    seen: set[str] = set()
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise DSSEHeaderError(
                DSSE_HEADER_DUPLICATE_KEY,
                f"Duplicate JSON key {key!r} in envelope object",
            )
        seen.add(key)
        result[key] = value
    return result


def _require_str(value: Any, field: str) -> str:
    """Assert a parsed JSON value is a plain Python str; reject int/float/etc."""
    if not isinstance(value, str):
        raise DSSEHeaderError(
            DSSE_MALFORMED_ENVELOPE,
            f"Field {field!r} must be a JSON string; got {type(value).__name__}",
        )
    return value


def _validate_b64url_nopad(value: str, field: str) -> str:
    """Confirm that a string is a valid base64url-no-pad blob; return it."""
    try:
        b64url_nopad_decode(value)
    except (ValueError, binascii.Error) as exc:
        raise DSSEHeaderError(
            DSSE_MALFORMED_ENVELOPE,
            f"Field {field!r} is not valid base64url-no-pad: {exc}",
        ) from exc
    return value


# ---------------------------------------------------------------------------
# Public parser.
# ---------------------------------------------------------------------------


def parse_strict_envelope(raw_bytes: bytes) -> StrictEnvelope:
    """Parse and strictly validate a DSSE sidecar JSON document.

    Parameters
    ----------
    raw_bytes:
        The raw bytes of the ``bundle.dsse.json`` sidecar file.

    Returns
    -------
    StrictEnvelope
        A frozen, validated envelope struct.

    Raises
    ------
    DSSEHeaderError
        On any structural, key, type, or payloadType violation.
        ``err.code`` is one of the DSSE_* constants.
    """
    # -----------------------------------------------------------------------
    # Step 1: Decode UTF-8.
    # -----------------------------------------------------------------------
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DSSEHeaderError(
            DSSE_MALFORMED_ENVELOPE,
            f"Sidecar bytes are not valid UTF-8: {exc}",
        ) from exc

    # -----------------------------------------------------------------------
    # Step 2: Parse JSON with duplicate-key detection.
    #
    # DSSEHeaderError raised inside the hook propagates through json.loads
    # only if json.loads does not wrap it.  We need to re-raise cleanly.
    # -----------------------------------------------------------------------
    try:
        doc = json.loads(text, object_pairs_hook=_reject_duplicates_hook)
    except DSSEHeaderError:
        raise
    except json.JSONDecodeError as exc:
        raise DSSEHeaderError(
            DSSE_MALFORMED_ENVELOPE,
            f"Sidecar JSON parse error: {exc}",
        ) from exc

    # -----------------------------------------------------------------------
    # Step 3: Top-level type must be a dict (JSON object).
    # -----------------------------------------------------------------------
    if not isinstance(doc, dict):
        raise DSSEHeaderError(
            DSSE_MALFORMED_ENVELOPE,
            f"Sidecar root must be a JSON object; got {type(doc).__name__}",
        )

    # -----------------------------------------------------------------------
    # Step 4: Unknown top-level keys.
    # -----------------------------------------------------------------------
    unknown = set(doc.keys()) - _TOPLEVEL_KEYS
    if unknown:
        # Report in a deterministic order for stable error messages.
        listed = ", ".join(repr(k) for k in sorted(unknown))
        raise DSSEHeaderError(
            DSSE_HEADER_UNKNOWN_FIELD,
            f"Unknown top-level envelope field(s): {listed}",
        )

    # -----------------------------------------------------------------------
    # Step 5: Required keys present.
    # -----------------------------------------------------------------------
    for required in ("payloadType", "payload", "signatures"):
        if required not in doc:
            raise DSSEHeaderError(
                DSSE_MALFORMED_ENVELOPE,
                f"Required envelope field {required!r} is missing",
            )

    # -----------------------------------------------------------------------
    # Step 6: payloadType — must be a string, NFC, bytewise-exact match.
    # -----------------------------------------------------------------------
    raw_pt = _require_str(doc["payloadType"], "payloadType")
    nfc_pt = payload_type_nfc(raw_pt)
    if nfc_pt != PINNED_PAYLOAD_TYPE:
        raise DSSEHeaderError(
            DSSE_PAYLOADTYPE_MISMATCH,
            f"payloadType {raw_pt!r} (NFC: {nfc_pt!r}) does not match "
            f"pinned URI {PINNED_PAYLOAD_TYPE!r}",
        )

    # -----------------------------------------------------------------------
    # Step 7: payload — must be a non-empty base64url-no-pad string.
    # -----------------------------------------------------------------------
    raw_payload = _require_str(doc["payload"], "payload")
    if not raw_payload:
        raise DSSEHeaderError(
            DSSE_MALFORMED_ENVELOPE,
            "Field 'payload' must not be an empty string",
        )
    _validate_b64url_nopad(raw_payload, "payload")

    # -----------------------------------------------------------------------
    # Step 8: signatures — must be a non-empty list of objects.
    # -----------------------------------------------------------------------
    sigs_raw = doc["signatures"]
    if not isinstance(sigs_raw, list):
        raise DSSEHeaderError(
            DSSE_MALFORMED_ENVELOPE,
            f"Field 'signatures' must be a JSON array; got {type(sigs_raw).__name__}",
        )
    if len(sigs_raw) == 0:
        raise DSSEHeaderError(
            DSSE_MALFORMED_ENVELOPE,
            "Field 'signatures' must not be empty (zero signatures present)",
        )

    validated_sigs: list[StrictSignature] = []
    for idx, sig_obj in enumerate(sigs_raw):
        if not isinstance(sig_obj, dict):
            raise DSSEHeaderError(
                DSSE_MALFORMED_ENVELOPE,
                f"signatures[{idx}] must be a JSON object; "
                f"got {type(sig_obj).__name__}",
            )
        # Unknown signature keys.
        unknown_sig = set(sig_obj.keys()) - _SIG_KEYS
        if unknown_sig:
            listed = ", ".join(repr(k) for k in sorted(unknown_sig))
            raise DSSEHeaderError(
                DSSE_HEADER_UNKNOWN_FIELD,
                f"Unknown field(s) in signatures[{idx}]: {listed}",
            )
        # Required keys.
        for req in ("keyid", "sig"):
            if req not in sig_obj:
                raise DSSEHeaderError(
                    DSSE_MALFORMED_ENVELOPE,
                    f"Required field {req!r} missing from signatures[{idx}]",
                )
        raw_keyid = _require_str(sig_obj["keyid"], f"signatures[{idx}].keyid")
        raw_sig = _require_str(sig_obj["sig"], f"signatures[{idx}].sig")
        _validate_b64url_nopad(raw_keyid, f"signatures[{idx}].keyid")
        _validate_b64url_nopad(raw_sig, f"signatures[{idx}].sig")
        validated_sigs.append(StrictSignature(keyid=raw_keyid, sig=raw_sig))

    return StrictEnvelope(
        payload_type=nfc_pt,
        payload_bytes_b64=raw_payload,
        signatures=tuple(validated_sigs),
    )
