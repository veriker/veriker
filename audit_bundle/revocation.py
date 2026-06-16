"""audit_bundle.revocation — verifier-side key revocation (iat-ignoring, signed list).

Design intent (DSSE v0.4 PRD D1 — iat-backdating closure)
----------------------------------------------------------
A compromised signing key cannot escape revocation by backdating the envelope
``iat`` because **no security decision here reads ``iat``**.  The sole inputs to
a revocation decision are:

  * the signer's **kid** (derived from the raw public key, not from any envelope
    field the signer controls),
  * **verifier_now** — the verifier's own wall clock at check time,
  * the **signed revocation list** — whose signature is verified against an
    injected revocation-root pubkey (C18-distributed, injected by the caller).

The revocation verdict records ``(revocation_list_hash, verifier_now)`` so an
auditor can replay the decision deterministically: given the same list bytes and
the same verifier clock reading, the verdict is re-derivable.

Signed revocation list format (``vkernel_revocations.json``)
-------------------------------------------------------------
A JSON object::

    {
      "payload": {
        "revocations": [
          {"kid": "<kid>", "not_after": <int unix seconds>},
          ...
        ],
        "issued_at": <int unix seconds>,
        "expires":   <int unix seconds>
      },
      "sig":      "<base64url-no-pad Ed25519 sig over rfc8785.dumps(payload)>",
      "root_kid": "<kid of the revocation-root pubkey>"
    }

``sig`` is an Ed25519 signature by the revocation-root key over the RFC 8785
(JCS) canonical byte serialisation of the ``payload`` object.  The revocation-
root pubkey is never stored in this file; it is always injected at load time via
the ``revocation_root_resolver`` callable.

Absent / stale list — fail-closed
----------------------------------
Callers that omit the revocation list, or pass ``None``, receive a
``DSSE_REVOCATION_LIST_ABSENT`` error (revoked=True / fail-closed).  A stale
list (``verifier_now > expires``) returns ``DSSE_REVOCATION_LIST_STALE`` (also
fail-closed).  A verifier that cannot obtain a fresh, validly-signed revocation
list MUST treat the result as fail-closed: silence is NOT "not revoked".

Boundary — ``not_after``
--------------------------
A kid's ``not_after`` is the instant at which revocation takes effect.
``is_revoked`` returns ``revoked=True`` when ``verifier_now >= not_after``
(inclusive).  A key is valid while ``verifier_now < not_after``; at the exact
boundary second it is revoked.

This module is pure ``cryptography`` + stdlib + ``rfc8785``.
It does NOT import ``emitter_premium``, ``dsse.envelope``, or any other
audit_bundle submodule — with ONE deliberate exception: ``audit_bundle._freeze``,
a stdlib-only leaf with zero audit_bundle imports of its own, used to deep-freeze
``RevocationList.entries`` at construction. The no-cycles / standalone-
auditability intent of this contract is preserved (audit the one extra file).
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._freeze import deep_freeze

__all__ = [
    "RevocationListInvalid",
    "RevocationList",
    "RevocationVerdict",
    "load_revocation_list",
    "is_revoked",
]

# ---------------------------------------------------------------------------
# Reason codes (string constants — no enum so callers can compare w/ ==)
# ---------------------------------------------------------------------------
DSSE_KEY_REVOKED: str = "DSSE_KEY_REVOKED"
DSSE_REVOCATION_LIST_STALE: str = "DSSE_REVOCATION_LIST_STALE"
DSSE_REVOCATION_LIST_ABSENT: str = "DSSE_REVOCATION_LIST_ABSENT"
DSSE_REVOCATION_TIME_UNSOUND: str = "DSSE_REVOCATION_TIME_UNSOUND"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class RevocationListInvalid(Exception):
    """Raised by ``load_revocation_list`` when the list cannot be trusted.

    Possible causes:
    * JSON parse failure
    * missing required keys in the top-level structure or payload
    * wrong type for ``issued_at``, ``expires``, or ``not_after``
    * Ed25519 signature verification failure (bad sig or wrong root key)
    * revocation-root resolver raises / returns wrong-length bytes
    """


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _RevocationEntry:
    """One entry in the signed revocation list."""

    kid: str
    not_after: int  # Unix epoch seconds — revoked iff verifier_now >= not_after


@dataclass(frozen=True)
class RevocationList:
    """A parsed and signature-verified revocation list.

    Attributes
    ----------
    entries:
        Mapping from kid → not_after (Unix epoch seconds). Deeply immutable
        (frozen in ``__post_init__``): this is the decision map ``is_revoked``
        reads, while the verdict records the SHA-256 of the raw signed bytes —
        an in-place mutation between load and check would make the verdict
        claim a deterministic replayability it no longer has, so mutation
        raises ``TypeError`` instead.
    issued_at:
        When the list was issued (Unix epoch seconds, from the signed payload).
    expires:
        When the list expires (Unix epoch seconds, from the signed payload).
        ``is_revoked`` hard-fails if ``verifier_now > expires``.
    revocation_list_hash:
        SHA-256 hex digest of the raw signed bytes (the full JSON object as
        received), for auditor replay.
    """

    entries: dict[str, int]  # kid → not_after (deep-frozen in __post_init__)
    issued_at: int
    expires: int
    revocation_list_hash: str

    def __post_init__(self) -> None:
        # Freeze at EVERY construction site (not just load_revocation_list —
        # emitter/pipeline.py builds a RevocationList directly), so the
        # invariant lives on the type rather than on one factory.
        object.__setattr__(self, "entries", deep_freeze(self.entries))


@dataclass(frozen=True)
class RevocationVerdict:
    """The output of ``is_revoked``.

    Attributes
    ----------
    revoked:
        ``True`` iff the key should be treated as revoked (or the list is
        stale / time is unsound — fail-closed in all error cases).
    reason_code:
        One of the ``DSSE_*`` constants above, or ``None`` when the key is
        valid (``revoked=False``).
    revocation_list_hash:
        SHA-256 hex digest of the raw revocation-list bytes used for this
        decision, for auditor replay.
    verifier_now:
        The verifier's clock value (Unix epoch seconds) at the time of this
        check, for auditor replay.
    """

    revoked: bool
    reason_code: str | None
    revocation_list_hash: str
    verifier_now: int


# ---------------------------------------------------------------------------
# b64url helpers (stdlib only — mirrors pae.py idiom, no cross-import)
# ---------------------------------------------------------------------------


def _b64url_nopad_decode(s: str) -> bytes:
    """Decode a base64url string with no padding characters."""
    remainder = len(s) % 4
    if remainder == 1:
        raise ValueError(
            f"Invalid base64url-nopad string: length {len(s)} has remainder 1 mod 4"
        )
    padding = (4 - remainder) % 4
    return base64.urlsafe_b64decode(s + "=" * padding)


# ---------------------------------------------------------------------------
# load_revocation_list
# ---------------------------------------------------------------------------


def load_revocation_list(
    raw_bytes: bytes,
    *,
    revocation_root_resolver: Callable[[str], bytes],
) -> RevocationList:
    """Parse and signature-verify a signed revocation list.

    Parameters
    ----------
    raw_bytes:
        The raw bytes of the ``vkernel_revocations.json`` file (or in-memory
        equivalent).  The SHA-256 of these bytes is recorded as
        ``RevocationList.revocation_list_hash`` for auditor replay.
    revocation_root_resolver:
        A callable ``(root_kid: str) -> pubkey_raw32: bytes`` that returns the
        raw 32-byte Ed25519 public key for the given root kid.  This is how
        the C18-distributed revocation root is injected — WS-3 does NOT read
        any production root file.  Unit tests pass a resolver that returns a
        test-generated root pubkey.  Must raise ``RevocationListInvalid`` (or
        any exception) if the kid is unknown; callers may also raise
        ``KeyError``, which is re-wrapped.

    Returns
    -------
    RevocationList
        A frozen, signature-verified list ready to be passed to ``is_revoked``.

    Raises
    ------
    RevocationListInvalid
        On any parse, type, or signature error.  Callers must handle this and
        treat the list as absent (fail-closed) if verification fails.
    """
    # Record the hash of the raw bytes for auditor traceability BEFORE parsing,
    # so the hash covers what the caller actually received.
    revocation_list_hash = hashlib.sha256(raw_bytes).hexdigest()

    # --- Parse ---
    try:
        doc: Any = json.loads(raw_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RevocationListInvalid(f"JSON parse error: {exc}") from exc

    if not isinstance(doc, dict):
        raise RevocationListInvalid("top-level document must be a JSON object")

    for required_key in ("payload", "sig", "root_kid"):
        if required_key not in doc:
            raise RevocationListInvalid(
                f"missing required top-level key: {required_key!r}"
            )

    raw_payload: Any = doc["payload"]
    sig_str: Any = doc["sig"]
    root_kid: Any = doc["root_kid"]

    if not isinstance(raw_payload, dict):
        raise RevocationListInvalid("'payload' must be a JSON object")
    if not isinstance(sig_str, str):
        raise RevocationListInvalid("'sig' must be a string")
    if not isinstance(root_kid, str):
        raise RevocationListInvalid("'root_kid' must be a string")

    # Validate payload fields
    for required_payload_key in ("revocations", "issued_at", "expires"):
        if required_payload_key not in raw_payload:
            raise RevocationListInvalid(
                f"missing required payload key: {required_payload_key!r}"
            )

    issued_at: Any = raw_payload["issued_at"]
    expires: Any = raw_payload["expires"]
    revocations_raw: Any = raw_payload["revocations"]

    if not isinstance(issued_at, int) or isinstance(issued_at, bool):
        raise RevocationListInvalid("payload.issued_at must be an integer")
    if not isinstance(expires, int) or isinstance(expires, bool):
        raise RevocationListInvalid("payload.expires must be an integer")
    if not isinstance(revocations_raw, list):
        raise RevocationListInvalid("payload.revocations must be an array")

    # Parse entries
    entries: dict[str, int] = {}
    for idx, entry in enumerate(revocations_raw):
        if not isinstance(entry, dict):
            raise RevocationListInvalid(f"payload.revocations[{idx}] must be an object")
        if "kid" not in entry or "not_after" not in entry:
            raise RevocationListInvalid(
                f"payload.revocations[{idx}] missing 'kid' or 'not_after'"
            )
        entry_kid: Any = entry["kid"]
        entry_not_after: Any = entry["not_after"]
        if not isinstance(entry_kid, str):
            raise RevocationListInvalid(
                f"payload.revocations[{idx}].kid must be a string"
            )
        if not isinstance(entry_not_after, int) or isinstance(entry_not_after, bool):
            raise RevocationListInvalid(
                f"payload.revocations[{idx}].not_after must be an integer"
            )
        entries[entry_kid] = entry_not_after

    # --- Resolve the revocation-root public key ---
    try:
        pubkey_raw32 = revocation_root_resolver(root_kid)
    except RevocationListInvalid:
        raise
    except Exception as exc:
        raise RevocationListInvalid(
            f"revocation_root_resolver raised for kid {root_kid!r}: {exc}"
        ) from exc

    if not isinstance(pubkey_raw32, bytes) or len(pubkey_raw32) != 32:
        raise RevocationListInvalid(
            f"revocation_root_resolver must return exactly 32 bytes; "
            f"got {type(pubkey_raw32).__name__} of length "
            f"{len(pubkey_raw32) if isinstance(pubkey_raw32, bytes) else '?'}"
        )

    # --- Verify Ed25519 signature over rfc8785.dumps(payload) ---
    try:
        sig_bytes = _b64url_nopad_decode(sig_str)
    # binascii.Error subclasses ValueError, so this covers every
    # malformed-input failure; a broader catch would launder verifier
    # bugs into RevocationListInvalid.
    except ValueError as exc:
        raise RevocationListInvalid(
            f"'sig' is not valid base64url-no-pad: {exc}"
        ) from exc

    # The signed bytes are the RFC 8785 (JCS) canonical serialisation of the
    # payload object — deterministic regardless of the original JSON formatting.
    try:
        canonical_payload_bytes: bytes = rfc8785.dumps(raw_payload)
    except Exception as exc:
        raise RevocationListInvalid(f"rfc8785.dumps failed on payload: {exc}") from exc

    try:
        pubkey = Ed25519PublicKey.from_public_bytes(pubkey_raw32)
    except Exception as exc:
        raise RevocationListInvalid(
            f"Cannot construct Ed25519PublicKey from resolver bytes: {exc}"
        ) from exc

    try:
        pubkey.verify(sig_bytes, canonical_payload_bytes)
    except InvalidSignature as exc:
        raise RevocationListInvalid(
            "Ed25519 signature verification failed — list may be tampered or "
            "signed by a different key"
        ) from exc
    except Exception as exc:
        raise RevocationListInvalid(
            f"Ed25519 signature check raised unexpectedly: {exc}"
        ) from exc

    return RevocationList(
        entries=entries,
        issued_at=int(issued_at),
        expires=int(expires),
        revocation_list_hash=revocation_list_hash,
    )


# ---------------------------------------------------------------------------
# is_revoked
# ---------------------------------------------------------------------------


def is_revoked(
    rev_list: RevocationList | None,
    kid: str,
    verifier_now: int,
    *,
    max_clock_skew: int = 300,
    max_list_age: int | None = None,
) -> RevocationVerdict:
    """Check whether ``kid`` is revoked at ``verifier_now``.

    CRITICAL: This function does NOT take and does NOT read any envelope ``iat``
    field.  The revocation decision is made purely from:

      * ``kid``          — the key fingerprint (derived from the public key,
                           not from any signer-controlled envelope field),
      * ``verifier_now`` — the verifier's own wall clock,
      * ``rev_list``     — the signed revocation list (verified at load time).

    A compromised key cannot escape revocation by backdating ``iat`` because
    ``iat`` is simply never consulted here (D1 closure).

    Parameters
    ----------
    rev_list:
        A ``RevocationList`` returned by ``load_revocation_list``, or ``None``.
        Passing ``None`` is a caller error that is caught and returned as a
        fail-closed verdict (``DSSE_REVOCATION_LIST_ABSENT``).  Callers MUST
        provide a validly signed list; absent is never "not revoked".
    kid:
        The key fingerprint to check (``base64url_nopad(sha256(pubkey_raw32))``).
        This is derived from the signer's public key, not from the envelope.
    verifier_now:
        The verifier's current time as Unix epoch seconds.  Callers should use
        ``int(time.time())`` or inject a deterministic value in tests.
    max_clock_skew:
        Tolerance (seconds) for the time-sanity check.  A ``verifier_now``
        earlier than ``rev_list.issued_at - max_clock_skew`` is flagged as
        ``DSSE_REVOCATION_TIME_UNSOUND`` (fail-closed).  Default 300 s.
    max_list_age:
        Optional additional staleness limit.  If set, ``verifier_now >
        rev_list.issued_at + max_list_age`` also triggers
        ``DSSE_REVOCATION_LIST_STALE`` (fail-closed).  Default ``None``
        (no additional age limit beyond the list's own ``expires`` field).

    Returns
    -------
    RevocationVerdict
        Always returned (never raises).  The ``revocation_list_hash`` and
        ``verifier_now`` fields are always populated so auditors can replay
        the decision.

    Verdict boundary table
    ----------------------
    +--------------------------+-------------------------+-----------------------------+
    | Condition                | revoked                 | reason_code                 |
    +==========================+=========================+=============================+
    | rev_list is None         | True (fail-closed)      | DSSE_REVOCATION_LIST_ABSENT |
    +--------------------------+-------------------------+-----------------------------+
    | verifier_now < issued_at | True (fail-closed)      | DSSE_REVOCATION_TIME_UNSOUND|
    |  - max_clock_skew        |                         |                             |
    +--------------------------+-------------------------+-----------------------------+
    | verifier_now > expires   | True (fail-closed)      | DSSE_REVOCATION_LIST_STALE  |
    | OR max_list_age exceeded |                         |                             |
    +--------------------------+-------------------------+-----------------------------+
    | kid in list AND          | True                    | DSSE_KEY_REVOKED            |
    | verifier_now >= not_after|                         |                             |
    +--------------------------+-------------------------+-----------------------------+
    | kid in list AND          | False                   | None                        |
    | verifier_now < not_after |                         |                             |
    +--------------------------+-------------------------+-----------------------------+
    | kid NOT in list          | False                   | None                        |
    | (list fresh, time sound) |                         |                             |
    +--------------------------+-------------------------+-----------------------------+
    """
    # --- Absent list: hard fail-closed ---
    if rev_list is None:
        # Use a placeholder hash for absent-list verdicts (nothing to hash).
        absent_hash = hashlib.sha256(b"ABSENT").hexdigest()
        return RevocationVerdict(
            revoked=True,
            reason_code=DSSE_REVOCATION_LIST_ABSENT,
            revocation_list_hash=absent_hash,
            verifier_now=verifier_now,
        )

    list_hash = rev_list.revocation_list_hash

    # --- Time-sanity check: backward clock jump / unsound verifier time ---
    # If verifier_now is far behind issued_at (more than max_clock_skew), the
    # verifier's clock is suspect — fail closed.
    if verifier_now < rev_list.issued_at - max_clock_skew:
        return RevocationVerdict(
            revoked=True,
            reason_code=DSSE_REVOCATION_TIME_UNSOUND,
            revocation_list_hash=list_hash,
            verifier_now=verifier_now,
        )

    # --- Staleness check: list expired or too old ---
    if verifier_now > rev_list.expires:
        return RevocationVerdict(
            revoked=True,
            reason_code=DSSE_REVOCATION_LIST_STALE,
            revocation_list_hash=list_hash,
            verifier_now=verifier_now,
        )
    if max_list_age is not None and verifier_now > rev_list.issued_at + max_list_age:
        return RevocationVerdict(
            revoked=True,
            reason_code=DSSE_REVOCATION_LIST_STALE,
            revocation_list_hash=list_hash,
            verifier_now=verifier_now,
        )

    # --- Revocation decision: kid present AND cutoff elapsed ---
    # NEVER reads any envelope iat.  Decision = (kid in list) AND
    # (verifier_now >= that kid's not_after).
    not_after = rev_list.entries.get(kid)
    if not_after is not None and verifier_now >= not_after:
        return RevocationVerdict(
            revoked=True,
            reason_code=DSSE_KEY_REVOKED,
            revocation_list_hash=list_hash,
            verifier_now=verifier_now,
        )

    # --- Not revoked ---
    # kid either not in list, or in list but not_after has not elapsed yet.
    return RevocationVerdict(
        revoked=False,
        reason_code=None,
        revocation_list_hash=list_hash,
        verifier_now=verifier_now,
    )
