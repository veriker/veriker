"""Content-addressed identifier scheme for source snapshots.

CID format: '<scheme>:<lowercase_hex_digest>'
v1 supports 'sha256' only; scheme prefix is forward-compat for later
multibase/multihash adoption without stdlib changes.
"""

import hashlib
import re
from dataclasses import dataclass

_CID_PATTERN = re.compile(r"^([a-z][a-z0-9]*):[0-9a-f]+$")
_DIGEST_LENGTHS: dict[str, int] = {"sha256": 64}


class BadCID(ValueError):
    """Raised when a CID string is structurally malformed or has wrong digest length."""


def compute_cid(raw_bytes: bytes, scheme: str = "sha256") -> str:
    """Return '<scheme>:<hex_digest>' for raw_bytes using scheme.

    Only 'sha256' is supported at v1.  Raises ValueError for any other scheme
    so callers get an explicit error rather than silent bad output.
    """
    if scheme != "sha256":
        raise ValueError(f"Unsupported CID scheme at v1: {scheme!r}")
    return f"sha256:{hashlib.sha256(raw_bytes).hexdigest()}"


#: Below this many preimage bytes a content hash's input is small enough that a
#: producer SHOULD double-check it isn't a low-entropy field (phone, DOB, ZIP,
#: SSN, enum) whose exported hash becomes a guess-confirm recovery oracle. A
#: heuristic tripwire (length, not true entropy) — a 16-byte random nonce will
#: trip it too; that is acceptable for a producer-side advisory.
LOW_ENTROPY_PREIMAGE_THRESHOLD_BYTES = 32


def commitment_preimage_advisory(raw_bytes: bytes, *, context: str = "") -> str | None:
    """Red-team B-1 producer-side guard — flag a content-hash preimage that may
    be a recovery oracle when the bundle crosses the producer trust boundary.

    Content addresses are UNSALTED ``sha256(preimage)``; when the preimage is a
    low-entropy high-sensitivity field the exported hash is a dictionary
    guess-confirm oracle (an attacker recomputes the hash over the enumerable
    field space with the same canonical encoder). This is NOT closed by removing
    the hash (it is the verifiable commitment) — it is closed by salting or by
    never letting a bare low-entropy field be the sole preimage.

    Returns an advisory string when ``raw_bytes`` is shorter than
    LOW_ENTROPY_PREIMAGE_THRESHOLD_BYTES (a length-based heuristic, not an
    entropy measurement), else None. Producer/lint code should surface the
    advisory; it is deliberately NON-fatal so it never breaks verification or a
    legitimately-short high-entropy preimage (e.g. a random nonce). See the
    low-entropy-preimage note in the audit-bundle contract.
    """
    if len(raw_bytes) >= LOW_ENTROPY_PREIMAGE_THRESHOLD_BYTES:
        return None
    where = f" ({context})" if context else ""
    return (
        f"low-entropy content-hash preimage{where}: {len(raw_bytes)} bytes is "
        "below the recovery-oracle tripwire. If this commits a low-entropy "
        "sensitive field (phone/DOB/ZIP/SSN/enum), its exported unsalted hash "
        "is a dictionary recovery oracle — salt it or fold in a high-entropy "
        "component before exporting across the producer trust boundary."
    )


def parse_cid(cid: str) -> tuple[str, str]:
    """Parse '<scheme>:<hex_digest>' into (scheme, digest_hex).

    Raises BadCID if:
    - overall format doesn't match '<lowercase_alnum>:<lowercase_hex>'
    - digest length is wrong for a known scheme (e.g. sha256 needs 64 chars)
    """
    if not isinstance(cid, str) or not _CID_PATTERN.match(cid):
        raise BadCID(f"Malformed CID (expected '<scheme>:<lowercase_hex>'): {cid!r}")
    scheme, digest = cid.split(":", 1)
    expected = _DIGEST_LENGTHS.get(scheme)
    if expected is not None and len(digest) != expected:
        raise BadCID(
            f"CID scheme {scheme!r} requires a {expected}-char digest; "
            f"got {len(digest)} chars in {cid!r}"
        )
    return scheme, digest


@dataclass(frozen=True, eq=False)
class CID:
    """Immutable, content-addressed identifier.

    Equality and hashing are over (scheme, digest). Two CIDs whose hex
    digests happen to coincide under different schemes are NOT equal —
    hash domains are scheme-specific.
    """

    scheme: str
    digest: str

    @property
    def as_string(self) -> str:
        return f"{self.scheme}:{self.digest}"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CID):
            return NotImplemented
        return self.scheme == other.scheme and self.digest == other.digest

    def __hash__(self) -> int:
        return hash((self.scheme, self.digest))

    def __repr__(self) -> str:
        return f"CID({self.as_string!r})"
