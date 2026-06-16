"""Source properties schema for audit-bundle source registry.

Per SCOPING.md §Revised kernel item 3 and K2 lock: Properties 1+2+4+5 at v1.
Source governance (a curated authoritative registry / publisher accountability)
is a separate substrate, out of scope for this open verifier.

Source attributes are producer-declared properties checked against provided
inputs (not trust decisions the verifier makes):
  1. issuer identity (Property 1 — IssuerVerifier checks against a configured allow-list)
  2. signed artifact present (Property 2 — derived from SignatureVerifier)
  4. publication class (Property 4 — the producer's declared class label, transcribed)
  5. status flags if supplied (Property 5 — producer-declared; the verifier maintains no feed)

Immutable once stamped; history tracked via DecisionProvenance.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class BadPublicationClass(ValueError):
    """Raised by validate_publication_class for values not in the v1 set."""


class PublicationClass(str, Enum):
    """v1 publication class constants."""

    PEER_REVIEWED = "peer_reviewed"
    PRESS = "press"
    REGULATORY = "regulatory"
    BLOG = "blog"
    UNKNOWN = "unknown"


_V1_PUBLICATION_CLASSES: frozenset[str] = frozenset(m.value for m in PublicationClass)


def validate_publication_class(value: str) -> None:
    """Raise BadPublicationClass if value is not in the v1 set."""
    if value not in _V1_PUBLICATION_CLASSES:
        raise BadPublicationClass(
            f"{value!r} is not a valid v1 publication class; "
            f"expected one of {sorted(_V1_PUBLICATION_CLASSES)}"
        )


@dataclass(frozen=True, slots=True)
class SourceProperties:
    """Immutable snapshot of source attributes at a point in time.

    All fields frozen; designed for append-only stamping into audit bundles.
    schema_version enables schema evolution without mutation.

    external_status_flags is a tuple (RES-10): ``frozen=True`` locks only the
    top-level bindings, so the previous ``list[str]`` field let the
    "immutable snapshot" drift in place after construction — the same
    frozen-dataclass mutable-field class the package-wide ratchet
    (tests/test_frozen_field_ratchet.py) inventories. A list argument is
    coerced at construction, so existing callers are unaffected; the stored
    value has no mutation API at all, which removes this field from the
    ratchet's burn-down list outright.
    """

    source_cid: str
    issuer_identity_verified: bool
    issuer_identifier: str | None
    signed_artifact_present: bool
    signing_key_id: str | None
    publication_class: str
    external_status_flags: tuple[str, ...] = ()
    schema_version: str = "0.1"

    def __post_init__(self) -> None:
        # Coerce list→tuple BEFORE validating elements. A bare str is
        # rejected explicitly — tuple("ab") would silently char-split a
        # single flag into ("a", "b").
        flags = self.external_status_flags
        if isinstance(flags, (str, bytes)):
            raise TypeError(
                f"external_status_flags must be a sequence of flag strings, "
                f"not a single {type(flags).__name__}: {flags!r}"
            )
        flags = tuple(flags)
        for i, flag in enumerate(flags):
            if not isinstance(flag, str):
                raise TypeError(
                    f"external_status_flags[{i}] must be str; got {type(flag).__name__}"
                )
        object.__setattr__(self, "external_status_flags", flags)
        # Property 4 is a transcribed producer label, but the v1 set is
        # closed — an off-vocabulary class is rejected where the snapshot is
        # minted, not discovered later at the manifest parse boundary
        # (bundle_manifest validates bundle-side data; this guards the
        # producer/SDK construction path with the same single validator).
        validate_publication_class(self.publication_class)


def default_v1_property_set(source_cid: str) -> SourceProperties:
    """Return a no-claims baseline for source_cid before any verifier runs."""
    return SourceProperties(
        source_cid=source_cid,
        issuer_identity_verified=False,
        issuer_identifier=None,
        signed_artifact_present=False,
        signing_key_id=None,
        publication_class=PublicationClass.UNKNOWN,
        external_status_flags=(),
        schema_version="0.1",
    )


def properties_to_canonical_dict(props: SourceProperties) -> dict:
    """Return a JCS-canonicalizable dict for inclusion in BundleManifest.

    Keys are ordered lexicographically — pass to json.dumps(sort_keys=True)
    to produce a fully canonical JSON byte string.
    """
    return {
        "external_status_flags": list(props.external_status_flags),
        "issuer_identifier": props.issuer_identifier,
        "issuer_identity_verified": props.issuer_identity_verified,
        "publication_class": str(props.publication_class),
        "schema_version": props.schema_version,
        "signed_artifact_present": props.signed_artifact_present,
        "signing_key_id": props.signing_key_id,
        "source_cid": props.source_cid,
    }
