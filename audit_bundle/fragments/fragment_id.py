"""Tagged-union FragmentID schema for sub-document addressing.

Four well-known concrete fragment types cover the main source modalities
shipped to date:
  ByteOffsetFragment    — byte-range in a text/binary blob
  SentenceIDFragment    — sentence-granularity in NLP pipelines
  PageCoordFragment     — PDF page + bounding box
  TimestampSampleFragment — time-series / sensor domains (SAM-V2)

Plus a generic open-extension type for domains outside the four well-known
modalities (graph reasoning, audio frames, video shots, supply-chain
artifact paths, ...):
  OpaqueFragment        — caller-tagged kind + locator dict; substrate
                          performs only shape validation, semantic
                          validation is plugin-registered

The 'kind' discriminator field in canonical dicts lets consumers dispatch
without isinstance checks, which is necessary for cross-language consumers
that receive JCS-serialised JSON. OpaqueFragment uses kind='opaque' as
the discriminator and carries kind_tag for the user-specified subtype.
"""
from __future__ import annotations

from dataclasses import dataclass


class BadFragmentID(ValueError):
    """Raised when a fragment dict is malformed, has an unknown kind, or fails bounds checks."""


# ---------------------------------------------------------------------------
# Concrete fragment types
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ByteOffsetFragment:
    """Half-open byte-range [start, end) within the content identified by source_cid."""
    source_cid: str
    start: int
    end: int

    def __post_init__(self) -> None:
        if self.start < 0 or self.end < 0:
            raise BadFragmentID(f"ByteOffsetFragment: start and end must be >= 0; got start={self.start}, end={self.end}")
        if self.end <= self.start:
            raise BadFragmentID(f"ByteOffsetFragment: end must be > start; got start={self.start}, end={self.end}")


@dataclass(frozen=True, slots=True)
class SentenceIDFragment:
    """0-based index into the deterministic sentence segmentation of source_cid."""
    source_cid: str
    sentence_index: int

    def __post_init__(self) -> None:
        if self.sentence_index < 0:
            raise BadFragmentID(f"SentenceIDFragment: sentence_index must be >= 0; got {self.sentence_index}")


@dataclass(frozen=True, slots=True)
class PageCoordFragment:
    """PDF-style bounding box on a specific page (1-based) of source_cid."""
    source_cid: str
    page: int
    x0: float
    y0: float
    x1: float
    y1: float

    def __post_init__(self) -> None:
        if self.page < 1:
            raise BadFragmentID(f"PageCoordFragment: page must be >= 1; got {self.page}")
        if self.x1 <= self.x0:
            raise BadFragmentID(f"PageCoordFragment: x1 must be > x0; got x0={self.x0}, x1={self.x1}")
        if self.y1 <= self.y0:
            raise BadFragmentID(f"PageCoordFragment: y1 must be > y0; got y0={self.y0}, y1={self.y1}")


@dataclass(frozen=True, slots=True)
class TimestampSampleFragment:
    """Single sensor sample in a time-series source (required for SAM-V2 integration)."""
    source_cid: str
    timestamp_iso: str
    sensor_id: str
    sample_index: int

    def __post_init__(self) -> None:
        if self.sample_index < 0:
            raise BadFragmentID(f"TimestampSampleFragment: sample_index must be >= 0; got {self.sample_index}")


# Reserved discriminator values for the four well-known fragment kinds. An
# OpaqueFragment.kind_tag may not collide with any of these, otherwise the
# tagged-union dispatch in fragment_from_dict would break.
_WELL_KNOWN_KIND_TAGS: frozenset[str] = frozenset(
    {"byte_offset", "sentence_id", "page_coord", "timestamp_sample"}
)


@dataclass(frozen=True)
class OpaqueFragment:
    """Open-extension fragment for domains outside the four well-known kinds.

    The substrate validates only shape:
      - kind_tag is a non-empty string distinct from the well-known kinds
      - locator is a dict with string keys
    Per-domain semantic validation is the responsibility of a TypedCheck
    plugin registered against the bundle. The locator dict must be
    JCS-canonicalizable (string keys, JSON-primitive values) so the
    overall manifest stays deterministic; deep canonicalization happens
    at the JCS-serialization layer, not here.

    Note on immutability: dataclass(frozen=True) prevents attribute
    rebinding but cannot prevent mutation of the locator dict in place.
    Callers passing the dict are responsible for not mutating it after
    construction. Slots are intentionally NOT enabled (dict field
    interacts poorly with frozen+slots default-factory semantics).
    """

    source_cid: str
    kind_tag: str
    locator: dict

    def __post_init__(self) -> None:
        if not isinstance(self.kind_tag, str) or not self.kind_tag:
            raise BadFragmentID(
                f"OpaqueFragment: kind_tag must be a non-empty string; got {self.kind_tag!r}"
            )
        if self.kind_tag in _WELL_KNOWN_KIND_TAGS:
            raise BadFragmentID(
                f"OpaqueFragment: kind_tag={self.kind_tag!r} collides with a "
                f"well-known kind discriminator; use the dedicated fragment "
                f"class (one of ByteOffsetFragment / SentenceIDFragment / "
                f"PageCoordFragment / TimestampSampleFragment) instead"
            )
        if self.kind_tag == _KIND_OPAQUE:
            raise BadFragmentID(
                f"OpaqueFragment: kind_tag={self.kind_tag!r} collides with the "
                f"reserved 'opaque' discriminator; pick a domain-specific tag"
            )
        if not isinstance(self.locator, dict):
            raise BadFragmentID(
                f"OpaqueFragment: locator must be a dict; got {type(self.locator).__name__}"
            )
        for key in self.locator.keys():
            if not isinstance(key, str):
                raise BadFragmentID(
                    f"OpaqueFragment: locator keys must be strings; got {key!r} "
                    f"({type(key).__name__})"
                )


# ---------------------------------------------------------------------------
# Union type
# ---------------------------------------------------------------------------

FragmentID = (
    ByteOffsetFragment
    | SentenceIDFragment
    | PageCoordFragment
    | TimestampSampleFragment
    | OpaqueFragment
)

# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

_KIND_BYTE_OFFSET = 'byte_offset'
_KIND_SENTENCE_ID = 'sentence_id'
_KIND_PAGE_COORD = 'page_coord'
_KIND_TIMESTAMP_SAMPLE = 'timestamp_sample'
_KIND_OPAQUE = 'opaque'

_KIND_MAP: dict[type, str] = {
    ByteOffsetFragment: _KIND_BYTE_OFFSET,
    SentenceIDFragment: _KIND_SENTENCE_ID,
    PageCoordFragment: _KIND_PAGE_COORD,
    TimestampSampleFragment: _KIND_TIMESTAMP_SAMPLE,
    OpaqueFragment: _KIND_OPAQUE,
}


def fragment_to_canonical_dict(fragment: FragmentID) -> dict:
    """Return a JCS-canonicalizable dict with a 'kind' discriminator.

    Key ordering follows JCS (RFC 8785): alphabetical. The dict is plain Python
    — callers are responsible for passing it to json.dumps(sort_keys=True) if
    they need a canonical JSON byte string.
    """
    kind = _KIND_MAP.get(type(fragment))
    if kind is None:
        raise BadFragmentID(f"Unknown FragmentID type: {type(fragment)!r}")

    if isinstance(fragment, ByteOffsetFragment):
        return {
            'end': fragment.end,
            'kind': kind,
            'source_cid': fragment.source_cid,
            'start': fragment.start,
        }
    if isinstance(fragment, SentenceIDFragment):
        return {
            'kind': kind,
            'sentence_index': fragment.sentence_index,
            'source_cid': fragment.source_cid,
        }
    if isinstance(fragment, PageCoordFragment):
        return {
            'kind': kind,
            'page': fragment.page,
            'source_cid': fragment.source_cid,
            'x0': fragment.x0,
            'x1': fragment.x1,
            'y0': fragment.y0,
            'y1': fragment.y1,
        }
    if isinstance(fragment, TimestampSampleFragment):
        return {
            'kind': kind,
            'sample_index': fragment.sample_index,
            'sensor_id': fragment.sensor_id,
            'source_cid': fragment.source_cid,
            'timestamp_iso': fragment.timestamp_iso,
        }
    # OpaqueFragment — locator copied so the canonical dict is independent
    # of any subsequent caller-side mutation of the original locator dict.
    return {
        'kind': kind,
        'kind_tag': fragment.kind_tag,
        'locator': dict(fragment.locator),
        'source_cid': fragment.source_cid,
    }


def fragment_from_dict(d: dict) -> FragmentID:
    """Reconstruct a FragmentID from a canonical dict.

    Raises BadFragmentID on:
    - missing or unknown 'kind'
    - missing required fields
    - bounds violations (delegated to __post_init__)
    """
    if not isinstance(d, dict):
        raise BadFragmentID(f"Expected a dict, got {type(d)!r}")

    kind = d.get('kind')
    if kind is None:
        raise BadFragmentID("Missing required field 'kind' in fragment dict")

    try:
        if kind == _KIND_BYTE_OFFSET:
            return ByteOffsetFragment(
                source_cid=d['source_cid'],
                start=d['start'],
                end=d['end'],
            )
        if kind == _KIND_SENTENCE_ID:
            return SentenceIDFragment(
                source_cid=d['source_cid'],
                sentence_index=d['sentence_index'],
            )
        if kind == _KIND_PAGE_COORD:
            return PageCoordFragment(
                source_cid=d['source_cid'],
                page=d['page'],
                x0=d['x0'],
                y0=d['y0'],
                x1=d['x1'],
                y1=d['y1'],
            )
        if kind == _KIND_TIMESTAMP_SAMPLE:
            return TimestampSampleFragment(
                source_cid=d['source_cid'],
                timestamp_iso=d['timestamp_iso'],
                sensor_id=d['sensor_id'],
                sample_index=d['sample_index'],
            )
        if kind == _KIND_OPAQUE:
            locator = d['locator']
            if not isinstance(locator, dict):
                raise BadFragmentID(
                    f"OpaqueFragment: locator must be a dict in canonical form; "
                    f"got {type(locator).__name__}"
                )
            return OpaqueFragment(
                source_cid=d['source_cid'],
                kind_tag=d['kind_tag'],
                locator=dict(locator),  # defensive copy on the deserialization boundary
            )
    except KeyError as exc:
        raise BadFragmentID(f"Missing required field {exc} for kind={kind!r}") from exc

    raise BadFragmentID(f"Unknown fragment kind: {kind!r}")
