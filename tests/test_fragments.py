"""Tests for audit_bundle.fragments: fragment_id schemas, sentence_segmenter, and manifest integration."""
import pathlib
import pytest
from unittest.mock import patch

from audit_bundle.fragments.fragment_id import (
    BadFragmentID,
    ByteOffsetFragment,
    OpaqueFragment,
    PageCoordFragment,
    SentenceIDFragment,
    TimestampSampleFragment,
    fragment_from_dict,
    fragment_to_canonical_dict,
)
from audit_bundle.fragments.sentence_segmenter import (
    SEGMENTER_VERSION,
    resolve_byte_offset,
    resolve_sentence_id,
    segment_sentences,
)
from audit_bundle.snapshots.cid import compute_cid
from audit_bundle.snapshots.snapshot_policy import default_v1_policy, policy_to_canonical_dict
from audit_bundle.bundle_manifest import (
    BundleManifest,
    FragmentSourceUnreachable,
    validate_manifest,
)


# ---------------------------------------------------------------------------
# Roundtrip serialisation tests
# ---------------------------------------------------------------------------


def test_fragment_id_roundtrip_byte_offset():
    f = ByteOffsetFragment(source_cid="sha256:aabbcc", start=0, end=42)
    assert fragment_from_dict(fragment_to_canonical_dict(f)) == f


def test_fragment_id_roundtrip_sentence_id():
    f = SentenceIDFragment(source_cid="sha256:aabbcc", sentence_index=7)
    assert fragment_from_dict(fragment_to_canonical_dict(f)) == f


def test_fragment_id_roundtrip_page_coord():
    f = PageCoordFragment(
        source_cid="sha256:aabbcc", page=3, x0=0.0, y0=0.0, x1=100.0, y1=50.0
    )
    assert fragment_from_dict(fragment_to_canonical_dict(f)) == f


def test_fragment_id_roundtrip_timestamp_sample():
    f = TimestampSampleFragment(
        source_cid="sha256:aabbcc",
        timestamp_iso="2026-04-30T00:00:00Z",
        sensor_id="sensor-42",
        sample_index=5,
    )
    assert fragment_from_dict(fragment_to_canonical_dict(f)) == f


# ---------------------------------------------------------------------------
# OpaqueFragment — open-extension type for domains outside the four
# well-known kinds (graph reasoning, audio frames, supply-chain artifacts, ...)
# ---------------------------------------------------------------------------


def test_opaque_fragment_roundtrip_graph_kind():
    """Graph-reasoning domain: triple addressed by subject-predicate-object."""
    f = OpaqueFragment(
        source_cid="sha256:aabbcc",
        kind_tag="kg_triple",
        locator={"subject": "ex:Alice", "predicate": "ex:knows", "object": "ex:Bob"},
    )
    canonical = fragment_to_canonical_dict(f)
    assert canonical["kind"] == "opaque"
    assert canonical["kind_tag"] == "kg_triple"
    assert canonical["locator"] == {
        "subject": "ex:Alice", "predicate": "ex:knows", "object": "ex:Bob"
    }
    assert fragment_from_dict(canonical) == f


def test_opaque_fragment_roundtrip_audio_frame():
    """Audio-frame domain: stream + timestamp + channel."""
    f = OpaqueFragment(
        source_cid="sha256:audio01",
        kind_tag="audio_frame",
        locator={"stream_id": "ch1", "frame_index": 42, "channel": "L"},
    )
    assert fragment_from_dict(fragment_to_canonical_dict(f)) == f


def test_opaque_fragment_rejects_well_known_kind_tag():
    """kind_tag colliding with a well-known kind must be rejected — otherwise
    tagged-union dispatch in fragment_from_dict would be ambiguous."""
    for collision in ("byte_offset", "sentence_id", "page_coord", "timestamp_sample"):
        with pytest.raises(BadFragmentID, match="well-known"):
            OpaqueFragment(
                source_cid="sha256:aa", kind_tag=collision, locator={"x": 1}
            )


def test_opaque_fragment_rejects_reserved_opaque_tag():
    """kind_tag='opaque' is reserved as the discriminator value itself."""
    with pytest.raises(BadFragmentID, match="reserved"):
        OpaqueFragment(source_cid="sha256:aa", kind_tag="opaque", locator={})


def test_opaque_fragment_rejects_empty_kind_tag():
    with pytest.raises(BadFragmentID, match="non-empty string"):
        OpaqueFragment(source_cid="sha256:aa", kind_tag="", locator={})


def test_opaque_fragment_rejects_non_string_locator_keys():
    with pytest.raises(BadFragmentID, match="locator keys must be strings"):
        OpaqueFragment(
            source_cid="sha256:aa",
            kind_tag="kg_triple",
            locator={1: "non-string-key"},  # type: ignore[dict-item]
        )


def test_opaque_fragment_rejects_non_dict_locator():
    with pytest.raises(BadFragmentID, match="locator must be a dict"):
        OpaqueFragment(
            source_cid="sha256:aa",
            kind_tag="kg_triple",
            locator=["not-a-dict"],  # type: ignore[arg-type]
        )


def test_opaque_fragment_canonical_dict_isolates_caller_locator():
    """Mutating the original locator after construction must not leak into
    the canonical dict — the canonical form takes a defensive copy."""
    locator = {"subject": "ex:A"}
    f = OpaqueFragment(source_cid="sha256:aa", kind_tag="kg_triple", locator=locator)
    canonical = fragment_to_canonical_dict(f)
    locator["subject"] = "ex:MUTATED"
    assert canonical["locator"] == {"subject": "ex:A"}


# ---------------------------------------------------------------------------
# Kind dispatch
# ---------------------------------------------------------------------------


def test_fragment_id_kind_dispatch():
    d = {"kind": "byte_offset", "source_cid": "sha256:aabbcc", "start": 0, "end": 10}
    result = fragment_from_dict(d)
    assert isinstance(result, ByteOffsetFragment)
    assert result.start == 0
    assert result.end == 10


# ---------------------------------------------------------------------------
# Unknown kind
# ---------------------------------------------------------------------------


def test_fragment_id_unknown_kind():
    with pytest.raises(BadFragmentID):
        fragment_from_dict({"kind": "fancy_new_kind", "source_cid": "sha256:aabbcc"})


# ---------------------------------------------------------------------------
# Bounds validation
# ---------------------------------------------------------------------------


def test_fragment_id_bounds_validation():
    # end <= start must raise
    with pytest.raises(BadFragmentID):
        ByteOffsetFragment(source_cid="sha256:aabbcc", start=10, end=5)

    # page=0 is invalid (must be >= 1)
    with pytest.raises(BadFragmentID):
        PageCoordFragment(
            source_cid="sha256:aabbcc", page=0, x0=0.0, y0=0.0, x1=10.0, y1=10.0
        )


# ---------------------------------------------------------------------------
# Sentence segmenter — version constant (regression guard)
# ---------------------------------------------------------------------------


def test_segmenter_version_constant():
    assert SEGMENTER_VERSION == "0.1-decimal-aware-regex"


# ---------------------------------------------------------------------------
# Sentence segmenter — basic splitting
# ---------------------------------------------------------------------------


def test_segmenter_basic():
    result = segment_sentences("Hello. World!")
    assert len(result) == 2

    result2 = segment_sentences("Foo? Bar.")
    assert len(result2) == 2


# ---------------------------------------------------------------------------
# Sentence segmenter — decimal-aware (W1-W2 stamper bug regression guard)
# ---------------------------------------------------------------------------


def test_segmenter_decimal_aware():
    text = "The figure was 17.4 percent. Then 23.5 percent."
    result = segment_sentences(text)
    assert len(result) == 2, (
        f"Expected 2 sentences (decimal-aware split), got {len(result)}: {result!r}"
    )


# ---------------------------------------------------------------------------
# resolve_sentence_id
# ---------------------------------------------------------------------------


def test_resolve_sentence_id_in_range():
    text = "First sentence. Second sentence."
    tup = resolve_sentence_id(text, 0)
    assert len(tup) == 3  # (byte_start, byte_end, text)
    assert "First" in tup[2]

    tup1 = resolve_sentence_id(text, 1)
    assert "Second" in tup1[2]


def test_resolve_sentence_id_out_of_range():
    text = "Only one sentence."
    with pytest.raises(BadFragmentID):
        resolve_sentence_id(text, 5)

    with pytest.raises(BadFragmentID):
        resolve_sentence_id(text, -1)


# ---------------------------------------------------------------------------
# resolve_byte_offset
# ---------------------------------------------------------------------------


def test_resolve_byte_offset_in_range():
    text = "Hello World"
    frag = ByteOffsetFragment(source_cid="sha256:aabbcc", start=0, end=5)
    assert resolve_byte_offset(text, frag) == "Hello"

    frag2 = ByteOffsetFragment(source_cid="sha256:aabbcc", start=6, end=11)
    assert resolve_byte_offset(text, frag2) == "World"


def test_resolve_byte_offset_out_of_range():
    text = "Hi"
    frag = ByteOffsetFragment(source_cid="sha256:aabbcc", start=0, end=100)
    with pytest.raises(BadFragmentID):
        resolve_byte_offset(text, frag)


# ---------------------------------------------------------------------------
# BundleManifest + fragment_anchors integration
# ---------------------------------------------------------------------------


def test_manifest_with_fragment_anchors(tmp_path):
    """Manifest validates when snapshot present; FragmentSourceUnreachable when file gone.

    Step 7 of validate_manifest (SnapshotCIDMismatch) fires before Step 10
    (FragmentSourceUnreachable) because both check the same file path. To
    specifically exercise FragmentSourceUnreachable we patch Path.exists with a
    call-counter: the first call (Step 7) returns True so CID integrity passes;
    the second call (Step 10) returns False, exposing the unreachable-source
    path. Path.read_bytes is also patched so Step 7's compute_cid check succeeds.
    """
    bundle_dir = tmp_path / "bundle"
    snap_dir = bundle_dir / "snapshots"
    snap_dir.mkdir(parents=True)

    content = b"Sentence one. Sentence two."
    cid_str = compute_cid(content)
    rel_path = "snapshots/src.bin"
    snap_file = bundle_dir / rel_path
    snap_file.write_bytes(content)

    policy_dict = policy_to_canonical_dict(default_v1_policy())
    fragment_dict = {"kind": "sentence_id", "source_cid": cid_str, "sentence_index": 0}

    manifest = BundleManifest(
        schema_version="vcp-v1.1-canary4",
        bundle_id="frag-test-001",
        created_at="2026-04-30T00:00:00Z",
        files={},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
        snapshots={cid_str: rel_path},
        snapshot_policy=policy_dict,
        fragment_anchors={"anchor_0": fragment_dict},
    )

    # Passing: snapshot on disk, CID matches, fragment anchor valid
    validate_manifest(manifest, bundle_dir)

    # Remove snapshot file; patch Path.exists/read_bytes so Step 7 passes but
    # Step 10 sees the file as missing, triggering FragmentSourceUnreachable.
    snap_file.unlink()
    _target = str(snap_file)
    _calls = [0]
    _real_exists = pathlib.Path.exists
    _real_read = pathlib.Path.read_bytes

    def _patched_exists(self):
        if str(self) == _target:
            _calls[0] += 1
            return _calls[0] == 1  # True on first (Step 7), False on second (Step 10)
        return _real_exists(self)

    def _patched_read(self):
        if str(self) == _target:
            return content  # correct bytes so compute_cid passes in Step 7
        return _real_read(self)

    with patch.object(pathlib.Path, "exists", _patched_exists), \
         patch.object(pathlib.Path, "read_bytes", _patched_read):
        with pytest.raises(FragmentSourceUnreachable):
            validate_manifest(manifest, bundle_dir)
