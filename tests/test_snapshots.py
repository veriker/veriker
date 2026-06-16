"""Tests for audit_bundle snapshots: CID, SnapshotStore, IngestRecord, and BundleManifest integration."""
import hashlib
import json

import pytest

from audit_bundle.snapshots.cid import CID, BadCID, compute_cid, parse_cid
from audit_bundle.snapshots.snapshot_store import CIDCollision, SnapshotMissing, SnapshotStore
from audit_bundle.snapshots.ingest_record import (
    SnapshotIngestRecord,
    append_ingest_record,
    record_to_canonical_json,
)
from audit_bundle.snapshots.snapshot_policy import default_v1_policy, policy_to_canonical_dict
from audit_bundle.bundle_manifest import (
    BundleManifest,
    SnapshotCIDMismatch,
    SnapshotPolicyMissing,
    validate_manifest,
)


# ---------------------------------------------------------------------------
# CID tests
# ---------------------------------------------------------------------------


def test_compute_cid_stable():
    """Same bytes produce the same CID; different bytes produce different CIDs."""
    assert compute_cid(b"hello") == compute_cid(b"hello")
    assert compute_cid(b"hello") != compute_cid(b"world")


def test_cid_parse_roundtrip():
    """parse_cid(cid.as_string) returns the same scheme and digest."""
    cid_str = compute_cid(b"roundtrip test")
    scheme, digest = parse_cid(cid_str)
    cid = CID(scheme=scheme, digest=digest)
    scheme2, digest2 = parse_cid(cid.as_string)
    assert scheme2 == scheme
    assert digest2 == digest


def test_cid_malformed():
    """'foo', 'sha256:', and 'sha256:zzz' all raise BadCID."""
    for bad in ("foo", "sha256:", "sha256:zzz"):
        with pytest.raises(BadCID):
            parse_cid(bad)


# ---------------------------------------------------------------------------
# SnapshotStore tests
# ---------------------------------------------------------------------------


def test_snapshot_store_write_then_read(tmp_path):
    """write(raw) returns a CID; read(cid) returns the original bytes."""
    store = SnapshotStore(tmp_path / "store")
    payload = b"the quick brown fox"
    cid = store.write(payload)
    assert store.read(cid) == payload


def test_snapshot_store_idempotent_write(tmp_path):
    """Writing the same bytes twice returns the same CID without error."""
    store = SnapshotStore(tmp_path / "store")
    payload = b"idempotent payload"
    cid1 = store.write(payload)
    cid2 = store.write(payload)
    assert cid1 == cid2


def test_snapshot_store_collision(tmp_path, monkeypatch):
    """Monkeypatched compute_cid returning same CID for different payloads raises CIDCollision."""
    import audit_bundle.snapshots.snapshot_store as ss_mod

    store = SnapshotStore(tmp_path / "store")
    payload_a = b"first payload"
    payload_b = b"second different payload"

    # Write payload_a and capture its CID string
    cid_a = store.write(payload_a)
    fixed_cid_str = cid_a.as_string

    # Force compute_cid to always return cid_a's string regardless of input
    monkeypatch.setattr(ss_mod, "compute_cid", lambda raw, scheme="sha256": fixed_cid_str)

    with pytest.raises(CIDCollision):
        store.write(payload_b)


def test_snapshot_store_missing_read(tmp_path):
    """Reading a CID that was never written raises SnapshotMissing."""
    store = SnapshotStore(tmp_path / "store")
    cid = CID(scheme="sha256", digest="a" * 64)
    with pytest.raises(SnapshotMissing):
        store.read(cid)


# ---------------------------------------------------------------------------
# IngestRecord tests
# ---------------------------------------------------------------------------


def _make_record(source_url: str = "https://example.com") -> SnapshotIngestRecord:
    cid = CID(scheme="sha256", digest="b" * 64)
    return SnapshotIngestRecord(
        cid=cid,
        source_url=source_url,
        ingested_at="2026-04-30T00:00:00Z",
        policy_version="0.1",
        policy_dict_sha256="c" * 64,
    )


def test_ingest_record_canonical():
    """record_to_canonical_json produces identical bytes on repeated calls (deterministic JCS)."""
    record = _make_record()
    assert record_to_canonical_json(record) == record_to_canonical_json(record)


def test_append_ingest_record_append_only(tmp_path):
    """Appending 3 records: file size grows monotonically; read-back order is preserved."""
    path = tmp_path / "ingest.jsonl"
    urls = [
        "https://a.example.com",
        "https://b.example.com",
        "https://c.example.com",
    ]
    records = [_make_record(url) for url in urls]

    sizes: list[int] = []
    for r in records:
        append_ingest_record(path, r)
        sizes.append(path.stat().st_size)

    assert sizes[0] < sizes[1] < sizes[2], "File must grow monotonically after each append"

    lines = path.read_bytes().splitlines()
    assert len(lines) == 3
    for i, r in enumerate(records):
        parsed = json.loads(lines[i])
        assert parsed["source_url"] == r.source_url


# ---------------------------------------------------------------------------
# SnapshotPolicy regression guard
# ---------------------------------------------------------------------------

# Pinned at 2026-04-30; update only with an intentional policy spec change
# and a PR explaining the drift.
_EXPECTED_DEFAULT_V1_POLICY_SHA = (
    "671b2af4381150346387c2706b872fa2dc1abff49e22241eddcf580d83537b56"
)


def test_default_v1_policy_canonical_sha():
    """sha256 of default_v1_policy() canonical dict is stable (regression guard)."""

    def _sha(policy) -> str:
        d = policy_to_canonical_dict(policy)
        return hashlib.sha256(
            json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()

    sha1 = _sha(default_v1_policy())
    sha2 = _sha(default_v1_policy())
    assert sha1 == sha2, "Policy canonical sha must be stable across calls"
    assert sha1 == _EXPECTED_DEFAULT_V1_POLICY_SHA, (
        f"default_v1_policy has drifted; got {sha1!r}, "
        f"expected {_EXPECTED_DEFAULT_V1_POLICY_SHA!r}"
    )


# ---------------------------------------------------------------------------
# BundleManifest + snapshots integration
# ---------------------------------------------------------------------------


def test_bundle_manifest_with_snapshots(tmp_path):
    """Manifest with 2 snapshots validates cleanly; tampering raises CIDMismatch with
    the specific path; removing snapshot_policy raises SnapshotPolicyMissing."""
    bundle_dir = tmp_path / "bundle"
    snap_dir = bundle_dir / "snapshots"
    snap_dir.mkdir(parents=True)

    content_a = b"snapshot blob alpha"
    content_b = b"snapshot blob beta"

    cid_str_a = compute_cid(content_a)
    cid_str_b = compute_cid(content_b)

    # Use the first 8 hex chars of each digest as a short filename
    fname_a = snap_dir / (cid_str_a.split(":")[1][:8] + ".bin")
    fname_b = snap_dir / (cid_str_b.split(":")[1][:8] + ".bin")
    fname_a.write_bytes(content_a)
    fname_b.write_bytes(content_b)

    rel_a = fname_a.relative_to(bundle_dir).as_posix()
    rel_b = fname_b.relative_to(bundle_dir).as_posix()

    policy_dict = policy_to_canonical_dict(default_v1_policy())

    # Insert cid_str_a first so iteration order is deterministic (Python 3.7+ dicts)
    manifest = BundleManifest(
        schema_version="vcp-v1.1-canary4",
        bundle_id="test-bundle-snap-001",
        created_at="2026-04-30T00:00:00Z",
        files={},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
        snapshots={cid_str_a: rel_a, cid_str_b: rel_b},
        snapshot_policy=policy_dict,
    )

    # Baseline: clean validation must pass
    validate_manifest(manifest, bundle_dir)

    # Tamper snapshot_a → CIDMismatch must name that path
    fname_a.write_bytes(b"corrupted bytes")
    with pytest.raises(SnapshotCIDMismatch) as exc_info:
        validate_manifest(manifest, bundle_dir)
    assert rel_a in str(exc_info.value)

    # Restore snapshot_a; remove snapshot_policy → SnapshotPolicyMissing
    fname_a.write_bytes(content_a)
    manifest_no_policy = BundleManifest(
        schema_version="vcp-v1.1-canary4",
        bundle_id="test-bundle-snap-001",
        created_at="2026-04-30T00:00:00Z",
        files={},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
        snapshots={cid_str_a: rel_a, cid_str_b: rel_b},
        snapshot_policy=None,
    )
    with pytest.raises(SnapshotPolicyMissing):
        validate_manifest(manifest_no_policy, bundle_dir)
