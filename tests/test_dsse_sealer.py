"""tests/test_dsse_sealer.py — DSSE WS-2: opt-in Ed25519 sidecar sealing.

Covers:
* bundle.dsse.json emitted only when dsse_signing_key is supplied.
* Sidecar structure: payloadType==PINNED_URI, one signature, payload decodes
  to JSON with schema_version / manifest_sha256 / files.
* payload.manifest_sha256 matches sha256 of the on-disk manifest.json bytes.
* payload.files set matches content+spec files (relative POSIX), sorted,
  excludes manifest.json + bundle.dsse.json.
* Manifest byte-stability: two write_bundle calls (one without key, one with)
  produce byte-identical manifest.json files.
* Round-trip: verify_envelope(...) returns ok=True.
* KeyLoaderError raised when env var is absent; valid key loaded when set.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from audit_bundle.dsse.envelope import PINNED_URI, verify_envelope
from audit_bundle.dsse.pae import (
    b64url_nopad_decode,
    kid_from_raw32,
)
from audit_bundle.emitter import BundleContent, write_bundle
from audit_bundle.vkernel_key_loader import (
    KeyLoaderError,
    load_signing_key,
    signing_key_from_seed,
)

# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------

_FIXED_SEED: bytes = b"\x01" * 32  # deterministic test key


def _signing_key():
    return signing_key_from_seed(_FIXED_SEED)


def _pubkey_raw32():
    key = _signing_key()
    return key.public_key().public_bytes_raw()


def _kid():
    return kid_from_raw32(_pubkey_raw32())


def _allowlist():
    return {_kid(): _pubkey_raw32()}


def _content() -> BundleContent:
    return BundleContent(
        bundle_id="dsse-sealer-test",
        created_at="2026-06-04T00:00:00Z",
        schema_version="vcp-v1.2-dsse",
        files={
            "data/rows.jsonl": b'{"a":1}\n{"a":2}\n',
            "payload/out.json": b'{"count":2}\n',
        },
        spec_files={"rules.json": b'{"rule":"noop"}\n'},
        typed_checks=[],
    )


# ---------------------------------------------------------------------------
# Sidecar structure tests.
# ---------------------------------------------------------------------------


def test_sidecar_emitted_when_key_provided(tmp_path: Path) -> None:
    """bundle.dsse.json is created when dsse_signing_key is supplied."""
    out = tmp_path / "bundle"
    write_bundle(out, _content(), dsse_signing_key=_signing_key(), dsse_iat=0)
    assert (out / "bundle.dsse.json").exists(), "sidecar not written"


def test_no_sidecar_without_key(tmp_path: Path) -> None:
    """bundle.dsse.json is NOT written when no signing key is supplied."""
    out = tmp_path / "bundle"
    write_bundle(out, _content())
    assert not (out / "bundle.dsse.json").exists(), "unexpected sidecar written"


def test_sidecar_payload_type(tmp_path: Path) -> None:
    out = tmp_path / "bundle"
    write_bundle(out, _content(), dsse_signing_key=_signing_key(), dsse_iat=0)
    sidecar = json.loads((out / "bundle.dsse.json").read_bytes())
    assert sidecar["payloadType"] == PINNED_URI


def test_sidecar_has_exactly_one_signature(tmp_path: Path) -> None:
    out = tmp_path / "bundle"
    write_bundle(out, _content(), dsse_signing_key=_signing_key(), dsse_iat=0)
    sidecar = json.loads((out / "bundle.dsse.json").read_bytes())
    assert len(sidecar["signatures"]) == 1


def test_payload_decodes_to_expected_structure(tmp_path: Path) -> None:
    """Payload must contain schema_version, manifest_sha256, iat, files."""
    out = tmp_path / "bundle"
    write_bundle(out, _content(), dsse_signing_key=_signing_key(), dsse_iat=0)
    sidecar = json.loads((out / "bundle.dsse.json").read_bytes())

    raw_payload = b64url_nopad_decode(sidecar["payload"])
    payload = json.loads(raw_payload)

    assert "schema_version" in payload
    assert "manifest_sha256" in payload
    assert "iat" in payload
    assert "files" in payload
    assert payload["schema_version"] == "vcp-v1.2-dsse"
    assert payload["iat"] == 0


def test_manifest_sha256_matches_on_disk_bytes(tmp_path: Path) -> None:
    """payload.manifest_sha256 must equal sha256 of the manifest.json bytes."""
    out = tmp_path / "bundle"
    write_bundle(out, _content(), dsse_signing_key=_signing_key(), dsse_iat=0)

    sidecar = json.loads((out / "bundle.dsse.json").read_bytes())
    raw_payload = b64url_nopad_decode(sidecar["payload"])
    payload = json.loads(raw_payload)

    manifest_bytes = (out / "manifest.json").read_bytes()
    expected_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    assert payload["manifest_sha256"] == expected_sha256


def test_files_sorted_and_excludes_manifest_and_sidecar(tmp_path: Path) -> None:
    """payload.files must be sorted by path; must NOT include manifest.json
    or bundle.dsse.json; must include all content + spec files."""
    out = tmp_path / "bundle"
    write_bundle(out, _content(), dsse_signing_key=_signing_key(), dsse_iat=0)

    sidecar = json.loads((out / "bundle.dsse.json").read_bytes())
    raw_payload = b64url_nopad_decode(sidecar["payload"])
    payload = json.loads(raw_payload)

    paths = [e["path"] for e in payload["files"]]

    # Sorted order.
    assert paths == sorted(paths), f"files not sorted: {paths}"

    # Excludes manifest.json and bundle.dsse.json.
    assert "manifest.json" not in paths
    assert "bundle.dsse.json" not in paths

    # Includes every content file (as declared in BundleContent.files).
    assert "data/rows.jsonl" in paths
    assert "payload/out.json" in paths

    # Includes every spec file (under spec/).
    assert "spec/rules.json" in paths


def test_files_sha256_values_match_digests(tmp_path: Path) -> None:
    """Each entry in payload.files must carry the sha256 of the on-disk file."""
    out = tmp_path / "bundle"
    write_bundle(out, _content(), dsse_signing_key=_signing_key(), dsse_iat=0)

    sidecar = json.loads((out / "bundle.dsse.json").read_bytes())
    raw_payload = b64url_nopad_decode(sidecar["payload"])
    payload = json.loads(raw_payload)

    by_path = {e["path"]: e["sha256"] for e in payload["files"]}

    for rel_path, file_bytes in _content().files.items():
        expected = hashlib.sha256(file_bytes).hexdigest()
        assert by_path[rel_path] == expected, (
            f"sha256 mismatch for {rel_path!r}: "
            f"expected {expected!r}, got {by_path[rel_path]!r}"
        )

    for rel_name, spec_bytes in _content().spec_files.items():
        full_rel = f"spec/{rel_name}"
        expected = hashlib.sha256(spec_bytes).hexdigest()
        assert by_path[full_rel] == expected, (
            f"sha256 mismatch for {full_rel!r}: "
            f"expected {expected!r}, got {by_path[full_rel]!r}"
        )


# ---------------------------------------------------------------------------
# Manifest byte-stability.
# ---------------------------------------------------------------------------


def test_manifest_bytes_identical_with_and_without_key(tmp_path: Path) -> None:
    """Sealing must NOT alter manifest.json bytes — byte-identical guarantee."""
    out_no_key = tmp_path / "bundle_no_key"
    out_with_key = tmp_path / "bundle_with_key"

    write_bundle(out_no_key, _content())
    write_bundle(out_with_key, _content(), dsse_signing_key=_signing_key(), dsse_iat=0)

    manifest_no_key = (out_no_key / "manifest.json").read_bytes()
    manifest_with_key = (out_with_key / "manifest.json").read_bytes()

    assert manifest_no_key == manifest_with_key, (
        "manifest.json changed when a signing key was supplied — byte-stability violated"
    )


# ---------------------------------------------------------------------------
# Round-trip verify.
# ---------------------------------------------------------------------------


def test_round_trip_verify_envelope_ok(tmp_path: Path) -> None:
    """verify_envelope with the correct allowlist must return ok=True."""
    out = tmp_path / "bundle"
    write_bundle(out, _content(), dsse_signing_key=_signing_key(), dsse_iat=0)

    sidecar_bytes = (out / "bundle.dsse.json").read_bytes()
    result = verify_envelope(sidecar_bytes, _allowlist())
    assert result.ok is True, f"verify_envelope failed: {result}"


def test_round_trip_verify_wrong_key_fails(tmp_path: Path) -> None:
    """verify_envelope with a DIFFERENT key in the allowlist must return ok=False."""
    out = tmp_path / "bundle"
    write_bundle(out, _content(), dsse_signing_key=_signing_key(), dsse_iat=0)

    # Build a wrong-key allowlist (different seed, mapped to the same kid — will
    # actually produce a different kid, so the lookup fails with DSSE_UNKNOWN_KID).
    wrong_key = signing_key_from_seed(b"\x02" * 32)
    wrong_raw32 = wrong_key.public_key().public_bytes_raw()
    wrong_allowlist = {kid_from_raw32(wrong_raw32): wrong_raw32}

    sidecar_bytes = (out / "bundle.dsse.json").read_bytes()
    result = verify_envelope(sidecar_bytes, wrong_allowlist)
    assert result.ok is False


# ---------------------------------------------------------------------------
# Key loader tests.
# ---------------------------------------------------------------------------


def test_load_signing_key_raises_on_absent_env(monkeypatch) -> None:
    """load_signing_key must raise KeyLoaderError when the env var is absent."""
    monkeypatch.delenv("VKERNEL_DSSE_SIGNING_KEY", raising=False)
    with pytest.raises(KeyLoaderError):
        load_signing_key()


def test_load_signing_key_from_base64url_env(monkeypatch) -> None:
    """load_signing_key must produce the correct key from a base64url-encoded seed."""
    seed = b"\x01" * 32
    encoded = base64.urlsafe_b64encode(seed).rstrip(b"=").decode("ascii")
    monkeypatch.setenv("VKERNEL_DSSE_SIGNING_KEY", encoded)

    key = load_signing_key()
    # Verify round-trips: the key signs and the expected public key verifies.
    pub_raw = key.public_key().public_bytes_raw()
    expected_pub_raw = signing_key_from_seed(seed).public_key().public_bytes_raw()
    assert pub_raw == expected_pub_raw


def test_load_signing_key_from_hex_env(monkeypatch) -> None:
    """load_signing_key must produce the correct key from a hex-encoded seed."""
    seed = b"\x02" * 32
    encoded_hex = seed.hex()  # 64 lowercase hex chars
    monkeypatch.setenv("VKERNEL_DSSE_SIGNING_KEY", encoded_hex)

    key = load_signing_key()
    pub_raw = key.public_key().public_bytes_raw()
    expected_pub_raw = signing_key_from_seed(seed).public_key().public_bytes_raw()
    assert pub_raw == expected_pub_raw


def test_load_signing_key_raises_on_malformed_env(monkeypatch) -> None:
    """load_signing_key must raise KeyLoaderError on garbage input."""
    monkeypatch.setenv("VKERNEL_DSSE_SIGNING_KEY", "not-a-valid-key!!!")
    with pytest.raises(KeyLoaderError):
        load_signing_key()


def test_signing_key_from_seed_wrong_length() -> None:
    """signing_key_from_seed must raise KeyLoaderError for non-32-byte seeds."""
    with pytest.raises(KeyLoaderError):
        signing_key_from_seed(b"\x01" * 16)
