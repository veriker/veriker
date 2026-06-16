"""RES-04 — one signed snapshot feeds all checks (single-read ratchet).

The bundle-level verifier previously read manifest.json up to FIVE times per
gated verify() call (cutover check, gate binding compare, admission,
manifest load, post-binding schema checks) and re-read + re-verified
bundle.dsse.json after the gate. Each extra read was a TOCTOU window, and the
post-binding re-reads swallowed OSError into empty values — silently
disabling checks 8a/8b under flaky storage or a post-gate swap.

These tests pin the fixed contract:
  (1) gated verify() reads manifest.json EXACTLY ONCE and bundle.dsse.json
      EXACTLY ONCE;
  (2) bytes swapped on disk after the first read are INVISIBLE — the verdict
      binds to the gate-checked snapshot;
  (3) the non-gated path also reads manifest.json exactly once (admission and
      parse cannot diverge);
  (4) 8a fires end-to-end at the bundle level: a signed header whose
      schema_version disagrees with the manifest's is rejected (previously
      only unit-tested via contract_slots).

Self-contained on the open surface: builds its own sealed bundles via
sign_envelope and a structural (_DsseCtx dataclass) DSSE context.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit_bundle.dsse.envelope import sign_envelope
from audit_bundle.dsse.pae import kid_from_raw32
from audit_bundle.revocation import RevocationList
from audit_bundle.verifier import BundleVerifier

_NOW = 1_770_000_000  # stable test clock


@dataclass
class _DsseCtx:
    """Structural stand-in for the verifier's DsseVerifyContext protocol.

    Not frozen: the protocol declares plain (writable) attributes, and a
    frozen dataclass's read-only attributes fail structural assignability.
    """

    allowlist: Mapping[str, bytes]
    revocation_list: RevocationList | None
    verifier_now: int = _NOW
    require_dsse: bool = True
    allow_legacy: bool = False


def _make_manifest(bundle_dir: Path, *, schema_version: str) -> bytes:
    manifest = {
        "schema_version": schema_version,
        "bundle_id": "res04-single-snapshot",
        "created_at": "2026-06-11T00:00:00Z",
        "files": {},
        "spec_files": {},
        "cross_refs": {},
        "payload": {},
        "typed_checks": [],
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    (bundle_dir / "manifest.json").write_bytes(manifest_bytes)
    return manifest_bytes


def _seal(
    bundle_dir: Path,
    manifest_bytes: bytes,
    key: Ed25519PrivateKey,
    *,
    header_schema_version: str,
) -> None:
    payload_bytes = rfc8785.dumps(
        {
            "schema_version": header_schema_version,
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "iat": _NOW,
            "files": [],  # no content files beyond the envelope pair
        }
    )
    sidecar = sign_envelope(payload_bytes, key)
    (bundle_dir / "bundle.dsse.json").write_bytes(
        json.dumps(sidecar, ensure_ascii=False).encode("utf-8")
    )


def _sealed_bundle(
    bundle_dir: Path, *, header_schema_version: str | None = None
) -> _DsseCtx:
    """Sealed post-cutover bundle + structural DSSE context for verify()."""
    bundle_dir.mkdir(parents=True, exist_ok=True)
    manifest_bytes = _make_manifest(bundle_dir, schema_version="vcp-v1.2-dsse")
    key = Ed25519PrivateKey.generate()
    _seal(
        bundle_dir,
        manifest_bytes,
        key,
        header_schema_version=header_schema_version or "vcp-v1.2-dsse",
    )
    pub_raw32 = key.public_key().public_bytes_raw()
    return _DsseCtx(
        allowlist={kid_from_raw32(pub_raw32): pub_raw32},
        revocation_list=RevocationList(
            entries={}, issued_at=_NOW, expires=_NOW + 3600, revocation_list_hash=""
        ),
    )


def _count_reads(monkeypatch) -> dict[str, int]:
    """Patch Path.read_bytes to count reads per file basename."""
    counts: dict[str, int] = {}
    real_read_bytes = Path.read_bytes

    def counted(self: Path) -> bytes:
        counts[self.name] = counts.get(self.name, 0) + 1
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", counted)
    return counts


def test_gated_verify_reads_each_envelope_file_exactly_once(
    tmp_path: Path, monkeypatch
) -> None:
    bundle_dir = tmp_path / "sealed"
    ctx = _sealed_bundle(bundle_dir)

    counts = _count_reads(monkeypatch)
    result = BundleVerifier().verify(bundle_dir, dsse=ctx)

    assert result.ok, f"sealed bundle must verify: {result}"
    assert counts.get("manifest.json") == 1, counts
    assert counts.get("bundle.dsse.json") == 1, counts


def test_post_gate_swap_is_invisible_to_the_verdict(
    tmp_path: Path, monkeypatch
) -> None:
    """Bytes swapped after the first read must not reach any later check.

    The swapped manifest carries a different schema_version; with the old
    post-binding re-read this would feed check 8a a manifest the gate never
    bound (and a swallowed read error would silently DISABLE 8a). With the
    single-snapshot contract the second read never happens at all.
    """
    bundle_dir = tmp_path / "sealed_swap"
    ctx = _sealed_bundle(bundle_dir)

    swapped = json.dumps(
        {"schema_version": "vcp-SWAPPED", "files": {}, "spec_files": {}}
    ).encode("utf-8")
    counts: dict[str, int] = {}
    real_read_bytes = Path.read_bytes

    def swap_after_first(self: Path) -> bytes:
        if self.name == "manifest.json":
            counts["manifest.json"] = counts.get("manifest.json", 0) + 1
            if counts["manifest.json"] > 1:
                return swapped
        return real_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", swap_after_first)
    result = BundleVerifier().verify(bundle_dir, dsse=ctx)

    assert counts["manifest.json"] == 1, (
        "manifest.json was re-read after the gate — the verdict is no longer "
        f"bound to the signed snapshot (reads={counts['manifest.json']})"
    )
    assert result.ok, f"swap after the only read must be invisible: {result}"


def test_nongated_verify_reads_manifest_exactly_once(
    tmp_path: Path, monkeypatch
) -> None:
    """Admission and parse must consume the same bytes on the legacy path too."""
    bundle_dir = tmp_path / "legacy"
    bundle_dir.mkdir()
    _make_manifest(bundle_dir, schema_version="vcp-v1.1")

    counts = _count_reads(monkeypatch)
    result = BundleVerifier().verify(bundle_dir)

    assert result.ok, f"legacy bundle must verify: {result}"
    assert counts.get("manifest.json") == 1, counts


def test_8a_header_manifest_disagreement_rejects_end_to_end(
    tmp_path: Path,
) -> None:
    """Bundle-level 8a e2e: payload binding valid, signed header schema_version
    disagrees with the manifest's → SCHEMA_VERSION_HEADER_MANIFEST_DISAGREE."""
    bundle_dir = tmp_path / "disagree"
    ctx = _sealed_bundle(bundle_dir, header_schema_version="vcp-v9.9-OTHER")

    result = BundleVerifier().verify(bundle_dir, dsse=ctx)

    assert not result.ok
    codes = {f.reason_code for f in result.failures}
    assert "SCHEMA_VERSION_HEADER_MANIFEST_DISAGREE" in codes, codes
