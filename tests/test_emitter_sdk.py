"""tests/test_emitter_sdk.py — the reference-emitter SDK pipeline + hook seams.

Proves the open SDK (audit_bundle.emitter) produces verifier-conformant bundles
and that the three hook seams compose their manifest contributions correctly,
including a synthetic *premium-shaped* injection (aggregate_stamp + dispatch
records + attestation block) without importing any premium module.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from audit_bundle.emitter import (
    AttestationResult,
    BundleContent,
    CausalChainResult,
    NullAttestationProvider,
    NullCausalChainEmitter,
    StaticTimestampProvider,
    TimestampResult,
    UnsafeBundleRelPath,
    assemble_manifest,
    sha256,
    write_bundle,
)
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck
from audit_bundle.verifier import BundleVerifier


def _content() -> BundleContent:
    return BundleContent(
        bundle_id="sdk-test-rc",
        created_at="2026-06-01T00:00:00Z",
        files={
            "data/rows.jsonl": b'{"a":1}\n{"a":2}\n',
            "payload/release.json": b'{"count": 2}\n',
        },
        spec_files={"rules.json": b'{"rule":"noop"}\n'},
        typed_checks=["spec_sha_pin", "file_integrity_many_small"],
    )


def test_write_bundle_is_verifier_green(tmp_path: Path) -> None:
    """A bundle emitted by write_bundle passes the substrate integrity checks."""
    out = tmp_path / "bundle"
    write_bundle(out, _content())

    verifier = BundleVerifier(plugins=[SpecShaPinCheck(), FileIntegrityManySmall()])
    result = verifier.verify(out)
    assert result.ok is True, result


def test_files_written_with_matching_digests(tmp_path: Path) -> None:
    out = tmp_path / "bundle"
    manifest = write_bundle(out, _content())

    # Content written verbatim at the declared paths.
    assert (out / "data/rows.jsonl").read_bytes() == b'{"a":1}\n{"a":2}\n'
    assert (out / "spec/rules.json").read_bytes() == b'{"rule":"noop"}\n'
    # Digests in the manifest match the on-disk bytes.
    assert manifest["files"]["data/rows.jsonl"] == sha256(b'{"a":1}\n{"a":2}\n')
    assert manifest["spec_files"]["rules.json"] == sha256(b'{"rule":"noop"}\n')


def test_canonical_manifest_is_sorted_and_newline_terminated(tmp_path: Path) -> None:
    out = tmp_path / "bundle"
    write_bundle(out, _content())
    text = (out / "manifest.json").read_text(encoding="utf-8")
    assert text.endswith("\n")
    reparsed = json.loads(text)
    # sort_keys=True → re-dumping with sort_keys reproduces the body.
    assert (
        json.dumps(reparsed, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        == text
    )


def test_open_defaults_emit_no_dispatch_or_stamp(tmp_path: Path) -> None:
    """Trivial/static family: default hooks add no dispatch_records, no
    aggregate_stamp, and created_at is the declared static value."""
    out = tmp_path / "bundle"
    manifest = write_bundle(out, _content())
    assert manifest["created_at"] == "2026-06-01T00:00:00Z"
    assert "dispatch_records" not in manifest
    assert "aggregate_stamp" not in manifest


def test_hooks_compose_premium_shaped_fields() -> None:
    """assemble_manifest merges all three hook contributions. Uses synthetic
    providers shaped like the premium tier (layer_b anchors + dispatch records +
    attestation) — no premium module is imported; the SDK only needs the
    interface. (TimestampResult deliberately has NO aggregate_stamp seam: the
    top-level manifest key is the §C14 lattice aggregate, never
    hook-minted — 2026-06-12 collision fix.)"""

    class _PremiumShapedTimestamp:
        def stamp(self) -> TimestampResult:
            return TimestampResult(
                created_at="2026-06-01T00:00:00Z",
                extra_manifest_fields={"layer_b_anchors": {"tsa_count": 4}},
            )

    class _ChainEmitter:
        def emit(self) -> CausalChainResult:
            return CausalChainResult(
                dispatch_records=({"idx": 0, "op": "COMPUTE"},),
                extra_manifest_fields={"causal_chain": {"events": 1}},
            )

    class _Attestor:
        def attest(self) -> AttestationResult:
            return AttestationResult(
                extra_manifest_fields={"attested_serving": {"tee": "synthetic"}}
            )

    manifest = assemble_manifest(
        _content(),
        timestamp_provider=_PremiumShapedTimestamp(),
        causal_chain_emitter=_ChainEmitter(),
        attestation_provider=_Attestor(),
        files_digests={"data/rows.jsonl": "deadbeef"},
        spec_digests={"rules.json": "cafef00d"},
    )

    assert "aggregate_stamp" not in manifest
    assert manifest["layer_b_anchors"] == {"tsa_count": 4}
    assert manifest["dispatch_records"] == [{"idx": 0, "op": "COMPUTE"}]
    assert manifest["causal_chain"] == {"events": 1}
    assert manifest["attested_serving"] == {"tee": "synthetic"}


def test_default_providers_are_noops() -> None:
    assert NullCausalChainEmitter().emit() == CausalChainResult()
    assert NullAttestationProvider().attest() == AttestationResult()
    assert StaticTimestampProvider("2026-06-01T00:00:00Z").stamp() == TimestampResult(
        created_at="2026-06-01T00:00:00Z"
    )


# ---------------------------------------------------------------------------
# RES-07 — write-side path discipline. The verifier's read side rejects
# traversal/absolute manifest paths (_safe_bundle_path, resolve_within); the
# emitter must apply the same discipline BEFORE bytes hit disk, so a hostile
# or merely-odd upstream filename can never write outside the bundle root or
# collide with the structural envelope files.
# ---------------------------------------------------------------------------

_BAD_REL_PATHS = [
    "../outside",  # the RES-07 traversal
    "a/../../outside",  # nested traversal
    "a/../b",  # resolves inside, but non-canonical (two spellings of one file)
    "/etc/target",  # POSIX absolute — pathlib `/` would discard the root
    "C:/target",  # Windows drive absolute
    "a\\b",  # backslash: separator on Windows, filename byte on POSIX
    "..",
    ".",
    "",
    "./a",  # dot segment
    "a//b",  # empty segment
    "a/",  # trailing-slash empty segment
]


@pytest.mark.parametrize("bad", _BAD_REL_PATHS)
def test_bad_files_key_rejected_before_any_write(tmp_path: Path, bad: str) -> None:
    """A non-canonical files key fails closed and leaves NO trace — not even
    the bundle scaffold, and never a byte outside out_dir."""
    out = tmp_path / "bundle"
    content = BundleContent(
        bundle_id="res07",
        created_at="2026-06-01T00:00:00Z",
        files={bad: b"poison"},
    )
    with pytest.raises(UnsafeBundleRelPath):
        write_bundle(out, content)
    assert not out.exists()
    assert not (tmp_path / "outside").exists()


@pytest.mark.parametrize("bad", _BAD_REL_PATHS)
def test_bad_spec_key_rejected_before_any_write(tmp_path: Path, bad: str) -> None:
    """spec_files keys get the same discipline (a `..` key would escape spec/
    and could overwrite a sibling content file or land outside the bundle)."""
    out = tmp_path / "bundle"
    content = BundleContent(
        bundle_id="res07",
        created_at="2026-06-01T00:00:00Z",
        spec_files={bad: b"poison"},
    )
    with pytest.raises(UnsafeBundleRelPath):
        write_bundle(out, content)
    assert not out.exists()


@pytest.mark.parametrize("envelope", ["manifest.json", "bundle.dsse.json"])
def test_envelope_names_rejected_as_files_keys(tmp_path: Path, envelope: str) -> None:
    """files may not name the structural envelope: the pipeline writes those
    itself, so an entry here records a digest the finished bundle no longer
    matches — and the seal path excludes envelope names from the sidecar, so
    the signature would never cover it."""
    out = tmp_path / "bundle"
    content = BundleContent(
        bundle_id="res07",
        created_at="2026-06-01T00:00:00Z",
        files={envelope: b"{}"},
    )
    with pytest.raises(UnsafeBundleRelPath):
        write_bundle(out, content)


def test_envelope_names_are_ordinary_under_spec(tmp_path: Path) -> None:
    """Envelope names are TOP-LEVEL-only (integrity_ownership: 'Top-level
    names only'); spec/manifest.json is just a pinned spec document."""
    out = tmp_path / "bundle"
    content = BundleContent(
        bundle_id="res07",
        created_at="2026-06-01T00:00:00Z",
        spec_files={"manifest.json": b'{"doc": true}\n'},
    )
    manifest = write_bundle(out, content)
    assert (out / "spec/manifest.json").read_bytes() == b'{"doc": true}\n'
    assert manifest["spec_files"]["manifest.json"] == sha256(b'{"doc": true}\n')


def test_symlink_prefix_cannot_redirect_writes(tmp_path: Path) -> None:
    """Lexically-clean key, but a symlink dir already inside out_dir points
    out of tree — the resolve-containment guard in _write_file (the write-side
    twin of _safe_bundle_path) refuses before any byte lands outside."""
    outside = tmp_path / "outside"
    outside.mkdir()
    out = tmp_path / "bundle"
    out.mkdir()
    (out / "data").symlink_to(outside)
    content = BundleContent(
        bundle_id="res07",
        created_at="2026-06-01T00:00:00Z",
        files={"data/x.bin": b"poison"},
    )
    with pytest.raises(UnsafeBundleRelPath):
        write_bundle(out, content)
    assert not (outside / "x.bin").exists()


def test_assemble_manifest_rejects_bad_digest_keys() -> None:
    """Direct assemble_manifest callers (the write-it-yourself path) cannot
    assemble a manifest whose files/spec keys the verifier would path-reject."""
    content = BundleContent(bundle_id="res07", created_at="2026-06-01T00:00:00Z")
    with pytest.raises(UnsafeBundleRelPath):
        assemble_manifest(content, files_digests={"../x": "00"}, spec_digests={})
    with pytest.raises(UnsafeBundleRelPath):
        assemble_manifest(content, files_digests={}, spec_digests={"/abs": "00"})


# ---------------------------------------------------------------------------
# RES-08 — stale-root posture. write_bundle deliberately does NOT sweep
# pre-existing entries (builders write plugin-owned siblings into out_dir by
# design); the fail-closed authority is the verifier's unconditional
# conservation gate. These tests PIN that doctrine: a stale file can never
# ride a green verdict, and validate=True surfaces it at emit time.
# ---------------------------------------------------------------------------


def _flat_codes(verdict) -> list[str]:
    codes = [r.code for r in verdict.reasons]
    for leg in verdict.legs:
        codes.extend(_flat_codes(leg))
    return codes


def test_stale_file_in_root_never_rides_a_green_verdict(tmp_path: Path) -> None:
    """Emitting into a dirty root is allowed (no sweep, no delete) — and the
    verifier's conservation gate rejects the stale file in every lane."""
    out = tmp_path / "bundle"
    out.mkdir(parents=True)
    (out / "stale_evidence.json").write_bytes(b'{"from_prior_run": true}\n')

    write_bundle(out, _content())
    assert (out / "stale_evidence.json").exists()  # emitter did not delete it

    verifier = BundleVerifier(plugins=[SpecShaPinCheck(), FileIntegrityManySmall()])
    result = verifier.verify(out)
    assert result.ok is False
    assert "EXTRA_FILE_NOT_IN_MANIFEST" in _flat_codes(result)


def test_validate_true_catches_stale_root_at_emit(tmp_path: Path) -> None:
    """The opt-in self-check IS the emit-time stale-root check: it runs the
    verifier's own orchestration, so the conservation gate fires in-process
    and names the surplus path."""
    from audit_bundle.emitter.pipeline import BundleSelfCheckFailed

    out = tmp_path / "bundle"
    out.mkdir(parents=True)
    (out / "stale_evidence.json").write_bytes(b'{"from_prior_run": true}\n')

    with pytest.raises(BundleSelfCheckFailed, match="stale_evidence.json"):
        write_bundle(out, _content(), validate=True)


def test_multi_segment_spec_keys_still_allowed(tmp_path: Path) -> None:
    """Repo-relative spec keys (multi-segment, canonical) remain valid — the
    discipline rejects escape and non-canonical form, not nesting."""
    out = tmp_path / "bundle"
    content = BundleContent(
        bundle_id="res07",
        created_at="2026-06-01T00:00:00Z",
        spec_files={"schedules/2026/withholding.json": b"{}\n"},
    )
    manifest = write_bundle(out, content)
    assert (out / "spec/schedules/2026/withholding.json").exists()
    assert "schedules/2026/withholding.json" in manifest["spec_files"]
