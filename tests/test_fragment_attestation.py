"""Adversarial verify-path tests for L8 fragment attestation.

ADR: the internal design notes (LOCKED).

Broken-first: every adversarial mutation MUST make the REAL
BundleVerifier.verify() return ok=False. Before this plugin there was zero
coverage of span attestation through the verifier — fragment anchors were
"informational" and a fabricated quote attributed to a real, admitted source
rode along inside an otherwise-green bundle.

The attestation verdict is rendered solely from the deterministic_offset (byte
range or sentence index) over the FROZEN snapshot bytes, compared to the claimed
quote in content_selector.exact (ADR D3.b). Fail-closed on unresolvable source,
out-of-bounds offset, segmenter drift, or misquote (ADR D3.a).
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.dont_write_bytecode = True

from audit_bundle.fragments.sentence_segmenter import SEGMENTER_VERSION
from audit_bundle.plugins.fragment_attestation import FragmentAttestationCheck
from audit_bundle.verifier import BundleVerifier, VerifyResult

# A synthetic "admitted source" snapshot. Two sentences; sentence 0 is the
# passage genuine citations quote.
SNAPSHOT_TEXT = (
    "The claimant must satisfy the mutual obligation requirements. "
    "Failure to comply may result in a payment suspension."
)
GENUINE_QUOTE = "The claimant must satisfy the mutual obligation requirements."
SOURCE_CID = "sha256:" + hashlib.sha256(SNAPSHOT_TEXT.encode("utf-8")).hexdigest()
SNAP_REL = "snapshots/src-001.txt"

_first_bytes = SNAPSHOT_TEXT.encode("utf-8")
_GENUINE_START = _first_bytes.index(GENUINE_QUOTE.encode("utf-8"))
_GENUINE_END = _GENUINE_START + len(GENUINE_QUOTE.encode("utf-8"))


def _build_bundle(
    tmp_path: Path,
    anchors: dict,
    *,
    include_snapshot: bool = True,
    snapshot_text: str = SNAPSHOT_TEXT,
    declare_snapshot: bool = True,
) -> Path:
    """Write a minimal bundle: a source snapshot + a manifest with anchors."""
    bundle_dir = tmp_path / "bundle"
    (bundle_dir / "snapshots").mkdir(parents=True, exist_ok=True)

    files: dict[str, str] = {}
    if include_snapshot:
        snap_path = bundle_dir / SNAP_REL
        snap_path.write_text(snapshot_text, encoding="utf-8")
        files[SNAP_REL] = hashlib.sha256(snapshot_text.encode("utf-8")).hexdigest()

    manifest = {
        "schema_version": "vcp-v1.1-canary4",
        "bundle_id": "frag-attest-test",
        "files": files,
        "spec_files": {},
        "cross_refs": {},
        "typed_checks": [],
        "snapshots": {SOURCE_CID: SNAP_REL} if declare_snapshot else {},
        "fragment_anchors": anchors,
    }
    # A bundle that declares snapshots MUST declare how they were captured
    # (manifest contract step 6). Previously omitted because only the CLI ran
    # validate_manifest; now that verify() is complete-by-construction (ADR D5) the
    # gap is enforced, so this fixture carries a minimal honest snapshot_policy.
    if declare_snapshot:
        manifest["snapshot_policy"] = {
            "policy_version": "0.1",
            "normalization_version": "0.1",
            "rendered_text_extractor": "identity",
            "raw_bytes_kept": True,
        }
    (bundle_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return bundle_dir


def _verify(bundle_dir: Path) -> VerifyResult:
    return BundleVerifier(plugins=[FragmentAttestationCheck()]).verify(bundle_dir)


def _byte_anchor(
    exact: str, start: int = _GENUINE_START, end: int = _GENUINE_END
) -> dict:
    return {
        "kind": "byte_offset",
        "source_cid": SOURCE_CID,
        "start": start,
        "end": end,
        "content_selector": {"type": "TextQuoteSelector", "exact": exact},
    }


def _sentence_anchor(
    exact: str, index: int = 0, seg_ver: str | None = SEGMENTER_VERSION
) -> dict:
    a = {
        "kind": "sentence_id",
        "source_cid": SOURCE_CID,
        "sentence_index": index,
        "content_selector": {"type": "TextQuoteSelector", "exact": exact},
    }
    if seg_ver is not None:
        a["segmenter_version"] = seg_ver
    return a


def _reason_codes(result: VerifyResult) -> set[str]:
    """Reason detail strings carry the plugin's reason_code; surface them."""
    return {f.detail for f in result.failures}


# ---------------------------------------------------------------------------
# Genuine anchors PASS
# ---------------------------------------------------------------------------


def test_genuine_byte_offset_quote_passes(tmp_path: Path) -> None:
    bundle = _build_bundle(tmp_path, {"q1": _byte_anchor(GENUINE_QUOTE)})
    result = _verify(bundle)
    assert result.ok, [f.detail for f in result.failures]


def test_genuine_sentence_id_quote_passes(tmp_path: Path) -> None:
    bundle = _build_bundle(tmp_path, {"q1": _sentence_anchor(GENUINE_QUOTE, index=0)})
    result = _verify(bundle)
    assert result.ok, [f.detail for f in result.failures]


def test_pure_locator_anchor_without_claim_is_skipped(tmp_path: Path) -> None:
    """An anchor with no content_selector.exact asserts no quote -> not attested."""
    anchor = {"kind": "byte_offset", "source_cid": SOURCE_CID, "start": 0, "end": 5}
    bundle = _build_bundle(tmp_path, {"loc": anchor})
    result = _verify(bundle)
    assert result.ok, [f.detail for f in result.failures]


# ---------------------------------------------------------------------------
# The implemented property is NORMALIZED equality, NOT byte-exact (D7.d).
# These lock the honest scope so it can't be silently re-marketed as
# "byte for byte": a quote re-cased / re-punctuated / re-spaced versus its
# cited span STILL attests. (Truthfulness: the README must match this.)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "claimed",
    [
        GENUINE_QUOTE.upper(),  # case-insensitive (casefold)
        GENUINE_QUOTE.replace(".", ""),  # punctuation-insensitive (drop P*)
        "  The   claimant must satisfy the mutual obligation requirements.  ",  # ws
        "the claimant must satisfy the mutual obligation requirements",  # all three
    ],
)
def test_normalization_makes_attestation_case_punct_ws_insensitive(
    tmp_path: Path, claimed: str
) -> None:
    """A claimed quote that differs from the cited span ONLY in case,
    punctuation, or whitespace still attests — the comparison is normalized
    (NFC + casefold + punctuation-drop + whitespace-collapse), NOT byte-exact.
    Documents the real, weaker-than-'byte for byte' property the verifier ships."""
    bundle = _build_bundle(tmp_path, {"q1": _byte_anchor(claimed)})
    result = _verify(bundle)
    assert result.ok, [f.detail for f in result.failures]


# ---------------------------------------------------------------------------
# Adversarial mutations FAIL CLOSED (the load-bearing cases)
# ---------------------------------------------------------------------------


def test_fabricated_quote_byte_offset_fails(tmp_path: Path) -> None:
    """Real source, fabricated quote: bytes at the cited span != claim -> ok=False."""
    fabricated = "The claimant must NOT satisfy the obligation requirements."
    bundle = _build_bundle(tmp_path, {"q1": _byte_anchor(fabricated)})
    result = _verify(bundle)
    assert not result.ok
    assert any("MISQUOTE" in d for d in _reason_codes(result))


def test_fabricated_quote_sentence_id_fails(tmp_path: Path) -> None:
    fabricated = "Failure to comply has no consequences whatsoever."
    bundle = _build_bundle(tmp_path, {"q1": _sentence_anchor(fabricated, index=0)})
    result = _verify(bundle)
    assert not result.ok
    assert any("MISQUOTE" in d for d in _reason_codes(result))


def test_wrong_byte_range_out_of_bounds_fails(tmp_path: Path) -> None:
    bundle = _build_bundle(
        tmp_path, {"q1": _byte_anchor(GENUINE_QUOTE, start=0, end=10_000)}
    )
    result = _verify(bundle)
    assert not result.ok
    assert any("OUT_OF_BOUNDS" in d for d in _reason_codes(result))


def test_segmenter_version_drift_fails(tmp_path: Path) -> None:
    """A stored sentence anchor from a different segmenter version is detected."""
    bundle = _build_bundle(
        tmp_path, {"q1": _sentence_anchor(GENUINE_QUOTE, index=0, seg_ver="9.9-bogus")}
    )
    result = _verify(bundle)
    assert not result.ok
    assert any("SEGMENTER_MISMATCH" in d for d in _reason_codes(result))


def test_attestable_anchor_with_missing_snapshot_fails(tmp_path: Path) -> None:
    """A quote claim whose source_cid is not in snapshots cannot be re-derived."""
    bundle = _build_bundle(
        tmp_path, {"q1": _byte_anchor(GENUINE_QUOTE)}, declare_snapshot=False
    )
    result = _verify(bundle)
    assert not result.ok
    assert any("SOURCE_UNRESOLVABLE" in d for d in _reason_codes(result))


def test_attestable_anchor_with_deleted_snapshot_file_fails(tmp_path: Path) -> None:
    """source_cid declared in snapshots but the file is absent -> fail closed."""
    bundle = _build_bundle(tmp_path, {"q1": _byte_anchor(GENUINE_QUOTE)})
    (bundle / SNAP_REL).unlink()
    result = _verify(bundle)
    assert not result.ok
    # file_integrity OR fragment_attestation must flag it; the point is ok=False.
    assert any(
        "SOURCE_UNRESOLVABLE" in d or "missing" in d.lower()
        for d in _reason_codes(result)
    )


def _ns_manifest(anchors: dict, snapshots: dict):
    """A minimal manifest stand-in carrying only the two attrs the plugin reads,
    so the plugin's check() can be exercised in isolation (no full verify())."""
    import types

    return types.SimpleNamespace(fragment_anchors=anchors, snapshots=snapshots)


SECRET = "TOP-SECRET-HOSTFILE: db_password=hunter2; api_key=sk-leak-0xCAFEBABE"


@pytest.mark.parametrize(
    "rel_path",
    [
        "../claude_secret.txt",  # parent-dir traversal
        "../../../../etc/passwd",  # deep traversal
    ],
)
def test_snapshot_path_traversal_fails_closed_without_leak(
    tmp_path: Path, rel_path: str
) -> None:
    """A manifest snapshots value that resolves OUTSIDE the bundle must fail
    closed (FRAGMENT_SOURCE_UNRESOLVABLE) BEFORE any read — and must never
    surface out-of-bundle bytes in the failure detail. Regression for the
    arbitrary-host-file-read disclosure oracle (H1): pre-fix this plugin joined
    the manifest-controlled path with no containment check, read the escaped
    file, and printed ~200 bytes of it in the FRAGMENT_MISQUOTE detail."""
    bundle_dir = tmp_path / "bundle"
    (bundle_dir / "snapshots").mkdir(parents=True, exist_ok=True)
    # Plant a secret OUTSIDE the bundle tree, at the spot ../claude_secret.txt
    # resolves to (tmp_path/claude_secret.txt).
    (tmp_path / "claude_secret.txt").write_text(SECRET, encoding="utf-8")

    anchor = _byte_anchor(GENUINE_QUOTE)
    manifest = _ns_manifest({"q1": anchor}, {SOURCE_CID: rel_path})
    result = FragmentAttestationCheck().check(bundle_dir, manifest)

    assert not result.ok
    assert "SOURCE_UNRESOLVABLE" in result.reason_code
    # The disclosure oracle: no out-of-bundle bytes may ride along in the detail.
    assert SECRET not in result.detail
    assert "hunter2" not in result.detail


def test_snapshot_absolute_path_fails_closed_without_leak(tmp_path: Path) -> None:
    """An absolute snapshots value (pathlib's `/` absolutizes, discarding the
    bundle root) is the other half of the traversal oracle — same fail-closed,
    no-leak contract."""
    bundle_dir = tmp_path / "bundle"
    (bundle_dir / "snapshots").mkdir(parents=True, exist_ok=True)
    secret_file = tmp_path / "abs_secret.txt"
    secret_file.write_text(SECRET, encoding="utf-8")

    manifest = _ns_manifest(
        {"q1": _byte_anchor(GENUINE_QUOTE)}, {SOURCE_CID: str(secret_file)}
    )
    result = FragmentAttestationCheck().check(bundle_dir, manifest)

    assert not result.ok
    assert "SOURCE_UNRESOLVABLE" in result.reason_code
    assert SECRET not in result.detail
    assert "hunter2" not in result.detail


def test_reserved_kind_with_quote_claim_fails_closed(tmp_path: Path) -> None:
    """A page-coord (RESERVED resolver) anchor carrying a quote claim cannot
    be attested on the deterministic path -> fail closed, never silent-pass."""
    anchor = {
        "kind": "page_coord",
        "source_cid": SOURCE_CID,
        "page": 1,
        "x0": 0.0,
        "y0": 0.0,
        "x1": 10.0,
        "y1": 10.0,
        "content_selector": {"type": "TextQuoteSelector", "exact": GENUINE_QUOTE},
    }
    bundle = _build_bundle(tmp_path, {"q1": anchor})
    result = _verify(bundle)
    assert not result.ok
    assert any("RESERVED" in d for d in _reason_codes(result))


# ---------------------------------------------------------------------------
# BLOCK-02 — the plugin binds the bytes IT read to the declared source_cid.
# The attested/misquote claim names "source_cid=X"; that claim must be
# self-certifying over the plugin's OWN read, never deferred to the deep
# snapshot-CID validator's separate later read of the same path (under
# mid-run mutation the two reads can see different bytes, and the composite
# verdict would assert a CID-pinned source supports a quote it lacks).
# ---------------------------------------------------------------------------


def test_quote_present_but_bytes_not_cid_pinned_fails_closed(
    tmp_path: Path,
) -> None:
    """The BLOCK-02 split, made static: the snapshot file CONTAINS the claimed
    quote (the quote leg alone would attest), but its bytes do not hash to the
    declared source_cid. The plugin itself must refuse — attestation is only
    meaningful over the pinned bytes."""
    bundle_dir = tmp_path / "bundle"
    (bundle_dir / "snapshots").mkdir(parents=True)
    (bundle_dir / SNAP_REL).write_text(SNAPSHOT_TEXT, encoding="utf-8")
    foreign_cid = (
        "sha256:" + hashlib.sha256(b"entirely different pinned bytes").hexdigest()
    )
    anchor = dict(_byte_anchor(GENUINE_QUOTE))
    anchor["source_cid"] = foreign_cid

    manifest = _ns_manifest({"q1": anchor}, {foreign_cid: SNAP_REL})
    result = FragmentAttestationCheck().check(bundle_dir, manifest)

    assert not result.ok
    assert result.reason_code == "FRAGMENT_SOURCE_CID_MISMATCH"
    assert foreign_cid in result.detail


@pytest.mark.skipif(sys.platform != "linux", reason="symlink semantics")
def test_contained_symlink_to_regular_snapshot_still_attests(
    tmp_path: Path,
) -> None:
    """As-built tolerance parity with the strict-SHA walk (BLOCK-01): a
    snapshot declared via a CONTAINED symlink to a regular in-bundle file
    still attests — _safe_bundle_path resolves the link before the no-follow
    open, and the CID binding pins the target's bytes either way."""
    bundle_dir = tmp_path / "bundle"
    (bundle_dir / "snapshots").mkdir(parents=True)
    real = bundle_dir / "snapshots" / "real.txt"
    real.write_text(SNAPSHOT_TEXT, encoding="utf-8")
    link_rel = "snapshots/link.txt"
    (bundle_dir / link_rel).symlink_to(real)

    manifest = _ns_manifest({"q1": _byte_anchor(GENUINE_QUOTE)}, {SOURCE_CID: link_rel})
    result = FragmentAttestationCheck().check(bundle_dir, manifest)

    assert result.ok, result.detail
