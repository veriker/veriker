"""tests/test_fragment_anchor_coverage.py — present attestable quote claims must
be re-derived by SOMETHING, or the verdict is could-not-conclude (RES-06
follow-up, 2026-06-11).

An anchor carrying content_selector.exact asserts "source S says 'X'" — a
falsifiable quote claim. Before the fragment-anchor coverage guard, that claim
was re-derived ONLY when a FragmentAttestationCheck plugin happened to be wired:
the CLI wires it, but ``BundleVerifier()`` defaults to NO plugins, so a LIBRARY
consumer's verdict read OK over quote claims nothing had checked ("quote-
supported" reduced to "has a trusted CID label" — the RES-06 laundering shape,
at the verifier layer). The guard mirrors the ratified cross-host per-edge
pattern: present attestable anchor content-keys − plugin-reported verified
keys == ∅, else clean-ERROR.

Also pins the VE honesty disclosure: a VE-mode verdict states on its face
whether text-level quote fidelity was re-derived (n attestable anchors) or
rests on producer-side discipline (zero anchors).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from audit_bundle.output_modes.mode import (
    ModeSignal,
    OutputMode,
    mode_to_canonical_dict,
)
from audit_bundle.plugins.fragment_attestation import FragmentAttestationCheck
from audit_bundle.verdict import VERIFIER_INCOMPLETE, VerdictState
from audit_bundle.verifier import BundleVerifier

SNAPSHOT_TEXT = (
    "The claimant must satisfy the mutual obligation requirements. "
    "Failure to comply may result in a payment suspension."
)
GENUINE_QUOTE = "The claimant must satisfy the mutual obligation requirements."
SOURCE_CID = "sha256:" + hashlib.sha256(SNAPSHOT_TEXT.encode("utf-8")).hexdigest()
SNAP_REL = "snapshots/src-001.txt"

_bytes = SNAPSHOT_TEXT.encode("utf-8")
_START = _bytes.index(GENUINE_QUOTE.encode("utf-8"))
_END = _START + len(GENUINE_QUOTE.encode("utf-8"))


def _attestable_anchor() -> dict:
    return {
        "kind": "byte_offset",
        "source_cid": SOURCE_CID,
        "start": _START,
        "end": _END,
        "content_selector": {"type": "TextQuoteSelector", "exact": GENUINE_QUOTE},
    }


def _pure_locator_anchor() -> dict:
    # No content_selector.exact — asserts nothing falsifiable about a quote.
    return {
        "kind": "byte_offset",
        "source_cid": SOURCE_CID,
        "start": _START,
        "end": _END,
    }


def _build_bundle(
    tmp_path: Path,
    anchors: dict,
    *,
    ve_mode: bool = False,
) -> Path:
    bundle_dir = tmp_path / "bundle"
    (bundle_dir / "snapshots").mkdir(parents=True, exist_ok=True)
    snap_path = bundle_dir / SNAP_REL
    snap_path.write_text(SNAPSHOT_TEXT, encoding="utf-8")

    manifest: dict = {
        "schema_version": "vcp-v1.1-canary4",
        "bundle_id": "frag-anchor-coverage-test",
        "files": {SNAP_REL: hashlib.sha256(_bytes).hexdigest()},
        "spec_files": {},
        "cross_refs": {},
        "typed_checks": [],
        "snapshots": {SOURCE_CID: SNAP_REL},
        "fragment_anchors": anchors,
        "snapshot_policy": {
            "policy_version": "0.1",
            "normalization_version": "0.1",
            "rendered_text_extractor": "identity",
            "raw_bytes_kept": True,
        },
    }
    if ve_mode:
        manifest["output_mode_signal"] = mode_to_canonical_dict(
            ModeSignal(
                mode=OutputMode.VE,
                generation_constraints=("quote_supported_only",),
            )
        )
    (bundle_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return bundle_dir


def _anchor_legs(result):
    return [r for r in result.reasons if r.check_name == "fragment_anchors"]


def test_pluginless_library_verify_fails_closed_on_attestable_anchor(tmp_path):
    """THE laundering regression: BundleVerifier() with no plugins must NOT
    conclude OK over a present quote claim nothing re-derived."""
    bundle_dir = _build_bundle(tmp_path, {"a1": _attestable_anchor()})
    result = BundleVerifier().verify(bundle_dir)
    assert result.state is VerdictState.ERROR, (
        "a present-but-unverified quote claim must be could-not-conclude, "
        f"got {result.state}"
    )
    legs = _anchor_legs(result)
    assert legs and legs[0].code == VERIFIER_INCOMPLETE
    assert "NOT re-derived" in legs[0].detail


def test_wired_fragment_attestation_covers_the_claims(tmp_path):
    bundle_dir = _build_bundle(tmp_path, {"a1": _attestable_anchor()})
    result = BundleVerifier(plugins=[FragmentAttestationCheck()]).verify(bundle_dir)
    assert result.ok, [(r.code, r.detail) for r in result.reasons]
    assert not _anchor_legs(result)


def test_pure_locator_anchor_imposes_no_coverage_obligation(tmp_path):
    bundle_dir = _build_bundle(tmp_path, {"loc1": _pure_locator_anchor()})
    result = BundleVerifier().verify(bundle_dir)
    assert result.ok, [(r.code, r.detail) for r in result.reasons]


def test_no_anchors_no_obligation(tmp_path):
    bundle_dir = _build_bundle(tmp_path, {})
    result = BundleVerifier().verify(bundle_dir)
    assert result.ok, [(r.code, r.detail) for r in result.reasons]


def test_ve_mode_with_zero_anchors_discloses_producer_discipline(tmp_path):
    """A VE verdict must say on its face when quote fidelity was NOT re-derived
    — 'VE' must not read as 'text verified' on a bundle with no quote claims."""
    bundle_dir = _build_bundle(tmp_path, {}, ve_mode=True)
    result = BundleVerifier().verify(bundle_dir)
    assert result.ok
    disclosures = result.completeness.disclosures
    assert any(
        d.startswith("output_mode:VE:") and "NO attestable fragment anchors" in d
        for d in disclosures
    ), disclosures


def test_ve_mode_with_verified_anchors_discloses_coverage(tmp_path):
    bundle_dir = _build_bundle(tmp_path, {"a1": _attestable_anchor()}, ve_mode=True)
    result = BundleVerifier(plugins=[FragmentAttestationCheck()]).verify(bundle_dir)
    assert result.ok
    disclosures = result.completeness.disclosures
    assert any(
        d.startswith("output_mode:VE:") and "1 attestable fragment anchor" in d
        for d in disclosures
    ), disclosures
