"""Tests: three-set manifest (vc-c6-001) + sum-invariant plugin (vc-c6-002)."""

from __future__ import annotations

import types

import pytest

from audit_bundle.bundle_manifest import (
    BundleManifest,
    validate_manifest,
)
from audit_bundle.manifest_three_set import (
    BadVisibilityPolicy,
    PerOutputManifest,
    ThreeSetMismatch,
    per_output_manifest_to_canonical_dict,
    validate_per_output_manifest,
)
from audit_bundle.output_modes.mode import (
    ModeSignal,
    OutputMode,
    mode_to_canonical_dict,
)
from audit_bundle.plugins.three_set_sum_invariant import ThreeSetSumInvariantCheck
from audit_bundle.retrieval.capture import capture_trace, load_trace
from audit_bundle.retrieval.three_set import (
    derive_three_set,
    three_set_to_canonical_dict,
)
from audit_bundle.snapshots.cid import compute_cid
from audit_bundle.snapshots.snapshot_policy import (
    default_v1_policy,
    policy_to_canonical_dict,
)


# ---------------------------------------------------------------------------
# Shared CIDs
# ---------------------------------------------------------------------------

_CID_A = "sha256:" + "a" * 64
_CID_B = "sha256:" + "b" * 64
_CID_C = "sha256:" + "c" * 64


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _capture(
    tmp_path,
    trace_id: str,
    candidates: list[str],
    context: list[str],
    log_rel: str = "traces.jsonl",
) -> str:
    """Capture a trace to bundle_dir; return bundle-relative log path."""
    log = tmp_path / log_rel
    selected = [
        {
            "source_cid": cid,
            "fragment": {"kind": "byte_offset", "start": i * 10, "end": i * 10 + 5},
            "rank": i,
        }
        for i, cid in enumerate(context)
    ]
    rankings = [(cid, float(len(candidates) - i)) for i, cid in enumerate(candidates)]
    capture_trace(
        trace_id=trace_id,
        retriever_name="bm25_v0",
        retriever_version="0.1.0",
        query="test query",
        candidate_source_cids=candidates,
        rankings=rankings,
        selected_chunks=selected,
        context_window_source_cids=context,
        model_router_version="router-v0.1",
        output_jsonl_path=log,
    )
    return log_rel


def _make_snapshot(bundle_dir, content: bytes) -> tuple[str, str]:
    """Write a snapshot file; return (cid_str, bundle-relative path)."""
    snaps = bundle_dir / "snapshots"
    snaps.mkdir(parents=True, exist_ok=True)
    cid = compute_cid(content)
    short = cid.split(":")[1][:16]
    fpath = snaps / f"{short}.bin"
    fpath.write_bytes(content)
    return cid, fpath.relative_to(bundle_dir).as_posix()


def _props_dict(source_cid: str) -> dict:
    return {
        "issuer_identity_verified": False,
        "issuer_identifier": None,
        "signed_artifact_present": False,
        "signing_key_id": None,
        "publication_class": "regulatory",
        "external_status_flags": [],
        "schema_version": "0.1",
        "source_cid": source_cid,
    }


def _mock_manifest(per_output_manifests, snapshots=None, source_attributes=None):
    """Minimal namespace accepted by ThreeSetSumInvariantCheck.check()."""
    return types.SimpleNamespace(
        per_output_manifests=tuple(per_output_manifests),
        snapshots=dict(snapshots or {}),
        source_attributes=dict(source_attributes or {}),
    )


# ---------------------------------------------------------------------------
# PerOutputManifest — canonical roundtrip
# ---------------------------------------------------------------------------


def test_per_output_manifest_canonical_roundtrip():
    """PerOutputManifest → canonical dict → reconstruct → equality."""
    three_set = {
        "context_injected": sorted([_CID_A, _CID_B]),
        "quote_supporting": [_CID_A],
        "retrieved": sorted([_CID_A, _CID_B, _CID_C]),
    }
    pom = PerOutputManifest(
        output_id="out-001",
        trace_id="trace-001",
        three_set=three_set,
        visibility_policy="customer_visible",
        emitted_at="2026-05-01T00:00:00.000Z",
    )
    canon = per_output_manifest_to_canonical_dict(pom)
    restored = PerOutputManifest(
        output_id=canon["output_id"],
        trace_id=canon["trace_id"],
        three_set=canon["three_set"],
        visibility_policy=canon["visibility_policy"],
        emitted_at=canon["emitted_at"],
    )
    assert restored == pom
    # All five canonical keys present
    assert set(canon) == {
        "output_id",
        "trace_id",
        "three_set",
        "visibility_policy",
        "emitted_at",
    }


# ---------------------------------------------------------------------------
# validate_per_output_manifest — matching three_set passes
# ---------------------------------------------------------------------------


def test_validate_per_output_manifest_match(tmp_path):
    """Stored three_set derived from the real trace passes validation."""
    trace_id = "trace-match-001"
    log_rel = _capture(tmp_path, trace_id, [_CID_A, _CID_B, _CID_C], [_CID_A, _CID_B])

    trace = load_trace(tmp_path / log_rel, trace_id)
    view = derive_three_set(trace, stamped_source_cids=[_CID_A])
    three_set = three_set_to_canonical_dict(view)

    pom = PerOutputManifest(
        output_id="out-match-001",
        trace_id=trace_id,
        three_set=three_set,
        visibility_policy="customer_visible",
        emitted_at="2026-05-01T00:00:00.000Z",
    )
    manifest = BundleManifest(
        schema_version="vcp-v1.1-canary4",
        bundle_id="bundle-match",
        created_at="2026-05-01T00:00:00Z",
        files={},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
        retrieval_trace_log=log_rel,
    )
    validate_per_output_manifest(pom, manifest, tmp_path)  # must not raise


# ---------------------------------------------------------------------------
# validate_per_output_manifest — duplicate trace_id in the log (RES-12) and
# malformed log content both land in the ThreeSetMismatch contract (this call
# site previously caught only TraceNotFound/OSError, so a RetrievalTraceError
# escaped as a raw exception despite load_trace's docstring listing it).
# ---------------------------------------------------------------------------


def test_validate_per_output_manifest_duplicate_trace_id(tmp_path):
    """A second log record reusing the bound trace_id → ThreeSetMismatch,
    never a silent first-match bind."""
    trace_id = "trace-dup-001"
    log_rel = _capture(tmp_path, trace_id, [_CID_A, _CID_B, _CID_C], [_CID_A, _CID_B])

    trace = load_trace(tmp_path / log_rel, trace_id)
    view = derive_three_set(trace, stamped_source_cids=[_CID_A])
    three_set = three_set_to_canonical_dict(view)

    # Shadow attempt: append a second record reusing the same trace_id.
    import json as _json

    from audit_bundle.retrieval.trace import trace_to_canonical_dict as _tcd

    shadow = _tcd(trace)
    with (tmp_path / log_rel).open("a", encoding="utf-8") as fh:
        fh.write(_json.dumps(shadow, sort_keys=True) + "\n")

    pom = PerOutputManifest(
        output_id="out-dup-001",
        trace_id=trace_id,
        three_set=three_set,
        visibility_policy="customer_visible",
        emitted_at="2026-05-01T00:00:00.000Z",
    )
    manifest = BundleManifest(
        schema_version="vcp-v1.1-canary4",
        bundle_id="bundle-dup",
        created_at="2026-05-01T00:00:00Z",
        files={},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
        retrieval_trace_log=log_rel,
    )
    with pytest.raises(ThreeSetMismatch, match="malformed or ambiguous"):
        validate_per_output_manifest(pom, manifest, tmp_path)


# ---------------------------------------------------------------------------
# validate_per_output_manifest — tampered three_set raises ThreeSetMismatch
# ---------------------------------------------------------------------------


def test_validate_per_output_manifest_tampered(tmp_path):
    """Tampering the stored three_set (dropping a cid from retrieved) raises ThreeSetMismatch.

    The validator re-derives the three-set from the immutable trace and compares
    it to the stored dict.  An attacker who drops a cid from the retrieved set
    (to conceal a consulted source) produces a mismatch that is always detected.
    """
    trace_id = "trace-tamper-001"
    log_rel = _capture(tmp_path, trace_id, [_CID_A, _CID_B, _CID_C], [_CID_A, _CID_B])

    trace = load_trace(tmp_path / log_rel, trace_id)
    view = derive_three_set(trace, stamped_source_cids=[_CID_A])
    valid_three_set = three_set_to_canonical_dict(view)

    # Tamper: drop _CID_C from retrieved (attacker tries to hide that source C was considered)
    tampered_three_set = dict(valid_three_set)
    tampered_three_set["retrieved"] = [
        cid for cid in valid_three_set["retrieved"] if cid != _CID_C
    ]

    pom = PerOutputManifest(
        output_id="out-tampered-001",
        trace_id=trace_id,
        three_set=tampered_three_set,
        visibility_policy="customer_visible",
        emitted_at="2026-05-01T00:00:00.000Z",
    )
    manifest = BundleManifest(
        schema_version="vcp-v1.1-canary4",
        bundle_id="bundle-tamper",
        created_at="2026-05-01T00:00:00Z",
        files={},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
        retrieval_trace_log=log_rel,
    )
    with pytest.raises(ThreeSetMismatch):
        validate_per_output_manifest(pom, manifest, tmp_path)


# ---------------------------------------------------------------------------
# validate_per_output_manifest — bad visibility policy
# ---------------------------------------------------------------------------


def test_validate_per_output_manifest_bad_visibility(tmp_path):
    """Unknown visibility_policy raises BadVisibilityPolicy."""
    trace_id = "trace-vis-001"
    log_rel = _capture(tmp_path, trace_id, [_CID_A, _CID_B], [_CID_A])

    trace = load_trace(tmp_path / log_rel, trace_id)
    view = derive_three_set(trace, stamped_source_cids=[_CID_A])
    three_set = three_set_to_canonical_dict(view)

    pom = PerOutputManifest(
        output_id="out-vis-001",
        trace_id=trace_id,
        three_set=three_set,
        visibility_policy="novel-policy",  # not in K4 v1 enum
        emitted_at="2026-05-01T00:00:00.000Z",
    )
    manifest = BundleManifest(
        schema_version="vcp-v1.1-canary4",
        bundle_id="bundle-vis",
        created_at="2026-05-01T00:00:00Z",
        files={},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
        retrieval_trace_log=log_rel,
    )
    with pytest.raises(BadVisibilityPolicy, match="novel-policy"):
        validate_per_output_manifest(pom, manifest, tmp_path)


# ---------------------------------------------------------------------------
# ThreeSetSumInvariantCheck plugin — pass
# ---------------------------------------------------------------------------


def test_three_set_sum_invariant_plugin_pass(tmp_path):
    """Valid per_output_manifest entry returns ok=True from the plugin."""
    three_set = {
        "context_injected": sorted([_CID_A, _CID_B]),
        "quote_supporting": [_CID_A],
        "retrieved": sorted([_CID_A, _CID_B, _CID_C]),
    }
    pom_dict = {
        "output_id": "out-pass-001",
        "trace_id": "trace-001",
        "three_set": three_set,
        "visibility_policy": "customer_visible",
        "emitted_at": "2026-05-01T00:00:00.000Z",
    }
    manifest = _mock_manifest(
        per_output_manifests=[pom_dict],
        snapshots={_CID_A: "a.bin", _CID_B: "b.bin", _CID_C: "c.bin"},
        source_attributes={},
    )

    plugin = ThreeSetSumInvariantCheck()
    result = plugin.check(tmp_path, manifest)

    assert result.ok is True
    assert result.reason_code == "PASS"


# ---------------------------------------------------------------------------
# ThreeSetSumInvariantCheck plugin — orphan CID
# ---------------------------------------------------------------------------


def test_three_set_sum_invariant_plugin_orphan(tmp_path):
    """CID in quote_supporting absent from snapshots and source_attributes → THREE_SET_ORPHAN_CID."""
    orphan_cid = "sha256:" + "f" * 64
    three_set = {
        "context_injected": sorted([_CID_A, orphan_cid]),
        "quote_supporting": [orphan_cid],
        "retrieved": sorted([_CID_A, orphan_cid]),
    }
    pom_dict = {
        "output_id": "out-orphan-001",
        "trace_id": "trace-001",
        "three_set": three_set,
        "visibility_policy": "customer_visible",
        "emitted_at": "2026-05-01T00:00:00.000Z",
    }
    manifest = _mock_manifest(
        per_output_manifests=[pom_dict],
        snapshots={_CID_A: "a.bin"},  # orphan_cid NOT in snapshots
        source_attributes={},  # orphan_cid NOT in source_attributes
    )

    plugin = ThreeSetSumInvariantCheck()
    result = plugin.check(tmp_path, manifest)

    assert result.ok is False
    assert result.reason_code == "THREE_SET_ORPHAN_CID"
    assert orphan_cid in result.detail or "ORPHAN" in result.detail


# ---------------------------------------------------------------------------
# ThreeSetSumInvariantCheck plugin — QUOTE_NOT_IN_CONTEXT
# ---------------------------------------------------------------------------


def test_three_set_sum_invariant_plugin_violation_quote_not_in_context(tmp_path):
    """quote_supporting has a cid absent from context_injected → QUOTE_NOT_IN_CONTEXT."""
    three_set = {
        "context_injected": [_CID_A],  # _CID_B not injected
        "quote_supporting": sorted([_CID_A, _CID_B]),  # but _CID_B claimed as quote
        "retrieved": sorted([_CID_A, _CID_B, _CID_C]),
    }
    pom_dict = {
        "output_id": "out-qnic-001",
        "trace_id": "trace-001",
        "three_set": three_set,
        "visibility_policy": "customer_visible",
        "emitted_at": "2026-05-01T00:00:00.000Z",
    }
    # All CIDs known to the manifest so the orphan check is not the trigger
    manifest = _mock_manifest(
        per_output_manifests=[pom_dict],
        snapshots={_CID_A: "a.bin", _CID_B: "b.bin", _CID_C: "c.bin"},
    )

    plugin = ThreeSetSumInvariantCheck()
    result = plugin.check(tmp_path, manifest)

    assert result.ok is False
    assert result.reason_code == "QUOTE_NOT_IN_CONTEXT"


# ---------------------------------------------------------------------------
# Full BundleManifest validation with per_output_manifests
# ---------------------------------------------------------------------------


def test_bundle_manifest_with_per_output_manifests_validates(tmp_path):
    """Full manifest with snapshots + source_attributes + retrieval_trace + per_output_manifests passes."""
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()

    # 1. Real snapshot
    cid_str, snap_rel = _make_snapshot(
        bundle_dir, b"source content for W3 three-set test"
    )

    # 2. Retrieval trace
    trace_id = "trace-full-001"
    log_rel = _capture(bundle_dir, trace_id, [cid_str], [cid_str])

    # 3. Derive a valid three_set
    trace = load_trace(bundle_dir / log_rel, trace_id)
    view = derive_three_set(trace, stamped_source_cids=[cid_str])
    three_set = three_set_to_canonical_dict(view)

    pom_dict = per_output_manifest_to_canonical_dict(
        PerOutputManifest(
            output_id="out-full-001",
            trace_id=trace_id,
            three_set=three_set,
            visibility_policy="access_controlled",
            emitted_at="2026-05-01T00:00:00.000Z",
        )
    )

    policy_dict = policy_to_canonical_dict(default_v1_policy())

    # output_mode_signal is required when per_output_manifests is non-empty
    # (vc-mode-006 invariant). Use ES-mode here since the derived three_set has
    # no quote_supporting and VE-mode would require it.
    mode_signal_dict = mode_to_canonical_dict(
        ModeSignal(mode=OutputMode.ES, rails_active=("M1.1",))
    )

    manifest = BundleManifest(
        schema_version="vcp-v1.1-canary4",
        bundle_id="bundle-full-pom-test",
        created_at="2026-05-01T00:00:00Z",
        files={},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
        snapshots={cid_str: snap_rel},
        snapshot_policy=policy_dict,
        source_attributes={cid_str: _props_dict(cid_str)},
        retrieval_trace_id=trace_id,
        retrieval_trace_log=log_rel,
        per_output_manifests=(pom_dict,),
        output_mode_signal=mode_signal_dict,
    )

    validate_manifest(manifest, bundle_dir)  # must not raise
