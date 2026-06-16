"""Tests for audit_bundle retrieval: RetrievalTrace, ThreeSetView, capture, and manifest integration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from audit_bundle.retrieval.trace import (
    RetrievalTrace,
    RetrievalTraceError,
    trace_from_dict,
    trace_to_canonical_dict,
)
from audit_bundle.retrieval.three_set import (
    ThreeSetView,
    derive_three_set,
    three_set_sum_invariant_check,
    three_set_to_canonical_dict,
)
from audit_bundle.retrieval.capture import (
    TraceNotFound,
    capture_trace,
    load_trace,
)
from audit_bundle.bundle_manifest import (
    BadRetrievalTraceLog,
    BundleManifest,
    MissingRetrievalTraceLog,
    RetrievalTraceOrphan,
    SourceAttributesOrphan,
    validate_manifest,
)
from audit_bundle.snapshots.cid import compute_cid
from audit_bundle.snapshots.snapshot_policy import (
    default_v1_policy,
    policy_to_canonical_dict,
)


# ---------------------------------------------------------------------------
# Test-local constants
# ---------------------------------------------------------------------------

_CID_A = "sha256:" + "a" * 64
_CID_B = "sha256:" + "b" * 64
_CID_C = "sha256:" + "c" * 64


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_trace(
    trace_id: str = "trace-001",
    candidate_set: tuple[str, ...] = (_CID_A, _CID_B, _CID_C),
    context_window_injected: tuple[str, ...] = (_CID_A, _CID_B),
) -> RetrievalTrace:
    """Build a valid RetrievalTrace with consistent subset relationships."""
    selected_chunks = tuple(
        {
            "source_cid": cid,
            "fragment": {"kind": "byte_offset", "start": i * 100, "end": i * 100 + 50},
            "rank": i,
        }
        for i, cid in enumerate(context_window_injected)
    )
    rankings = tuple(
        (cid, float(len(candidate_set) - i)) for i, cid in enumerate(candidate_set)
    )
    return RetrievalTrace(
        trace_id=trace_id,
        retriever_name="test_retriever",
        retriever_version="0.1.0",
        query="test query",
        candidate_set=candidate_set,
        rankings=rankings,
        selected_chunks=selected_chunks,
        context_window_injected=context_window_injected,
        model_router_version="test-router-v0.1",
        captured_at="2026-05-01T00:00:00.000Z",
    )


def _props_dict(source_cid: str, pub_class: str = "regulatory") -> dict:
    """Minimal valid source_attributes entry dict."""
    return {
        "issuer_identity_verified": False,
        "issuer_identifier": None,
        "signed_artifact_present": False,
        "signing_key_id": None,
        "publication_class": pub_class,
        "external_status_flags": [],
        "schema_version": "0.1",
        "source_cid": source_cid,
    }


def _make_bundle_with_snapshot(tmp_path):
    """Create bundle_dir with one real snapshot. Returns (bundle_dir, cid_str, snap_rel)."""
    bundle_dir = tmp_path / "bundle"
    snap_dir = bundle_dir / "snapshots"
    snap_dir.mkdir(parents=True)
    content = b"snapshot blob for retrieval integration test"
    cid_str = compute_cid(content)
    fname = snap_dir / (cid_str.split(":")[1][:16] + ".bin")
    fname.write_bytes(content)
    return bundle_dir, cid_str, fname.relative_to(bundle_dir).as_posix()


def _capture_trace_to_bundle(
    bundle_dir,
    trace_id: str,
    candidate_cids: list[str],
    context_cids: list[str],
    log_rel: str = "traces.jsonl",
) -> str:
    """Write a trace log into bundle_dir; return the bundle-relative log path."""
    log_path = bundle_dir / log_rel
    selected = [
        {"source_cid": cid, "fragment": {}, "rank": i}
        for i, cid in enumerate(context_cids)
    ]
    rankings = [
        (cid, float(len(candidate_cids) - i)) for i, cid in enumerate(candidate_cids)
    ]
    capture_trace(
        trace_id=trace_id,
        retriever_name="bm25_v0",
        retriever_version="0.1.0",
        query="integration test query",
        candidate_source_cids=candidate_cids,
        rankings=rankings,
        selected_chunks=selected,
        context_window_source_cids=context_cids,
        model_router_version="router-v0.1",
        output_jsonl_path=log_path,
    )
    return log_rel


# ---------------------------------------------------------------------------
# RetrievalTrace — roundtrip
# ---------------------------------------------------------------------------


def test_retrieval_trace_roundtrip():
    """trace_to_canonical_dict + trace_from_dict yields an identical dataclass."""
    original = _make_trace()
    restored = trace_from_dict(trace_to_canonical_dict(original))
    assert restored == original


# ---------------------------------------------------------------------------
# RES-09 — finite-scores invariant. NaN/Infinity are not RFC 8259 JSON;
# stdlib json round-trips them as non-standard tokens (the same laundering
# vector the dispatch boundary closes with NON_FINITE_VALUE), which would
# break the "JCS-canonicalizable" contract. Rejected at construction (the
# chokepoint), at the write path (whole-record allow_nan=False belt), and at
# the read parse boundary (parse_constant).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_score",
    [float("nan"), float("inf"), float("-inf")],
    ids=["nan", "inf", "-inf"],
)
def test_nonfinite_score_rejected_at_construction(bad_score):
    import dataclasses

    with pytest.raises(RetrievalTraceError, match="non-finite"):
        dataclasses.replace(_make_trace(), rankings=((_CID_A, bad_score),))


@pytest.mark.parametrize("bad_score", [True, "0.5", None, [1.0]])
def test_non_number_score_rejected_at_construction(bad_score):
    import dataclasses

    with pytest.raises(RetrievalTraceError, match="score must be a finite number"):
        dataclasses.replace(_make_trace(), rankings=((_CID_A, bad_score),))


def test_malformed_rankings_entry_rejected_at_construction():
    import dataclasses

    with pytest.raises(RetrievalTraceError, match="must be a .source_cid, score. pair"):
        dataclasses.replace(_make_trace(), rankings=("not-a-pair-at-all",))


@pytest.mark.parametrize(
    "token_value", [float("nan"), float("inf")], ids=["nan", "inf"]
)
def test_trace_from_dict_rejects_nonfinite_score(token_value):
    """trace_from_dict coerces scores with float(); the construction guard
    must still catch a non-finite value arriving as a float OR as the string
    forms float() happily accepts ('nan', '1e999')."""
    d = trace_to_canonical_dict(_make_trace())
    d["rankings"][0]["score"] = token_value
    with pytest.raises(RetrievalTraceError, match="non-finite"):
        trace_from_dict(d)
    d["rankings"][0]["score"] = "nan"
    with pytest.raises(RetrievalTraceError, match="non-finite"):
        trace_from_dict(d)


def test_capture_trace_rejects_nonfinite_hidden_in_fragment(tmp_path):
    """Scores are guarded per-field; the allow_nan=False serializer is the
    whole-record belt — a non-finite float inside the opaque fragment dict
    fails closed at the single write path instead of poisoning the log."""
    log = tmp_path / "traces.jsonl"
    with pytest.raises(RetrievalTraceError, match="non-finite"):
        capture_trace(
            trace_id="trace-nan-fragment",
            retriever_name="bm25_v0",
            retriever_version="0.1.0",
            query="q",
            candidate_source_cids=[_CID_A],
            rankings=[(_CID_A, 1.0)],
            selected_chunks=[
                {
                    "source_cid": _CID_A,
                    "fragment": {"kind": "span", "weight": float("nan")},
                    "rank": 0,
                }
            ],
            context_window_source_cids=[_CID_A],
            model_router_version="router-v0.1",
            output_jsonl_path=log,
        )
    assert not log.exists()  # nothing was appended


# ---------------------------------------------------------------------------
# RES-12 — duplicate-ID shadowing. trace_id is a BINDING IDENTITY (a
# per-output manifest names it; the verifier checks the three-set against the
# record it resolves to), so first-match-wins on duplicates would let the
# machine verdict bind record #1 while a human reading the log treats the
# later row as current. Duplicates reject at read (load_trace full-scans) AND
# at the single write path (capture_trace refuses a reused id). Corrections
# are event_stream supersession events + a fresh trace_id, never a reused key.
# ---------------------------------------------------------------------------


def _trace_log_with_duplicate(tmp_path: Path, mutate: bool) -> Path:
    """A two-row log sharing one trace_id; rows differ iff mutate."""
    log = tmp_path / "traces.jsonl"
    d = trace_to_canonical_dict(_make_trace(trace_id="trace-dup"))
    line1 = json.dumps(d, sort_keys=True)
    if mutate:
        d = dict(d)
        d["query"] = "a different query the producer 'corrected' in place"
    line2 = json.dumps(d, sort_keys=True)
    log.write_text(line1 + "\n" + line2 + "\n", encoding="utf-8")
    return log


def test_load_trace_rejects_conflicting_duplicate(tmp_path):
    log = _trace_log_with_duplicate(tmp_path, mutate=True)
    with pytest.raises(RetrievalTraceError, match="duplicates trace_id"):
        load_trace(log, "trace-dup")


def test_load_trace_rejects_byte_identical_duplicate(tmp_path):
    """Even an identical re-append rejects — one identity, one record; no
    equality carve-out to reason about."""
    log = _trace_log_with_duplicate(tmp_path, mutate=False)
    with pytest.raises(RetrievalTraceError, match="duplicates trace_id"):
        load_trace(log, "trace-dup")


def test_load_trace_other_ids_unaffected_by_full_scan(tmp_path):
    """Full-scan still resolves a unique id sharing the file with others."""
    log = tmp_path / "traces.jsonl"
    a = trace_to_canonical_dict(_make_trace(trace_id="trace-a"))
    b = trace_to_canonical_dict(_make_trace(trace_id="trace-b"))
    log.write_text(
        json.dumps(a, sort_keys=True) + "\n" + json.dumps(b, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    assert load_trace(log, "trace-b").trace_id == "trace-b"


def test_capture_trace_refuses_reused_trace_id(tmp_path):
    """'Must be unique per output' is enforced at the single write path; the
    refused append leaves the log untouched."""
    log = tmp_path / "traces.jsonl"
    kwargs = dict(
        retriever_name="bm25_v0",
        retriever_version="0.1.0",
        query="q",
        candidate_source_cids=[_CID_A],
        rankings=[(_CID_A, 1.0)],
        selected_chunks=[{"source_cid": _CID_A, "fragment": {}, "rank": 0}],
        context_window_source_cids=[_CID_A],
        model_router_version="router-v0.1",
        output_jsonl_path=log,
    )
    capture_trace(trace_id="trace-once", **kwargs)
    with pytest.raises(RetrievalTraceError, match="already present"):
        capture_trace(trace_id="trace-once", **kwargs)
    assert len(log.read_text(encoding="utf-8").splitlines()) == 1


def test_load_trace_rejects_depth_bomb_line(tmp_path):
    """load_trace runs on the verdict path; each line is admission-bounded
    before parse (the ratchet-blind file-handle iteration shape)."""
    log = tmp_path / "traces.jsonl"
    d = trace_to_canonical_dict(_make_trace(trace_id="trace-ok"))
    log.write_text(
        json.dumps(d, sort_keys=True) + "\n" + "[" * 5000 + "]" * 5000 + "\n",
        encoding="utf-8",
    )
    with pytest.raises(RetrievalTraceError, match="inadmissible"):
        load_trace(log, "trace-ok")


def test_load_trace_rejects_nonfinite_json_tokens(tmp_path):
    """A hand-edited / foreign-producer log line carrying the NaN token is
    bundle-supplied data — rejected at the parse boundary as not-valid-JSON,
    never laundered through stdlib's permissive default."""
    log = tmp_path / "traces.jsonl"
    log.write_text(
        '{"trace_id": "trace-evil", "rankings": [{"score": NaN, "source_cid": "x"}]}\n',
        encoding="utf-8",
    )
    with pytest.raises(RetrievalTraceError, match="not valid JSON"):
        load_trace(log, "trace-evil")


# ---------------------------------------------------------------------------
# RetrievalTrace — subset invariant enforced at __post_init__
# ---------------------------------------------------------------------------


def test_retrieval_trace_subset_invariant_at_init():
    """candidate_set ⊇ selected_chunks ⊇ context_window_injected; each violation raises."""
    # selected_chunk source_cid not in candidate_set
    with pytest.raises(RetrievalTraceError, match="Three-set violation"):
        RetrievalTrace(
            trace_id="t1",
            retriever_name="r",
            retriever_version="0.1",
            query="q",
            candidate_set=(_CID_A,),
            rankings=((_CID_A, 1.0),),
            selected_chunks=({"source_cid": _CID_B, "fragment": {}, "rank": 0},),
            context_window_injected=(),
            model_router_version="rv1",
            captured_at="2026-05-01T00:00:00.000Z",
        )

    # context_window cid not in selected_chunks source_cids
    with pytest.raises(RetrievalTraceError, match="Three-set violation"):
        RetrievalTrace(
            trace_id="t2",
            retriever_name="r",
            retriever_version="0.1",
            query="q",
            candidate_set=(_CID_A, _CID_B),
            rankings=((_CID_A, 2.0), (_CID_B, 1.0)),
            selected_chunks=({"source_cid": _CID_A, "fragment": {}, "rank": 0},),
            context_window_injected=(_CID_B,),  # _CID_B not in selected_chunks
            model_router_version="rv1",
            captured_at="2026-05-01T00:00:00.000Z",
        )


# ---------------------------------------------------------------------------
# ThreeSetView — subset invariant checks
# ---------------------------------------------------------------------------


def test_three_set_subset_chain_pass():
    """retrieved >= context_injected >= quote_supporting → ThreeSetView constructs OK."""
    trace = _make_trace(
        candidate_set=(_CID_A, _CID_B, _CID_C),
        context_window_injected=(_CID_A, _CID_B),
    )
    view = derive_three_set(trace, stamped_source_cids=[_CID_A])
    assert set(view.retrieved) == {_CID_A, _CID_B, _CID_C}
    assert set(view.context_injected) == {_CID_A, _CID_B}
    assert set(view.quote_supporting) == {_CID_A}


def test_three_set_quote_not_in_context():
    """quote_supporting has cid not in context_injected → reason_code='QUOTE_NOT_IN_CONTEXT'."""
    view = ThreeSetView(
        retrieved=(_CID_A, _CID_B),
        context_injected=(_CID_A,),
        quote_supporting=(_CID_B,),  # _CID_B is not in context_injected
    )
    ok, reason = three_set_sum_invariant_check(view)
    assert ok is False
    assert reason == "QUOTE_NOT_IN_CONTEXT"


def test_three_set_context_not_in_retrieved():
    """context_injected has cid not in retrieved → reason_code='CONTEXT_NOT_IN_RETRIEVED'."""
    view = ThreeSetView(
        retrieved=(_CID_A,),
        context_injected=(_CID_A, _CID_B),  # _CID_B is not in retrieved
        quote_supporting=(_CID_A,),
    )
    ok, reason = three_set_sum_invariant_check(view)
    assert ok is False
    assert reason == "CONTEXT_NOT_IN_RETRIEVED"


def test_three_set_canonical_sorted():
    """three_set_to_canonical_dict yields sorted lists regardless of insertion order."""
    view = ThreeSetView(
        retrieved=(_CID_C, _CID_B, _CID_A),  # deliberately reversed
        context_injected=(_CID_B, _CID_A),
        quote_supporting=(_CID_B,),
    )
    canon = three_set_to_canonical_dict(view)
    assert canon["retrieved"] == sorted([_CID_A, _CID_B, _CID_C])
    assert canon["context_injected"] == sorted([_CID_A, _CID_B])
    assert canon["quote_supporting"] == sorted([_CID_B])


# ---------------------------------------------------------------------------
# capture_trace + load_trace
# ---------------------------------------------------------------------------


def test_capture_trace_roundtrip(tmp_path):
    """capture_trace + load_trace returns the same RetrievalTrace."""
    log_path = tmp_path / "traces.jsonl"
    captured = capture_trace(
        trace_id="trace-rt-001",
        retriever_name="bm25_v0",
        retriever_version="0.1.0",
        query="roundtrip query",
        candidate_source_cids=[_CID_A, _CID_B, _CID_C],
        rankings=[(_CID_A, 3.0), (_CID_B, 2.0), (_CID_C, 1.0)],
        selected_chunks=[
            {
                "source_cid": _CID_A,
                "fragment": {"kind": "byte_offset", "start": 0, "end": 100},
                "rank": 0,
            },
            {
                "source_cid": _CID_B,
                "fragment": {"kind": "byte_offset", "start": 0, "end": 80},
                "rank": 1,
            },
        ],
        context_window_source_cids=[_CID_A, _CID_B],
        model_router_version="router-v0.1",
        output_jsonl_path=log_path,
    )
    loaded = load_trace(log_path, "trace-rt-001")
    assert loaded == captured


def test_capture_trace_append_only(tmp_path):
    """Capturing 3 traces: file size grows monotonically AND prior records preserve their
    byte offsets (defense-in-depth — file size can grow even if early records are mutated;
    we want a hard assertion that record N's bytes are byte-identical after record N+1)."""
    log_path = tmp_path / "traces.jsonl"

    scenarios = [
        ("tid-001", [_CID_A, _CID_B], [_CID_A]),
        ("tid-002", [_CID_B, _CID_C], [_CID_B]),
        ("tid-003", [_CID_A, _CID_C], [_CID_C]),
    ]

    sizes: list[int] = []
    snapshots: list[bytes] = []  # full file bytes after each capture
    for tid, candidates, context in scenarios:
        selected = [
            {
                "source_cid": cid,
                "fragment": {"kind": "byte_offset", "start": 0, "end": 10},
                "rank": i,
            }
            for i, cid in enumerate(context)
        ]
        rankings = [
            (cid, float(len(candidates) - i)) for i, cid in enumerate(candidates)
        ]
        capture_trace(
            trace_id=tid,
            retriever_name="test_ret",
            retriever_version="0.1.0",
            query=f"query for {tid}",
            candidate_source_cids=candidates,
            rankings=rankings,
            selected_chunks=selected,
            context_window_source_cids=context,
            model_router_version="router-v0.1",
            output_jsonl_path=log_path,
        )
        sizes.append(log_path.stat().st_size)
        snapshots.append(log_path.read_bytes())

    assert sizes[0] < sizes[1] < sizes[2], "file must grow after each capture"

    # Append-only byte-offset preservation: every previous capture's bytes must
    # remain a strict prefix of every subsequent capture's bytes.  Catches
    # any mutation that grew the file (e.g. rewriting record 0 to a longer
    # variant) but still yielded a monotonically larger size.
    assert snapshots[1].startswith(snapshots[0]), (
        "append-only violation: bytes after capture 1 are not a prefix of bytes after capture 2"
    )
    assert snapshots[2].startswith(snapshots[1]), (
        "append-only violation: bytes after capture 2 are not a prefix of bytes after capture 3"
    )

    for tid, _, _ in scenarios:
        t = load_trace(log_path, tid)
        assert t.trace_id == tid


def test_load_trace_not_found(tmp_path):
    """load_trace with unknown trace_id raises TraceNotFound."""
    log_path = tmp_path / "traces.jsonl"
    capture_trace(
        trace_id="real-trace",
        retriever_name="r",
        retriever_version="0.1.0",
        query="q",
        candidate_source_cids=[_CID_A],
        rankings=[(_CID_A, 1.0)],
        selected_chunks=[{"source_cid": _CID_A, "fragment": {}, "rank": 0}],
        context_window_source_cids=[_CID_A],
        model_router_version="rv",
        output_jsonl_path=log_path,
    )
    with pytest.raises(TraceNotFound):
        load_trace(log_path, "nonexistent-trace-id")


# ---------------------------------------------------------------------------
# BundleManifest + retrieval_trace integration
# ---------------------------------------------------------------------------


def test_manifest_with_retrieval_trace(tmp_path):
    """Manifest with retrieval_trace_id + log validates clean.
    Remove log → BadRetrievalTraceLog.
    Set trace_id but log=None → MissingRetrievalTraceLog.
    """
    bundle_dir, cid_str, snap_rel = _make_bundle_with_snapshot(tmp_path)
    trace_id = "trace-manifest-001"
    trace_log_rel = _capture_trace_to_bundle(bundle_dir, trace_id, [cid_str], [cid_str])
    policy_dict = policy_to_canonical_dict(default_v1_policy())

    manifest = BundleManifest(
        schema_version="vcp-v1.1-canary4",
        bundle_id="bundle-rt-test",
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
        retrieval_trace_log=trace_log_rel,
    )

    # Clean: passes without exception
    validate_manifest(manifest, bundle_dir)

    # Remove the log file → BadRetrievalTraceLog
    (bundle_dir / trace_log_rel).unlink()
    with pytest.raises(BadRetrievalTraceLog):
        validate_manifest(manifest, bundle_dir)

    # trace_id set but retrieval_trace_log=None → MissingRetrievalTraceLog
    manifest_no_log = BundleManifest(
        schema_version="vcp-v1.1-canary4",
        bundle_id="bundle-rt-no-log",
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
        retrieval_trace_log=None,
    )
    with pytest.raises(MissingRetrievalTraceLog):
        validate_manifest(manifest_no_log, bundle_dir)


def test_retrieval_trace_orphan(tmp_path):
    """candidate_set CID annotated in source_attributes but not in snapshots → orphan error.

    The manifest validator detects the orphan at check 11 (SourceAttributesOrphan)
    before reaching check 15 (RetrievalTraceOrphan); both exceptions indicate the
    same violation class and are accepted here.
    """
    bundle_dir, cid_str, snap_rel = _make_bundle_with_snapshot(tmp_path)
    orphan_cid = (
        "sha256:" + "f" * 64
    )  # not in snapshots, but in candidate_set + source_attributes

    trace_id = "trace-orphan-001"
    # candidate_set has both cid_str (snapshotted) and orphan_cid (not snapshotted)
    trace_log_rel = _capture_trace_to_bundle(
        bundle_dir,
        trace_id,
        candidate_cids=[cid_str, orphan_cid],
        context_cids=[
            cid_str
        ],  # orphan_cid not selected into context; candidate_set ⊇ context ✓
    )
    policy_dict = policy_to_canonical_dict(default_v1_policy())

    manifest = BundleManifest(
        schema_version="vcp-v1.1-canary4",
        bundle_id="bundle-orphan-test",
        created_at="2026-05-01T00:00:00Z",
        files={},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
        snapshots={cid_str: snap_rel},  # orphan_cid NOT in snapshots
        snapshot_policy=policy_dict,
        source_attributes={
            cid_str: _props_dict(cid_str),
            orphan_cid: _props_dict(orphan_cid),  # annotated but no snapshot
        },
        retrieval_trace_id=trace_id,
        retrieval_trace_log=trace_log_rel,
    )

    with pytest.raises((SourceAttributesOrphan, RetrievalTraceOrphan)):
        validate_manifest(manifest, bundle_dir)
