"""Tests: output_modes package end-to-end (vc-mode-011).

Covers:
  - OutputMode enum values (regression guard against silent rename)
  - ModeSignal canonical round-trip (VE + ES)
  - ModeSignal validation invariants (ModeMisconfiguration)
  - mode_from_dict unknown mode (BadOutputMode)
  - VEPipeline post_process: unsupported segment suppressed (K1 lock)
  - VEPipeline post_process: stamp not in quote_supporting suppressed
  - ESPipeline post_process: failure-mode labeling with [unsupported:] marker
  - ModeDispatcher routing to VEPipeline vs ESPipeline
  - policy_default_mode_for: K1 default-VE / explicit-opt-in-ES table
  - BundleManifest integration: output_mode_signal validation (three sub-cases)
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from audit_bundle.output_modes.mode import (
    BadOutputMode,
    ModeSignal,
    ModeMisconfiguration,
    OutputMode,
    mode_from_dict,
    mode_to_canonical_dict,
)
from audit_bundle.output_modes.ve_pipeline import VEPipeline
from audit_bundle.output_modes.dispatch import ModeDispatcher, policy_default_mode_for
from audit_bundle.retrieval.capture import capture_trace
from audit_bundle.retrieval.three_set import ThreeSetView, three_set_to_canonical_dict


# ---------------------------------------------------------------------------
# Shared fixture helpers
# ---------------------------------------------------------------------------


def _make_trace(
    tmp_path, trace_id: str, cids: list[str], log_rel: str = "traces.jsonl"
) -> str:
    """Capture a minimal valid trace and return the bundle-relative log path."""
    log = tmp_path / log_rel
    selected = [
        {
            "source_cid": cid,
            "fragment": {"kind": "byte_offset", "start": i * 10, "end": i * 10 + 5},
            "rank": i,
        }
        for i, cid in enumerate(cids)
    ]
    rankings = [(cid, float(len(cids) - i)) for i, cid in enumerate(cids)]
    capture_trace(
        trace_id=trace_id,
        retriever_name="test_bm25_v0",
        retriever_version="0.1.0",
        query="test query",
        candidate_source_cids=cids,
        rankings=rankings,
        selected_chunks=selected,
        context_window_source_cids=cids,
        model_router_version="test-router-v0.1",
        output_jsonl_path=log,
    )
    return log_rel


# ---------------------------------------------------------------------------
# OutputMode enum values
# ---------------------------------------------------------------------------


def test_output_mode_enum_values():
    assert OutputMode.VE.value == "verified_extractive"
    assert OutputMode.ES.value == "exploratory_synthesis"


# ---------------------------------------------------------------------------
# ModeSignal canonical round-trip
# ---------------------------------------------------------------------------


def test_mode_signal_canonical_roundtrip():
    ve_signal = ModeSignal(
        mode=OutputMode.VE,
        generation_constraints=("abstain_on_ambiguity", "quote_supported_only"),
    )
    ve_dict = mode_to_canonical_dict(ve_signal)
    ve_reconstructed = mode_from_dict(ve_dict)
    assert ve_reconstructed == ve_signal

    es_signal = ModeSignal(
        mode=OutputMode.ES,
        rails_active=("failure_mode_rail", "hallucination_rail"),
    )
    es_dict = mode_to_canonical_dict(es_signal)
    es_reconstructed = mode_from_dict(es_dict)
    assert es_reconstructed == es_signal


# ---------------------------------------------------------------------------
# ModeSignal validation invariants
# ---------------------------------------------------------------------------


def test_mode_signal_validation():
    # VE requires non-empty generation_constraints
    with pytest.raises(ModeMisconfiguration):
        ModeSignal(mode=OutputMode.VE)  # generation_constraints defaults to ()

    # ES requires non-empty rails_active
    with pytest.raises(ModeMisconfiguration):
        ModeSignal(mode=OutputMode.ES)  # rails_active defaults to ()


# ---------------------------------------------------------------------------
# mode_from_dict — unknown mode value
# ---------------------------------------------------------------------------


def test_mode_from_dict_unknown_mode():
    with pytest.raises(BadOutputMode):
        mode_from_dict({"mode": "fancy", "policy_version": "0.1"})


# ---------------------------------------------------------------------------
# VEPipeline — unsupported segment (no stamp) is suppressed
# ---------------------------------------------------------------------------


_VE_SOURCES = {
    "cid-abc": "Preamble text. Stamped content. Trailing text.",
}


def _ve_lookup(cid: str) -> str:
    return _VE_SOURCES[cid]


def test_ve_pipeline_post_process_drops_unsupported():
    raw = json.dumps(
        {
            "segments": [
                {"text": "Stamped content. ", "stamped_source_cid": "cid-abc"},
                {"text": "Unsupported content. ", "stamped_source_cid": None},
            ]
        }
    )
    three_set = ThreeSetView(
        retrieved=("cid-abc",),
        context_injected=("cid-abc",),
        quote_supporting=("cid-abc",),
    )
    pipeline = VEPipeline(generation_constraints=("quote_supported_only",))
    result = pipeline.post_process(raw, three_set, _ve_lookup)
    # Stamped verbatim segment kept; unsupported (None stamp) SUPPRESSED — not labeled
    assert result == "Stamped content. "


# ---------------------------------------------------------------------------
# VEPipeline — stamp present but cid not in quote_supporting: suppress
# ---------------------------------------------------------------------------


def test_ve_pipeline_post_process_drops_stamp_not_in_quote_supporting():
    raw = json.dumps(
        {
            "segments": [
                {"text": "Text citing X. ", "stamped_source_cid": "cid-xyz"},
            ]
        }
    )
    three_set = ThreeSetView(
        retrieved=("cid-xyz",),
        context_injected=("cid-xyz",),
        quote_supporting=(),  # cid-xyz absent from quote_supporting
    )
    pipeline = VEPipeline(generation_constraints=("quote_supported_only",))
    result = pipeline.post_process(raw, three_set, lambda _: "Text citing X.")
    assert result == ""


# ---------------------------------------------------------------------------
# VEPipeline — a trusted CID label alone keeps NOTHING (RES-06): the segment
# text must occur verbatim (canonicalized) in the stamped source
# ---------------------------------------------------------------------------


def test_ve_pipeline_drops_synthesized_text_with_forged_quote_stamp():
    """THE RES-06 scenario: arbitrary synthesized text stamped with a
    quote-supporting CID must be suppressed — 'quote-supported only' must not
    reduce to 'has a trusted CID label'."""
    raw = json.dumps(
        {
            "segments": [
                {"text": "Stamped content. ", "stamped_source_cid": "cid-abc"},
                {
                    "text": "Entirely synthesized claim the source never said. ",
                    "stamped_source_cid": "cid-abc",  # forged stamp on a real CID
                },
            ]
        }
    )
    three_set = ThreeSetView(
        retrieved=("cid-abc",),
        context_injected=("cid-abc",),
        quote_supporting=("cid-abc",),
    )
    pipeline = VEPipeline(generation_constraints=("quote_supported_only",))
    result = pipeline.post_process(raw, three_set, _ve_lookup)
    assert result == "Stamped content. "


def test_ve_pipeline_verbatim_match_uses_versioned_canonicalization():
    # Case / punctuation / whitespace variance is tolerated (ADR D7.d
    # canonicalization — the SAME normalization the verifier-side fragment
    # attestation uses), so an honest quote is not suppressed over formatting.
    raw = json.dumps(
        {
            "segments": [
                {"text": "STAMPED   content", "stamped_source_cid": "cid-abc"},
            ]
        }
    )
    three_set = ThreeSetView(
        retrieved=("cid-abc",),
        context_injected=("cid-abc",),
        quote_supporting=("cid-abc",),
    )
    pipeline = VEPipeline(generation_constraints=("quote_supported_only",))
    assert pipeline.post_process(raw, three_set, _ve_lookup) == "STAMPED   content"


def test_ve_pipeline_fails_closed_on_lookup_failure():
    # A quote that cannot be checked is not retained: lookup raising or
    # returning a non-str suppresses the segment.
    raw = json.dumps(
        {
            "segments": [
                {"text": "Stamped content. ", "stamped_source_cid": "cid-abc"},
            ]
        }
    )
    three_set = ThreeSetView(
        retrieved=("cid-abc",),
        context_injected=("cid-abc",),
        quote_supporting=("cid-abc",),
    )
    pipeline = VEPipeline(generation_constraints=("quote_supported_only",))

    def _raising(_cid: str) -> str:
        raise KeyError(_cid)

    assert pipeline.post_process(raw, three_set, _raising) == ""
    assert pipeline.post_process(raw, three_set, lambda _: None) == ""  # type: ignore[arg-type, return-value]


def test_ve_pipeline_drops_canonically_empty_segment():
    # Pure punctuation/whitespace canonicalizes to "" — asserts no falsifiable
    # quote, so it is suppressed (trivial containment must not retain it).
    raw = json.dumps(
        {
            "segments": [
                {"text": " ... !!! ", "stamped_source_cid": "cid-abc"},
            ]
        }
    )
    three_set = ThreeSetView(
        retrieved=("cid-abc",),
        context_injected=("cid-abc",),
        quote_supporting=("cid-abc",),
    )
    pipeline = VEPipeline(generation_constraints=("quote_supported_only",))
    assert pipeline.post_process(raw, three_set, _ve_lookup) == ""


# ---------------------------------------------------------------------------
# ESPipeline — failure-mode labeling
# ---------------------------------------------------------------------------


def test_es_pipeline_post_process_labels_failure_modes():
    pytest.importorskip("nexi_methodology", reason="nexi_methodology not installed")
    from audit_bundle.output_modes.es_pipeline import ESPipeline
    from nexi_methodology.failure_modes import FailureModeTaxonomy

    # Empty taxonomy — any Mode-N reference will be flagged as unknown
    taxonomy = FailureModeTaxonomy(version="test-v0", modes=[], candidates=[])
    three_set = ThreeSetView(
        retrieved=("cid-1",),
        context_injected=("cid-1",),
        quote_supporting=(),
    )

    # Hedge-out style sentence that cites an unknown failure-mode ID (Mode-3)
    raw_output = "This analysis exhibits a Mode-3 failure pattern."
    pipeline = ESPipeline(taxonomy=taxonomy, rails_active=("Mode-3",))
    result = pipeline.post_process(raw_output, three_set)

    assert "[unsupported: Mode-3] Mode-3" in result


# ---------------------------------------------------------------------------
# ModeDispatcher routing
# ---------------------------------------------------------------------------


def test_dispatcher_routes_correctly():
    ve_signal = ModeSignal(mode=OutputMode.VE, generation_constraints=("c1",))
    es_signal = ModeSignal(mode=OutputMode.ES, rails_active=("r1",))

    mock_ve = MagicMock()
    mock_ve.post_process.return_value = "ve-output"
    mock_ve.emit_signal.return_value = ve_signal

    mock_es = MagicMock()
    mock_es.post_process.return_value = "es-output"
    mock_es.emit_signal.return_value = es_signal

    dispatcher = ModeDispatcher(ve_pipeline=mock_ve, es_pipeline=mock_es)
    three_set = ThreeSetView(
        retrieved=("cid-a",),
        context_injected=("cid-a",),
        quote_supporting=("cid-a",),
    )

    # VE dispatch — must route to ve_pipeline, not es_pipeline
    ve_text, ve_sig = dispatcher.dispatch(OutputMode.VE, "raw", three_set)
    mock_ve.post_process.assert_called_once()
    mock_es.post_process.assert_not_called()
    assert ve_text == "ve-output"
    assert ve_sig is ve_signal

    mock_ve.reset_mock()
    mock_es.reset_mock()
    mock_ve.post_process.return_value = "ve-output"
    mock_ve.emit_signal.return_value = ve_signal
    mock_es.post_process.return_value = "es-output"
    mock_es.emit_signal.return_value = es_signal

    # ES dispatch — must route to es_pipeline, not ve_pipeline
    es_text, es_sig = dispatcher.dispatch(OutputMode.ES, "raw", three_set)
    mock_es.post_process.assert_called_once()
    mock_ve.post_process.assert_not_called()
    assert es_text == "es-output"
    assert es_sig is es_signal


# ---------------------------------------------------------------------------
# policy_default_mode_for — K1 decision table (4 cases)
# ---------------------------------------------------------------------------


def test_policy_default_mode_for():
    # Unauthenticated always gets VE regardless of opt-in flag
    assert policy_default_mode_for(False, False) is OutputMode.VE
    assert policy_default_mode_for(False, True) is OutputMode.VE
    # Authenticated without explicit opt-in → VE
    assert policy_default_mode_for(True, False) is OutputMode.VE
    # Authenticated + explicit opt-in → ES (only valid ES path)
    assert policy_default_mode_for(True, True) is OutputMode.ES


# ---------------------------------------------------------------------------
# BundleManifest integration with output_mode_signal
# ---------------------------------------------------------------------------


def test_bundle_manifest_with_mode_signal(tmp_path):
    from audit_bundle.bundle_manifest import (
        BundleManifest,
        OutputModeMissingForOutputBundle,
        VEModeRequiresQuoteSupport,
        validate_manifest,
    )

    # Trace log with one source CID
    _cid = "sha256:" + "a" * 64
    log_rel = _make_trace(tmp_path, "trace-t001", [_cid])

    # Canonical three-set dicts for both scenarios
    three_set_with_qs = three_set_to_canonical_dict(
        ThreeSetView(
            retrieved=(_cid,),
            context_injected=(_cid,),
            quote_supporting=(_cid,),
        )
    )
    three_set_no_qs = three_set_to_canonical_dict(
        ThreeSetView(
            retrieved=(_cid,),
            context_injected=(_cid,),
            quote_supporting=(),
        )
    )

    ve_signal_dict = mode_to_canonical_dict(
        ModeSignal(mode=OutputMode.VE, generation_constraints=("quote_supported_only",))
    )

    def _manifest(**overrides):
        base = dict(
            schema_version="vcp-v1.1-canary4",
            bundle_id="test-bundle-001",
            created_at="2026-05-01T00:00:00.000Z",
            files={},
            spec_files={},
            cross_refs={},
            payload={},
            typed_checks=[],
            retrieval_trace_id="trace-t001",
            retrieval_trace_log=log_rel,
        )
        base.update(overrides)
        return BundleManifest(**base)

    pom_with_qs = {
        "output_id": "out-001",
        "trace_id": "trace-t001",
        "three_set": three_set_with_qs,
        "visibility_policy": "customer_visible",
        "emitted_at": "2026-05-01T00:00:00.000Z",
    }
    pom_no_qs = {
        "output_id": "out-001",
        "trace_id": "trace-t001",
        "three_set": three_set_no_qs,
        "visibility_policy": "customer_visible",
        "emitted_at": "2026-05-01T00:00:00.000Z",
    }

    # Case 1: valid VE bundle with per_output_manifests + output_mode_signal — passes
    m1 = _manifest(
        per_output_manifests=(pom_with_qs,),
        output_mode_signal=ve_signal_dict,
    )
    validate_manifest(m1, tmp_path)  # must not raise

    # Case 2: VE mode but quote_supporting empty → VEModeRequiresQuoteSupport
    m2 = _manifest(
        per_output_manifests=(pom_no_qs,),
        output_mode_signal=ve_signal_dict,
    )
    with pytest.raises(VEModeRequiresQuoteSupport):
        validate_manifest(m2, tmp_path)

    # Case 3: per_output_manifests non-empty but output_mode_signal=None → OutputModeMissingForOutputBundle
    m3 = _manifest(
        per_output_manifests=(pom_with_qs,),
        output_mode_signal=None,
    )
    with pytest.raises(OutputModeMissingForOutputBundle):
        validate_manifest(m3, tmp_path)
