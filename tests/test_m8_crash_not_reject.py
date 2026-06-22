"""tests/test_m8_crash_not_reject.py — M8: verifier crashes must not launder into REJECT.

Redteam finding M8
------------------
Two catch sites used ``except (X, Exception)`` — the ``Exception`` member
makes the specific member dead and converts ANY verifier exception
(including internal bugs such as AttributeError) into a REJECT-class
verdict error:

  * ``bundle_manifest.py`` step 14: ``except (TraceNotFound, Exception)``
    → BadRetrievalTraceLog
  * ``revocation.py`` sig decode: ``except (ValueError, Exception)``
    → RevocationListInvalid

A REJECT verdict is a claim about the BUNDLE; a verifier crash is a claim
about the VERIFIER. Collapsing the two both loses the crash signal and
lets an unverified "bundle is bad" claim ride a verdict.

The fix narrows each catch to the documented hostile-data exception
family and normalises every malformed-content failure inside
``load_trace``/``trace_from_dict`` to ``RetrievalTraceError`` so the
narrow catch still covers the full hostile-data surface:

  * hostile bundle data  → documented REJECT-class error (fail-closed kept)
  * verifier bug         → exception propagates (crash visible, not REJECT)
"""

from __future__ import annotations

import json

import pytest

import audit_bundle.bundle_manifest as bundle_manifest_mod
import audit_bundle.revocation as revocation_mod
from audit_bundle.bundle_manifest import (
    BadRetrievalTraceLog,
    BundleManifest,
    validate_manifest,
)
from audit_bundle.retrieval.capture import TraceNotFound, capture_trace, load_trace
from audit_bundle.retrieval.trace import RetrievalTraceError, trace_from_dict
from audit_bundle.revocation import RevocationListInvalid, load_revocation_list

_CID_A = "sha256:" + "a" * 64


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_trace_log(bundle_dir, trace_id: str, log_rel: str = "traces.jsonl") -> str:
    """Capture one valid trace into bundle_dir; return bundle-relative path."""
    bundle_dir.mkdir(parents=True, exist_ok=True)
    capture_trace(
        trace_id=trace_id,
        retriever_name="r",
        retriever_version="0.1.0",
        query="q",
        candidate_source_cids=[_CID_A],
        rankings=[(_CID_A, 1.0)],
        selected_chunks=[{"source_cid": _CID_A, "fragment": {}, "rank": 0}],
        context_window_source_cids=[_CID_A],
        model_router_version="rv",
        output_jsonl_path=bundle_dir / log_rel,
    )
    return log_rel


def _valid_trace_dict() -> dict:
    """A canonical trace dict that trace_from_dict accepts unmodified."""
    return {
        "trace_id": "t-1",
        "retriever_name": "r",
        "retriever_version": "0.1.0",
        "query": "q",
        "candidate_set": [_CID_A],
        "rankings": [{"source_cid": _CID_A, "score": 1.0}],
        "selected_chunks": [{"source_cid": _CID_A, "fragment": {}, "rank": 0}],
        "context_window_injected": [_CID_A],
        "model_router_version": "rv",
        "captured_at": "2026-05-01T00:00:00.000Z",
    }


def _manifest_with_trace(trace_id: str, log_rel: str) -> BundleManifest:
    return BundleManifest(
        schema_version="vcp-v1.1-canary4",
        bundle_id="bundle-m8",
        created_at="2026-05-01T00:00:00Z",
        files={},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
        retrieval_trace_id=trace_id,
        retrieval_trace_log=log_rel,
    )


# ---------------------------------------------------------------------------
# load_trace / trace_from_dict — hostile data normalised to documented errors
# ---------------------------------------------------------------------------


class TestHostileTraceDataNormalised:
    def test_malformed_json_line_raises_retrieval_trace_error(self, tmp_path):
        """A non-JSON line in the log → RetrievalTraceError, not bare JSONDecodeError."""
        log = tmp_path / "traces.jsonl"
        log.write_text("{not json\n", encoding="utf-8")
        with pytest.raises(RetrievalTraceError, match="not valid JSON"):
            load_trace(log, "any-id")

    def test_scalar_json_line_raises_retrieval_trace_error(self, tmp_path):
        """A JSON scalar line (previously AttributeError on .get) → RetrievalTraceError."""
        log = tmp_path / "traces.jsonl"
        log.write_text("42\n", encoding="utf-8")
        with pytest.raises(RetrievalTraceError, match="not a JSON object"):
            load_trace(log, "any-id")

    def test_missing_trace_id_still_trace_not_found(self, tmp_path):
        """Well-formed log without the id keeps the documented TraceNotFound."""
        log_rel = _write_trace_log(tmp_path, "present-id")
        with pytest.raises(TraceNotFound):
            load_trace(tmp_path / log_rel, "absent-id")

    def test_non_numeric_score_raises_retrieval_trace_error(self):
        """float('abc') previously leaked a bare ValueError out of trace_from_dict."""
        d = _valid_trace_dict()
        d["rankings"] = [{"source_cid": _CID_A, "score": "abc"}]
        with pytest.raises(RetrievalTraceError, match="rankings"):
            trace_from_dict(d)

    def test_non_iterable_candidate_set_raises_retrieval_trace_error(self):
        """tuple(5) previously leaked a bare TypeError out of trace_from_dict."""
        d = _valid_trace_dict()
        d["candidate_set"] = 5
        with pytest.raises(RetrievalTraceError, match="wrong type"):
            trace_from_dict(d)


# ---------------------------------------------------------------------------
# bundle_manifest step 14 — hostile log still REJECTs; verifier bug crashes
# ---------------------------------------------------------------------------


class TestManifestStep14:
    def test_garbage_trace_log_still_rejects(self, tmp_path):
        """Hostile log content keeps the fail-closed BadRetrievalTraceLog verdict."""
        bundle_dir = tmp_path / "bundle"
        bundle_dir.mkdir()
        (bundle_dir / "traces.jsonl").write_text("][ garbage\n", encoding="utf-8")
        manifest = _manifest_with_trace("t-1", "traces.jsonl")
        with pytest.raises(BadRetrievalTraceLog):
            validate_manifest(manifest, bundle_dir)

    def test_verifier_bug_propagates_not_reject(self, tmp_path, monkeypatch):
        """An internal bug in load_trace must crash, NOT become BadRetrievalTraceLog."""
        bundle_dir = tmp_path / "bundle"
        log_rel = _write_trace_log(bundle_dir, "t-1")
        manifest = _manifest_with_trace("t-1", log_rel)
        # Sanity: the bundle itself is clean.
        validate_manifest(manifest, bundle_dir)

        def buggy_load_trace(path, trace_id):
            raise AttributeError("simulated verifier bug")

        monkeypatch.setattr(bundle_manifest_mod, "load_trace", buggy_load_trace)
        with pytest.raises(AttributeError, match="simulated verifier bug"):
            validate_manifest(manifest, bundle_dir)


# ---------------------------------------------------------------------------
# revocation sig decode — hostile sig still REJECTs; verifier bug crashes
# ---------------------------------------------------------------------------


def _minimal_signed_doc_with_sig(sig_str: str) -> bytes:
    """A structurally complete revocation doc with an attacker-chosen sig field."""
    payload = {"revocations": [], "issued_at": 1, "expires": 2}
    doc = {"payload": payload, "sig": sig_str, "root_kid": "k"}
    return json.dumps(doc).encode("utf-8")


class TestRevocationSigDecode:
    def test_invalid_b64_sig_still_rejects(self):
        """A sig whose length is 1 mod 4 hits the ValueError path → RevocationListInvalid."""
        raw = _minimal_signed_doc_with_sig("AAAAA")  # len 5 → remainder 1
        with pytest.raises(RevocationListInvalid, match="base64url"):
            load_revocation_list(raw, revocation_root_resolver=lambda k: b"\x00" * 32)

    def test_verifier_bug_propagates_not_reject(self, monkeypatch):
        """An internal bug in the decoder must crash, NOT become RevocationListInvalid."""
        raw = _minimal_signed_doc_with_sig("AAAA")

        def buggy_decode(s: str) -> bytes:
            raise RuntimeError("simulated verifier bug")

        monkeypatch.setattr(revocation_mod, "_b64url_nopad_decode", buggy_decode)
        with pytest.raises(RuntimeError, match="simulated verifier bug"):
            load_revocation_list(raw, revocation_root_resolver=lambda k: b"\x00" * 32)
