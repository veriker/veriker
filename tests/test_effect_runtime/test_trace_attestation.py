"""Unit tests for audit_bundle.effect_runtime.trace_attestation —
verifier-set discipline for the WASM execution trace."""

from __future__ import annotations

import hashlib

import pytest

from audit_bundle.discharge.verifier_signing import VerifierSigningKey
from audit_bundle.effect_runtime.trace_attestation import (
    EXECUTION_TRACE_PAYLOAD_KIND,
    ExecutionTraceVerifierKey,
    TraceSigningError,
    _build_trace_payload,
    sign_execution_trace,
    verify_execution_trace_signature,
)


_KEY_BYTES = b"v15-test-secret-32bytes-padding!"  # 32 bytes
_KEY = ExecutionTraceVerifierKey(verifier_id="v-kernel-test", secret=_KEY_BYTES)
_OTHER_KEY = ExecutionTraceVerifierKey(
    verifier_id="v-kernel-test", secret=b"alternate-secret-32bytes-padding"
)
_FOREIGN_VERIFIER_KEY = ExecutionTraceVerifierKey(
    verifier_id="attacker", secret=_KEY_BYTES
)

_BUNDLE_ID = "bundle-v15-test-001"
_OTHER_BUNDLE_ID = "bundle-v15-test-OTHER"
_WASM_SHA = hashlib.sha256(b"sample-wasm-bytes-v15").hexdigest()
_OTHER_WASM_SHA = hashlib.sha256(b"different-wasm-bytes").hexdigest()


def _record_with_signed_trace(**overrides):
    """Build a record with a freshly-signed execution trace under default
    bindings; allow per-call override of any sign_execution_trace kwarg."""
    rec: dict = {"schema_version": "0.1"}
    kwargs = dict(
        key=_KEY,
        wasm_module_sha256=_WASM_SHA,
        declared_effects=["net"],
        observed_imports=["wasi:sockets/tcp"],
        fuel_consumed=42,
        max_memory_bytes=65536,
        return_status="ok",
        bundle_id=_BUNDLE_ID,
        record_idx=0,
        timestamp_utc="2026-05-03T12:30:00Z",
    )
    kwargs.update(overrides)
    return sign_execution_trace(rec, **kwargs)


# ---------------------------------------------------------------------------
# Type alias / constants
# ---------------------------------------------------------------------------


def test_execution_trace_verifier_key_is_verifier_signing_key():
    """V15 reuses V16's key envelope. A v0.2 trace key is the same
    underlying type as a discharge key."""
    assert ExecutionTraceVerifierKey is VerifierSigningKey


def test_payload_kind_constant():
    """The domain-separation tag literal is part of the contract;
    changing it breaks all existing v0.2 traces."""
    assert EXECUTION_TRACE_PAYLOAD_KIND == "execution_trace.v0.2"


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_sign_attaches_verifier_signature():
    rec = _record_with_signed_trace()
    assert "execution_trace" in rec
    sig = rec["execution_trace"]["verifier_signature"]
    assert sig["algorithm"] == "hmac-sha256"
    assert sig["verifier_id"] == _KEY.verifier_id
    assert sig["timestamp_utc"] == "2026-05-03T12:30:00Z"
    assert isinstance(sig["mac"], str)
    assert len(sig["mac"]) == 64


def test_sign_then_verify_passes():
    rec = _record_with_signed_trace()
    assert verify_execution_trace_signature(
        rec, key=_KEY, bundle_id=_BUNDLE_ID, record_idx=0
    ) is True


def test_sign_returns_same_record_object():
    rec: dict = {"schema_version": "0.1", "marker": "preserve-me"}
    out = sign_execution_trace(
        rec,
        key=_KEY,
        wasm_module_sha256=_WASM_SHA,
        declared_effects=[],
        observed_imports=[],
        fuel_consumed=0,
        max_memory_bytes=0,
        return_status="ok",
        bundle_id=_BUNDLE_ID,
        record_idx=0,
        timestamp_utc="2026-05-03T12:30:00Z",
    )
    assert out is rec
    assert rec["marker"] == "preserve-me"


def test_declared_and_observed_lists_are_sorted_in_record():
    """Stable canonical-bytes form requires sort. Verify the writeback
    persists the sorted form — caller-passed unsorted lists must be
    sorted in the persisted trace."""
    rec = _record_with_signed_trace(
        declared_effects=["net", "fs", "model"],
        observed_imports=["wasi:filesystem/types", "wasi:sockets/tcp",
                          "nexi:dispatch/model"],
    )
    assert rec["execution_trace"]["declared_effects"] == ["fs", "model", "net"]
    assert rec["execution_trace"]["observed_imports"] == [
        "nexi:dispatch/model", "wasi:filesystem/types", "wasi:sockets/tcp",
    ]


# ---------------------------------------------------------------------------
# Verify-side rejection paths (BUG-3 / BUG-5 / BUG-8 lessons applied)
# ---------------------------------------------------------------------------


def test_verify_rejects_when_caller_bundle_id_mismatches():
    """BUG 3 lesson: bundle_id is mandatory caller-supplied. A mismatch
    between caller-supplied and trace-self-reported bundle_id rejects."""
    rec = _record_with_signed_trace()
    assert verify_execution_trace_signature(
        rec, key=_KEY, bundle_id=_OTHER_BUNDLE_ID, record_idx=0
    ) is False


def test_verify_rejects_empty_caller_bundle_id():
    rec = _record_with_signed_trace()
    assert verify_execution_trace_signature(
        rec, key=_KEY, bundle_id="", record_idx=0
    ) is False


def test_verify_rejects_when_caller_record_idx_mismatches():
    rec = _record_with_signed_trace(record_idx=5)
    assert verify_execution_trace_signature(
        rec, key=_KEY, bundle_id=_BUNDLE_ID, record_idx=5
    ) is True
    assert verify_execution_trace_signature(
        rec, key=_KEY, bundle_id=_BUNDLE_ID, record_idx=4
    ) is False


def test_verify_rejects_bool_record_idx():
    """BUG 8 lesson: isinstance(True, int) is True; bool must be
    rejected even though it would otherwise satisfy the int check."""
    rec = _record_with_signed_trace(record_idx=1)
    assert verify_execution_trace_signature(
        rec, key=_KEY, bundle_id=_BUNDLE_ID, record_idx=1
    ) is True
    assert verify_execution_trace_signature(
        rec, key=_KEY, bundle_id=_BUNDLE_ID, record_idx=True
    ) is False


def test_verify_rejects_wrong_key():
    """A trace signed by _KEY MUST NOT verify under _OTHER_KEY (different
    secret) or _FOREIGN_VERIFIER_KEY (different verifier_id)."""
    rec = _record_with_signed_trace()
    assert verify_execution_trace_signature(
        rec, key=_OTHER_KEY, bundle_id=_BUNDLE_ID, record_idx=0
    ) is False
    assert verify_execution_trace_signature(
        rec, key=_FOREIGN_VERIFIER_KEY, bundle_id=_BUNDLE_ID, record_idx=0
    ) is False


def test_verify_rejects_tampered_observed_imports():
    """The trace's observed_imports is part of the signed payload; any
    tampering after signing breaks the MAC."""
    rec = _record_with_signed_trace()
    rec["execution_trace"]["observed_imports"].append("wasi:filesystem/types")
    assert verify_execution_trace_signature(
        rec, key=_KEY, bundle_id=_BUNDLE_ID, record_idx=0
    ) is False


def test_verify_rejects_tampered_fuel_consumed():
    rec = _record_with_signed_trace()
    rec["execution_trace"]["fuel_consumed"] = 0  # was 42
    assert verify_execution_trace_signature(
        rec, key=_KEY, bundle_id=_BUNDLE_ID, record_idx=0
    ) is False


def test_verify_rejects_tampered_return_status():
    rec = _record_with_signed_trace(return_status="trapped:syscall_denied")
    assert verify_execution_trace_signature(
        rec, key=_KEY, bundle_id=_BUNDLE_ID, record_idx=0
    ) is True
    rec["execution_trace"]["return_status"] = "ok"  # downgrade an attack to "ok"
    assert verify_execution_trace_signature(
        rec, key=_KEY, bundle_id=_BUNDLE_ID, record_idx=0
    ) is False


def test_verify_rejects_tampered_wasm_module_sha():
    """A trace signed for module SHA A MUST NOT verify after the SHA
    is rewritten to module SHA B (cross-module replay)."""
    rec = _record_with_signed_trace()
    rec["execution_trace"]["wasm_module_sha256"] = _OTHER_WASM_SHA
    assert verify_execution_trace_signature(
        rec, key=_KEY, bundle_id=_BUNDLE_ID, record_idx=0
    ) is False


def test_verify_rejects_missing_execution_trace():
    """No execution_trace at all → False."""
    rec = {"schema_version": "0.1"}
    assert verify_execution_trace_signature(
        rec, key=_KEY, bundle_id=_BUNDLE_ID, record_idx=0
    ) is False


def test_verify_rejects_missing_signature():
    rec = _record_with_signed_trace()
    del rec["execution_trace"]["verifier_signature"]
    assert verify_execution_trace_signature(
        rec, key=_KEY, bundle_id=_BUNDLE_ID, record_idx=0
    ) is False


def test_verify_rejects_wrong_algorithm():
    rec = _record_with_signed_trace()
    rec["execution_trace"]["verifier_signature"]["algorithm"] = "ed25519"
    assert verify_execution_trace_signature(
        rec, key=_KEY, bundle_id=_BUNDLE_ID, record_idx=0
    ) is False


def test_verify_rejects_non_hex_mac():
    rec = _record_with_signed_trace()
    rec["execution_trace"]["verifier_signature"]["mac"] = "not-hex"
    assert verify_execution_trace_signature(
        rec, key=_KEY, bundle_id=_BUNDLE_ID, record_idx=0
    ) is False


# ---------------------------------------------------------------------------
# BUG 5 — domain-separation tag in canonical bytes
# ---------------------------------------------------------------------------


def test_payload_includes_domain_separation_tag():
    """The HMAC payload bytes MUST contain the literal `_kind` field with
    value 'execution_trace.v0.2'. Prevents cross-protocol forgery: a
    V14 stamp_upgrade payload and a V15 execution_trace payload cannot
    canonical-bytes collide regardless of schema evolution."""
    payload = _build_trace_payload(
        bundle_id=_BUNDLE_ID,
        record_idx=0,
        wasm_module_sha256=_WASM_SHA,
        declared_effects=["net"],
        observed_imports=["wasi:sockets/tcp"],
        fuel_consumed=42,
        max_memory_bytes=65536,
        return_status="ok",
        verifier_id=_KEY.verifier_id,
        timestamp_utc="2026-05-03T12:30:00Z",
    )
    assert b'"_kind":"execution_trace.v0.2"' in payload


def test_changing_kind_changes_mac():
    """Mutating the domain-separation tag value MUST produce a different
    HMAC under the same key."""
    import hmac as _hmac
    payload = _build_trace_payload(
        bundle_id=_BUNDLE_ID,
        record_idx=0,
        wasm_module_sha256=_WASM_SHA,
        declared_effects=[],
        observed_imports=[],
        fuel_consumed=0,
        max_memory_bytes=0,
        return_status="ok",
        verifier_id=_KEY.verifier_id,
        timestamp_utc="2026-05-03T12:30:00Z",
    )
    real_mac = _hmac.new(_KEY_BYTES, payload, hashlib.sha256).hexdigest()
    attacker = payload.replace(
        b'"_kind":"execution_trace.v0.2"',
        b'"_kind":"stamp_upgrade.v0.2"',
    )
    assert attacker != payload
    attacker_mac = _hmac.new(
        _KEY_BYTES, attacker, hashlib.sha256
    ).hexdigest()
    assert real_mac != attacker_mac


# ---------------------------------------------------------------------------
# Sign-side rejection paths
# ---------------------------------------------------------------------------


def test_sign_rejects_non_dict_record():
    with pytest.raises(TraceSigningError, match="dict"):
        sign_execution_trace(
            ["not-a-record"],  # type: ignore[arg-type]
            key=_KEY,
            wasm_module_sha256=_WASM_SHA,
            declared_effects=[],
            observed_imports=[],
            fuel_consumed=0,
            max_memory_bytes=0,
            return_status="ok",
            bundle_id=_BUNDLE_ID,
            record_idx=0,
            timestamp_utc="2026-05-03T12:30:00Z",
        )


def test_sign_rejects_empty_bundle_id():
    with pytest.raises(TraceSigningError, match="bundle_id"):
        sign_execution_trace(
            {}, key=_KEY,
            wasm_module_sha256=_WASM_SHA,
            declared_effects=[], observed_imports=[],
            fuel_consumed=0, max_memory_bytes=0,
            return_status="ok",
            bundle_id="", record_idx=0,
            timestamp_utc="2026-05-03T12:30:00Z",
        )


def test_sign_rejects_bool_record_idx():
    """BUG 8 lesson at the signer side."""
    with pytest.raises(TraceSigningError, match="bool excluded"):
        sign_execution_trace(
            {}, key=_KEY,
            wasm_module_sha256=_WASM_SHA,
            declared_effects=[], observed_imports=[],
            fuel_consumed=0, max_memory_bytes=0,
            return_status="ok",
            bundle_id=_BUNDLE_ID, record_idx=True,
            timestamp_utc="2026-05-03T12:30:00Z",
        )


def test_sign_rejects_negative_record_idx():
    with pytest.raises(TraceSigningError, match="non-negative"):
        sign_execution_trace(
            {}, key=_KEY,
            wasm_module_sha256=_WASM_SHA,
            declared_effects=[], observed_imports=[],
            fuel_consumed=0, max_memory_bytes=0,
            return_status="ok",
            bundle_id=_BUNDLE_ID, record_idx=-1,
            timestamp_utc="2026-05-03T12:30:00Z",
        )


def test_sign_rejects_non_hex_module_sha():
    with pytest.raises(TraceSigningError, match="hex"):
        sign_execution_trace(
            {}, key=_KEY,
            wasm_module_sha256="not-a-real-sha-just-a-string",
            declared_effects=[], observed_imports=[],
            fuel_consumed=0, max_memory_bytes=0,
            return_status="ok",
            bundle_id=_BUNDLE_ID, record_idx=0,
            timestamp_utc="2026-05-03T12:30:00Z",
        )


def test_sign_rejects_non_string_effect_label():
    with pytest.raises(TraceSigningError, match="declared_effects entries"):
        sign_execution_trace(
            {}, key=_KEY,
            wasm_module_sha256=_WASM_SHA,
            declared_effects=[42, "net"],  # type: ignore[list-item]
            observed_imports=[],
            fuel_consumed=0, max_memory_bytes=0,
            return_status="ok",
            bundle_id=_BUNDLE_ID, record_idx=0,
            timestamp_utc="2026-05-03T12:30:00Z",
        )


def test_sign_rejects_invalid_return_status():
    """Only 'ok' or 'trapped:<reason>' admitted."""
    with pytest.raises(TraceSigningError, match="return_status"):
        sign_execution_trace(
            {}, key=_KEY,
            wasm_module_sha256=_WASM_SHA,
            declared_effects=[], observed_imports=[],
            fuel_consumed=0, max_memory_bytes=0,
            return_status="success",  # not admitted
            bundle_id=_BUNDLE_ID, record_idx=0,
            timestamp_utc="2026-05-03T12:30:00Z",
        )


def test_sign_admits_trapped_status_prefix():
    """Any status starting with 'trapped:' is admitted at sign time —
    typed reasons enforced upstream by wasm_runner.TrapReason."""
    rec = _record_with_signed_trace(return_status="trapped:custom_reason")
    assert verify_execution_trace_signature(
        rec, key=_KEY, bundle_id=_BUNDLE_ID, record_idx=0
    ) is True


def test_sign_rejects_negative_fuel():
    with pytest.raises(TraceSigningError, match="fuel_consumed"):
        sign_execution_trace(
            {}, key=_KEY,
            wasm_module_sha256=_WASM_SHA,
            declared_effects=[], observed_imports=[],
            fuel_consumed=-1, max_memory_bytes=0,
            return_status="ok",
            bundle_id=_BUNDLE_ID, record_idx=0,
            timestamp_utc="2026-05-03T12:30:00Z",
        )


def test_sign_rejects_bool_fuel():
    with pytest.raises(TraceSigningError, match="fuel_consumed"):
        sign_execution_trace(
            {}, key=_KEY,
            wasm_module_sha256=_WASM_SHA,
            declared_effects=[], observed_imports=[],
            fuel_consumed=True, max_memory_bytes=0,
            return_status="ok",
            bundle_id=_BUNDLE_ID, record_idx=0,
            timestamp_utc="2026-05-03T12:30:00Z",
        )


def test_trace_payload_keys_constant_matches_builder():
    """Drift guard: _TRACE_PAYLOAD_KEYS is the documented contract of the V15
    HMAC payload; the builder hardcodes the dict literal (sibling constant
    _PAYLOAD_KEYS in verifier_signing drifted silently once)."""
    import json as _json

    from audit_bundle.effect_runtime.trace_attestation import _TRACE_PAYLOAD_KEYS

    payload = _json.loads(
        _build_trace_payload(
            bundle_id="b",
            record_idx=0,
            wasm_module_sha256="0" * 64,
            declared_effects=["fs_read"],
            observed_imports=["wasi_snapshot_preview1.fd_read"],
            fuel_consumed=1,
            max_memory_bytes=1,
            return_status="ok",
            verifier_id="v-kernel-test",
            timestamp_utc="2026-06-10T00:00:00Z",
        )
    )
    assert sorted(payload.keys()) == sorted(_TRACE_PAYLOAD_KEYS)
