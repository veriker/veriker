"""V15 — adversarial test suite for the C15 plugin's effect_enforcement_mode='wasm'
branch. Each attack must trap with a named reason code.

Coverage for the five reason-code categories (s15-007):
  - WASM_TRACE_MISSING
  - WASM_TRACE_SIGNATURE_INVALID
  - WASM_EFFECT_DIVERGENCE
  - WASM_RESERVED_LABEL_REJECTED
  - WASM_RESOURCE_LIMIT_EXCEEDED
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from audit_bundle.discharge.verifier_signing import VerifierSigningKey
from audit_bundle.effect_runtime.trace_attestation import sign_execution_trace
from audit_bundle.plugins.dispatch_record_wellformed import (
    DispatchRecordWellformedCheck,
)


_KEY_BYTES = b"v15-plugin-secret-32bytes-pad!!!"
_KEY = VerifierSigningKey(verifier_id="v-kernel-test", secret=_KEY_BYTES)
_OTHER_KEY = VerifierSigningKey(
    verifier_id="v-kernel-test", secret=b"different-secret-32-bytes-padddd"
)
_BUNDLE_ID = "bundle-v15-plugin-001"
_OTHER_BUNDLE_ID = "bundle-v15-plugin-OTHER"
_WASM_SHA = hashlib.sha256(b"plugin-test-wasm-bytes").hexdigest()


class _Manifest:
    def __init__(self, dispatch_records=(), bundle_id=_BUNDLE_ID):
        self.dispatch_records = dispatch_records
        self.bundle_id = bundle_id
        self.created_at = "2026-05-03T12:00:00Z"
        self.per_output_manifests = ()
        self.schema_version = "vcp-v1.1-canary4"


def _record(*, effect=None, mode=None, has_trace=True,
            declared_effects=None, observed_imports=None,
            return_status="ok", sign_with=_KEY,
            sign_bundle_id=_BUNDLE_ID, sign_record_idx=0):
    """Build a dispatch_record with optional V15 fields."""
    rec: dict = {
        "schema_version": "0.1",
        "op": {"kind": "COMPUTE", "name": "score"},
        "inputs": [],
        "outputs": [
            {"name": "r", "type": {"base": "Int", "refine": "(>= r 0)"}},
        ],
        "effect": effect if effect is not None else {},
        "locale": "en-US",
        "predicates": [],
        "stamp_declared": "INTERNAL_BENCHMARK",
        "stamp_observed": "INTERNAL_BENCHMARK",
    }
    if mode is not None:
        rec["effect_enforcement_mode"] = mode
    if has_trace:
        sign_execution_trace(
            rec, key=sign_with,
            wasm_module_sha256=_WASM_SHA,
            declared_effects=(
                declared_effects
                if declared_effects is not None
                else (list(effect) if isinstance(effect, dict) else [])
            ),
            observed_imports=observed_imports or [],
            fuel_consumed=42,
            max_memory_bytes=65536,
            return_status=return_status,
            bundle_id=sign_bundle_id,
            record_idx=sign_record_idx,
            timestamp_utc="2026-05-03T12:30:00Z",
        )
    return rec


# ---------------------------------------------------------------------------
# v0.1 / mode='advisory' — no behavior change
# ---------------------------------------------------------------------------


def test_no_mode_field_passes_v0_1_path(tmp_path):
    """Pre-V15 bundles (no effect_enforcement_mode field) verify exactly
    as v0.1 — no execution_trace required."""
    rec = _record(effect={"net": []}, mode=None, has_trace=False)
    plugin = DispatchRecordWellformedCheck()  # no key needed
    res = plugin.check(tmp_path, _Manifest(dispatch_records=(rec,)))
    assert res.ok is True


def test_advisory_mode_passes_without_trace(tmp_path):
    """Explicit mode='advisory' is the v0.1 posture; no trace required."""
    rec = _record(effect={"net": []}, mode="advisory", has_trace=False)
    plugin = DispatchRecordWellformedCheck()
    res = plugin.check(tmp_path, _Manifest(dispatch_records=(rec,)))
    assert res.ok is True


def test_advisory_mode_admits_reserved_labels(tmp_path):
    """Reserved labels are advisory at v0.1 (and under mode='advisory'
    at v0.2). The C15 plugin emits them as advisory in the message,
    not a hard fail."""
    rec = _record(effect={"db": [], "net": []}, mode="advisory",
                  has_trace=False)
    plugin = DispatchRecordWellformedCheck()
    res = plugin.check(tmp_path, _Manifest(dispatch_records=(rec,)))
    assert res.ok is True


# ---------------------------------------------------------------------------
# mode='wasm' happy path
# ---------------------------------------------------------------------------


def test_wasm_mode_happy_path_passes(tmp_path):
    """Declared net + observed wasi:sockets/tcp + verifier-signed trace +
    return_status='ok' → PASS."""
    rec = _record(
        effect={"net": []}, mode="wasm",
        observed_imports=["wasi:sockets/tcp"],
        return_status="ok",
    )
    plugin = DispatchRecordWellformedCheck(recheck_key=_KEY)
    res = plugin.check(tmp_path, _Manifest(dispatch_records=(rec,)))
    assert res.ok is True, res.detail


def test_wasm_mode_pure_dispatch_passes(tmp_path):
    """Declared empty effect + no observed imports + clean run → PASS.
    The pure-compute dispatch case under WASM enforcement."""
    rec = _record(
        effect={}, mode="wasm",
        observed_imports=[],
        return_status="ok",
    )
    plugin = DispatchRecordWellformedCheck(recheck_key=_KEY)
    res = plugin.check(tmp_path, _Manifest(dispatch_records=(rec,)))
    assert res.ok is True, res.detail


# ---------------------------------------------------------------------------
# WASM_TRACE_MISSING
# ---------------------------------------------------------------------------


def test_wasm_mode_no_trace_rejected(tmp_path):
    rec = _record(effect={"net": []}, mode="wasm", has_trace=False)
    plugin = DispatchRecordWellformedCheck(recheck_key=_KEY)
    res = plugin.check(tmp_path, _Manifest(dispatch_records=(rec,)))
    assert res.ok is False
    assert res.reason_code == "WASM_TRACE_MISSING"


def test_wasm_mode_trace_not_a_dict_rejected(tmp_path):
    rec = _record(effect={"net": []}, mode="wasm", has_trace=False)
    rec["execution_trace"] = ["not", "a", "dict"]
    plugin = DispatchRecordWellformedCheck(recheck_key=_KEY)
    res = plugin.check(tmp_path, _Manifest(dispatch_records=(rec,)))
    assert res.ok is False
    assert res.reason_code == "WASM_TRACE_MISSING"


# ---------------------------------------------------------------------------
# WASM_TRACE_SIGNATURE_INVALID
# ---------------------------------------------------------------------------


def test_wasm_mode_no_recheck_key_fails_closed(tmp_path):
    """FAIL-CLOSED — plugin without a recheck_key MUST reject any
    mode='wasm' record. Mirrors V14 / C16 BUG-1 fix posture."""
    rec = _record(effect={"net": []}, mode="wasm",
                  observed_imports=["wasi:sockets/tcp"])
    plugin = DispatchRecordWellformedCheck()  # NO recheck_key
    res = plugin.check(tmp_path, _Manifest(dispatch_records=(rec,)))
    assert res.ok is False
    assert res.reason_code == "WASM_TRACE_SIGNATURE_INVALID"
    assert "recheck_key" in res.detail or "fail" in res.detail.lower()


def test_wasm_mode_trace_signed_under_wrong_key_rejected(tmp_path):
    rec = _record(effect={"net": []}, mode="wasm",
                  observed_imports=["wasi:sockets/tcp"],
                  sign_with=_OTHER_KEY)
    plugin = DispatchRecordWellformedCheck(recheck_key=_KEY)
    res = plugin.check(tmp_path, _Manifest(dispatch_records=(rec,)))
    assert res.ok is False
    assert res.reason_code == "WASM_TRACE_SIGNATURE_INVALID"


def test_wasm_mode_cross_bundle_replay_rejected(tmp_path):
    """Trace was signed for bundle A; verifier sees bundle B."""
    rec = _record(effect={"net": []}, mode="wasm",
                  observed_imports=["wasi:sockets/tcp"],
                  sign_bundle_id=_OTHER_BUNDLE_ID)
    plugin = DispatchRecordWellformedCheck(recheck_key=_KEY)
    res = plugin.check(tmp_path, _Manifest(
        dispatch_records=(rec,), bundle_id=_BUNDLE_ID,
    ))
    assert res.ok is False
    assert res.reason_code == "WASM_TRACE_SIGNATURE_INVALID"


def test_wasm_mode_cross_record_replay_rejected(tmp_path):
    """Trace was signed for record_idx=5; verifier sees it at record_idx=0."""
    rec = _record(effect={"net": []}, mode="wasm",
                  observed_imports=["wasi:sockets/tcp"],
                  sign_record_idx=5)
    plugin = DispatchRecordWellformedCheck(recheck_key=_KEY)
    res = plugin.check(tmp_path, _Manifest(dispatch_records=(rec,)))
    assert res.ok is False
    assert res.reason_code == "WASM_TRACE_SIGNATURE_INVALID"


def test_wasm_mode_empty_manifest_bundle_id_fails_closed(tmp_path):
    """If the manifest has no bundle_id, the plugin can't supply
    authoritative ground truth; fail closed."""
    rec = _record(effect={"net": []}, mode="wasm",
                  observed_imports=["wasi:sockets/tcp"])
    plugin = DispatchRecordWellformedCheck(recheck_key=_KEY)
    res = plugin.check(tmp_path, _Manifest(
        dispatch_records=(rec,), bundle_id="",
    ))
    assert res.ok is False
    assert res.reason_code == "WASM_TRACE_SIGNATURE_INVALID"


def test_wasm_mode_tampered_observed_imports_rejected(tmp_path):
    """Sign with one observed_imports list, then mutate after signing —
    MAC re-verify catches the tamper."""
    rec = _record(effect={"net": []}, mode="wasm",
                  observed_imports=["wasi:sockets/tcp"])
    rec["execution_trace"]["observed_imports"].append("wasi:filesystem/types")
    plugin = DispatchRecordWellformedCheck(recheck_key=_KEY)
    res = plugin.check(tmp_path, _Manifest(dispatch_records=(rec,)))
    assert res.ok is False
    assert res.reason_code == "WASM_TRACE_SIGNATURE_INVALID"


# ---------------------------------------------------------------------------
# WASM_RESERVED_LABEL_REJECTED
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("reserved", ["db", "subprocess", "random",
                                       "clock", "notify"])
def test_wasm_mode_reserved_label_rejected(tmp_path, reserved):
    rec = _record(
        effect={reserved: [], "net": []}, mode="wasm",
        declared_effects=[reserved, "net"],
        observed_imports=["wasi:sockets/tcp"],
    )
    plugin = DispatchRecordWellformedCheck(recheck_key=_KEY)
    res = plugin.check(tmp_path, _Manifest(dispatch_records=(rec,)))
    assert res.ok is False
    assert res.reason_code == "WASM_RESERVED_LABEL_REJECTED"
    assert reserved in res.detail


# ---------------------------------------------------------------------------
# WASM_EFFECT_DIVERGENCE — declared-effects must bound observed-effects
# ---------------------------------------------------------------------------


def test_wasm_mode_observed_outside_declared_rejected(tmp_path):
    """Dispatcher declared net only, but observed_imports include
    wasi:filesystem/types (which is admitted by 'fs', not 'net')."""
    rec = _record(
        effect={"net": []}, mode="wasm",
        declared_effects=["net"],
        observed_imports=["wasi:sockets/tcp", "wasi:filesystem/types"],
    )
    plugin = DispatchRecordWellformedCheck(recheck_key=_KEY)
    res = plugin.check(tmp_path, _Manifest(dispatch_records=(rec,)))
    assert res.ok is False
    assert res.reason_code == "WASM_EFFECT_DIVERGENCE"
    assert "wasi:filesystem/types" in res.detail


def test_wasm_mode_observed_completely_unknown_rejected(tmp_path):
    """Observed import isn't in the v0.2 vocabulary at all."""
    rec = _record(
        effect={"net": []}, mode="wasm",
        declared_effects=["net"],
        observed_imports=["attacker:malware/run"],
    )
    plugin = DispatchRecordWellformedCheck(recheck_key=_KEY)
    res = plugin.check(tmp_path, _Manifest(dispatch_records=(rec,)))
    assert res.ok is False
    assert res.reason_code == "WASM_EFFECT_DIVERGENCE"


def test_wasm_mode_declared_pure_observed_io_rejected(tmp_path):
    """Dispatcher declared {} (pure compute) but observed_imports has
    a network call → divergence."""
    rec = _record(
        effect={}, mode="wasm",
        declared_effects=[],
        observed_imports=["wasi:sockets/tcp"],
    )
    plugin = DispatchRecordWellformedCheck(recheck_key=_KEY)
    res = plugin.check(tmp_path, _Manifest(dispatch_records=(rec,)))
    assert res.ok is False
    assert res.reason_code == "WASM_EFFECT_DIVERGENCE"


# ---------------------------------------------------------------------------
# WASM_RESOURCE_LIMIT_EXCEEDED — trapped run not admitted under wasm
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("trap_status", [
    "trapped:fuel_exhausted",
    "trapped:mem_cap_exceeded",
    "trapped:syscall_denied",
    "trapped:guest_trap",
    "trapped:bad_bytecode",
])
def test_wasm_mode_trapped_run_rejected(tmp_path, trap_status):
    rec = _record(
        effect={"net": []}, mode="wasm",
        observed_imports=["wasi:sockets/tcp"],
        return_status=trap_status,
    )
    plugin = DispatchRecordWellformedCheck(recheck_key=_KEY)
    res = plugin.check(tmp_path, _Manifest(dispatch_records=(rec,)))
    assert res.ok is False
    assert res.reason_code == "WASM_RESOURCE_LIMIT_EXCEEDED"


# ---------------------------------------------------------------------------
# Unknown mode value
# ---------------------------------------------------------------------------


def test_unknown_mode_value_rejected(tmp_path):
    rec = _record(effect={}, mode="hardened", has_trace=False)
    plugin = DispatchRecordWellformedCheck(recheck_key=_KEY)
    res = plugin.check(tmp_path, _Manifest(dispatch_records=(rec,)))
    assert res.ok is False
    assert res.reason_code == "EFFECT_ENFORCEMENT_MODE_UNKNOWN"
