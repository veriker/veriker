"""audit_bundle.effect_runtime — V-Kernel v0.2 WASM Component Model effect
enforcement (C15 hardening).

Implements the audit-bundle contract §C15 (effect-calculus enforcement via
WASM Component Model lowering).

Public surface (validation):
  - effect_binding.translate_effects_to_allowlist  — declared effect → allowlist
  - trace_attestation.sign_execution_trace         — verifier-set discipline
  - trace_attestation.verify_execution_trace_signature

The sandboxed execution runtime (WasmRuntime, ResourceLimits, ExecutionResult,
TrapReason) lives in the `wasm_runner` submodule and is imported directly from
there by the code that drives it. It is intentionally not re-exported here, so
importing this package pulls only the validation surface — the checks need the
validation halves (effect_binding, trace_attestation), not the runtime.

Verifier-set discipline (load-bearing for the C15 v0.2 invariant):
  Only `trace_attestation.sign_execution_trace` is allowed to write
  `execution_trace.verifier_signature`. The C15 plugin enforces this by
  rejecting unsigned trace blocks under mode='wasm' as
  WASM_TRACE_MISSING / WASM_TRACE_SIGNATURE_INVALID.

v0.2 fragment locked: the six v0.1 effect labels (net / fs / model /
llm_spend_usd / time_bound_ms / locale_bound). Reserved labels (db /
subprocess / random / clock / notify) reject under mode='wasm'.
locale_bound + (net | fs) combinations reject as WASM_LOCALE_BOUND_DEFERRED
at v0.2 (no host-side header guard wired); v0.3 lands the host shim.

v0.3 deferred: Pyodide/PyScript Python→WASM compile shim; multi-component
composition; full WIT-imported wasi:sockets/wasi:filesystem toolchain;
locale_bound enforcement via per-effect host shims.
"""

from __future__ import annotations

from .effect_binding import (
    EFFECT_LABEL_TO_IMPORTS,
    EffectBindingError,
    RESERVED_LABELS,
    translate_effects_to_allowlist,
)
from .trace_attestation import (
    EXECUTION_TRACE_PAYLOAD_KIND,
    ExecutionTraceVerifierKey,
    TraceSigningError,
    sign_execution_trace,
    verify_execution_trace_signature,
)

__all__ = [
    "EFFECT_LABEL_TO_IMPORTS",
    "EXECUTION_TRACE_PAYLOAD_KIND",
    "EffectBindingError",
    "ExecutionTraceVerifierKey",
    "RESERVED_LABELS",
    "TraceSigningError",
    "sign_execution_trace",
    "translate_effects_to_allowlist",
    "verify_execution_trace_signature",
]
