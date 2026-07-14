# audit_bundle.effect_runtime — V-Kernel v0.2 WASM Component Model effect enforcement (C15 hardening)

**Reference:** the audit-bundle contract §C15, "v0.2 enforcement plan — WASM Component Model lowering".

## Layered shipped-vs-deferred disclosure

- **Contract** — the audit-bundle contract §C15 v0.2 extends the v0.1 well-formedness invariant with an optional `dispatch_record.effect_enforcement_mode` field whose values are `"advisory"` (default; preserves v0.1 posture) and `"wasm"` (enforced via the runtime in this subpkg). When `mode="wasm"`, the record carries a verifier-signed `execution_trace` field that the C15 plugin re-verifies.
- **Plugin code** — `audit_bundle/plugins/dispatch_record_wellformed.py` extended with the `mode="wasm"` branch; this subpkg ships three modules (`wasm_runner.py`, `effect_binding.py`, `trace_attestation.py`) plus their adversarial test suite at `tests/test_effect_runtime/`.
- **Full enforcement scope at v0.2** — Wasmtime-backed sandboxed instantiation with structural fuel cap, memory cap, and syscall counter; effect-label-to-Linker-import allowlist translation grounded in the locked v0.1 vocabulary (`net` / `fs` / `model` / `llm_spend_usd` / `time_bound_ms` / `locale_bound`); reserved labels (`db` / `subprocess` / `random` / `clock` / `notify`) **reject in `mode="wasm"`** (advisory at v0.1, hard-fail at v0.2 because no v0.2-enforcement story exists for them); execution-trace verifier-signing with HMAC-SHA256 + `_kind="execution_trace.v0.2"` domain-separation tag (mirrors V14 BUG 5 fix posture); fail-closed when `recheck_key` is absent.
- **v0.3 deferred** — Pyodide / PyScript Python-dispatcher → WASM compilation shim (v0.2 ships the runtime substrate; consumer dispatchers compile to WASM out-of-band); multi-component composition (one component invoking another); cross-language wit-bindgen toolchain (Rust/Go/Java → WASM Component Model with auto-generated WIT bindings); full WIT-imported `wasi:sockets/tcp` / `wasi:filesystem/preopens` (v0.2 enforces effect containment via Linker import allowlist + per-effect host shims, which gives the same property — declared effects bound observed effects — without requiring the WASI 0.2 generator toolchain); locale_bound enforcement (v0.2 rejects locale_bound + net/fs combinations as `WASM_LOCALE_BOUND_DEFERRED`; v0.3 lands effect-specific host shims with header inspection).

## Public surface

```python
# Validation surface — re-exported at the package level.
from audit_bundle.effect_runtime import (
    # effect_binding
    translate_effects_to_allowlist, EffectBindingError,
    # trace_attestation
    sign_execution_trace, verify_execution_trace_signature, TraceSigningError,
)

# Sandboxed execution runtime — imported directly from its submodule, not
# re-exported by the package (so importing the package pulls only validation).
from audit_bundle.effect_runtime.wasm_runner import (
    WasmRuntime, ExecutionResult, ResourceLimits, TrapReason,
)
```

## Verifier-set discipline

Only `trace_attestation.sign_execution_trace` is allowed to write
`execution_trace.verifier_signature`. The C15 plugin enforces this — an
unsigned `execution_trace` block when `mode="wasm"` is hard-rejected as
`WASM_TRACE_MISSING` or `WASM_TRACE_SIGNATURE_INVALID`.

## Toolchain

- **Wasmtime Python binding** (`wasmtime>=44,<45`). Native `wasmtime.wat2wasm()`
  used for fixture compilation in the test suite — no external `wat2wasm` /
  `wabt` binary required.
- **Resource caps** — `Store.set_fuel(n)` for instruction-count cap;
  `Store.set_limits(memory_size=...)` for linear-memory cap; explicit
  syscall counter per `Linker` import.
