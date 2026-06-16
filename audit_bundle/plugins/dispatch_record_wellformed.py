"""Dispatch record well-formedness — C15 schema discipline per the audit-bundle contract §C15.

v0.1 scope (still in effect for mode='advisory'): well-formedness — shape validation,
op_kind enum, per-output type fields, effect-label locked-set membership, refinement
formula regex-based fragment membership check.

v0.2 scope (V15): when a dispatch_record carries
`effect_enforcement_mode == 'wasm'`, the plugin additionally verifies that:
  - reserved-set labels (db / subprocess / random / clock / notify) are NOT
    declared (no v0.2 enforcement story → reject),
  - a verifier-signed `execution_trace` is present and re-verifies under the
    plugin's recheck_key (FAIL-CLOSED when no key wired — mirrors the V14
    fail-closed posture),
  - the trace's observed_imports are all admitted by some declared effect
    label (effect-containment soundness from the effect calculus),
  - the trace's return_status == 'ok' (a trapped run means the dispatcher's
    declared resources were not enough; v0.2 admits only fully-completed
    runs into mode='wasm' bundles).

When `effect_enforcement_mode` is absent or `'advisory'`, the plugin behaves
as v0.1 — the V15 branch is opt-in; pre-V15 bundles continue to verify
unchanged.

Deferred to v0.3: full WIT-imported wasi:sockets/wasi:filesystem toolchain;
multi-component composition; Pyodide/PyScript Python→WASM compilation shim;
locale_bound enforcement via per-effect host shims (v0.2 rejects
locale_bound + net/fs combinations with WASM_LOCALE_BOUND_DEFERRED).


"""

from __future__ import annotations

import re
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check

# Import the key-envelope type via the V15 stream's re-export, NOT directly
# from the V14 discharge stream. The CHANGELOG promises "V15 ↔ V14: no file
# overlap"; importing through effect_runtime keeps that promise load-bearing
# on the import graph too.
from audit_bundle.effect_runtime import (
    ExecutionTraceVerifierKey as VerifierSigningKey,
)
from audit_bundle.effect_runtime.effect_binding import (
    LOCKED_LABELS as _EFFECT_LOCKED_LABELS_FROM_RUNTIME,
    RESERVED_LABELS as _EFFECT_RESERVED_LABELS_FROM_RUNTIME,
    label_admits_import,
    reverse_map_import,
)
from audit_bundle.effect_runtime.trace_attestation import (
    verify_execution_trace_signature,
)
from audit_bundle.plugin import PluginResult
from audit_bundle.stamp_claims import dispatch_record_keys

_SCHEMA_VERSION_RECOGNIZED: str = "0.1"

# Default op.kind enum admitted by the C15 plugin. Constructor-configurable
# via DispatchRecordWellformedCheck(op_kinds_admitted=...). The open
# vocabulary is the domain-generic categories. New domains should
# prefer the generic categories or pass a custom frozenset at construction.
_DEFAULT_OP_KIND_ENUM: frozenset[str] = frozenset(
    {
        # Domain-generic categories (preferred for new pilots)
        "TOOL",
        "COMPUTE",
        "MODEL_CALL",
        "RETRIEVAL",
        "FORECAST",
    }
)

# Locked + reserved sets are sourced from effect_runtime/ for V15 coherence.
# V15 must not drift from the v0.1 vocabulary; effect_runtime/ owns the lock,
# this plugin imports it. (Pre-V15 these were duplicated literals; V15
# centralises them in effect_runtime/effect_binding.py to avoid drift.)
_EFFECT_LOCKED_SET: frozenset[str] = _EFFECT_LOCKED_LABELS_FROM_RUNTIME
_EFFECT_RESERVED_SET: frozenset[str] = _EFFECT_RESERVED_LABELS_FROM_RUNTIME

# V15 — admitted values for dispatch_record.effect_enforcement_mode.
# Absent = pre-V15 bundle = treat as 'advisory' (v0.1 posture preserved).
_ENFORCEMENT_MODE_ADVISORY: str = "advisory"
_ENFORCEMENT_MODE_WASM: str = "wasm"
_ENFORCEMENT_MODES: frozenset[str] = frozenset(
    {
        _ENFORCEMENT_MODE_ADVISORY,
        _ENFORCEMENT_MODE_WASM,
    }
)

_REFINE_CHAR_RE: re.Pattern = re.compile(r"^[\s\(\)a-zA-Z0-9_+\-*\<\>=!.,:|\"\']+$")

_REFINE_BANNED_TOKENS: tuple[str, ...] = (
    "forall ",
    "exists ",
    "as Array",
    "as String",
    "declare-rec",
    "mod ",
    "div ",
    "/ ",
)

# Schema versions for which the DISPATCH_RECORD_FIELD_ABSENT cardinality check is
# active. Empty at v0.1 — pre-Phase-0 legacy bundles ('vcp-v1.1-canary4', 'legacy')
# pass cleanly even when per_output_manifests > 0 and dispatch_records is empty.
# Post-Phase-0 cutover, the new Phase-0 schema_version goes into this set, and
# legacy bundles re-verified at that time MUST carry explicit-null dispatch_records
# (the contract's "forward-compatible legacy marker" stance, audit-bundle contract §C15).
_PHASE_0_CUTOVER_SCHEMA_VERSIONS: frozenset[str] = frozenset({"vcp-v1.1"})


def _parens_balanced(s: str) -> bool:
    depth = 0
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


class DispatchRecordWellformedCheck:
    """TypedCheck plugin enforcing the audit-bundle contract §C15 well-formedness.

    Constructor:
      `recheck_key` — VerifierSigningKey used to re-verify HMAC signatures
        on `execution_trace.verifier_signature` for records with
        `effect_enforcement_mode='wasm'`. When None (default), the plugin
        operates in V15 FAIL-CLOSED mode: any record that opts into
        mode='wasm' is rejected as WASM_TRACE_SIGNATURE_INVALID. Mirrors
        the V14 / C16 fail-closed posture — production deployments wiring
        the V15 enforced path MUST supply a key. Bundles that stay on
        mode='advisory' (or omit the field) verify cleanly with key=None.
    """

    name: str = "dispatch_record_wellformed"
    applies_to_files: frozenset[str] = frozenset()

    def __init__(
        self,
        *,
        recheck_key: VerifierSigningKey | None = None,
        op_kinds_admitted: frozenset[str] | None = None,
    ):
        self.recheck_key = recheck_key
        # Domain-agnostic extension point: callers register additional
        # op.kind categories by passing a custom frozenset. None preserves
        # the v0.1 default (RETRIEVAL/FORECAST + legacy product kinds +
        # generic TOOL/COMPUTE/MODEL_CALL). Subclassing not required.
        self.op_kinds_admitted: frozenset[str] = (
            frozenset(op_kinds_admitted)
            if op_kinds_admitted is not None
            else _DEFAULT_OP_KIND_ENUM
        )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        records = getattr(manifest, "dispatch_records", ()) or ()
        per_output = getattr(manifest, "per_output_manifests", ()) or ()
        bundle_id = getattr(manifest, "bundle_id", None)

        if not records:
            schema_version = getattr(manifest, "schema_version", None)
            if (
                len(per_output) > 0
                and schema_version in _PHASE_0_CUTOVER_SCHEMA_VERSIONS
            ):
                return PluginResult(
                    ok=False,
                    reason_code="DISPATCH_RECORD_FIELD_ABSENT",
                    detail=(
                        f"per_output_manifests has {len(per_output)} row(s) but "
                        "dispatch_records is empty (Phase-0 cardinality mismatch)"
                    ),
                    files_audited=(),
                )
            return PluginResult(
                ok=True,
                reason_code="PASS",
                detail="no dispatch_records present (W3-baseline / pre-Phase-0 bundle)",
                files_audited=(),
            )

        reserved_advisory_count = 0
        out_of_fragment_count = 0

        for idx, record in enumerate(records):
            if record is None:
                continue
            if not isinstance(record, dict):
                # Fail-closed type guard: manifest.dispatch_records element
                # types are not validated at parse, so a hostile non-dict
                # element (e.g. "foo" / 123 / [...]) would otherwise raise
                # AttributeError out of the plugin and degrade the run to a
                # VERIFIER_INTERNAL_ERROR crash instead of a recorded REJECT.
                return PluginResult(
                    ok=False,
                    reason_code="DISPATCH_RECORD_MALFORMED",
                    detail=(
                        f"record[{idx}]: dispatch_records element must be a "
                        f"JSON object, got {type(record).__name__!r}"
                    ),
                    files_audited=(),
                )

            # Sub-invariant 1 — schema_version recognized
            sv = record.get("schema_version")
            if sv != _SCHEMA_VERSION_RECOGNIZED:
                return PluginResult(
                    ok=False,
                    reason_code="SCHEMA_VERSION_UNRECOGNIZED",
                    detail=(
                        f"record[{idx}]: schema_version={sv!r} is not recognized; "
                        f"only {_SCHEMA_VERSION_RECOGNIZED!r} is valid at this release"
                    ),
                    files_audited=(),
                )

            # Sub-invariant 2 — op.kind in enum
            op = record.get("op", {})
            op_kind = op.get("kind") if isinstance(op, dict) else None
            if op_kind not in self.op_kinds_admitted:
                return PluginResult(
                    ok=False,
                    reason_code="OP_KIND_OUT_OF_ENUM",
                    detail=(
                        f"record[{idx}]: op.kind={op_kind!r} is not in the recognized "
                        f"enum {sorted(self.op_kinds_admitted)}"
                    ),
                    files_audited=(),
                )

            # Sub-invariant 3 — effect-row vocabulary locked
            effect = record.get("effect", {})
            if isinstance(effect, dict):
                for label in effect:
                    if label in _EFFECT_LOCKED_SET:
                        continue
                    if label in _EFFECT_RESERVED_SET:
                        reserved_advisory_count += 1
                    else:
                        return PluginResult(
                            ok=False,
                            reason_code="EFFECT_LABEL_UNKNOWN",
                            detail=(
                                f"record[{idx}]: effect label {label!r} is not in the "
                                "v0.1 locked vocabulary or the reserved-forward set"
                            ),
                            files_audited=(),
                        )

            # Sub-invariant 4 — refinement formula in v0.1 fragment
            outputs = record.get("outputs", [])
            if not isinstance(outputs, list):
                outputs = []
            for out_idx, output in enumerate(outputs):
                if not isinstance(output, dict):
                    continue
                out_type = output.get("type")
                if not isinstance(out_type, dict):
                    continue
                refine = out_type.get("refine")
                if refine is None:
                    continue
                if not isinstance(refine, str):
                    return PluginResult(
                        ok=False,
                        reason_code="REFINEMENT_PARSE_ERROR",
                        detail=(
                            f"record[{idx}] output[{out_idx}]: refine value must be a "
                            f"string, got {type(refine).__name__!r}"
                        ),
                        files_audited=(),
                    )
                if not _REFINE_CHAR_RE.match(refine):
                    return PluginResult(
                        ok=False,
                        reason_code="REFINEMENT_PARSE_ERROR",
                        detail=(
                            f"record[{idx}] output[{out_idx}]: refine string contains "
                            f"characters outside the v0.1 allowlist: {refine!r}"
                        ),
                        files_audited=(),
                    )
                if not _parens_balanced(refine):
                    return PluginResult(
                        ok=False,
                        reason_code="REFINEMENT_PARSE_ERROR",
                        detail=(
                            f"record[{idx}] output[{out_idx}]: refine string has "
                            f"unbalanced parentheses: {refine!r}"
                        ),
                        files_audited=(),
                    )
                for token in _REFINE_BANNED_TOKENS:
                    if token in refine:
                        out_of_fragment_count += 1
                        break

            # V15 — Sub-invariant 5: effect_enforcement_mode branch.
            # mode absent or 'advisory' → v0.1 posture preserved (no extra check).
            # mode='wasm' → enforce execution_trace + reserved-label rejection.
            wasm_failure = self._check_wasm_enforcement(
                idx=idx,
                record=record,
                bundle_id=bundle_id,
            )
            if wasm_failure is not None:
                return wasm_failure

        # Per-record C15 coverage (proof, not promise): content keys for every
        # element this check actually read and disposed of (None elements are
        # skip-by-contract and still covered; non-dict non-None elements never
        # reach here — they reject above). Consumed by
        # BundleVerifier._step_stamp_claims_guard; a non-canonicalizable
        # element yields no key → stays uncovered → the guard fails closed.
        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail=(
                f"all dispatch_records well-formed; {len(records)} records audited; "
                f"{reserved_advisory_count} reserved-label advisories; "
                f"{out_of_fragment_count} out-of-fragment refinements ignored"
            ),
            files_audited=(),
            verified_dispatch_records=dispatch_record_keys(records),
        )

    # ------------------------------------------------------------------
    # V15 — WASM-mode enforcement branch
    # ------------------------------------------------------------------

    def _check_wasm_enforcement(
        self,
        *,
        idx: int,
        record: dict,
        bundle_id,
    ) -> PluginResult | None:
        """Run V15 enforcement when record.effect_enforcement_mode='wasm'.

        Returns None when the record opts out (mode absent / 'advisory')
        AND carries no execution_trace, or a failure PluginResult tagged
        with one of:
          - EFFECT_ENFORCEMENT_MODE_BYPASS
          - EFFECT_ENFORCEMENT_MODE_UNKNOWN
          - WASM_RESERVED_LABEL_REJECTED
          - WASM_TRACE_MISSING
          - WASM_TRACE_SIGNATURE_INVALID
          - WASM_EFFECT_DIVERGENCE
          - WASM_DECLARED_EFFECT_DRIFT
          - WASM_RESOURCE_LIMIT_EXCEEDED
        """
        mode = record.get("effect_enforcement_mode")
        # An advisory-mode record carrying an execution_trace is a bypass
        # surface — an MLIR→WASM workload that produced a real trace could be
        # re-emitted with mode='advisory' (or omitted) and effect={} to skip
        # every V15 check below. Reject any trace-bearing record that is not in
        # mode='wasm'; producers must emit effect_enforcement_mode='wasm'
        # whenever a trace is present.
        trace_present = (
            isinstance(record.get("execution_trace"), dict)
            and len(record.get("execution_trace") or {}) > 0
        )
        if mode != _ENFORCEMENT_MODE_WASM and trace_present:
            return PluginResult(
                ok=False,
                reason_code="EFFECT_ENFORCEMENT_MODE_BYPASS",
                detail=(
                    f"record[{idx}]: execution_trace is present but "
                    f"effect_enforcement_mode={mode!r}; under the V15 "
                    "composition invariant, any record carrying a verifier-"
                    "signable trace MUST opt into mode='wasm' so the C15 "
                    "plugin's strong checks (signed-trace verify, "
                    "declared==observed containment, reserved-label "
                    "rejection, return_status='ok') run. Allowing a record "
                    "to ship a trace under mode='advisory' is the "
                    "MLIR→WASM bypass surface — effectful code could "
                    "execute under V15 then re-emit as advisory + "
                    "effect={} and skip every check"
                ),
                files_audited=(),
            )
        if mode is None or mode == _ENFORCEMENT_MODE_ADVISORY:
            return None
        if mode not in _ENFORCEMENT_MODES:
            return PluginResult(
                ok=False,
                reason_code="EFFECT_ENFORCEMENT_MODE_UNKNOWN",
                detail=(
                    f"record[{idx}]: effect_enforcement_mode={mode!r} is not "
                    f"in the v0.2 enum {sorted(_ENFORCEMENT_MODES)}"
                ),
                files_audited=(),
            )

        # mode == 'wasm' — full V15 enforcement.

        # Sub-check (a) — execution_trace must exist with the V15 schema.
        # Trace existence is checked BEFORE the reserved-label check so that
        # the reserved-label check operates on the HMAC-bound
        # trace["declared_effects"], not the unbound record["effect"].
        trace = record.get("execution_trace")
        if not isinstance(trace, dict):
            return PluginResult(
                ok=False,
                reason_code="WASM_TRACE_MISSING",
                detail=(
                    f"record[{idx}]: effect_enforcement_mode='wasm' but "
                    "execution_trace is absent or not a dict; the V15 "
                    "verifier-set discipline requires a verifier-signed "
                    "trace block"
                ),
                files_audited=(),
            )

        # Sub-check (b) — recheck_key must be wired (FAIL-CLOSED).
        if self.recheck_key is None:
            return PluginResult(
                ok=False,
                reason_code="WASM_TRACE_SIGNATURE_INVALID",
                detail=(
                    f"record[{idx}]: effect_enforcement_mode='wasm' but the "
                    "DispatchRecordWellformedCheck plugin was constructed "
                    "without a recheck_key. Production deployments wiring "
                    "the V15 enforced path MUST supply a "
                    "VerifierSigningKey (mirrors the V14 / C16 fail-closed "
                    "posture); without it the plugin cannot verify the HMAC "
                    "and fails closed"
                ),
                files_audited=(),
            )

        # Sub-check (c) — verifier signature must re-verify against
        # caller-supplied authoritative bindings.
        if not isinstance(bundle_id, str) or not bundle_id:
            return PluginResult(
                ok=False,
                reason_code="WASM_TRACE_SIGNATURE_INVALID",
                detail=(
                    f"record[{idx}]: manifest carries no bundle_id (or it "
                    "is empty); cannot supply authoritative ground truth "
                    "to the trace HMAC re-verification"
                ),
                files_audited=(),
            )
        if not verify_execution_trace_signature(
            record,
            key=self.recheck_key,
            bundle_id=bundle_id,
            record_idx=idx,
        ):
            return PluginResult(
                ok=False,
                reason_code="WASM_TRACE_SIGNATURE_INVALID",
                detail=(
                    f"record[{idx}]: execution_trace.verifier_signature failed "
                    f"HMAC re-verification under verifier_id="
                    f"{self.recheck_key.verifier_id!r}; signature is forged, "
                    "replayed across bundles/records, signed under a different "
                    "key, or the trace body was tampered after signing"
                ),
                files_audited=(),
            )

        # All effect-vocabulary reasoning below uses the HMAC-BOUND
        # `trace["declared_effects"]` as the authoritative declared set.
        # Reading `record["effect"].keys()` for the reserved-label +
        # effect-containment checks would let a record drift from its signed
        # trace and bypass containment in either direction (reproducer: trace
        # signs declared=["net"]/observed=fs while
        # record["effect"]={"net":[],"fs":[]} → containment passes because the
        # record-level set covers fs). This applies the authoritative
        # caller-supplied-bindings discipline to declared_effects.
        # Additionally: enforce set-equality between record and trace so that
        # the record's effect dict stays self-consistent with what the verifier
        # signed for downstream consumers reading
        # `record["effect"]`.
        trace_declared_raw = trace.get("declared_effects")
        if not isinstance(trace_declared_raw, list):
            return PluginResult(
                ok=False,
                reason_code="WASM_TRACE_SIGNATURE_INVALID",
                detail=(
                    f"record[{idx}]: execution_trace.declared_effects is not a "
                    f"list (got {type(trace_declared_raw).__name__}); a valid "
                    "HMAC-verified trace must carry a sorted list of declared "
                    "effect labels"
                ),
                files_audited=(),
            )
        for label in trace_declared_raw:
            if not isinstance(label, str):
                return PluginResult(
                    ok=False,
                    reason_code="WASM_TRACE_SIGNATURE_INVALID",
                    detail=(
                        f"record[{idx}]: trace.declared_effects entry "
                        f"{label!r} is not a string"
                    ),
                    files_audited=(),
                )
        trace_declared_set = set(trace_declared_raw)

        # Sub-check (d) — record-level effect dict must agree with the
        # HMAC-bound trace.declared_effects set. The record["effect"] dict is
        # otherwise unbound — downstream consumers reading it would see
        # attacker-controlled data not covered by the signature.
        # This dispatcher-level inconsistency (record.effect.keys() vs
        # HMAC-bound trace.declared_effects) gets the dedicated reason code
        # WASM_DECLARED_EFFECT_DRIFT so operators can distinguish "the
        # dispatcher lied between two of its own declarations" from "the WASM
        # module lied between declaration and runtime behavior" (which keeps
        # WASM_EFFECT_DIVERGENCE).
        effect = record.get("effect", {}) or {}
        if not isinstance(effect, dict):
            return PluginResult(
                ok=False,
                reason_code="WASM_DECLARED_EFFECT_DRIFT",
                detail=(
                    f"record[{idx}]: record.effect is not a dict (got "
                    f"{type(effect).__name__}) — under "
                    f"effect_enforcement_mode='wasm' the record must carry a "
                    "dict whose keys equal trace.declared_effects"
                ),
                files_audited=(),
            )
        record_effect_set = set(effect.keys())
        if record_effect_set != trace_declared_set:
            return PluginResult(
                ok=False,
                reason_code="WASM_DECLARED_EFFECT_DRIFT",
                detail=(
                    f"record[{idx}]: record.effect.keys()="
                    f"{sorted(record_effect_set)} differs from HMAC-bound "
                    f"trace.declared_effects={sorted(trace_declared_set)}; "
                    "under effect_enforcement_mode='wasm' the two sets must "
                    "match exactly so downstream consumers reading "
                    "record.effect see the same vocabulary the verifier "
                    "signed"
                ),
                files_audited=(),
            )

        # Sub-check (e) — reserved-set labels reject in mode='wasm'.
        # Operates on the HMAC-bound trace.declared_effects; iterating
        # record.effect instead would let an attacker mutate it post-signing
        # to hide reserved labels the verifier had attested to.
        for label in sorted(trace_declared_set):
            if label in _EFFECT_RESERVED_SET:
                return PluginResult(
                    ok=False,
                    reason_code="WASM_RESERVED_LABEL_REJECTED",
                    detail=(
                        f"record[{idx}]: HMAC-bound trace.declared_effects "
                        f"contains reserved-set label {label!r}; reserved "
                        "labels have no v0.2 enforcement story and must not "
                        "be declared under effect_enforcement_mode='wasm'. "
                        "Migrate to a locked label (net / fs / model / "
                        "llm_spend_usd / time_bound_ms) or stay on "
                        "mode='advisory' (locale_bound is deferred at v0.2 "
                        "when combined with net/fs — see "
                        "WASM_LOCALE_BOUND_DEFERRED)"
                    ),
                    files_audited=(),
                )

        # locale_bound is DEFERRED at v0.2 when combined with host-call
        # effects. The generic host stub in wasm_runner.py does NOT inspect
        # call arguments, so a record declaring {"net":[], "locale_bound":[]}
        # would have its network calls unconstrained by locale despite the
        # declaration.
        # Honest v0.2 behavior — declaring locale_bound alongside any
        # host-call effect (`net`, `fs`) rejects with the dedicated
        # reason code WASM_LOCALE_BOUND_DEFERRED. Declaring locale_bound
        # alone, or with non-host-call effects only (`model`,
        # `llm_spend_usd`, `time_bound_ms`), is a no-op and admitted.
        # Removed when v0.3 wires effect-specific host shims with
        # locale-header inspection.
        if "locale_bound" in trace_declared_set:
            host_call_effects = trace_declared_set & {"net", "fs"}
            if host_call_effects:
                return PluginResult(
                    ok=False,
                    reason_code="WASM_LOCALE_BOUND_DEFERRED",
                    detail=(
                        f"record[{idx}]: HMAC-bound trace.declared_effects "
                        f"declares 'locale_bound' alongside host-call "
                        f"effect(s) {sorted(host_call_effects)}; v0.2 "
                        "cannot enforce locale-header restrictions on "
                        "host calls (the generic host stub does not "
                        "inspect arguments). Either drop 'locale_bound' "
                        "(it has no v0.2 effect on these calls anyway) or "
                        "drop the host-call effects. v0.3 will land "
                        "effect-specific host shims with header inspection"
                    ),
                    files_audited=(),
                )

        # Sub-check (f) — observed_imports ⊆ admitted-by-declared-effects.
        # Effect-containment soundness from the effect calculus: every observed
        # import must be reverse-mappable to a label that the dispatcher
        # actually declared on this record. Source of `declared_effects` is
        # the HMAC-bound trace.declared_effects.
        # `verify_execution_trace_signature` already enforces that
        # observed_imports is a list (returns False if absent or non-list), so
        # the "absent field treated as empty list" case is unreachable in
        # practice. The invariant is made explicit here for defense-in-depth
        # and contract clarity: require observed_imports as a present-and-list
        # field, never default-to-empty. Same discipline applied to
        # declared_effects (which sub-check (a)/(d) already typed-check via
        # trace_declared_raw).
        declared_effects = sorted(trace_declared_set)
        if "observed_imports" not in trace:
            return PluginResult(
                ok=False,
                reason_code="WASM_EFFECT_DIVERGENCE",
                detail=(
                    f"record[{idx}]: execution_trace.observed_imports is "
                    "absent — required field; under v0.2 a verifier-signed "
                    "trace MUST carry the observed_imports list (even if "
                    "empty)"
                ),
                files_audited=(),
            )
        observed = trace.get("observed_imports")
        if not isinstance(observed, list):
            return PluginResult(
                ok=False,
                reason_code="WASM_EFFECT_DIVERGENCE",
                detail=(
                    f"record[{idx}]: execution_trace.observed_imports is not a "
                    f"list (got {type(observed).__name__})"
                ),
                files_audited=(),
            )
        for imp in observed:
            if not isinstance(imp, str):
                return PluginResult(
                    ok=False,
                    reason_code="WASM_EFFECT_DIVERGENCE",
                    detail=(
                        f"record[{idx}]: observed_imports entry is not a str ({imp!r})"
                    ),
                    files_audited=(),
                )
            admitted_label = reverse_map_import(imp)
            if admitted_label is None:
                return PluginResult(
                    ok=False,
                    reason_code="WASM_EFFECT_DIVERGENCE",
                    detail=(
                        f"record[{idx}]: observed import {imp!r} is not "
                        "reverse-mappable to any v0.2 effect label — the "
                        "import is outside the entire substrate vocabulary"
                    ),
                    files_audited=(),
                )
            if admitted_label not in declared_effects:
                return PluginResult(
                    ok=False,
                    reason_code="WASM_EFFECT_DIVERGENCE",
                    detail=(
                        f"record[{idx}]: observed import {imp!r} is admitted "
                        f"by effect label {admitted_label!r} which is NOT "
                        f"declared on this record (declared_effects="
                        f"{sorted(declared_effects)}); declared effects must "
                        "bound observed effects (effect-containment soundness)"
                    ),
                    files_audited=(),
                )
            if not label_admits_import(admitted_label, imp):
                # Defense in depth — reverse_map said admitted_label
                # admits imp, but label_admits_import disagrees. Should
                # never happen if the maps are consistent.
                return PluginResult(
                    ok=False,
                    reason_code="WASM_EFFECT_DIVERGENCE",
                    detail=(
                        f"record[{idx}]: vocabulary internal-consistency "
                        f"check failed for import {imp!r} / label "
                        f"{admitted_label!r}"
                    ),
                    files_audited=(),
                )

        # Sub-check (g) — the trace must report a clean run. v0.2 admits
        # only return_status='ok' under mode='wasm' (a trapped run means
        # the dispatcher's declared resources weren't enough; bundles
        # claiming WASM enforcement should not ship trapped traces).
        ret_status = trace.get("return_status")
        if ret_status != "ok":
            return PluginResult(
                ok=False,
                reason_code="WASM_RESOURCE_LIMIT_EXCEEDED",
                detail=(
                    f"record[{idx}]: execution_trace.return_status="
                    f"{ret_status!r} indicates the WASM run did not complete "
                    "cleanly; under effect_enforcement_mode='wasm' only "
                    "'ok' is admitted at v0.2 — trapped runs indicate the "
                    "dispatcher's resource declarations were insufficient"
                ),
                files_audited=(),
            )

        return None


register_typed_check("dispatch_record_wellformed")
