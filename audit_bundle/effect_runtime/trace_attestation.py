"""trace_attestation — verifier-set discipline for the WASM execution trace.

LOAD-BEARING INVARIANT (held across V15 + the C15-v0.2 contract):
  Only `sign_execution_trace` is allowed to write `execution_trace.
  verifier_signature`. Every other code path that wants to record a
  WASM execution trace MUST go through here. The C15 plugin enforces
  this by rejecting unsigned traces under mode='wasm' as
  WASM_TRACE_MISSING / WASM_TRACE_SIGNATURE_INVALID (mirrors V16's
  proof.discharge_status verifier-set discipline + V14's stamp_upgrade
  signing path).

Signature scheme (v0.2 — applies the V14 panel-review BUG 5 / BUG 3 / BUG 8
fixes from 2026-05-03 by construction):

  HMAC-SHA256 over the canonical-bytes JSON of:
    {"_kind": "execution_trace.v0.2",         # BUG 5: domain-separation tag
     "bundle_id": "<id>",                      # BUG 3: caller-supplied authoritative
     "record_idx": <int>,                      # BUG 3 + BUG 8: int-only, no bool
     "wasm_module_sha256": "<hex>",            # binds sig to specific bytecode
     "declared_effects": ["..."],              # sorted list of effect labels
     "observed_imports": ["..."],              # sorted list of admitted imports
     "fuel_consumed": <int>,
     "max_memory_bytes": <int>,
     "return_status": "<status>",
     "verifier_id": "<id>",
     "timestamp_utc": "<iso8601>"}

  The `_kind` tag prevents cross-protocol forgery (a V14 stamp-upgrade
  payload and a V15 execution-trace payload cannot canonical-bytes
  collide regardless of payload-schema evolution). `bundle_id` and
  `record_idx` are MANDATORY caller-supplied — verify_execution_trace_
  signature explicitly rejects None / bool subclass-of-int (Python's
  isinstance(True, int) trap; without the check, `record_idx=True`
  would silently sign for record_idx=1).

  Signed under a verifier-secret key (reuses VerifierSigningKey from
  audit_bundle.discharge.verifier_signing — V15 does NOT mint a parallel
  key class). Deployments that wire V16 (refinement discharge) for free
  inherit a verifier key pair for V15.

Canonical-bytes format: JSON with sort_keys=True, separators=(',',':'),
ensure_ascii=False (mirrors discharge/verifier_signing.py).

v1.0 will replace HMAC with Ed25519 detached signatures + a verifier-key
trust root. The HMAC layer at v0.2 is honest about its limit: a leaked
key allows trace forgery. Production deployments rotate the secret
quarterly per SOC 2 controls.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re

from audit_bundle.discharge.verifier_signing import (
    VerifierSigningKey,
)


# Re-export under a V15-flavoured name so V15 callers can use a typed
# alias without crossing the discharge/ namespace. V0.2 uses the same
# underlying key envelope; v1.0 may split if Ed25519 introduces per-
# stream key types.
ExecutionTraceVerifierKey = VerifierSigningKey


# Domain-separation tag for the trace HMAC payload. Prevents cross-
# protocol forgery (V14 stamp-upgrade payload bytes cannot collide with
# V15 execution-trace payload bytes regardless of schema evolution).
EXECUTION_TRACE_PAYLOAD_KIND: str = "execution_trace.v0.2"


# Allowed values for execution_trace.return_status. "ok" means the
# guest returned without trapping; "trapped:<reason>" encodes the
# typed trap reason that came out of the sandbox runtime.
_RETURN_STATUS_OK: str = "ok"
_RETURN_STATUS_TRAP_PREFIX: str = "trapped:"


# Hex regex (mirrors discharge/verifier_signing.py BUG 6 fix). Used to
# validate `wasm_module_sha256` at signing time.
_SHA256_RE: re.Pattern = re.compile(r"^[0-9a-fA-F]{64}$")


# Cumulative-pre-soak Patch 7 (Gate 1, 2026-05-04): the docstring above
# claims execution_trace timestamp_utc is enforced as ISO-8601, but
# pre-fix sign / verify only checked for non-empty string. Now we
# enforce a strict subset: ISO-8601 calendar date + 'T' + 24-hour time
# (with optional fractional seconds) + UTC marker (`Z` suffix or
# `+00:00` offset; never local time). This matches the grammar that
# `_now_iso8601_utc()` in discharge/verifier_signing.py emits, so all
# auto-generated timestamps remain valid; only adversarially-crafted
# strings (local time, non-UTC offset like `-08:00`, naive timestamps
# without a UTC marker, compact-offset forms like `+0000`) are
# rejected. Fractional seconds are admitted (the regex's `(?:\.\d+)?`
# group). Round-2 LOW fix (Patch 13, 2026-05-04): aligned this comment
# with the regex — the pre-Patch-13 comment incorrectly claimed
# fractional-second strings were rejected. The signing path raises
# TraceSigningError on a malformed timestamp; the verify path returns
# False (never raises).
_ISO8601_UTC_RE: re.Pattern = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)$"
)


def _is_iso8601_utc(value) -> bool:
    """True iff `value` is a string matching the strict ISO-8601 UTC
    grammar accepted by sign_execution_trace + verify_execution_trace_
    signature. Used by both paths so they agree on what 'malformed'
    means.
    """
    if not isinstance(value, str) or not value:
        return False
    return bool(_ISO8601_UTC_RE.match(value))


class TraceSigningError(Exception):
    """Raised by sign_execution_trace on shape / invariant violation
    (missing field, malformed timestamp, non-hex module SHA, bool
    record_idx, etc.). Verify-side never raises — verify_execution_
    trace_signature returns False on any defect."""


# ---------------------------------------------------------------------------
# Canonical-bytes payload
# ---------------------------------------------------------------------------


_TRACE_PAYLOAD_KEYS: tuple[str, ...] = (
    "_kind",
    "bundle_id",
    "record_idx",
    "wasm_module_sha256",
    "declared_effects",
    "observed_imports",
    "fuel_consumed",
    "max_memory_bytes",
    "return_status",
    "verifier_id",
    "timestamp_utc",
)


def _canonical_bytes(obj) -> bytes:
    """Mirror of discharge/verifier_signing.py::_canonical_bytes —
    JSON sort_keys=True, separators=(',',':'), ensure_ascii=False."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _build_trace_payload(
    *,
    bundle_id: str,
    record_idx: int,
    wasm_module_sha256: str,
    declared_effects: list[str],
    observed_imports: list[str],
    fuel_consumed: int,
    max_memory_bytes: int,
    return_status: str,
    verifier_id: str,
    timestamp_utc: str,
) -> bytes:
    """Build the HMAC payload bytes. Caller is responsible for shape
    validation; this function does not check (the public sign /verify
    helpers do)."""
    payload = {
        "_kind": EXECUTION_TRACE_PAYLOAD_KIND,
        "bundle_id": bundle_id,
        "record_idx": record_idx,
        "wasm_module_sha256": wasm_module_sha256,
        # Sort lists so that an attacker can't forge a payload by
        # reordering — the canonical-bytes form is order-stable.
        "declared_effects": sorted(declared_effects),
        "observed_imports": sorted(observed_imports),
        "fuel_consumed": fuel_consumed,
        "max_memory_bytes": max_memory_bytes,
        "return_status": return_status,
        "verifier_id": verifier_id,
        "timestamp_utc": timestamp_utc,
    }
    return _canonical_bytes(payload)


def _hmac_hex(key: ExecutionTraceVerifierKey, payload: bytes) -> str:
    return hmac.new(key.secret, payload, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# sign_execution_trace — sole writer of execution_trace.verifier_signature
# ---------------------------------------------------------------------------


def sign_execution_trace(
    record: dict,
    *,
    key: ExecutionTraceVerifierKey,
    wasm_module_sha256: str,
    # Cumulative-pre-soak Patch 13 (Gate 1, 2026-05-04): broaden the
    # type hint to match the runtime check (isinstance(..., (list, tuple))).
    # Tuples are deduped + sorted to a list before signing so the canonical
    # bytes are unaffected; the prior list[str]-only hint surprised callers
    # that built immutable tuples.
    declared_effects: list[str] | tuple[str, ...],
    observed_imports: list[str] | tuple[str, ...],
    fuel_consumed: int,
    max_memory_bytes: int,
    return_status: str,
    bundle_id: str,
    record_idx: int,
    timestamp_utc: str,
) -> dict:
    """Attach a verifier-signed `execution_trace` block to `record` and
    return the updated record (in-place; the input dict is mutated and
    also returned for chaining).

    Raises TraceSigningError on any shape / invariant violation. Never
    silently truncates input; never falls back to caller-controlled
    defaults for security-critical fields.

    Mandatory caller-supplied authoritative bindings:
      - bundle_id      (caller reads from manifest.bundle_id)
      - record_idx     (caller reads from the iteration index)
      - wasm_module_sha256  (caller computes from the wasm bytes)
    These are verifier-set, never dispatcher-trusted.
    """
    if not isinstance(record, dict):
        raise TraceSigningError(
            f"record must be a dict, got {type(record).__name__}"
        )
    if not isinstance(bundle_id, str) or not bundle_id:
        raise TraceSigningError(
            "bundle_id must be a non-empty string (caller-supplied "
            "authoritative — never the trace's self-report)"
        )
    # BUG 8 lesson: isinstance(True, int) is True; exclude bool explicitly.
    if isinstance(record_idx, bool) or not isinstance(record_idx, int) \
            or record_idx < 0:
        raise TraceSigningError(
            f"record_idx must be a non-negative int (bool excluded), "
            f"got {record_idx!r} of type {type(record_idx).__name__}"
        )
    if not isinstance(wasm_module_sha256, str) \
            or not _SHA256_RE.match(wasm_module_sha256):
        raise TraceSigningError(
            f"wasm_module_sha256={wasm_module_sha256!r} is not a "
            "64-character hex SHA-256"
        )
    if not isinstance(declared_effects, (list, tuple)):
        raise TraceSigningError(
            f"declared_effects must be a list, got "
            f"{type(declared_effects).__name__}"
        )
    if not isinstance(observed_imports, (list, tuple)):
        raise TraceSigningError(
            f"observed_imports must be a list, got "
            f"{type(observed_imports).__name__}"
        )
    for label in declared_effects:
        if not isinstance(label, str):
            raise TraceSigningError(
                f"declared_effects entries must be str, got "
                f"{type(label).__name__} ({label!r})"
            )
    for imp in observed_imports:
        if not isinstance(imp, str):
            raise TraceSigningError(
                f"observed_imports entries must be str, got "
                f"{type(imp).__name__} ({imp!r})"
            )
    # Same bool-vs-int trap on the resource counters.
    if isinstance(fuel_consumed, bool) or not isinstance(fuel_consumed, int) \
            or fuel_consumed < 0:
        raise TraceSigningError(
            f"fuel_consumed must be a non-negative int, got {fuel_consumed!r}"
        )
    if isinstance(max_memory_bytes, bool) \
            or not isinstance(max_memory_bytes, int) \
            or max_memory_bytes < 0:
        raise TraceSigningError(
            f"max_memory_bytes must be a non-negative int, got "
            f"{max_memory_bytes!r}"
        )
    if not isinstance(return_status, str) or not return_status:
        raise TraceSigningError(
            f"return_status must be a non-empty string, got {return_status!r}"
        )
    if return_status != _RETURN_STATUS_OK \
            and not return_status.startswith(_RETURN_STATUS_TRAP_PREFIX):
        raise TraceSigningError(
            f"return_status must be {_RETURN_STATUS_OK!r} or "
            f"{_RETURN_STATUS_TRAP_PREFIX!r}<reason>, got {return_status!r}"
        )
    # Cumulative-pre-soak Patch 7 (Gate 1, 2026-05-04): enforce strict
    # ISO-8601 UTC grammar (calendar date + 'T' + 24-hour time + Z or
    # +00:00). The pre-fix non-empty check let local-time strings like
    # "2026-05-04 10:00 PST" pass and silently bind a non-UTC time into
    # the HMAC payload, undermining the auditability claim that traces
    # describe their own absolute wall-clock provenance.
    if not _is_iso8601_utc(timestamp_utc):
        raise TraceSigningError(
            f"timestamp_utc={timestamp_utc!r} is not a strict ISO-8601 UTC "
            "string — must match YYYY-MM-DDTHH:MM:SS[.fff](Z|+00:00)"
        )

    # Round-2 Sonnet BUG 1 fix (panel review 2026-05-03 round 2): dedup
    # before sorting so duplicate entries (which the canonical-bytes
    # sort+separators path would otherwise persist) don't produce an
    # auditor-visible inconsistency. The HMAC stays sound either way
    # (the signed bytes match what's persisted), but a clean canonical
    # form has no duplicates.
    declared_sorted = sorted(set(declared_effects))
    observed_sorted = sorted(set(observed_imports))

    payload = _build_trace_payload(
        bundle_id=bundle_id,
        record_idx=record_idx,
        wasm_module_sha256=wasm_module_sha256,
        declared_effects=declared_sorted,
        observed_imports=observed_sorted,
        fuel_consumed=fuel_consumed,
        max_memory_bytes=max_memory_bytes,
        return_status=return_status,
        verifier_id=key.verifier_id,
        timestamp_utc=timestamp_utc,
    )
    mac = _hmac_hex(key, payload)

    record["execution_trace"] = {
        "bundle_id": bundle_id,
        "record_idx": record_idx,
        "wasm_module_sha256": wasm_module_sha256,
        "declared_effects": declared_sorted,
        "observed_imports": observed_sorted,
        "fuel_consumed": fuel_consumed,
        "max_memory_bytes": max_memory_bytes,
        "return_status": return_status,
        "verifier_signature": {
            "algorithm": "hmac-sha256",
            "verifier_id": key.verifier_id,
            "timestamp_utc": timestamp_utc,
            "mac": mac,
        },
    }
    return record


# ---------------------------------------------------------------------------
# verify_execution_trace_signature — never raises
# ---------------------------------------------------------------------------


def verify_execution_trace_signature(
    record: dict,
    *,
    key: ExecutionTraceVerifierKey,
    bundle_id: str,
    record_idx: int,
) -> bool:
    """Re-verify the HMAC on record['execution_trace']['verifier_
    signature'] under caller-supplied authoritative bindings.

    BUG 3 lesson: bundle_id and record_idx are MANDATORY caller-supplied.
    A previous implementation that fell back to the trace's self-reported
    values would degrade to attacker-controlled bindings (cross-bundle
    replay surface). The fallback is removed by construction here.

    Returns False on any defect (missing field, malformed dict, wrong
    algorithm, MAC mismatch, body-vs-payload inconsistency). Never raises.
    """
    if not isinstance(record, dict):
        return False
    trace = record.get("execution_trace")
    if not isinstance(trace, dict):
        return False
    sig = trace.get("verifier_signature")
    if not isinstance(sig, dict):
        return False
    if sig.get("algorithm") != "hmac-sha256":
        return False
    if sig.get("verifier_id") != key.verifier_id:
        return False
    sig_mac = sig.get("mac")
    if not isinstance(sig_mac, str) or not _SHA256_RE.match(sig_mac):
        return False

    # Authoritative caller-supplied bindings — no fallback to trace self-report.
    if not isinstance(bundle_id, str) or not bundle_id:
        return False
    if isinstance(record_idx, bool) or not isinstance(record_idx, int) \
            or record_idx < 0:
        return False

    # V15 BUG 8 fix (panel review 2026-05-03): trace body must
    # MANDATORILY carry bundle_id and record_idx so the trace is
    # self-authenticating for an auditor reading the body alone. Pre-
    # fix, `if trace_bundle_id is not None` skipped the consistency
    # check whenever the field was absent — the HMAC still caught the
    # cryptographic mismatch, but the trace body could be persisted
    # without describing its bundle/record context. Now the consistency
    # check fires unconditionally; missing or wrong-type fields are
    # treated as a forgery signal.
    trace_bundle_id = trace.get("bundle_id")
    if not isinstance(trace_bundle_id, str) or not trace_bundle_id:
        return False
    if trace_bundle_id != bundle_id:
        return False
    trace_record_idx = trace.get("record_idx")
    if isinstance(trace_record_idx, bool) \
            or not isinstance(trace_record_idx, int) \
            or trace_record_idx < 0:
        return False
    if trace_record_idx != record_idx:
        return False

    # Pull authoritative body fields (these are part of the signed payload).
    wasm_module_sha256 = trace.get("wasm_module_sha256")
    if not isinstance(wasm_module_sha256, str) \
            or not _SHA256_RE.match(wasm_module_sha256):
        return False
    declared_effects = trace.get("declared_effects")
    observed_imports = trace.get("observed_imports")
    if not isinstance(declared_effects, list) \
            or not isinstance(observed_imports, list):
        return False
    for label in declared_effects:
        if not isinstance(label, str):
            return False
    for imp in observed_imports:
        if not isinstance(imp, str):
            return False
    fuel_consumed = trace.get("fuel_consumed")
    max_memory_bytes = trace.get("max_memory_bytes")
    if isinstance(fuel_consumed, bool) \
            or not isinstance(fuel_consumed, int) \
            or fuel_consumed < 0:
        return False
    if isinstance(max_memory_bytes, bool) \
            or not isinstance(max_memory_bytes, int) \
            or max_memory_bytes < 0:
        return False
    return_status = trace.get("return_status")
    if not isinstance(return_status, str) or not return_status:
        return False
    if return_status != _RETURN_STATUS_OK \
            and not return_status.startswith(_RETURN_STATUS_TRAP_PREFIX):
        return False
    timestamp_utc = sig.get("timestamp_utc")
    # Cumulative-pre-soak Patch 7 (Gate 1, 2026-05-04): mirror the strict
    # ISO-8601 UTC check from sign_execution_trace; a sig whose
    # timestamp_utc is not a strict UTC string fails verification (never
    # raises) so adversarial-path callers yield a clean rejection.
    if not _is_iso8601_utc(timestamp_utc):
        return False

    expected_payload = _build_trace_payload(
        bundle_id=bundle_id,
        record_idx=record_idx,
        wasm_module_sha256=wasm_module_sha256,
        declared_effects=declared_effects,
        observed_imports=observed_imports,
        fuel_consumed=fuel_consumed,
        max_memory_bytes=max_memory_bytes,
        return_status=return_status,
        verifier_id=key.verifier_id,
        timestamp_utc=timestamp_utc,
    )
    expected_mac = _hmac_hex(key, expected_payload)
    # Constant-time compare — defense against MAC-comparison timing oracles.
    return hmac.compare_digest(expected_mac, sig_mac)
