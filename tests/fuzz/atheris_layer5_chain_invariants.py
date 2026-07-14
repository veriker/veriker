"""Atheris-driven Layer 5 chain-validator regression fuzzer.

Layers 1-4 cover single-envelope attacks (byte fuzz / catastrophic-tier / CBOR
structure / cross-protocol differential). Layer 5 climbs the cascade to
**multi-event chain integrity**: the Layer-A counter chain that binds events
together via monotonic counters + hash linkage + Merkle accumulation.

`verify_bundle_layer_a` enforces (per the SCOPING doc + verified via
`_verify_layer_a_pipeline`):
  - Pass 1: event_id uniqueness across all events; monotonic_counter strict
            +1 increment; counter_log_index == monotonic_counter
  - Pass 2: prev_event_hash linkage (each event's prev_event_hash equals
            sha256(deterministic_cbor(prev event)))
  - Per-event: event_kind in V0_3_EVENT_KINDS allowlist
  - Per-event: HMAC signature over canonical_event_preimage verifies under
               the host's derived k_event (HKDF from per-host IKM)

This harness runs structure-aware mutations on the last event of a canonical
2-event chain, re-signs the mutated event correctly so the per-event signature
still passes, then runs verify_bundle_layer_a. The oracle is one-sided: every
mutation in `_OPS` violates a chain-level invariant the substrate CLAIMS to
enforce, so verify MUST raise LayerAVerificationError. If it returns
successfully, that's a regression in the chain validator.

Mutations:

  counter_skip            — monotonic_counter += K (K from fdp; expect
                            COUNTER_GAP_DETECTED)
  counter_equal           — monotonic_counter = events[0].monotonic_counter
                            (same as prior; expect COUNTER_GAP_DETECTED)
  counter_zero_or_neg     — monotonic_counter ∈ [-100, 0] (expect COUNTER_GAP
                            since prior + 1 != target)
  counter_log_index_drift — counter_log_index ≠ monotonic_counter
                            (expect COUNTER_GAP_DETECTED via the second branch
                            of the pass-1 check)
  prev_event_hash_random  — prev_event_hash := fdp.ConsumeBytes(32) (expect
                            HASH_CHAIN_BROKEN)
  event_id_dup            — event_id := events[0].event_id (expect
                            EVENT_ID_DUPLICATE)
  event_kind_invalid      — event_kind := fdp-chosen string ∉ V0_3_EVENT_KINDS
                            (expect EVENT_KIND_UNKNOWN or CDDL_VALIDATION_FAILED)

Each mutation re-signs the event under the new preimage (so per-event sig
passes) and re-builds the bundle Merkle root via seal_of1_manifest_anchor
(so the recomputed root matches the carried root). Only the chain-level
invariant is broken; the test is isolated to the chain validator.

Oracle:
  - verify returns successfully → REGRESSION (raise AssertionError, atheris
    saves the artifact)
  - verify raises LayerAVerificationError (typed) → expected
  - verify raises anything else → §C9 §contract violation (raise
    AssertionError; atheris saves)

Pinned context: the canonical chain is built ONCE at module load using
pycose-real SCITT receipts and HKDF-derived k_event. Each iteration
deep-copies the canonical events list before mutating.

Run:
    .venv/bin/python tests/fuzz/atheris_layer5_chain_invariants.py \\
        -atheris_runs=10000000 \\
        -print_final_stats=1 \\
        -artifact_prefix=tests/fuzz/crashes/layer5_chain_invariants/
"""

from __future__ import annotations

import copy
import hashlib
import sys

import atheris

with atheris.instrument_imports():
    from pycose.algorithms import EdDSA
    from pycose.headers import KID, Algorithm
    from pycose.keys import OKPKey
    from pycose.keys.curves import Ed25519
    from pycose.keys.keyparam import KpKid
    from pycose.messages import Sign1Message

    from audit_bundle.bundle_manifest import V0_3_EVENT_KINDS
    from audit_bundle.extensions.c19.layer_a_counter import (
        LayerAVerificationError,
        canonical_event_preimage,
        compute_event_hash,
        compute_event_signature,
        derive_event_signature_key,
        deterministic_cbor_encode,
        seal_of1_manifest_anchor,
        verify_bundle_layer_a,
    )


# ---------------------------------------------------------------------------
# Pinned context — fixed at module load.
# ---------------------------------------------------------------------------
_HOST = "host-A"
_BUNDLE_ID = "bundle-layer5-canonical"
_IKM = hashlib.sha256(b"host-A-ikm-layer5").digest()
_TS_KID = b"layer5-ts-key-1"
_K_EVENT = derive_event_signature_key(_IKM)

_cose_key = OKPKey.generate_key(crv=Ed25519, optional_params={KpKid: _TS_KID})
_PINNED_TS_VERIFY = _cose_key


def _make_scitt_receipt(payload_bytes: bytes) -> bytes:
    msg = Sign1Message(
        phdr={Algorithm: EdDSA, KID: _TS_KID}, uhdr={}, payload=payload_bytes
    )
    msg.key = _cose_key
    return msg.encode()


def _build_event(*, monotonic_counter: int, prev_event_hash: bytes, payload: dict) -> dict:
    payload_bytes = deterministic_cbor_encode(payload)
    payload_hash = hashlib.sha256(payload_bytes).digest()
    receipt = _make_scitt_receipt(payload_bytes)
    event_id = f"ev-{monotonic_counter}"
    preimage = canonical_event_preimage(
        host_id=_HOST,
        event_id=event_id,
        prev_event_hash=prev_event_hash,
        bundle_id=_BUNDLE_ID,
        monotonic_counter=monotonic_counter,
        payload_hash=payload_hash,
    )
    sig = compute_event_signature(_K_EVENT, preimage)
    return {
        "event_id": event_id,
        "prev_event_id": None,
        "prev_event_hash": prev_event_hash.hex(),
        "host_id": _HOST,
        "event_kind": "dispatch_record",
        "monotonic_counter": monotonic_counter,
        "counter_log_index": monotonic_counter,
        "scitt_statement_id": payload_hash.hex(),
        "scitt_statement_content_sha256": payload_hash.hex(),
        "scitt_inclusion_proof": receipt.hex(),
        "payload_hash": payload_hash.hex(),
        "event_signature": {"key_id": "k_event_A", "sig": sig.hex()},
        "causal_dependencies": [],
    }


def _normalize_event_for_leaf(ev: dict) -> dict:
    """Convert an exported event dict (hex-string fields) into the BYTES-keyed
    normalized form the substrate verifier hashes for the Merkle leaf. Mirrors
    `_verify_layer_a_pipeline`'s normalization at `layer_a_counter.py:1481-1501`.
    """
    return {
        "event_id": ev["event_id"],
        "prev_event_id": ev["prev_event_id"],
        "prev_event_hash": bytes.fromhex(ev["prev_event_hash"]),
        "monotonic_counter": ev["monotonic_counter"],
        "counter_log_index": ev["counter_log_index"],
        "event_kind": ev["event_kind"],
        "payload_hash": bytes.fromhex(ev["payload_hash"]),
    }


def _event_leaf_hash(ev: dict) -> bytes:
    return compute_event_hash(deterministic_cbor_encode(_normalize_event_for_leaf(ev)))


def _build_canonical_chain() -> list[dict]:
    ev1 = _build_event(
        monotonic_counter=1,
        prev_event_hash=b"\x00" * 32,
        payload={"step": "first"},
    )
    ev1_hash = _event_leaf_hash(ev1)
    ev2 = _build_event(
        monotonic_counter=2,
        prev_event_hash=ev1_hash,
        payload={"step": "second"},
    )
    return [ev1, ev2]


_CANONICAL_EVENTS = _build_canonical_chain()

# Precomputed leaf hashes of the canonical chain. Used by `_op_prev_hash_random`
# to detect libfuzzer's CMP-operator pulling the legitimate hash out of the
# verifier's `ev["prev_event_hash"] != prev_hash` comparison and feeding it
# back as "random" bytes (which produces a false-positive regression finding —
# the "random" hash is actually correct, so verify legitimately accepts).
_CANONICAL_EVENT_LEAF_HASHES = [
    compute_event_hash(deterministic_cbor_encode(_normalize_event_for_leaf(ev)))
    for ev in _CANONICAL_EVENTS
]


def _build_layer_a(events: list[dict]) -> dict:
    """Re-seal the bundle: recompute event_dag_merkle_root + manifest_header_leaf
    from the current events list. Called after every mutation so the carried
    root matches the mutated chain (isolating the test to chain-validator
    invariants, NOT MERKLE_ROOT_MISMATCH from a stale root)."""
    event_hashes = [_event_leaf_hash(ev) for ev in events]
    sealed = seal_of1_manifest_anchor(
        event_hashes=event_hashes,
        bundle_id=_BUNDLE_ID,
        created_at="2026-05-26T00:00:00Z",
        dispatch_records=[],
    )
    return {
        "bundle_id": _BUNDLE_ID,
        "protocol_version": "v0.3",
        "scitt_log_id": "log-1",
        "assurance_profile": "production-standard",
        "chain_height": len(events),
        "events": events,
        "event_dag_merkle_root": sealed["event_dag_merkle_root"],
        "manifest_header_merkle_leaf": sealed["manifest_header_merkle_leaf"],
    }


# Module-load sanity: the unmutated canonical chain MUST verify green. If this
# raises, the harness construction is wrong and no run is meaningful.
def _sanity_check_canonical_verifies() -> None:
    la = _build_layer_a(copy.deepcopy(_CANONICAL_EVENTS))
    verify_bundle_layer_a(
        bundle_bytes=deterministic_cbor_encode(la),
        layer_a=la,
        pinned_ts_key_ids=frozenset({_TS_KID}),
        pinned_ts_verifying_keys={_TS_KID: _PINNED_TS_VERIFY},
        pinned_issuer_keys={_HOST: _IKM},
    )


_sanity_check_canonical_verifies()


# ---------------------------------------------------------------------------
# Verdict shim — normalise verify_bundle_layer_a to (verdict, code) shape.
# Untyped exceptions raise AssertionError so atheris saves them as §C9 findings.
# ---------------------------------------------------------------------------
def _verify(layer_a: dict) -> tuple[str, str]:
    try:
        verify_bundle_layer_a(
            bundle_bytes=deterministic_cbor_encode(layer_a),
            layer_a=layer_a,
            pinned_ts_key_ids=frozenset({_TS_KID}),
            pinned_ts_verifying_keys={_TS_KID: _PINNED_TS_VERIFY},
            pinned_issuer_keys={_HOST: _IKM},
        )
    except LayerAVerificationError as exc:
        code = getattr(exc, "code", None)
        return "FAIL", str(getattr(code, "value", code))
    except Exception as exc:
        raise AssertionError(
            f"VERIFY-RAISED-UNTYPED ({type(exc).__name__}): {exc!r}"
        ) from exc
    return "PASS", "ok"


def _resign(ev: dict) -> None:
    """Recompute and write back the per-event signature after any mutation that
    touched a canonical_event_preimage field (host_id, event_id, prev_event_hash,
    monotonic_counter, payload_hash). Bundle_id is fixed.
    """
    preimage = canonical_event_preimage(
        host_id=ev["host_id"],
        event_id=ev["event_id"],
        prev_event_hash=bytes.fromhex(ev["prev_event_hash"]),
        bundle_id=_BUNDLE_ID,
        monotonic_counter=ev["monotonic_counter"],
        payload_hash=bytes.fromhex(ev["payload_hash"]),
    )
    sig = compute_event_signature(_K_EVENT, preimage)
    ev["event_signature"]["sig"] = sig.hex()


# ---------------------------------------------------------------------------
# Mutation operations. Each takes (events, fdp) and mutates events[1] (the
# last event in the 2-event chain) so no downstream propagation is needed.
# Each returns the op name for the AssertionError detail line.
# ---------------------------------------------------------------------------
def _op_counter_skip(events: list[dict], fdp: atheris.FuzzedDataProvider) -> str:
    delta = fdp.ConsumeIntInRange(2, 100)
    events[1]["monotonic_counter"] += delta
    events[1]["counter_log_index"] = events[1]["monotonic_counter"]
    _resign(events[1])
    return "counter_skip"


def _op_counter_equal(events: list[dict], fdp: atheris.FuzzedDataProvider) -> str:
    events[1]["monotonic_counter"] = events[0]["monotonic_counter"]
    events[1]["counter_log_index"] = events[1]["monotonic_counter"]
    _resign(events[1])
    return "counter_equal"


def _op_counter_zero_or_neg(
    events: list[dict], fdp: atheris.FuzzedDataProvider
) -> str:
    events[1]["monotonic_counter"] = fdp.ConsumeIntInRange(-100, 0)
    events[1]["counter_log_index"] = events[1]["monotonic_counter"]
    _resign(events[1])
    return "counter_zero_or_neg"


def _op_cli_drift(events: list[dict], fdp: atheris.FuzzedDataProvider) -> str:
    delta = fdp.ConsumeIntInRange(1, 100)
    if fdp.ConsumeBool():
        delta = -delta
    events[1]["counter_log_index"] = events[1]["monotonic_counter"] + delta
    _resign(events[1])
    return "counter_log_index_drift"


def _op_prev_hash_random(
    events: list[dict], fdp: atheris.FuzzedDataProvider
) -> str:
    raw = fdp.ConsumeBytes(32)
    if len(raw) < 32:
        raw = raw + b"\x00" * (32 - len(raw))
    raw = raw[:32]
    # CMP-leak guard: libfuzzer's CMP operator observes the verifier's
    # `ev["prev_event_hash"] != prev_hash` comparison and learns the legitimate
    # ev1_hash, then feeds it back as "random" bytes. The resulting mutation
    # is no-op (random == legitimate) and the substrate correctly accepts it
    # — a false-positive regression. Surfaced 2026-05-26 on iter ~3980 of the
    # first 10M Layer 5 run; documented as a Layer 5 harness-design pitfall.
    # Defense: if the "random" value collides with the canonical leaf hash,
    # flip every bit so the mutation is guaranteed to be a genuine miss.
    if raw == _CANONICAL_EVENT_LEAF_HASHES[0]:
        raw = bytes(b ^ 0xFF for b in raw)
    events[1]["prev_event_hash"] = raw.hex()
    _resign(events[1])
    return "prev_event_hash_random"


def _op_event_id_dup(events: list[dict], fdp: atheris.FuzzedDataProvider) -> str:
    events[1]["event_id"] = events[0]["event_id"]
    _resign(events[1])
    return "event_id_dup"


def _op_event_kind_invalid(
    events: list[dict], fdp: atheris.FuzzedDataProvider
) -> str:
    try:
        kind = fdp.ConsumeUnicodeNoSurrogates(20) or "INVALID-KIND"
    except Exception:
        kind = "INVALID-KIND"
    # Guarantee the kind is not in the allowlist (in case fdp picked a valid one).
    if kind in V0_3_EVENT_KINDS:
        kind = kind + "-mutated"
    events[1]["event_kind"] = kind
    _resign(events[1])
    return "event_kind_invalid"


_OPS = [
    _op_counter_skip,
    _op_counter_equal,
    _op_counter_zero_or_neg,
    _op_cli_drift,
    _op_prev_hash_random,
    _op_event_id_dup,
    _op_event_kind_invalid,
]


# ---------------------------------------------------------------------------
# Atheris entry point.
# ---------------------------------------------------------------------------
def test_one(data: bytes) -> None:
    if len(data) < 4:
        return
    fdp = atheris.FuzzedDataProvider(data)
    op_fn = _OPS[fdp.ConsumeIntInRange(0, len(_OPS) - 1)]

    events = copy.deepcopy(_CANONICAL_EVENTS)
    op_name = op_fn(events, fdp)
    layer_a = _build_layer_a(events)
    verdict, code = _verify(layer_a)

    if verdict == "PASS":
        # Every op in _OPS violates a chain-level invariant; verify MUST reject.
        raise AssertionError(
            f"CHAIN-INVARIANT-REGRESSION: op={op_name} verify=PASS "
            f"event[1]={events[1]!r} layer_a_root={layer_a['event_dag_merkle_root']!r}"
        )
    # verdict == "FAIL": expected. Code value is logged via libfuzzer's stderr
    # at coverage-growth events, not per-iter (too noisy at fuzz rates).


def main() -> None:
    atheris.Setup(sys.argv, test_one)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
