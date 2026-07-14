"""Atheris-driven Layer 4 cross-protocol differential.

Runs BOTH `verify_cross_host_authenticator_cose` and
`verify_emergency_offline_root_signature` against the SAME mutated COSE_Sign1
envelope. Both verifiers share the offline_root_cose_sig_structure encoder, the
same pinned Ed25519 alg (`-8`), and the same canonical Sig_structure
construction — cross-protocol separation rides ENTIRELY on the external_aad
parameter (`CROSS_HOST_COSE_DOMAIN_AAD` vs `OFFLINE_ROOT_COSE_DOMAIN_AAD`).

Layer 3's re-sign arm exercised this under 21.7M iter but only one verifier saw
each envelope — a gap on the offline-root side could not surface. This harness
verdicts both verifiers per iteration, so an envelope that satisfies BOTH AAD
contexts (the cross-protocol replay window the per-protocol tag is supposed to
close) is caught explicitly.

Oracle:

  - cross_host == PASS  AND  offline_root == PASS  → CROSS-PROTOCOL REPLAY,
        RAISE. A single envelope verified by two protocol roles means the
        domain-separation tag is not actually separating them. This is the
        primary finding class this harness is designed to surface.

  - exactly one PASS                                → expected (the AAD-pin is
        doing its job — the envelope is valid for one role and invalid for the
        other) → return silently.

  - both FAIL                                       → expected (malformed or
        non-matching envelope) → return silently.

  - either verifier raises a non-typed exception    → §C9 violation, RAISE
        (the harness wraps the raise as AssertionError so atheris saves the
        artifact). cross_host's contract is "never raise"; offline_root's
        contract is "only raise LayerAVerificationError".

Setup (fixed at module load):
  - Same pinned 32-byte Ed25519 seed as Layer 2/3/D1 + corpus differential
    (so envelopes minted in those harnesses replay cleanly into this oracle).
  - Same canonical preimage and AAD constants (re-imported from the modules
    under test — never hard-coded copies).
  - OfflineRootPolicy instantiated ONCE with the same public key pinned
    under a single key_id (`b"\\xab" * 32`, matching the existing inline
    regression test pattern).

The mutator is copied verbatim from `atheris_differential_pycose.py` (same
slot perturbations, same re-sign branches), with `_resign_over_chosen_inputs`
re-weighted: the OFFLINE_ROOT_COSE_DOMAIN_AAD re-sign branch is now selected
~3x more often than CROSS_HOST_COSE_DOMAIN_AAD — that is the dangerous
direction (envelope signed under offline-root AAD, then presented to the
cross-host verifier under cross-host AAD), and we want the fuzzer to spend
budget there.

Run:
    .venv/bin/python tests/fuzz/atheris_layer4_cross_protocol.py \\
        -atheris_runs=10000000 \\
        -print_final_stats=1 \\
        -artifact_prefix=tests/fuzz/crashes/layer4_cross_protocol/ \\
        tests/fuzz/corpus/cose_bundle_layer3/
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    import cbor2
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    from audit_bundle.extensions.c19.cross_host_peerreview import (
        CROSS_HOST_COSE_DOMAIN_AAD,
        sign_cross_host_authenticator_cose,
        verify_cross_host_authenticator_cose,
    )
    from audit_bundle.extensions.c19.layer_a_counter import (
        LayerAVerificationError,
    )
    from audit_bundle.extensions.c19.offline_root import (
        OFFLINE_ROOT_COSE_DOMAIN_AAD,
        OfflineRootPolicy,
        offline_root_cose_sig_structure,
        verify_emergency_offline_root_signature,
    )


# ---------------------------------------------------------------------------
# Pinned context — must match Layer 2/3 + D1 + corpus differential exactly.
# ---------------------------------------------------------------------------
_PRIV_SEED = bytes.fromhex(
    "00010203" "04050607" "08090a0b" "0c0d0e0f"
    "10111213" "14151617" "18191a1b" "1c1d1e1f"
)
_PRIV = Ed25519PrivateKey.from_private_bytes(_PRIV_SEED)
_PUB_RAW = _PRIV.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
_PREIMAGE = b"v-kernel layer-2 cose fuzz canonical preimage"

# Same key_id constant used by the existing inline regression test
# (test_cose_bundle_slot_safety.py:522). Picked there because the offline-root
# protocol just needs a key_id to be bound to a verifying key; the value is
# arbitrary as long as the policy mapping is consistent. Matching the existing
# test keeps regression-replay symmetric across the two harness families.
_KEY_ID = b"\xab" * 32

_POLICY = OfflineRootPolicy(
    pinned_offline_root_key_ids=frozenset({_KEY_ID}),
    pinned_offline_root_verifying_keys={_KEY_ID: _PUB_RAW},
)

_CANONICAL_COSE = sign_cross_host_authenticator_cose(
    private_key=_PRIV, preimage=_PREIMAGE
)
_CANONICAL_DECODED = cbor2.loads(_CANONICAL_COSE)
_CANONICAL_PROTECTED_BSTR = _CANONICAL_DECODED[0]
_CANONICAL_UNPROTECTED = _CANONICAL_DECODED[1]
_CANONICAL_PAYLOAD = _CANONICAL_DECODED[2]
_CANONICAL_SIG = _CANONICAL_DECODED[3]


# ---------------------------------------------------------------------------
# Verdict shims — normalise BOTH verifiers to the same (verdict, code) shape.
# cross_host returns (bool, code, detail); offline_root raises
# LayerAVerificationError on fail and returns None on pass.
# ---------------------------------------------------------------------------
def _cross_host_verdict(cose_bytes: bytes) -> tuple[str, str]:
    try:
        ok, code, _detail = verify_cross_host_authenticator_cose(
            public_key_raw=_PUB_RAW, preimage=_PREIMAGE, cose_bytes=cose_bytes
        )
    except Exception as exc:
        # §C9 fail-closed contract: verify must never raise. Re-raise so
        # atheris saves the input as a crash; this is itself a finding.
        raise AssertionError(
            f"VERIFY-RAISED-CROSS-HOST ({type(exc).__name__}): {exc!r} "
            f"cose_len={len(cose_bytes)} cose_hex={cose_bytes.hex()}"
        ) from exc
    return ("PASS" if ok else "FAIL"), code


def _offline_root_verdict(cose_bytes: bytes) -> tuple[str, str]:
    try:
        verify_emergency_offline_root_signature(
            rotation_preimage=_PREIMAGE,
            emergency_offline_root_signature=cose_bytes,
            offline_root_key_id=_KEY_ID,
            policy=_POLICY,
        )
    except LayerAVerificationError as exc:
        # Typed contract failure — expected for any envelope minted under the
        # cross-host AAD or otherwise non-matching. Normalise to FAIL + code.
        code = getattr(exc, "code", None)
        # exc.code is a ReasonCode enum; render to str for the oracle output.
        return "FAIL", str(code.value if hasattr(code, "value") else code)
    except Exception as exc:
        # ANY exception that is not LayerAVerificationError is itself a §C9
        # finding for this verifier (contract: only raise LayerAVerificationError).
        raise AssertionError(
            f"VERIFY-RAISED-OFFLINE-ROOT ({type(exc).__name__}): {exc!r} "
            f"cose_len={len(cose_bytes)} cose_hex={cose_bytes.hex()}"
        ) from exc
    return "PASS", "ok"


# ---------------------------------------------------------------------------
# Structure-aware mutator (copied from atheris_differential_pycose.py — same
# pinned key/preimage/AAD constants → identical mutation space). The only
# delta is `_resign_over_chosen_inputs` re-weighting the offline-root AAD
# branch so the cross-protocol replay window gets more budget per iteration.
# ---------------------------------------------------------------------------
def _safe_cbor_dumps(value) -> bytes | None:
    try:
        return cbor2.dumps(value)
    except Exception:
        return None


def _build_value(fdp: atheris.FuzzedDataProvider, depth: int = 0):
    kind = (
        fdp.ConsumeIntInRange(0, 3) if depth >= 3 else fdp.ConsumeIntInRange(0, 9)
    )
    if kind == 0:
        return None
    if kind == 1:
        return fdp.ConsumeIntInRange(-1 << 31, (1 << 31) - 1)
    if kind == 2:
        return fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 64))
    if kind == 3:
        try:
            return fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 32))
        except Exception:
            return ""
    if kind == 4:
        return fdp.ConsumeBool()
    if kind == 5:
        return [_build_value(fdp, depth + 1) for _ in range(fdp.ConsumeIntInRange(0, 4))]
    if kind == 6:
        d = {}
        for _ in range(fdp.ConsumeIntInRange(0, 4)):
            ktype = fdp.ConsumeIntInRange(0, 3)
            if ktype == 0:
                k = fdp.ConsumeIntInRange(-128, 128)
            elif ktype == 1:
                try:
                    k = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 8))
                except Exception:
                    k = ""
            elif ktype == 2:
                k = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 8))
            else:
                k = None
            d[k] = _build_value(fdp, depth + 1)
        return d
    if kind == 7:
        return fdp.ConsumeIntInRange(-(1 << 62), 1 << 62)
    if kind == 8:
        return fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 128))
    try:
        return fdp.ConsumeFloat()
    except Exception:
        return 0.0


def _mutate_protected_bstr(fdp: atheris.FuzzedDataProvider) -> bytes:
    op = fdp.ConsumeIntInRange(0, 9)
    if op == 0:
        encoded = _safe_cbor_dumps({1: fdp.ConsumeIntInRange(-32, 32)})
        return encoded if encoded is not None else b""
    if op == 1:
        encoded = _safe_cbor_dumps(
            {1: -8, fdp.ConsumeIntInRange(-16, 32): _build_value(fdp, 1)}
        )
        return encoded if encoded is not None else b""
    if op == 2:
        return bytes([0xA2, 0x01, 0x26, 0x01, 0x27])
    if op == 3:
        return bytes([0xBF, 0x01, 0x27, 0xFF])
    if op == 4:
        choices = ["EdDSA", b"EdDSA", None, [-8]]
        encoded = _safe_cbor_dumps({1: choices[fdp.ConsumeIntInRange(0, 3)]})
        return encoded if encoded is not None else b""
    if op == 5:
        encoded = _safe_cbor_dumps(_build_value(fdp, 0))
        return encoded if encoded is not None else b""
    if op == 6:
        return b""
    if op == 7:
        return bytes([0xA1, 0x01, 0x38, 0x07])
    if op == 8:
        v = [-8, [1, -8], b"\x01\x27", None][fdp.ConsumeIntInRange(0, 3)]
        encoded = _safe_cbor_dumps(v)
        return encoded if encoded is not None else b""
    encoded = _safe_cbor_dumps({fdp.ConsumeIntInRange(2, 16): -8})
    return encoded if encoded is not None else b""


def _mutate_unprotected(fdp: atheris.FuzzedDataProvider):
    op = fdp.ConsumeIntInRange(0, 7)
    if op == 0:
        return {fdp.ConsumeIntInRange(-16, 32): _build_value(fdp, 1)}
    if op == 1:
        return {4: fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 32))}
    if op == 2:
        return {1: fdp.ConsumeIntInRange(-32, 32)}
    if op == 3:
        return {None: 0, 0: 0, 1: -8}
    if op == 4:
        choices = [None, [], 0, b"", "abc"]
        return choices[fdp.ConsumeIntInRange(0, 4)]
    if op == 5:
        return _build_value(fdp, 0)
    if op == 6:
        return {fdp.ConsumeIntInRange(0, 8): {99: "nested"}}
    return {}


def _mutate_payload(fdp: atheris.FuzzedDataProvider):
    op = fdp.ConsumeIntInRange(0, 5)
    if op == 0:
        return None
    if op == 1:
        return fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 64))
    if op == 2:
        return fdp.ConsumeIntInRange(-128, 128)
    if op == 3:
        return _build_value(fdp, 0)
    if op == 4:
        return []
    return {1: 1}


def _resign_over_chosen_inputs(
    fdp: atheris.FuzzedDataProvider, target_protected_bstr: bytes
) -> bytes:
    # Re-weighted vs the D1 harness: the OFFLINE_ROOT_COSE_DOMAIN_AAD branch
    # (choice 1, 2, 3) is selected ~3x more often than the cross-host AAD
    # branch (choice 0). The dangerous direction for THIS harness is an
    # envelope signed under offline-root's AAD then accepted by the cross-host
    # verifier (or vice versa), so weight the offline-root re-sign higher.
    choice = fdp.ConsumeIntInRange(0, 8)
    if choice == 0:
        # cross-host AAD (rare — already saturated by Layer 3's 21.7M)
        aad, pre, prot = CROSS_HOST_COSE_DOMAIN_AAD, _PREIMAGE, target_protected_bstr
    elif choice in (1, 2, 3):
        # offline-root AAD (dominant — the new exploration surface)
        aad, pre, prot = OFFLINE_ROOT_COSE_DOMAIN_AAD, _PREIMAGE, target_protected_bstr
    elif choice == 4:
        aad_len = fdp.ConsumeIntInRange(1, 32)
        aad, pre, prot = (
            fdp.ConsumeBytes(aad_len) or b"x",
            _PREIMAGE,
            target_protected_bstr,
        )
    elif choice == 5:
        aad, pre, prot = (
            OFFLINE_ROOT_COSE_DOMAIN_AAD,
            fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 64)),
            target_protected_bstr,
        )
    elif choice == 6:
        # Cross-AAD attack: sign over cross-host AAD with offline-root's
        # canonical protected header — explicit cross-protocol confusion.
        signed_over = b"\xa1\x01\x26"
        try:
            sig_input = offline_root_cose_sig_structure(
                _PREIMAGE,
                external_aad=CROSS_HOST_COSE_DOMAIN_AAD,
                protected_bstr=signed_over,
            )
            return _PRIV.sign(sig_input)
        except Exception:
            return _CANONICAL_SIG
    elif choice == 7:
        aad, pre, prot = OFFLINE_ROOT_COSE_DOMAIN_AAD, b"", target_protected_bstr
    else:
        return _CANONICAL_SIG
    try:
        sig_input = offline_root_cose_sig_structure(
            pre, external_aad=aad, protected_bstr=prot
        )
        return _PRIV.sign(sig_input)
    except Exception:
        return _CANONICAL_SIG


def _mutate_signature(fdp: atheris.FuzzedDataProvider):
    op = fdp.ConsumeIntInRange(0, 6)
    if op == 0:
        b = bytearray(_CANONICAL_SIG)
        for _ in range(fdp.ConsumeIntInRange(1, 4)):
            b[fdp.ConsumeIntInRange(0, 63)] ^= fdp.ConsumeIntInRange(1, 255)
        return bytes(b)
    if op == 1:
        return _CANONICAL_SIG[: fdp.ConsumeIntInRange(0, 63)]
    if op == 2:
        return _CANONICAL_SIG + fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, 32))
    if op == 3:
        return fdp.ConsumeBytes(64)
    if op == 4:
        choices = [None, 0, [], {}, ""]
        return choices[fdp.ConsumeIntInRange(0, 4)]
    if op == 5:
        return _CANONICAL_SIG
    return _build_value(fdp, 0)


def _build_envelope(fdp: atheris.FuzzedDataProvider) -> bytes | None:
    outer = fdp.ConsumeIntInRange(0, 11)
    if outer == 0:
        protected = (
            _mutate_protected_bstr(fdp)
            if fdp.ConsumeBool()
            else _CANONICAL_PROTECTED_BSTR
        )
        unprotected = (
            _mutate_unprotected(fdp) if fdp.ConsumeBool() else _CANONICAL_UNPROTECTED
        )
        payload = _mutate_payload(fdp) if fdp.ConsumeBool() else _CANONICAL_PAYLOAD
        signature = _mutate_signature(fdp) if fdp.ConsumeBool() else _CANONICAL_SIG
        return _safe_cbor_dumps([protected, unprotected, payload, signature])
    if outer == 1:
        return _safe_cbor_dumps(
            [_CANONICAL_PROTECTED_BSTR, _CANONICAL_UNPROTECTED, _CANONICAL_SIG]
        )
    if outer == 2:
        return _safe_cbor_dumps(
            [
                _CANONICAL_PROTECTED_BSTR,
                _CANONICAL_UNPROTECTED,
                _CANONICAL_PAYLOAD,
                _CANONICAL_SIG,
                _build_value(fdp, 0),
            ]
        )
    if outer == 3:
        return _safe_cbor_dumps(
            {
                0: _CANONICAL_PROTECTED_BSTR,
                1: _CANONICAL_UNPROTECTED,
                2: _CANONICAL_PAYLOAD,
                3: _CANONICAL_SIG,
            }
        )
    if outer == 4:
        return _safe_cbor_dumps(
            cbor2.CBORTag(
                fdp.ConsumeIntInRange(0, 30),
                [
                    _CANONICAL_PROTECTED_BSTR,
                    _CANONICAL_UNPROTECTED,
                    _CANONICAL_PAYLOAD,
                    _CANONICAL_SIG,
                ],
            )
        )
    if outer == 5:
        return _safe_cbor_dumps(_build_value(fdp, 0))
    if outer == 6:
        return _safe_cbor_dumps(
            [
                _build_value(fdp, 0),
                _CANONICAL_UNPROTECTED,
                _CANONICAL_PAYLOAD,
                _CANONICAL_SIG,
            ]
        )
    if outer == 7:
        try:
            return (
                b"\x9f"
                + cbor2.dumps(_CANONICAL_PROTECTED_BSTR)
                + cbor2.dumps(_CANONICAL_UNPROTECTED)
                + cbor2.dumps(_CANONICAL_PAYLOAD)
                + cbor2.dumps(_CANONICAL_SIG)
                + b"\xff"
            )
        except Exception:
            return None
    if outer == 8:
        return _CANONICAL_COSE
    if outer == 9:
        return _safe_cbor_dumps(
            [
                _CANONICAL_PROTECTED_BSTR,
                _CANONICAL_UNPROTECTED,
                _CANONICAL_PAYLOAD,
                _mutate_signature(fdp),
            ]
        )
    if outer == 10:
        new_protected = (
            _mutate_protected_bstr(fdp)
            if fdp.ConsumeBool()
            else _CANONICAL_PROTECTED_BSTR
        )
        sig = _resign_over_chosen_inputs(fdp, new_protected)
        return _safe_cbor_dumps(
            [new_protected, _CANONICAL_UNPROTECTED, _CANONICAL_PAYLOAD, sig]
        )
    new_protected = (
        _mutate_protected_bstr(fdp)
        if fdp.ConsumeBool()
        else _CANONICAL_PROTECTED_BSTR
    )
    new_unprotected = (
        _mutate_unprotected(fdp) if fdp.ConsumeBool() else _CANONICAL_UNPROTECTED
    )
    new_payload = _mutate_payload(fdp) if fdp.ConsumeBool() else _CANONICAL_PAYLOAD
    sig = _resign_over_chosen_inputs(fdp, new_protected)
    return _safe_cbor_dumps([new_protected, new_unprotected, new_payload, sig])


# ---------------------------------------------------------------------------
# Atheris entry point.
# ---------------------------------------------------------------------------
def _classify_and_oracle(envelope: bytes) -> None:
    """Verdict both verifiers on `envelope` and apply the BOTH-PASS oracle."""
    ch_v, ch_why = _cross_host_verdict(envelope)  # raises on §C9 violation
    or_v, or_why = _offline_root_verdict(envelope)  # raises on non-typed exc

    if ch_v == "PASS" and or_v == "PASS":
        raise AssertionError(
            f"CROSS-PROTOCOL-REPLAY: cross_host=PASS offline_root=PASS "
            f"ch_code={ch_why!r} or_code={or_why!r} "
            f"envelope_len={len(envelope)} canonical_len={len(_CANONICAL_COSE)} "
            f"envelope_hex={envelope.hex()}"
        )
    # All other combinations (one PASS or both FAIL) are expected — the AAD
    # tag is doing its job, or the envelope is simply malformed.


def test_one(data: bytes) -> None:
    if len(data) < 2:
        return
    fdp = atheris.FuzzedDataProvider(data)
    # Pick arm: ~1/8 raw bytes, ~7/8 structure-aware. Random bytes rarely
    # decode to a 4-tuple so the raw arm is low-yield but cheap to keep.
    arm = fdp.ConsumeIntInRange(0, 7)
    if arm == 0:
        envelope = bytes(fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 512)))
        if not envelope:
            return
    else:
        envelope = _build_envelope(fdp)
        if envelope is None:
            return
    _classify_and_oracle(envelope)


def main() -> None:
    atheris.Setup(sys.argv, test_one)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
