"""Atheris-driven differential: pycose vs production verify_cross_host.

Wraps the one-shot `differential_pycose_vs_production.py` corpus oracle in
an atheris harness so libfuzzer can widen the input distribution far past
the 110-input curated+grown corpus the prior session covered.

Two arms, picked per-iteration by the FuzzedDataProvider:

  - raw-bytes arm  — pass fuzzer bytes straight at both verifiers; useful
    for low-cost coverage of the byte-level CBOR parser entry, but most
    inputs won't decode to a 4-tuple and both arms will FAIL-agree.

  - structure-aware arm — reuse the Layer 3 mutator + re-sign branches
    (verbatim, since both harnesses pin the same key+preimage+AAD); this
    is the dominant arm and where divergences come from.

Oracle (split by direction):

  - production=PASS, pycose=FAIL  → CRITICAL, RAISE
        Verifier accepted something pycose's RFC 9052 reader rejected.
        That is a verifier bug pycose just caught for us.

  - production=FAIL, pycose=PASS  → known pycose-side-gap class, COUNT
        Prior session enumerated several: Layer 2 #2 (trailing bytes),
        Layer 3 #1 (indefinite-length outer encoding), Layer 2 #1/#3
        (slot-type / non-empty unprotected) — all directions where the
        production verifier is deliberately stricter than pycose. We
        emit a one-line trace and continue without crashing the harness,
        so 10M iter does not get saturated by Layer 2 #2 echoes.

  - both PASS / both FAIL         → agree, no action.

Setup (fixed at module load):
  - Ed25519 keypair from the same 32-byte seed as Layer 2/3 + the corpus
    differential script (so any envelope minted in those harnesses we
    save through replay flows cleanly through this oracle too)
  - canonical preimage + canonical envelope decoded into its 4 slots

Run:
    .venv/bin/python tests/fuzz/atheris_differential_pycose.py \\
        -atheris_runs=10000000 \\
        -print_final_stats=1 \\
        -artifact_prefix=tests/fuzz/crashes/differential_pycose/ \\
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

    from pycose.algorithms import EdDSA
    from pycose.keys import OKPKey
    from pycose.keys.curves import Ed25519
    from pycose.keys.keyparam import KpAlg
    from pycose.messages import Sign1Message

    from audit_bundle.extensions.c19.cross_host_peerreview import (
        CROSS_HOST_COSE_DOMAIN_AAD,
        sign_cross_host_authenticator_cose,
        verify_cross_host_authenticator_cose,
    )
    from audit_bundle.extensions.c19.offline_root import (
        OFFLINE_ROOT_COSE_DOMAIN_AAD,
        offline_root_cose_sig_structure,
    )


# ---------------------------------------------------------------------------
# Pinned context — must match Layer 2/3 + differential corpus script exactly.
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

_CANONICAL_COSE = sign_cross_host_authenticator_cose(
    private_key=_PRIV, preimage=_PREIMAGE
)
_CANONICAL_DECODED = cbor2.loads(_CANONICAL_COSE)
_CANONICAL_PROTECTED_BSTR = _CANONICAL_DECODED[0]
_CANONICAL_UNPROTECTED = _CANONICAL_DECODED[1]
_CANONICAL_PAYLOAD = _CANONICAL_DECODED[2]
_CANONICAL_SIG = _CANONICAL_DECODED[3]

# pycose verifier key (instantiated once, reused per call).
_PYCOSE_KEY = OKPKey(
    crv=Ed25519,
    x=_PUB_RAW,
    optional_params={KpAlg: EdDSA},
)

# Pycose-side-gap counter — purely informational; logged occasionally.
_PYCOSE_GAP_COUNT = [0]
_GAP_LOG_EVERY = 100_000


# ---------------------------------------------------------------------------
# Verdict functions (mirror differential_pycose_vs_production.py exactly, but
# silent — print_per_iter would flood at fuzzing rates).
# ---------------------------------------------------------------------------
def _pycose_verdict(cose_bytes: bytes) -> tuple[str, str]:
    try:
        decoded = cbor2.loads(cose_bytes)
    except Exception as exc:
        return "FAIL", f"cbor-decode:{type(exc).__name__}"
    if not isinstance(decoded, (list, tuple)) or len(decoded) != 4:
        return "FAIL", "not-4-elem-array"
    try:
        msg = Sign1Message.from_cose_obj(
            list(decoded), allow_unknown_attributes=False
        )
        msg.key = _PYCOSE_KEY
        msg.external_aad = CROSS_HOST_COSE_DOMAIN_AAD
        msg.payload = _PREIMAGE  # detached
        ok = msg.verify_signature()
    except Exception as exc:
        return "FAIL", f"pycose-{type(exc).__name__}"
    return ("PASS" if ok else "FAIL"), "ok" if ok else "sig-mismatch"


def _production_verdict(cose_bytes: bytes) -> tuple[str, str]:
    try:
        ok, code, _detail = verify_cross_host_authenticator_cose(
            public_key_raw=_PUB_RAW, preimage=_PREIMAGE, cose_bytes=cose_bytes
        )
    except Exception as exc:
        # §C9 fail-closed contract: verify must never raise. Re-raise so
        # atheris saves the input as a crash; this is itself a finding.
        raise AssertionError(
            f"VERIFY-RAISED ({type(exc).__name__}): {exc!r} "
            f"cose_len={len(cose_bytes)} cose_hex={cose_bytes.hex()}"
        ) from exc
    return ("PASS" if ok else "FAIL"), code


# ---------------------------------------------------------------------------
# Structure-aware mutator (copied verbatim from atheris_verify_cose_layer3.py
# — same key, same preimage, same AAD constants → identical mutation space).
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
    choice = fdp.ConsumeIntInRange(0, 6)
    if choice == 0:
        aad, pre, prot = CROSS_HOST_COSE_DOMAIN_AAD, _PREIMAGE, target_protected_bstr
    elif choice == 1:
        aad, pre, prot = OFFLINE_ROOT_COSE_DOMAIN_AAD, _PREIMAGE, target_protected_bstr
    elif choice == 2:
        aad_len = fdp.ConsumeIntInRange(1, 32)
        aad, pre, prot = (
            fdp.ConsumeBytes(aad_len) or b"x",
            _PREIMAGE,
            target_protected_bstr,
        )
    elif choice == 3:
        aad, pre, prot = (
            CROSS_HOST_COSE_DOMAIN_AAD,
            fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 64)),
            target_protected_bstr,
        )
    elif choice == 4:
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
    elif choice == 5:
        aad, pre, prot = CROSS_HOST_COSE_DOMAIN_AAD, b"", target_protected_bstr
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
    """Run both verdicts on `envelope` and apply the split-direction oracle."""
    py_v, py_why = _pycose_verdict(envelope)
    pr_v, pr_why = _production_verdict(envelope)  # raises on §C9 exception

    if py_v == pr_v:
        return  # agree (both PASS or both FAIL) — no finding

    if pr_v == "PASS" and py_v == "FAIL":
        # Dangerous direction: production accepted what pycose rejected.
        raise AssertionError(
            f"DIFFERENTIAL-DANGEROUS-DIR: production=PASS pycose=FAIL "
            f"pr_code={pr_why!r} py_reason={py_why!r} "
            f"envelope_len={len(envelope)} canonical_len={len(_CANONICAL_COSE)} "
            f"envelope_hex={envelope.hex()}"
        )

    # pr_v == "FAIL" and py_v == "PASS": known pycose-side-gap class.
    # Count and continue; do not crash the harness.
    _PYCOSE_GAP_COUNT[0] += 1
    if _PYCOSE_GAP_COUNT[0] % _GAP_LOG_EVERY == 0:
        sys.stderr.write(
            f"[pycose-gap] count={_PYCOSE_GAP_COUNT[0]} "
            f"pr_code={pr_why!r} env_len={len(envelope)}\n"
        )


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
