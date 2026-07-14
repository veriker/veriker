"""Layer 3 structure-aware CBOR fuzz: COSE_Sign1 envelope semantics.

Layer 2 (`atheris_verify_cose_bundle.py`) saturated at 83.4M iter / 0 new
findings after the 4-fix cascade — byte-level mutation cannot easily reach
bugs only triggerable through valid-CBOR-with-wrong-semantics paths (e.g.
an envelope whose outer CBOR shape is RFC-perfect but where one inner slot
carries an attacker-crafted semantic payload).

This harness decodes the canonical envelope into its 4-slot CBOR
structure, lets atheris pick a slot + mutation type, applies the mutation
while preserving outer-CBOR validity, re-encodes, and feeds the result to
`verify_cross_host_authenticator_cose`.

Setup (fixed at module load, deterministic — same as Layer 2):
  - Ed25519 keypair from a fixed 32-byte seed
  - One canonical preimage
  - One canonical valid COSE_Sign1 envelope, decoded into its 4-tuple

Per-iteration mutation menu (FuzzedDataProvider picks):
  slot 0 (protected_bstr): mutate the CBOR INSIDE the bstr (key change,
         value change, add key, dup key, indefinite-length encode,
         non-shortest-int encode, swap to non-dict)
  slot 1 (unprotected map): inject a key/value pair, swap to non-map,
         add nested CBOR, mix int+None keys
  slot 2 (payload): swap None -> bytes / int / list / dict
  slot 3 (signature): mutate bytes (flip / truncate / extend / replace
         with other CBOR types)
  also: swap the whole envelope to a 3- or 5-element array, change
         outer container type

Oracle: same as Layer 2 — ok=True for any byte-different result = bypass.
Also Layer 1 oracle (contract: (bool, str, str), no raise).

NOTE: this harness does NOT re-sign after mutation. Re-signing would test
"does the verifier accept a valid signature over an unintended structure",
but most Layer-3 bugs are reachable without re-sign because the
Sig_structure is reconstructed from the transmitted protected_bstr — any
mutation outside protected_bstr that the verifier accepts is a structural
bug, not a forgery. Re-sign variant is a follow-up if this arm saturates.

Run:
    .venv/bin/python tests/fuzz/atheris_verify_cose_layer3.py \\
        -max_total_time=120 \\
        -print_final_stats=1 \\
        -artifact_prefix=tests/fuzz/crashes/cose_bundle_layer3/ \\
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
    from audit_bundle.extensions.c19.offline_root import (
        OFFLINE_ROOT_COSE_DOMAIN_AAD,
        offline_root_cose_sig_structure,
    )


# Deterministic Ed25519 keypair (same seed as Layer 2 for cross-comparison).
_PRIV_SEED = bytes.fromhex(
    "00010203" "04050607" "08090a0b" "0c0d0e0f"
    "10111213" "14151617" "18191a1b" "1c1d1e1f"
)
_PRIV = Ed25519PrivateKey.from_private_bytes(_PRIV_SEED)
_PUB_RAW = _PRIV.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)

# Canonical preimage + the one valid COSE_Sign1 envelope
_PREIMAGE = b"v-kernel layer-2 cose fuzz canonical preimage"
_CANONICAL_COSE = sign_cross_host_authenticator_cose(
    private_key=_PRIV, preimage=_PREIMAGE
)
_CANONICAL_DECODED = cbor2.loads(_CANONICAL_COSE)
# [protected_bstr, unprotected_map, payload, signature]
_CANONICAL_PROTECTED_BSTR = _CANONICAL_DECODED[0]
_CANONICAL_UNPROTECTED = _CANONICAL_DECODED[1]
_CANONICAL_PAYLOAD = _CANONICAL_DECODED[2]
_CANONICAL_SIG = _CANONICAL_DECODED[3]


def _safe_cbor_dumps(value) -> bytes | None:
    """Encode `value` to CBOR; return None on any encoder failure (the
    encoded payload is what we'd want to fuzz the verifier with — if cbor2
    can't even produce it, skip this iteration without crashing the harness).
    """
    try:
        return cbor2.dumps(value)
    except Exception:
        return None


def _build_value(fdp: atheris.FuzzedDataProvider, depth: int = 0):
    """Build an arbitrary CBOR-encodable Python value from the fuzzer.

    Bounded recursion (depth <= 3) keeps the harness throughput up and
    avoids the encoder choking on pathological nesting.
    """
    if depth >= 3:
        kind = fdp.ConsumeIntInRange(0, 3)
    else:
        kind = fdp.ConsumeIntInRange(0, 9)
    if kind == 0:
        return None
    if kind == 1:
        return fdp.ConsumeIntInRange(-1 << 31, (1 << 31) - 1)
    if kind == 2:
        return fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 64))
    if kind == 3:
        n = fdp.ConsumeIntInRange(0, 32)
        try:
            return fdp.ConsumeUnicodeNoSurrogates(n)
        except Exception:
            return ""
    if kind == 4:
        return fdp.ConsumeBool()
    if kind == 5:
        n = fdp.ConsumeIntInRange(0, 4)
        return [_build_value(fdp, depth + 1) for _ in range(n)]
    if kind == 6:
        n = fdp.ConsumeIntInRange(0, 4)
        d = {}
        for _ in range(n):
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
        # raw CBOR fragment as bytes (an attacker-crafted bstr)
        return fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 128))
    # kind == 9: float (cbor2 supports float)
    try:
        return fdp.ConsumeFloat()
    except Exception:
        return 0.0


def _mutate_protected_bstr(fdp: atheris.FuzzedDataProvider) -> bytes:
    """Build a new protected_bstr (a CBOR bstr containing a CBOR map).

    Mutation menu:
      0 — start from canonical {1:-8}, change alg value
      1 — start from canonical, add extra label
      2 — start from canonical, duplicate the alg key (non-canonical)
      3 — start from canonical, swap to indefinite-length map encoding
      4 — start from canonical, replace value with non-int alg
      5 — replace entire protected with arbitrary fuzzer-built value
      6 — empty bstr
      7 — non-canonical int encoding for the alg label
      8 — protected bstr containing a non-map (list / int / null)
      9 — start from canonical, swap key 1 -> something else (alg-absent)
    """
    op = fdp.ConsumeIntInRange(0, 9)
    if op == 0:
        # alg value mutation — anything but -8 should fail; -8 with this
        # path is identity unless we touch encoding form
        new_alg = fdp.ConsumeIntInRange(-32, 32)
        encoded = _safe_cbor_dumps({1: new_alg})
        return encoded if encoded is not None else b""
    if op == 1:
        new_label = fdp.ConsumeIntInRange(-16, 32)
        encoded = _safe_cbor_dumps({1: -8, new_label: _build_value(fdp, 1)})
        return encoded if encoded is not None else b""
    if op == 2:
        # Non-canonical: duplicate alg key. cbor2 won't emit duplicates
        # directly; hand-build the bytes.
        # Map header (a2) + 01 26 (alg ES256) + 01 27 (alg EdDSA)
        # produces a2 01 26 01 27 — a non-canonical 2-entry map with
        # both entries keyed at 1 (last-wins -> EdDSA in cbor2).
        return bytes([0xA2, 0x01, 0x26, 0x01, 0x27])
    if op == 3:
        # Indefinite-length map encoding: bf ... ff (RFC 8949 §3.2.2)
        # bf 01 27 ff = indefinite-length map with one entry {1: -8} ff
        return bytes([0xBF, 0x01, 0x27, 0xFF])
    if op == 4:
        # alg as a non-int (string / bytes / null / list)
        choices = ["EdDSA", b"EdDSA", None, [-8]]
        encoded = _safe_cbor_dumps({1: choices[fdp.ConsumeIntInRange(0, 3)]})
        return encoded if encoded is not None else b""
    if op == 5:
        v = _build_value(fdp, 0)
        encoded = _safe_cbor_dumps(v)
        return encoded if encoded is not None else b""
    if op == 6:
        return b""
    if op == 7:
        # Non-shortest-int encoding for the alg value. -8 in shortest form
        # is 0x27 (1-byte negint). Encode it as 0x38 0x07 (1-byte tag for
        # 8-bit negint) — same logical value, non-canonical encoding.
        return bytes([0xA1, 0x01, 0x38, 0x07])
    if op == 8:
        # protected bstr that decodes to a non-map
        v = [
            -8,
            [1, -8],
            b"\x01\x27",
            None,
        ][fdp.ConsumeIntInRange(0, 3)]
        encoded = _safe_cbor_dumps(v)
        return encoded if encoded is not None else b""
    # op == 9: protected with NO alg key — verifier should fail alg-pin
    new_label = fdp.ConsumeIntInRange(2, 16)
    encoded = _safe_cbor_dumps({new_label: -8})
    return encoded if encoded is not None else b""


def _mutate_unprotected(fdp: atheris.FuzzedDataProvider):
    """Build a new unprotected slot. Canonical is `{}`."""
    op = fdp.ConsumeIntInRange(0, 7)
    if op == 0:
        # add a single int key
        return {fdp.ConsumeIntInRange(-16, 32): _build_value(fdp, 1)}
    if op == 1:
        # add a fake `kid` (label 4)
        return {4: fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 32))}
    if op == 2:
        # add a fake `alg` (label 1) — alg-confusion arm
        return {1: fdp.ConsumeIntInRange(-32, 32)}
    if op == 3:
        # mixed int + None keys — exercises the §C9 detail formatter
        return {None: 0, 0: 0, 1: -8}
    if op == 4:
        # non-dict (verifier should reject as COSE_UNPROTECTED_MALFORMED)
        choices = [None, [], 0, b"", "abc"]
        return choices[fdp.ConsumeIntInRange(0, 4)]
    if op == 5:
        # arbitrary fuzzer-built value (could be a dict, could be anything)
        return _build_value(fdp, 0)
    if op == 6:
        # nested dict
        return {fdp.ConsumeIntInRange(0, 8): {99: "nested"}}
    # op == 7: keep canonical empty
    return {}


def _mutate_payload(fdp: atheris.FuzzedDataProvider):
    """Build a new payload. Canonical is `None` (detached)."""
    op = fdp.ConsumeIntInRange(0, 5)
    if op == 0:
        return None  # canonical
    if op == 1:
        return fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 64))
    if op == 2:
        return fdp.ConsumeIntInRange(-128, 128)
    if op == 3:
        return _build_value(fdp, 0)
    if op == 4:
        return []
    # op == 5
    return {1: 1}


def _resign_over_chosen_inputs(
    fdp: atheris.FuzzedDataProvider, target_protected_bstr: bytes
) -> bytes:
    """Sign a Sig_structure of the fuzzer's choice using our keypair.

    Per the per-protocol domain-tag contract, a signature minted under
    OFFLINE_ROOT_COSE_DOMAIN_AAD must NOT verify under
    CROSS_HOST_COSE_DOMAIN_AAD (cross-protocol replay defence), and vice
    versa. We let the fuzzer pick the (external_aad, preimage,
    protected_bstr) combo that goes into Sig_structure — the verifier
    rebuilds Sig_structure from CROSS_HOST_COSE_DOMAIN_AAD + the
    transmitted protected_bstr + the caller's preimage, so any mismatch
    should fail closed.
    """
    choice = fdp.ConsumeIntInRange(0, 6)
    if choice == 0:
        # honest re-sign — should produce the canonical envelope
        aad, pre, prot = (
            CROSS_HOST_COSE_DOMAIN_AAD,
            _PREIMAGE,
            target_protected_bstr,
        )
    elif choice == 1:
        # wrong domain AAD (cross-protocol replay arm)
        aad, pre, prot = (
            OFFLINE_ROOT_COSE_DOMAIN_AAD,
            _PREIMAGE,
            target_protected_bstr,
        )
    elif choice == 2:
        # arbitrary AAD chosen by fuzzer
        aad_len = fdp.ConsumeIntInRange(1, 32)
        aad, pre, prot = (
            fdp.ConsumeBytes(aad_len) or b"x",
            _PREIMAGE,
            target_protected_bstr,
        )
    elif choice == 3:
        # right AAD but wrong preimage
        aad, pre, prot = (
            CROSS_HOST_COSE_DOMAIN_AAD,
            fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 64)),
            target_protected_bstr,
        )
    elif choice == 4:
        # sign over a different protected_bstr than what's transmitted —
        # the verifier rebuilds Sig_structure from the TRANSMITTED bstr, so
        # this should fail (C7: no re-encode between signer and verifier).
        signed_over = b"\xa1\x01\x26"  # {1: -7} (ES256, not EdDSA)
        # Sig_structure references signed_over, but we'll attach the
        # different `target_protected_bstr` to the envelope outside.
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
        # empty preimage — verifier should still produce a valid Sig_structure
        # but the caller's preimage in verify won't match
        aad, pre, prot = (
            CROSS_HOST_COSE_DOMAIN_AAD,
            b"",
            target_protected_bstr,
        )
    else:
        # right everything but signed over an empty external_aad — the
        # offline_root_cose_sig_structure helper REJECTS empty AAD (C1a), so
        # this branch tests the harness's resilience, not the verifier; fall
        # back to canonical.
        return _CANONICAL_SIG

    try:
        sig_input = offline_root_cose_sig_structure(
            pre, external_aad=aad, protected_bstr=prot
        )
        return _PRIV.sign(sig_input)
    except Exception:
        return _CANONICAL_SIG


def _mutate_signature(fdp: atheris.FuzzedDataProvider):
    """Build a new signature slot. Canonical is 64-byte Ed25519 sig."""
    op = fdp.ConsumeIntInRange(0, 6)
    if op == 0:
        # flip bytes in the canonical sig
        b = bytearray(_CANONICAL_SIG)
        n_flips = fdp.ConsumeIntInRange(1, 4)
        for _ in range(n_flips):
            i = fdp.ConsumeIntInRange(0, 63)
            b[i] ^= fdp.ConsumeIntInRange(1, 255)
        return bytes(b)
    if op == 1:
        # truncate
        return _CANONICAL_SIG[: fdp.ConsumeIntInRange(0, 63)]
    if op == 2:
        # extend
        extra = fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, 32))
        return _CANONICAL_SIG + extra
    if op == 3:
        # canonical-length but other bytes
        return fdp.ConsumeBytes(64)
    if op == 4:
        # not bytes — int, None, list, dict, str
        choices = [None, 0, [], {}, ""]
        return choices[fdp.ConsumeIntInRange(0, 4)]
    if op == 5:
        return _CANONICAL_SIG  # canonical
    # op == 6: arbitrary fuzzer-built value
    return _build_value(fdp, 0)


def _build_envelope(fdp: atheris.FuzzedDataProvider) -> bytes | None:
    """Build a candidate envelope. Returns None if encoding fails."""
    outer = fdp.ConsumeIntInRange(0, 11)
    if outer == 0:
        # standard 4-element envelope, mutate any subset of slots
        protected = (
            _mutate_protected_bstr(fdp)
            if fdp.ConsumeBool()
            else _CANONICAL_PROTECTED_BSTR
        )
        unprotected = (
            _mutate_unprotected(fdp)
            if fdp.ConsumeBool()
            else _CANONICAL_UNPROTECTED
        )
        payload = (
            _mutate_payload(fdp)
            if fdp.ConsumeBool()
            else _CANONICAL_PAYLOAD
        )
        signature = (
            _mutate_signature(fdp)
            if fdp.ConsumeBool()
            else _CANONICAL_SIG
        )
        return _safe_cbor_dumps([protected, unprotected, payload, signature])
    if outer == 1:
        # 3-element array
        return _safe_cbor_dumps(
            [_CANONICAL_PROTECTED_BSTR, _CANONICAL_UNPROTECTED, _CANONICAL_SIG]
        )
    if outer == 2:
        # 5-element array (extra trailing slot)
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
        # outer is a map, not an array (verifier should reject)
        return _safe_cbor_dumps(
            {
                0: _CANONICAL_PROTECTED_BSTR,
                1: _CANONICAL_UNPROTECTED,
                2: _CANONICAL_PAYLOAD,
                3: _CANONICAL_SIG,
            }
        )
    if outer == 4:
        # outer is a CBOR-tagged value (COSE_Sign1 is technically tagged 18
        # in tagged form per RFC 9052; the cross-host signer emits the
        # untagged form). Tagged variants exercise a parser differential.
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
        # arbitrary fuzzer-built outer value
        return _safe_cbor_dumps(_build_value(fdp, 0))
    if outer == 6:
        # 4-element envelope where slot 0 is NOT a bytes — the verifier's
        # `cbor2.loads(protected_bstr)` should fail closed
        return _safe_cbor_dumps(
            [
                _build_value(fdp, 0),
                _CANONICAL_UNPROTECTED,
                _CANONICAL_PAYLOAD,
                _CANONICAL_SIG,
            ]
        )
    if outer == 7:
        # indefinite-length array encoding for the outer envelope
        # 9f <protected> <unprotected> <payload> <signature> ff
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
        # canonical envelope, no mutation (sanity arm)
        return _CANONICAL_COSE
    if outer == 9:
        # only mutate the signature — pure-signature-malleability arm
        return _safe_cbor_dumps(
            [
                _CANONICAL_PROTECTED_BSTR,
                _CANONICAL_UNPROTECTED,
                _CANONICAL_PAYLOAD,
                _mutate_signature(fdp),
            ]
        )
    if outer == 10:
        # re-sign arm: canonical-shape envelope, attacker-chosen Sig_structure
        # (wrong AAD / wrong preimage / mismatched protected_bstr / etc.)
        new_protected = (
            _mutate_protected_bstr(fdp)
            if fdp.ConsumeBool()
            else _CANONICAL_PROTECTED_BSTR
        )
        sig = _resign_over_chosen_inputs(fdp, new_protected)
        return _safe_cbor_dumps(
            [
                new_protected,
                _CANONICAL_UNPROTECTED,
                _CANONICAL_PAYLOAD,
                sig,
            ]
        )
    # outer == 11: re-sign with full slot freedom
    new_protected = (
        _mutate_protected_bstr(fdp)
        if fdp.ConsumeBool()
        else _CANONICAL_PROTECTED_BSTR
    )
    new_unprotected = (
        _mutate_unprotected(fdp)
        if fdp.ConsumeBool()
        else _CANONICAL_UNPROTECTED
    )
    new_payload = (
        _mutate_payload(fdp)
        if fdp.ConsumeBool()
        else _CANONICAL_PAYLOAD
    )
    sig = _resign_over_chosen_inputs(fdp, new_protected)
    return _safe_cbor_dumps(
        [new_protected, new_unprotected, new_payload, sig]
    )


def test_one(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    envelope = _build_envelope(fdp)
    if envelope is None:
        return
    result = verify_cross_host_authenticator_cose(
        public_key_raw=_PUB_RAW,
        preimage=_PREIMAGE,
        cose_bytes=envelope,
        role="sender",
    )

    # Layer 1 oracle: contract is (bool, str, str), never raises.
    assert isinstance(result, tuple), (
        f"verify returned {type(result).__name__}, expected tuple"
    )
    assert len(result) == 3, f"verify returned {len(result)}-tuple, expected 3"
    ok, reason_code, detail = result
    assert isinstance(ok, bool), f"ok is {type(ok).__name__}, expected bool"
    assert isinstance(reason_code, str), (
        f"reason_code is {type(reason_code).__name__}, expected str"
    )
    assert isinstance(detail, str), (
        f"detail is {type(detail).__name__}, expected str"
    )

    # Layer 2 oracle, lifted: ok=True for any byte-different envelope under
    # the fixed pubkey+preimage is a CRITICAL signature bypass per §C9.
    if ok and envelope != _CANONICAL_COSE:
        raise AssertionError(
            f"COSE-SIG-BYPASS (Layer 3): verify accepted byte-different "
            f"cose_bytes under fixed (pubkey, preimage). "
            f"reason_code={reason_code!r} "
            f"envelope_len={len(envelope)} canonical_len={len(_CANONICAL_COSE)} "
            f"envelope_hex={envelope.hex()}"
        )


def main() -> None:
    atheris.Setup(sys.argv, test_one)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
