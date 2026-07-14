"""Layer 2 COSE-envelope fuzz: catastrophic-tier bypass-finder.

The promise the round-2 parse-boundary commit (ad3111cc7, 2026-05-23) handed
off: "Signature-bypass tier (COSE envelopes, Layer 2) remains for the
coverage-guided atheris harness." This harness is that harness.

Setup (fixed at module load, deterministic):
  - Ed25519 keypair from a fixed 32-byte seed (reproducible)
  - One canonical preimage (b"v-kernel layer-2 cose fuzz canonical preimage")
  - One canonical valid COSE_Sign1 envelope signed by that keypair over that
    preimage (computed once via sign_cross_host_authenticator_cose)

Per-iteration:
  - atheris hands us raw bytes -> use as the candidate `cose_bytes`
  - call verify_cross_host_authenticator_cose with FIXED K + preimage + role
  - oracle:
      (a) Contract: result is (bool, str, str); never raises (Layer 1 oracle)
      (b) Bypass:   ok is True ONLY when the candidate is byte-identical to
                    the canonical valid envelope. ok=True for any byte-
                    different input under the fixed pubkey is a signature
                    bypass — a CRITICAL fail-open per §C9.

The bypass oracle is exact: COSE_Sign1's signature is over
Sig_structure(protected_bstr, external_aad, payload). Any byte change to
the candidate that survives the parser checks AND verifies under EdDSA
would imply either (i) the protected_bstr fed into Sig_structure changed
while the signature still verified (preimage collision — practically
impossible for SHA-512-based EdDSA), or (ii) the verifier consulted a
different protected_bstr than the one it signed over (C7 separation bug —
exactly what we're looking for).

Run:
    .venv/bin/python tests/fuzz/atheris_verify_cose_bundle.py \\
        -max_total_time=120 \\
        -print_final_stats=1 \\
        -artifact_prefix=tests/fuzz/crashes/cose_bundle/ \\
        tests/fuzz/corpus/cose_bundle/
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    from audit_bundle.extensions.c19.cross_host_peerreview import (
        sign_cross_host_authenticator_cose,
        verify_cross_host_authenticator_cose,
    )


# Deterministic Ed25519 keypair (seed is arbitrary but fixed for reproducibility)
_PRIV_SEED = bytes.fromhex(
    "00010203" "04050607" "08090a0b" "0c0d0e0f"
    "10111213" "14151617" "18191a1b" "1c1d1e1f"
)
_PRIV = Ed25519PrivateKey.from_private_bytes(_PRIV_SEED)
_PUB_RAW = _PRIV.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)

# Canonical preimage + the one valid COSE_Sign1 envelope that signs it
_PREIMAGE = b"v-kernel layer-2 cose fuzz canonical preimage"
_CANONICAL_COSE = sign_cross_host_authenticator_cose(
    private_key=_PRIV, preimage=_PREIMAGE
)


def test_one(data: bytes) -> None:
    result = verify_cross_host_authenticator_cose(
        public_key_raw=_PUB_RAW,
        preimage=_PREIMAGE,
        cose_bytes=data,
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

    # Layer 2 oracle: bypass-finder. The ONLY byte string that may legitimately
    # verify under the fixed (pub, preimage) is the exact canonical envelope.
    # Any other ok=True is a signature bypass — CRITICAL.
    if ok and data != _CANONICAL_COSE:
        raise AssertionError(
            f"COSE-SIG-BYPASS: verify accepted byte-different cose_bytes under "
            f"fixed (pubkey, preimage). reason_code={reason_code!r} "
            f"data_len={len(data)} canonical_len={len(_CANONICAL_COSE)} "
            f"data_hex={data.hex()}"
        )


def main() -> None:
    atheris.Setup(sys.argv, test_one)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
