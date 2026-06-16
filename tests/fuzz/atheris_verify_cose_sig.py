"""Layer 1 COSE-envelope fuzz: single-call byte fuzz of
``verify_cross_host_authenticator_cose`` (cross_host_peerreview.py:310).

Oracle (intentionally narrow, mirrors the shape-contract harness):
  1. The function must return a ``(bool, str, str)`` tuple.
  2. It must not raise. Every malformed input must surface as
     ``(False, REASON_CODE, detail)`` so a hostile peer cannot crash the
     cross-host verifier (fail-stop / DoS) — only get rejected (fail-closed).

The catastrophic-tier oracle (mutated *valid* signature wrongly returns
``True``) lives in the Layer 2 sibling harness, ``atheris_verify_cose_bundle.py``,
which pins a real keypair + preimage at startup. Layer 1's value is parser/
length/type robustness on the raw-bytes boundary.

Input layout (FuzzedDataProvider sequential):
    [0..32)   public_key_raw      — 32-byte Ed25519 pubkey (short → from_public_bytes raises → fail-closed)
    [32..96)  preimage            — arbitrary bytes fed into the Sig_structure
    [96..)    cose_bytes          — candidate COSE_Sign1 CBOR

Run:
    .venv/bin/python tests/fuzz/atheris_verify_cose_sig.py \\
        -max_total_time=120 \\
        -print_final_stats=1 \\
        -artifact_prefix=tests/fuzz/crashes/cose/ \\
        tests/fuzz/corpus/cose/
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from audit_bundle.extensions.c19.cross_host_peerreview import (  # noqa: F401
        verify_cross_host_authenticator_cose,
    )


def test_one(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    public_key_raw = fdp.ConsumeBytes(32)
    preimage = fdp.ConsumeBytes(64)
    cose_bytes = fdp.ConsumeBytes(fdp.remaining_bytes())
    # Bit 0 of the next byte (consumed past the body) picks role; the
    # remainder of the bytes-pool is exhausted by ConsumeRemainingBytes
    # above, so an unconsumed signal is fine for one extra coin flip.
    role = "ack" if (sum(public_key_raw) + len(cose_bytes)) % 2 else "sender"

    result = verify_cross_host_authenticator_cose(
        public_key_raw=public_key_raw,
        preimage=preimage,
        cose_bytes=cose_bytes,
        role=role,
    )

    # The contract is a (bool, str, str) triple. Anything else — including a
    # raised exception that propagates out of this function — is a §C9 break.
    assert isinstance(result, tuple), (
        f"verify_cross_host_authenticator_cose returned {type(result).__name__}, "
        f"expected tuple"
    )
    assert len(result) == 3, (
        f"verify_cross_host_authenticator_cose returned {len(result)}-tuple, "
        f"expected 3"
    )
    ok, reason_code, detail = result
    assert isinstance(ok, bool), f"ok is {type(ok).__name__}, expected bool"
    assert isinstance(reason_code, str), (
        f"reason_code is {type(reason_code).__name__}, expected str"
    )
    assert isinstance(detail, str), (
        f"detail is {type(detail).__name__}, expected str"
    )


def main() -> None:
    atheris.Setup(sys.argv, test_one)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
