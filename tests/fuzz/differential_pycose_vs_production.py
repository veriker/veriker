"""Differential harness: pycose vs production verify_cross_host_authenticator_cose.

Feeds each envelope through both verifiers under the same fixed
(pinned_pubkey, preimage, external_aad) configuration. The contract is:

    BOTH must agree on PASS/FAIL.

Divergences are findings — they typically indicate either (a) a spec-
conformance gap in our verifier (we accept something pycose rejects, or
vice versa), or (b) a known-and-deliberate stricter policy of one side.

The harness runs against the existing tests/fuzz/corpus/cose_bundle_layer3/
seeds (curated + libfuzzer-grown). Stdout reports per-input verdicts and a
final divergence count.

Same deterministic key + preimage as atheris_verify_cose_bundle.py and
atheris_verify_cose_layer3.py (so any envelope minted in those harnesses
that we save also flows through this).
"""
from __future__ import annotations

import sys
import cbor2
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pycose.messages import Sign1Message
from pycose.keys import OKPKey
from pycose.algorithms import EdDSA
from pycose.keys.curves import Ed25519
from pycose.keys.keyparam import KpAlg

from audit_bundle.extensions.c19.cross_host_peerreview import (
    verify_cross_host_authenticator_cose,
)

# Pin same deterministic seed used in Layer 2/3 atheris harnesses.
_SK_BYTES = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)
_SK = Ed25519PrivateKey.from_private_bytes(_SK_BYTES)
_PK_BYTES = _SK.public_key().public_bytes_raw()
_PREIMAGE = b"v-kernel layer-2 cose fuzz canonical preimage"
_CROSS_HOST_AAD = b"nexi:c19:cross-host-receipt:v0.4"


def _pycose_verdict(cose_bytes: bytes) -> tuple[str, str]:
    """Returns (verdict, why) where verdict in {"PASS","FAIL"}."""
    verifier_key = OKPKey(
        crv=Ed25519,
        x=_PK_BYTES,
        optional_params={KpAlg: EdDSA},
    )
    try:
        decoded = cbor2.loads(cose_bytes)
    except Exception as exc:
        return "FAIL", f"cbor-decode: {type(exc).__name__}"
    if not isinstance(decoded, (list, tuple)) or len(decoded) != 4:
        return "FAIL", "not-4-elem-array"
    try:
        msg = Sign1Message.from_cose_obj(
            list(decoded), allow_unknown_attributes=False
        )
        msg.key = verifier_key
        msg.external_aad = _CROSS_HOST_AAD
        msg.payload = _PREIMAGE  # detached payload
        ok = msg.verify_signature()
    except Exception as exc:
        return "FAIL", f"pycose-{type(exc).__name__}"
    return ("PASS" if ok else "FAIL"), "ok" if ok else "sig-mismatch"


def _production_verdict(cose_bytes: bytes) -> tuple[str, str]:
    try:
        ok, code, detail = verify_cross_host_authenticator_cose(
            public_key_raw=_PK_BYTES, preimage=_PREIMAGE, cose_bytes=cose_bytes
        )
    except Exception as exc:
        return "FAIL", f"raised-{type(exc).__name__}"
    return ("PASS" if ok else "FAIL"), code


def differential_one(cose_bytes: bytes, label: str = "<envelope>") -> bool:
    """Run both verifiers on one input; return True iff they agree."""
    py_v, py_why = _pycose_verdict(cose_bytes)
    pr_v, pr_why = _production_verdict(cose_bytes)
    agree = py_v == pr_v
    marker = "OK " if agree else "DIV"
    print(
        f"  [{marker}] {label}: pycose={py_v}({py_why})  production={pr_v}({pr_why})"
    )
    return agree


def main() -> int:
    corpus_dirs = [
        Path("tests/fuzz/corpus/cose_bundle"),
        Path("tests/fuzz/corpus/cose_bundle_layer3"),
        Path("tests/fuzz/crashes/cose_bundle"),
        Path("tests/fuzz/crashes/cose_bundle_layer3"),
    ]
    inputs: list[tuple[str, bytes]] = []
    for d in corpus_dirs:
        if not d.exists():
            continue
        for f in sorted(d.iterdir()):
            if f.is_file():
                inputs.append((f"{d.name}/{f.name}", f.read_bytes()))

    print(f"Differential pycose vs verify_cross_host_authenticator_cose")
    print(f"  inputs: {len(inputs)}")
    print(f"  pubkey: {_PK_BYTES.hex()}")
    print(f"  preimage: {_PREIMAGE!r}")
    print(f"  external_aad: {_CROSS_HOST_AAD!r}")
    print()

    divergences: list[str] = []
    for label, blob in inputs:
        if not differential_one(blob, label):
            divergences.append(label)

    print()
    print(f"Total inputs: {len(inputs)}")
    print(f"Divergences:  {len(divergences)}")
    for d in divergences:
        print(f"  - {d}")
    return 1 if divergences else 0


if __name__ == "__main__":
    sys.exit(main())
