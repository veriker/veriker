"""DSSE envelope fuzz harness: verify_envelope must never raise uncaught.

Oracle: every fuzzed byte sequence fed to verify_envelope must produce a
VerifyEnvelopeResult (ok, reason_code, payload_bytes, kid, detail).
An uncaught exception or a non-VerifyEnvelopeResult return is a §C9 contract
break — it means a hostile peer can crash or DoS the verifier.

Coverage targets:
  - Duplicate JSON keys
  - Unknown top-level / signature fields
  - Truncated / trailing bytes
  - Multi-signature or zero-signature arrays
  - Overflow-length integers in framing positions
  - Garbage base64 strings in payload / sig / keyid fields
  - Non-UTF-8 byte sequences

The harness uses a FIXED allowlist (one known key) so that a well-formed
signed envelope can occasionally pass the gate and exercise the success path.

Run (requires atheris installed in the venv):
    .venv/bin/python tests/fuzz/atheris_dsse_envelope.py \\
        -max_total_time=120 \\
        -print_final_stats=1 \\
        -artifact_prefix=tests/fuzz/crashes/dsse/ \\
        tests/fuzz/corpus/dsse/

This file is NOT collected by pytest (atheris is not installed in CI).
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from audit_bundle.dsse.envelope import VerifyEnvelopeResult, verify_envelope
    from audit_bundle.dsse.pae import kid_from_raw32

# ---------------------------------------------------------------------------
# Fixed allowlist — one known key so sign→verify can exercise the ok=True path.
# ---------------------------------------------------------------------------

_SEED: bytes = b"\xab" * 32
_SIGNING_KEY: Ed25519PrivateKey = Ed25519PrivateKey.from_private_bytes(_SEED)
_PUBKEY_RAW32: bytes = _SIGNING_KEY.public_key().public_bytes_raw()
_KID: str = kid_from_raw32(_PUBKEY_RAW32)
_ALLOWLIST: dict[str, bytes] = {_KID: _PUBKEY_RAW32}


def test_one(data: bytes) -> None:
    """Feed fuzzed bytes to verify_envelope; assert structured result."""
    result = verify_envelope(data, _ALLOWLIST)

    # Contract: must return a VerifyEnvelopeResult, never raise.
    assert isinstance(result, VerifyEnvelopeResult), (
        f"verify_envelope returned {type(result).__name__}, expected VerifyEnvelopeResult"
    )
    assert isinstance(result.ok, bool), (
        f"result.ok is {type(result.ok).__name__}, expected bool"
    )
    if result.ok:
        assert result.reason_code is None, (
            f"ok=True but reason_code={result.reason_code!r}"
        )
        assert isinstance(result.payload_bytes, bytes), (
            f"ok=True but payload_bytes is {type(result.payload_bytes).__name__}"
        )
        assert isinstance(result.kid, str), (
            f"ok=True but kid is {type(result.kid).__name__}"
        )
    else:
        assert isinstance(result.reason_code, str), (
            f"ok=False but reason_code is {type(result.reason_code).__name__}"
        )
    assert isinstance(result.detail, str), (
        f"result.detail is {type(result.detail).__name__}, expected str"
    )


def main() -> None:
    atheris.Setup(sys.argv, test_one)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
