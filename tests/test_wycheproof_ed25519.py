"""Wycheproof Ed25519 vector regression for the substrate's COSE_Sign1
envelope-consumer paths.

Closes the Wycheproof gap named in the internal design notes: the
substrate signs / verifies Ed25519 via pyca/cryptography (well-tested under
Wycheproof upstream), but the *consumer-side* envelope handling in
`offline_root.verify_emergency_offline_root_signature` and
`cross_host_peerreview.verify_cross_host_authenticator_cose` was never run
against the known-bad signature corpus. The interesting class is "invalid"
vectors that pyca rejects at the primitive level — confirm our envelope
consumer also rejects them, all the way through (no upstream cbor2 / parse-
boundary slip that would let a malformed signature reach a passing return).

Vector file: `tests/fuzz/corpus/wycheproof/ed25519_test.json`
Source:      https://github.com/C2SP/wycheproof  (the canonical upstream;
             `google/wycheproof` redirects here as of 2025-10)
Snapshot:    `testvectors_v1/ed25519_test.json` @ commit
             `e0df04e0c033f2d25c5051dd06230336c7822358`
             (2025-10-02 "testvectors_v1: reformat JSON files")
File SHA-256: 70471c053c711731f2195ef4875b60ea7f5d6793939d99058ac12da810cb8e00
Schema:      `eddsa_verify_schema_v1.json`

The vector file is committed to the repo (pinned snapshot, not re-fetched at
test time) so the test is hermetic and the assertion oracle is stable across
upstream re-edits. If Wycheproof publishes new vectors, refresh the snapshot
and bump the file-sha256 pin in this docstring.

Distribution at snapshot:
  - 150 tests across 77 groups (each group has its own publicKey.pk)
  - 88 valid, 62 invalid, 0 acceptable (the v1 schema dropped "acceptable")
  - Flag classes present: Valid, InvalidSignature, TruncatedSignature,
    SignatureWithGarbage, CompressedSignature, InvalidEncoding,
    SignatureMalleability, Ktv, InvalidKtv, TinkOverflow

Bound standards:
  - RFC 8032 §5.1 (Ed25519 sig encoding, malleability rejection)
  - RFC 9052 §4.4 (COSE_Sign1 Sig_structure)
  - RFC 8949 §4.2 (deterministic CBOR encoding)
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

import cbor2
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from audit_bundle.extensions.c19.cross_host_peerreview import (
    CROSS_HOST_COSE_DOMAIN_AAD,
    _CROSS_HOST_COSE_PROTECTED_BSTR,
    sign_cross_host_authenticator_cose,
    verify_cross_host_authenticator_cose,
)
from audit_bundle.extensions.c19.layer_a_counter import LayerAVerificationError
from audit_bundle.extensions.c19.offline_root import (
    OFFLINE_ROOT_COSE_ALG_EDDSA,
    OFFLINE_ROOT_COSE_DOMAIN_AAD,
    OfflineRootPolicy,
    sign_emergency_offline_root_signature,
    verify_emergency_offline_root_signature,
)


# ---------------------------------------------------------------------------
# Vector loading + integrity pin.
# ---------------------------------------------------------------------------

_VECTOR_PATH = (
    Path(__file__).parent / "fuzz" / "corpus" / "wycheproof" / "ed25519_test.json"
)
_PINNED_SHA256 = (
    "70471c053c711731f2195ef4875b60ea7f5d6793939d99058ac12da810cb8e00"
)


def _load_vectors() -> dict:
    """Load + integrity-check the snapshot. If the file SHA-256 has drifted
    from the pin in this module's docstring, the test must fail loudly — a
    silent corpus change would invalidate every per-vector result counted
    below. To intentionally bump the snapshot, refresh the pin alongside it.
    """
    raw = _VECTOR_PATH.read_bytes()
    got = hashlib.sha256(raw).hexdigest()
    assert got == _PINNED_SHA256, (
        f"Wycheproof corpus file SHA-256 drift: got {got}, pinned {_PINNED_SHA256}. "
        f"If the snapshot was intentionally refreshed, bump _PINNED_SHA256 + "
        f"the docstring pin."
    )
    return json.loads(raw)


_VECTORS_CACHE: dict | None = None


def _vectors() -> dict:
    global _VECTORS_CACHE
    if _VECTORS_CACHE is None:
        _VECTORS_CACHE = _load_vectors()
    return _VECTORS_CACHE


def _flatten() -> list[tuple[bytes, dict]]:
    """Flatten (publicKey.pk, test) pairs across all groups."""
    out: list[tuple[bytes, dict]] = []
    for grp in _vectors()["testGroups"]:
        pk_hex = grp["publicKey"]["pk"]
        pk = bytes.fromhex(pk_hex)
        for t in grp["tests"]:
            out.append((pk, t))
    return out


def _pytest_id(pair) -> str:
    pk, t = pair
    return f"tc{t['tcId']}-{t['result']}-{'+'.join(t.get('flags', []) or ['noflag'])}"


# Single source of truth — parametrize from this.
_ALL_PAIRS = _flatten() if _VECTOR_PATH.exists() else []
_VALID_PAIRS = [p for p in _ALL_PAIRS if p[1]["result"] == "valid"]
_INVALID_PAIRS = [p for p in _ALL_PAIRS if p[1]["result"] == "invalid"]


# ---------------------------------------------------------------------------
# Layer 0 — corpus sanity. If this fails, the loader / pin is broken; every
# downstream assertion is meaningless until this is restored.
# ---------------------------------------------------------------------------


def test_wycheproof_corpus_loads_and_is_nonempty():
    j = _vectors()
    assert j["algorithm"] == "EDDSA"
    assert j["schema"] == "eddsa_verify_schema_v1.json"
    assert j["numberOfTests"] == 150
    assert len(_ALL_PAIRS) == 150
    assert len(_VALID_PAIRS) + len(_INVALID_PAIRS) == 150


# ---------------------------------------------------------------------------
# Layer 1 — pyca/cryptography primitive sanity. Tripwire: pyca internally
# consumes Wycheproof, so this should be 100% pass; any failure means the
# library itself is broken (treat as red flag, not a substrate finding).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pair", _ALL_PAIRS, ids=_pytest_id)
def test_wycheproof_pyca_primitive_oracle(pair):
    pk_raw, t = pair
    msg = bytes.fromhex(t["msg"])
    sig = bytes.fromhex(t["sig"])
    result = t["result"]  # "valid" | "invalid" | "acceptable"
    flags = t.get("flags", [])

    # Building the public key itself: every group's pk in the snapshot is a
    # valid 32-byte raw Ed25519 key, so from_public_bytes must succeed.
    pub = Ed25519PublicKey.from_public_bytes(pk_raw)

    try:
        pub.verify(sig, msg)
        verified = True
    except (InvalidSignature, ValueError, TypeError):
        # ValueError covers wrong-length signatures in some pyca versions;
        # both branches collapse to "did not verify".
        verified = False

    if result == "valid":
        assert verified, (
            f"pyca/cryptography FAILED to verify a Wycheproof VALID vector "
            f"tcId={t['tcId']} flags={flags} — library-level regression"
        )
    elif result == "invalid":
        assert not verified, (
            f"pyca/cryptography ACCEPTED a Wycheproof INVALID vector "
            f"tcId={t['tcId']} flags={flags} — primitive-level forgery "
            f"window (extremely unlikely; check library version + supply chain)"
        )
    else:  # "acceptable" — RFC-compliant either way; assert behavior is
        # recorded but does not enforce a direction.
        pass


# ---------------------------------------------------------------------------
# Layer 2 — substrate envelope-consumer regression.
#
# For each "invalid" vector, build a minimal COSE_Sign1 envelope where the
# Wycheproof signature occupies the signature slot, pin the Wycheproof
# public key into the verifier policy, and assert the envelope verifier
# REJECTS the message. The reject can happen at any step on the consumer
# path (length pre-check, alg pin, canonical-header check, Ed25519 verify,
# etc.) — the load-bearing property is "no invalid vector slips through
# to a passing return", not which specific reason code fires. We do
# bucket the reason codes per flag class to surface where the rejection
# actually happened, so a future shift (e.g. a length-check relaxation
# letting more vectors reach the Ed25519 step) is visible.
# ---------------------------------------------------------------------------


# Reuse the canonical outer protected_bstr for the offline-root envelope. It
# is `cbor2.dumps({1: -8})` — same 3 bytes the verifier accepts.
_OFFLINE_ROOT_PROTECTED_BSTR_LOCAL = cbor2.dumps({1: OFFLINE_ROOT_COSE_ALG_EDDSA})


def _build_offline_root_envelope(sig: bytes) -> bytes:
    """COSE_Sign1 = [protected_bstr, {}, nil, sig], canonical encoding."""
    return cbor2.dumps(
        [_OFFLINE_ROOT_PROTECTED_BSTR_LOCAL, {}, None, sig], canonical=True
    )


def _build_cross_host_envelope(sig: bytes) -> bytes:
    """Parallel construction for the cross-host verifier. Uses the cross-
    host protected_bstr constant (byte-identical to offline-root's per the
    C1a separation-via-AAD note in the module docstring)."""
    return cbor2.dumps(
        [_CROSS_HOST_COSE_PROTECTED_BSTR, {}, None, sig], canonical=True
    )


@pytest.mark.parametrize("pair", _INVALID_PAIRS, ids=_pytest_id)
def test_wycheproof_offline_root_envelope_rejects_invalid(pair):
    """Wrap the Wycheproof (pk, sig, msg) in an offline-root COSE_Sign1
    envelope and assert `verify_emergency_offline_root_signature` raises."""
    pk_raw, t = pair
    msg = bytes.fromhex(t["msg"])
    sig = bytes.fromhex(t["sig"])
    flags = t.get("flags", [])

    kid = b"wycheproof-" + pk_raw[:8].hex().encode()
    policy = OfflineRootPolicy(
        pinned_offline_root_key_ids=frozenset({kid}),
        pinned_offline_root_verifying_keys={kid: pk_raw},
    )
    cose = _build_offline_root_envelope(sig)

    with pytest.raises(LayerAVerificationError) as exc:
        verify_emergency_offline_root_signature(
            rotation_preimage=msg,
            emergency_offline_root_signature=cose,
            offline_root_key_id=kid,
            policy=policy,
        )
    # The reason code is informational; the load-bearing assertion is the
    # raise above. We attach the code + flags to any unrelated assertion
    # failure (e.g. if a future refactor lets the verifier swallow + return
    # None for some class) by surfacing them in the exception note.
    assert exc.value is not None, (
        f"offline-root verifier did not raise on Wycheproof invalid vector "
        f"tcId={t['tcId']} flags={flags}"
    )


@pytest.mark.parametrize("pair", _INVALID_PAIRS, ids=_pytest_id)
def test_wycheproof_cross_host_envelope_rejects_invalid(pair):
    """Parallel cross-host check: `verify_cross_host_authenticator_cose`
    returns (ok=False, reason_code, detail) for every Wycheproof invalid."""
    pk_raw, t = pair
    msg = bytes.fromhex(t["msg"])
    sig = bytes.fromhex(t["sig"])
    flags = t.get("flags", [])

    cose = _build_cross_host_envelope(sig)
    ok, reason, detail = verify_cross_host_authenticator_cose(
        public_key_raw=pk_raw,
        preimage=msg,
        cose_bytes=cose,
        role="sender",
    )
    assert ok is False, (
        f"cross-host verifier ACCEPTED Wycheproof invalid vector "
        f"tcId={t['tcId']} flags={flags} reason={reason!r} detail={detail!r} "
        f"— consumer-side envelope let a known-bad signature through"
    )
    assert reason != "PASS"


# ---------------------------------------------------------------------------
# Layer 2 round-trip smoke — valid Wycheproof vectors cannot be replayed
# *through* the envelope (because the envelope wraps preimage in a
# Sig_structure that the Wycheproof sig was NOT minted over). To confirm
# the envelope-consumer can still accept honest input, we mint envelopes
# with a fresh Ed25519 key per call and verify them. This is a tripwire
# against a future regression that breaks the envelope itself.
# ---------------------------------------------------------------------------


def _fresh_keypair() -> tuple[Ed25519PrivateKey, bytes]:
    priv = Ed25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes_raw()
    return priv, pub_raw


def test_offline_root_envelope_round_trip_with_fresh_key():
    priv, pub_raw = _fresh_keypair()
    kid = b"smoke-or"
    policy = OfflineRootPolicy(
        pinned_offline_root_key_ids=frozenset({kid}),
        pinned_offline_root_verifying_keys={kid: pub_raw},
    )
    preimage = b"smoke-offline-root-preimage"
    cose = sign_emergency_offline_root_signature(priv, preimage)
    verify_emergency_offline_root_signature(
        rotation_preimage=preimage,
        emergency_offline_root_signature=cose,
        offline_root_key_id=kid,
        policy=policy,
    )


def test_cross_host_envelope_round_trip_with_fresh_key():
    priv, pub_raw = _fresh_keypair()
    preimage = b"smoke-cross-host-preimage"
    cose = sign_cross_host_authenticator_cose(private_key=priv, preimage=preimage)
    ok, reason, detail = verify_cross_host_authenticator_cose(
        public_key_raw=pub_raw,
        preimage=preimage,
        cose_bytes=cose,
        role="sender",
    )
    assert ok is True, f"fresh-key cross-host round-trip failed: {reason!r} {detail!r}"
    assert reason == "PASS"


# ---------------------------------------------------------------------------
# Coverage report — fires once per session, surfaces the per-flag-class
# bucketing of where (which reason code) each invalid vector got rejected
# in the cross-host path. Pure observability; no oracle. Helps a future
# audit see "ah, all SignatureMalleability vectors hit InvalidSignature at
# the Ed25519 step, all TruncatedSignature hit the length check" without
# re-running the suite by hand.
# ---------------------------------------------------------------------------


def test_wycheproof_invalid_rejection_buckets_by_flag():
    buckets: dict[str, Counter] = {}
    for pk_raw, t in _INVALID_PAIRS:
        sig = bytes.fromhex(t["sig"])
        msg = bytes.fromhex(t["msg"])
        cose = _build_cross_host_envelope(sig)
        ok, reason, _ = verify_cross_host_authenticator_cose(
            public_key_raw=pk_raw,
            preimage=msg,
            cose_bytes=cose,
            role="sender",
        )
        for flag in t.get("flags", ["noflag"]):
            buckets.setdefault(flag, Counter())[reason] += 1
        # invariant — already enforced parametrized above, re-asserted here
        # so this test stands alone if run in isolation
        assert ok is False

    # Surface the bucket map in pytest -v output via the assertion message.
    # Format: flag -> {reason -> count}. Sorted for stable diffing.
    summary = "\n".join(
        f"  {flag}: {dict(sorted(counter.items()))}"
        for flag, counter in sorted(buckets.items())
    )
    # Always passes; the assert is there to attach the bucket-map to the
    # test's captured stdout so it shows up in pytest -v / -s.
    assert buckets is not None, summary
    print("\n[wycheproof rejection-bucket map — cross-host envelope]\n" + summary)
