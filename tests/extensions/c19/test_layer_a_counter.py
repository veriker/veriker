"""Broken-first test suite per `the internal design notes`.
Run pytest BEFORE the real impl lands — expect ALL tests to fail with ImportError
(the M0 stub is docstring-only). That is the broken-first gate. Then sc19a-002..008
fill in the real impl and ALL tests MUST pass without modification to this file.

Adversarial classes encoded (from the audit-bundle contract §"C19
Adversary model" table ~ line 724):
  R3-002  receipt-bytes binding
  R3-003  verify-then-parse pipeline ordering
  R3-004  HKDF-derive-then-HMAC (NOT HKDF-as-prefix) + per-context separation
  R3-006  CBOR-processing-layer policy (pre-CDDL)
  R3-007  TUF-pinned SCITT trust
  R4-002 / R4-ADD-2  duplicate-key rejection pre-CDDL
  R4-007 / R4-ADD-3  event-signature preimage canonical order
  Round-2 B1  counter forgeability (gap / index mismatch / hash-chain break)
  RFC 9052    COSE_Sign1 shape (alg in protected, alg=none rejected)
  Forward-compat  EVENT_KIND_UNKNOWN
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

import cbor2
import pytest

# Import surface drives the real-impl API surface. Sc19a-001 lands this file
# BEFORE the implementation; expect ImportError until sc19a-003 stubs land.
from audit_bundle.extensions.c19.layer_a_counter import (  # noqa: F401
    LayerACounterPlugin,
    LayerAVerificationError,
    PROTOCOL_VERSION,
    ReasonCode,
    canonical_event_preimage,
    compute_bundle_merkle_root,
    compute_event_hash,
    compute_event_signature,
    deterministic_cbor_encode,
    derive_event_signature_key,
    issue_scitt_statement,
    scan_cbor_for_policy_violations,
    verify_bundle_layer_a,
    verify_event_signature,
    verify_scitt_receipt,
)


# ---------------------------------------------------------------------------
# Fixtures — minimal builders for happy-path + adversarial cases.
# ---------------------------------------------------------------------------


@pytest.fixture
def host_ikm() -> bytes:
    """32-byte HMAC IKM; deterministic for tests."""
    return b"\x11" * 32


@pytest.fixture
def host_id() -> str:
    return "host-A"


@pytest.fixture
def bundle_id() -> str:
    return "11111111-1111-4111-8111-111111111111"


def _zero_hash() -> bytes:
    return b"\x00" * 32


def _payload_hash(blob: bytes) -> bytes:
    return hashlib.sha256(blob).digest()


# ---------------------------------------------------------------------------
# POSITIVE — happy paths land in sc19a-008 (pipeline orchestrator) but the
# scaffolding lives here.
# ---------------------------------------------------------------------------


def test_happy_path_single_event_chain(host_ikm, host_id, bundle_id):
    """One host, one bundle, one root event; counter=1; chain integrity holds."""
    from audit_bundle.extensions.c19.layer_a_counter import verify_chain_integrity

    payload_hash = _payload_hash(b"event-1 payload")
    ev = {
        "event_id": "ev-1",
        "prev_event_id": None,
        "prev_event_hash": _zero_hash(),
        "monotonic_counter": 1,
        "counter_log_index": 1,
        "event_kind": "retrieval",
        "payload_hash": payload_hash,
    }
    merkle_root = verify_chain_integrity([ev])
    assert isinstance(merkle_root, bytes) and len(merkle_root) == 32


def test_happy_path_three_event_chain(host_ikm, host_id, bundle_id):
    from audit_bundle.extensions.c19.layer_a_counter import verify_chain_integrity

    events = []
    prev_hash = _zero_hash()
    for i in range(1, 4):
        ev = {
            "event_id": f"ev-{i}",
            "prev_event_id": None if i == 1 else f"ev-{i - 1}",
            "prev_event_hash": prev_hash,
            "monotonic_counter": i,
            "counter_log_index": i,
            "event_kind": "reasoning_step",
            "payload_hash": _payload_hash(f"event-{i}".encode()),
        }
        events.append(ev)
        prev_hash = compute_event_hash(deterministic_cbor_encode(ev))
    merkle_root = verify_chain_integrity(events)
    assert len(merkle_root) == 32


# ---------------------------------------------------------------------------
# R3-002 — receipt-bytes binding
# ---------------------------------------------------------------------------


def test_scitt_receipt_payload_mismatch_rejected():
    """Receipt verifies COSE_Sign1 over bytes B1, but event.scitt_statement_content_sha256
    asserts B2. Verifier MUST emit SCITT_RECEIPT_PAYLOAD_MISMATCH."""
    from audit_bundle.extensions.c19.layer_a_counter import (
        ScittReceipt,
        verify_scitt_receipt,
    )

    pinned_kid = b"k1"
    pinned_keys = _fresh_eddsa_keypair(pinned_kid)
    # Receipt covers cose_payload_bytes = b"REAL"; but the bundle claims
    # statement_content_sha256 hashes b"FAKE" — mismatch on (5) of pipeline.
    real_bytes = b"REAL"
    fake_sha = hashlib.sha256(b"FAKE").digest()
    receipt = ScittReceipt(
        statement_id=hashlib.sha256(real_bytes).digest(),
        statement_content_sha256=fake_sha,  # the lie
        cose_payload_bytes=real_bytes,
        receipt_bytes=_well_formed_cose_sign1(
            real_bytes, pinned_keys["signing"], pinned_kid
        ),
        ts_key_id=pinned_kid,
    )
    with pytest.raises(LayerAVerificationError) as exc:
        verify_scitt_receipt(
            receipt=receipt,
            pinned_ts_key_ids=frozenset({pinned_kid}),
            pinned_ts_verifying_keys={pinned_kid: pinned_keys["verifying"]},
        )
    assert exc.value.code is ReasonCode.SCITT_RECEIPT_PAYLOAD_MISMATCH


# ---------------------------------------------------------------------------
# R3-003 — verify-then-parse pipeline ordering
# ---------------------------------------------------------------------------


def test_parse_then_verify_probe_attack_rejected():
    """Bundle ships invalid SCITT receipt but malformed CDDL designed to crash a
    parse-then-verify pipeline. Verifier MUST short-circuit at SCITT verify
    stage and NEVER touch CDDL on untrusted bytes."""
    pinned_kid = b"k1"
    pinned_keys = _fresh_eddsa_keypair(pinned_kid)
    # bundle_bytes is a small, malformed-after-SCITT-extraction blob:
    # SCITT extraction will succeed but verification will fail BEFORE any
    # CBOR-processing-layer / CDDL validation touches the bundle's structural
    # parse. We use a layer_a dict shape that would crash CDDL if it ever ran.
    pinned_issuer = {"host-A": b"\x11" * 32}
    layer_a = _malformed_layer_a_with_bad_scitt_receipt(
        pinned_kid, pinned_keys, host_id="host-A"
    )
    bundle_bytes = b"\x00" * 1024
    with pytest.raises(LayerAVerificationError) as exc:
        verify_bundle_layer_a(
            bundle_bytes=bundle_bytes,
            layer_a=layer_a,
            pinned_ts_key_ids=frozenset({pinned_kid}),
            pinned_ts_verifying_keys={pinned_kid: pinned_keys["verifying"]},
            pinned_issuer_keys=pinned_issuer,
        )
    # The verifier must abort at the SCITT stage (RECEIPT_VERIFICATION_FAILED
    # or RECEIPT_PAYLOAD_MISMATCH or TS_KEY_MISMATCH) — NOT at CDDL.
    assert exc.value.code in {
        ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED,
        ReasonCode.SCITT_RECEIPT_PAYLOAD_MISMATCH,
        ReasonCode.SCITT_TS_KEY_MISMATCH,
    }


def test_bundle_too_large_rejected():
    """Bundle byte stream exceeds MAX_BUNDLE_BYTES; verifier emits BUNDLE_TOO_LARGE
    BEFORE any parsing."""
    from audit_bundle.extensions.c19.layer_a_counter import MAX_BUNDLE_BYTES

    huge = b"\x00" * (MAX_BUNDLE_BYTES + 1)
    with pytest.raises(LayerAVerificationError) as exc:
        verify_bundle_layer_a(
            bundle_bytes=huge,
            layer_a={},  # never inspected — fails at size guard
            pinned_ts_key_ids=frozenset(),
            pinned_ts_verifying_keys={},
            pinned_issuer_keys={},
        )
    assert exc.value.code is ReasonCode.BUNDLE_TOO_LARGE


# ---------------------------------------------------------------------------
# R3-004 — HKDF-derive-then-HMAC + context separation
# ---------------------------------------------------------------------------


def test_hkdf_output_as_prefix_rejected(host_ikm, host_id, bundle_id):
    """Forged sig built via OLD pattern HKDF-Expand(info)||event_bytes used as
    HMAC input must NOT verify under the corrected construction."""
    k_event = derive_event_signature_key(host_ikm)
    # Build canonical preimage using correct construction
    preimage = canonical_event_preimage(
        host_id=host_id,
        event_id="ev-1",
        prev_event_hash=_zero_hash(),
        bundle_id=bundle_id,
        monotonic_counter=1,
        payload_hash=_payload_hash(b"x"),
    )
    # Forged sig: attacker mixes HKDF output as prefix to message body, then
    # MACs under host_ikm (or any key choice). Verifier rejects.
    bogus_sig = hmac.new(host_ikm, k_event + preimage, hashlib.sha256).digest()
    assert verify_event_signature(k_event, preimage, bogus_sig) is False


def test_context_separation_event_vs_cross_host_distinct_keys(host_ikm):
    """Identical IKM, distinct info labels → distinct keys → MAC under one does
    NOT verify under the other over identical data."""
    from audit_bundle.extensions.c19.layer_a_counter import (
        _CTX_CROSS_HOST_RECEIPT,
        _CTX_EVENT,
        _hkdf_expand,
        _hkdf_extract,
    )

    prk = _hkdf_extract(salt=b"", ikm=host_ikm)
    k_event = _hkdf_expand(prk, info=_CTX_EVENT, length=32)
    k_ack = _hkdf_expand(prk, info=_CTX_CROSS_HOST_RECEIPT, length=32)
    assert k_event != k_ack
    data = b"identical-message"
    sig_under_event = hmac.new(k_event, data, hashlib.sha256).digest()
    assert verify_event_signature(k_ack, data, sig_under_event) is False


# ---------------------------------------------------------------------------
# R3-006 / R4-ADD-2 — CBOR-processing-layer policy precedes CDDL
# ---------------------------------------------------------------------------


def _make_duplicate_key_cbor() -> bytes:
    """Hand-craft a CBOR map with two `payload_hash` keys (V1, V2).

    Per RFC 8949 §3 a CBOR map header A2 declares 2 key-value pairs. cbor2's
    loads() silently keeps the last value on duplicates; the byte-stream
    scanner must catch this at the byte level.
    """
    key = cbor2.dumps("payload_hash")  # text string
    v1 = cbor2.dumps(b"\x01" * 32)
    v2 = cbor2.dumps(b"\x02" * 32)
    # Map of definite length 2
    return b"\xa2" + key + v1 + key + v2


def test_cbor_duplicate_key_rejected_pre_cddl():
    blob = _make_duplicate_key_cbor()
    with pytest.raises(LayerAVerificationError) as exc:
        scan_cbor_for_policy_violations(blob)
    assert exc.value.code is ReasonCode.CBOR_DUPLICATE_KEY


def test_cbor_indefinite_length_rejected():
    # 0x5f = byte string, indefinite length (RFC 8949 §3.2.2)
    blob = b"\x5f\x42\xaa\xbb\xff"
    with pytest.raises(LayerAVerificationError) as exc:
        scan_cbor_for_policy_violations(blob)
    assert exc.value.code is ReasonCode.CBOR_INDEFINITE_LENGTH


def test_cbor_tag_not_allowed_rejected():
    # Tag 0 (standard date/time string) — outside allowlist {18}
    blob = cbor2.dumps(cbor2.CBORTag(0, "2026-05-20"))
    with pytest.raises(LayerAVerificationError) as exc:
        scan_cbor_for_policy_violations(blob)
    assert exc.value.code is ReasonCode.CBOR_TAG_NOT_ALLOWED


# ---------------------------------------------------------------------------
# R4-ADD-3 / R4-007 — event-signature preimage canonical order
# ---------------------------------------------------------------------------


def test_preimage_canonical_order_locked(host_id, bundle_id):
    """Canonical order is [ctx_label, protocol_version, host_id, event_id,
    prev_event_hash, bundle_id, monotonic_counter, payload_hash]. Swapping
    prev_event_hash to position 3 (BEFORE event_id) MUST produce distinct bytes."""
    canonical = canonical_event_preimage(
        host_id=host_id,
        event_id="ev-1",
        prev_event_hash=_zero_hash(),
        bundle_id=bundle_id,
        monotonic_counter=1,
        payload_hash=_payload_hash(b"x"),
    )
    # Wrong-order encoding by hand: prev_event_hash placed BEFORE event_id.
    wrong_order = deterministic_cbor_encode(
        [
            "nexi/audit/v0.3/event",
            PROTOCOL_VERSION,
            host_id,
            _zero_hash(),  # WRONG: prev_event_hash here
            "ev-1",
            bundle_id,
            1,
            _payload_hash(b"x"),
        ]
    )
    assert canonical != wrong_order


# ---------------------------------------------------------------------------
# Round-2 B1 — counter forgeability
# ---------------------------------------------------------------------------


def test_counter_gap_detected():
    from audit_bundle.extensions.c19.layer_a_counter import verify_chain_integrity

    events = [
        {
            "event_id": "a",
            "prev_event_id": None,
            "prev_event_hash": _zero_hash(),
            "monotonic_counter": 1,
            "counter_log_index": 1,
            "event_kind": "retrieval",
            "payload_hash": _payload_hash(b"a"),
        },
        {
            "event_id": "b",
            "prev_event_id": "a",
            "prev_event_hash": b"\x00" * 32,
            "monotonic_counter": 2,
            "counter_log_index": 2,
            "event_kind": "retrieval",
            "payload_hash": _payload_hash(b"b"),
        },
        # GAP: jumps to 4
        {
            "event_id": "c",
            "prev_event_id": "b",
            "prev_event_hash": b"\x00" * 32,
            "monotonic_counter": 4,
            "counter_log_index": 4,
            "event_kind": "retrieval",
            "payload_hash": _payload_hash(b"c"),
        },
    ]
    with pytest.raises(LayerAVerificationError) as exc:
        verify_chain_integrity(events)
    assert exc.value.code is ReasonCode.COUNTER_GAP_DETECTED


def test_counter_log_index_mismatch_rejected():
    from audit_bundle.extensions.c19.layer_a_counter import verify_chain_integrity

    ev = {
        "event_id": "a",
        "prev_event_id": None,
        "prev_event_hash": _zero_hash(),
        "monotonic_counter": 1,
        "counter_log_index": 99,  # mismatch
        "event_kind": "retrieval",
        "payload_hash": _payload_hash(b"a"),
    }
    with pytest.raises(LayerAVerificationError) as exc:
        verify_chain_integrity([ev])
    assert exc.value.code is ReasonCode.COUNTER_GAP_DETECTED


def test_hash_chain_broken_rejected():
    from audit_bundle.extensions.c19.layer_a_counter import verify_chain_integrity

    ev_a = {
        "event_id": "a",
        "prev_event_id": None,
        "prev_event_hash": _zero_hash(),
        "monotonic_counter": 1,
        "counter_log_index": 1,
        "event_kind": "retrieval",
        "payload_hash": _payload_hash(b"a"),
    }
    ev_b = {
        "event_id": "b",
        "prev_event_id": "a",
        "prev_event_hash": b"\xde" * 32,  # NOT sha256(canonical(ev_a))
        "monotonic_counter": 2,
        "counter_log_index": 2,
        "event_kind": "retrieval",
        "payload_hash": _payload_hash(b"b"),
    }
    with pytest.raises(LayerAVerificationError) as exc:
        verify_chain_integrity([ev_a, ev_b])
    assert exc.value.code is ReasonCode.HASH_CHAIN_BROKEN


# ---------------------------------------------------------------------------
# R3-007 — TUF-pinned SCITT trust
# ---------------------------------------------------------------------------


def test_scitt_ts_key_mismatch_rejected():
    pinned_kid = b"good-kid"
    pinned_keys = _fresh_eddsa_keypair(pinned_kid)
    rogue_kid = b"rogue-kid"
    rogue_keys = _fresh_eddsa_keypair(rogue_kid)
    # Receipt signed by rogue key, presented for verification under verifier
    # binary that only pins `good-kid`.
    blob = b"REAL"
    from audit_bundle.extensions.c19.layer_a_counter import ScittReceipt

    receipt = ScittReceipt(
        statement_id=hashlib.sha256(blob).digest(),
        statement_content_sha256=hashlib.sha256(blob).digest(),
        cose_payload_bytes=blob,
        receipt_bytes=_well_formed_cose_sign1(blob, rogue_keys["signing"], rogue_kid),
        ts_key_id=rogue_kid,
    )
    with pytest.raises(LayerAVerificationError) as exc:
        verify_scitt_receipt(
            receipt=receipt,
            pinned_ts_key_ids=frozenset({pinned_kid}),
            pinned_ts_verifying_keys={pinned_kid: pinned_keys["verifying"]},
        )
    assert exc.value.code is ReasonCode.SCITT_TS_KEY_MISMATCH


# ---------------------------------------------------------------------------
# RFC 9052 — COSE_Sign1 shape (alg in protected, alg=none rejected)
# ---------------------------------------------------------------------------


def test_cose_sign1_alg_none_rejected():
    from audit_bundle.extensions.c19.layer_a_counter import ScittReceipt

    pinned_kid = b"k1"
    pinned_keys = _fresh_eddsa_keypair(pinned_kid)
    blob = b"REAL"
    receipt = ScittReceipt(
        statement_id=hashlib.sha256(blob).digest(),
        statement_content_sha256=hashlib.sha256(blob).digest(),
        cose_payload_bytes=blob,
        receipt_bytes=_cose_sign1_alg_none(blob, pinned_kid),
        ts_key_id=pinned_kid,
    )
    with pytest.raises(LayerAVerificationError) as exc:
        verify_scitt_receipt(
            receipt=receipt,
            pinned_ts_key_ids=frozenset({pinned_kid}),
            pinned_ts_verifying_keys={pinned_kid: pinned_keys["verifying"]},
        )
    assert exc.value.code is ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED


def test_cose_sign1_alg_in_unprotected_rejected():
    from audit_bundle.extensions.c19.layer_a_counter import ScittReceipt

    pinned_kid = b"k1"
    pinned_keys = _fresh_eddsa_keypair(pinned_kid)
    blob = b"REAL"
    receipt = ScittReceipt(
        statement_id=hashlib.sha256(blob).digest(),
        statement_content_sha256=hashlib.sha256(blob).digest(),
        cose_payload_bytes=blob,
        receipt_bytes=_cose_sign1_alg_in_unprotected(
            blob, pinned_keys["signing"], pinned_kid
        ),
        ts_key_id=pinned_kid,
    )
    with pytest.raises(LayerAVerificationError) as exc:
        verify_scitt_receipt(
            receipt=receipt,
            pinned_ts_key_ids=frozenset({pinned_kid}),
            pinned_ts_verifying_keys={pinned_kid: pinned_keys["verifying"]},
        )
    assert exc.value.code is ReasonCode.SCITT_RECEIPT_VERIFICATION_FAILED


# ---------------------------------------------------------------------------
# Forward-incompat — EVENT_KIND_UNKNOWN
# ---------------------------------------------------------------------------


def test_event_kind_unknown_rejected():
    from audit_bundle.extensions.c19.layer_a_counter import validate_event_cddl

    ev = {
        b"event_id": "ev-1",
        b"prev_event_id": None,
        b"prev_event_hash": b"\x00" * 32,
        b"monotonic_counter": 1,
        b"counter_log_index": 1,
        b"scitt_statement_id": b"\x00" * 32,
        b"scitt_statement_content_sha256": b"\x00" * 32,
        b"scitt_inclusion_proof": b"\x00",
        b"event_kind": "future_kind_v0_5",  # unknown
        b"payload_hash": b"\x00" * 32,
        b"event_signature": {"key_id": "k", "sig": b"\x00" * 32},
        b"causal_dependencies": [],
    }
    with pytest.raises(LayerAVerificationError) as exc:
        validate_event_cddl(ev)
    assert exc.value.code is ReasonCode.EVENT_KIND_UNKNOWN


# ---------------------------------------------------------------------------
# Backward-compat invariant
# ---------------------------------------------------------------------------


def test_legacy_bundle_no_causal_chain_layer_a_still_verifies():
    """bundle.manifest.causal_chain == None continues to verify cleanly."""
    from audit_bundle.bundle_manifest import BundleManifest

    plugin = _make_default_plugin()

    def _empty_manifest(**overrides):
        defaults = dict(
            schema_version="vcp-v1.1-canary4",
            bundle_id="00000000-0000-4000-8000-000000000000",
            created_at="2026-05-20T00:00:00Z",
            files={},
            spec_files={},
            cross_refs={},
            payload={},
            typed_checks=[],
        )
        defaults.update(overrides)
        return BundleManifest(**defaults)

    m = _empty_manifest(causal_chain=None)
    result = plugin.check(bundle_dir=None, manifest=m)
    assert result.ok is True
    assert result.reason_code == "PASS"

    m2 = _empty_manifest(
        causal_chain={"layer_b": {"placeholder": True}}
    )  # no layer_a key
    result2 = plugin.check(bundle_dir=None, manifest=m2)
    assert result2.ok is True


# ---------------------------------------------------------------------------
# COSE helpers — pycose wrappers used by SCITT receipt tests.
# ---------------------------------------------------------------------------


def _fresh_eddsa_keypair(kid: bytes) -> dict:
    """Return {'signing': pycose key with private material, 'verifying': key with public only}."""
    from pycose.keys import OKPKey
    from pycose.keys.curves import Ed25519
    from pycose.keys.keyparam import KpKid

    # Generate Ed25519 keypair
    sk = OKPKey.generate_key(crv=Ed25519, optional_params={KpKid: kid})
    # OKPKey with both x (public) and d (private) is signing-capable.
    # For verification we duplicate the key but pycose accepts it as-is.
    return {"signing": sk, "verifying": sk, "kid": kid}


def _well_formed_cose_sign1(payload: bytes, signing_key, kid: bytes) -> bytes:
    """COSE_Sign1 with alg=EdDSA in PROTECTED header, kid in protected."""
    from pycose.algorithms import EdDSA
    from pycose.headers import Algorithm, KID
    from pycose.messages import Sign1Message

    msg = Sign1Message(
        phdr={Algorithm: EdDSA, KID: kid},
        uhdr={},
        payload=payload,
    )
    msg.key = signing_key
    return msg.encode()


def _cose_sign1_alg_none(payload: bytes, kid: bytes) -> bytes:
    """Hand-build a COSE_Sign1 envelope with alg absent / alg=none. We bypass
    pycose's encode() (which would refuse) by constructing the raw CBOR array:
        [protected_bstr (CBOR map with NO alg), unprotected_map, payload, sig].
    """
    import cbor2

    protected_map = cbor2.dumps({})  # no alg
    unprotected_map = {4: kid}  # only kid, alg absent
    return cbor2.dumps(
        cbor2.CBORTag(
            18,
            [protected_map, unprotected_map, payload, b"\x00" * 64],
        )
    )


def _cose_sign1_alg_in_unprotected(payload: bytes, signing_key, kid: bytes) -> bytes:
    """COSE_Sign1 with alg ONLY in unprotected headers — RFC 9052 §3.1 violation."""
    import cbor2

    protected_map = cbor2.dumps({})  # alg missing from protected
    unprotected_map = {1: -8, 4: kid}  # alg=-8 (EdDSA) here only
    # Sign with EdDSA over Sig_structure with empty external_aad
    sig_structure = ["Signature1", protected_map, b"", payload]
    to_be_signed = cbor2.dumps(sig_structure)
    from pycose.algorithms import EdDSA

    sig = EdDSA.sign(signing_key, to_be_signed)
    return cbor2.dumps(
        cbor2.CBORTag(18, [protected_map, unprotected_map, payload, sig])
    )


def _malformed_layer_a_with_bad_scitt_receipt(
    pinned_kid: bytes, pinned_keys: dict, host_id: str
) -> dict:
    """A layer_a dict whose SCITT receipt fails verification AND whose CDDL
    shape would crash if reached (event.event_signature.sig set to a non-bytes)."""
    blob = b"REAL"
    bogus_kid = b"BAD-KID"
    other = _fresh_eddsa_keypair(bogus_kid)
    return {
        "event_dag_merkle_root": "00" * 32,
        "chain_height": 1,
        "scitt_log_id": "test-log",
        "assurance_profile": "offline-auditor-minimal",
        "protocol_version": "v0.3",
        "events": [
            {
                "event_id": "ev-1",
                "prev_event_id": None,
                "prev_event_hash": "00" * 32,
                "monotonic_counter": 1,
                "counter_log_index": 1,
                "scitt_statement_id": "00" * 32,
                "scitt_statement_content_sha256": hashlib.sha256(blob).hexdigest(),
                # receipt: signed by `bogus_kid`, NOT pinned — fails TS_KEY_MISMATCH first
                "scitt_inclusion_proof_kid": bogus_kid.hex(),
                "scitt_inclusion_proof_payload": blob.hex(),
                "scitt_inclusion_proof_bytes": _well_formed_cose_sign1(
                    blob, other["signing"], bogus_kid
                ).hex(),
                "event_kind": "retrieval",
                "payload_hash": "00" * 32,
                "event_signature": {
                    "key_id": "k",
                    "sig": "NOT-BYTES-SHOULD-CRASH-CDDL",
                },
            },
        ],
    }


def _make_default_plugin() -> "LayerACounterPlugin":
    pinned_kid = b"k1"
    pinned_keys = _fresh_eddsa_keypair(pinned_kid)
    return LayerACounterPlugin(
        pinned_ts_key_ids=frozenset({pinned_kid}),
        pinned_ts_verifying_keys={pinned_kid: pinned_keys["verifying"]},
        pinned_issuer_keys={"host-A": b"\x11" * 32},
    )


# ---------------------------------------------------------------------------
# sc19a-003 — deterministic-CBOR primitive sanity checks (RFC 8949 §4.2.1)
# ---------------------------------------------------------------------------


def test_deterministic_cbor_encode_canonical_form():
    """Map keys sorted bytewise-lex of their deterministic encodings."""
    out = deterministic_cbor_encode({"b": 1, "a": 2, "aa": 3, "c": 4})
    # cbor2 canonical=True puts shorter keys first (length-then-lex sort over
    # deterministic-encoded text strings: "a" < "b" < "c" < "aa").
    assert isinstance(out, bytes) and len(out) > 0
    # Round-trip preserves dict
    assert cbor2.loads(out) == {"a": 2, "b": 1, "c": 4, "aa": 3}


def test_deterministic_cbor_encode_int_shortest_form():
    """Integer 100 encodes as 1 byte + 1 byte (mt=0, ai=24, val=100)."""
    out = deterministic_cbor_encode(100)
    assert out == b"\x18\x64"


def test_scan_cbor_for_policy_violations_accepts_clean_blob():
    """Clean canonical map passes without exception."""
    blob = deterministic_cbor_encode({"a": 1, "b": 2, "c": [1, 2, 3]})
    scan_cbor_for_policy_violations(blob)  # should not raise


# ---------------------------------------------------------------------------
# sc19a-004 — HKDF + canonical preimage primitive tests
# ---------------------------------------------------------------------------


def test_hkdf_extract_matches_rfc5869_test_vector_1():
    """RFC 5869 §A.1 SHA-256 Test Case 1.

    IKM  = 0x0b * 22
    salt = 0x000102030405060708090a0b0c
    PRK  = 0x077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
    """
    from audit_bundle.extensions.c19.layer_a_counter import _hkdf_extract

    ikm = b"\x0b" * 22
    salt = bytes.fromhex("000102030405060708090a0b0c")
    prk = _hkdf_extract(salt=salt, ikm=ikm)
    assert (
        prk.hex() == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    )


def test_hkdf_expand_matches_rfc5869_test_vector_1():
    """RFC 5869 §A.1 SHA-256 Test Case 1.

    PRK  = 0x077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
    info = 0xf0f1f2f3f4f5f6f7f8f9
    L    = 42
    OKM  = 0x3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf
           34007208d5b887185865
    """
    from audit_bundle.extensions.c19.layer_a_counter import _hkdf_expand

    prk = bytes.fromhex(
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    )
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    okm = _hkdf_expand(prk, info=info, length=42)
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )


def test_derive_event_signature_key_produces_32_bytes(host_ikm):
    k_event = derive_event_signature_key(host_ikm)
    assert isinstance(k_event, bytes) and len(k_event) == 32


def test_canonical_event_preimage_includes_all_eight_fields(host_id, bundle_id):
    preimage = canonical_event_preimage(
        host_id=host_id,
        event_id="ev-1",
        prev_event_hash=_zero_hash(),
        bundle_id=bundle_id,
        monotonic_counter=1,
        payload_hash=_payload_hash(b"x"),
    )
    decoded = cbor2.loads(preimage)
    assert isinstance(decoded, list) and len(decoded) == 8
    assert decoded[0] == "nexi/audit/v0.3/event"
    assert decoded[1] == PROTOCOL_VERSION
    assert decoded[2] == host_id
    assert decoded[3] == "ev-1"
    assert decoded[4] == _zero_hash()  # prev_event_hash position 4
    assert decoded[5] == bundle_id  # bundle_id position 5
    assert decoded[6] == 1
    assert decoded[7] == _payload_hash(b"x")


def test_compute_event_signature_deterministic(host_ikm, host_id, bundle_id):
    k_event = derive_event_signature_key(host_ikm)
    preimage = canonical_event_preimage(
        host_id=host_id,
        event_id="ev-1",
        prev_event_hash=_zero_hash(),
        bundle_id=bundle_id,
        monotonic_counter=1,
        payload_hash=_payload_hash(b"x"),
    )
    assert compute_event_signature(k_event, preimage) == compute_event_signature(
        k_event, preimage
    )


def test_verify_event_signature_constant_time_compare(host_ikm, host_id, bundle_id):
    k_event = derive_event_signature_key(host_ikm)
    preimage = canonical_event_preimage(
        host_id=host_id,
        event_id="ev-1",
        prev_event_hash=_zero_hash(),
        bundle_id=bundle_id,
        monotonic_counter=1,
        payload_hash=_payload_hash(b"x"),
    )
    good = compute_event_signature(k_event, preimage)
    bad = bytes(b ^ 0xFF for b in good)
    assert verify_event_signature(k_event, preimage, good) is True
    assert verify_event_signature(k_event, preimage, bad) is False


# ---------------------------------------------------------------------------
# sc19a-007 — chain integrity + Merkle root tests
# ---------------------------------------------------------------------------


def test_compute_bundle_merkle_root_empty_bundle():
    root = compute_bundle_merkle_root([])
    assert root == hashlib.sha256(b"\x01").digest()


def test_compute_bundle_merkle_root_single_leaf():
    leaf = hashlib.sha256(b"event-1").digest()
    root = compute_bundle_merkle_root([leaf])
    expected = hashlib.sha256(b"\x01" + leaf).digest()
    assert root == expected


def test_compute_bundle_merkle_root_three_leaves_deterministic():
    leaves = [hashlib.sha256(f"event-{i}".encode()).digest() for i in range(3)]
    root_a = compute_bundle_merkle_root(leaves)
    root_b = compute_bundle_merkle_root(leaves)
    assert root_a == root_b
    assert len(root_a) == 32


def test_compute_bundle_merkle_root_second_preimage_resistant():
    """Internal-node hash with leaf-shaped inputs MUST NOT collide with a leaf
    hash — domain separation via 0x00 / 0x01 prefixes."""
    leaf_bytes = hashlib.sha256(b"x").digest()
    # A single-leaf bundle hashes to H(0x01 || leaf_bytes).
    single_leaf_root = compute_bundle_merkle_root([leaf_bytes])
    # An attacker who hashed the same bytes WITHOUT the leaf prefix should
    # not collide.
    naive = hashlib.sha256(leaf_bytes).digest()
    assert single_leaf_root != naive
    # Also: an internal-node hash with two crafted "leaf-like" children must
    # not equal a real leaf hash.
    internal = hashlib.sha256(b"\x00" + leaf_bytes + leaf_bytes).digest()
    assert single_leaf_root != internal


def test_verify_chain_integrity_happy_path_three_events_returns_correct_root():
    from audit_bundle.extensions.c19.layer_a_counter import verify_chain_integrity

    events = []
    prev = b"\x00" * 32
    for i in range(1, 4):
        ev = {
            "event_id": f"ev-{i}",
            "prev_event_id": None if i == 1 else f"ev-{i - 1}",
            "prev_event_hash": prev,
            "monotonic_counter": i,
            "counter_log_index": i,
            "event_kind": "retrieval",
            "payload_hash": _payload_hash(f"event-{i}".encode()),
        }
        events.append(ev)
        prev = compute_event_hash(deterministic_cbor_encode(ev))
    expected = compute_bundle_merkle_root(
        [compute_event_hash(deterministic_cbor_encode(e)) for e in events]
    )
    assert verify_chain_integrity(events) == expected


def test_verify_chain_integrity_event_id_duplicate_rejected():
    from audit_bundle.extensions.c19.layer_a_counter import verify_chain_integrity

    ev = {
        "event_id": "dup",
        "prev_event_id": None,
        "prev_event_hash": _zero_hash(),
        "monotonic_counter": 1,
        "counter_log_index": 1,
        "event_kind": "retrieval",
        "payload_hash": _payload_hash(b"a"),
    }
    canon = compute_event_hash(deterministic_cbor_encode(ev))
    ev2 = {
        "event_id": "dup",
        "prev_event_id": "dup",
        "prev_event_hash": canon,
        "monotonic_counter": 2,
        "counter_log_index": 2,
        "event_kind": "retrieval",
        "payload_hash": _payload_hash(b"b"),
    }
    with pytest.raises(LayerAVerificationError) as exc:
        verify_chain_integrity([ev, ev2])
    assert exc.value.code is ReasonCode.EVENT_ID_DUPLICATE


# ---------------------------------------------------------------------------
# OF1 — Manifest header integrity (defense-7 honest-anchor closure)
#
# Authoritative scope: PRD `the internal design notes`.
# These six tests (T1-T6) encode the OF1 adversary class and the back-compat
# invariant. T2-T5 MUST fail loudly BEFORE the of1-I implementation lands
# (broken-first per `the internal design notes`)
# and MUST pass after of1-I lands. T1 is the positive round-trip; T6 confirms
# legacy bundles (without `manifest_header_merkle_leaf`) verify unchanged.
# ---------------------------------------------------------------------------


# Every _of1_minimal_manifest carries this schema_version. The CANONICAL OF1 leaf
# (ADR §9.2 RESOLUTION, Option C) FOLDS the declared schema_version, so an honest
# fixture must mint its stored leaf folding the SAME value — `_of1_canonical_leaf`
# below does this. (Pre-Option-C the generic path folded NEITHER field; the bare
# leaf is retired as the generic convention.)
_OF1_FIXTURE_SCHEMA_VERSION = "vcp-v1.1"


def _of1_canonical_leaf(
    *,
    bundle_id: str,
    created_at: str,
    dispatch_records: tuple[dict, ...],
    assurance_profile: str | None = None,
    schema_version: str | None = _OF1_FIXTURE_SCHEMA_VERSION,
) -> bytes:
    """Mint the canonical OF1 leaf the generic validator now recomputes for a
    `_of1_minimal_manifest` (folds the fixture's schema_version, + assurance_profile
    when the fixture declares one). Honest fixtures store THIS leaf; an adversarial
    fixture stores this honest leaf and then MUTATES a covered field, so the
    mismatch the test asserts is caused by the attack — not by a stale convention."""
    from audit_bundle.extensions.c19.layer_a_counter import (
        compute_manifest_header_leaf_from_manifest,
    )

    return compute_manifest_header_leaf_from_manifest(
        bundle_id=bundle_id,
        created_at=created_at,
        dispatch_records=dispatch_records,
        assurance_profile=assurance_profile,
        schema_version=schema_version,
    )


def _of1_minimal_manifest(
    *,
    bundle_id_str: str = "of1-bundle-1",
    created_at: str = "2026-05-20T12:00:00Z",
    dispatch_records: tuple[dict, ...] = (),
    manifest_header_merkle_leaf_hex: str | None = None,
    assurance_profile: str | None = None,
):
    """Build a minimal BundleManifest exercising only the OF1 fields.

    Other validate_manifest checks (file SHA / spec SHA / cross_refs / etc.)
    are satisfied by leaving everything else empty. Check 10 (the OF1 check)
    fires when causal_chain.layer_a.manifest_header_merkle_leaf is non-None.
    """
    from audit_bundle.bundle_manifest import BundleManifest

    layer_a = (
        None
        if manifest_header_merkle_leaf_hex is None
        else {"manifest_header_merkle_leaf": manifest_header_merkle_leaf_hex}
    )
    return BundleManifest(
        schema_version=_OF1_FIXTURE_SCHEMA_VERSION,
        bundle_id=bundle_id_str,
        created_at=created_at,
        files={},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
        dispatch_records=dispatch_records,
        assurance_profile=assurance_profile,
        causal_chain=None if layer_a is None else {"layer_a": layer_a},
    )


def test_of1_T1_compute_manifest_header_leaf_deterministic_and_idx_sorted(tmp_path):
    """T1 (positive): the canonical OF1 leaf is deterministic for fixed inputs and
    is stable under expected ordering. Same inputs → same 32-byte leaf;
    validate_manifest accepts a manifest whose stored leaf matches the CANONICAL
    recompute (folding the manifest's declared schema_version — ADR §9.2 Option C)."""
    from audit_bundle.bundle_manifest import validate_manifest

    dispatch_records = (
        {"op": {"kind": "TOOL"}, "stamp_observed": "UNVERIFIED", "idx": 0},
        {"op": {"kind": "COMPUTE"}, "stamp_observed": "UNVERIFIED", "idx": 1},
    )
    leaf_a = _of1_canonical_leaf(
        bundle_id="of1-bundle-1",
        created_at="2026-05-20T12:00:00Z",
        dispatch_records=dispatch_records,
    )
    leaf_b = _of1_canonical_leaf(
        bundle_id="of1-bundle-1",
        created_at="2026-05-20T12:00:00Z",
        dispatch_records=dispatch_records,
    )
    assert isinstance(leaf_a, bytes) and len(leaf_a) == 32
    assert leaf_a == leaf_b  # deterministic
    m = _of1_minimal_manifest(
        dispatch_records=dispatch_records,
        manifest_header_merkle_leaf_hex=leaf_a.hex(),
    )
    validate_manifest(
        m, tmp_path
    )  # MUST NOT raise — canonical leaf matches manifest fields


def test_of1_T1b_schema_version_folds_and_is_canonical(tmp_path):
    """T1b (CC-2b D1/G4 + ADR §9.2 Option C): schema_version coverage is folded
    AND canonical at the validator.

    PRIMITIVE contract (unchanged): `compute_manifest_header_leaf` folds
    `schema_version` only when present — None omits the key (byte-identical to the
    pre-CC-2b leaf), distinct versions → distinct leaves, same version →
    deterministic. (The primitive's fold-when-present semantics are the building
    block the canonical helper sits on; they did not change.)

    CANONICAL contract (Option C, decided 2026-06-05): the generic
    `validate_manifest` path now FOLDS the manifest's declared `schema_version`
    (it no longer recomputes a bare leaf). A bundle whose stored leaf was minted
    BARE is therefore REJECTED by the generic validator; the canonical folded leaf
    is ACCEPTED. This REPLACES the prior 'generic path passes None so no bundle
    re-mints' back-compat contract, retired by the unification — the only bare-leaf
    producers were test / redteam / fuzz harnesses that never run the generic
    validator (see ADR §9.2)."""
    from audit_bundle.bundle_manifest import (
        ManifestHeaderLeafMismatch,
        validate_manifest,
    )
    from audit_bundle.extensions.c19.layer_a_counter import (
        compute_manifest_header_leaf,
    )

    dispatch_records = (
        {"op": {"kind": "TOOL"}, "stamp_observed": "UNVERIFIED", "idx": 0},
    )
    common = dict(
        bundle_id="of1-g4",
        created_at="2026-05-20T12:00:00Z",
        dispatch_records=dispatch_records,
    )
    # --- primitive contract: fold-when-present (unchanged) ---
    bare = compute_manifest_header_leaf(**common)
    none_path = compute_manifest_header_leaf(**common, schema_version=None)
    covered_a = compute_manifest_header_leaf(
        **common, schema_version="vcp-v1.1-canary4"
    )
    covered_a2 = compute_manifest_header_leaf(
        **common, schema_version="vcp-v1.1-canary4"
    )
    covered_b = compute_manifest_header_leaf(**common, schema_version="vcp-v1.1")

    assert none_path == bare  # None omits the key, byte-identical
    assert covered_a != bare  # covering the field changes the leaf
    assert covered_a == covered_a2  # deterministic for a fixed schema_version
    assert covered_a != covered_b  # distinct schema versions → distinct leaves

    # --- canonical contract: the generic validator folds schema_version now ---
    # A BARE leaf (folds neither field) NO LONGER passes the generic validator...
    m_bare = _of1_minimal_manifest(
        bundle_id_str="of1-g4",
        dispatch_records=dispatch_records,
        manifest_header_merkle_leaf_hex=bare.hex(),
    )
    with pytest.raises(ManifestHeaderLeafMismatch):
        validate_manifest(m_bare, tmp_path)
    # ...but the CANONICAL leaf (folds the fixture's schema_version) DOES.
    m_canon = _of1_minimal_manifest(
        bundle_id_str="of1-g4",
        dispatch_records=dispatch_records,
        manifest_header_merkle_leaf_hex=_of1_canonical_leaf(**common).hex(),
    )
    validate_manifest(m_canon, tmp_path)  # MUST NOT raise


def test_of1_T2_created_at_shift_attack_detected(tmp_path):
    """T2 (adversarial): the C14 defense-7 KNOWN GAP attack — hostile sealer
    shifts manifest.created_at forward AFTER computing the Merkle leaf to admit
    a later-than-real upgrade signature. validate_manifest check 10 MUST raise
    ManifestHeaderLeafMismatch when the stored leaf disagrees with the leaf
    recomputed from the (shifted) created_at field."""
    from audit_bundle.bundle_manifest import (
        ManifestHeaderLeafMismatch,
        validate_manifest,
    )

    dispatch_records = ({"op": {"kind": "TOOL"}, "idx": 0},)
    # Honest leaf is the CANONICAL leaf (folds the fixture's schema_version), so the
    # ONLY divergence the validator sees is the attacker's shifted created_at.
    leaf_honest = _of1_canonical_leaf(
        bundle_id="of1-bundle-1",
        created_at="2026-05-20T12:00:00Z",
        dispatch_records=dispatch_records,
    )
    m_attack = _of1_minimal_manifest(
        bundle_id_str="of1-bundle-1",
        # Sealer-shifted created_at +1h forward; stored leaf still binds the
        # honest value (the attack scenario).
        created_at="2026-05-20T13:00:00Z",
        dispatch_records=dispatch_records,
        manifest_header_merkle_leaf_hex=leaf_honest.hex(),
    )
    with pytest.raises(ManifestHeaderLeafMismatch):
        validate_manifest(m_attack, tmp_path)


def test_of1_T3_bundle_id_mutation_detected(tmp_path):
    """T3 (adversarial): bundle_id mutation — sealer keeps created_at + records
    honest but mutates bundle_id (e.g., to enable cross-bundle leaf-reuse).
    validate_manifest check 10 MUST raise."""
    from audit_bundle.bundle_manifest import (
        ManifestHeaderLeafMismatch,
        validate_manifest,
    )

    dispatch_records = ({"op": {"kind": "TOOL"}, "idx": 0},)
    # Canonical honest leaf — only the mutated bundle_id should drive the mismatch.
    leaf_honest = _of1_canonical_leaf(
        bundle_id="of1-bundle-honest",
        created_at="2026-05-20T12:00:00Z",
        dispatch_records=dispatch_records,
    )
    m_attack = _of1_minimal_manifest(
        bundle_id_str="of1-bundle-MUTATED",  # the lie
        created_at="2026-05-20T12:00:00Z",
        dispatch_records=dispatch_records,
        manifest_header_merkle_leaf_hex=leaf_honest.hex(),
    )
    with pytest.raises(ManifestHeaderLeafMismatch):
        validate_manifest(m_attack, tmp_path)


def test_of1_T4_dispatch_records_body_mutation_detected(tmp_path):
    """T4 (adversarial): dispatch_records body mutation — sealer changes a
    record's body (e.g., stamp_observed value) without recomputing the leaf.
    record_sha drift in dispatch_records_index causes the recomputed leaf to
    diverge from the stored one. validate_manifest check 10 MUST raise."""
    from audit_bundle.bundle_manifest import (
        ManifestHeaderLeafMismatch,
        validate_manifest,
    )

    honest_records = (
        {"op": {"kind": "TOOL"}, "stamp_observed": "UNVERIFIED", "idx": 0},
    )
    # Canonical honest leaf — only the mutated record body should drive the mismatch.
    leaf_honest = _of1_canonical_leaf(
        bundle_id="of1-bundle-1",
        created_at="2026-05-20T12:00:00Z",
        dispatch_records=honest_records,
    )
    # Sealer mutates the body of record 0 — stamp_observed jumped a tier.
    mutated_records = (
        {"op": {"kind": "TOOL"}, "stamp_observed": "CONFIRMED_EXTERNAL", "idx": 0},
    )
    m_attack = _of1_minimal_manifest(
        bundle_id_str="of1-bundle-1",
        created_at="2026-05-20T12:00:00Z",
        dispatch_records=mutated_records,
        manifest_header_merkle_leaf_hex=leaf_honest.hex(),
    )
    with pytest.raises(ManifestHeaderLeafMismatch):
        validate_manifest(m_attack, tmp_path)


def test_of1_T5_dispatch_records_permutation_detected(tmp_path):
    """T5 (adversarial / sort-stability): re-ordering dispatch_records swaps
    which record sits at idx 0 vs idx 1. Because dispatch_records_index is
    keyed by idx (the position in the tuple), the (idx, record_sha) pair at
    idx 0 now binds a different record_sha — the recomputed leaf diverges.
    validate_manifest check 10 MUST raise."""
    from audit_bundle.bundle_manifest import (
        ManifestHeaderLeafMismatch,
        validate_manifest,
    )

    record_a = {"op": {"kind": "TOOL"}, "stamp_observed": "UNVERIFIED", "idx": 0}
    record_b = {"op": {"kind": "COMPUTE"}, "stamp_observed": "TARGET", "idx": 1}
    honest_records = (record_a, record_b)
    # Canonical honest leaf — only the record permutation should drive the mismatch.
    leaf_honest = _of1_canonical_leaf(
        bundle_id="of1-bundle-1",
        created_at="2026-05-20T12:00:00Z",
        dispatch_records=honest_records,
    )
    # Permuted order — sealer swapped records.
    permuted_records = (record_b, record_a)
    m_attack = _of1_minimal_manifest(
        bundle_id_str="of1-bundle-1",
        created_at="2026-05-20T12:00:00Z",
        dispatch_records=permuted_records,
        manifest_header_merkle_leaf_hex=leaf_honest.hex(),
    )
    with pytest.raises(ManifestHeaderLeafMismatch):
        validate_manifest(m_attack, tmp_path)


def test_of1_T6_legacy_bundle_without_manifest_header_leaf_unchanged(tmp_path):
    """T6 (back-compat): bundles WITHOUT `manifest_header_merkle_leaf` in
    causal_chain.layer_a — and bundles with no causal_chain at all — continue
    to validate exactly as they do today. The OF1 check fires only when the
    field is non-None. Also: verify_chain_integrity with
    manifest_header_leaf=None returns the same root as the no-kw form
    (signature-level back-compat for the kw-only param)."""
    from audit_bundle.bundle_manifest import validate_manifest
    from audit_bundle.extensions.c19.layer_a_counter import (
        compute_bundle_merkle_root,
        compute_event_hash,
        deterministic_cbor_encode,
        verify_chain_integrity,
    )

    # Path 1: bundle with no causal_chain at all (W3 / v0.2 baseline).
    m_no_chain = _of1_minimal_manifest(manifest_header_merkle_leaf_hex=None)
    validate_manifest(m_no_chain, tmp_path)  # MUST NOT raise

    # Path 2: signature-level back-compat — verify_chain_integrity called with
    # the new kw-only `manifest_header_leaf=None` returns the same root as
    # without the kw at all.
    events = []
    prev = b"\x00" * 32
    for i in range(1, 3):
        ev = {
            "event_id": f"of1-ev-{i}",
            "prev_event_id": None if i == 1 else f"of1-ev-{i - 1}",
            "prev_event_hash": prev,
            "monotonic_counter": i,
            "counter_log_index": i,
            "event_kind": "retrieval",
            "payload_hash": _payload_hash(f"of1-event-{i}".encode()),
        }
        events.append(ev)
        prev = compute_event_hash(deterministic_cbor_encode(ev))

    root_default = verify_chain_integrity(events)
    root_explicit_none = verify_chain_integrity(events, manifest_header_leaf=None)
    expected_legacy = compute_bundle_merkle_root(
        [compute_event_hash(deterministic_cbor_encode(e)) for e in events]
    )
    assert root_default == root_explicit_none == expected_legacy


# ---------------------------------------------------------------------------
# OF1S — Sealer-side helper for OF1 manifest header anchor
#
# Follow-on to OF1 (v0_3_of1 merged 2026-05-20). OF1 wave 2 shipped the
# verifier-side substrate but left emitters to compute the manifest-header
# leaf + extended Merkle root themselves — adoption-blocked. OF1S adds a
# pure sealer-side helper `seal_of1_manifest_anchor(...)` returning a dict
# ready to spread into causal_chain.layer_a. The test below is the
# load-bearing round-trip: seal → store → verify must pass.
# ---------------------------------------------------------------------------


def test_of1s_seal_to_verify_round_trip_passes(tmp_path):
    """OF1S (broken-first until seal_of1_manifest_anchor lands): build a
    synthetic event list + manifest fields, run the sealer helper to get
    the OF1-anchored Merkle root + leaf, then re-verify via the same
    leaf-aware verify_chain_integrity path. Bytes MUST round-trip.

    Also confirms validate_manifest's check 20 passes against the sealed
    leaf when the manifest fields used to seal are the same fields stored
    on the manifest (the honest-anchor mode happy path).
    """
    from audit_bundle.bundle_manifest import BundleManifest, validate_manifest
    from audit_bundle.extensions.c19.layer_a_counter import (
        compute_event_hash,
        compute_manifest_header_leaf,
        deterministic_cbor_encode,
        seal_of1_manifest_anchor,
        verify_chain_integrity,
    )

    bundle_id = "of1s-bundle-1"
    created_at = "2026-05-20T18:30:00Z"
    # The manifest's declared schema_version. The CANONICAL leaf folds it (ADR §9.2
    # Option C), so the sealer MUST seal with the same value the manifest stores, or
    # the generic validator's recompute (Round-trip 3) would MISMATCH.
    schema_version = "vcp-v1.1"
    dispatch_records = (
        {"op": {"kind": "TOOL"}, "stamp_observed": "UNVERIFIED", "idx": 0},
        {"op": {"kind": "COMPUTE"}, "stamp_observed": "TARGET", "idx": 1},
    )

    events = []
    prev = b"\x00" * 32
    for i in range(1, 3):
        ev = {
            "event_id": f"of1s-ev-{i}",
            "prev_event_id": None if i == 1 else f"of1s-ev-{i - 1}",
            "prev_event_hash": prev,
            "monotonic_counter": i,
            "counter_log_index": i,
            "event_kind": "retrieval",
            "payload_hash": _payload_hash(f"of1s-event-{i}".encode()),
        }
        events.append(ev)
        prev = compute_event_hash(deterministic_cbor_encode(ev))

    event_hashes = [compute_event_hash(deterministic_cbor_encode(e)) for e in events]

    sealed = seal_of1_manifest_anchor(
        event_hashes=event_hashes,
        bundle_id=bundle_id,
        created_at=created_at,
        dispatch_records=dispatch_records,
        schema_version=schema_version,
    )
    assert set(sealed.keys()) == {
        "event_dag_merkle_root",
        "manifest_header_merkle_leaf",
    }
    assert len(sealed["event_dag_merkle_root"]) == 64
    assert len(sealed["manifest_header_merkle_leaf"]) == 64

    # Round-trip 1 — sealed leaf == canonical leaf on the same inputs (folds the
    # declared schema_version, the convention the sealer + validator both use).
    recomputed_leaf = compute_manifest_header_leaf(
        bundle_id=bundle_id,
        created_at=created_at,
        dispatch_records=dispatch_records,
        schema_version=schema_version,
    )
    assert recomputed_leaf.hex() == sealed["manifest_header_merkle_leaf"]

    # Round-trip 2 — sealed root == verifier's recompute over [leaf, *events].
    verifier_root = verify_chain_integrity(events, manifest_header_leaf=recomputed_leaf)
    assert verifier_root.hex() == sealed["event_dag_merkle_root"]

    # Round-trip 3 — validate_manifest check 20 accepts the sealed leaf.
    m = BundleManifest(
        schema_version=schema_version,
        bundle_id=bundle_id,
        created_at=created_at,
        files={},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
        dispatch_records=dispatch_records,
        causal_chain={
            "layer_a": {
                "event_dag_merkle_root": sealed["event_dag_merkle_root"],
                "manifest_header_merkle_leaf": sealed["manifest_header_merkle_leaf"],
            }
        },
    )
    validate_manifest(m, tmp_path)  # MUST NOT raise — honest-anchor happy path


def test_of1s_seal_helper_deterministic_under_identical_inputs():
    """OF1S determinism: two calls with byte-identical inputs return
    byte-identical hex outputs. Sanity check that no nondeterministic
    salt slipped into the implementation."""
    from audit_bundle.extensions.c19.layer_a_counter import (
        seal_of1_manifest_anchor,
    )

    event_hashes = [hashlib.sha256(f"ev-{i}".encode()).digest() for i in range(3)]
    dispatch_records = ({"op": {"kind": "TOOL"}, "idx": 0},)

    a = seal_of1_manifest_anchor(
        event_hashes=event_hashes,
        bundle_id="b1",
        created_at="2026-05-20T00:00:00Z",
        dispatch_records=dispatch_records,
    )
    b = seal_of1_manifest_anchor(
        event_hashes=event_hashes,
        bundle_id="b1",
        created_at="2026-05-20T00:00:00Z",
        dispatch_records=dispatch_records,
    )
    assert a == b
