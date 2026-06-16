"""M7 regression — crypto-extension defense-in-depth gaps (C19).

Six documented/structural gaps where stated guarantees outran the code:

  (1) the CBOR verify-before-parse policy scan ran on the verifier's own
      canonical re-encode (tautological — could never fire on wire bytes);
      it now runs on the ATTACKER'S bytes at the real ingestion points
      (COSE envelope, protected header, notarized statement payload);
  (2) the strict bytes-keyed validate_event_cddl was never invoked — the live
      str-keyed path now rejects unknown event keys (validate_event_keys_str);
  (3) host_id selected the per-event HMAC key while living outside the
      validated key set, with a silent first-pinned-key fallback — now typed,
      and absent-host_id key selection fails closed unless exactly one issuer
      key is pinned;
  (4) verify_scitt_receipt verified the COSE signature over the DECODED
      payload but hashed the CALLER-supplied cose_payload_bytes with no
      assertion the two were equal — now enforced;
  (6) detect_and_verify_rotation_event passed raw receipt bytes where a
      ScittReceipt was expected (AttributeError if reached) — now decodes the
      wire bytes and binds them to the co-signed pre-commitment id.

(Gap (5), the C18 TUF payload_type allowlist, is covered in
tests/c18/test_c18_tuf_protocol.py.)
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import cbor2
import pytest

_PKG_ROOT = Path(__file__).resolve().parents[3]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

pytest.importorskip("pycose")

from pycose.algorithms import EdDSA  # noqa: E402
from pycose.headers import KID, Algorithm  # noqa: E402
from pycose.keys.curves import Ed25519  # noqa: E402
from pycose.keys.keyparam import KpKid  # noqa: E402
from pycose.keys.okp import OKPKey  # noqa: E402
from pycose.messages import Sign1Message  # noqa: E402

from audit_bundle.extensions.c19 import layer_a_counter as LA  # noqa: E402
from audit_bundle.extensions.c19.layer_a_counter import (  # noqa: E402
    LayerAVerificationError,
    ReasonCode,
    ScittReceipt,
    _decode_cose_sign1,
    canonical_event_preimage,
    canonical_rotation_preimage,
    compute_event_hash,
    compute_event_signature,
    compute_rotation_co_signature,
    derive_event_signature_key,
    derive_key_rotation_subkey_new,
    derive_key_rotation_subkey_old,
    detect_and_verify_rotation_event,
    deterministic_cbor_encode,
    seal_of1_manifest_anchor,
    validate_event_keys_str,
    verify_bundle_layer_a,
    verify_scitt_receipt,
)

TS_KID = b"ts-key-m7"
HOST = "host-A"
HOST_B = "host-B"
BUNDLE_ID = "bundle-m7-regression"
IKM = hashlib.sha256(b"host-A-ikm-m7").digest()
IKM_B = hashlib.sha256(b"host-B-ikm-m7").digest()

_cose_key = OKPKey.generate_key(crv=Ed25519, optional_params={KpKid: TS_KID})
_PINNED_IDS = frozenset({TS_KID})
_PINNED_KEYS = {TS_KID: _cose_key}


def _scitt_receipt(payload_bytes: bytes) -> bytes:
    msg = Sign1Message(
        phdr={Algorithm: EdDSA, KID: TS_KID}, uhdr={}, payload=payload_bytes
    )
    msg.key = _cose_key
    return msg.encode()


# ---------------------------------------------------------------------------
# (1) CBOR policy scan fires on WIRE bytes
# ---------------------------------------------------------------------------


def _valid_envelope_parts() -> tuple[bytes, bytes, bytes]:
    payload = deterministic_cbor_encode({"k": "v"})
    blob = _scitt_receipt(payload)
    protected_bstr, _, decoded_payload, sig = _decode_cose_sign1(blob)
    assert decoded_payload == payload
    return protected_bstr, payload, sig


def test_duplicate_key_in_unprotected_header_rejected_at_wire_bytes():
    """cbor2.loads silently collapses duplicate map keys; the scan must fire
    BEFORE the decode on the attacker's envelope bytes."""
    protected_bstr, payload, sig = _valid_envelope_parts()
    dup_map = (
        b"\xa2" + cbor2.dumps("a") + cbor2.dumps(1) + cbor2.dumps("a") + cbor2.dumps(2)
    )
    blob = (
        b"\xd2\x84"
        + cbor2.dumps(protected_bstr)
        + dup_map
        + cbor2.dumps(payload)
        + cbor2.dumps(sig)
    )
    with pytest.raises(LayerAVerificationError) as exc:
        _decode_cose_sign1(blob)
    assert exc.value.code is ReasonCode.CBOR_DUPLICATE_KEY


def test_indefinite_length_envelope_rejected_at_wire_bytes():
    blob = b"\xd2\x9f\xff"  # tag 18 over an indefinite-length array
    with pytest.raises(LayerAVerificationError) as exc:
        _decode_cose_sign1(blob)
    assert exc.value.code is ReasonCode.CBOR_INDEFINITE_LENGTH


def test_disallowed_tag_rejected_at_wire_bytes():
    blob = cbor2.dumps(cbor2.CBORTag(99, [b"", {}, b"p", b"s"]))
    with pytest.raises(LayerAVerificationError) as exc:
        _decode_cose_sign1(blob)
    assert exc.value.code is ReasonCode.CBOR_TAG_NOT_ALLOWED


def test_duplicate_key_in_protected_header_rejected():
    """The protected header is an opaque bstr to the envelope scan — its inner
    bytes are attacker wire bytes too and get their own scan."""
    _, payload, sig = _valid_envelope_parts()
    dup_protected = b"\xa2\x01\x26\x01\x26"  # {1: -7, 1: -7}
    blob = (
        b"\xd2\x84"
        + cbor2.dumps(dup_protected)
        + b"\xa0"
        + cbor2.dumps(payload)
        + cbor2.dumps(sig)
    )
    receipt = ScittReceipt(
        statement_id=hashlib.sha256(payload).digest(),
        statement_content_sha256=hashlib.sha256(payload).digest(),
        cose_payload_bytes=payload,
        receipt_bytes=blob,
        ts_key_id=TS_KID,
    )
    with pytest.raises(LayerAVerificationError) as exc:
        verify_scitt_receipt(
            receipt=receipt,
            pinned_ts_key_ids=_PINNED_IDS,
            pinned_ts_verifying_keys=_PINNED_KEYS,
        )
    assert exc.value.code is ReasonCode.CBOR_DUPLICATE_KEY


# ---------------------------------------------------------------------------
# (4) cose_payload_bytes MUST be the COSE-verified payload
# ---------------------------------------------------------------------------


def test_substituted_cose_payload_bytes_rejected():
    """Pre-fix false-green: signature verifies over the envelope's REAL
    payload while the content check hashes a caller-supplied SUBSTITUTE whose
    sha256 self-consistently matches statement_content_sha256 — two valid
    checks that never referred to the same statement."""
    real_payload = deterministic_cbor_encode({"decision": "DENY"})
    blob = _scitt_receipt(real_payload)
    fake_payload = deterministic_cbor_encode({"decision": "APPROVE"})
    receipt = ScittReceipt(
        statement_id=hashlib.sha256(fake_payload).digest(),
        statement_content_sha256=hashlib.sha256(fake_payload).digest(),
        cose_payload_bytes=fake_payload,
        receipt_bytes=blob,
        ts_key_id=TS_KID,
    )
    with pytest.raises(LayerAVerificationError) as exc:
        verify_scitt_receipt(
            receipt=receipt,
            pinned_ts_key_ids=_PINNED_IDS,
            pinned_ts_verifying_keys=_PINNED_KEYS,
        )
    assert exc.value.code is ReasonCode.SCITT_RECEIPT_PAYLOAD_MISMATCH


def test_honest_receipt_still_verifies():
    payload = deterministic_cbor_encode({"decision": "APPROVE"})
    blob = _scitt_receipt(payload)
    receipt = ScittReceipt(
        statement_id=hashlib.sha256(payload).digest(),
        statement_content_sha256=hashlib.sha256(payload).digest(),
        cose_payload_bytes=payload,
        receipt_bytes=blob,
        ts_key_id=TS_KID,
    )
    verify_scitt_receipt(
        receipt=receipt,
        pinned_ts_key_ids=_PINNED_IDS,
        pinned_ts_verifying_keys=_PINNED_KEYS,
    )


# ---------------------------------------------------------------------------
# (2) + (3) live-path strict event keys + host_id
# ---------------------------------------------------------------------------


def _build_event(*, host_id_field: str | None, sign_as: str, extra: dict | None = None):
    payload = {"decision": "APPROVE"}
    payload_bytes = deterministic_cbor_encode(payload)
    payload_hash = hashlib.sha256(payload_bytes).digest()
    receipt = _scitt_receipt(payload_bytes)
    prev = b"\x00" * 32
    k_event = derive_event_signature_key(IKM if sign_as == HOST else IKM_B)
    preimage = canonical_event_preimage(
        host_id=sign_as,
        event_id="ev-1",
        prev_event_hash=prev,
        bundle_id=BUNDLE_ID,
        monotonic_counter=1,
        payload_hash=payload_hash,
    )
    sig = compute_event_signature(k_event, preimage)
    ev = {
        "event_id": "ev-1",
        "prev_event_id": None,
        "prev_event_hash": prev.hex(),
        "event_kind": "dispatch_record",
        "monotonic_counter": 1,
        "counter_log_index": 1,
        "scitt_statement_id": hashlib.sha256(payload_bytes).hexdigest(),
        "scitt_statement_content_sha256": hashlib.sha256(payload_bytes).hexdigest(),
        "scitt_inclusion_proof": receipt.hex(),
        "payload_hash": payload_hash.hex(),
        "event_signature": {"key_id": f"k_event_{sign_as}", "sig": sig.hex()},
        "causal_dependencies": [],
    }
    if host_id_field is not None:
        ev["host_id"] = host_id_field
    if extra:
        ev.update(extra)
    normalized = {
        "event_id": "ev-1",
        "prev_event_id": None,
        "prev_event_hash": prev,
        "monotonic_counter": 1,
        "counter_log_index": 1,
        "event_kind": "dispatch_record",
        "payload_hash": payload_hash,
    }
    return ev, compute_event_hash(deterministic_cbor_encode(normalized))


def _build_layer_a(ev, ev_hash) -> dict:
    sealed = seal_of1_manifest_anchor(
        event_hashes=[ev_hash],
        bundle_id=BUNDLE_ID,
        created_at="2026-06-09T00:00:00Z",
        dispatch_records=[],
    )
    return {
        "bundle_id": BUNDLE_ID,
        "protocol_version": "v0.3",
        "scitt_log_id": "log-m7",
        "assurance_profile": "production-standard",
        "chain_height": 1,
        "events": [ev],
        "event_dag_merkle_root": sealed["event_dag_merkle_root"],
        "manifest_header_merkle_leaf": sealed["manifest_header_merkle_leaf"],
    }


def _verify(la, issuer_keys):
    return verify_bundle_layer_a(
        bundle_bytes=deterministic_cbor_encode(la),
        layer_a=la,
        pinned_ts_key_ids=_PINNED_IDS,
        pinned_ts_verifying_keys=_PINNED_KEYS,
        pinned_issuer_keys=issuer_keys,
    )


def test_unknown_event_key_rejected_on_live_path():
    ev, h = _build_event(
        host_id_field=HOST, sign_as=HOST, extra={"policy_override": "APPROVE"}
    )
    la = _build_layer_a(ev, h)
    with pytest.raises(LayerAVerificationError) as exc:
        _verify(la, {HOST: IKM})
    assert exc.value.code is ReasonCode.CDDL_VALIDATION_FAILED
    assert "unknown keys" in exc.value.detail
    assert "policy_override" in exc.value.detail


def test_non_str_host_id_rejected_on_live_path():
    ev, h = _build_event(host_id_field=HOST, sign_as=HOST)
    ev["host_id"] = 7
    la = _build_layer_a(ev, h)
    with pytest.raises(LayerAVerificationError) as exc:
        _verify(la, {HOST: IKM})
    assert exc.value.code is ReasonCode.CDDL_VALIDATION_FAILED


def test_clean_event_with_host_id_verifies():
    ev, h = _build_event(host_id_field=HOST, sign_as=HOST)
    la = _build_layer_a(ev, h)
    root = _verify(la, {HOST: IKM})
    assert isinstance(root, bytes) and len(root) == 32


def test_absent_host_id_single_pinned_issuer_still_verifies():
    """Back-compat: one pinned issuer key -> unambiguous selection."""
    ev, h = _build_event(host_id_field=None, sign_as=HOST)
    la = _build_layer_a(ev, h)
    root = _verify(la, {HOST: IKM})
    assert len(root) == 32


def test_absent_host_id_multiple_pinned_issuers_fails_closed():
    """The old code silently selected the FIRST pinned key — omission chose
    the key. Now ambiguous selection is a reject."""
    ev, h = _build_event(host_id_field=None, sign_as=HOST)
    la = _build_layer_a(ev, h)
    with pytest.raises(LayerAVerificationError) as exc:
        _verify(la, {HOST: IKM, HOST_B: IKM_B})
    assert exc.value.code is ReasonCode.EVENT_SIGNATURE_INVALID
    assert "ambiguous" in exc.value.detail


def test_host_id_swap_requires_named_hosts_key():
    """Regression pin for the documented mitigation: renaming host_id forces
    verification under the NAMED host's key (host_id is in the HMAC preimage),
    so a swap without that host's key material fails."""
    ev, h = _build_event(host_id_field=HOST_B, sign_as=HOST)  # signed by A, claims B
    la = _build_layer_a(ev, h)
    with pytest.raises(LayerAVerificationError) as exc:
        _verify(la, {HOST: IKM, HOST_B: IKM_B})
    assert exc.value.code is ReasonCode.EVENT_SIGNATURE_INVALID


def test_rotation_extra_keys_admitted_only_on_key_rotation_kind():
    ev = {"event_kind": "dispatch_record", "old_key_id": "k1"}
    with pytest.raises(LayerAVerificationError):
        validate_event_keys_str(ev, idx=0)
    ev_rot = {"event_kind": "key_rotation", "old_key_id": "k1"}
    validate_event_keys_str(ev_rot, idx=0)  # must not raise


# ---------------------------------------------------------------------------
# (6) rotation pre-commit receipt: wire bytes -> ScittReceipt + id binding
# ---------------------------------------------------------------------------

_OLD_KID = "k_host_2026"
_NEW_KID = "k_host_2027"
_IKM_OLD = hashlib.sha256(b"old-key-ikm").digest()
_IKM_NEW = hashlib.sha256(b"new-key-ikm").digest()


def _rotation_event(*, scitt_id_hex: str | None, receipt_field):
    from audit_bundle.extensions.c19.pre_commit_log import (
        KeyProvisionStatement,
        issue_pre_commit_statement,
    )

    stmt = KeyProvisionStatement(
        host_id=HOST,
        new_key_id=_NEW_KID,
        activation_at_iso8601="2026-06-03T00:00:00Z",
        issuance_at_iso8601="2026-06-01T00:00:00Z",
    )
    receipt_bytes, content_sha = issue_pre_commit_statement(
        statement=stmt, issuer_signing_key=_cose_key, issuer_kid=TS_KID
    )
    scitt_id = scitt_id_hex if scitt_id_hex is not None else content_sha.hex()
    preimage_kwargs = dict(
        host_id=HOST,
        old_key_id=_OLD_KID,
        new_key_id=_NEW_KID,
        new_key_pre_commitment_scitt_id=scitt_id,
        valid_not_before="2026-06-03T00:00:00Z",
        valid_not_after="2027-06-03T00:00:00Z",
        rotation_reason="scheduled",
    )
    preimage = canonical_rotation_preimage(**preimage_kwargs)
    co_old = compute_rotation_co_signature(
        derive_key_rotation_subkey_old(_IKM_OLD), preimage
    )
    co_new = compute_rotation_co_signature(
        derive_key_rotation_subkey_new(_IKM_NEW), preimage
    )
    event = {
        "event_kind": "key_rotation",
        "host_id": HOST,
        "old_key_id": _OLD_KID,
        "new_key_id": _NEW_KID,
        "rotation_reason": "scheduled",
        "new_key_pre_commitment_scitt_id": scitt_id,
        "new_key_pre_commitment_scitt_receipt": (
            receipt_bytes if receipt_field == "bytes" else receipt_field
        ),
        "pre_commit_issuance_iso8601": "2026-06-01T00:00:00Z",
        "rotation_at": "2026-06-03T00:00:00Z",
        "valid_not_before": "2026-06-03T00:00:00Z",
        "valid_not_after": "2027-06-03T00:00:00Z",
        "co_signed_old_key": co_old,
        "co_signed_new_key": co_new,
    }
    return event, receipt_bytes


def _detect(event):
    return detect_and_verify_rotation_event(
        event=event,
        assurance_profile="production-standard",
        pinned_ts_key_ids=_PINNED_IDS,
        pinned_ts_verifying_keys=_PINNED_KEYS,
        pinned_offline_root_key_ids=frozenset(),
        pinned_offline_root_verifying_keys={},
        host_signing_keys_by_kid={_OLD_KID: _IKM_OLD, _NEW_KID: _IKM_NEW},
    )


def test_rotation_with_raw_receipt_bytes_now_verifies():
    """The old code passed the raw bytes straight into a ScittReceipt-typed
    parameter — this path could only AttributeError. It now decodes and
    verifies end-to-end."""
    event, _ = _rotation_event(scitt_id_hex=None, receipt_field="bytes")
    windows = _detect(event)
    assert _NEW_KID in windows


def test_rotation_receipt_hex_serialized_also_accepted():
    event, receipt_bytes = _rotation_event(scitt_id_hex=None, receipt_field="bytes")
    event["new_key_pre_commitment_scitt_receipt"] = receipt_bytes.hex()
    windows = _detect(event)
    assert _NEW_KID in windows


def test_rotation_receipt_not_matching_co_signed_id_rejected():
    """A hex-64 co-signed id that matches neither the envelope nor its payload
    means the supplied receipt is NOT the pre-committed statement."""
    event, _ = _rotation_event(scitt_id_hex="ee" * 32, receipt_field="bytes")
    with pytest.raises(LayerAVerificationError) as exc:
        _detect(event)
    assert exc.value.code is ReasonCode.SCITT_RECEIPT_PAYLOAD_MISMATCH


def test_rotation_receipt_unpinned_ts_key_rejected():
    other_kid = b"ts-key-evil"
    other_key = OKPKey.generate_key(crv=Ed25519, optional_params={KpKid: other_kid})
    payload = deterministic_cbor_encode(
        {
            "payload_type": "nexi/audit/v0.3/key-rotation-pre-commit",
            "host_id": HOST,
            "new_key_id": _NEW_KID,
            "activation_at": "2026-06-03T00:00:00Z",
            "issuance_at": "2026-06-01T00:00:00Z",
        }
    )
    msg = Sign1Message(
        phdr={Algorithm: EdDSA, KID: other_kid}, uhdr={}, payload=payload
    )
    msg.key = other_key
    forged = msg.encode()
    event, _ = _rotation_event(scitt_id_hex=None, receipt_field="bytes")
    event["new_key_pre_commitment_scitt_id"] = hashlib.sha256(payload).hexdigest()
    event["new_key_pre_commitment_scitt_receipt"] = forged
    # Re-co-sign over the new id so the failure isolates to the TS-key gate.
    preimage = canonical_rotation_preimage(
        host_id=HOST,
        old_key_id=_OLD_KID,
        new_key_id=_NEW_KID,
        new_key_pre_commitment_scitt_id=event["new_key_pre_commitment_scitt_id"],
        valid_not_before="2026-06-03T00:00:00Z",
        valid_not_after="2027-06-03T00:00:00Z",
        rotation_reason="scheduled",
    )
    event["co_signed_old_key"] = compute_rotation_co_signature(
        derive_key_rotation_subkey_old(_IKM_OLD), preimage
    )
    event["co_signed_new_key"] = compute_rotation_co_signature(
        derive_key_rotation_subkey_new(_IKM_NEW), preimage
    )
    with pytest.raises(LayerAVerificationError) as exc:
        _detect(event)
    assert exc.value.code is ReasonCode.SCITT_TS_KEY_MISMATCH


# Keep module-level LA import load-bearing for future reason-code additions.
_ = LA


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
