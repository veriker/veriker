"""Tests for the NATIVE Fulcio identity leg (audit_bundle/extensions/fulcio_identity.py).

Grounded against a SYNTHETIC Fulcio keyless bundle (tests/fixtures/synthetic_fulcio_bundle.json)
+ matching synthetic trust anchors (tests/fixtures/synthetic_fulcio_trust_anchors.json), both
emitted by tests/fixtures/_generate_synthetic_fulcio.py. The fixture carries the PUBLIC release
SAN (github.com/nexiverify/veriker/...) so the OSS-exported tree asserts the identity releases
actually sign under — a real captured staging cert bakes its SAN into signed DER that the export
identity rewrite cannot flip, breaking this test in every export. The real captured staging
bundle stays at sigstore_staging_bundle_v0_3.json for the rekor inclusion-proof grounding in
tests/test_rekor_anchor.py (whose value depends on real transparency-log data).

The positive path verifies the synthetic Fulcio chain + SAN/issuer + embedded SCT + artifact
signature; the negatives are crafted to fail each check, including the load-bearing ORDER
property (a broken chain with a CORRECT SAN must fail at the chain and NEVER report identity as
established).

Run explicitly:  pytest tests/test_fulcio_native.py
"""

from __future__ import annotations

import base64
import dataclasses
import datetime
import json
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID, ObjectIdentifier

from audit_bundle.extensions.fulcio_identity import (
    CT_CONSISTENCY_ASSUMPTION,
    FULCIO_OK_CT_ASSUMED,
    PROVENANCE_NATIVE_STAGING,
    REASON_ARTIFACT_SIG_INVALID,
    REASON_ARTIFACT_SIG_MISSING,
    REASON_CERT_NOT_VALID_AT_TIME,
    REASON_CERT_PARSE_FAILED,
    REASON_CHAIN_BUILD_FAILED,
    REASON_LEAF_IS_CA,
    REASON_NO_CERTIFICATE,
    REASON_OIDC_ISSUER_MISMATCH,
    REASON_SAN_MISMATCH,
    REASON_SCT_NO_MATCHING_CT_KEY,
    REASON_SCT_SIGNATURE_INVALID,
    TIME_ANCHOR_EMBEDDED_SCT,
    TIME_ANCHOR_REKOR_INTEGRATED,
    FulcioTrustAnchors,
    FulcioVerifyError,
    _embedded_scts,
    _extract_oidc_issuer,
    verify_fulcio_identity_native,
)

_FIXTURES = Path(__file__).parent / "fixtures"
_BUNDLE = _FIXTURES / "synthetic_fulcio_bundle.json"
_ANCHORS = _FIXTURES / "synthetic_fulcio_trust_anchors.json"

# The PUBLIC release identity the synthetic leaf carries in its SAN (the workflow that signs
# releases in the public repo). A synthetic cert legitimately carries the public SAN in BOTH the
# source and exported trees, so the export identity rewrite of this line is a harmless no-op.
_STAGING_SAN = (
    "https://github.com/nexiverify/veriker/.github/workflows/"
    "keyless-attest-staging.yml@refs/heads/main"
)
_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
# The embedded SCT timestamp (= the bundle's CT-attested trusted time), epoch seconds.
_SCT_EPOCH = 1780688301


def _anchors() -> FulcioTrustAnchors:
    return FulcioTrustAnchors.from_anchors_json(json.loads(_ANCHORS.read_text()))


def _bundle() -> dict:
    return json.loads(_BUNDLE.read_text())


def _verify(
    bundle: dict | None = None,
    anchors: FulcioTrustAnchors | None = None,
    *,
    expected_san: str = _STAGING_SAN,
    expected_oidc_issuer: str = _OIDC_ISSUER,
    integrated_time: int | None = None,
    skew_seconds: int = 300,
):
    return verify_fulcio_identity_native(
        bundle if bundle is not None else _bundle(),
        trust_anchors=anchors or _anchors(),
        expected_san=expected_san,
        expected_oidc_issuer=expected_oidc_issuer,
        integrated_time=integrated_time,
        skew_seconds=skew_seconds,
    )


# --------------------------------------------------------------------------- positive


def test_staging_bundle_verifies_ct_assumed() -> None:
    v = _verify()
    assert v.ok is True
    # The label carries the irreducible CT residual — NEVER a bare "ok" / "trustless".
    assert v.label == FULCIO_OK_CT_ASSUMED
    assert v.label.lower() not in {"ok", "verified", "trustless"}
    assert v.provenance == PROVENANCE_NATIVE_STAGING
    assert v.chain_verified and v.identity_verified
    assert v.sct_verified and v.artifact_signature_verified
    assert v.verified_identity == _STAGING_SAN
    assert v.verified_oidc_issuer == _OIDC_ISSUER
    assert v.ct_assumption == CT_CONSISTENCY_ASSUMPTION
    assert v.reasons == ()


def test_verdict_exposes_verified_message_digest_for_artifact_binding() -> None:
    # The verdict surfaces the digest leg (d) VERIFIED under the leaf key, so a caller can bind it
    # to the artifact off the verified value (not a re-read of the raw bundle). It equals the
    # bundle's signed digest on a pass.
    bundle = _bundle()
    expected = base64.b64decode(bundle["messageSignature"]["messageDigest"]["digest"])
    v = _verify(bundle=bundle, integrated_time=_SCT_EPOCH)
    assert v.ok is True
    assert v.verified_message_digest == expected
    assert len(v.verified_message_digest) == 32


def test_verified_message_digest_is_none_on_failure() -> None:
    # On any failure (here: a tampered artifact sig) the verdict carries no verified digest.
    bundle = _bundle()
    sig = bytearray(base64.b64decode(bundle["messageSignature"]["signature"]))
    sig[10] ^= 0xFF
    bundle["messageSignature"]["signature"] = base64.b64encode(bytes(sig)).decode()
    v = _verify(bundle=bundle, integrated_time=_SCT_EPOCH)
    assert v.ok is False
    assert v.verified_message_digest is None


def test_time_anchor_is_sct_when_integrated_time_absent() -> None:
    # The staging entry records integratedTime=0, so the leg falls back to the CT-attested
    # embedded-SCT timestamp (and labels which anchor it used).
    v = _verify()
    assert v.time_anchor_source == TIME_ANCHOR_EMBEDDED_SCT
    assert v.time_anchor_epoch_seconds == _SCT_EPOCH


def test_explicit_rekor_integrated_time_anchor_used() -> None:
    v = _verify(integrated_time=_SCT_EPOCH + 60)  # within the 10-min validity window
    assert v.ok is True
    assert v.time_anchor_source == TIME_ANCHOR_REKOR_INTEGRATED
    assert v.time_anchor_epoch_seconds == _SCT_EPOCH + 60


# --------------------------------------------------------------------------- identity


def test_wrong_san_fails() -> None:
    v = _verify(
        expected_san="https://github.com/attacker/evil/.github/workflows/x.yml@refs/heads/main"
    )
    assert v.ok is False
    assert v.label == REASON_SAN_MISMATCH
    assert v.chain_verified is True  # chain still validated; identity is what failed
    assert v.identity_verified is False


def test_wrong_oidc_issuer_fails() -> None:
    v = _verify(expected_oidc_issuer="https://accounts.google.com")
    assert v.ok is False
    assert v.label == REASON_OIDC_ISSUER_MISMATCH
    assert v.identity_verified is False


# --------------------------------------------------------------------------- chain / ORDER


def test_broken_chain_with_correct_san_fails_at_chain_not_identity() -> None:
    """ORDER PROOF: empty pinned roots -> chain cannot build; even though the SAN is correct,
    identity is NEVER evaluated (SAN-pin-before-chain is tribunal-rejected)."""
    a = dataclasses.replace(_anchors(), fulcio_roots=(), fulcio_intermediates=())
    v = _verify(anchors=a)
    assert v.ok is False
    assert v.label == REASON_CHAIN_BUILD_FAILED
    assert v.chain_verified is False
    assert v.identity_verified is False  # the load-bearing property
    assert v.verified_identity is None


def test_missing_intermediate_fails_chain() -> None:
    a = dataclasses.replace(_anchors(), fulcio_intermediates=())
    v = _verify(anchors=a)
    assert v.ok is False
    assert v.chain_verified is False
    assert v.identity_verified is False


def test_rogue_ca_leaf_fails_chain() -> None:
    """A syntactically valid leaf that chains to a ROGUE self-signed CA (not the pinned root),
    even carrying the correct SAN + issuer, must fail the chain and never reach identity."""
    bundle, _leaf_key = _rogue_bundle(
        san=_STAGING_SAN,
        oidc_issuer=_OIDC_ISSUER,
        not_before=datetime.datetime(2026, 6, 5, 19, 0, 0),
        not_after=datetime.datetime(2026, 6, 5, 20, 0, 0),
    )
    v = _verify(bundle=bundle, integrated_time=_SCT_EPOCH)
    assert v.ok is False
    assert v.label == REASON_CHAIN_BUILD_FAILED
    assert v.identity_verified is False


def _bundle_with_leaf(cert: x509.Certificate) -> dict:
    from cryptography.hazmat.primitives.serialization import Encoding

    bundle = _bundle()
    bundle["verificationMaterial"]["certificate"]["rawBytes"] = base64.b64encode(
        cert.public_bytes(Encoding.DER)
    ).decode()
    return bundle


def test_pinned_intermediate_as_leaf_fails_at_chain_not_identity() -> None:
    """A pinned CA (here an intermediate) presented in the END-ENTITY slot must be rejected AT the
    chain (a CA is not an end-entity), before identity — never reported as chain_verified=True and
    deferred to a downstream SAN/SCT failure."""
    inter = _anchors().fulcio_intermediates[0]
    v = _verify(bundle=_bundle_with_leaf(inter), integrated_time=_SCT_EPOCH)
    assert v.ok is False
    assert v.label == REASON_LEAF_IS_CA
    assert v.chain_verified is False
    assert v.identity_verified is False


def test_pinned_root_as_leaf_fails_chain() -> None:
    """A pinned self-signed root as the leaf terminates the walk with NO verified leaf signer; the
    `leaf_signer is None` guard rejects it (the SCT issuer would otherwise be unbound)."""
    root = _anchors().fulcio_roots[0]
    v = _verify(bundle=_bundle_with_leaf(root), integrated_time=_SCT_EPOCH)
    assert v.ok is False
    assert v.label in {REASON_CHAIN_BUILD_FAILED, REASON_LEAF_IS_CA}
    assert v.identity_verified is False


def test_expired_at_integrated_time_fails() -> None:
    # A trusted time ~400 days after the 10-minute keyless window -> leaf not valid at time.
    v = _verify(integrated_time=_SCT_EPOCH + 400 * 86400)
    assert v.ok is False
    assert v.label == REASON_CERT_NOT_VALID_AT_TIME
    assert REASON_CERT_NOT_VALID_AT_TIME in v.reasons
    assert v.identity_verified is False


# --------------------------------------------------------------------------- SCT


def test_bad_ct_key_fails_sct() -> None:
    # Replace every pinned CT key with an unrelated P-256 key -> the real SCT no longer verifies.
    wrong = ec.generate_private_key(ec.SECP256R1()).public_key()
    a = _anchors()
    a = dataclasses.replace(
        a, ctlogs=tuple(dataclasses.replace(c, public_key=wrong) for c in a.ctlogs)
    )
    v = _verify(anchors=a)
    assert v.ok is False
    assert v.label == REASON_SCT_SIGNATURE_INVALID
    assert v.sct_verified is False
    # Chain + identity passed first (order); only the SCT leg failed.
    assert v.chain_verified is True and v.identity_verified is True


def test_no_matching_ct_key_fails_sct() -> None:
    # Drop the one CT key whose logId matches the SCT -> no key can verify it.
    a = _anchors()
    bundle = _bundle()
    leaf = x509.load_der_x509_certificate(
        base64.b64decode(bundle["verificationMaterial"]["certificate"]["rawBytes"])
    )
    sct_log_id = _embedded_scts(leaf)[0].log_id
    a = dataclasses.replace(
        a, ctlogs=tuple(c for c in a.ctlogs if c.log_id != sct_log_id)
    )
    v = _verify(anchors=a)
    assert v.ok is False
    assert v.label == REASON_SCT_NO_MATCHING_CT_KEY
    assert v.sct_verified is False


def test_sct_binds_to_chain_validated_signer_not_name_match() -> None:
    """Regression (CA-key-rollover decoupling): a same-subject-DN DECOY intermediate with a
    DIFFERENT key, placed FIRST in the anchor set, must NOT break verification. The SCT
    issuer_key_hash binds to the chain-VALIDATED leaf signer, not a subject-name rematch — so the
    decoy (which did not sign the leaf) is ignored and the real intermediate's key is used.
    Under the old name-rematch this failed with SCT_SIGNATURE_INVALID (wrong key_hash)."""
    a = _anchors()
    real_inter = a.fulcio_intermediates[0]
    decoy_key = ec.generate_private_key(ec.SECP256R1())
    decoy = (
        x509.CertificateBuilder()
        .subject_name(real_inter.subject)  # SAME DN as the real intermediate
        .issuer_name(real_inter.subject)
        .public_key(decoy_key.public_key())  # but a DIFFERENT key
        .serial_number(999)
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(decoy_key, hashes.SHA256())
    )
    a2 = dataclasses.replace(a, fulcio_intermediates=(decoy, real_inter))
    v = _verify(anchors=a2)
    assert (
        v.ok is True
    )  # chain validates against the REAL intermediate; SCT binds to its key
    assert v.sct_verified is True


# --------------------------------------------------------------------------- artifact sig


def test_missing_message_signature_fails() -> None:
    bundle = _bundle()
    del bundle["messageSignature"]
    v = _verify(bundle=bundle)
    assert v.ok is False
    assert v.label == REASON_ARTIFACT_SIG_MISSING
    # chain + identity + SCT all passed; only the artifact-sig leg is missing.
    assert v.chain_verified and v.identity_verified and v.sct_verified
    assert v.artifact_signature_verified is False


def test_tampered_message_signature_fails() -> None:
    bundle = _bundle()
    sig = bytearray(base64.b64decode(bundle["messageSignature"]["signature"]))
    sig[10] ^= 0xFF  # flip a byte in the ECDSA signature
    bundle["messageSignature"]["signature"] = base64.b64encode(bytes(sig)).decode()
    v = _verify(bundle=bundle)
    assert v.ok is False
    assert v.label == REASON_ARTIFACT_SIG_INVALID
    assert v.artifact_signature_verified is False


# --------------------------------------------------------------------------- fuzz / robustness


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\x00",
        b"not-a-certificate",
        bytes(range(40)),
        b"\x30\x82\xff\xff" + b"\x00" * 16,  # DER SEQUENCE header with a bogus length
    ],
)
def test_malformed_certificate_bytes_return_verdict_not_crash(raw: bytes) -> None:
    bundle = {
        "verificationMaterial": {
            "certificate": {"rawBytes": base64.b64encode(raw).decode()}
        }
    }
    v = _verify(bundle=bundle, integrated_time=_SCT_EPOCH)
    assert v.ok is False  # no exception escapes; a clean fail-closed verdict


def test_truncated_real_certificate_returns_verdict() -> None:
    bundle = _bundle()
    raw = base64.b64decode(bundle["verificationMaterial"]["certificate"]["rawBytes"])
    bundle["verificationMaterial"]["certificate"]["rawBytes"] = base64.b64encode(
        raw[: len(raw) // 2]
    ).decode()
    v = _verify(bundle=bundle, integrated_time=_SCT_EPOCH)
    assert v.ok is False


@pytest.mark.parametrize(
    "bundle",
    [
        {},
        {"verificationMaterial": {}},
        {"verificationMaterial": {"certificate": {}}},
        {"verificationMaterial": None},
    ],
)
def test_malformed_bundle_returns_no_certificate(bundle: dict) -> None:
    v = _verify(bundle=bundle, integrated_time=_SCT_EPOCH)
    assert v.ok is False
    assert v.label == REASON_NO_CERTIFICATE


# Redteam regression (2026-06-05): a malformed bundle must produce a fail-closed VERDICT, never an
# escaped exception. These probe the three escape classes found redteaming the native leg — each
# would otherwise propagate out of verify_fulcio_identity_native and crash the UNWRAPPED composite
# consumer verdict (the advisory leg becoming a denial-of-verdict).


@pytest.mark.parametrize("raw_bytes", [12345, ["a", "b"], True, {"x": 1}])
def test_nonstring_rawbytes_fails_closed_not_typeerror(raw_bytes: object) -> None:
    # R-2: base64.b64decode(non-string) raised TypeError; the caller caught only ValueError.
    bundle = _bundle()
    bundle["verificationMaterial"]["certificate"]["rawBytes"] = raw_bytes
    v = _verify(bundle=bundle, integrated_time=_SCT_EPOCH)  # no exception escapes
    assert v.ok is False
    assert v.label == REASON_CERT_PARSE_FAILED


@pytest.mark.parametrize("tlog", [["notadict"], [123], "xxx", [None]])
def test_malformed_tlog_falls_back_to_sct_time_not_attributeerror(tlog: object) -> None:
    # R-3: entries[0].get(...) on a non-dict raised AttributeError; _rekor_integrated_time caught
    # only KeyError/TypeError/ValueError/IndexError. A malformed tlog must degrade to the
    # CT-attested SCT time (the authenticated anchor), not crash. integrated_time omitted so the
    # leg exercises _rekor_integrated_time on the bundle.
    bundle = _bundle()
    bundle["verificationMaterial"]["tlogEntries"] = tlog
    v = _verify(bundle=bundle)  # no exception escapes
    assert v.ok is True
    assert v.label == FULCIO_OK_CT_ASSUMED
    assert v.time_anchor_source == TIME_ANCHOR_EMBEDDED_SCT


@pytest.mark.parametrize(
    "digest_bytes", [b"", b"\x00" * 16, b"\x00" * 31, b"\x00" * 64]
)
def test_wrong_length_message_digest_fails_closed_not_valueerror(
    digest_bytes: bytes,
) -> None:
    # R-1: a messageDigest whose decoded length != 32 fed to Prehashed(SHA-256) raised ValueError;
    # the verify caught only InvalidSignature. Must fail closed as ARTIFACT_SIGNATURE_INVALID.
    bundle = _bundle()
    bundle["messageSignature"]["messageDigest"]["digest"] = base64.b64encode(
        digest_bytes
    ).decode()
    v = _verify(bundle=bundle, integrated_time=_SCT_EPOCH)  # no exception escapes
    assert v.ok is False
    assert v.label == REASON_ARTIFACT_SIG_INVALID
    assert v.artifact_signature_verified is False


# --------------------------------------------------------------------------- anchors loader / OIDC


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.__setitem__("fulcio_roots_pem", [123]),  # non-string PEM entry
        lambda d: d.__setitem__("fulcio_intermediates_pem", [123]),
        lambda d: d["ctlogs"][0].__setitem__("key_pem", 5),
        lambda d: d.__setitem__("fulcio_roots_pem", "x"),  # not a list
        lambda d: d.pop("ctlogs"),  # missing key
    ],
)
def test_malformed_anchors_fixture_raises_fulcio_verify_error(mutate) -> None:
    # A malformed fixture must surface as FulcioVerifyError (the loader's contract), never a raw
    # AttributeError/etc. escaping — `[123]` previously escaped as AttributeError(.encode on int).
    data = json.loads(_ANCHORS.read_text())
    mutate(data)
    with pytest.raises(FulcioVerifyError):
        FulcioTrustAnchors.from_anchors_json(data)


def _cert_with_v2_issuer(ext_value: bytes) -> x509.Certificate:
    k = ec.generate_private_key(ec.SECP256R1())
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")]))
        .public_key(k.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .add_extension(
            x509.UnrecognizedExtension(
                ObjectIdentifier("1.3.6.1.4.1.57264.1.8"), ext_value
            ),
            critical=False,
        )
        .sign(k, hashes.SHA256())
    )


def test_v2_oidc_issuer_long_form_der_length_round_trips() -> None:
    # An issuer > 127 bytes uses DER long-form length (0x81 LL). The old short-form-only parse
    # mangled it (leading U+FFFD); the fixed reader round-trips it exactly.
    issuer = "https://" + ("a" * 200) + ".example.com"
    der = b"\x0c\x81" + bytes([len(issuer.encode())]) + issuer.encode()
    assert _extract_oidc_issuer(_cert_with_v2_issuer(der)) == issuer


@pytest.mark.parametrize(
    "ext_value",
    [
        b"\x0c\x7f",
        b"",
        b"\x04\x03abc",
        b"\x0c\x81",
    ],  # truncated / empty / wrong-tag / dangling len
)
def test_malformed_v2_oidc_issuer_returns_none_fail_closed(ext_value: bytes) -> None:
    # A malformed v2 issuer extension yields None (fail closed), not a garbled partial string that
    # could spuriously compare. With no v1 fallback present, the overall issuer is None.
    assert _extract_oidc_issuer(_cert_with_v2_issuer(ext_value)) is None


# --------------------------------------------------------------------------- helpers


def _rogue_bundle(
    *,
    san: str,
    oidc_issuer: str,
    not_before: datetime.datetime,
    not_after: datetime.datetime,
) -> tuple[dict, ec.EllipticCurvePrivateKey]:
    """A sigstore-shaped bundle whose leaf chains to a ROGUE self-signed CA (not the pinned root).

    Carries the correct SAN + Fulcio v1 OIDC-issuer extension so the test proves the chain check
    rejects it BEFORE any identity comparison. Includes a leaf-signed messageSignature (never
    reached — the chain fails first)."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rogue-ca")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    _ = ca  # the rogue CA is self-signed; the leaf below is signed by ca_key
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(2)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san)]),
            critical=True,
        )
        .add_extension(
            x509.UnrecognizedExtension(
                ObjectIdentifier("1.3.6.1.4.1.57264.1.1"), oidc_issuer.encode("utf-8")
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    raw_b64 = base64.b64encode(leaf.public_bytes(Encoding.DER)).decode()
    digest = hashes.Hash(hashes.SHA256())
    digest.update(b"rogue-artifact")
    msg_digest = digest.finalize()
    sig = leaf_key.sign(msg_digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    bundle = {
        "verificationMaterial": {"certificate": {"rawBytes": raw_b64}},
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": base64.b64encode(msg_digest).decode(),
            },
            "signature": base64.b64encode(sig).decode(),
        },
    }
    return bundle, leaf_key
