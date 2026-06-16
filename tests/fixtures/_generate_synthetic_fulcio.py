"""Generate a SYNTHETIC Fulcio keyless bundle + trust anchors for the native-Fulcio leg test.

WHY SYNTHETIC (not the real captured staging bundle):
    The PUBLIC release (github.com/veriker/veriker) signs releases from the PUBLIC repo,
    so the C18 cosign cert-identity the OSS test asserts must name the PUBLIC workflow. A real
    captured Sigstore-STAGING cert bakes its SAN (github.com/veriker/...) into SIGNED DER
    that no text rewrite can flip — so `release/oss_export.py`'s identity rewrite would change
    the test's expected SAN literal to the public identity while the captured cert kept the
    internal one, breaking `test_fulcio_native` in every exported tree. A synthetic self-signed
    chain legitimately carries the PUBLIC SAN in BOTH the source and exported trees.

WHY A SEPARATE FIXTURE (not overwriting sigstore_staging_bundle_v0_3.json):
    That real captured bundle is ALSO consumed by `tests/test_rekor_anchor.py` to ground the
    RFC 6962 inclusion recompute against a REAL transparency-log Merkle root — a deliberately
    non-tautological test ("a fabricated fixture would re-create the very tautology this exists
    to kill"). Replacing it with a synthetic cert would invalidate that real proof and gut the
    test. So the real bundle stays for rekor; this synthetic pair serves only the Fulcio leg.

WHAT IT EXERCISES (mirrors verify_fulcio_identity_native's four legs):
    (a) leaf -> synthetic intermediate -> synthetic PINNED root  (X.509 chain + validity window)
    (b) the PUBLIC SAN + the Fulcio OIDC-issuer extension          (identity, only after chain)
    (c) one embedded precert SCT signed by a synthetic CT-log key  (RFC 6962 §3.2 recompute)
    (d) a messageSignature over an artifact digest under the leaf key

Tier-2 lane (uses `cryptography`, off the stdlib-only core). Re-run to regenerate:
    python tests/fixtures/_generate_synthetic_fulcio.py
Keys are freshly generated each run; the test re-derives everything from the emitted fixtures
(no externally pinned value), so a regenerated pair stays self-consistent.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import struct
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from cryptography.x509.oid import NameOID, ObjectIdentifier

_UTC = datetime.timezone.utc
_HERE = Path(__file__).parent
# Make the package importable when the generator is run as a script (sys.path[0] is the
# fixtures dir, not the repo root) — needed for the verifier self-check in build_fixtures().
_REPO_ROOT = _HERE.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Order of the NIST P-256 (secp256r1) base-point group. Keys are derived DETERMINISTICALLY from
# fixed labels, so the key material / SPKIs / CT log_id are stable across regenerations (a
# reviewer re-running the generator gets the SAME identities, not fresh system-entropy keys).
# NOTE: the emitted JSON is NOT byte-identical across runs — ECDSA here uses random per-signature
# nonces (cryptography 41 has no RFC 6979 deterministic_signing), so the cert/SCT/artifact
# signatures differ each run. That is harmless: the test re-derives everything from the committed
# fixture, and the in-generator self-check (step 6) re-verifies the full 4-leg path on every run.
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _det_key(label: str) -> ec.EllipticCurvePrivateKey:
    """A deterministic secp256r1 private key from `label` (scalar in [1, n-1])."""
    d = (
        int.from_bytes(hashlib.sha256(label.encode("utf-8")).digest(), "big")
        % (_P256_N - 1)
        + 1
    )
    return ec.derive_private_key(d, ec.SECP256R1())


# The PUBLIC keyless-attest identity the synthetic leaf carries (matches what the export's
# identity rewrite produces from the internal staging literal, so the source `_STAGING_SAN`
# literal is already the public value and the rewrite of that line is a harmless no-op).
PUBLIC_SAN = (
    "https://github.com/veriker/veriker/.github/workflows/"
    "keyless-attest-staging.yml@refs/heads/main"
)
OIDC_ISSUER = "https://token.actions.githubusercontent.com"

# The embedded-SCT timestamp (epoch seconds) == the bundle's CT-attested trusted time. Kept
# byte-stable at the value test_fulcio_native already pins as `_SCT_EPOCH`.
SCT_EPOCH = 1780688301
# A real keyless leaf is valid for ~10 minutes; the test pins this window (e.g. +60s passes,
# +400 days fails CERT_NOT_VALID_AT_TRUSTED_TIME).
_LEAF_WINDOW_SECONDS = 600

# Fulcio / CT extension OIDs.
_OID_FULCIO_ISSUER_V1 = ObjectIdentifier("1.3.6.1.4.1.57264.1.1")  # raw UTF-8 issuer
_OID_PRECERT_SCT = ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")  # SCT list


def _der_len(n: int) -> bytes:
    """DER length octets (definite form), short or long as needed."""
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der_octet_string(content: bytes) -> bytes:
    return b"\x04" + _der_len(len(content)) + content


def _build_ca(
    common_name: str,
    key: ec.EllipticCurvePrivateKey,
    *,
    issuer_name: x509.Name | None = None,
    issuer_key: ec.EllipticCurvePrivateKey | None = None,
    not_before: datetime.datetime,
    not_after: datetime.datetime,
    serial: int,
) -> x509.Certificate:
    """A CA certificate (basicConstraints CA:TRUE). Self-signed unless an issuer is supplied."""
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    signing_key = issuer_key if issuer_key is not None else key
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name if issuer_name is not None else subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(signing_key, hashes.SHA256())
    )


def _spki_der(cert_or_key) -> bytes:
    pub = (
        cert_or_key.public_key() if hasattr(cert_or_key, "public_key") else cert_or_key
    )
    return pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def _leaf_extensions(
    san: str, oidc_issuer: str
) -> list[tuple[x509.ExtensionType, bool]]:
    """The leaf's non-SCT extensions, in a FIXED order (so stripping the appended SCT extension
    reproduces this exact precert TBS)."""
    return [
        (x509.BasicConstraints(ca=False, path_length=None), True),
        (
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san)]),
            True,
        ),
        (
            x509.UnrecognizedExtension(
                _OID_FULCIO_ISSUER_V1, oidc_issuer.encode("utf-8")
            ),
            False,
        ),
    ]


def _build_leaf(
    *,
    leaf_key: ec.EllipticCurvePrivateKey,
    issuer_name: x509.Name,
    issuer_key: ec.EllipticCurvePrivateKey,
    not_before: datetime.datetime,
    not_after: datetime.datetime,
    serial: int,
    extra_extensions: list[tuple[x509.ExtensionType, bool]] | None = None,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([])
        )  # keyless leaves carry identity in the SAN, not the subject
        .issuer_name(issuer_name)
        .public_key(leaf_key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    for ext, critical in _leaf_extensions(PUBLIC_SAN, OIDC_ISSUER):
        builder = builder.add_extension(ext, critical)
    for ext, critical in extra_extensions or []:
        builder = builder.add_extension(ext, critical)
    return builder.sign(issuer_key, hashes.SHA256())


def _sct_signed_payload(
    *, ts_ms: int, issuer_key_hash: bytes, precert_tbs: bytes, ext_bytes: bytes
) -> bytes:
    """The RFC 6962 §3.2 digitally-signed payload for a PRECERT entry — byte-for-byte the layout
    `fulcio_identity._verify_embedded_sct` reconstructs."""
    return (
        b"\x00"  # SCT version v1
        + b"\x00"  # SignatureType = certificate_timestamp
        + struct.pack(">Q", ts_ms)
        + b"\x00\x01"  # LogEntryType = precert_entry
        + issuer_key_hash
        + struct.pack(">I", len(precert_tbs))[
            1:
        ]  # uint24-length-prefixed TBSCertificate
        + precert_tbs
        + struct.pack(">H", len(ext_bytes))  # CtExtensions: 2-byte length
        + ext_bytes
    )


def _sct_list_extension_value(
    *, log_id: bytes, ts_ms: int, ext_bytes: bytes, sct_signature_der: bytes
) -> bytes:
    """Build the SignedCertificateTimestampList and wrap it in the inner DER OCTET STRING that
    the X.509 extension value carries (the outer extnValue OCTET STRING is added by cryptography's
    UnrecognizedExtension). TLS encoding per RFC 6962 §3.3 / §3.2."""
    # digitally-signed signature: SignatureAndHashAlgorithm (sha256=0x04, ecdsa=0x03) + opaque<16>.
    signature_block = (
        b"\x04\x03" + struct.pack(">H", len(sct_signature_der)) + sct_signature_der
    )
    serialized_sct = (
        b"\x00"  # version v1
        + log_id  # 32-byte LogID
        + struct.pack(">Q", ts_ms)  # timestamp (uint64 ms)
        + struct.pack(">H", len(ext_bytes))  # CtExtensions length-prefixed
        + ext_bytes
        + signature_block
    )
    # SerializedSCT (2-byte length) then the list wrapper (2-byte total length).
    sct_with_len = struct.pack(">H", len(serialized_sct)) + serialized_sct
    sct_list = struct.pack(">H", len(sct_with_len)) + sct_with_len
    return _der_octet_string(sct_list)


def build_fixtures() -> tuple[dict, dict]:
    sct_dt = datetime.datetime.fromtimestamp(SCT_EPOCH, tz=_UTC).replace(tzinfo=None)
    ts_ms = SCT_EPOCH * 1000
    leaf_not_before = sct_dt
    leaf_not_after = sct_dt + datetime.timedelta(seconds=_LEAF_WINDOW_SECONDS)
    ca_not_before = datetime.datetime(2020, 1, 1)
    ca_not_after = datetime.datetime(2035, 1, 1)

    root_key = _det_key("veriker-synthetic-fulcio-root")
    inter_key = _det_key("veriker-synthetic-fulcio-intermediate")
    leaf_key = _det_key("veriker-synthetic-fulcio-leaf")
    ct_key = _det_key("veriker-synthetic-ct-log")

    root = _build_ca(
        "veriker synthetic fulcio root",
        root_key,
        not_before=ca_not_before,
        not_after=ca_not_after,
        serial=1,
    )
    inter = _build_ca(
        "veriker synthetic fulcio intermediate",
        inter_key,
        issuer_name=root.subject,
        issuer_key=root_key,
        not_before=ca_not_before,
        not_after=ca_not_after,
        serial=2,
    )

    # (1) Build the PRECERT (leaf WITHOUT the SCT extension) -> its TBS is what the CT log signs
    #     and what `tbs_precertificate_bytes` reproduces from the final cert by stripping the SCT.
    precert = _build_leaf(
        leaf_key=leaf_key,
        issuer_name=inter.subject,
        issuer_key=inter_key,
        not_before=leaf_not_before,
        not_after=leaf_not_after,
        serial=3,
    )
    precert_tbs = precert.tbs_certificate_bytes

    # (2) Sign the RFC 6962 precert-entry payload with the CT-log key.
    issuer_key_hash = hashlib.sha256(_spki_der(inter)).digest()
    ct_log_id = hashlib.sha256(_spki_der(ct_key)).digest()
    ext_bytes = b""  # no CT extensions
    payload = _sct_signed_payload(
        ts_ms=ts_ms,
        issuer_key_hash=issuer_key_hash,
        precert_tbs=precert_tbs,
        ext_bytes=ext_bytes,
    )
    sct_sig = ct_key.sign(payload, ec.ECDSA(hashes.SHA256()))

    # (3) Build the FINAL leaf = precert extensions + the embedded SCT-list extension.
    sct_ext_value = _sct_list_extension_value(
        log_id=ct_log_id, ts_ms=ts_ms, ext_bytes=ext_bytes, sct_signature_der=sct_sig
    )
    leaf = _build_leaf(
        leaf_key=leaf_key,
        issuer_name=inter.subject,
        issuer_key=inter_key,
        not_before=leaf_not_before,
        not_after=leaf_not_after,
        serial=3,
        extra_extensions=[
            (x509.UnrecognizedExtension(_OID_PRECERT_SCT, sct_ext_value), False)
        ],
    )

    # (4) Self-check: stripping the SCT from the final cert MUST reproduce the precert TBS the SCT
    #     was signed over — otherwise the verifier's leg (c) recompute would not match.
    leaf = x509.load_der_x509_certificate(leaf.public_bytes(Encoding.DER))
    assert leaf.tbs_precertificate_bytes == precert_tbs, (
        "tbs_precertificate_bytes drift — the SCT would not verify"
    )

    # (5) The artifact signature (leg d): sign a digest under the leaf key.
    artifact = b"veriker synthetic release artifact"
    msg_digest = hashlib.sha256(artifact).digest()
    msg_sig = leaf_key.sign(msg_digest, ec.ECDSA(Prehashed(hashes.SHA256())))

    bundle = {
        "_comment": (
            "SYNTHETIC Sigstore-shaped keyless bundle for the native-Fulcio leg test "
            "(audit_bundle.extensions.fulcio_identity). NOT a real captured Sigstore entry; "
            "see tests/fixtures/_generate_synthetic_fulcio.py for why a synthetic public-SAN "
            "chain is used here while tests/fixtures/sigstore_staging_bundle_v0_3.json keeps the "
            "REAL captured entry for the rekor inclusion-proof grounding."
        ),
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {
                "rawBytes": base64.b64encode(leaf.public_bytes(Encoding.DER)).decode()
            },
            # integratedTime 0 -> the leg falls back to the CT-attested embedded-SCT time.
            "tlogEntries": [{"integratedTime": "0"}],
        },
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": base64.b64encode(msg_digest).decode(),
            },
            "signature": base64.b64encode(msg_sig).decode(),
        },
    }

    anchors = {
        "_comment": (
            "SYNTHETIC Fulcio trust anchors (root + intermediate CA + CT-log key) for the "
            "native-Fulcio leg test. Regenerate with tests/fixtures/_generate_synthetic_fulcio.py."
        ),
        "fulcio_roots_pem": [root.public_bytes(Encoding.PEM).decode()],
        "fulcio_intermediates_pem": [inter.public_bytes(Encoding.PEM).decode()],
        "ctlogs": [
            {
                "log_id_hex": ct_log_id.hex(),
                "key_details": "PKIX_ECDSA_P256_SHA_256",
                "key_pem": ct_key.public_key()
                .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                .decode(),
                "valid_start": "2020-01-01T00:00:00Z",
                "valid_end": "2035-01-01T00:00:00Z",
            }
        ],
    }

    # (6) LOAD-BEARING self-check — the property the whole fixture exists to protect. Run the
    #     REAL verifier over the emitted bundle/anchors and assert ALL FOUR legs verify
    #     INDEPENDENTLY. This proves the fixture is not a tautology (the verifier, not the
    #     generator's self-agreement, accepts it) AND that any future drift between this
    #     generator's RFC 6962 §3.2 SCT reconstruction and fulcio_identity._verify_embedded_sct
    #     is caught at regeneration time rather than silently producing a vacuous SCT leg.
    from audit_bundle.extensions.fulcio_identity import (  # noqa: PLC0415
        FULCIO_OK_CT_ASSUMED,
        FulcioTrustAnchors,
        verify_fulcio_identity_native,
    )

    verdict = verify_fulcio_identity_native(
        bundle,
        trust_anchors=FulcioTrustAnchors.from_anchors_json(anchors),
        expected_san=PUBLIC_SAN,
        expected_oidc_issuer=OIDC_ISSUER,
    )
    assert verdict.ok and verdict.label == FULCIO_OK_CT_ASSUMED, (
        f"the real verifier REJECTED the synthetic fixture: label={verdict.label} "
        f"reasons={verdict.reasons} — generator/verifier drift, fixture would be vacuous"
    )
    assert (
        verdict.chain_verified
        and verdict.identity_verified
        and verdict.sct_verified
        and verdict.artifact_signature_verified
    ), f"a leg did not verify independently (no-tautology check failed): {verdict}"
    return bundle, anchors


def main() -> None:
    bundle, anchors = build_fixtures()
    (_HERE / "synthetic_fulcio_bundle.json").write_text(
        json.dumps(bundle, indent=2) + "\n", encoding="utf-8"
    )
    (_HERE / "synthetic_fulcio_trust_anchors.json").write_text(
        json.dumps(anchors, indent=2) + "\n", encoding="utf-8"
    )
    print("wrote synthetic_fulcio_bundle.json + synthetic_fulcio_trust_anchors.json")


if __name__ == "__main__":
    main()
