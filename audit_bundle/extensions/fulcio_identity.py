"""SCITT v0.5 — NATIVE Fulcio identity verification (staging-grounded, advisory).

Promotes the Fulcio cert-identity check from DELEGATED-to-cosign to a NATIVE crypto leg:
parse the keyless Fulcio leaf cert from a Sigstore bundle and verify, WITHOUT cosign and
WITHOUT network, that

  (a) the leaf chains to a PINNED Fulcio root (X.509 signature path), and every cert in
      the path is valid AT the bundle's trusted time (Rekor integratedTime, or — when that
      is absent/zero, as in the staging keyless fixture — the CT-attested embedded-SCT
      timestamp) with bounded clock skew;
  (b) ONLY AFTER (a) passes: the SAN (the GitHub-Actions workflow identity) and the Fulcio
      OIDC-issuer extension pin-match the expected release identity. SAN-pin BEFORE chain
      verification would be a "string compare on attacker-controllable bytes" — so a broken
      chain short-circuits and the identity is NEVER reported as established;
  (c) the embedded precertificate SCT (RFC 6962 §3.2) verifies against the PINNED CT-log
      public key — a single ECDSA/SHA-256 signature check over the reconstructed precert.
      NO CT-inclusion fetch, NO TUF client, NO network;
  (d) the artifact signature (`messageSignature`) over the signed-blob digest verifies under
      the LEAF public key from the Fulcio cert. This establishes the identity-bound key →
      digest half of "verify, don't trust the signer" (the half cosign does NATIVELY here);
      it does NOT by itself re-hash the artifact bytes, so the digest → artifact half stays the
      CALLER's responsibility (the composite binds the verified digest to the COSE statement —
      `verified_message_digest` on the verdict is provided for exactly that). NOT full
      cosign-equivalence: cosign verify-blob re-hashes the blob; this leg takes no blob bytes.

‼ SCOPE / POSTURE:

  * This leg runs grounded on STAGING anchors in the test/CI path. Production
    `fulcio_identity` STAYS delegated-to-cosign as the AUTHORITATIVE leg until a PRODUCTION
    signing-ceremony test vector exercises the production Fulcio/CT/Rekor anchors. The staging
    native leg is ADDITIVE / ADVISORY, never authoritative, until then.
  * There is NO runtime {staging,production} trust switch (a downgrade-attack smell). Staging
    anchors live ONLY in the test/CI path; callers pass an explicit
    :class:`FulcioTrustAnchors`. The composite production verdict API hard-pins production
    anchors and exposes no env parameter.
  * The CT-log-consistency residual (split-view / equivocating log) is IRREDUCIBLE without an
    independent CT monitor. A pass is therefore labeled :data:`FULCIO_OK_CT_ASSUMED`, NEVER a
    bare ``ok`` and never "fully trustless." The label is load-bearing.
  * This is a bounded OFFLINE subset (X.509 chain + one SCT sig + one artifact sig), NOT a
    second Sigstore stack: no TUF, no network, no CT monitor, no Rekor write.

Tier-2 network-substrate side (sibling to rekor_anchor.py / c18_tuf_client.py). stdlib +
`cryptography` (an existing substrate dep). MUST NOT be pulled onto the offline stdlib core
(`veriker/cli/verify.py` / `audit_bundle/verifier.py`) per the two-verifier boundary.


"""

from __future__ import annotations

import base64
import binascii
import datetime
import hashlib
import struct
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)
from cryptography.x509.oid import ExtensionOID, ObjectIdentifier

_UTC = datetime.timezone.utc

# Fulcio X.509v3 extension OIDs (sigstore/fulcio "1.3.6.1.4.1.57264.1.*").
_OID_FULCIO_ISSUER_V1 = ObjectIdentifier(
    "1.3.6.1.4.1.57264.1.1"
)  # raw UTF-8 issuer (deprecated)
_OID_FULCIO_ISSUER_V2 = ObjectIdentifier(
    "1.3.6.1.4.1.57264.1.8"
)  # DER-wrapped UTF8String issuer

#: Label for a passing native Fulcio leg. Carries the irreducible CT-consistency assumption on
#: the face of the verdict — NEVER collapse to a bare ``ok`` or "trustless"; the label is
#: load-bearing.
FULCIO_OK_CT_ASSUMED = "FULCIO_OK_CT_ASSUMED"

#: Provenance tag for the staging-grounded native leg (vs production DELEGATED authority).
PROVENANCE_NATIVE_STAGING = "NATIVE_STAGING"

#: The irreducible residual surfaced on every passing verdict.
CT_CONSISTENCY_ASSUMPTION = (
    "CT-log split-view/consistency NOT checked (no independent CT monitor); SCT signature "
    "verified against the pinned CT-log key only. Irreducible offline residual."
)

# Time-anchor source tags.
TIME_ANCHOR_REKOR_INTEGRATED = "rekor_integrated_time"
TIME_ANCHOR_EMBEDDED_SCT = "embedded_sct_timestamp"

# --- Reason codes (stable strings; mirror rekor_anchor's style). ---
REASON_NO_CERTIFICATE = "BUNDLE_HAS_NO_CERTIFICATE"
REASON_CERT_PARSE_FAILED = "LEAF_CERTIFICATE_PARSE_FAILED"
REASON_CHAIN_BUILD_FAILED = "CHAIN_DOES_NOT_BUILD_TO_PINNED_ROOT"
REASON_LEAF_IS_CA = "LEAF_IS_A_CA_NOT_AN_END_ENTITY"
REASON_CERT_NOT_VALID_AT_TIME = "CERT_NOT_VALID_AT_TRUSTED_TIME"
REASON_NO_TIME_ANCHOR = "NO_TRUSTED_TIME_ANCHOR_AVAILABLE"
REASON_SAN_MISMATCH = "SAN_DISAGREES_WITH_EXPECTED_IDENTITY"
REASON_SAN_MISSING = "LEAF_HAS_NO_SAN_URI"
REASON_OIDC_ISSUER_MISMATCH = "OIDC_ISSUER_DISAGREES_WITH_EXPECTED_ISSUER"
REASON_OIDC_ISSUER_MISSING = "LEAF_HAS_NO_FULCIO_OIDC_ISSUER_EXTENSION"
REASON_SCT_MISSING = "LEAF_HAS_NO_EMBEDDED_SCT"
REASON_SCT_NO_MATCHING_CT_KEY = "NO_PINNED_CT_KEY_MATCHES_SCT_LOG_ID"
REASON_SCT_SIGNATURE_INVALID = "SCT_SIGNATURE_INVALID"
REASON_SCT_PARSE_FAILED = "SCT_PARSE_FAILED"
REASON_ARTIFACT_SIG_MISSING = "BUNDLE_HAS_NO_MESSAGE_SIGNATURE"
REASON_ARTIFACT_SIG_INVALID = "ARTIFACT_SIGNATURE_INVALID_UNDER_LEAF_KEY"


class FulcioVerifyError(RuntimeError):
    """Raised on a malformed trust-anchors fixture (programmer/config error, not a verdict)."""


# -----------------------------------------------------------------------------
# Trust anchors (PUBLIC keys). Loaded from the pinned staging fixture in tests/CI.
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class CtLogKey:
    """One pinned CT-log key, indexed by its 32-byte logId (= SHA-256(DER SPKI))."""

    log_id: bytes
    public_key: ec.EllipticCurvePublicKey | rsa.RSAPublicKey
    valid_start: datetime.datetime | None
    valid_end: datetime.datetime | None

    def valid_at(self, when: datetime.datetime) -> bool:
        if self.valid_start is not None and when < self.valid_start:
            return False
        if self.valid_end is not None and when >= self.valid_end:
            return False
        return True


@dataclass(frozen=True)
class FulcioTrustAnchors:
    """Pinned Fulcio CA roots + candidate intermediates + CT-log keys for ONE trust environment.

    There is deliberately no "environment" field and no production/staging selector here: a
    caller binds a specific set of PUBLIC anchors. The staging set is used only by the test/CI
    native leg; the production verdict API pins production anchors separately. This separation
    (not a runtime switch) is the no-downgrade posture: there is no env-driven way to swap in
    weaker anchors at runtime.
    """

    fulcio_roots: tuple[x509.Certificate, ...]
    fulcio_intermediates: tuple[x509.Certificate, ...]
    ctlogs: tuple[CtLogKey, ...]

    @classmethod
    def from_anchors_json(cls, data: dict) -> "FulcioTrustAnchors":
        """Build from the `sigstore_staging_trust_anchors.json` shape (see the fixture generator)."""
        try:
            roots = tuple(
                x509.load_pem_x509_certificate(p.encode("ascii"))
                for p in data["fulcio_roots_pem"]
            )
            intermediates = tuple(
                x509.load_pem_x509_certificate(p.encode("ascii"))
                for p in data["fulcio_intermediates_pem"]
            )
            ctlogs = tuple(
                CtLogKey(
                    log_id=bytes.fromhex(c["log_id_hex"]),
                    public_key=load_pem_public_key(c["key_pem"].encode("ascii")),  # type: ignore[arg-type]
                    valid_start=_parse_iso(c.get("valid_start")),
                    valid_end=_parse_iso(c.get("valid_end")),
                )
                for c in data["ctlogs"]
            )
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            # AttributeError: a non-string PEM entry (e.g. an int) reaching .encode(). Treat any
            # such shape error as a malformed fixture -> FulcioVerifyError, never a raw escape.
            raise FulcioVerifyError(
                f"malformed Fulcio trust-anchors fixture: {exc}"
            ) from exc
        if not roots:
            raise FulcioVerifyError("trust anchors carry no Fulcio roots")
        return cls(roots, intermediates, ctlogs)


def _parse_iso(value: str | None) -> datetime.datetime | None:
    if not value:
        return None
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))


def _embedded_scts(leaf: x509.Certificate) -> list[Any]:
    """The leaf's embedded precert SCTs as a plain list (empty if the extension is absent).

    cryptography types the extension `.value` loosely as `ExtensionType`; the concrete
    `PrecertificateSignedCertificateTimestamps` value is iterable over SCT objects.
    """
    try:
        ext = leaf.extensions.get_extension_for_oid(
            ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS
        ).value
    except x509.ExtensionNotFound:
        return []
    return list(ext)  # type: ignore[call-overload]


# -----------------------------------------------------------------------------
# Verdict.
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class FulcioNativeVerdict:
    """Outcome of the native Fulcio identity verification.

    ``ok`` is True ONLY when all four checks pass (chain+validity, identity, SCT, artifact-sig).
    ``label`` is :data:`FULCIO_OK_CT_ASSUMED` on a pass (carrying the irreducible CT residual) and
    a failure reason otherwise. ``provenance`` is :data:`PROVENANCE_NATIVE_STAGING` — this leg is
    advisory, never the authoritative production verdict, until the production signing ceremony.
    """

    ok: bool
    label: str
    provenance: str
    chain_verified: bool
    identity_verified: bool
    sct_verified: bool
    artifact_signature_verified: bool
    verified_identity: str | None
    verified_oidc_issuer: str | None
    #: The artifact digest that the leaf signature (leg d) was VERIFIED to cover, on a pass (None
    #: otherwise). Exposed so a caller can bind it to the actual artifact / COSE statement WITHOUT
    #: re-reading the raw bundle — closing the key→digest→artifact chain off the verified value.
    verified_message_digest: bytes | None
    time_anchor_source: str | None
    time_anchor_epoch_seconds: int | None
    ct_assumption: str
    reasons: tuple[str, ...]


# -----------------------------------------------------------------------------
# (a) chain build + validity at the trusted time.
# -----------------------------------------------------------------------------


def _verify_cert_signature(child: x509.Certificate, parent: x509.Certificate) -> bool:
    """True iff `parent` signed `child` (ECDSA or RSA-PKCS1v15; the Fulcio cert types)."""
    pub = parent.public_key()
    hash_alg = child.signature_hash_algorithm
    if hash_alg is None:
        return False
    try:
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(hash_alg),
            )
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(
                child.signature,
                child.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hash_alg,
            )
        else:
            return False
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
        return bool(bc.ca)  # type: ignore[attr-defined]
    except x509.ExtensionNotFound:
        return False


def _not_before(cert: x509.Certificate) -> datetime.datetime:
    return cert.not_valid_before.replace(tzinfo=_UTC)


def _not_after(cert: x509.Certificate) -> datetime.datetime:
    return cert.not_valid_after.replace(tzinfo=_UTC)


def _build_and_validate_chain(
    leaf: x509.Certificate,
    anchors: FulcioTrustAnchors,
    when: datetime.datetime,
    skew: datetime.timedelta,
) -> tuple[bool, list[str], x509.Certificate | None]:
    """Build leaf -> intermediate(s) -> pinned root and validate signatures + validity-at-`when`.

    Minimal sound path validation (NOT full RFC 5280): each link's signature verifies, every cert
    is valid at `when` (± `skew`), non-leaf certs assert basicConstraints CA, and the path
    terminates at a PINNED trusted root (matched by exact fingerprint).

    Returns ``(ok, reasons, leaf_signer)`` where `leaf_signer` is the cert that was VERIFIED to
    have signed the leaf (the leaf's issuing intermediate). Callers that need the issuer for SCT
    `issuer_key_hash` MUST use this returned object — not a separate subject-name rematch — so the
    SCT is bound to the SAME key the chain validated (defends against a CA-key-rollover anchor set
    with two intermediates sharing a subject DN but different keys).
    """
    reasons: list[str] = []
    root_fps = {r.fingerprint(hashes.SHA256()) for r in anchors.fulcio_roots}
    by_subject: dict[bytes, list[x509.Certificate]] = {}
    for c in (*anchors.fulcio_intermediates, *anchors.fulcio_roots):
        by_subject.setdefault(c.subject.public_bytes(), []).append(c)

    def valid_at(cert: x509.Certificate) -> bool:
        return _not_before(cert) - skew <= when <= _not_after(cert) + skew

    # An end-entity Fulcio leaf is never a CA. Reject a CA cert in the leaf slot up front (real
    # path validation does the same) — otherwise a PINNED intermediate presented as the leaf would
    # report chain_verified=True and only fail later at SAN/SCT. Fail at the chain, before identity.
    if _is_ca(leaf):
        reasons.append(REASON_LEAF_IS_CA)
        return False, reasons, None

    current = leaf
    leaf_signer: x509.Certificate | None = None
    if not valid_at(current):
        reasons.append(REASON_CERT_NOT_VALID_AT_TIME)
    # Walk up to the root; bounded depth guards against cycles / over-long chains.
    for depth in range(8):
        if (
            current.fingerprint(hashes.SHA256()) in root_fps
            and current.subject == current.issuer
        ):
            # Reached a pinned self-signed root whose own signature we still confirm.
            if not _verify_cert_signature(current, current):
                reasons.append(REASON_CHAIN_BUILD_FAILED)
            return (not reasons), reasons, leaf_signer
        parents = by_subject.get(current.issuer.public_bytes(), [])
        signer = next((p for p in parents if _verify_cert_signature(current, p)), None)
        if signer is None:
            reasons.append(REASON_CHAIN_BUILD_FAILED)
            return False, reasons, leaf_signer
        if not _is_ca(signer):
            # An issuer that is not a CA cannot sign certs — reject.
            reasons.append(REASON_CHAIN_BUILD_FAILED)
            return False, reasons, leaf_signer
        if depth == 0:
            leaf_signer = (
                signer  # the VERIFIED signer of the leaf (for SCT issuer_key_hash)
            )
        if not valid_at(signer):
            reasons.append(REASON_CERT_NOT_VALID_AT_TIME)
        current = signer
    reasons.append(
        REASON_CHAIN_BUILD_FAILED
    )  # exceeded max depth without a pinned root
    return False, reasons, leaf_signer


# -----------------------------------------------------------------------------
# (b) SAN + OIDC issuer (ONLY after chain validation).
# -----------------------------------------------------------------------------


def _extract_san_uris(leaf: x509.Certificate) -> list[str]:
    try:
        san = leaf.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
    except x509.ExtensionNotFound:
        return []
    return list(san.get_values_for_type(x509.UniformResourceIdentifier))  # type: ignore[arg-type]


def _der_utf8string(raw: bytes) -> str | None:
    """Decode a DER UTF8String (tag 0x0C) honoring BOTH short- and long-form lengths.

    Returns None on a non-UTF8String tag, an indefinite/implausible length, or a truncated value —
    so a malformed v2 issuer extension fails closed (no garbled partial that could spuriously match)
    rather than the previous short-form-only parse that mangled any issuer longer than 127 bytes.
    """
    if len(raw) < 2 or raw[0] != 0x0C:
        return None
    length_byte = raw[1]
    if length_byte < 0x80:  # short form: the byte IS the length
        ln, off = length_byte, 2
    else:  # long form: low 7 bits = count of subsequent length octets
        n = length_byte & 0x7F
        if (
            n == 0 or n > 4 or len(raw) < 2 + n
        ):  # indefinite or implausibly large -> reject
            return None
        ln, off = int.from_bytes(raw[2 : 2 + n], "big"), 2 + n
    if len(raw) < off + ln:  # truncated value
        return None
    try:
        # Strict: a non-UTF-8 issuer value is malformed — reject (None) rather
        # than lenient-decode attacker bytes into U+FFFD and ==-compare.
        return raw[off : off + ln].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None


def _extract_oidc_issuer(leaf: x509.Certificate) -> str | None:
    """The Fulcio OIDC-issuer claim. Prefer the v2 DER-wrapped extension; fall back to v1 raw."""
    for oid, der_wrapped in (
        (_OID_FULCIO_ISSUER_V2, True),
        (_OID_FULCIO_ISSUER_V1, False),
    ):
        try:
            raw = leaf.extensions.get_extension_for_oid(oid).value.value  # type: ignore[attr-defined]
        except x509.ExtensionNotFound:
            continue
        except AttributeError:
            # A future cryptography could parse this OID into a typed extension lacking `.value`.
            continue
        if not isinstance(raw, (bytes, bytearray)):
            continue
        raw = bytes(raw)
        if der_wrapped:
            issuer = _der_utf8string(raw)  # v2 is a DER-encoded UTF8String
            if issuer is not None:
                return issuer
            continue
        return raw.decode("utf-8", errors="replace")  # v1 is the raw UTF-8 issuer
    return None


def _canon(value: str) -> str:
    return value.strip().rstrip("/")


# -----------------------------------------------------------------------------
# (c) embedded precert SCT verification (RFC 6962 §3.2).
# -----------------------------------------------------------------------------


def _verify_embedded_sct(
    leaf: x509.Certificate, issuer: x509.Certificate, anchors: FulcioTrustAnchors
) -> tuple[bool, datetime.datetime | None, list[str]]:
    """Verify the leaf's embedded precertificate SCT against a pinned CT-log key.

    Reconstructs the RFC 6962 §3.2 digitally-signed payload for a precert entry
    (version‖SignatureType‖timestamp‖entry_type‖issuer_key_hash‖TBS(no SCT ext)‖CtExtensions)
    and checks one ECDSA/SHA-256 signature against the CT key whose logId matches the SCT and is
    valid at the SCT timestamp. Returns (ok, sct_time, reasons). NO CT-inclusion fetch.
    """
    reasons: list[str] = []
    scts = _embedded_scts(leaf)
    if not scts:
        reasons.append(REASON_SCT_MISSING)
        return False, None, reasons

    issuer_key_hash = hashlib.sha256(
        issuer.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
    ).digest()
    try:
        tbs = (
            leaf.tbs_precertificate_bytes
        )  # TBSCertificate with the SCT extension stripped
    except Exception:  # noqa: BLE001 - cryptography raises a generic error if unavailable
        reasons.append(REASON_SCT_PARSE_FAILED)
        return False, None, reasons

    sct_time: datetime.datetime | None = None
    for sct in scts:
        try:
            ts = sct.timestamp.replace(tzinfo=_UTC)
            ts_ms = int(ts.timestamp() * 1000)
            ext_bytes = sct.extension_bytes
            signed = (
                b"\x00"  # SCT version v1
                + b"\x00"  # SignatureType = certificate_timestamp
                + struct.pack(">Q", ts_ms)
                + b"\x00\x01"  # LogEntryType = precert_entry
                + issuer_key_hash
                + struct.pack(">I", len(tbs))[
                    1:
                ]  # uint24 length-prefixed TBSCertificate
                + tbs
                + struct.pack(">H", len(ext_bytes))  # CtExtensions: 2-byte length
                + ext_bytes
            )
        except (struct.error, ValueError):
            reasons.append(REASON_SCT_PARSE_FAILED)
            continue
        ctkey = next(
            (c for c in anchors.ctlogs if c.log_id == sct.log_id and c.valid_at(ts)),
            None,
        )
        if ctkey is None:
            reasons.append(REASON_SCT_NO_MATCHING_CT_KEY)
            continue
        try:
            if isinstance(ctkey.public_key, ec.EllipticCurvePublicKey):
                ctkey.public_key.verify(
                    sct.signature, signed, ec.ECDSA(hashes.SHA256())
                )
            elif isinstance(ctkey.public_key, rsa.RSAPublicKey):
                ctkey.public_key.verify(
                    sct.signature, signed, padding.PKCS1v15(), hashes.SHA256()
                )
            else:
                reasons.append(REASON_SCT_SIGNATURE_INVALID)
                continue
            return True, ts, []  # first SCT that verifies is sufficient
        except InvalidSignature:
            reasons.append(REASON_SCT_SIGNATURE_INVALID)
            sct_time = ts
    return False, sct_time, reasons


# -----------------------------------------------------------------------------
# (d) artifact signature under the leaf key.
# -----------------------------------------------------------------------------


def _verify_artifact_signature(
    bundle: dict, leaf: x509.Certificate
) -> tuple[bool, list[str], bytes | None]:
    """Verify `messageSignature.signature` over the artifact digest using the leaf public key.

    SCOPE: this proves "the leaf key signed THIS digest value", not "the leaf key signed the
    artifact bytes". Binding the digest to the actual artifact (re-hashing the signed blob and
    comparing) is the CALLER's responsibility — see the composite verifier's optional
    statement-binding check. Here we only verify the signature over the supplied digest.
    """
    ms = bundle.get("messageSignature")
    if not isinstance(ms, dict):
        return False, [REASON_ARTIFACT_SIG_MISSING], None
    try:
        sig = base64.b64decode(ms["signature"], validate=True)
        digest = base64.b64decode(ms["messageDigest"]["digest"], validate=True)
        algorithm = ms["messageDigest"].get("algorithm", "SHA2_256")
    except (KeyError, TypeError, binascii.Error, ValueError):
        return False, [REASON_ARTIFACT_SIG_MISSING], None
    if algorithm != "SHA2_256":
        return False, [REASON_ARTIFACT_SIG_INVALID], None
    pub = leaf.public_key()
    try:
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(sig, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(sig, digest, padding.PKCS1v15(), Prehashed(hashes.SHA256()))
        else:
            return False, [REASON_ARTIFACT_SIG_INVALID], None
    except (InvalidSignature, ValueError):
        # ValueError: a messageDigest whose decoded length != the Prehashed(SHA-256) digest size
        # (32). cryptography raises ValueError, NOT InvalidSignature, for that — catch both so a
        # malformed digest fails closed rather than escaping as an uncaught exception.
        return False, [REASON_ARTIFACT_SIG_INVALID], None
    # Return the digest that was VERIFIED under the leaf key, so the caller can bind it to the
    # actual artifact off the value that passed the check (not a separate re-read of the bundle).
    return True, [], digest


# -----------------------------------------------------------------------------
# Public entry point.
# -----------------------------------------------------------------------------


def _leaf_from_bundle(bundle: dict) -> x509.Certificate:
    material = bundle.get("verificationMaterial")
    if not isinstance(material, dict):
        raise FulcioVerifyError(REASON_NO_CERTIFICATE)
    cert_obj = material.get("certificate")
    raw_b64 = cert_obj.get("rawBytes") if isinstance(cert_obj, dict) else None
    if not raw_b64:
        # v0.3 bundles may carry a single cert; older ones a x509CertificateChain.
        chain = material.get("x509CertificateChain", {})
        certs = chain.get("certificates") if isinstance(chain, dict) else None
        raw_b64 = certs[0].get("rawBytes") if certs else None
    if not raw_b64:
        raise FulcioVerifyError(REASON_NO_CERTIFICATE)
    return x509.load_der_x509_certificate(base64.b64decode(raw_b64))


def _rekor_integrated_time(bundle: dict) -> int | None:
    """Best-effort Rekor integratedTime (seconds) from a Sigstore protobuf bundle. 0/absent => None."""
    try:
        entries = bundle["verificationMaterial"]["tlogEntries"]
        t = int(entries[0].get("integratedTime", 0))
        return t if t > 0 else None
    except (KeyError, TypeError, ValueError, IndexError, AttributeError):
        # AttributeError: tlogEntries holding non-dicts (entries[0].get on a str/int). Treat any
        # malformed tlog as "no Rekor time" -> fall back to the CT-attested SCT time. Fail closed.
        return None


def verify_fulcio_identity_native(
    bundle: dict,
    *,
    trust_anchors: FulcioTrustAnchors,
    expected_san: str,
    expected_oidc_issuer: str,
    integrated_time: int | None = None,
    skew_seconds: int = 300,
) -> FulcioNativeVerdict:
    """Natively verify the Fulcio cert-identity of a Sigstore keyless bundle (staging-grounded).

    Checks run in a STRICT ORDER (chain BEFORE SAN), so identity is never read off an
    unverified cert: (a) X.509 chain to a pinned root + validity at the trusted time;
    (b) SAN + OIDC-issuer pin-match — evaluated ONLY after
    (a) passes; (c) embedded precert SCT vs the pinned CT key; (d) artifact signature under the
    leaf key. A pass is labeled :data:`FULCIO_OK_CT_ASSUMED`.

    Trusted time: `integrated_time` (Rekor, seconds) when > 0, else the CT-attested embedded-SCT
    timestamp (the staging keyless fixture records integratedTime=0). The SCT timestamp's
    authenticity is itself established by leg (c), which is REQUIRED for ``ok`` — so the fallback
    introduces no unverified trust input.
    """
    reasons: list[str] = []
    skew = datetime.timedelta(seconds=skew_seconds)

    def fail(label: str) -> FulcioNativeVerdict:
        return FulcioNativeVerdict(
            ok=False,
            label=label,
            provenance=PROVENANCE_NATIVE_STAGING,
            chain_verified=chain_ok,
            identity_verified=identity_ok,
            sct_verified=sct_ok,
            artifact_signature_verified=artifact_ok,
            verified_identity=verified_identity,
            verified_oidc_issuer=verified_issuer,
            verified_message_digest=verified_digest,
            time_anchor_source=anchor_source,
            time_anchor_epoch_seconds=anchor_seconds,
            ct_assumption=CT_CONSISTENCY_ASSUMPTION,
            reasons=tuple(reasons),
        )

    chain_ok = identity_ok = sct_ok = artifact_ok = False
    verified_identity: str | None = None
    verified_issuer: str | None = None
    verified_digest: bytes | None = None
    anchor_source: str | None = None
    anchor_seconds: int | None = None

    try:
        leaf = _leaf_from_bundle(bundle)
    except FulcioVerifyError:
        reasons.append(REASON_NO_CERTIFICATE)
        return fail(REASON_NO_CERTIFICATE)
    except (ValueError, TypeError):
        # TypeError: a non-string `rawBytes` (int/list/bool) fed to base64.b64decode. Fail
        # closed as a parse error — never let it escape as an uncaught exception.
        reasons.append(REASON_CERT_PARSE_FAILED)
        return fail(REASON_CERT_PARSE_FAILED)

    # Resolve the trusted-time anchor. Prefer Rekor integratedTime; else the embedded SCT time.
    rekor_t = (
        integrated_time
        if integrated_time is not None
        else _rekor_integrated_time(bundle)
    )
    if rekor_t is None:
        scts = _embedded_scts(leaf)
        if scts:
            when = scts[0].timestamp.replace(tzinfo=_UTC)
            anchor_source = TIME_ANCHOR_EMBEDDED_SCT
            anchor_seconds = int(when.timestamp())
        else:
            reasons.append(REASON_NO_TIME_ANCHOR)
            return fail(REASON_NO_TIME_ANCHOR)
    else:
        anchor_source = TIME_ANCHOR_REKOR_INTEGRATED
        anchor_seconds = rekor_t
        when = datetime.datetime.fromtimestamp(rekor_t, tz=_UTC)

    # (a) chain build + validity at the trusted time. MUST pass before SAN is even read.
    # `leaf_signer` is the cert VERIFIED to have signed the leaf — fed to the SCT leg so
    # issuer_key_hash binds to the chain-validated key, not a separate subject-name rematch.
    chain_ok, chain_reasons, leaf_signer = _build_and_validate_chain(
        leaf, trust_anchors, when, skew
    )
    reasons.extend(chain_reasons)
    if not chain_ok or leaf_signer is None:
        if leaf_signer is None and REASON_CHAIN_BUILD_FAILED not in reasons:
            reasons.append(REASON_CHAIN_BUILD_FAILED)
        # Surface the most specific chain reason (e.g. expired-at-time) on the label.
        return fail(chain_reasons[0] if chain_reasons else REASON_CHAIN_BUILD_FAILED)

    # (b) identity — SAN + OIDC issuer — ONLY now that the chain is trusted.
    san_uris = _extract_san_uris(leaf)
    if not san_uris:
        reasons.append(REASON_SAN_MISSING)
        return fail(REASON_SAN_MISSING)
    if not any(_canon(u) == _canon(expected_san) for u in san_uris):
        reasons.append(REASON_SAN_MISMATCH)
        return fail(REASON_SAN_MISMATCH)
    verified_identity = expected_san
    oidc = _extract_oidc_issuer(leaf)
    if oidc is None:
        reasons.append(REASON_OIDC_ISSUER_MISSING)
        return fail(REASON_OIDC_ISSUER_MISSING)
    if _canon(oidc) != _canon(expected_oidc_issuer):
        reasons.append(REASON_OIDC_ISSUER_MISMATCH)
        return fail(REASON_OIDC_ISSUER_MISMATCH)
    verified_issuer = oidc
    identity_ok = True

    # (c) embedded precert SCT vs the pinned CT key (issuer = the chain-validated leaf signer).
    sct_ok, _sct_time, sct_reasons = _verify_embedded_sct(
        leaf, leaf_signer, trust_anchors
    )
    reasons.extend(sct_reasons)
    if not sct_ok:
        return fail(sct_reasons[-1] if sct_reasons else REASON_SCT_SIGNATURE_INVALID)

    # (d) artifact signature under the leaf key.
    artifact_ok, art_reasons, verified_digest = _verify_artifact_signature(bundle, leaf)
    reasons.extend(art_reasons)
    if not artifact_ok:
        return fail(art_reasons[-1] if art_reasons else REASON_ARTIFACT_SIG_INVALID)

    return FulcioNativeVerdict(
        ok=True,
        label=FULCIO_OK_CT_ASSUMED,
        provenance=PROVENANCE_NATIVE_STAGING,
        chain_verified=True,
        identity_verified=True,
        sct_verified=True,
        artifact_signature_verified=True,
        verified_identity=verified_identity,
        verified_oidc_issuer=verified_issuer,
        verified_message_digest=verified_digest,
        time_anchor_source=anchor_source,
        time_anchor_epoch_seconds=anchor_seconds,
        ct_assumption=CT_CONSISTENCY_ASSUMPTION,
        reasons=(),
    )
