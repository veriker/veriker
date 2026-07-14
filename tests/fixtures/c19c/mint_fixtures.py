"""Deterministic test-fixture mint helper for S19c.

Mints test-only Ed25519 SREP envelopes and test-only RFC 3161 CMS tokens
against test-only Ed25519 / RSA keypairs derived deterministically from a
seed. Tests monkeypatch the verifier's pinned constants
(`PINNED_ROUGHTIME_ROOTS`, `NEXI_TSA_ALLOWLIST`, plus the per-TSA cert /
BLS-pubkey registries the verifier resolves through its module surface)
with the TEST keys for the duration of each test.

The fixtures are designed so production pinned keys are NEVER reached
during tests — the monkeypatch logs a marker line and the test asserts
on caplog.

v0.3 reference-implementation envelope shape (NOT exact draft-19 RESP
wire format; v0.4 substrate hardening binds the wire format to draft-19
RESP exactly):

    srep_bytes = cbor2.dumps({
        "PUBK": pubkey_raw_32B,
        "MIDP": midp_ms_uint,
        "RADI": radi_ms_uint,
        "NONC": nonce_32B,
    }, canonical=True)
    srep_signature = ed25519_sign(sk, srep_bytes)
    transmitted = cbor2.dumps({"srep": srep_bytes, "sig": srep_signature},
                              canonical=True)

The verifier's `verify_per_event_roughtime_quorum` reverses this:
    pkt = cbor2.loads(transmitted)
    srep = cbor2.loads(pkt["srep"])
    ed25519_verify(pinned_pubkey, pkt["srep"], pkt["sig"])
    -> extracts MIDP, RADI, NONC from srep

Test-only TSA token envelope shape (NOT exact RFC 3161 CMS; reference-
implementation v0.3, v0.4 substrate hardening adopts full RFC 3161 CMS):

    cms_token_dict = {
        "tsa_name": str,
        "messageImprint": {
            "hashAlgorithm": "sha256" | "sha384" | "sha1",
            "hashedMessage_hex": str,
        },
        "nonce_hex": str | None,
        "genTime_iso": str,
        "policyOid": str,
        "signature_b64": base64(ed25519_sign(tsa_signing_sk,
                                             json.dumps(payload, sort_keys=True).encode())),
        "signing_cert_pem": <PEM of TSA signing cert chained to test CA root>,
        "ca_chain_pem": <PEM of test CA root>,
    }
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
from typing import Any

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

from audit_bundle.extensions.c19.tsa_roughtime_bls import ROUGHTIME_NONCE_DOMAIN

# Deterministic 32-byte seeds for Ed25519 keys (NOT secrets — test fixtures only).
_ROOT_NAMES_FOR_TEST = (
    "cloudflare-roughtime-2",
    "int08h-roughtime",
    "roughtime-se",
    "time-txryan-com",
)
_ROOT_SEEDS = {
    name: hashlib.sha256(f"S19c-test-roughtime-{name}".encode()).digest()
    for name in _ROOT_NAMES_FOR_TEST
}

_TSA_NAMES_FOR_TEST = (
    "digicert-tsa",
    "globalsign-tsa",
    "cellnex-tsa",
    "entrust-tsa",
    "placeholder-tsa-5",
)
_TSA_SEEDS = {
    name: hashlib.sha256(f"S19c-test-tsa-{name}".encode()).digest()
    for name in _TSA_NAMES_FOR_TEST
}

# ETSI EN 319 421/422 policy OID allowlist (subset; matches verifier).
ETSI_POLICY_OID_ALLOWLIST = (
    "0.4.0.2023.1.1",  # ETSI EN 319 421 baseline policy
    "0.4.0.194112.1.0",  # ETSI EN 319 422 BTSP policy
)


def deterministic_cbor(obj: Any) -> bytes:
    """R6-002 deterministic-CBOR encoder. Wraps cbor2 with canonical=True
    (RFC 8949 §4.2.1 deterministic encoding)."""
    return cbor2.dumps(obj, canonical=True)


def expected_nonce_for(preimage_label: str, preimage_bytes: bytes) -> bytes:
    """R6-002 nonce-binding: sha256(deterministic_cbor({"label",
    "preimage"}) || ROUGHTIME_NONCE_DOMAIN). Both fixture-mint and
    verifier MUST use this exact recipe."""
    cbor_blob = deterministic_cbor(
        {"label": preimage_label, "preimage": preimage_bytes}
    )
    return hashlib.sha256(cbor_blob + ROUGHTIME_NONCE_DOMAIN).digest()


# ──────────────────────────────────────────────────────────────────────────
# Roughtime test keys + SREP minting
# ──────────────────────────────────────────────────────────────────────────


def make_roughtime_test_keypair(
    root_name: str,
) -> tuple[ed25519.Ed25519PrivateKey, bytes]:
    """Returns (signing_key, pubkey_raw_32B) for the test root."""
    seed = _ROOT_SEEDS[root_name]
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    pk_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sk, pk_bytes


def make_test_pinned_roughtime_roots() -> tuple[dict, ...]:
    """Returns a 4-element tuple matching `PINNED_ROUGHTIME_ROOTS` shape but
    with test Ed25519 pubkeys. Tests monkeypatch
    `tsa_roughtime_bls.PINNED_ROUGHTIME_ROOTS` with this."""
    roots = []
    pinned_meta = {
        "cloudflare-roughtime-2": (
            "roughtime.cloudflare.com",
            2003,
            "US",
            "Cloudflare, Inc.",
        ),
        "int08h-roughtime": ("roughtime.int08h.com", 2002, "US", "int08h LLC"),
        "roughtime-se": ("roughtime.se", 2002, "EU-SE", "STUPI AB"),
        "time-txryan-com": (
            "time.txryan.com",
            2002,
            "US",
            "Tx Ryan (independent operator)",
        ),
    }
    for name in _ROOT_NAMES_FOR_TEST:
        _, pk_bytes = make_roughtime_test_keypair(name)
        addr, port, jur, org = pinned_meta[name]
        roots.append(
            {
                "name": name,
                "address": addr,
                "port": port,
                "pubkey_b64": base64.b64encode(pk_bytes).decode("ascii"),
                "jurisdiction": jur,
                "operator_org": org,
            }
        )
    return tuple(roots)


def mint_srep(
    *,
    root_name: str,
    midp_ms: int,
    radi_ms: int,
    nonce: bytes,
    pubkey_override: bytes | None = None,
    signing_key_override: ed25519.Ed25519PrivateKey | None = None,
) -> dict:
    """Mint a single SREP response dict in the shape `verify_per_event_
    roughtime_quorum` consumes from `srep_responses`.

    `pubkey_override` lets a test simulate a SREP claiming to be from a
    pinned root but with a wrong pubkey (verifier should raise
    ROUGHTIME_SREP_SIGNATURE_INVALID). `signing_key_override` lets a test
    simulate a SREP signed by an attacker key (same effect)."""
    sk, pk = make_roughtime_test_keypair(root_name)
    if pubkey_override is not None:
        pk = pubkey_override
    if signing_key_override is not None:
        sk = signing_key_override

    srep_bytes = deterministic_cbor(
        {
            "PUBK": pk,
            "MIDP": midp_ms,
            "RADI": radi_ms,
            "NONC": nonce,
        }
    )
    sig = sk.sign(srep_bytes)
    transmitted = deterministic_cbor({"srep": srep_bytes, "sig": sig})

    # Pinned root port (verifier reads from PINNED_ROUGHTIME_ROOTS, but the
    # bundle MAY embed `port` per-SREP for the `cloudflare-roughtime-2` :2002
    # decommissioned-port trap. Default to pinned port.
    pinned_port = (
        {
            "cloudflare-roughtime-2": 2003,
            "int08h-roughtime": 2002,
            "roughtime-se": 2002,
            "time-txryan-com": 2002,
        }[root_name]
        if root_name in _ROOT_NAMES_FOR_TEST
        else 2002
    )

    return {
        "root_name": root_name,
        "srep_bytes_b64": base64.b64encode(transmitted).decode("ascii"),
        "midp_ms": midp_ms,
        "radi_ms": radi_ms,
        "port": pinned_port,
    }


# ──────────────────────────────────────────────────────────────────────────
# RFC 3161 TSA test cert chains + token minting (simplified envelope —
# v0.3 reference implementation)
# ──────────────────────────────────────────────────────────────────────────


def _det_rsa_key(seed_label: str) -> rsa.RSAPrivateKey:
    """RSA key from a deterministic seed. Uses Python `random.Random` for
    deterministic prime generation isn't supported by `cryptography`'s
    `generate_private_key`, so we cache by label and accept the dev-env
    cost (~50ms per key on first call). Tests run with the same labels each
    time but the resulting keys differ across processes — that's fine
    because each test process re-mints its own fixtures + monkeypatches
    in-process."""
    # The `cryptography` lib uses OS randomness — keys aren't bit-identical
    # across runs. That's OK; tests don't compare cert bytes across runs.
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


_TSA_CA_KEY: rsa.RSAPrivateKey | None = None
_TSA_CA_CERT: x509.Certificate | None = None
_TSA_SIGNING_KEYS: dict[str, rsa.RSAPrivateKey] = {}
_TSA_SIGNING_CERTS: dict[str, x509.Certificate] = {}


def _ensure_tsa_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    global _TSA_CA_KEY, _TSA_CA_CERT
    if _TSA_CA_KEY is not None and _TSA_CA_CERT is not None:
        return _TSA_CA_KEY, _TSA_CA_CERT
    ca_key = _det_rsa_key("S19c-test-ca")
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "S19c Test eIDAS QTL CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NEXI Test"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "EU"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1))
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _TSA_CA_KEY = ca_key
    _TSA_CA_CERT = cert
    return ca_key, cert


def _ensure_tsa_signing_cert(
    tsa_name: str, *, include_eku_timestamping: bool = True
) -> tuple[rsa.RSAPrivateKey, x509.Certificate, x509.Certificate]:
    """Returns (signing_key, signing_cert, ca_cert) for the named TSA.

    `include_eku_timestamping=False` lets a test simulate a cert without
    `id-kp-timeStamping` EKU — verifier should raise TSA_CERT_CHAIN_REJECTED."""
    cache_key = f"{tsa_name}__eku_{include_eku_timestamping}"
    if cache_key in _TSA_SIGNING_KEYS:
        return (
            _TSA_SIGNING_KEYS[cache_key],
            _TSA_SIGNING_CERTS[cache_key],
            _ensure_tsa_ca()[1],
        )

    ca_key, ca_cert = _ensure_tsa_ca()
    sk = _det_rsa_key(f"S19c-test-tsa-signing-{tsa_name}")
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, f"{tsa_name} signing"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NEXI Test"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "EU"),
        ]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(sk.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1))
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if include_eku_timestamping:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                [x509.ObjectIdentifier("1.3.6.1.5.5.7.3.8")]
            ),  # id-kp-timeStamping
            critical=True,
        )
    cert = builder.sign(ca_key, hashes.SHA256())
    _TSA_SIGNING_KEYS[cache_key] = sk
    _TSA_SIGNING_CERTS[cache_key] = cert
    return sk, cert, ca_cert


def _cert_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def mint_tsa_token(
    *,
    tsa_name: str,
    merkle_root_hex: str,
    hash_algorithm: str = "sha256",
    nonce_bytes: bytes | None = None,
    policy_oid: str | None = None,
    gentime_iso: str | None = None,
    include_eku_timestamping: bool = True,
    signing_key_override: rsa.RSAPrivateKey | None = None,
    issuing_ca_cert_override: x509.Certificate | None = None,
    imprint_hex_override: str | None = None,
) -> dict:
    """Mint a single test RFC 3161-shaped CMS token dict in the shape
    `verify_per_batch_tsa_root` consumes from `rfc3161_tokens`.

    Override knobs let a test exercise specific failure modes:
        signing_key_override          -> signed by an attacker key (cert-chain rejected)
        issuing_ca_cert_override      -> chained to a non-pinned CA (cert-chain rejected)
        include_eku_timestamping=False -> missing id-kp-timeStamping EKU
        imprint_hex_override          -> different imprint than merkle_root_hex (imprint mismatch)
        hash_algorithm='sha1'         -> SHA-1 imprint (weak algorithm)
        nonce_bytes=None              -> nonce field omitted (nonce missing)
        policy_oid outside allowlist  -> policy OID not allowed
    """
    if policy_oid is None:
        policy_oid = ETSI_POLICY_OID_ALLOWLIST[0]
    if gentime_iso is None:
        gentime_iso = "2026-05-20T12:00:00Z"

    signing_sk, signing_cert, ca_cert = _ensure_tsa_signing_cert(
        tsa_name,
        include_eku_timestamping=include_eku_timestamping,
    )
    if signing_key_override is not None:
        signing_sk = signing_key_override

    imprint_hex = (
        imprint_hex_override if imprint_hex_override is not None else merkle_root_hex
    )

    payload = {
        "tsa_name": tsa_name,
        "messageImprint": {
            "hashAlgorithm": hash_algorithm,
            "hashedMessage_hex": imprint_hex,
        },
        "nonce_hex": nonce_bytes.hex() if nonce_bytes is not None else None,
        "genTime_iso": gentime_iso,
        "policyOid": policy_oid,
    }
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )
    signature = signing_sk.sign(
        payload_bytes,
        padding=__import__(
            "cryptography"
        ).hazmat.primitives.asymmetric.padding.PKCS1v15(),
        algorithm=hashes.SHA256(),
    )

    issuing_ca = (
        issuing_ca_cert_override if issuing_ca_cert_override is not None else ca_cert
    )

    return {
        "tsa_name": tsa_name,
        "cms_token_b64": base64.b64encode(payload_bytes).decode("ascii"),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "signing_cert_pem": _cert_pem(signing_cert),
        "ca_chain_pem": _cert_pem(issuing_ca),
        "policy_oid": policy_oid,
        "imprint_algorithm": hash_algorithm,
        "imprint_hex": imprint_hex,
        "nonce_hex": nonce_bytes.hex() if nonce_bytes is not None else None,
        "gentime_iso": gentime_iso,
    }


def get_test_tsa_ca_pem() -> str:
    """The pinned test CA root the verifier path-validates TSA cert chains
    against. Tests monkeypatch the verifier's CA-trust-anchor lookup with
    this single-element list."""
    _, ca_cert = _ensure_tsa_ca()
    return _cert_pem(ca_cert)


# ──────────────────────────────────────────────────────────────────────────
# BLS aggregate over merkle_root_hex (multi-TSA quorum at root level)
# ──────────────────────────────────────────────────────────────────────────


def _bls_sk_for_tsa(tsa_name: str) -> int:
    """Returns a deterministic BLS scalar SK for the named TSA."""
    from py_ecc.bls import G2ProofOfPossession as bls

    seed = hashlib.sha256(f"S19c-test-bls-{tsa_name}".encode()).digest()
    return bls.KeyGen(seed)


def bls_pk_for_tsa(tsa_name: str) -> bytes:
    """Returns the BLS public key bytes for the named TSA. Tests
    monkeypatch the verifier's per-TSA BLS pubkey lookup with these."""
    from py_ecc.bls import G2ProofOfPossession as bls

    sk = _bls_sk_for_tsa(tsa_name)
    return bls.SkToPk(sk)


def mint_bls_aggregate(
    *,
    tsa_names: list[str],
    merkle_root_hex: str,
    spurious_extra_key_seed: bytes | None = None,
) -> str:
    """Mint a BLS aggregate signature over `bytes.fromhex(merkle_root_hex)`
    contributed-to by each `tsa_name`. Returns base64.

    `spurious_extra_key_seed` lets a test mix in a sig from a non-pinned
    TSA — verifier should raise BLS_AGGREGATE_VERIFICATION_FAILED."""
    from py_ecc.bls import G2ProofOfPossession as bls

    msg = bytes.fromhex(merkle_root_hex)
    sigs = []
    for name in tsa_names:
        sk = _bls_sk_for_tsa(name)
        sigs.append(bls.Sign(sk, msg))
    if spurious_extra_key_seed is not None:
        spurious_sk = bls.KeyGen(spurious_extra_key_seed)
        sigs.append(bls.Sign(spurious_sk, msg))
    agg = bls.Aggregate(sigs)
    return base64.b64encode(agg).decode("ascii")


# ──────────────────────────────────────────────────────────────────────────
# Convenience: build a complete `causal_chain["layer_b_anchors"]` for tests
# ──────────────────────────────────────────────────────────────────────────


def merkle_root_of(per_event_hashes_hex: list[str]) -> str:
    """Simple Merkle-root recomputation used by both fixture-mint and the
    verifier. For v0.3 reference implementation: sha256 over the canonical-
    CBOR concatenation of per-event hash bytes (NOT a binary Merkle tree;
    v0.4 upgrades to a proper binary tree with SHA-256 nodes).

    Bound here as a module-level helper so the verifier and the fixture
    mint use the same recipe."""
    leaves = [bytes.fromhex(h) for h in per_event_hashes_hex]
    blob = cbor2.dumps(leaves, canonical=True)
    return hashlib.sha256(blob).hexdigest()
