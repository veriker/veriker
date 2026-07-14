"""Generator for `sigstore_staging_trust_anchors.json` (provenance + reproducibility).

The committed `sigstore_staging_trust_anchors.json` pins the PUBLIC Sigstore STAGING
trust anchors needed by the native-Fulcio staging leg (`audit_bundle.extensions.fulcio_identity`):

  * the staging Fulcio CA (root + intermediate) — chain-build anchor for the leaf cert;
  * the staging CT-log keys (logId-indexed) — verify the embedded precert SCT;
  * the staging Rekor log keys — recorded for completeness (the staging checkpoint leg is
    NOT wired here; production Rekor keys stay pinned in `rekor_anchor`).

These are PUBLIC keys (safe to commit). Provenance: the `sigstore` PyPI wheel ships the
TUF-distributed staging `trusted_root.json` under
`sigstore/_store/https%3A%2F%2Ftuf-repo-cdn.sigstage.dev/trusted_root.json`
(mediaType application/vnd.dev.sigstore.trustedroot+json;version=0.1). This script reshapes
that file into the flat anchors fixture; it is a TEST/CI convenience, NOT a runtime dependency
(the leg itself is stdlib + `cryptography`).

Re-run:
    pip download sigstore --no-deps -d /tmp/sigdl
    python -m zipfile -e /tmp/sigdl/sigstore-*.whl /tmp/sigdl/extracted/
    python tests/fixtures/_extract_staging_trust_anchors.py \
        "/tmp/sigdl/extracted/sigstore/_store/https%3A%2F%2Ftuf-repo-cdn.sigstage.dev/trusted_root.json"

The values are also publicly fetchable from https://tuf-repo-cdn.sigstage.dev (TUF). We extract
from the pinned wheel copy so the fixture is reproducible offline and not subject to live drift.
"""

from __future__ import annotations

import base64
import json
import sys

from cryptography import x509
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)

SIGSTORE_WHEEL_VERSION = (
    "sigstore 4.3.0"  # the wheel the values below were extracted from
)


def _cert_pem(raw_b64: str) -> str:
    cert = x509.load_der_x509_certificate(base64.b64decode(raw_b64))
    return cert.public_bytes(Encoding.PEM).decode("ascii")


def _key_pem(raw_b64: str) -> str:
    key = load_der_public_key(base64.b64decode(raw_b64))
    return key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode(
        "ascii"
    )


def extract(trusted_root: dict) -> dict:
    # Fulcio CA: split each chain into trusted self-signed roots + candidate intermediates.
    roots_pem: list[str] = []
    intermediates_pem: list[str] = []
    for ca in trusted_root.get("certificateAuthorities", []):
        certs = [
            x509.load_der_x509_certificate(base64.b64decode(c["rawBytes"]))
            for c in ca["certChain"]["certificates"]
        ]
        for cert in certs:
            pem = cert.public_bytes(Encoding.PEM).decode("ascii")
            if cert.subject == cert.issuer:
                if pem not in roots_pem:
                    roots_pem.append(pem)
            elif pem not in intermediates_pem:
                intermediates_pem.append(pem)

    ctlogs = []
    for ct in trusted_root.get("ctlogs", []):
        pk = ct["publicKey"]
        valid = pk.get("validFor", {})
        ctlogs.append(
            {
                "log_id_hex": base64.b64decode(ct["logId"]["keyId"]).hex(),
                "key_details": pk.get("keyDetails"),
                "key_pem": _key_pem(pk["rawBytes"]),
                "valid_start": valid.get("start"),
                "valid_end": valid.get("end"),
            }
        )

    rekor_tlogs = []
    for tl in trusted_root.get("tlogs", []):
        pk = tl["publicKey"]
        rekor_tlogs.append(
            {
                "log_id_hex": base64.b64decode(tl["logId"]["keyId"]).hex(),
                "key_details": pk.get("keyDetails"),
                "key_pem": _key_pem(pk["rawBytes"]),
            }
        )

    return {
        "_comment": (
            "PUBLIC Sigstore STAGING trust anchors (root+intermediate Fulcio CA, CT-log keys, "
            "Rekor log keys). Used ONLY by the native-Fulcio STAGING leg in the test/CI path "
            "(audit_bundle.extensions.fulcio_identity). NOT production anchors; NOT a runtime "
            "trust-environment switch. See the internal design notes."
        ),
        "_provenance": (
            f"{SIGSTORE_WHEEL_VERSION} wheel -> sigstore/_store/"
            "https%3A%2F%2Ftuf-repo-cdn.sigstage.dev/trusted_root.json (TUF-distributed, "
            "mediaType vnd.dev.sigstore.trustedroot+json;version=0.1). Regenerate with "
            "tests/fixtures/_extract_staging_trust_anchors.py."
        ),
        "fulcio_roots_pem": roots_pem,
        "fulcio_intermediates_pem": intermediates_pem,
        "ctlogs": ctlogs,
        "rekor_tlogs": rekor_tlogs,
    }


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} <staging trusted_root.json>")
    with open(sys.argv[1], encoding="utf-8") as fh:
        trusted_root = json.load(fh)
    out = extract(trusted_root)
    import pathlib

    dest = pathlib.Path(__file__).with_name("sigstore_staging_trust_anchors.json")
    dest.write_text(json.dumps(out, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(
        f"wrote {dest} ({len(out['fulcio_roots_pem'])} roots, "
        f"{len(out['fulcio_intermediates_pem'])} intermediates, "
        f"{len(out['ctlogs'])} ctlogs, {len(out['rekor_tlogs'])} rekor tlogs)"
    )


if __name__ == "__main__":
    main()
