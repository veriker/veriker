#!/usr/bin/env python3
"""content_provenance_re_derivation.py — stdlib re-derivation pack for content provenance domain.

SCOPE BOUNDARY:
This proves WHAT a system produced and that the content has NOT been altered since
it was signed by its stated producer.  It is NOT truth-detection and NOT a
disinformation classifier.  A factually FALSE but unaltered, correctly-signed piece
of content PASSES this check — that is by design and out of scope.

Re-derivation primitive (one sentence):
  Re-hash the published content bytes and re-check they match the producer-signed
  manifest hash, and assert the provenance chain (producer id + declared generation
  inputs) is intact and unaltered.

the audit-bundle contract §C5 (auditor independence) + AB4 (duplicate-don't-import).
Stdlib only — no 3rd-party deps.  HMAC-SHA256 via stdlib hmac + hashlib.

Reading order:
  1. Reads payload/provenance_result.json from --bundle-dir.
  2. Reads artifact/content.txt and artifact/provenance.json.
  3. Asserts content_sha in payload matches sha256(artifact/content.txt).
  4. Asserts provenance_sha in payload matches sha256(artifact/provenance.json).
  5. Re-computes HMAC-SHA256(synthetic_key, content_bytes) and asserts it matches
     the producer_hmac field in the provenance manifest.
  6. Asserts provenance chain fields (producer_id, generation_inputs) match
     between payload and provenance manifest.

Exit codes:
  0  all assertions passed (CONTENT_PROVENANCE_VERIFIED)
  1  mismatch found — description written to stderr (CONTENT_PROVENANCE_ALTERED)
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from pathlib import Path

# Synthetic producer key — must match _build_bundle.py exactly (AB4 pattern).
# Fixed bytes, deterministic, local-only demo.
_SYNTHETIC_PRODUCER_KEY = b"SYNTHETIC_PRODUCER_KEY_LOCAL_DEMO_ONLY_NOT_A_SECRET"


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _producer_hmac(key: bytes, data: bytes) -> str:
    """HMAC-SHA256 over data using key.  Returns hex string."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def _fail(msg: str) -> int:
    print(msg, file=sys.stderr)
    return 1


# ---------------------------------------------------------------------------
# Main verification logic
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Content provenance re-derivation check"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    # --- Load payload/provenance_result.json ---
    payload_path = bundle_dir / "payload" / "provenance_result.json"
    if not payload_path.exists():
        # Domain pilot opted out — not a failure
        return 0

    try:
        payload = json.loads(payload_path.read_bytes())
    except (json.JSONDecodeError, OSError) as exc:
        return _fail(
            f"content_provenance_re_derivation: failed to read payload/provenance_result.json: {exc}"
        )

    # --- Extract committed values from payload ---
    try:
        committed_content_sha: str = payload["content_sha"]
        committed_provenance_sha: str = payload["provenance_sha"]
        committed_producer_id: str = payload["producer_id"]
        committed_generation_inputs: dict = payload["generation_inputs"]
        committed_producer_hmac: str = payload["producer_hmac"]
    except KeyError as exc:
        return _fail(
            f"content_provenance_re_derivation: payload/provenance_result.json missing field {exc}"
        )

    # --- Load artifact/content.txt ---
    content_path = bundle_dir / "artifact" / "content.txt"
    if not content_path.exists():
        return _fail(
            "content_provenance_re_derivation: artifact/content.txt not found in bundle_dir"
        )
    content_bytes = content_path.read_bytes()

    # --- Load artifact/provenance.json ---
    provenance_path = bundle_dir / "artifact" / "provenance.json"
    if not provenance_path.exists():
        return _fail(
            "content_provenance_re_derivation: artifact/provenance.json not found in bundle_dir"
        )
    provenance_bytes = provenance_path.read_bytes()

    try:
        provenance_manifest = json.loads(provenance_bytes)
    except json.JSONDecodeError as exc:
        return _fail(
            f"content_provenance_re_derivation: artifact/provenance.json is not valid JSON: {exc}"
        )

    # --- Assert content_sha matches actual file (detects post-signing alteration) ---
    actual_content_sha = _sha256(content_bytes)
    if actual_content_sha != committed_content_sha:
        return _fail(
            f"content_provenance_re_derivation: CONTENT_PROVENANCE_ALTERED\n"
            f"  content_sha in payload         : {committed_content_sha!r}\n"
            f"  sha256(artifact/content.txt)   : {actual_content_sha!r}\n"
            f"  Content bytes do not match committed hash — post-signing alteration detected"
        )

    # --- Assert provenance_sha matches actual file ---
    actual_provenance_sha = _sha256(provenance_bytes)
    if actual_provenance_sha != committed_provenance_sha:
        return _fail(
            f"content_provenance_re_derivation: CONTENT_PROVENANCE_ALTERED\n"
            f"  provenance_sha in payload         : {committed_provenance_sha!r}\n"
            f"  sha256(artifact/provenance.json)  : {actual_provenance_sha!r}\n"
            f"  Provenance manifest does not match committed hash — tamper detected"
        )

    # --- Re-derive HMAC and assert it matches the manifest's producer_hmac ---
    rederived_hmac_hex = _producer_hmac(_SYNTHETIC_PRODUCER_KEY, content_bytes)
    expected_hmac_field = f"hmac-sha256:{rederived_hmac_hex}"
    manifest_hmac_field: str = provenance_manifest.get("producer_hmac", "")
    if manifest_hmac_field != expected_hmac_field:
        return _fail(
            f"content_provenance_re_derivation: CONTENT_PROVENANCE_ALTERED\n"
            f"  producer_hmac in manifest      : {manifest_hmac_field!r}\n"
            f"  re-derived hmac                : {expected_hmac_field!r}\n"
            f"  Producer HMAC mismatch — content not signed by the committed producer key, "
            f"or content bytes were altered after signing"
        )

    # --- Assert provenance chain: producer_id ---
    manifest_producer_id = provenance_manifest.get("producer_id", "")
    if manifest_producer_id != committed_producer_id:
        return _fail(
            f"content_provenance_re_derivation: CONTENT_PROVENANCE_ALTERED\n"
            f"  producer_id in payload    : {committed_producer_id!r}\n"
            f"  producer_id in manifest   : {manifest_producer_id!r}\n"
            f"  Producer identity mismatch — provenance chain altered"
        )

    # --- Assert provenance chain: generation_inputs ---
    manifest_generation_inputs = provenance_manifest.get("generation_inputs", {})
    if manifest_generation_inputs != committed_generation_inputs:
        return _fail(
            f"content_provenance_re_derivation: CONTENT_PROVENANCE_ALTERED\n"
            f"  generation_inputs in payload  : {json.dumps(committed_generation_inputs, sort_keys=True)}\n"
            f"  generation_inputs in manifest : {json.dumps(manifest_generation_inputs, sort_keys=True)}\n"
            f"  Generation inputs mismatch — provenance chain altered"
        )

    # All checks passed
    return 0


if __name__ == "__main__":
    sys.exit(main())
