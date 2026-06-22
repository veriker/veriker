"""_build_bundle.py -- build a deterministic caselaw_citation_gate audit bundle.

Case-law citation credibility-gate re-derivation pilot over a VERBATIM-rooted
court-record corpus (Axis-2 spec-pinned dispatch).

An AI legal assistant (producer) asserts a set of supporting citations and a gate
decision (AUTO_APPROVE / ROUTE_TO_HUMAN). The bundle lets an auditor re-derive that
decision from committed evidence: each asserted reporter cite is resolved against the
rooted corpus, and the quoted holding is screened for verbatim membership in the
resolved record's `rooted_text` -- the court's ACTUAL opinion text (captured from
CourtListener by _root_corpus.py, frozen with provenance). A cite that does not
resolve is UNRESOLVED (possible fabrication / still in the human-root queue); a cite
that resolves but whose quote is not found verbatim is MISQUOTE (real source,
fabricated/inverted quote); both force ROUTE_TO_HUMAN.

This is the successor to caselaw_citation_gate_minimal: same gate shape, but the
misquote yardstick is the court's verbatim words, not a human paraphrase -- the fix
for the load-bearing open question in the integration assessment.

The honest fixture deliberately mixes ROOTED (verbatim quotes that really appear in
the rooted opinions), MISQUOTE (a real case quoted for the OPPOSITE / fabricated
words), and UNRESOLVED (a fabricated case, plus optionally an authority that is in the
human-root queue rather than the corpus) so the honest gate decision is
ROUTE_TO_HUMAN, and that verdict re-derives.

Trust-root note (honest framing):
  The auditor anchors the METHOD (resolve + verbatim-misquote + comparator). That each
  rooted_text is the genuine complete opinion for its cite is a trust-root
  concern (corpus genuineness, out of scope for the verifier's re-derivation),
  mitigated by per-record CourtListener provenance, not machine-proven.

Usage (from v-kernel-audit-bundle root):
    python examples/caselaw_citation_gate/_build_bundle.py --out-dir /tmp/clg_kb_bundle

Exit codes:
  0  success
  1  assertion / computation failure
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# Import the canonical compute function from the primitive module so the builder
# and the verifier share ONE definition and cannot drift.
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from caselaw_gate_kb_recompute import (  # noqa: E402
    MISQUOTE,
    ROUTE_TO_HUMAN,
    UNRESOLVED,
    compute_gate_verdict,
)

# ATTEST half (§C16): the gate authority Ed25519-signs the verdict binding. These
# are producer-side imports (cryptography via the substrate signer); they are NOT
# part of the stdlib-bound recompute path the verifier re-runs.
from caselaw_verdict_binding import canonical_gate_verdict_payload, sha256_hex  # noqa: E402
from audit_bundle.gate.ed25519_verdict_signing import (  # noqa: E402
    Ed25519VerifierKey,
    sign_payload,
)
from audit_bundle.emitter import BundleContent, write_bundle  # noqa: E402

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "caselaw-citation-gate-kb-rc"
_CREATED_AT = "2026-05-31T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
    "caselaw_gate_attestation",
]

_OUTPUT_ID = "gate_verdict"
_TYPE_KEY = "caselaw_gate_verdict"

# Fixed test signing seed = a SYNTHETIC gate-authority key, committed for
# byte-reproducibility. Ed25519 is deterministic given (key, message), so a fixed
# seed yields a reproducible bundle. In production the verify key resolves via a
# trust-root key registry; the committed pubkey is an in-bundle synthetic
# anchor (see CaselawGateAttestationCheck honest-framing docstring).
_GATE_AUTHORITY_SEED_HEX = (
    "1a2b3c4d5e6f70819293a4b5c6d7e8f900112233445566778899aabbccddeeff"
)
_GATE_AUTHORITY_ID = "nexi-caselaw-gate-authority-synthetic"

_CORPUS_SRC = _HERE / "corpus" / "rooted_records.json"
_ASSERTIONS_SRC = _HERE / "assertions" / "citation_assertions.json"
_SPEC_SRC = _HERE / "spec_pinned" / "caselaw_gate_kb.spec.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # Sweep __pycache__ before enumerating files (verifier-self-pollution guard)
    for pycache in out_dir.rglob("__pycache__"):
        if pycache.is_dir():
            shutil.rmtree(pycache, ignore_errors=True)

    # --- 1. Read committed evidence (frozen, rooted fixtures) ---
    corpus_bytes = _CORPUS_SRC.read_bytes()
    assertions_bytes = _ASSERTIONS_SRC.read_bytes()
    spec_bytes = _SPEC_SRC.read_bytes()
    spec_basename = _SPEC_SRC.name
    spec_sha = _sha256(spec_bytes)

    corpus = json.loads(corpus_bytes)
    assertions = json.loads(assertions_bytes)

    # --- 2. Compute the HONEST gate verdict (this is the producer's claim) ---
    verdict = compute_gate_verdict(corpus, assertions)

    # Sanity-check the fixture exercises misquote + fabrication + the human route,
    # so the pilot demonstrably bites (a fixture where everything is ROOTED would
    # hide the misquote/fabrication detection that is the whole point).
    statuses = {c["status"] for c in verdict["citations"]}
    assert verdict["decision"] == ROUTE_TO_HUMAN, (
        f"Expected honest decision ROUTE_TO_HUMAN; got {verdict['decision']!r}. "
        "The fixture should contain at least one non-ROOTED citation."
    )
    assert MISQUOTE in statuses and UNRESOLVED in statuses, (
        f"Expected the fixture to exercise MISQUOTE and UNRESOLVED; got {sorted(statuses)!r}."
    )

    # --- 3. Build outputs/gate_verdict.json bytes (producer's claimed value) ---
    claim_bytes = (
        json.dumps({"value": verdict}, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    # --- 4. ATTEST half (§C16): gate authority Ed25519-signs the verdict binding ---
    # Bind the signature to the verdict AND the evidence SHAs, so swapping either
    # the verdict or an evidence file invalidates it. The verifier holds only the
    # public key (committed below) and cannot re-sign -> forge-resistant.
    signing_key = Ed25519VerifierKey.from_hex(_GATE_AUTHORITY_SEED_HEX)
    signed_bytes = canonical_gate_verdict_payload(
        decision=verdict["decision"],
        citations=verdict["citations"],
        corpus_sha256=sha256_hex(corpus_bytes),
        assertions_sha256=sha256_hex(assertions_bytes),
    )
    signature_hex = sign_payload(signed_bytes, signing_key)

    pubkey_text = signing_key.public_key().to_hex() + "\n"
    pubkey_bytes = pubkey_text.encode("utf-8")

    attestation_bytes = (
        json.dumps(
            {
                "authority_id": _GATE_AUTHORITY_ID,
                "scheme": "ed25519",
                "signature": signature_hex,
                "signed_at": _CREATED_AT,
                "binds": {
                    "verdict": f"outputs/{_OUTPUT_ID}.json",
                    "corpus": "corpus/rooted_records.json",
                    "assertions": "assertions/citation_assertions.json",
                },
            },
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")

    # --- 5. Build outputs list for extra_manifest_fields ---
    outputs_list = [
        {
            "output_id": _OUTPUT_ID,
            "type": _TYPE_KEY,
            "conforms_to": f"spec/{spec_basename}",
        }
    ]

    # --- Emit via the reference-emitter SDK (scaffold + digests + manifest). ---
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "corpus/rooted_records.json": corpus_bytes,
            "assertions/citation_assertions.json": assertions_bytes,
            f"outputs/{_OUTPUT_ID}.json": claim_bytes,
            "attestation/gate_attestation.json": attestation_bytes,
            "attestation/gate_verifier_pubkey.hex": pubkey_bytes,
        },
        spec_files={spec_basename: spec_bytes},
        typed_checks=_TYPED_CHECKS,
        extra_manifest_fields={
            "fragment_anchors": {},
            "outputs": outputs_list,
        },
    )
    write_bundle(out_dir, content)

    n_rooted = sum(1 for c in verdict["citations"] if c["status"] == "ROOTED")
    print(f"Bundle written to {out_dir}")
    print(f"  rooted corpus    : {len(corpus)} verbatim court record(s)")
    print(f"  assertions       : {len(assertions)} cited authority(ies)")
    print(f"  gate verdict     : {verdict['decision']} ({n_rooted}/{len(assertions)} ROOTED)")
    for c in verdict["citations"]:
        print(f"    {c['id']}  {c['reporter_cite']:<16} -> {c['status']}")
    print(f"  output_id        : {_OUTPUT_ID}")
    print(f"  spec             : {spec_basename}  sha256={spec_sha[:16]}...")
    print(f"  attestation      : ed25519 over verdict+evidence  sig={signature_hex[:16]}...")
    print(f"  verify pubkey    : {signing_key.public_key().to_hex()[:16]}...  (synthetic in-bundle anchor)")
    print(f"  manifest         : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic caselaw_citation_gate audit bundle"
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        type=Path,
        help="Destination directory (created if absent)",
    )
    args = parser.parse_args()
    try:
        build(args.out_dir.resolve())
    except (AssertionError, ValueError, KeyError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
