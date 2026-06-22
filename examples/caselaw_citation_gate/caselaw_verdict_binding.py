"""caselaw_verdict_binding.py -- canonical signed-bytes encoding for the
gate-authority Ed25519 attestation over the citation-gate verdict.

SHARED between the signer (_build_bundle.py) and the verifier
(CaselawGateAttestationCheck.py). This is the one place in the pilot where the
AB4 'duplicate-don't-import' rule is deliberately INVERTED: the signed bytes
must be byte-for-byte identical on both sides or every signature fails (the
attestation binds the verdict, so both sides must hash exactly the same
preimage). A second copy would be a drift
hazard, not auditor independence.

WHAT THE SIGNATURE ADDS OVER THE RE-DERIVATION
----------------------------------------------
The Axis-2 re-derivation already proves the claimed verdict reconciles with the
committed evidence (a tampered claimed verdict -> REDERIVATION_MISMATCH). The
Ed25519 attestation adds a SEPARATE, portable property: a downstream consumer
(a filing system, opposing counsel, a court) can confirm the verdict was
produced by the holder of the gate-authority private key WITHOUT re-running the
re-derivation and WITHOUT holding the corpus -- and cannot forge a new verdict,
because it holds only the public key. That is the "signed tamper-evident
receipt" half of the credibility gate.

The binding spans the decision, every per-citation status (in assertion order),
AND the SHA-256 of the rooted corpus and the assertions. Binding the evidence
SHAs means the signed statement is precisely: "the gate authority attests this
verdict was computed over THIS rooted corpus and THESE assertions." Swapping
either evidence file (even with a re-aligned manifest SHA) invalidates the
signature.

Stdlib only (json, hashlib).
"""

from __future__ import annotations

import hashlib
import json

# Domain-separation tag -- prevents a signature minted for some other v-kernel
# payload type from ever verifying as a caselaw citation-gate verdict.
_DOMAIN_TAG = b"v-kernel.caselaw-citation-gate.verdict.v1"


def sha256_hex(data: bytes) -> str:
    """SHA-256 hex of raw bytes (the evidence-file digest the binding pins)."""
    return hashlib.sha256(data).hexdigest()


def canonical_gate_verdict_payload(
    *,
    decision: str,
    citations: list,
    corpus_sha256: str,
    assertions_sha256: str,
) -> bytes:
    """Return the exact bytes that get Ed25519-signed for the gate attestation.

    `citations` is the verdict's citation list; only (id, reporter_cite, status)
    are bound, in the given order (assertion order is significant -- a reordering
    is a different verdict). `corpus_sha256` / `assertions_sha256` pin the
    evidence the verdict was computed over.

    Any mutation to the decision, any per-citation status, the citation order, or
    either evidence file invalidates the signature. The verifier holds only the
    public key and therefore cannot re-sign -- that asymmetry is the
    forge-resistance property.
    """
    body = {
        "assertions_sha256": assertions_sha256,
        "citations": [
            {
                "id": c["id"],
                "reporter_cite": c["reporter_cite"],
                "status": c["status"],
            }
            for c in citations
        ],
        "corpus_sha256": corpus_sha256,
        "decision": decision,
    }
    return (
        _DOMAIN_TAG
        + b"\x00"
        + json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
