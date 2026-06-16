"""CaselawGateAttestationCheck -- ATTEST-half TypedCheck plugin (C16 pattern).

Verifies the gate authority's Ed25519 signature over the citation-gate verdict
binding. The verifier holds ONLY the public key committed at
attestation/gate_verifier_pubkey.hex -- it cannot forge a new valid signature.
Any mutation to the decision, a per-citation status, the citation order, or
either evidence file (even with a re-aligned manifest SHA) fires
CASELAW_GATE_ATTESTATION_INVALID.

Forge-resistance (C16): the verifier holds only the public key. There is no API
path from a public key back to a valid signature, so a party that mutates the
verdict cannot re-sign it without the private key (NOT bundled).

HONEST FRAMING (mirrors the attested-workpaper pilot): the pubkey here is an
in-bundle SYNTHETIC trust anchor, pinned by file integrity (manifest.files), and
the signing key is a fixed test seed for byte-reproducibility. This gives
tamper-evidence + forge-resistance against a public-key holder; it does NOT give
third-party-auditable identity -- that requires binding the public key to a
Sigstore/Fulcio identity (C18, posture-deferred). The honest register:
"forge-proof against a key holder" is a strictly weaker, true claim than
"third-party-auditable". In production the verify key resolves via a trust-root
key registry, not from inside the bundle.

Reason codes:
  CASELAW_GATE_ATTESTATION_VALID         -- gate-authority signature verified
  CASELAW_GATE_ATTESTATION_INVALID       -- signature did not verify
  CASELAW_GATE_ATTESTATION_PUBKEY_MISSING -- pubkey absent/malformed
  CASELAW_GATE_ATTESTATION_MALFORMED     -- attestation/verdict file unparseable

name='caselaw_gate_attestation'. Non-stdlib import (cryptography) -- this is a
plugin, not the stdlib-bound re-derivation pack, so the dependency is in-contract.
"""

from __future__ import annotations

import json
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.gate.ed25519_verdict_signing import Ed25519VerifyKey, verify_payload
from audit_bundle.plugin import PluginResult

from caselaw_verdict_binding import canonical_gate_verdict_payload, sha256_hex

_VERDICT_REL = "outputs/gate_verdict.json"
_ATTEST_REL = "attestation/gate_attestation.json"
_PUBKEY_REL = "attestation/gate_verifier_pubkey.hex"
_CORPUS_REL = "corpus/rooted_records.json"
_ASSERTIONS_REL = "assertions/citation_assertions.json"


class CaselawGateAttestationCheck:
    name: str = "caselaw_gate_attestation"
    applies_to_files: frozenset[str] = frozenset(
        {_VERDICT_REL, _ATTEST_REL, _PUBKEY_REL}
    )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        verdict_path = bundle_dir / _VERDICT_REL
        attest_path = bundle_dir / _ATTEST_REL
        pubkey_path = bundle_dir / _PUBKEY_REL
        corpus_path = bundle_dir / _CORPUS_REL
        assertions_path = bundle_dir / _ASSERTIONS_REL

        if not attest_path.exists():
            return PluginResult(
                True, "NO_ATTESTATION", "no gate_attestation.json to check", ()
            )

        if not pubkey_path.exists():
            return PluginResult(
                False,
                "CASELAW_GATE_ATTESTATION_PUBKEY_MISSING",
                f"{_PUBKEY_REL} absent -- cannot verify attestation (fail-closed)",
                (str(pubkey_path),),
            )

        try:
            verify_key = Ed25519VerifyKey.from_hex(
                pubkey_path.read_text(encoding="utf-8").strip()
            )
        except (ValueError, TypeError) as exc:
            return PluginResult(
                False,
                "CASELAW_GATE_ATTESTATION_PUBKEY_MISSING",
                f"{_PUBKEY_REL} malformed: {exc}",
                (str(pubkey_path),),
            )

        try:
            verdict = json.loads(verdict_path.read_text(encoding="utf-8"))["value"]
            attestation = json.loads(attest_path.read_text(encoding="utf-8"))
            corpus_bytes = corpus_path.read_bytes()
            assertions_bytes = assertions_path.read_bytes()
        except (json.JSONDecodeError, KeyError, FileNotFoundError, OSError) as exc:
            return PluginResult(
                False,
                "CASELAW_GATE_ATTESTATION_MALFORMED",
                f"could not read verdict/attestation/evidence: {exc}",
                (str(verdict_path), str(attest_path)),
            )

        signature_hex = attestation.get("signature", "")

        # Reconstruct the canonical signed bytes from the verdict's own fields and
        # the evidence SHAs computed from the committed files. Mutating either the
        # verdict or an evidence file changes these bytes -> signature won't verify.
        signed_bytes = canonical_gate_verdict_payload(
            decision=verdict.get("decision", ""),
            citations=verdict.get("citations", []),
            corpus_sha256=sha256_hex(corpus_bytes),
            assertions_sha256=sha256_hex(assertions_bytes),
        )

        if not verify_payload(signed_bytes, signature_hex, verify_key):
            return PluginResult(
                False,
                "CASELAW_GATE_ATTESTATION_INVALID",
                (
                    "[CASELAW_GATE_ATTESTATION_INVALID] Ed25519 gate-authority "
                    "signature does not verify -- the verdict (decision / citation "
                    "statuses / order) or an evidence file (rooted corpus / "
                    "assertions) was tampered, or it was signed by a different key. "
                    "The verifier holds only the public key and cannot re-sign "
                    "(forge-resistant)."
                ),
                (str(verdict_path), str(attest_path), str(pubkey_path)),
            )

        return PluginResult(
            True,
            "CASELAW_GATE_ATTESTATION_VALID",
            (
                f"gate-authority Ed25519 attestation verified: "
                f"decision={verdict.get('decision')!r} "
                f"over {len(verdict.get('citations', []))} citation(s), "
                f"bound to corpus+assertions SHAs"
            ),
            (str(verdict_path), str(attest_path), str(pubkey_path)),
        )


register_typed_check("caselaw_gate_attestation")
