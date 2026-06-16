"""audit_bundle.gate — signed disbursement-gate verdicts.

A verifier that gates an *action* hands its verdict to a separate disburser as a
checkable artifact. Two signers over the SAME canonical gate-verdict tuple:

  - ``verdict_signing`` — HMAC-SHA256 (symmetric): tamper-evident + portable, but
    a key-holding disburser holds the same key it verifies with, so it can forge.
  - ``ed25519_verdict_signing`` — Ed25519 (asymmetric): the verifier signs with a
    private key; the disburser verifies with a public-only key and cannot forge.

See ``verdict_signing`` for the honest HMAC-vs-asymmetric scope note.

Public surface:
  - sign_gate_verdict_hmac(...) / verify_gate_verdict_hmac(...)            (HMAC)
  - sign_gate_verdict_ed25519(...) / verify_gate_verdict_ed25519(...)  (Ed25519)
  - sign_payload(...) / verify_payload(...)  (generic Ed25519 over caller-canonical bytes)
  - Ed25519VerifierKey (private+public) / Ed25519VerifyKey (public-only)
  - {AUTO_APPROVE, HUMAN_REVIEW, GATE_VALUES}
  - {VerifierSigningKey, SigningError}  (re-exported from discharge)
"""

from __future__ import annotations

from .ed25519_verdict_signing import (
    Ed25519VerifierKey,
    Ed25519VerifyKey,
    sign_action_gate_verdict_ed25519,
    sign_gate_verdict_ed25519,
    sign_payload,
    verify_action_gate_verdict_ed25519,
    verify_gate_verdict_ed25519,
    verify_payload,
)

# Enforcement halves (hosted-availability SKU): the runtime chokepoint + the
# spent-nonce store. These are the CLOSED tier and are EXCLUDED from the open
# drop (OSS_RELEASE_BOUNDARY.md). Imported OPTIONALLY so the open verdict-signing
# surface above stands alone when the closed modules are absent — the same
# pattern as effect_runtime no longer re-exporting wasm_runner. In the internal
# tree the modules are present and the behaviour is unchanged.
try:
    from .chokepoint import (
        APPROVED,
        EXPIRED,
        MALFORMED_TOKEN,
        NONCE_REPLAYED,
        NOT_AUTO_APPROVE,
        SIGNATURE_INVALID,
        ActionChokepoint,
        DispatchResult,
        verify_decision,
    )
    from .nonce_store import FileNonceStore, InMemoryNonceStore, SpentNonceStore

    _HAS_ENFORCEMENT = True
except ModuleNotFoundError:
    _HAS_ENFORCEMENT = False
from .verdict_signing import (
    ACTION_GATE_EXPIRED,
    ACTION_GATE_MALFORMED,
    ACTION_GATE_OK,
    ACTION_GATE_SIGNATURE_INVALID,
    AUTO_APPROVE,
    GATE_VALUES,
    HUMAN_REVIEW,
    ActionGateVerdictCheck,
    SigningError,
    VerifierSigningKey,
    compute_action_sha,
    sign_action_gate_verdict_hmac,
    sign_gate_verdict_hmac,
    verify_action_gate_verdict_hmac,
    verify_gate_verdict_hmac,
)

__all__ = [
    "ACTION_GATE_OK",
    "ACTION_GATE_MALFORMED",
    "ACTION_GATE_SIGNATURE_INVALID",
    "ACTION_GATE_EXPIRED",
    "ActionGateVerdictCheck",
    "AUTO_APPROVE",
    "GATE_VALUES",
    "HUMAN_REVIEW",
    "SigningError",
    "VerifierSigningKey",
    "sign_gate_verdict_hmac",
    "verify_gate_verdict_hmac",
    "compute_action_sha",
    "sign_action_gate_verdict_hmac",
    "verify_action_gate_verdict_hmac",
    "Ed25519VerifierKey",
    "Ed25519VerifyKey",
    "sign_gate_verdict_ed25519",
    "verify_gate_verdict_ed25519",
    "sign_action_gate_verdict_ed25519",
    "verify_action_gate_verdict_ed25519",
    "sign_payload",
    "verify_payload",
]

# Enforcement names are part of the public surface ONLY when the closed tier is
# present (internal tree). Absent in the open drop.
if _HAS_ENFORCEMENT:
    __all__ += [
        "ActionChokepoint",
        "DispatchResult",
        "verify_decision",
        "SpentNonceStore",
        "InMemoryNonceStore",
        "FileNonceStore",
        "APPROVED",
        "MALFORMED_TOKEN",
        "SIGNATURE_INVALID",
        "EXPIRED",
        "NOT_AUTO_APPROVE",
        "NONCE_REPLAYED",
    ]
