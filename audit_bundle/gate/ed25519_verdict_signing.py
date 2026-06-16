"""Asymmetric (Ed25519) signing for disbursement-gate verdicts (C16 pattern).

PROBLEM THIS CLOSES
-------------------
``verdict_signing`` signs gate verdicts with HMAC-SHA256. That is symmetric:
the signer and verifier share one secret. It gives tamper-evidence and
portability, but NOT forge-resistance — a key-holding disburser holds the same
key it verifies with, so it could mint its own valid "AUTO_APPROVE, $9M"
verdict. The HMAC module says this plainly ("does NOT give non-repudiation").

This module closes that gap. Ed25519 is asymmetric: the verifier signs with a
PRIVATE key; the disburser verifies with a PUBLIC-only key. A party holding
only the public key cannot produce a signature that verifies — there is no API
path from the public key back to a valid signature. A key-holding (public-key-
holding) disburser therefore CANNOT forge a verdict.

The signed bytes are IDENTICAL to the HMAC path: this module imports and reuses
``_canonical_gate_payload`` from ``verdict_signing`` rather than re-deriving the
tuple. Only the signing primitive changes (HMAC → Ed25519). Keeping one
canonical encoding means a verdict's signed-field set can't silently drift
between the two signers.

SCOPE — WHAT THIS IS / IS NOT
-----------------------------
This gives forge-resistance against a key-holding disburser: holding the public
verify key is insufficient to sign. It does NOT yet give third-party-auditable
identity — i.e. an EXTERNAL auditor verifying a verdict without trusting a
NEXI-published public key. That requires binding the public key to a
Sigstore/Fulcio-issued identity, which is a posture decision deferred to the
roadmap (Tier 2). The honest register: "forge-proof against a key-holding
disburser" is a strictly weaker, true claim than "third-party-auditable".

USAGE
-----
    key = Ed25519VerifierKey.generate()         # verifier side (private+public)
    sig = sign_gate_verdict_ed25519(
        bundle_id="b1", case_id="c1", rule_id="r1",
        gate="AUTO_APPROVE", rederived_net_cents=900_000_00,
        rules_sha="abc...", key=key,
    )
    verify_key = key.public_key()               # handed to the disburser
    ok = verify_gate_verdict_ed25519(
        bundle_id="b1", case_id="c1", rule_id="r1",
        gate="AUTO_APPROVE", rederived_net_cents=900_000_00,
        rules_sha="abc...", signature=sig, verify_key=verify_key,
    )
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# Reuse the SAME canonical payloads as the HMAC signer — do not re-implement the
# tuples. A second copy would be a drift hazard. Both ``_canonical_gate_payload``
# (v0_1) and ``_canonical_action_gate_payload`` (v0_2) raise ``SigningError`` for an
# out-of-domain value; we propagate it on sign and treat it as a verification miss
# on verify (mirroring the HMAC signer). The structured check result and its
# reason codes are likewise SHARED with the HMAC twin — one verdict shape for
# the action-gate check regardless of signature scheme.
from .verdict_signing import (
    ACTION_GATE_EXPIRED,
    ACTION_GATE_MALFORMED,
    ACTION_GATE_OK,
    ACTION_GATE_SIGNATURE_INVALID,
    ActionGateVerdictCheck,
    SigningError,
    _canonical_action_gate_payload,
    _canonical_gate_payload,
    _require_now_epoch,
)


@dataclass(frozen=True)
class Ed25519VerifyKey:
    """A public-only key: can verify gate verdicts, cannot sign.

    This is what the disburser holds. There is no method on this class — and no
    API in this module — that turns a public key into a valid signature. That
    absence is the forge-resistance property.
    """

    _public: ed25519.Ed25519PublicKey

    @classmethod
    def from_hex(cls, hex_str: str) -> Ed25519VerifyKey:
        raw = bytes.fromhex(hex_str)
        return cls(_public=ed25519.Ed25519PublicKey.from_public_bytes(raw))

    def to_hex(self) -> str:
        """Raw 32-byte public key as hex (portable, no PEM wrapping)."""
        raw = self._public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw.hex()


@dataclass(frozen=True)
class Ed25519VerifierKey:
    """A private+public keypair: can sign and verify gate verdicts.

    This is what the verifier holds. It hands out only ``public_key()`` to the
    disburser.
    """

    _private: ed25519.Ed25519PrivateKey

    @classmethod
    def generate(cls) -> Ed25519VerifierKey:
        return cls(_private=ed25519.Ed25519PrivateKey.generate())

    @classmethod
    def from_hex(cls, hex_str: str) -> Ed25519VerifierKey:
        raw = bytes.fromhex(hex_str)
        return cls(_private=ed25519.Ed25519PrivateKey.from_private_bytes(raw))

    def to_hex(self) -> str:
        """Raw 32-byte private seed as hex. Keep secret — confers signing power."""
        raw = self._private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return raw.hex()

    def public_key(self) -> Ed25519VerifyKey:
        """The public-only verify key to hand to the disburser."""
        return Ed25519VerifyKey(_public=self._private.public_key())


# ---------------------------------------------------------------------------
# Generic payload signer/verifier — the primitive both this module's gate-verdict
# functions AND a pilot attestation leg (spec-conformance verdict, input-provenance
# steward record) build on. A pilot signs a payload its OWN canonical encoder
# produces; the substrate owns the Ed25519 wrapping so the pilot does not have to
# re-wrap ``cryptography`` directly (the payroll example had to, pre-this-helper —
# see examples/payroll_agent_gate_minimal/ed25519_authority.py).
#
# These take ALREADY-CANONICALISED bytes and make no claim about their shape —
# domain separation, length-prefixing, and field choice are the caller's
# responsibility (and the caller's invariant to keep stable). The forge-resistance
# property is identical to the gate-verdict path: a holder of only the verify key
# cannot produce a signature that verifies.
# ---------------------------------------------------------------------------


def sign_payload(payload: bytes, key: Ed25519VerifierKey) -> str:
    """Sign arbitrary canonical payload bytes with a private key, returning hex.

    The substrate makes no claim about ``payload``'s internal structure — the
    caller owns its canonical encoding (domain separator, length-prefixing). This
    is the primitive :func:`sign_gate_verdict_ed25519` is one caller of.
    """
    if not isinstance(key, Ed25519VerifierKey):
        raise TypeError(
            "sign_payload requires an Ed25519VerifierKey (private); "
            f"got {type(key).__name__}. A public-only key cannot sign."
        )
    return key._private.sign(payload).hex()


def verify_payload(payload: bytes, sig: str, verify_key: Ed25519VerifyKey) -> bool:
    """Verify a hex signature over canonical payload bytes with a public-only key.

    Fail-closed, mirroring :func:`verify_gate_verdict_ed25519`:
      * ``verify_key`` must be an ``Ed25519VerifyKey`` — ``None`` (or anything
        without a public key) raises rather than silently passing;
      * a non-str / malformed-hex / non-matching signature returns False.
    """
    if not isinstance(verify_key, Ed25519VerifyKey):
        raise TypeError(
            "verify_payload requires an Ed25519VerifyKey; "
            f"got {type(verify_key).__name__}. Verification cannot proceed "
            "without a key (fail-closed)."
        )
    if not isinstance(sig, str):
        return False
    try:
        sig_bytes = bytes.fromhex(sig)
    except (ValueError, TypeError):
        return False
    try:
        verify_key._public.verify(sig_bytes, payload)
        return True
    except InvalidSignature:
        return False


def sign_gate_verdict_ed25519(
    *,
    bundle_id: str,
    case_id: str,
    rule_id: str,
    gate: str,
    rederived_net_cents: int | None,
    rules_sha: str,
    key: Ed25519VerifierKey,
) -> str:
    """Sign a gate verdict with the verifier's private key, returning hex.

    Signs the same canonical, domain-separated payload as the HMAC signer, via the
    generic :func:`sign_payload` primitive.
    """
    payload = _canonical_gate_payload(
        bundle_id=bundle_id,
        case_id=case_id,
        rule_id=rule_id,
        gate=gate,
        rederived_net_cents=rederived_net_cents,
        rules_sha=rules_sha,
    )
    return sign_payload(payload, key)


def verify_gate_verdict_ed25519(
    *,
    bundle_id: str,
    case_id: str,
    rule_id: str,
    gate: str,
    rederived_net_cents: int | None,
    rules_sha: str,
    signature: str,
    verify_key: Ed25519VerifyKey,
) -> bool:
    """Verify a gate verdict signature with a public-only key.

    Fail-closed:
      * ``verify_key`` must be an ``Ed25519VerifyKey`` — passing ``None`` (or
        anything without a public key) raises rather than silently passing;
      * a malformed-hex or non-matching signature returns False, never raises
        past the caller's expectation.
    """
    if not isinstance(verify_key, Ed25519VerifyKey):
        raise TypeError(
            "verify_gate_verdict_ed25519 requires an Ed25519VerifyKey; "
            f"got {type(verify_key).__name__}. Verification cannot proceed "
            "without a key (fail-closed)."
        )
    try:
        payload = _canonical_gate_payload(
            bundle_id=bundle_id,
            case_id=case_id,
            rule_id=rule_id,
            gate=gate,
            rederived_net_cents=rederived_net_cents,
            rules_sha=rules_sha,
        )
    except SigningError:
        return False  # an out-of-domain gate value can never match a real verdict
    return verify_payload(payload, signature, verify_key)


# ---------------------------------------------------------------------------
# v0_2 — ACTION-BOUND (POSITIONAL) verdicts, asymmetric. The forge-resistant
# token for an out-of-process chokepoint: the chokepoint holds only the public
# key and cannot mint its own AUTO_APPROVE. Reuses _canonical_action_gate_payload
# (same bytes as the HMAC v0_2 path — no drift) and enforces expiry on verify.
# ---------------------------------------------------------------------------


def sign_action_gate_verdict_ed25519(
    *,
    bundle_id: str,
    case_id: str,
    rule_id: str,
    gate: str,
    action_sha: str,
    idempotency_key: str,
    not_after: int,
    key: Ed25519VerifierKey,
) -> str:
    """Sign an action-bound verdict with the verifier's private key, returning hex.

    Signs the same canonical, domain-separated v0_2 payload as the HMAC signer, via
    the generic :func:`sign_payload` primitive."""
    payload = _canonical_action_gate_payload(
        bundle_id=bundle_id,
        case_id=case_id,
        rule_id=rule_id,
        gate=gate,
        action_sha=action_sha,
        idempotency_key=idempotency_key,
        not_after=not_after,
    )
    return sign_payload(payload, key)


def verify_action_gate_verdict_ed25519(
    *,
    bundle_id: str,
    case_id: str,
    rule_id: str,
    gate: str,
    action_sha: str,
    idempotency_key: str,
    not_after: int,
    signature: str,
    verify_key: Ed25519VerifyKey,
    now_epoch: int,
) -> ActionGateVerdictCheck:
    """Verify an action-bound verdict with a public-only key, PLUS enforce expiry.

    Returns the same :class:`ActionGateVerdictCheck` shape as
    :func:`verify_action_gate_verdict_hmac` — one structured verdict face for
    the action-gate check regardless of signature scheme: separate
    ``signature_valid`` / ``fresh`` legs, the echoed ``now_epoch``/``not_after``
    pair, and a machine-stable ``reason``. ``bool(result)`` is the composite
    ``result.ok``. Fail-closed:
      * ``verify_key`` must be an ``Ed25519VerifyKey`` — passing ``None`` raises;
      * a malformed tuple is ``ACTION_GATE_MALFORMED``; a non-matching
        signature is ``ACTION_GATE_SIGNATURE_INVALID``;
      * an expired token is ``ACTION_GATE_EXPIRED`` even when the signature is
        valid (``not_after`` is bound into the signed bytes);
      * a wrong-typed ``now_epoch`` raises ``TypeError``.

    Clock posture (determinism, API-enforced): like the HMAC twin, this
    function NEVER reads ambient time — ``now_epoch`` is REQUIRED and echoed in
    the result, so the clock behind a freshness verdict is always recorded with
    the decision. The caller owns the clock: the hosted enforcement path
    (``gate.chokepoint.ActionChokepoint`` — closed tier, EXCLUDED from the
    open drop per ``OSS_RELEASE_BOUNDARY.md``) passes the reading from its
    injectable ``now_fn``; a replay/audit harness passes the pinned historical
    instant; a live ergonomic caller passes ``int(time.time())`` at its own
    call site. (The former optional-``now_epoch`` wall-clock fallback was
    removed after four independent reviews flagged it; see the SECURITY.md
    clock table.)"""
    now = _require_now_epoch(now_epoch)
    if not isinstance(verify_key, Ed25519VerifyKey):
        raise TypeError(
            "verify_action_gate_verdict_ed25519 requires an Ed25519VerifyKey; "
            f"got {type(verify_key).__name__}. Verification cannot proceed "
            "without a key (fail-closed)."
        )

    def _conclude(
        *, signature_valid: bool, fresh: bool, reason: str
    ) -> ActionGateVerdictCheck:
        return ActionGateVerdictCheck(
            signature_valid=signature_valid,
            fresh=fresh,
            now_epoch=now,
            not_after=not_after,
            reason=reason,
        )

    try:
        payload = _canonical_action_gate_payload(
            bundle_id=bundle_id,
            case_id=case_id,
            rule_id=rule_id,
            gate=gate,
            action_sha=action_sha,
            idempotency_key=idempotency_key,
            not_after=not_after,
        )
    except SigningError:
        return _conclude(
            signature_valid=False, fresh=False, reason=ACTION_GATE_MALFORMED
        )
    if not verify_payload(payload, signature, verify_key):
        return _conclude(
            signature_valid=False, fresh=False, reason=ACTION_GATE_SIGNATURE_INVALID
        )
    if now > not_after:
        return _conclude(signature_valid=True, fresh=False, reason=ACTION_GATE_EXPIRED)
    return _conclude(signature_valid=True, fresh=True, reason=ACTION_GATE_OK)
