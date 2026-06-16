"""audit_bundle.gate.verdict_signing — signed disbursement-gate verdicts.

A V-Kernel verifier that gates an *action* (e.g. authorizing a payroll
disbursement) must be able to hand its verdict to a separate disburser — possibly
in another process, host, or moment — such that the disburser can act on a
*checkable artifact* rather than on an in-process function return it has to trust.
This module produces and verifies that artifact.

It deliberately reuses ``audit_bundle.discharge.verifier_signing.VerifierSigningKey``
(the proven C16 key envelope): HMAC-SHA256 over ``key.secret``, key loaded from
``VKERNEL_VERIFIER_HMAC_KEY`` via ``from_env`` (fail-closed with ``SigningError``)
or from explicit bytes via ``from_secret_bytes``. Only the canonical *payload*
differs — this signs a gate-verdict tuple whose meaning is "the verifier gated this
case to <gate> at <amount> against ruleset <rules_sha>", NOT the discharge module's
"an SMT obligation was discharged". A distinct domain separator guarantees a
discharge signature can never be replayed as a gate verdict, or vice versa.

==================== WHAT AN HMAC SIGNATURE HERE DOES AND DOES NOT BUY =========
DOES: tamper-evidence + portability. A verdict altered after signing (gate flipped
      to AUTO_APPROVE, amount changed, bound to a different case or ruleset) fails
      verification. The disburser checks a signature over a portable token instead
      of re-running or trusting the verifier in-process.
DOES NOT: non-repudiation against a key-holding disburser. HMAC is symmetric — any
      holder of the key can mint a valid verdict. Closing that requires an
      *asymmetric* verifier identity (verify-only public key at the disburser) —
      the C18 verifier-identity / Sigstore work, deferred. The canonical tuple is
      designed so that swap is a key-type change, not a tuple change. (This mirrors
      the discharge module's own honest HMAC-now / Ed25519-at-v1.0 caveat.)
NAMING: the scheme is in the function name — ``*_hmac`` here, ``*_ed25519`` in
      ``ed25519_verdict_signing``. No gate-verdict signer carries a bare
      ``sign_*`` name, so a call site always shows which of the two trust
      claims it is making. (See "Terminology" in ``the internal design notes``.)
================================================================================

Cross-file invariant: any side that signs or verifies a gate verdict MUST agree on
``_canonical_gate_payload``. Changing the tuple shape is a breaking change and must
bump ``_GATE_SIGNING_DOMAIN``.

==================== POSITIONAL (ACTION-BOUND) VERDICTS — v0_2 =================
The v0_1 verdict above authorizes a *case* at an *amount* (payroll-shaped). To make
a gate *positional* — the chokepoint that holds the capability the agent lacks, like
an inline tool-dispatch interceptor — the token must instead bind the *concrete
action* it authorizes, plus the freshness machinery that stops replay:

  * ``action_sha``      — sha256 commitment to the exact tool call / action
                          (``compute_action_sha``). Swapping any arg (a redirected
                          payee, a bumped amount, an added field) changes the sha,
                          so a token for one action cannot authorize another. The
                          payment-specific ``rederived_net_cents`` of v0_1 is
                          subsumed: when the action is a payment, the amount is one
                          of the args the sha commits to.
  * ``idempotency_key`` — a per-action nonce, bound into the signature so a
                          chokepoint can refuse a second use of the same token.
                          (The spent-nonce *store* lives at the chokepoint — Layer
                          2; v0_2 only makes the nonce tamper-evident.)
  * ``not_after``       — integer epoch-seconds expiry, bound into the signature so
                          it cannot be extended. ``verify_action_gate_verdict_hmac``
                          enforces it (fail-closed past expiry), not just the sig.

These live under their OWN domain separator (``_ACTION_GATE_SIGNING_DOMAIN``), so a
v0_1 case-verdict signature can never validate as a v0_2 action authorization or
vice versa — "old-shape rejected" falls out of domain separation. v0_2 is additive:
existing v0_1 callers (early demo pilots) are untouched.
================================================================================
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from audit_bundle.discharge.verifier_signing import SigningError, VerifierSigningKey

# Distinct domain separator from the discharge signer — a discharge signature can
# never be replayed as a gate verdict or vice versa.
_GATE_SIGNING_DOMAIN: Final = b"vkernel.gate.verdict.v0_1\x00"

# Action-bound (positional) verdict domain — see the v0_2 note in the module
# docstring. Distinct from _GATE_SIGNING_DOMAIN so a v0_1 case verdict can never be
# replayed as a v0_2 action authorization, or vice versa.
_ACTION_GATE_SIGNING_DOMAIN: Final = b"vkernel.gate.action_verdict.v0_2\x00"

# Domain for the action-commitment hash itself, so an ``action_sha`` can never
# collide with some other sha256 a caller might compute over the same bytes.
_ACTION_SHA_DOMAIN: Final = b"vkernel.gate.action_sha.v0_1\x00"

# The two gate outcomes a verdict can carry. Kept here (not imported from a pilot)
# so the substrate signer has no dependency on any example/.
AUTO_APPROVE: Final = "AUTO_APPROVE"
HUMAN_REVIEW: Final = "HUMAN_REVIEW"
GATE_VALUES: Final = frozenset({AUTO_APPROVE, HUMAN_REVIEW})

# Stable reason codes for the action-bound token check (see
# ActionGateVerdictCheck). Machine-stable strings, same discipline as the
# bundle verdict's reason codes (VERIFIER_CONTRACT C-6).
ACTION_GATE_OK: Final = "ACTION_GATE_OK"
ACTION_GATE_MALFORMED: Final = "ACTION_GATE_MALFORMED"
ACTION_GATE_SIGNATURE_INVALID: Final = "ACTION_GATE_SIGNATURE_INVALID"
ACTION_GATE_EXPIRED: Final = "ACTION_GATE_EXPIRED"

__all__ = [
    "AUTO_APPROVE",
    "HUMAN_REVIEW",
    "GATE_VALUES",
    "ACTION_GATE_OK",
    "ACTION_GATE_MALFORMED",
    "ACTION_GATE_SIGNATURE_INVALID",
    "ACTION_GATE_EXPIRED",
    "ActionGateVerdictCheck",
    "SigningError",
    "VerifierSigningKey",
    "sign_gate_verdict_hmac",
    "verify_gate_verdict_hmac",
    "compute_action_sha",
    "sign_action_gate_verdict_hmac",
    "verify_action_gate_verdict_hmac",
]


@dataclass(frozen=True)
class ActionGateVerdictCheck:
    """Structured verdict face of one action-bound token check.

    The two predicates of the check are epistemically different and are
    reported as SEPARATE legs:

      * ``signature_valid`` — pure cryptography: the token's bytes match the
        signature under the key. Deterministic function of its inputs.
      * ``fresh`` — clock policy: ``now_epoch <= not_after``. ``fresh`` is a
        CLAIM ONLY WHEN ``signature_valid`` — an unsigned ``not_after`` is not
        trustworthy, so an invalid-signature result always carries
        ``fresh=False`` without asserting anything about real freshness.

    ``now_epoch``/``not_after`` echo the exact pair that drove the freshness
    leg, so the clock behind a freshness verdict is ALWAYS recorded with the
    decision — re-running with the same arguments reproduces the same verdict,
    and a transcript that stores this object stores its own reproducibility.
    ``reason`` is the machine-stable dominant code (ACTION_GATE_OK |
    ACTION_GATE_MALFORMED | ACTION_GATE_SIGNATURE_INVALID |
    ACTION_GATE_EXPIRED).

    ``bool(check)`` is ``check.ok`` — the composite signature_valid AND fresh —
    so guard-style call sites (``if verify_action_gate_verdict_hmac(...)``)
    keep exactly the semantics of the pre-structured bool API.
    """

    signature_valid: bool
    fresh: bool
    now_epoch: int
    not_after: int
    reason: str

    @property
    def ok(self) -> bool:
        return self.signature_valid and self.fresh

    def __bool__(self) -> bool:
        return self.ok


def _resolve_key(key: VerifierSigningKey | None) -> VerifierSigningKey:
    return key if key is not None else VerifierSigningKey.from_env()


def _require_strict_int_cents(value: object) -> int | None:
    """Strict admission of rederived_net_cents: None or a plain int, never bool/float/str.

    Coercing via int() would let True/1.0/1.2/"1"/b"1" all encode to "1", so a
    signature issued for integer 1 would also validate those — contradicting the
    docstring claim that the verdict "proves approval of the exact disbursement
    amount". Fail-closed on any non-int (excluding bool, which is an int subclass
    in Python) so the signed amount is always a genuine integer-cents value."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise SigningError(
            f"rederived_net_cents must be None or a plain int (not bool/float/str/bytes); "
            f"got {type(value).__name__!r}: {value!r}"
        )
    return value


def _canonical_gate_payload(
    *,
    bundle_id: str,
    case_id: str,
    rule_id: str,
    gate: str,
    rederived_net_cents: int | None,
    rules_sha: str,
) -> bytes:
    """Domain-separated, length-prefixed canonical encoding of the gate-verdict tuple.

    Length-prefixing each field prevents canonical-encoding collisions (e.g.
    case 'ab' + rule 'c' vs case 'a' + rule 'bc'). ``rederived_net_cents`` is
    encoded as its decimal string, or empty when None (HUMAN_REVIEW carries no
    verifier-blessed amount — the amount is precisely what could not be
    re-derived). Binding ``rules_sha`` means a verdict signed against one ruleset
    cannot be replayed against a different (e.g. friendlier) one.
    """
    if gate not in GATE_VALUES:
        raise SigningError(f"gate must be one of {sorted(GATE_VALUES)}; got {gate!r}")
    net_cents = _require_strict_int_cents(rederived_net_cents)
    net_field = "" if net_cents is None else str(net_cents)
    parts = [
        _GATE_SIGNING_DOMAIN,
        bundle_id.encode("utf-8"),
        case_id.encode("utf-8"),
        rule_id.encode("utf-8"),
        gate.encode("utf-8"),
        net_field.encode("utf-8"),
        rules_sha.encode("utf-8"),
    ]
    out = bytearray()
    for part in parts:
        out += len(part).to_bytes(4, "big")
        out += part
    return bytes(out)


def sign_gate_verdict_hmac(
    *,
    bundle_id: str,
    case_id: str,
    rule_id: str,
    gate: str,
    rederived_net_cents: int | None,
    rules_sha: str,
    key: VerifierSigningKey | None = None,
) -> str:
    """Return the hex HMAC-SHA256 signature over the gate-verdict tuple.

    ``key`` defaults to :meth:`VerifierSigningKey.from_env` — fail-closed if
    ``VKERNEL_VERIFIER_HMAC_KEY`` is unset. Pass an explicit key in tests/demos.
    """
    signing_key = _resolve_key(key)
    payload = _canonical_gate_payload(
        bundle_id=bundle_id,
        case_id=case_id,
        rule_id=rule_id,
        gate=gate,
        rederived_net_cents=rederived_net_cents,
        rules_sha=rules_sha,
    )
    return hmac.new(signing_key.secret, payload, hashlib.sha256).hexdigest()


def verify_gate_verdict_hmac(
    *,
    bundle_id: str,
    case_id: str,
    rule_id: str,
    gate: str,
    rederived_net_cents: int | None,
    rules_sha: str,
    signature: str,
    key: VerifierSigningKey | None = None,
) -> bool:
    """Constant-time check that ``signature`` matches the gate-verdict tuple.

    Returns False on any mismatch (incl. a malformed ``gate`` or non-str
    signature). Raises SigningError only if no key is available (fail-closed — a
    missing key is never silently treated as "valid").
    """
    signing_key = _resolve_key(key)
    if not isinstance(signature, str):
        return False
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
    expected = hmac.new(signing_key.secret, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


# ===========================================================================
# v0_2 — ACTION-BOUND (POSITIONAL) GATE VERDICTS
# A token that authorizes a *concrete action* (by sha) with a nonce + expiry,
# for an out-of-process chokepoint that holds the capability the agent lacks.
# See the v0_2 note in the module docstring.
# ===========================================================================


def _validate_action_structure(value: object, path: str) -> None:
    """Recursive pre-hash validator: every mapping key at every depth must be str.

    ``json.dumps(sort_keys=True)`` coerces non-str keys — int 1 and str "1" both
    serialise to "1"; True → "true"; None → "null" — so two structurally distinct
    actions can collapse to the same sha. Reject non-str keys before hashing so
    the sha is injective over the supplied structure. Also rejects non-finite
    floats (belt-and-suspenders; json.dumps allow_nan=False catches them too).
    Raises :class:`SigningError` on any violation (fail-closed)."""
    if isinstance(value, bool):
        # bool is a subtype of int; allow as a leaf value — it serialises
        # unambiguously ("true"/"false"); only KEYS are the injectivity hazard.
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise SigningError(
                    f"action structure at {path!r}: mapping key {k!r} "
                    f"({type(k).__name__}) is not str — json.dumps would coerce "
                    "it, collapsing distinct actions to the same sha"
                )
            _validate_action_structure(v, f"{path}.{k}")
    elif isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            _validate_action_structure(item, f"{path}[{i}]")
    elif isinstance(value, float) and not (
        value == value and value not in (float("inf"), float("-inf"))
    ):
        # Non-finite float in a value position; allow_nan=False would catch this
        # too but raise here with a clearer message.
        raise SigningError(
            f"action structure at {path!r}: non-finite float {value!r} is not "
            "a canonically committable value"
        )


def compute_action_sha(*, tool: str, args: Mapping[str, Any]) -> str:
    """Canonical sha256 commitment to a concrete tool/action invocation.

    The positional chokepoint binds an authorization token to *this exact action*
    by its sha. Any change to the tool name or to any argument value — a swapped
    payee, a bumped amount, an added field — changes the sha, so a token authorizing
    one action cannot authorize a different one. This is the generic replacement for
    v0_1's payment-specific ``rederived_net_cents``: the amount, when relevant, is
    just one of ``args``.

    Canonical JSON (sorted keys, tight separators) over a domain separator. All
    mapping keys at every nesting depth must be ``str`` — non-str keys are rejected
    before hashing because ``json.dumps(sort_keys=True)`` coerces them (int 1 and
    str "1" produce the same bytes), making the sha non-injective over the action
    structure. Raises :class:`SigningError` on a non-str key or non-JSON-serialisable
    arg (fail-closed — an action that cannot be canonically committed must not
    silently receive a sha)."""
    _validate_action_structure(args, "args")
    try:
        body = json.dumps(
            {"tool": tool, "args": args},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SigningError(f"action is not canonically serialisable: {exc}") from exc
    return hashlib.sha256(_ACTION_SHA_DOMAIN + body).hexdigest()


def _canonical_action_gate_payload(
    *,
    bundle_id: str,
    case_id: str,
    rule_id: str,
    gate: str,
    action_sha: str,
    idempotency_key: str,
    not_after: int,
) -> bytes:
    """Domain-separated, length-prefixed encoding of the action-bound verdict tuple.

    Same length-prefixing discipline as :func:`_canonical_gate_payload`, under the
    distinct ``_ACTION_GATE_SIGNING_DOMAIN`` so a v0_1 case verdict can never be
    replayed as a v0_2 action authorization. ``not_after`` is bound into the bytes
    (integer epoch seconds, decimal-encoded) so an attacker cannot extend the token
    without breaking the signature."""
    if gate not in GATE_VALUES:
        raise SigningError(f"gate must be one of {sorted(GATE_VALUES)}; got {gate!r}")
    if not isinstance(not_after, int) or isinstance(not_after, bool):
        raise SigningError(f"not_after must be int epoch-seconds; got {not_after!r}")
    parts = [
        _ACTION_GATE_SIGNING_DOMAIN,
        bundle_id.encode("utf-8"),
        case_id.encode("utf-8"),
        rule_id.encode("utf-8"),
        gate.encode("utf-8"),
        action_sha.encode("utf-8"),
        idempotency_key.encode("utf-8"),
        str(not_after).encode("utf-8"),
    ]
    out = bytearray()
    for part in parts:
        out += len(part).to_bytes(4, "big")
        out += part
    return bytes(out)


def sign_action_gate_verdict_hmac(
    *,
    bundle_id: str,
    case_id: str,
    rule_id: str,
    gate: str,
    action_sha: str,
    idempotency_key: str,
    not_after: int,
    key: VerifierSigningKey | None = None,
) -> str:
    """Return the hex HMAC-SHA256 signature over the action-bound verdict tuple.

    ``key`` defaults to :meth:`VerifierSigningKey.from_env` (fail-closed). The HMAC
    caveat of v0_1 applies unchanged — symmetric, so tamper-evidence + portability,
    not forge-resistance against a key-holding chokepoint. Use
    :func:`audit_bundle.gate.ed25519_verdict_signing.sign_action_gate_verdict_ed25519`
    for the asymmetric, forge-resistant token."""
    signing_key = _resolve_key(key)
    payload = _canonical_action_gate_payload(
        bundle_id=bundle_id,
        case_id=case_id,
        rule_id=rule_id,
        gate=gate,
        action_sha=action_sha,
        idempotency_key=idempotency_key,
        not_after=not_after,
    )
    return hmac.new(signing_key.secret, payload, hashlib.sha256).hexdigest()


def _require_now_epoch(now_epoch: object) -> int:
    """Fail-closed admission of the caller's clock reading (programming-error
    guard, like the ed25519 verify-key typeguard — a wrong-typed clock raises,
    it never silently coerces into a freshness decision)."""
    if not isinstance(now_epoch, int) or isinstance(now_epoch, bool):
        raise TypeError(
            "now_epoch must be an int epoch-seconds clock reading; got "
            f"{type(now_epoch).__name__}. The caller owns the clock: an "
            "enforcement runtime passes its injected clock, a replay/audit "
            "harness passes the pinned historical instant, a live ergonomic "
            "caller passes int(time.time()) at its own call site."
        )
    return now_epoch


def verify_action_gate_verdict_hmac(
    *,
    bundle_id: str,
    case_id: str,
    rule_id: str,
    gate: str,
    action_sha: str,
    idempotency_key: str,
    not_after: int,
    signature: str,
    key: VerifierSigningKey | None = None,
    now_epoch: int,
) -> ActionGateVerdictCheck:
    """Constant-time signature check on an action-bound verdict, PLUS expiry.

    Returns an :class:`ActionGateVerdictCheck` — separate ``signature_valid`` /
    ``fresh`` legs, the ``now_epoch``/``not_after`` pair that drove the
    freshness leg, and a machine-stable ``reason``. ``bool(result)`` is the
    composite ``result.ok``, so a guard-style call site keeps the exact
    semantics of the pre-structured bool API. A malformed input (non-str
    signature, out-of-domain ``gate``, non-int ``not_after``) is
    ``ACTION_GATE_MALFORMED`` — a structured reject, never a pass. An
    expired-but-otherwise-valid token is ``ACTION_GATE_EXPIRED``
    (``not_after`` is part of the signed tuple, so it cannot be extended
    without breaking the signature). Raises ``SigningError`` only if no key is
    available, and ``TypeError`` for a wrong-typed ``now_epoch`` (both
    fail-closed programming-error guards).

    Clock posture (determinism, API-enforced): this function NEVER reads
    ambient time — ``now_epoch`` is REQUIRED and is echoed in the result, so
    the clock behind a freshness verdict is always recorded with the decision
    and re-running with the same arguments reproduces the same verdict. The
    caller owns the clock: the hosted enforcement path
    (``gate.chokepoint.ActionChokepoint`` — closed tier, EXCLUDED from the
    open drop per ``OSS_RELEASE_BOUNDARY.md``) passes the reading from its
    injectable ``now_fn``; a replay/audit harness passes the pinned historical
    instant; a live ergonomic caller passes ``int(time.time())`` at its own
    call site, which keeps the ambient read visibly the caller's. (This
    replaces the former optional-``now_epoch`` wall-clock fallback — flagged by
    four independent reviews; see the SECURITY.md clock table — so the
    "remember to inject and record" discipline is now enforced by the API
    rather than advised by this docstring.)"""
    now = _require_now_epoch(now_epoch)
    signing_key = _resolve_key(key)

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

    if not isinstance(signature, str):
        return _conclude(
            signature_valid=False, fresh=False, reason=ACTION_GATE_MALFORMED
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
    expected = hmac.new(signing_key.secret, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return _conclude(
            signature_valid=False, fresh=False, reason=ACTION_GATE_SIGNATURE_INVALID
        )
    if now > not_after:
        return _conclude(signature_valid=True, fresh=False, reason=ACTION_GATE_EXPIRED)
    return _conclude(signature_valid=True, fresh=True, reason=ACTION_GATE_OK)
