"""test_action_gate_verdict_signing.py — substrate tests for v0_2 action-bound
(positional) gate verdicts in audit_bundle.gate.

A v0_2 token authorizes a *concrete action* (by ``action_sha``) with a nonce
(``idempotency_key``) and an expiry (``not_after``), for an out-of-process
chokepoint that holds the capability a compromised agent lacks. These tests pin the
four properties Layer 1 must guarantee before any real chokepoint is wired:

  1. round-trip (HMAC + Ed25519);
  2. every field is bound — including a redirected action (action_sha) and a bumped
     nonce — so a token for one action cannot authorize another;
  3. expiry is enforced on verify, not just signed — a stale token fails closed;
  4. old-shape rejected — a v0_1 case-verdict signature can never validate as a v0_2
     action authorization (domain separation), and vice versa;
  5. Ed25519 forge-resistance carries over — a public-key-only holder cannot mint.
"""

from __future__ import annotations

import inspect
import time

import pytest

from audit_bundle.gate.ed25519_verdict_signing import (
    Ed25519VerifierKey,
    sign_action_gate_verdict_ed25519,
    verify_action_gate_verdict_ed25519,
)
from audit_bundle.gate.verdict_signing import (
    ACTION_GATE_EXPIRED,
    ACTION_GATE_MALFORMED,
    ACTION_GATE_OK,
    ACTION_GATE_SIGNATURE_INVALID,
    AUTO_APPROVE,
    HUMAN_REVIEW,
    SigningError,
    VerifierSigningKey,
    _ACTION_GATE_SIGNING_DOMAIN,
    _canonical_action_gate_payload,
    compute_action_sha,
    sign_action_gate_verdict_hmac,
    sign_gate_verdict_hmac,
    verify_action_gate_verdict_hmac,
)

_KEY = VerifierSigningKey.from_secret_bytes(b"\x11" * 32)
_ED_KEY = Ed25519VerifierKey.from_hex("11" * 32)

# A far-future expiry so signature-binding tests aren't accidentally tripped by the
# freshness check; the expiry tests set their own.
_FUTURE = 4_102_444_800  # 2100-01-01T00:00:00Z
_NOW = 1_700_000_000  # a fixed "current" epoch used by the binding tests

_ACTION = compute_action_sha(
    tool="payments.transfer",
    args={"payee_id": "PAYEE-saved-001", "amount_cents": 160385, "currency": "USD"},
)

_BASE = dict(
    bundle_id="payroll-agent-gate-minimal-rc",
    case_id="C-2001",
    rule_id="ACTING_PERIOD_SPLIT",
    gate=AUTO_APPROVE,
    action_sha=_ACTION,
    idempotency_key="nonce-9f3c-0001",
    not_after=_FUTURE,
)


# --------------------------------------------------------------------------- #
# compute_action_sha                                                          #
# --------------------------------------------------------------------------- #


def test_action_sha_is_deterministic_and_order_independent():
    a = compute_action_sha(tool="t", args={"x": 1, "y": 2})
    b = compute_action_sha(tool="t", args={"y": 2, "x": 1})  # different dict order
    assert a == b == compute_action_sha(tool="t", args={"x": 1, "y": 2})


@pytest.mark.parametrize(
    "mutate",
    [
        lambda: compute_action_sha(
            tool="payments.transfer",
            args={
                "payee_id": "PAYEE-ATTACKER",
                "amount_cents": 160385,
                "currency": "USD",
            },
        ),
        lambda: compute_action_sha(
            tool="payments.transfer",
            args={
                "payee_id": "PAYEE-saved-001",
                "amount_cents": 9_000_000,
                "currency": "USD",
            },
        ),
        lambda: compute_action_sha(
            tool="payments.transfer",
            args={
                "payee_id": "PAYEE-saved-001",
                "amount_cents": 160385,
                "currency": "USD",
                "memo": "x",
            },
        ),
        lambda: compute_action_sha(
            tool="data.exfiltrate",
            args={
                "payee_id": "PAYEE-saved-001",
                "amount_cents": 160385,
                "currency": "USD",
            },
        ),
    ],
)
def test_action_sha_changes_when_anything_changes(mutate):
    """Redirected payee, bumped amount, added field, or swapped tool — each yields a
    different sha, so a token for the original action cannot authorize the mutated one."""
    assert mutate() != _ACTION


def test_action_sha_fails_closed_on_non_serialisable():
    with pytest.raises(SigningError):
        compute_action_sha(tool="t", args={"bad": object()})


# --------------------------------------------------------------------------- #
# HMAC round-trip + field binding                                             #
# --------------------------------------------------------------------------- #


def test_round_trip_hmac():
    sig = sign_action_gate_verdict_hmac(**_BASE, key=_KEY)
    assert (
        verify_action_gate_verdict_hmac(
            **_BASE, signature=sig, key=_KEY, now_epoch=_NOW
        ).ok
        is True
    )


@pytest.mark.parametrize(
    "field,bad",
    [
        ("bundle_id", "other-bundle"),
        ("case_id", "C-9999"),
        ("rule_id", "ROUTINE_RETRO"),
        ("gate", HUMAN_REVIEW),
        (
            "action_sha",
            compute_action_sha(
                tool="payments.transfer",
                args={
                    "payee_id": "PAYEE-ATTACKER",
                    "amount_cents": 160385,
                    "currency": "USD",
                },
            ),
        ),
        ("idempotency_key", "nonce-REPLAYED"),
        ("not_after", _FUTURE + 1),
    ],
)
def test_every_field_is_bound_hmac(field, bad):
    """Tampering any signed field — including the action commitment, the nonce, and
    the expiry — must break verification."""
    sig = sign_action_gate_verdict_hmac(**_BASE, key=_KEY)
    tampered = dict(_BASE)
    tampered[field] = bad
    assert (
        verify_action_gate_verdict_hmac(
            **tampered, signature=sig, key=_KEY, now_epoch=_NOW
        ).ok
        is False
    )


def test_redirected_action_blocked_hmac():
    """The headline positional risk: a valid token for the saved-payee transfer must
    NOT authorize a transfer redirected to an attacker payee."""
    sig = sign_action_gate_verdict_hmac(**_BASE, key=_KEY)
    redirected = dict(
        _BASE,
        action_sha=compute_action_sha(
            tool="payments.transfer",
            args={
                "payee_id": "PAYEE-ATTACKER",
                "amount_cents": 160385,
                "currency": "USD",
            },
        ),
    )
    assert (
        verify_action_gate_verdict_hmac(
            **redirected, signature=sig, key=_KEY, now_epoch=_NOW
        ).ok
        is False
    )


# --------------------------------------------------------------------------- #
# Expiry — enforced on verify, not just signed                                #
# --------------------------------------------------------------------------- #


def test_fresh_token_passes():
    near = dict(_BASE, not_after=_NOW + 60)
    sig = sign_action_gate_verdict_hmac(**near, key=_KEY)
    assert (
        verify_action_gate_verdict_hmac(
            **near, signature=sig, key=_KEY, now_epoch=_NOW
        ).ok
        is True
    )


def test_expired_token_blocked_even_with_valid_signature():
    expired = dict(_BASE, not_after=_NOW - 1)
    sig = sign_action_gate_verdict_hmac(**expired, key=_KEY)
    # Signature is valid for the (expired) tuple, but verify must still fail closed.
    assert (
        verify_action_gate_verdict_hmac(
            **expired, signature=sig, key=_KEY, now_epoch=_NOW
        ).ok
        is False
    )


def test_expiry_boundary_inclusive():
    """A token is valid up to and including not_after; one second past, it fails."""
    at = dict(_BASE, not_after=_NOW)
    sig = sign_action_gate_verdict_hmac(**at, key=_KEY)
    assert (
        verify_action_gate_verdict_hmac(
            **at, signature=sig, key=_KEY, now_epoch=_NOW
        ).ok
        is True
    )
    assert (
        verify_action_gate_verdict_hmac(
            **at, signature=sig, key=_KEY, now_epoch=_NOW + 1
        ).ok
        is False
    )


def test_not_after_must_be_int():
    with pytest.raises(SigningError):
        sign_action_gate_verdict_hmac(**dict(_BASE, not_after="soon"), key=_KEY)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Domain separation — "old-shape rejected"                                    #
# --------------------------------------------------------------------------- #


def test_v0_1_signature_cannot_validate_as_action_verdict():
    """A v0_1 case-verdict signature presented to the v0_2 verifier must be rejected:
    the action-bound chokepoint requires an action authorization, and the legacy
    token shape is structurally different (different domain separator)."""
    v01_sig = sign_gate_verdict_hmac(
        bundle_id=_BASE["bundle_id"],
        case_id=_BASE["case_id"],
        rule_id=_BASE["rule_id"],
        gate=AUTO_APPROVE,
        rederived_net_cents=160385,
        rules_sha="a" * 64,
        key=_KEY,
    )
    assert (
        verify_action_gate_verdict_hmac(
            **_BASE, signature=v01_sig, key=_KEY, now_epoch=_NOW
        ).ok
        is False
    )


def test_action_payload_is_domain_separated():
    payload = _canonical_action_gate_payload(
        bundle_id=_BASE["bundle_id"],
        case_id=_BASE["case_id"],
        rule_id=_BASE["rule_id"],
        gate=_BASE["gate"],
        action_sha=_BASE["action_sha"],
        idempotency_key=_BASE["idempotency_key"],
        not_after=_BASE["not_after"],
    )
    assert payload[:4] == len(_ACTION_GATE_SIGNING_DOMAIN).to_bytes(4, "big")
    assert (
        payload[4 : 4 + len(_ACTION_GATE_SIGNING_DOMAIN)] == _ACTION_GATE_SIGNING_DOMAIN
    )


def test_wrong_key_fails_hmac():
    sig = sign_action_gate_verdict_hmac(**_BASE, key=_KEY)
    other = VerifierSigningKey.from_secret_bytes(b"\x22" * 32)
    assert (
        verify_action_gate_verdict_hmac(
            **_BASE, signature=sig, key=other, now_epoch=_NOW
        ).ok
        is False
    )


def test_invalid_gate_rejected_hmac():
    with pytest.raises(SigningError):
        sign_action_gate_verdict_hmac(**dict(_BASE, gate="MAYBE"), key=_KEY)


def test_bad_signature_type_returns_false():
    assert (
        verify_action_gate_verdict_hmac(
            **_BASE, signature=None, key=_KEY, now_epoch=_NOW
        ).ok
        is False
    )  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Ed25519 — round-trip, binding, expiry, forge-resistance                     #
# --------------------------------------------------------------------------- #


def test_round_trip_ed25519():
    sig = sign_action_gate_verdict_ed25519(**_BASE, key=_ED_KEY)
    vk = _ED_KEY.public_key()
    assert (
        verify_action_gate_verdict_ed25519(
            **_BASE, signature=sig, verify_key=vk, now_epoch=_NOW
        ).ok
        is True
    )


def test_redirected_action_blocked_ed25519():
    sig = sign_action_gate_verdict_ed25519(**_BASE, key=_ED_KEY)
    vk = _ED_KEY.public_key()
    redirected = dict(
        _BASE,
        action_sha=compute_action_sha(
            tool="payments.transfer",
            args={
                "payee_id": "PAYEE-ATTACKER",
                "amount_cents": 160385,
                "currency": "USD",
            },
        ),
    )
    assert (
        verify_action_gate_verdict_ed25519(
            **redirected, signature=sig, verify_key=vk, now_epoch=_NOW
        ).ok
        is False
    )


def test_expired_token_blocked_ed25519():
    expired = dict(_BASE, not_after=_NOW - 1)
    sig = sign_action_gate_verdict_ed25519(**expired, key=_ED_KEY)
    vk = _ED_KEY.public_key()
    assert (
        verify_action_gate_verdict_ed25519(
            **expired, signature=sig, verify_key=vk, now_epoch=_NOW
        ).ok
        is False
    )


def test_public_key_holder_cannot_forge_action_verdict():
    """A chokepoint holding only the public verify key cannot mint its own
    AUTO_APPROVE action token — the forge-resistance of the v0_1 path carries to v0_2."""
    attacker = Ed25519VerifierKey.generate()  # all a chokepoint can make for itself
    forged_sig = sign_action_gate_verdict_ed25519(
        **dict(_BASE, idempotency_key="nonce-FORGED"), key=attacker
    )
    vk = _ED_KEY.public_key()  # the real verifier's public key
    assert (
        verify_action_gate_verdict_ed25519(
            **dict(_BASE, idempotency_key="nonce-FORGED"),
            signature=forged_sig,
            verify_key=vk,
            now_epoch=_NOW,
        ).ok
        is False
    )


def test_verify_ed25519_requires_public_key():
    sig = sign_action_gate_verdict_ed25519(**_BASE, key=_ED_KEY)
    with pytest.raises(TypeError):
        verify_action_gate_verdict_ed25519(
            **_BASE, signature=sig, verify_key=None, now_epoch=_NOW
        )  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Structured verdict face — separate legs, echoed clock, no ambient time      #
# (RES-05 series: the wall-clock default was removed; now_epoch is required   #
# and the check records the clock that drove it)                              #
# --------------------------------------------------------------------------- #


def test_check_ok_legs_and_reason():
    sig = sign_action_gate_verdict_hmac(**_BASE, key=_KEY)
    check = verify_action_gate_verdict_hmac(
        **_BASE, signature=sig, key=_KEY, now_epoch=_NOW
    )
    assert check.signature_valid is True and check.fresh is True
    assert check.reason == ACTION_GATE_OK
    assert bool(check) is True  # __bool__ mirrors .ok for guard-style callers


def test_expired_check_separates_the_legs():
    """A valid-but-stale token is signature_valid=True, fresh=False, EXPIRED —
    the decomposition the chokepoint previously had to reconstruct by
    neutralizing the helper's expiry gate (now_epoch=not_after) and re-checking
    freshness itself."""
    expired = dict(_BASE, not_after=_NOW - 1)
    sig = sign_action_gate_verdict_hmac(**expired, key=_KEY)
    check = verify_action_gate_verdict_hmac(
        **expired, signature=sig, key=_KEY, now_epoch=_NOW
    )
    assert check.signature_valid is True and check.fresh is False
    assert check.reason == ACTION_GATE_EXPIRED
    assert bool(check) is False


def test_tampered_check_does_not_claim_freshness():
    """An invalid signature never asserts freshness — not_after is trustworthy
    only under a valid signature, so fresh is False without being a claim."""
    sig = sign_action_gate_verdict_hmac(**_BASE, key=_KEY)
    tampered = dict(_BASE, case_id="C-9999")
    check = verify_action_gate_verdict_hmac(
        **tampered, signature=sig, key=_KEY, now_epoch=_NOW
    )
    assert check.signature_valid is False and check.fresh is False
    assert check.reason == ACTION_GATE_SIGNATURE_INVALID


def test_malformed_inputs_get_a_distinct_reason():
    # Non-str signature and out-of-domain gate are MALFORMED, not lumped under
    # SIGNATURE_INVALID — a structured reject, never a pass.
    check = verify_action_gate_verdict_hmac(
        **_BASE, signature=None, key=_KEY, now_epoch=_NOW  # type: ignore[arg-type]
    )
    assert check.reason == ACTION_GATE_MALFORMED and check.ok is False
    sig = sign_action_gate_verdict_hmac(**_BASE, key=_KEY)
    check = verify_action_gate_verdict_hmac(
        **dict(_BASE, gate="MAYBE"), signature=sig, key=_KEY, now_epoch=_NOW
    )
    assert check.reason == ACTION_GATE_MALFORMED and check.ok is False


def test_check_echoes_the_driving_clock_pair():
    """The (now_epoch, not_after) pair that drove the freshness leg rides the
    result, so a transcript that stores the check stores its own
    reproducibility — the clock can never be 'not recorded'."""
    sig = sign_action_gate_verdict_hmac(**_BASE, key=_KEY)
    check = verify_action_gate_verdict_hmac(
        **_BASE, signature=sig, key=_KEY, now_epoch=_NOW
    )
    assert check.now_epoch == _NOW and check.not_after == _BASE["not_after"]
    vk = _ED_KEY.public_key()
    esig = sign_action_gate_verdict_ed25519(**_BASE, key=_ED_KEY)
    echeck = verify_action_gate_verdict_ed25519(
        **_BASE, signature=esig, verify_key=vk, now_epoch=_NOW
    )
    assert echeck.now_epoch == _NOW and echeck.not_after == _BASE["not_after"]
    assert echeck.reason == ACTION_GATE_OK


def test_now_epoch_is_required_signature_ratchet():
    """now_epoch has NO default on either twin — re-adding a wall-clock (or any)
    fallback requires deliberately changing the signature this test pins."""
    for fn in (verify_action_gate_verdict_hmac, verify_action_gate_verdict_ed25519):
        param = inspect.signature(fn).parameters["now_epoch"]
        assert param.default is inspect.Parameter.empty, (
            f"{fn.__name__}: now_epoch grew a default — the verifier must never "
            "own the clock; the caller passes (and thereby records) it"
        )


def test_verify_never_reads_ambient_time(monkeypatch):
    """Both verifiers are pure functions of their arguments: with time.time
    booby-trapped, verification still concludes. Catches any reintroduced
    ambient-clock read on the gate verify path."""

    def _boom():
        raise AssertionError("gate verify read the ambient clock")

    monkeypatch.setattr(time, "time", _boom)
    sig = sign_action_gate_verdict_hmac(**_BASE, key=_KEY)
    assert verify_action_gate_verdict_hmac(
        **_BASE, signature=sig, key=_KEY, now_epoch=_NOW
    ).ok
    vk = _ED_KEY.public_key()
    esig = sign_action_gate_verdict_ed25519(**_BASE, key=_ED_KEY)
    assert verify_action_gate_verdict_ed25519(
        **_BASE, signature=esig, verify_key=vk, now_epoch=_NOW
    ).ok


def test_wrong_typed_now_epoch_raises():
    """A wrong-typed clock raises (programming-error guard) — it never coerces
    into a freshness decision. bool is rejected explicitly (True == 1 would
    otherwise read as epoch second 1)."""
    sig = sign_action_gate_verdict_hmac(**_BASE, key=_KEY)
    for bad in (None, True, 1.5, "now"):
        with pytest.raises(TypeError):
            verify_action_gate_verdict_hmac(
                **_BASE, signature=sig, key=_KEY, now_epoch=bad  # type: ignore[arg-type]
            )
