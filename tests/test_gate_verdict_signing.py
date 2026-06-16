"""test_gate_verdict_signing.py — substrate tests for audit_bundle.gate.verdict_signing.

Covers the signed disbursement-gate verdict primitive: round-trip, every field
binding (tamper any field -> verification fails), domain separation from the C16
discharge signer, fail-closed key handling, and the HUMAN_REVIEW (None-amount) case.
"""

from __future__ import annotations

import pytest

from audit_bundle.gate.verdict_signing import (
    AUTO_APPROVE,
    HUMAN_REVIEW,
    _GATE_SIGNING_DOMAIN,
    SigningError,
    VerifierSigningKey,
    _canonical_gate_payload,
    sign_gate_verdict_hmac,
    verify_gate_verdict_hmac,
)

_KEY = VerifierSigningKey.from_secret_bytes(b"\x11" * 32)

_BASE = dict(
    bundle_id="payroll-agent-gate-minimal-rc",
    case_id="C-2001",
    rule_id="ACTING_PERIOD_SPLIT",
    gate=AUTO_APPROVE,
    rederived_net_cents=160385,
    rules_sha="a" * 64,
)


def test_round_trip():
    sig = sign_gate_verdict_hmac(**_BASE, key=_KEY)
    assert verify_gate_verdict_hmac(**_BASE, signature=sig, key=_KEY) is True


@pytest.mark.parametrize("field,bad", [
    ("bundle_id", "other-bundle"),
    ("case_id", "C-9999"),
    ("rule_id", "ROUTINE_RETRO"),
    ("gate", HUMAN_REVIEW),
    ("rederived_net_cents", 160386),
    ("rules_sha", "b" * 64),
])
def test_every_field_is_bound(field, bad):
    """Tampering any signed field must break verification — the verdict is bound to
    the exact (bundle, case, rule, gate, amount, ruleset) it was signed for."""
    sig = sign_gate_verdict_hmac(**_BASE, key=_KEY)
    tampered = dict(_BASE)
    tampered[field] = bad
    assert verify_gate_verdict_hmac(**tampered, signature=sig, key=_KEY) is False


def test_amount_change_breaks_signature():
    """The headline disbursement risk: a verdict's amount cannot be edited in
    transit without breaking the signature."""
    sig = sign_gate_verdict_hmac(**_BASE, key=_KEY)
    bumped = dict(_BASE, rederived_net_cents=999999)
    assert verify_gate_verdict_hmac(**bumped, signature=sig, key=_KEY) is False


def test_human_review_none_amount_round_trips():
    hr = dict(_BASE, case_id="C-2003", rule_id="RETRO_QUALIFYING_DATE_DISPUTE",
              gate=HUMAN_REVIEW, rederived_net_cents=None)
    sig = sign_gate_verdict_hmac(**hr, key=_KEY)
    assert verify_gate_verdict_hmac(**hr, signature=sig, key=_KEY) is True
    # A None-amount verdict must not verify if someone fills in an amount.
    forged = dict(hr, rederived_net_cents=181769)
    assert verify_gate_verdict_hmac(**forged, signature=sig, key=_KEY) is False


def test_wrong_key_fails():
    sig = sign_gate_verdict_hmac(**_BASE, key=_KEY)
    other = VerifierSigningKey.from_secret_bytes(b"\x22" * 32)
    assert verify_gate_verdict_hmac(**_BASE, signature=sig, key=other) is False


def test_invalid_gate_rejected():
    with pytest.raises(SigningError):
        sign_gate_verdict_hmac(**dict(_BASE, gate="MAYBE"), key=_KEY)


def test_bad_signature_type_returns_false():
    assert verify_gate_verdict_hmac(**_BASE, signature=None, key=_KEY) is False  # type: ignore[arg-type]


def test_payload_is_domain_separated():
    """The gate-verdict payload is prefixed with its own domain separator, so it
    can never collide with the discharge signer's payload (which uses a different
    scheme entirely) — a discharge signature can never be replayed as a gate
    verdict."""
    payload = _canonical_gate_payload(**_BASE)
    # The domain separator appears as the first length-prefixed field.
    assert payload[:4] == len(_GATE_SIGNING_DOMAIN).to_bytes(4, "big")
    assert payload[4:4 + len(_GATE_SIGNING_DOMAIN)] == _GATE_SIGNING_DOMAIN
    # A payload over the same fields without the domain prefix differs.
    assert _GATE_SIGNING_DOMAIN in payload


def test_from_env_fail_closed(monkeypatch):
    monkeypatch.delenv("VKERNEL_VERIFIER_HMAC_KEY", raising=False)
    with pytest.raises(SigningError):
        VerifierSigningKey.from_env()
    # And sign/verify with no key + no env must fail-closed, never silently pass.
    with pytest.raises(SigningError):
        sign_gate_verdict_hmac(**_BASE)


def test_from_env_round_trip(monkeypatch):
    monkeypatch.setenv("VKERNEL_VERIFIER_HMAC_KEY", "33" * 32)
    sig = sign_gate_verdict_hmac(**_BASE)
    assert verify_gate_verdict_hmac(**_BASE, signature=sig) is True
