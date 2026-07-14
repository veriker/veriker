"""tests/test_signing_strict_operands.py — strict-operand regression tests.

Three type-coercion gaps triaged REAL by ChatGPT redteam; each confirmed
collision is asserted to fail closed:

  F2 — _canonical_gate_payload collapses distinct monetary values via int()
       (True/1.0/1.2/"1"/b"1" all encoded to "1"; now SigningError).

  F3 — compute_action_sha non-injective over non-str mapping keys
       ({1:...}/{True:...}/{None:...} keys coerced by json.dumps sort_keys;
       now SigningError before hashing).

  F4 — scalar_epsilon comparator coerces non-numeric JSON claims via float()
       (True/"1"/"1.0" compared equal to 1.0; now (False, reason)).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from audit_bundle.gate.verdict_signing import (
    AUTO_APPROVE,
    SigningError,
    VerifierSigningKey,
    _canonical_gate_payload,
    compute_action_sha,
    sign_gate_verdict_hmac,
    verify_gate_verdict_hmac,
)
from audit_bundle.plugin import RecomputedValue
from audit_bundle.rederivation import dispatch as D
from audit_bundle.rederivation.comparators import resolve_comparator
from audit_bundle.rederivation.dispatch import run_spec_pinned_dispatch
from audit_bundle.rederivation.spec_binding import SpecAnchor

_KEY = VerifierSigningKey.from_secret_bytes(b"\xab" * 32)

_GATE_BASE = dict(
    bundle_id="test-bundle",
    case_id="C-0001",
    rule_id="RULE-A",
    gate=AUTO_APPROVE,
    rules_sha="c" * 64,
)


# ===========================================================================
# F2 — rederived_net_cents strict-int admission
# ===========================================================================


@pytest.mark.parametrize("bad_amount", [True, 1.0, 1.2, "1", b"1"])
def test_f2_non_int_amounts_raise_signing_error(bad_amount):
    """Each confirmed collision (True/1.0/1.2/"1"/b"1") must raise SigningError
    before the payload is built — the signed amount is never a coerced stand-in."""
    with pytest.raises(SigningError):
        _canonical_gate_payload(**_GATE_BASE, rederived_net_cents=bad_amount)


@pytest.mark.parametrize("bad_amount", [True, 1.0, 1.2, "1", b"1"])
def test_f2_sign_rejects_non_int_amounts(bad_amount):
    """sign_gate_verdict_hmac propagates the SigningError — no token is issued."""
    with pytest.raises(SigningError):
        sign_gate_verdict_hmac(**_GATE_BASE, rederived_net_cents=bad_amount, key=_KEY)


def test_f2_none_amount_round_trips():
    """None (HUMAN_REVIEW, no verifier-blessed amount) still encodes and round-trips."""
    sig = sign_gate_verdict_hmac(**_GATE_BASE, rederived_net_cents=None, key=_KEY)
    assert (
        verify_gate_verdict_hmac(
            **_GATE_BASE, rederived_net_cents=None, signature=sig, key=_KEY
        )
        is True
    )


def test_f2_plain_int_amount_round_trips():
    """A plain int amount encodes and round-trips — positive control."""
    sig = sign_gate_verdict_hmac(**_GATE_BASE, rederived_net_cents=1, key=_KEY)
    assert (
        verify_gate_verdict_hmac(
            **_GATE_BASE, rederived_net_cents=1, signature=sig, key=_KEY
        )
        is True
    )


def test_f2_distinct_amounts_produce_distinct_payloads():
    """int 1 and int 2 produce different payloads — baseline injectivity."""
    p1 = _canonical_gate_payload(**_GATE_BASE, rederived_net_cents=1)
    p2 = _canonical_gate_payload(**_GATE_BASE, rederived_net_cents=2)
    assert p1 != p2


# ===========================================================================
# F3 — compute_action_sha strict mapping-key admission
# ===========================================================================


@pytest.mark.parametrize(
    "bad_args",
    [
        {1: "acct-A"},
        {True: "acct-A"},
        {None: "acct-A"},
        {"outer": {1: "inner"}},  # non-str key at nested depth
        {"outer": [{2: "v"}]},  # non-str key inside a list element
    ],
)
def test_f3_non_str_keys_raise_signing_error(bad_args):
    """Each confirmed collision (int/bool/None key) must raise SigningError before
    hashing — the sha is injective only over all-string-keyed structures."""
    with pytest.raises(SigningError):
        compute_action_sha(tool="t", args=bad_args)


def test_f3_all_str_keys_hash_successfully():
    """An all-string-keyed action hashes without error — positive control."""
    sha = compute_action_sha(tool="t", args={"1": "acct-A", "nested": {"k": "v"}})
    assert len(sha) == 64  # sha256 hex


def test_f3_int_key_sha_never_equals_str_key_sha():
    """Because {1:...} now raises, no sha can ever be produced from it, so it
    cannot collide with the sha from {"1":...}. Assert the str-key sha is
    producible and the int-key path is closed."""
    str_sha = compute_action_sha(tool="t", args={"1": "acct-A"})
    with pytest.raises(SigningError):
        compute_action_sha(tool="t", args={1: "acct-A"})
    # The str_sha exists and is a valid hex digest.
    assert len(str_sha) == 64


def test_f3_bool_key_sha_never_equals_str_key_sha():
    """True → "true" key coercion is now blocked before hashing."""
    compute_action_sha(tool="t", args={"true": "v"})  # str "true" is fine
    with pytest.raises(SigningError):
        compute_action_sha(tool="t", args={True: "v"})  # bool key is not


def test_f3_valid_bool_leaf_value_still_accepted():
    """Bool as a leaf VALUE (not a key) is fine — it serialises unambiguously."""
    sha = compute_action_sha(tool="t", args={"flag": True, "count": 0})
    assert len(sha) == 64


# ===========================================================================
# F4 — scalar_epsilon strict numeric admission (comparator level)
# ===========================================================================


@pytest.mark.parametrize("bad_claimed", [True, "1", "1.0"])
def test_f4_non_numeric_claimed_returns_false(bad_claimed):
    """Each confirmed collision (True/"1"/"1.0") must return (False, reason).
    The comparator contract is 'never raises; returns (bool, str)'."""
    cmp = resolve_comparator("scalar_epsilon")
    ok, detail = cmp(1.0, bad_claimed, {"epsilon": 0.0})
    assert ok is False
    assert "non-numeric operand" in detail
    assert type(bad_claimed).__name__ in detail


@pytest.mark.parametrize("bad_recomputed", [True, "1"])
def test_f4_non_numeric_recomputed_returns_false(bad_recomputed):
    """Non-numeric recomputed operand is symmetric — also rejected."""
    cmp = resolve_comparator("scalar_epsilon")
    ok, detail = cmp(bad_recomputed, 1.0, {"epsilon": 0.0})
    assert ok is False
    assert "non-numeric operand" in detail


def test_f4_float_claimed_passes():
    """float 1.0 as claimed is still accepted — positive control."""
    cmp = resolve_comparator("scalar_epsilon")
    ok, detail = cmp(1.0, 1.0, {"epsilon": 0.0})
    assert ok is True


def test_f4_int_claimed_passes():
    """int 1 as claimed is accepted (int is a numeric JSON type)."""
    cmp = resolve_comparator("scalar_epsilon")
    ok, detail = cmp(1.0, 1, {"epsilon": 0.0})
    assert ok is True


# ===========================================================================
# F4 — dispatch-level: bool/str claimed under scalar_epsilon yields REJECT
# ===========================================================================


class _Manifest:
    def __init__(self, spec_files, outputs):
        self.spec_files = spec_files
        self.outputs = outputs


def _anchored_bundle_scalar_epsilon(tmp_path: Path, outputs):
    bundle = tmp_path / "bundle"
    (bundle / "spec").mkdir(parents=True, exist_ok=True)
    spec = {
        "spec_id": "strict-operands-f4",
        "types": {
            "t1": {
                "primitive_id": "noop-f4",
                "comparator": {"kind": "scalar_epsilon", "params": {"epsilon": 0.0}},
            }
        },
    }
    raw = json.dumps(spec).encode("utf-8")
    (bundle / "spec" / "strict_operands_f4.spec.json").write_bytes(raw)
    anchor = SpecAnchor(allowed={"strict-operands-f4": hashlib.sha256(raw).hexdigest()})
    manifest = _Manifest(spec_files=["strict_operands_f4.spec.json"], outputs=outputs)
    return bundle, manifest, anchor


def _write_claimed(bundle: Path, output_id: str, raw: bytes) -> None:
    out_dir = bundle / "outputs"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{output_id}.json").write_bytes(raw)


def _stub_primitive(value):
    class _P:
        primitive_id = "noop-f4"

        def recompute(self, inputs, pack_section):
            return RecomputedValue(value=value, detail="stub")

    return _P()


@pytest.mark.parametrize(
    "claimed_raw",
    [
        b'{"value": true}',  # bool true -> would have coerced to 1.0
        b'{"value": "1.0"}',  # str "1.0" -> would have coerced to 1.0
        b'{"value": "1"}',  # str "1"   -> would have coerced to 1.0
    ],
)
def test_f4_dispatch_non_numeric_claimed_under_scalar_epsilon_is_rejected(
    tmp_path, monkeypatch, claimed_raw
):
    """At the dispatch level, a non-numeric (bool/str) claimed value under a
    scalar_epsilon comparator must produce a REDERIVATION_MISMATCH (comparator
    returned False), never a spurious GREEN that matches recomputed 1.0."""
    output_id = "v1"
    bundle, manifest, anchor = _anchored_bundle_scalar_epsilon(
        tmp_path, [{"output_id": output_id, "type": "t1"}]
    )
    _write_claimed(bundle, output_id, claimed_raw)
    monkeypatch.setattr(D, "resolve_primitive", lambda _pid: _stub_primitive(1.0))

    failures = run_spec_pinned_dispatch(bundle, manifest, anchor)
    codes = {f.reason_code for f in failures}

    # Must not pass green.
    assert codes, f"expected at least one failure for {claimed_raw!r}; got none"
    # The specific reason code is REDERIVATION_MISMATCH (comparator returned
    # False with a reason string) or COMPARATOR_ERROR (comparator raised —
    # neither is acceptable as GREEN, and both are correct fail-closed outcomes).
    assert codes <= {"REDERIVATION_MISMATCH", "COMPARATOR_ERROR", "NON_FINITE_VALUE"}, (
        codes
    )
