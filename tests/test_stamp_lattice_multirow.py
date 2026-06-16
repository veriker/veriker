"""V14 — multi-row stamp aggregation under signed stamp upgrades (C14 v0.2).

Tests cover the v0.2 surface that v0.1 deferred: handling rows whose
`stamp_observed` has been verifier-upgraded post-discharge. Mirrors the
adversarial surface from the audit-bundle contract
§Stream V14 Adversarial test suite + the additional defenses surfaced by
porting the V16 panel-review BUG 1 (fail-closed) and BUG 2 (cross-bundle /
cross-record replay) lessons into V14.

Adversarial categories:
  1. forge_no_signature           — STAMP_UPGRADE_FORGED
  2. forge_invalid_mac            — STAMP_UPGRADE_FORGED
  3. cross_bundle_replay          — STAMP_UPGRADE_FORGED (bundle_id mismatch)
  4. cross_record_replay          — STAMP_UPGRADE_FORGED (record_idx mismatch)
  5. wrong_key_signed             — STAMP_UPGRADE_FORGED
  6. tier_jump_in_signing         — sign_stamp_upgrade raises SigningError
  7. tier_jump_handcrafted        — STAMP_UPGRADE_FORGED (verify rejects rank)
  8. from_stamp_drift             — STAMP_UPGRADE_FORGED (sig.from_stamp ≠ row.stamp_observed)
  9. discharge_link_broken        — STAMP_UPGRADE_DISCHARGE_LINK_BROKEN
 10. out_of_order_timestamp       — STAMP_UPGRADE_OUT_OF_ORDER
 11. sibling_upgrades_list        — STAMP_UPGRADE_CONFLICT
 12. body_sig_tamper              — STAMP_UPGRADE_FORGED (body to_stamp ≠ sig to_stamp)
 13. fail_closed_no_key           — STAMP_UPGRADE_FORGED (mirror C16 BUG 1)
 14. happy_path_signed_upgrade    — OK; effective stamp == to_stamp
 15. mixed_row_aggregate_min      — OK; aggregate = min over effective stamps
 16. mixed_row_aggregate_roundup  — STAMP_AGGREGATE_ROUNDUP_DETECTED
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from audit_bundle.discharge.verifier_signing import (
    SigningError,
    VerifierSigningKey,
    sign_and_write,
    sign_stamp_upgrade,
    verify_stamp_upgrade_signature,
)
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck


def _sha(label: str) -> str:
    """Stable 64-char hex SHA for test fixtures (BUG 6 fix from 2026-05-03
    panel review now enforces hex-format on discharge_obligation_sha)."""
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


_KEY_BYTES = b"v14-test-secret-32bytes-padding!"  # 32 bytes
_KEY = VerifierSigningKey(verifier_id="v-kernel-test", secret=_KEY_BYTES)
_OTHER_KEY = VerifierSigningKey(
    verifier_id="v-kernel-test", secret=b"alternate-secret-32bytes-padding"
)
_FOREIGN_VERIFIER_KEY = VerifierSigningKey(verifier_id="attacker", secret=_KEY_BYTES)

_BUNDLE_ID = "bundle-v14-test-001"
_OTHER_BUNDLE_ID = "bundle-v14-test-OTHER"
_BUNDLE_CREATED_AT = "2026-05-03T12:00:00Z"


# ---------------------------------------------------------------------------
# Manifest stub
# ---------------------------------------------------------------------------


class _Manifest:
    def __init__(
        self,
        dispatch_records=(),
        aggregate_stamp=None,
        bundle_id=_BUNDLE_ID,
        created_at=_BUNDLE_CREATED_AT,
    ):
        self.dispatch_records = dispatch_records
        self.aggregate_stamp = aggregate_stamp
        self.bundle_id = bundle_id
        self.created_at = created_at


def _record(
    stamp_observed,
    *,
    with_proof_obligation_sha=None,
    proof_discharge_status="not-attempted",
    proof_signed=False,
    record_idx=0,
):
    """Build a minimal dispatch_record for V14 tests.

    `with_proof_obligation_sha` — when non-None, attaches a proof field with
    that SHA. Required for upgrade_reason='discharged' linkage tests.
    `proof_discharge_status` — what the proof.discharge_status should claim.
    `proof_signed` — when True, also attaches a V16 verifier_signature
    matching the discharge_status.
    `record_idx` — the row position the record will land at in the
    manifest (Cumulative-pre-soak Patch 6 follow-up, 2026-05-04: V16
    signatures must bind to authoritative record_idx; the C14 plugin
    re-verifies under the loop's actual idx, so the fixture must sign
    at the same idx).
    """
    rec = {
        "schema_version": "0.1",
        "op": {"kind": "COMPUTE", "name": "score"},
        "inputs": [],
        "outputs": [
            {"name": "r", "type": {"base": "Int", "refine": "(>= r 0)"}},
        ],
        "effect": {},
        "locale": "en-US",
        "predicates": [],
        "stamp_declared": stamp_observed or "UNVERIFIED",
        "stamp_observed": stamp_observed,
    }
    if with_proof_obligation_sha is not None:
        rec["proof"] = {
            "kind": "smt-z3",
            "obligation_uri": "proofs/main.smt2",
            "obligation_sha": with_proof_obligation_sha,
            "discharge_status": proof_discharge_status,
            "recheck_context": {"r": 0, "__logic__": "QF_LIA"},
        }
        if proof_signed:
            rec = sign_and_write(
                rec,
                key=_KEY,
                discharge_status=proof_discharge_status,
                z3_status=proof_discharge_status,
                bundle_id=_BUNDLE_ID,
                record_idx=record_idx,
                refine_text="(>= r 0)",
                recheck_context={"r": 0, "__logic__": "QF_LIA"},
                timestamp_utc="2026-05-03T11:00:00Z",
            )
    return rec


def _signed_upgrade(
    record,
    *,
    from_stamp,
    to_stamp,
    record_idx=0,
    bundle_id=_BUNDLE_ID,
    key=_KEY,
    upgrade_reason="discharged",
    discharge_obligation_sha=None,
    timestamp_utc="2026-05-03T11:30:00Z",
):
    """Apply a real verifier signature; returns the upgraded record."""
    if discharge_obligation_sha is None and upgrade_reason == "discharged":
        proof = record.get("proof") or {}
        discharge_obligation_sha = proof.get("obligation_sha", "")
    if upgrade_reason != "discharged":
        discharge_obligation_sha = ""
    return sign_stamp_upgrade(
        record,
        key=key,
        from_stamp=from_stamp,
        to_stamp=to_stamp,
        upgrade_reason=upgrade_reason,
        discharge_obligation_sha=discharge_obligation_sha,
        bundle_id=bundle_id,
        record_idx=record_idx,
        timestamp_utc=timestamp_utc,
    )


# ===========================================================================
# Category 1 — forge_no_signature
# ===========================================================================


def test_forge_no_signature_fails(tmp_path):
    rec = _record("INTERNAL_BENCHMARK")
    rec["stamp_upgrade"] = {
        "from_stamp": "INTERNAL_BENCHMARK",
        "to_stamp": "INTERNAL_SOURCE",
        "upgrade_reason": "discharged",
        "discharge_obligation_sha": "a" * 64,
        # No verifier_signature.
    }
    manifest = _Manifest(dispatch_records=(rec,))
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_UPGRADE_FORGED"
    assert "record[0]" in result.detail


# ===========================================================================
# Category 2 — forge_invalid_mac
# ===========================================================================


def test_forge_invalid_mac_fails(tmp_path):
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha="a" * 64,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec["stamp_upgrade"] = {
        "from_stamp": "INTERNAL_BENCHMARK",
        "to_stamp": "INTERNAL_SOURCE",
        "upgrade_reason": "discharged",
        "discharge_obligation_sha": "a" * 64,
        "verifier_signature": {
            "algorithm": "hmac-sha256",
            "verifier_id": _KEY.verifier_id,
            "timestamp_utc": "2026-05-03T11:30:00Z",
            "bundle_id": _BUNDLE_ID,
            "record_idx": 0,
            "from_stamp": "INTERNAL_BENCHMARK",
            "to_stamp": "INTERNAL_SOURCE",
            "upgrade_reason": "discharged",
            "discharge_obligation_sha": "a" * 64,
            "mac": "0" * 64,  # wrong HMAC
        },
    }
    manifest = _Manifest(dispatch_records=(rec,))
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_UPGRADE_FORGED"


# ===========================================================================
# Category 3 — cross_bundle_replay
# ===========================================================================


def test_cross_bundle_replay_fails(tmp_path):
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha="b" * 64,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    # Sig is for bundle A; verifier sees bundle B
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        bundle_id=_OTHER_BUNDLE_ID,
        discharge_obligation_sha="b" * 64,
    )
    manifest = _Manifest(
        dispatch_records=(rec,),
        bundle_id=_BUNDLE_ID,  # ≠ _OTHER_BUNDLE_ID in sig
    )
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_UPGRADE_FORGED"


# ===========================================================================
# Category 4 — cross_record_replay
# ===========================================================================


def test_cross_record_replay_fails(tmp_path):
    # Sig is for record_idx=0; copy to record_idx=1.
    base = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha="c" * 64,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    upgraded_at_zero = _signed_upgrade(
        base,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        record_idx=0,
        discharge_obligation_sha="c" * 64,
    )
    # Manually move the sig to a different row
    other = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha="c" * 64,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    other["stamp_upgrade"] = upgraded_at_zero["stamp_upgrade"]
    manifest = _Manifest(dispatch_records=(base, other))  # other is at idx=1
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_UPGRADE_FORGED"


# ===========================================================================
# Category 5 — wrong_key_signed
# ===========================================================================


def test_wrong_key_signed_fails(tmp_path):
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha="d" * 64,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        key=_OTHER_KEY,  # signed by different key
        discharge_obligation_sha="d" * 64,
    )
    manifest = _Manifest(dispatch_records=(rec,))
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_UPGRADE_FORGED"


def test_foreign_verifier_id_fails(tmp_path):
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha="d" * 64,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        key=_FOREIGN_VERIFIER_KEY,
        discharge_obligation_sha="d" * 64,
    )
    manifest = _Manifest(dispatch_records=(rec,))
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_UPGRADE_FORGED"


# ===========================================================================
# Category 6 — tier_jump_in_signing (sign_stamp_upgrade raises)
# ===========================================================================


def test_tier_jump_signing_raises():
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha="e" * 64,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    with pytest.raises(SigningError, match="tier-transition"):
        sign_stamp_upgrade(
            rec,
            key=_KEY,
            from_stamp="INTERNAL_BENCHMARK",
            to_stamp="CONFIRMED_EXTERNAL",  # 3 tiers above
            upgrade_reason="discharged",
            discharge_obligation_sha="e" * 64,
            bundle_id=_BUNDLE_ID,
            record_idx=0,
        )


def test_downgrade_signing_raises():
    rec = _record(
        "INTERNAL_SOURCE",
        with_proof_obligation_sha="e" * 64,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    with pytest.raises(SigningError, match="tier-transition"):
        sign_stamp_upgrade(
            rec,
            key=_KEY,
            from_stamp="INTERNAL_SOURCE",
            to_stamp="INTERNAL_BENCHMARK",  # downgrade
            upgrade_reason="discharged",
            discharge_obligation_sha="e" * 64,
            bundle_id=_BUNDLE_ID,
        )


# ===========================================================================
# Category 7 — tier_jump_handcrafted (hostile dispatcher constructs upgrade
# directly, bypassing sign_stamp_upgrade's tier check; verify_signature
# must catch it via the rank rule)
# ===========================================================================


def test_tier_jump_handcrafted_signature_fails(tmp_path):
    """A hostile dispatcher who has the verifier key (or guesses it) cannot
    forge a multi-tier upgrade because verify_signature recomputes the rank
    rule and rejects."""
    # Build a real signed upgrade for a one-tier transition first.
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha="f" * 64,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    legitimate = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        discharge_obligation_sha="f" * 64,
    )
    # Now mutate the body's to_stamp without re-signing → sig MAC fails
    # because body-vs-sig consistency check fires before MAC, but rank
    # rule on tampered sig would also fire if attacker forged sig too.
    legitimate["stamp_upgrade"]["to_stamp"] = "CONFIRMED_EXTERNAL"
    manifest = _Manifest(dispatch_records=(legitimate,))
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_UPGRADE_FORGED"


# ===========================================================================
# Category 8 — from_stamp_drift
# ===========================================================================


def test_from_stamp_drift_fails(tmp_path):
    """Sig signed with from_stamp=INTERNAL_BENCHMARK; row's stamp_observed
    has been tampered to TARGET. Plugin must reject — the verifier signed
    a transition based on a different starting point."""
    sha_g = _sha("from-stamp-drift")
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=sha_g,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        discharge_obligation_sha=sha_g,
    )
    # Tamper the row's stamp_observed AFTER signing
    rec["stamp_observed"] = "TARGET"
    manifest = _Manifest(dispatch_records=(rec,))
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_UPGRADE_FORGED"
    assert "from_stamp" in result.detail.lower() or "drift" in result.detail.lower()


# ===========================================================================
# Category 9 — discharge_link_broken
# ===========================================================================


def test_discharge_link_no_proof_fails(tmp_path):
    """upgrade_reason='discharged' on a row with no proof field — sign raises."""
    rec = _record("INTERNAL_BENCHMARK")  # no proof
    with pytest.raises(SigningError, match="proof"):
        sign_stamp_upgrade(
            rec,
            key=_KEY,
            from_stamp="INTERNAL_BENCHMARK",
            to_stamp="INTERNAL_SOURCE",
            upgrade_reason="discharged",
            discharge_obligation_sha=_sha("h-no-proof"),
            bundle_id=_BUNDLE_ID,
        )


def test_discharge_link_status_not_discharged_signing_raises():
    """BUG 7 fix (Sonnet #1a 2026-05-03 panel review): upgrade_reason='discharged'
    against a proof in any state other than 'discharged' must fail at signing
    time, not just at plugin verification. The signer's docstring promised
    a stronger precondition than the prior code enforced."""
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=_sha("i-failed-status"),
        proof_discharge_status="failed",
        proof_signed=True,
    )
    with pytest.raises(SigningError, match="discharge_status"):
        sign_stamp_upgrade(
            rec,
            key=_KEY,
            from_stamp="INTERNAL_BENCHMARK",
            to_stamp="INTERNAL_SOURCE",
            upgrade_reason="discharged",
            discharge_obligation_sha=_sha("i-failed-status"),
            bundle_id=_BUNDLE_ID,
        )


def test_discharge_link_status_not_discharged_plugin_rejects(tmp_path):
    """Defense-in-depth pairing with the signing-time check: even if the
    signer can be bypassed (e.g. attacker controls the verifier key and
    skips sign_stamp_upgrade entirely), the C14 plugin re-runs V16's HMAC
    and rejects when the underlying proof.discharge_status mismatches.
    The reproducer hand-forges a stamp_upgrade that claims discharged but
    attaches to a proof in 'failed' state."""
    sha_i = _sha("i-failed-plugin-check")
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=sha_i,
        proof_discharge_status="failed",
        proof_signed=True,
    )
    # Manually construct an upgrade dict that bypasses sign_stamp_upgrade.
    # We also forge a sig dict — the plugin will reject on V16 MAC re-verify
    # OR on discharge_status mismatch (whichever fires first).
    rec["stamp_upgrade"] = {
        "from_stamp": "INTERNAL_BENCHMARK",
        "to_stamp": "INTERNAL_SOURCE",
        "upgrade_reason": "discharged",
        "discharge_obligation_sha": sha_i,
        "verifier_signature": {
            "algorithm": "hmac-sha256",
            "verifier_id": _KEY.verifier_id,
            "timestamp_utc": "2026-05-03T11:30:00Z",
            "bundle_id": _BUNDLE_ID,
            "record_idx": 0,
            "from_stamp": "INTERNAL_BENCHMARK",
            "to_stamp": "INTERNAL_SOURCE",
            "upgrade_reason": "discharged",
            "discharge_obligation_sha": sha_i,
            "mac": "0" * 64,  # forged MAC — V14 will catch on its own MAC check
        },
    }
    manifest = _Manifest(dispatch_records=(rec,))
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False
    # The forged V14 MAC fires first → STAMP_UPGRADE_FORGED.
    # That's correct: the plugin rejects before reaching the discharge-link
    # check. We confirm SOMETHING in the v0.2 surface caught it.
    assert result.reason_code in {
        "STAMP_UPGRADE_FORGED",
        "STAMP_UPGRADE_DISCHARGE_LINK_BROKEN",
    }


def test_discharge_link_proof_unsigned_signing_raises():
    """BUG 7 fix: signer refuses to attach an upgrade to a proof with no
    V16 signature, because such a proof is itself forged at the C16 level."""
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=_sha("j-unsigned"),
        proof_discharge_status="discharged",
        proof_signed=False,
    )  # NO V16 sig
    with pytest.raises(SigningError, match="V16 verifier_signature"):
        sign_stamp_upgrade(
            rec,
            key=_KEY,
            from_stamp="INTERNAL_BENCHMARK",
            to_stamp="INTERNAL_SOURCE",
            upgrade_reason="discharged",
            discharge_obligation_sha=_sha("j-unsigned"),
            bundle_id=_BUNDLE_ID,
        )


def test_discharge_link_obligation_sha_mismatch_fails():
    """sign_stamp_upgrade raises when discharge_obligation_sha != proof.obligation_sha."""
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=_sha("k-real"),
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    with pytest.raises(SigningError, match="obligation_sha"):
        sign_stamp_upgrade(
            rec,
            key=_KEY,
            from_stamp="INTERNAL_BENCHMARK",
            to_stamp="INTERNAL_SOURCE",
            upgrade_reason="discharged",
            discharge_obligation_sha=_sha("k-wrong"),  # different SHA
            bundle_id=_BUNDLE_ID,
        )


def test_discharge_obligation_sha_format_invalid_signing_raises():
    """BUG 6 fix (Opus O2 2026-05-03 panel review): discharge_obligation_sha
    must be a 64-char hex SHA-256. Non-hex strings rejected at signing time.

    Cumulative-pre-soak Patch 8 follow-up (2026-05-04): sign_and_write now
    enforces the same shape check on proof.obligation_sha (the source of
    truth that sign_stamp_upgrade equality-checks against). The pre-Patch
    fixture built a malformed-SHA proof via sign_and_write, then hijacked
    the field; post-Patch we sign with a valid SHA, then hijack to test
    that sign_stamp_upgrade still catches the resulting body-vs-arg
    mismatch via the format regex. Both layers (sign_and_write +
    sign_stamp_upgrade) now reject non-hex obligation_sha values."""
    rec_clean = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=_sha("k-format-test"),
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    # Hijack proof.obligation_sha to a non-hex value so the equality
    # check would have passed but the format check now fires.
    rec_clean["proof"]["obligation_sha"] = "not-a-real-sha-just-a-string"
    with pytest.raises(SigningError, match="hex"):
        sign_stamp_upgrade(
            rec_clean,
            key=_KEY,
            from_stamp="INTERNAL_BENCHMARK",
            to_stamp="INTERNAL_SOURCE",
            upgrade_reason="discharged",
            discharge_obligation_sha="not-a-real-sha-just-a-string",
            bundle_id=_BUNDLE_ID,
        )

    # Cumulative-pre-soak Patch 8 (Gate 1, 2026-05-04): also confirm
    # the equivalent shape check fires at sign_and_write itself, so the
    # malformed SHA never reaches the bundle even when no upgrade is
    # ever attached. Pre-Patch this check was absent and the malformed
    # value flowed through silently until V14 noticed.
    rec_with_bad_sha = {
        "proof": {
            "kind": "smt-z3",
            "obligation_uri": "proofs/main.smt2",
            "obligation_sha": "not-a-real-sha-just-a-string",
            "discharge_status": "discharged",
            "recheck_context": {"r": 0, "__logic__": "QF_LIA"},
        },
        "outputs": [{"type": {"refine": "(>= r 0)"}}],
    }
    with pytest.raises(SigningError, match="64-character hex"):
        sign_and_write(
            rec_with_bad_sha,
            key=_KEY,
            discharge_status="discharged",
            z3_status="discharged",
            bundle_id=_BUNDLE_ID,
        )


# ===========================================================================
# Category 10 — out_of_order_timestamp
# ===========================================================================


def test_out_of_order_timestamp_fails(tmp_path):
    """Sig signed at 2026-05-03T13:00 > bundle.created_at 2026-05-03T12:00."""
    sha_l = _sha("l-timestamp")
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=sha_l,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        discharge_obligation_sha=sha_l,
        timestamp_utc="2026-05-03T13:00:00Z",
    )
    manifest = _Manifest(dispatch_records=(rec,), created_at="2026-05-03T12:00:00Z")
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_UPGRADE_OUT_OF_ORDER"


def test_out_of_order_timestamp_fractional_seconds_fails(tmp_path):
    """BUG 2 fix (Sonnet #8 / Opus #2 2026-05-03 panel review): a sig
    timestamp 1ms LATER than bundle.created_at, expressed with fractional
    seconds, must be rejected. Lex compare would silently admit this
    because '.' (0x2E) < 'Z' (0x5A) in ASCII."""
    sha_l2 = _sha("l-fractional")
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=sha_l2,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        discharge_obligation_sha=sha_l2,
        timestamp_utc="2026-05-03T12:00:00.001Z",
    )
    manifest = _Manifest(dispatch_records=(rec,), created_at="2026-05-03T12:00:00Z")
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_UPGRADE_OUT_OF_ORDER"


def test_out_of_order_timestamp_tz_offset_fails(tmp_path):
    """BUG 2 fix: sig timestamp expressed in non-UTC -05:00 offset.

    Pre-Gate-3a-P2 (2026-05-19): the verifier accepted the sig (HMAC
    passes — the literal string is bound), then Defense-7's
    `_parse_iso8601_to_aware` returned None on the non-UTC offset and
    the OOO check fired STAMP_UPGRADE_OUT_OF_ORDER.

    Post-P2 (this commit): `verify_stamp_upgrade_signature` now applies
    the same ISO-8601-UTC grammar check that V15 already used (Sonnet 4.6
    §C2, 2026-05-19); the non-UTC offset is rejected BEFORE the HMAC,
    surfacing as STAMP_UPGRADE_FORGED at the C14 plugin layer. Same
    end-to-end rejection; the layer shifted upstream."""
    sha_l3 = _sha("l-tz-offset")
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=sha_l3,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        discharge_obligation_sha=sha_l3,
        timestamp_utc="2026-05-03T19:30:00-05:00",
    )
    manifest = _Manifest(dispatch_records=(rec,), created_at="2026-05-03T23:30:00Z")
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_UPGRADE_FORGED"


def test_out_of_order_timestamp_naive_rejected(tmp_path):
    """BUG 2 fix: naive (TZ-less) timestamp.

    Pre-Gate-3a-P2 (2026-05-19): sig was admitted, Defense-7 parsed the
    naive string to None and tripped STAMP_UPGRADE_FORGED at the OOO
    check with a "timestamp"/"parseable" detail string.

    Post-P2 (this commit): `verify_stamp_upgrade_signature` rejects on
    the ISO-8601-UTC grammar check before HMAC; the detail string is
    the generic HMAC-verification message from the C14 plugin's verify
    wrapper. Same reason_code (STAMP_UPGRADE_FORGED); the rejection
    surface shifted from Defense 7 to verifier_signing."""
    sha_l4 = _sha("l-naive")
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=sha_l4,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        discharge_obligation_sha=sha_l4,
        timestamp_utc="2026-05-03T11:30:00",
    )  # no TZ
    manifest = _Manifest(dispatch_records=(rec,), created_at="2026-05-03T12:00:00Z")
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_UPGRADE_FORGED"


# ===========================================================================
# Category 11 — sibling_upgrades_list (CONFLICT)
# ===========================================================================


def test_sibling_upgrades_list_fails(tmp_path):
    """A hostile dispatcher attaches both `stamp_upgrade` (signed) and a
    sibling `stamp_upgrades` plural list (unverified) — the verifier cannot
    arbitrate which is canonical and must reject."""
    sha_m = _sha("m-sibling-list")
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=sha_m,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        discharge_obligation_sha=sha_m,
    )
    rec["stamp_upgrades"] = [
        {"from_stamp": "INTERNAL_BENCHMARK", "to_stamp": "WEB_SOURCE"}
    ]
    manifest = _Manifest(dispatch_records=(rec,))
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_UPGRADE_CONFLICT"


@pytest.mark.parametrize(
    "rogue_key",
    [
        "stamp_upgrade_v2",
        "stampUpgrade",
        "STAMP_UPGRADE",
        "_stamp_upgrade",
        "stamp_upgrade_pending",
        "stamp_upgrade_99",
    ],
)
def test_sibling_upgrade_namespace_collision_fails(tmp_path, rogue_key):
    """BUG 4 fix (Sonnet #9 / Opus #10 panel review 2026-05-03): the
    sibling-conflict guard now treats the entire `stamp_upgrade` (and
    `stampupgrade` casefolded) namespace as canonical-only. Any key
    whose case-folded form starts with that prefix and isn't the
    canonical singular is rejected."""
    sha_m2 = _sha(f"m2-{rogue_key}")
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=sha_m2,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        discharge_obligation_sha=sha_m2,
    )
    rec[rogue_key] = {"from_stamp": "INTERNAL_BENCHMARK", "to_stamp": "WEB_SOURCE"}
    manifest = _Manifest(dispatch_records=(rec,))
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False, f"rogue key {rogue_key!r} should have been caught"
    assert result.reason_code == "STAMP_UPGRADE_CONFLICT"


# ===========================================================================
# Category 12 — body_sig_tamper
# ===========================================================================


def test_body_sig_tamper_to_stamp_fails(tmp_path):
    sha_n = _sha("n-body-tamper")
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=sha_n,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        discharge_obligation_sha=sha_n,
    )
    # Tamper body to_stamp (sig still says INTERNAL_SOURCE)
    rec["stamp_upgrade"]["to_stamp"] = "WEB_SOURCE"
    manifest = _Manifest(dispatch_records=(rec,))
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_UPGRADE_FORGED"


# ===========================================================================
# Category 13 — fail_closed_no_key (mirror C16 BUG 1)
# ===========================================================================


def test_fail_closed_no_key_signed_upgrade_rejected(tmp_path):
    sha_o = _sha("o-fail-closed")
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=sha_o,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        discharge_obligation_sha=sha_o,
    )
    manifest = _Manifest(dispatch_records=(rec,))
    plugin = StampLatticeCheck()  # NO recheck_key
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_UPGRADE_FORGED"
    assert (
        "recheck_key" in result.detail.lower()
        or "production deployments" in result.detail.lower()
        or "fail" in result.detail.lower()
    )


# ===========================================================================
# Category 14 — happy_path_signed_upgrade
# ===========================================================================


def test_happy_path_signed_upgrade_passes(tmp_path):
    sha_p = _sha("p-happy-path")
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=sha_p,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        discharge_obligation_sha=sha_p,
    )
    manifest = _Manifest(dispatch_records=(rec,), aggregate_stamp="INTERNAL_SOURCE")
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is True, result.detail
    assert result.reason_code == "PASS"
    assert "1 upgrade" in result.detail or "upgrade" in result.detail


def test_happy_path_predicate_satisfied_passes(tmp_path):
    rec = _record("COMPOSED_HYPOTHESIS")
    rec = sign_stamp_upgrade(
        rec,
        key=_KEY,
        from_stamp="COMPOSED_HYPOTHESIS",
        to_stamp="TARGET",
        upgrade_reason="predicate_satisfied",
        discharge_obligation_sha="",  # empty for non-discharged
        bundle_id=_BUNDLE_ID,
        record_idx=0,
        timestamp_utc="2026-05-03T11:30:00Z",
    )
    manifest = _Manifest(dispatch_records=(rec,), aggregate_stamp="TARGET")
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is True, result.detail


# ===========================================================================
# Category 15 — mixed_row_aggregate_min
# ===========================================================================


def test_mixed_row_aggregate_min(tmp_path):
    """3 unupgraded INTERNAL_BENCHMARK + 2 upgraded INTERNAL_SOURCE.
    Aggregate must be min over effective stamps = INTERNAL_BENCHMARK."""
    unupgraded = [_record("INTERNAL_BENCHMARK") for _ in range(3)]
    upgraded = []
    for i in range(2):
        rec = _record(
            "INTERNAL_BENCHMARK",
            with_proof_obligation_sha=str(i) * 64,
            proof_discharge_status="discharged",
            proof_signed=True,
            record_idx=3 + i,
        )
        rec = _signed_upgrade(
            rec,
            from_stamp="INTERNAL_BENCHMARK",
            to_stamp="INTERNAL_SOURCE",
            record_idx=3 + i,
            discharge_obligation_sha=str(i) * 64,
        )
        upgraded.append(rec)
    records = tuple(unupgraded + upgraded)
    manifest = _Manifest(dispatch_records=records, aggregate_stamp="INTERNAL_BENCHMARK")
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is True, result.detail
    assert "5 records" in result.detail
    assert "2 upgrade" in result.detail or "2 verifier-signed" in result.detail


def test_all_rows_upgraded_aggregate_internal_source(tmp_path):
    """5 rows, all upgraded INTERNAL_BENCHMARK → INTERNAL_SOURCE.
    Aggregate = INTERNAL_SOURCE (min over all effective stamps)."""
    records = []
    for i in range(5):
        rec = _record(
            "INTERNAL_BENCHMARK",
            with_proof_obligation_sha=("a" + str(i)) * 32,
            proof_discharge_status="discharged",
            proof_signed=True,
            record_idx=i,
        )
        rec = _signed_upgrade(
            rec,
            from_stamp="INTERNAL_BENCHMARK",
            to_stamp="INTERNAL_SOURCE",
            record_idx=i,
            discharge_obligation_sha=("a" + str(i)) * 32,
        )
        records.append(rec)
    manifest = _Manifest(
        dispatch_records=tuple(records), aggregate_stamp="INTERNAL_SOURCE"
    )
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is True, result.detail


# ===========================================================================
# Category 16 — mixed_row_aggregate_roundup (existing v0.1 invariant
# extended to effective stamps)
# ===========================================================================


def test_mixed_row_aggregate_roundup_fails(tmp_path):
    """3 unupgraded INTERNAL_BENCHMARK + 2 upgraded INTERNAL_SOURCE.
    Bundle claims aggregate_stamp=INTERNAL_SOURCE — roundup above effective
    min INTERNAL_BENCHMARK; rejected."""
    unupgraded = [_record("INTERNAL_BENCHMARK") for _ in range(3)]
    upgraded = []
    for i in range(2):
        rec = _record(
            "INTERNAL_BENCHMARK",
            with_proof_obligation_sha=("c" + str(i)) * 32,
            proof_discharge_status="discharged",
            proof_signed=True,
            record_idx=3 + i,
        )
        rec = _signed_upgrade(
            rec,
            from_stamp="INTERNAL_BENCHMARK",
            to_stamp="INTERNAL_SOURCE",
            record_idx=3 + i,
            discharge_obligation_sha=("c" + str(i)) * 32,
        )
        upgraded.append(rec)
    records = tuple(unupgraded + upgraded)
    manifest = _Manifest(
        dispatch_records=records, aggregate_stamp="INTERNAL_SOURCE"
    )  # roundup
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_AGGREGATE_ROUNDUP_DETECTED"


# ===========================================================================
# Panel-review BUG regressions (2026-05-03) — coverage gaps from earlier
# fixes that landed without explicit tests.
# ===========================================================================


def test_bug3_plugin_rejects_empty_manifest_bundle_id(tmp_path):
    """BUG 3 plugin-side: when the manifest's bundle_id is missing or empty,
    the plugin must fail-closed because the cross-bundle replay defense
    cannot operate without an authoritative binding from the manifest."""
    sha_b3 = _sha("bug3-empty-bundle-id")
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=sha_b3,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        discharge_obligation_sha=sha_b3,
    )
    manifest = _Manifest(dispatch_records=(rec,), bundle_id="")
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_UPGRADE_FORGED"
    assert "bundle_id" in result.detail


def test_bug3_verify_helper_requires_caller_bundle_id():
    """BUG 3 helper-side: verify_stamp_upgrade_signature must reject when
    bundle_id is None / empty / not a string. The prior fallback to
    sig-self-reported bundle_id was the C16 BUG-2 confused-deputy pattern."""
    sha_b3h = _sha("bug3-helper-bundle-id")
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=sha_b3h,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        discharge_obligation_sha=sha_b3h,
    )
    # Sanity: with the right bundle_id + record_idx, it verifies.
    assert (
        verify_stamp_upgrade_signature(
            rec, key=_KEY, bundle_id=_BUNDLE_ID, record_idx=0
        )
        is True
    )
    # Now the BUG 3 cases:
    assert (
        verify_stamp_upgrade_signature(rec, key=_KEY, bundle_id="", record_idx=0)
        is False
    )
    # Mismatched authoritative bundle_id rejects the sig (sig says
    # _BUNDLE_ID; caller authoritatively says something else).
    assert (
        verify_stamp_upgrade_signature(
            rec, key=_KEY, bundle_id=_OTHER_BUNDLE_ID, record_idx=0
        )
        is False
    )


def test_bug5_domain_separation_v14_payload_distinct_from_v16():
    """BUG 5 (Opus #6 panel review 2026-05-03): the V14 stamp-upgrade HMAC
    payload carries a literal `_kind="stamp_upgrade.v0.2"` field. A V14
    sig MUST NOT verify against an attacker-crafted payload whose canonical
    bytes match a V16 discharge_status payload (cross-protocol forgery).

    We verify the tag is present in the canonical payload by inspecting the
    builder output directly: changing `_kind` away from `stamp_upgrade.v0.2`
    must produce a different MAC. If the field were absent or non-load-
    bearing, both signatures would be identical."""
    from audit_bundle.discharge.verifier_signing import (
        _STAMP_UPGRADE_PAYLOAD_KIND,
        _build_stamp_upgrade_payload,
    )
    import hmac, hashlib

    # Real V14 payload bytes
    real = _build_stamp_upgrade_payload(
        bundle_id=_BUNDLE_ID,
        record_idx=0,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        upgrade_reason="discharged",
        discharge_obligation_sha=_sha("bug5-real"),
        verifier_id=_KEY.verifier_id,
        timestamp_utc="2026-05-03T11:30:00Z",
    )
    real_mac = hmac.new(_KEY_BYTES, real, hashlib.sha256).hexdigest()
    # The real bytes MUST contain the domain-separation tag literal.
    # Canonical-bytes use separators=(',',':') so no spaces appear.
    assert _STAMP_UPGRADE_PAYLOAD_KIND.encode() in real
    assert b'"_kind":"stamp_upgrade.v0.2"' in real
    # An attacker-crafted equivalent without the tag must produce a
    # different MAC under the same key.
    attacker_payload = real.replace(b'"_kind":"stamp_upgrade.v0.2",', b"")
    assert attacker_payload != real, (
        "replace failed — tag literal not found in canonical bytes"
    )
    attacker_mac = hmac.new(_KEY_BYTES, attacker_payload, hashlib.sha256).hexdigest()
    assert real_mac != attacker_mac


def test_bug8_sign_rejects_bool_record_idx():
    """BUG 8: isinstance(True, int) is True in Python. record_idx=True
    must be rejected at signing time (would otherwise silently sign for
    record_idx=1 since True == 1)."""
    sha_b8 = _sha("bug8-bool-sign")
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=sha_b8,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    with pytest.raises(SigningError, match="bool"):
        sign_stamp_upgrade(
            rec,
            key=_KEY,
            from_stamp="INTERNAL_BENCHMARK",
            to_stamp="INTERNAL_SOURCE",
            upgrade_reason="discharged",
            discharge_obligation_sha=sha_b8,
            bundle_id=_BUNDLE_ID,
            record_idx=True,  # bool subclass of int
        )


def test_bug8_verify_rejects_bool_record_idx():
    """BUG 8 helper-side: verify_stamp_upgrade_signature must reject
    record_idx=True even though isinstance(True, int) is True."""
    sha_b8v = _sha("bug8-bool-verify")
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=sha_b8v,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        discharge_obligation_sha=sha_b8v,
        record_idx=1,
    )
    # Sanity: with int record_idx=1 it verifies.
    assert (
        verify_stamp_upgrade_signature(
            rec, key=_KEY, bundle_id=_BUNDLE_ID, record_idx=1
        )
        is True
    )
    # BUG 8: True (bool) is rejected even though True == 1.
    assert (
        verify_stamp_upgrade_signature(
            rec, key=_KEY, bundle_id=_BUNDLE_ID, record_idx=True
        )
        is False
    )


# ===========================================================================
# v0.1 backward-compat — rows without stamp_upgrade still verify cleanly
# ===========================================================================


def test_v0_1_records_no_upgrade_passes(tmp_path):
    """Pre-v0.2 bundles (no stamp_upgrade fields) verify exactly as v0.1."""
    rec = _record("INTERNAL_BENCHMARK")
    manifest = _Manifest(dispatch_records=(rec,), aggregate_stamp="INTERNAL_BENCHMARK")
    plugin = StampLatticeCheck()  # No key needed since no upgrade
    result = plugin.check(tmp_path, manifest)
    assert result.ok is True


def test_v0_1_records_no_upgrade_no_key_passes(tmp_path):
    """A plugin without a recheck_key verifies un-upgraded bundles."""
    records = (
        _record("CONFIRMED_EXTERNAL"),
        _record("WEB_SOURCE"),
        _record("INTERNAL_SOURCE"),
    )
    manifest = _Manifest(dispatch_records=records, aggregate_stamp="INTERNAL_SOURCE")
    plugin = StampLatticeCheck()
    result = plugin.check(tmp_path, manifest)
    assert result.ok is True


# ===========================================================================
# Tribunal panel 2026-05-03 — BUGs 1-6 regressions
# ===========================================================================
# These tests cover the 6 BUGs surfaced by the 2026-05-03 tribunal review
# of stamp_lattice.py (default panel: Gemini 2.5 Pro + GPT-5 + Llama-3.3
# fallback). Every fix gets at least one test that would have caught the
# bug under the prior implementation.


# --- BUG 1 — round-down min-rule + invalid aggregate -----------------------


def test_bug1_min_rule_round_down_rejected(tmp_path):
    """BUG 1 (HIGH, GPT-5): the contract requires aggregate_stamp == min(
    effective per row). Prior code only rejected aggregate > min ("round-up").
    A bundle declaring aggregate_stamp lower than per-row min over-promises
    on the weakest row and silently passed. New STAMP_AGGREGATE_ROUNDDOWN
    reason code fires for any aggregate strictly below per-row min."""
    records = (
        _record("INTERNAL_SOURCE"),
        _record("WEB_SOURCE"),
    )
    # Per-row min = INTERNAL_SOURCE; declare aggregate=UNVERIFIED (round-down).
    manifest = _Manifest(dispatch_records=records, aggregate_stamp="UNVERIFIED")
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_AGGREGATE_ROUNDDOWN_DETECTED"
    assert "INTERNAL_SOURCE" in result.detail
    assert "UNVERIFIED" in result.detail


def test_bug1_aggregate_out_of_enum_rejected(tmp_path):
    """BUG 1 (HIGH): out-of-enum NON-None aggregate_stamp values were
    silently ignored on non-empty bundles. Now fail-closed as
    STAMP_AGGREGATE_INVALID. (None still permitted — v0.1 no-claim semantic
    preserved for backward-compat.)"""
    records = (_record("INTERNAL_BENCHMARK"),)
    manifest = _Manifest(
        dispatch_records=records, aggregate_stamp="aggregate_stamp_pareto_v3"
    )
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_AGGREGATE_INVALID"
    assert "aggregate_stamp_pareto_v3" in result.detail


def test_bug1_min_rule_round_down_under_upgrades(tmp_path):
    """BUG 1 + v0.2 interplay: round-down detection must use EFFECTIVE
    stamps (after applying signed upgrades), not raw stamp_observed."""
    sha_b1u = _sha("bug1-rounddown-upgrades")
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=sha_b1u,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        discharge_obligation_sha=sha_b1u,
    )
    # Effective per-row min = INTERNAL_SOURCE (the upgraded value).
    # Declare aggregate=UNVERIFIED: round-down vs effective min.
    manifest = _Manifest(dispatch_records=(rec,), aggregate_stamp="UNVERIFIED")
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_AGGREGATE_ROUNDDOWN_DETECTED"


# --- BUG 2 — datetime-typed created_at bypass ------------------------------


def test_bug2_out_of_order_datetime_typed_created_at(tmp_path):
    """BUG 2 (HIGH, GPT-5): the prior implementation only ran the out-of-
    order check when manifest.created_at was a non-empty STRING. If the
    upstream parser normalized created_at to an aware datetime, the BUG-2
    fix from the prior round was silently bypassed. Now: comparator
    accepts either str or aware datetime on either side."""
    sha_b2 = _sha("bug2-datetime-typed")
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=sha_b2,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        discharge_obligation_sha=sha_b2,
        timestamp_utc="2026-05-03T13:00:00Z",
    )
    # manifest.created_at = aware datetime, NOT str.
    from datetime import datetime as _dt, timezone as _tz

    bundle_dt_aware = _dt(2026, 5, 3, 12, 0, 0, tzinfo=_tz.utc)
    manifest = _Manifest(dispatch_records=(rec,), created_at=bundle_dt_aware)
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_UPGRADE_OUT_OF_ORDER"


def test_bug2_naive_datetime_created_at_rejected(tmp_path):
    """BUG 2 follow-up: a naive (TZ-less) datetime on manifest.created_at
    is unparseable per the v0.2 UTC contract. The comparator returns None
    for naive datetimes → STAMP_UPGRADE_FORGED."""
    sha_b2n = _sha("bug2-naive-dt")
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=sha_b2n,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        discharge_obligation_sha=sha_b2n,
        timestamp_utc="2026-05-03T11:30:00Z",
    )
    from datetime import datetime as _dt

    bundle_dt_naive = _dt(2026, 5, 3, 12, 0, 0)  # no tzinfo
    manifest = _Manifest(dispatch_records=(rec,), created_at=bundle_dt_naive)
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "STAMP_UPGRADE_FORGED"


def test_bug2_datetime_typed_happy_path(tmp_path):
    """BUG 2: with a properly aware datetime and a sig timestamp earlier
    than bundle.created_at, the bundle still verifies. Confirms the new
    coercion path doesn't break the happy case."""
    sha_b2h = _sha("bug2-happy-dt")
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=sha_b2h,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        discharge_obligation_sha=sha_b2h,
        timestamp_utc="2026-05-03T11:30:00Z",
    )
    from datetime import datetime as _dt, timezone as _tz

    bundle_dt = _dt(2026, 5, 3, 12, 0, 0, tzinfo=_tz.utc)
    manifest = _Manifest(
        dispatch_records=(rec,), aggregate_stamp="INTERNAL_SOURCE", created_at=bundle_dt
    )
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is True, result.detail


# --- BUG 3 — namespace discipline pre-canonical-presence -------------------


@pytest.mark.parametrize(
    "rogue_only_key",
    [
        "stamp_upgrade_v2",
        "stampUpgrade",
        "STAMP_UPGRADE",
        "_stamp_upgrade",
        "stamp_upgrade_pending",
    ],
)
def test_bug3_namespace_collision_without_canonical_rejected(tmp_path, rogue_only_key):
    """BUG 3 (MED, GPT-5): the prior sibling-conflict guard only ran
    inside `if "stamp_upgrade" in record:`. A record carrying ONLY a
    non-canonical variant (e.g., `STAMP_UPGRADE` uppercase) was silently
    ignored. The new top-level pre-scan rejects any namespace variant on
    any record regardless of canonical presence."""
    rec = _record("INTERNAL_BENCHMARK")  # no canonical stamp_upgrade
    rec[rogue_only_key] = {"from_stamp": "INTERNAL_BENCHMARK", "to_stamp": "WEB_SOURCE"}
    manifest = _Manifest(dispatch_records=(rec,), aggregate_stamp="INTERNAL_BENCHMARK")
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False, (
        f"rogue-only key {rogue_only_key!r} should be rejected with no canonical present"
    )
    assert result.reason_code == "STAMP_UPGRADE_CONFLICT"
    assert rogue_only_key in result.detail


# --- BUG 4 — reason → required-checks registry -----------------------------


def test_bug4_reason_registry_contains_discharged():
    """BUG 4 (MED, Gemini + GPT-5): the per-reason discharge-link gate is
    a registry, not a hard-coded conditional. Adding a new reason that
    requires a proof is a one-line frozenset edit."""
    from audit_bundle.plugins.stamp_lattice import (
        _REASONS_REQUIRING_DISCHARGE_LINK,
    )

    # 'discharged' must currently be the only reason requiring a link.
    # If this set changes, the cross-plugin contract has shifted and the
    # discharge-link check at defense 8 needs reviewing.
    assert _REASONS_REQUIRING_DISCHARGE_LINK == frozenset({"discharged"})


def test_bug4_predicate_satisfied_does_not_require_proof_link(tmp_path):
    """BUG 4 control: 'predicate_satisfied' is NOT in the registry, so
    it must verify cleanly without a proof field at all."""
    rec = _record("COMPOSED_HYPOTHESIS")  # no proof field
    rec = sign_stamp_upgrade(
        rec,
        key=_KEY,
        from_stamp="COMPOSED_HYPOTHESIS",
        to_stamp="TARGET",
        upgrade_reason="predicate_satisfied",
        discharge_obligation_sha="",
        bundle_id=_BUNDLE_ID,
        record_idx=0,
        timestamp_utc="2026-05-03T11:30:00Z",
    )
    manifest = _Manifest(dispatch_records=(rec,), aggregate_stamp="TARGET")
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is True, result.detail


# --- BUG 5 — refine_text shared helper -------------------------------------


def test_bug5_refine_text_helper_canonical_in_signing_module():
    """BUG 5 (MED, Gemini): the canonical "first output's refine" convention
    lives in audit_bundle.discharge.verifier_signing.extract_refine_text.
    Both V14 (sign_stamp_upgrade) and the C14 plugin import this same
    function; the V16 plugin (refinement_discharge) also uses it. The
    prior triple-implementation invited cross-plugin drift."""
    from audit_bundle.discharge.verifier_signing import extract_refine_text
    from audit_bundle.plugins import stamp_lattice as c14
    from audit_bundle.plugins import refinement_discharge as v16

    # All three modules name the same function (or import it).
    assert c14.extract_refine_text is extract_refine_text
    assert v16.extract_refine_text is extract_refine_text


def test_bug5_extract_refine_text_first_output_convention():
    """BUG 5: the helper returns the FIRST outputs[*].type.refine string."""
    from audit_bundle.discharge.verifier_signing import extract_refine_text

    record = {
        "outputs": [
            {"name": "a", "type": {"base": "Int", "refine": "(>= a 0)"}},
            {"name": "b", "type": {"base": "Int", "refine": "(>= b 100)"}},
        ],
    }
    assert extract_refine_text(record) == "(>= a 0)"


def test_bug5_extract_refine_text_no_refine_returns_none():
    """BUG 5: returns None when no output has a refine field."""
    from audit_bundle.discharge.verifier_signing import extract_refine_text

    record = {"outputs": [{"name": "a", "type": {"base": "Int"}}]}
    assert extract_refine_text(record) is None


def test_bug5_multi_output_discharge_link_verifies(tmp_path):
    """BUG 5 end-to-end: a record with multiple outputs (only first has a
    refine formula, per the v0.2 convention) signs and re-verifies cleanly
    through C14's discharge-link check. Without the shared helper, V14's
    signing would pick output[0].refine and C14's verification would do
    the same — but if the conventions ever drifted, this test would fail."""
    sha_b5 = _sha("bug5-multi-output")
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=sha_b5,
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    # Add a second output WITHOUT a refine formula. Per the v0.2 convention,
    # extract_refine_text returns the first output's refine.
    rec["outputs"].append({"name": "extra", "type": {"base": "String"}})
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        discharge_obligation_sha=sha_b5,
    )
    manifest = _Manifest(dispatch_records=(rec,), aggregate_stamp="INTERNAL_SOURCE")
    plugin = StampLatticeCheck(recheck_key=_KEY)
    result = plugin.check(tmp_path, manifest)
    assert result.ok is True, result.detail


# --- BUG 6 — sentinel allowlist → denylist ---------------------------------


@pytest.mark.parametrize(
    "rogue_aggregate_field",
    [
        "aggregate_stamp_median",  # GPT-5's example
        "aggregate_stamp_pareto",  # Gemini's example
        "aggregate_stamp_harmonic",
        "aggregateStamp_geometric",  # camelCase
        "AGGREGATE_STAMP_MAJORITY",  # uppercase canonical-allowlist member
        "_aggregate_stamp_avg",  # leading underscore
    ],
)
def test_bug6_aggregate_namespace_denylist_in_wire_manifest(
    tmp_path, rogue_aggregate_field
):
    """BUG 6 (MED, Gemini + GPT-5): the prior 4-name allowlist
    (avg/voted/weighted/majority) silently admitted any future
    aggregate_stamp_* schema drift. The denylist now mirrors the BUG 4
    upgrade-namespace fix: any non-canonical aggregate_stamp_* field
    (case-insensitive, also handling camelCase) is rejected as
    STAMP_AGGREGATION_RULE_REJECTED."""
    (tmp_path / "manifest.json").write_text(
        json.dumps({rogue_aggregate_field: "CONFIRMED_EXTERNAL"}),
        encoding="utf-8",
    )
    manifest = _Manifest(dispatch_records=())
    plugin = StampLatticeCheck()
    result = plugin.check(tmp_path, manifest)
    assert result.ok is False, (
        f"rogue field {rogue_aggregate_field!r} should be rejected"
    )
    assert result.reason_code == "STAMP_AGGREGATION_RULE_REJECTED"
    assert rogue_aggregate_field in result.detail


def test_bug6_canonical_aggregate_stamp_passes(tmp_path):
    """BUG 6 control: the canonical singular `aggregate_stamp` is the
    only admissible aggregate field, and a manifest carrying it (with no
    siblings in the namespace) verifies cleanly."""
    (tmp_path / "manifest.json").write_text(
        json.dumps({"aggregate_stamp": "INTERNAL_SOURCE"}),
        encoding="utf-8",
    )
    manifest = _Manifest(
        dispatch_records=(_record("INTERNAL_SOURCE"),),
        aggregate_stamp="INTERNAL_SOURCE",
    )
    plugin = StampLatticeCheck()
    result = plugin.check(tmp_path, manifest)
    assert result.ok is True, result.detail


# ============================================================================
# Gate 3a frontier-pair P2 (Sonnet 4.6 §C2, 2026-05-19)
# ============================================================================


def test_timestamp_garbage_bypasses_defense_7():
    """Gate 3a P2 (Sonnet 4.6 §C2, 2026-05-19): a V14 HMAC key-holder
    mints a stamp_upgrade sig with `timestamp_utc="garbage-time"` (a
    truthy but non-ISO-8601 string). Pre-patch the verifier accepts the
    sig (the HMAC binds the literal string, MAC integrity holds), then
    C14's Defense-7 OOO check at `_compare_timestamps` calls
    `_parse_iso8601_to_aware("garbage-time")` which returns None and
    SILENTLY SKIPS the comparison — Defense-7 is bypassed. Patched
    `verify_stamp_upgrade_signature` rejects the sig at the format check
    before HMAC, so Defense-7's precondition (sig accepted) cannot hold."""
    from audit_bundle.discharge.verifier_signing import (
        _build_stamp_upgrade_payload,
        _hmac_hex,
    )

    # Build a record carrying a properly-signed V16 proof so the V14
    # upgrade has a real grounding event to point at.
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=_sha("p2-test"),
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    obligation_sha = _sha("p2-test")

    # Mint a V14 sig with a garbage timestamp — HMAC binds the exact
    # string, so MAC integrity holds; only the new grammar check rejects.
    garbage_ts = "garbage-time"
    payload = _build_stamp_upgrade_payload(
        bundle_id=_BUNDLE_ID,
        record_idx=0,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        upgrade_reason="discharged",
        discharge_obligation_sha=obligation_sha,
        verifier_id=_KEY.verifier_id,
        timestamp_utc=garbage_ts,
    )
    mac = _hmac_hex(_KEY, payload)

    rec["stamp_upgrade"] = {
        "from_stamp": "INTERNAL_BENCHMARK",
        "to_stamp": "INTERNAL_SOURCE",
        "upgrade_reason": "discharged",
        "discharge_obligation_sha": obligation_sha,
        "verifier_signature": {
            "algorithm": "hmac-sha256",
            "verifier_id": _KEY.verifier_id,
            "timestamp_utc": garbage_ts,
            "bundle_id": _BUNDLE_ID,
            "record_idx": 0,
            "from_stamp": "INTERNAL_BENCHMARK",
            "to_stamp": "INTERNAL_SOURCE",
            "upgrade_reason": "discharged",
            "discharge_obligation_sha": obligation_sha,
            "mac": mac,
        },
    }

    # Patched verifier rejects on the ISO-8601 grammar check before HMAC.
    assert (
        verify_stamp_upgrade_signature(
            rec,
            key=_KEY,
            bundle_id=_BUNDLE_ID,
            record_idx=0,
        )
        is False
    )


def test_timestamp_valid_iso8601_still_passes():
    """Sanity for P2: a properly-shaped ISO-8601 UTC timestamp still
    verifies cleanly. Guards against the format check over-rejecting
    legitimate timestamps (e.g. one with fractional seconds)."""
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=_sha("p2-control"),
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        discharge_obligation_sha=_sha("p2-control"),
        timestamp_utc="2026-05-03T11:30:00.123Z",
    )
    assert (
        verify_stamp_upgrade_signature(
            rec,
            key=_KEY,
            bundle_id=_BUNDLE_ID,
            record_idx=0,
        )
        is True
    )


# ============================================================================
# Gate 3a frontier-pair P4 (Opus 4.7 §A1 + Sonnet 4.6 §A1/§B1/§D2, 2026-05-19)
# ============================================================================


def test_v14_sig_without_bundle_id_rejected():
    """Gate 3a P4: V14 sig dicts must self-authenticate, matching V16's
    pattern. Pre-patch a sig dict that omitted `bundle_id` from the dict
    still verified (the HMAC bound the caller-authoritative value), but
    the persisted sig was not self-describing — downstream consumers
    couldn't tell which bundle a sig was created for without recomputing
    the HMAC. Patched code hard-rejects, mirroring V16."""
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=_sha("p4-bundle-id"),
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        discharge_obligation_sha=_sha("p4-bundle-id"),
    )
    # Delete bundle_id from the sig dict. HMAC was minted with the caller-
    # authoritative bundle_id; the literal HMAC is still valid; only the
    # P4 self-authentication check rejects.
    del rec["stamp_upgrade"]["verifier_signature"]["bundle_id"]

    assert (
        verify_stamp_upgrade_signature(
            rec,
            key=_KEY,
            bundle_id=_BUNDLE_ID,
            record_idx=0,
        )
        is False
    )


def test_v14_sig_without_record_idx_rejected():
    """Gate 3a P4: same self-authentication discipline for record_idx —
    a sig dict that omitted `record_idx` previously verified silently."""
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=_sha("p4-record-idx"),
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        discharge_obligation_sha=_sha("p4-record-idx"),
    )
    del rec["stamp_upgrade"]["verifier_signature"]["record_idx"]

    assert (
        verify_stamp_upgrade_signature(
            rec,
            key=_KEY,
            bundle_id=_BUNDLE_ID,
            record_idx=0,
        )
        is False
    )


def test_v14_sig_with_bool_record_idx_rejected():
    """Gate 3a P4: bool subclass guard — `isinstance(True, int)` is True
    in Python. A sig with `record_idx=True` could silently verify against
    a caller record_idx=1. V16 already guarded; V14 didn't."""
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=_sha("p4-bool-idx"),
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        discharge_obligation_sha=_sha("p4-bool-idx"),
    )
    rec["stamp_upgrade"]["verifier_signature"]["record_idx"] = True

    assert (
        verify_stamp_upgrade_signature(
            rec,
            key=_KEY,
            bundle_id=_BUNDLE_ID,
            record_idx=1,
        )
        is False
    )


def test_v14_sig_with_normal_self_describing_bindings_still_passes():
    """Sanity for P4: a properly-signed V14 sig with all self-describing
    bindings still verifies. Guards against over-rejection."""
    rec = _record(
        "INTERNAL_BENCHMARK",
        with_proof_obligation_sha=_sha("p4-control"),
        proof_discharge_status="discharged",
        proof_signed=True,
    )
    rec = _signed_upgrade(
        rec,
        from_stamp="INTERNAL_BENCHMARK",
        to_stamp="INTERNAL_SOURCE",
        discharge_obligation_sha=_sha("p4-control"),
    )
    assert (
        verify_stamp_upgrade_signature(
            rec,
            key=_KEY,
            bundle_id=_BUNDLE_ID,
            record_idx=0,
        )
        is True
    )
