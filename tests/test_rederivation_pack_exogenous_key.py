"""tests/test_rederivation_pack_exogenous_key.py — Pattern-2 regression: bundle-supplied HMAC key.

The reference compliance re-derivation packs used to verify attestation
signatures against a key read FROM THE BUNDLE (spec/collector_hmac_key.hex).
The bundle author writes both the key and the signature, so the
"signed / responsible-actor binding" PASS claim was theater against an
adversarial producer (same family as the M2 monotone-growth false-green:
an unverified bundle-supplied input gating a positive claim).

The fix verifies against a VERIFIER-WIRED key (env VKERNEL_COLLECTOR_HMAC_KEY,
hex) and fails closed when no key is wired — the same exogenous-key shape
refinement_discharge / stamp_lattice already use.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from audit_bundle.plugins.reference import aigov_rederivation, control_rederivation

# The collector / bundle-author key. In the attack scenarios this is the key
# the adversarial producer mints (and pre-fix also shipped in the bundle);
# in the honest scenario it is the collector key the verifying deployment
# received out-of-band.
_COLLECTOR_KEY = bytes.fromhex("aa" * 32)
_VERIFIER_OWN_KEY = bytes.fromhex("bb" * 32)

_ENV = "VKERNEL_COLLECTOR_HMAC_KEY"

_CASES = [
    pytest.param(
        control_rederivation,
        "CTRL-KEYS",
        "aws_root_no_access_keys",
        {"SummaryMap": {"AccountAccessKeysPresent": 0}},
        id="control_rederivation",
    ),
    pytest.param(
        aigov_rederivation,
        "AIGOV-RISK-CLASS",
        "eu_ai_act_risk_classification",
        {"systems": []},
        id="aigov_rederivation",
    ),
]


def _build_bundle(
    bundle: Path, pack, control_id: str, test_fn: str, evidence: dict
) -> None:
    """A self-consistent bundle whose attestation is signed with a key the
    BUNDLE AUTHOR controls — the pre-fix false-green shape. The key is also
    shipped inside the bundle as the legacy spec/collector_hmac_key.hex; it
    must carry NO authority for the verifier."""
    for d in ("spec", "evidence", "payload", "coverage"):
        (bundle / d).mkdir(parents=True, exist_ok=True)
    (bundle / "spec" / "controls.json").write_text(
        json.dumps(
            {
                "schema": "nexi-control-lib-v1",
                "controls": {
                    control_id: {
                        "test_fn": test_fn,
                        "test_fn_version": "1.0.0",
                        "framework_mappings": [],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    (bundle / "spec" / "collector_hmac_key.hex").write_text(
        _COLLECTOR_KEY.hex(), encoding="utf-8"
    )
    ev_path = bundle / "evidence" / "e.json"
    ev_path.write_text(json.dumps(evidence), encoding="utf-8")
    att = {
        "control_id": control_id,
        "test_fn": test_fn,
        "test_fn_version": "1.0.0",
        "evidence_ref": "evidence/e.json",
        "evidence_sha256": pack.sha256_file(ev_path),
        "claimed_verdict": "pass",
        "observed_at": "2026-06-09T00:00:00Z",
        "attestor_id": "attestor://adversarial-producer",
    }
    att["signature"] = pack.sign_attestation(att, _COLLECTOR_KEY)
    (bundle / "payload" / "control_attestations.json").write_text(
        json.dumps([att]), encoding="utf-8"
    )
    (bundle / "coverage" / "control_period.json").write_text(
        json.dumps({"n_issued": 1, "n_withheld": 0}), encoding="utf-8"
    )


@pytest.mark.parametrize("pack,control_id,test_fn,evidence", _CASES)
def test_unwired_verifier_fails_closed(
    tmp_path: Path, monkeypatch, pack, control_id, test_fn, evidence
):
    """No verifier key wired -> the crafted bundle must NOT pass. The pre-fix
    code accepted exactly this bundle by trusting its own bundled key."""
    _build_bundle(tmp_path, pack, control_id, test_fn, evidence)
    monkeypatch.delenv(_ENV, raising=False)
    error, _ = pack._verify(tmp_path)
    assert error is not None
    assert error.startswith("SIGNATURE_UNVERIFIABLE_NO_KEY")


@pytest.mark.parametrize("pack,control_id,test_fn,evidence", _CASES)
def test_wired_key_rejects_bundle_key_signature(
    tmp_path: Path, monkeypatch, pack, control_id, test_fn, evidence
):
    """Verifier wired to its own key -> a signature minted under the bundle
    author's key fails: the bundle-supplied key carries no authority."""
    _build_bundle(tmp_path, pack, control_id, test_fn, evidence)
    monkeypatch.setenv(_ENV, _VERIFIER_OWN_KEY.hex())
    error, _ = pack._verify(tmp_path)
    assert error is not None
    assert error.startswith("SIGNATURE_INVALID")


@pytest.mark.parametrize("pack,control_id,test_fn,evidence", _CASES)
def test_wired_collector_key_passes(
    tmp_path: Path, monkeypatch, pack, control_id, test_fn, evidence
):
    """Honest path: the deployment received the collector key OUT-OF-BAND and
    wired it — signatures verify and the verdict re-derives."""
    _build_bundle(tmp_path, pack, control_id, test_fn, evidence)
    monkeypatch.setenv(_ENV, _COLLECTOR_KEY.hex())
    error, ledger = pack._verify(tmp_path)
    assert error is None
    assert ledger[0]["verifier_verdict"] == "pass"


@pytest.mark.parametrize("pack,control_id,test_fn,evidence", _CASES)
def test_malformed_env_key_rejects(
    tmp_path: Path, monkeypatch, pack, control_id, test_fn, evidence
):
    _build_bundle(tmp_path, pack, control_id, test_fn, evidence)
    monkeypatch.setenv(_ENV, "not-hex")
    error, _ = pack._verify(tmp_path)
    assert error is not None
    assert error.startswith("COLLECTOR_KEY_MALFORMED")


@pytest.mark.parametrize("pack,control_id,test_fn,evidence", _CASES)
def test_wired_key_still_catches_verdict_lie(
    tmp_path: Path, monkeypatch, pack, control_id, test_fn, evidence
):
    """The sound part is unchanged: even with a valid wired-key signature,
    a claimed verdict the evidence does not support is rejected."""
    _build_bundle(tmp_path, pack, control_id, test_fn, evidence)
    # Make the evidence FAIL the control while the attestation claims pass.
    ev_path = tmp_path / "evidence" / "e.json"
    if pack is control_rederivation:
        failing = {"SummaryMap": {"AccountAccessKeysPresent": 2}}
    else:
        failing = {"systems": [{"risk_classification": "bogus"}]}
    ev_path.write_text(json.dumps(failing), encoding="utf-8")
    att_path = tmp_path / "payload" / "control_attestations.json"
    atts = json.loads(att_path.read_text(encoding="utf-8"))
    atts[0]["evidence_sha256"] = pack.sha256_file(ev_path)
    atts[0].pop("signature")
    atts[0]["signature"] = pack.sign_attestation(atts[0], _COLLECTOR_KEY)
    att_path.write_text(json.dumps(atts), encoding="utf-8")
    monkeypatch.setenv(_ENV, _COLLECTOR_KEY.hex())
    error, _ = pack._verify(tmp_path)
    assert error is not None
    assert error.startswith("VERDICT_DIVERGENCE")
