"""Pilot tests for payroll_acting_discretion_minimal — the S2 case re-derivation
cannot reach.

Builds the bundle, verifies it green through the default plugin set (real Z3
re-run agrees the discretionary acting rate is in-band), and confirms the
forgery + divergence legs — including the two out-of-band placements that are the
headline: an over-payment windfall (a rate inside the raw classification band but
above the anti-windfall cap) and an under-payment below the band floor. Neither
is a "wrong recomputed number" — there is no canonical rate — so only the C16
band-membership check catches them.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
_PILOT_DIR = _HERE.parent
_PKG_ROOT = _PILOT_DIR.parents[1]
for p in (str(_PKG_ROOT), str(_PILOT_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from audit_bundle.discharge.verifier_signing import (  # noqa: E402
    DIVERGENCE_RECORD_KIND,
    VerifierSigningKey,
    sign_and_write,
    verify_divergence_record,
)
from audit_bundle.discharge.z3_runner import (  # noqa: E402
    InProcessZ3Invoker,
    pick_default_invoker,
)
from audit_bundle.plugins import default_post_w3_plugin_set  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.refinement_discharge import RefinementDischargeCheck  # noqa: E402
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402

_DEMO_KEY = "demo-vkernel-verifier-secret-0123456789abcdef"
_BUNDLE_ID = "payroll-acting-discretion-minimal-rc"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_build = _load("payroll_acting_build_bundle", _PILOT_DIR / "_build_bundle.py")

_z3_unavailable = pick_default_invoker() is None
pytestmark = pytest.mark.skipif(
    _z3_unavailable, reason="no Z3 invoker available (z3-solver module or binary)"
)


@pytest.fixture()
def built_bundle(tmp_path, monkeypatch):
    monkeypatch.setenv("VKERNEL_VERIFIER_HMAC_KEY", _DEMO_KEY)
    out = tmp_path / "bundle"
    _build.build(out)
    return out


def _manifest_stub(records, bundle_id=_BUNDLE_ID):
    class _M:
        def __init__(self):
            self.dispatch_records = tuple(records)
            self.bundle_id = bundle_id

    return _M()


def _diverged_record(built_bundle, *, new_acting_rate, key):
    """Re-sign the discharge record over a context whose acting_rate is out of
    band — a legitimately-MAC'd 'discharged' claim that the verifier's own Z3
    re-run will contradict."""
    recs = copy.deepcopy(
        json.loads((built_bundle / "manifest.json").read_text())["dispatch_records"]
    )
    rec = recs[0]
    rec["proof"]["discharge_status"] = "not-attempted"
    rec["proof"].pop("verifier_signature", None)
    rec["proof"]["recheck_context"] = {
        **rec["proof"]["recheck_context"],
        "acting_rate": new_acting_rate,
    }
    return sign_and_write(
        rec,
        key=key,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
        record_idx=0,
    )


def test_build_produces_signed_discharged_record(built_bundle):
    """The shipped record carries a verifier-signed 'discharged' status over a
    smt-z3 band-membership proof with a digest-pinned obligation file."""
    manifest = json.loads((built_bundle / "manifest.json").read_text())
    recs = manifest["dispatch_records"]
    assert len(recs) == 1
    proof = recs[0]["proof"]
    assert proof["kind"] == "smt-z3"
    assert proof["discharge_status"] == "discharged"
    assert proof["verifier_signature"]["algorithm"] == "hmac-sha256"
    obl_uri = proof["obligation_uri"]
    assert obl_uri == "proofs/acting_band.smt2"
    assert (built_bundle / obl_uri).exists()
    assert manifest["files"][obl_uri] == proof["obligation_sha"]
    # the chosen rate genuinely sits in the admissible band
    ctx = proof["recheck_context"]
    lo = max(ctx["band_min"], ctx["raise_floor"])
    hi = min(ctx["band_max"], ctx["windfall_ceiling"])
    assert lo <= ctx["acting_rate"] <= hi


def test_verifies_green_through_default_plugin_set(built_bundle, monkeypatch):
    """Headline: the honest bundle PASSes through the SAME default plugin set
    veriker/cli/verify.py uses — no pilot-local pack needed, because the acting rate is
    not re-derivable and C16 is the only check that reaches it."""
    monkeypatch.setenv("VKERNEL_VERIFIER_HMAC_KEY", _DEMO_KEY)
    plugins = [
        FileIntegrityManySmall(),
        SpecShaPinCheck(),
        *default_post_w3_plugin_set(),
    ]
    result = BundleVerifier(plugins=plugins).verify(built_bundle)
    assert result.ok is True, [
        f"{f.check_name}:{f.reason_code}" for f in result.failures
    ]


def test_c16_re_discharges_on_honest_bundle(built_bundle):
    """Direct C16 check with a real in-process Z3 invoker: the signed status is
    admitted AND the re-run agrees (detail says re-discharged)."""
    key = VerifierSigningKey.from_secret_bytes(_DEMO_KEY.encode("utf-8"))
    recs = json.loads((built_bundle / "manifest.json").read_text())["dispatch_records"]
    plugin = RefinementDischargeCheck(
        recheck_key=key, recheck_invoker=InProcessZ3Invoker()
    )
    result = plugin.check(built_bundle, _manifest_stub(recs))
    assert result.ok is True, result.detail
    assert "re-discharged" in result.detail


def test_fail_closed_without_key(built_bundle):
    """No verifier key → the non-trivial signed status is rejected as forged."""
    recs = json.loads((built_bundle / "manifest.json").read_text())["dispatch_records"]
    plugin = RefinementDischargeCheck(
        recheck_key=None, recheck_invoker=InProcessZ3Invoker()
    )
    result = plugin.check(built_bundle, _manifest_stub(recs))
    assert result.ok is False
    assert result.reason_code == "DISCHARGE_STATUS_FORGED"


def test_obligation_digest_tamper_rejected(built_bundle):
    key = VerifierSigningKey.from_secret_bytes(_DEMO_KEY.encode("utf-8"))
    recs = copy.deepcopy(
        json.loads((built_bundle / "manifest.json").read_text())["dispatch_records"]
    )
    recs[0]["proof"]["obligation_sha"] = "b" * 64
    plugin = RefinementDischargeCheck(
        recheck_key=key, recheck_invoker=InProcessZ3Invoker()
    )
    result = plugin.check(built_bundle, _manifest_stub(recs))
    assert result.ok is False
    assert result.reason_code == "PROOF_OBLIGATION_SHA_MISMATCH"


@pytest.mark.parametrize(
    "label,new_rate",
    [
        # over-payment: inside the raw class band (<=373077) but above the
        # anti-windfall cap (366153) — the buddy-deal placement
        ("windfall_over_payment", 370000),
        # under-payment: below the class-band minimum (326923)
        ("below_floor_under_payment", 320000),
    ],
)
def test_out_of_band_rate_diverges_and_retains_record(built_bundle, label, new_rate):
    """The claimed advance, and the case re-derivation cannot reach: a producer
    signs 'discharged' over an out-of-band acting rate (there is no canonical
    rate to compare against). The verifier's own Z3 re-run finds a counterexample
    → FAILED, contradicting the signed claim. The verdict fails closed AND a
    signed divergence record is retained on the verdict face and re-verifies
    (retain-and-still-reject)."""
    key = VerifierSigningKey.from_secret_bytes(_DEMO_KEY.encode("utf-8"))
    diverged = _diverged_record(built_bundle, new_acting_rate=new_rate, key=key)

    with tempfile.TemporaryDirectory() as td:
        tmp_bundle = Path(td) / "bundle"
        shutil.copytree(built_bundle, tmp_bundle)
        plugin = RefinementDischargeCheck(
            recheck_key=key, recheck_invoker=InProcessZ3Invoker()
        )
        result = plugin.check(tmp_bundle, _manifest_stub([diverged]))
        assert result.ok is False, label
        assert result.reason_code == "DISCHARGE_STATUS_VERIFIER_DIVERGENCE", label

        # Read-only verify() invariant: the verifier-signed divergence record is
        # retained on the verdict face (PluginResult.disclosures), NOT appended to
        # the bundle (writing events.jsonl into the bundle would flip a re-verify
        # GREEN→RED as UNOWNED surplus). retain-and-still-reject persists.
        assert not (tmp_bundle / "events.jsonl").exists(), label
        disclosures = [
            d for d in result.disclosures if "DISCHARGE_STATUS_VERIFIER_DIVERGENCE" in d
        ]
        assert len(disclosures) == 1, (
            f"{label}: divergence record was not retained: {result.disclosures!r}"
        )
        det = json.loads(disclosures[0].split(" — ", 1)[1])
        assert det["record_kind"] == DIVERGENCE_RECORD_KIND
        assert det["producer_claimed"] == "discharged"
        assert det["verifier_computed"] == "failed"
        assert verify_divergence_record(
            det, key=key, bundle_id=_BUNDLE_ID, record_idx=0
        )

    # the shipped bundle stays clean — no events.jsonl committed
    assert not (built_bundle / "events.jsonl").exists()
