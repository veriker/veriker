"""Pilot tests for payroll_no_cliff_minimal — the S2 case where the verifier
must SEARCH, not compare.

Builds the bundle, verifies it green through the default plugin set (Z3 proves
the schedule is cliff-free across the WHOLE earnings domain), and drives the
divergence leg: a producer publishes a schedule with a marginal rate above 100%
— a real income cliff — and signs it 'discharged'. The verifier's own Z3 search
finds a violating earnings pair (FAILED), contradicting the claim, and retains a
signed, re-verifiable divergence record (retain-and-still-reject).

The point this pilot makes vs. `x ∈ [a,b]`: the obligation quantifies over all
earnings (g1, g2 are free); it cannot be reduced to bounding a single produced
value, and it cannot be checked by inspecting the finitely-many paychecks in the
bundle — a cliff can hide between any two of them.
"""

from __future__ import annotations

import copy
import hashlib
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
_BUNDLE_ID = "payroll-no-cliff-minimal-rc"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_build = _load("payroll_no_cliff_build_bundle", _PILOT_DIR / "_build_bundle.py")

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


def test_build_produces_signed_discharged_record(built_bundle):
    manifest = json.loads((built_bundle / "manifest.json").read_text())
    recs = manifest["dispatch_records"]
    assert len(recs) == 1
    proof = recs[0]["proof"]
    assert proof["kind"] == "smt-z3"
    assert proof["discharge_status"] == "discharged"
    assert proof["verifier_signature"]["algorithm"] == "hmac-sha256"
    # the obligation leaves the earnings free — this is a for-all claim, not a
    # bound on a value
    assert proof["recheck_context"]["__sorts__"] == {"g1": "Int", "g2": "Int"}
    obl_uri = proof["obligation_uri"]
    assert obl_uri == "proofs/no_cliff.smt2"
    assert manifest["files"][obl_uri] == proof["obligation_sha"]


def test_verifies_green_through_default_plugin_set(built_bundle, monkeypatch):
    """Headline: PASS through the SAME default plugin set veriker/cli/verify.py uses —
    Z3 re-searches the domain and finds no cliff (re-discharged)."""
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
    key = VerifierSigningKey.from_secret_bytes(_DEMO_KEY.encode("utf-8"))
    recs = json.loads((built_bundle / "manifest.json").read_text())["dispatch_records"]
    plugin = RefinementDischargeCheck(
        recheck_key=key, recheck_invoker=InProcessZ3Invoker()
    )
    result = plugin.check(built_bundle, _manifest_stub(recs))
    assert result.ok is True, result.detail
    assert "re-discharged" in result.detail


def test_fail_closed_without_key(built_bundle):
    recs = json.loads((built_bundle / "manifest.json").read_text())["dispatch_records"]
    plugin = RefinementDischargeCheck(
        recheck_key=None, recheck_invoker=InProcessZ3Invoker()
    )
    result = plugin.check(built_bundle, _manifest_stub(recs))
    assert result.ok is False
    assert result.reason_code == "DISCHARGE_STATUS_FORGED"


def test_cliff_schedule_diverges_and_retains_record(built_bundle):
    """The headline: a producer publishes a schedule with a 130% marginal rate
    in the middle bracket — a real income cliff — writes a matching obligation
    file, and signs it 'discharged'. The verifier's own Z3 search finds an
    earnings pair where the higher earner takes home LESS (FAILED), contradicting
    the claim. Verdict fails closed with a retained, re-verifiable divergence
    record. Re-derivation / a range check could never find this: there is no
    single value, and the violating pair lies between sampled incomes."""
    key = VerifierSigningKey.from_secret_bytes(_DEMO_KEY.encode("utf-8"))

    cliff_formula = _build.monotone_formula(15, 130, 29)  # 130% marginal → cliff
    cliff_obl = _build.obligation_text(cliff_formula, (15, 130, 29)).encode("utf-8")
    cliff_sha = hashlib.sha256(cliff_obl).hexdigest()

    recs = copy.deepcopy(
        json.loads((built_bundle / "manifest.json").read_text())["dispatch_records"]
    )
    rec = recs[0]
    rec["outputs"][0]["type"]["refine"] = cliff_formula
    rec["proof"]["discharge_status"] = "not-attempted"
    rec["proof"]["obligation_sha"] = cliff_sha
    rec["proof"].pop("verifier_signature", None)
    diverged = sign_and_write(
        rec,
        key=key,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
        record_idx=0,
    )

    with tempfile.TemporaryDirectory() as td:
        tmp_bundle = Path(td) / "bundle"
        shutil.copytree(built_bundle, tmp_bundle)
        # the on-disk obligation file must match the claimed sha (proof-shape
        # check); write the cliff schedule's obligation text into the copy
        (tmp_bundle / "proofs" / "no_cliff.smt2").write_bytes(cliff_obl)

        plugin = RefinementDischargeCheck(
            recheck_key=key, recheck_invoker=InProcessZ3Invoker()
        )
        result = plugin.check(tmp_bundle, _manifest_stub([diverged]))
        assert result.ok is False
        assert result.reason_code == "DISCHARGE_STATUS_VERIFIER_DIVERGENCE"

        # Read-only verify() invariant: the verifier-signed divergence record is
        # retained on the verdict face (PluginResult.disclosures), NOT appended to
        # the bundle (writing events.jsonl into the bundle would flip a re-verify
        # GREEN→RED as UNOWNED surplus). retain-and-still-reject persists.
        assert not (tmp_bundle / "events.jsonl").exists()
        disclosures = [
            d for d in result.disclosures if "DISCHARGE_STATUS_VERIFIER_DIVERGENCE" in d
        ]
        assert len(disclosures) == 1, (
            f"divergence record was not retained: {result.disclosures!r}"
        )
        det = json.loads(disclosures[0].split(" — ", 1)[1])
        assert det["record_kind"] == DIVERGENCE_RECORD_KIND
        assert det["producer_claimed"] == "discharged"
        assert det["verifier_computed"] == "failed"
        assert verify_divergence_record(
            det, key=key, bundle_id=_BUNDLE_ID, record_idx=0
        )

    assert not (built_bundle / "events.jsonl").exists()
