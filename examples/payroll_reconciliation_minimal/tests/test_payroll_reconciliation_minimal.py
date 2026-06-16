"""test_payroll_reconciliation_minimal.py — pilot happy-path + tamper tests.

Gate 3 of the v-kernel-pilot four-gate success criteria.

Covers:
  * happy path: build + full verify.py → PASS
  * tamper A (byte mutation of input, no SHA re-stamp): caught end-to-end by the
    full verifier via FileIntegrityManySmall (BAD_FILE_SHA)
  * tamper B (SHA-consistent clawback forgery): the re-derivation pack itself
    catches it — the Phoenix point that hashing the output is not enough; you
    must re-derive the amount owed from the pinned rules + inputs
  * tamper C (closed-world accounting forgery): the coverage sum-invariant check
    rejects a pay population where issued + withheld != eligible
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PILOT_DIR = _HERE.parent
_PKG_ROOT = _PILOT_DIR.parents[1]

for p in (str(_PKG_ROOT), str(_PILOT_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

# The bundle now carries a verifier-signed S2 / C16 discharge record, so both
# the build and the verify path require the verifier HMAC key. Use the disclosed
# synthetic demo secret unless the environment already supplies one.
_DEMO_KEY = "demo-vkernel-verifier-secret-0123456789abcdef"
os.environ.setdefault("VKERNEL_VERIFIER_HMAC_KEY", _DEMO_KEY)
_KEYED_ENV = {**os.environ, "VKERNEL_VERIFIER_HMAC_KEY": os.environ["VKERNEL_VERIFIER_HMAC_KEY"]}


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_build = _load("payroll_build_bundle", _PILOT_DIR / "_build_bundle.py")


def _full_verify(bundle_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(_PILOT_DIR / "verify.py"), "--bundle-dir", str(bundle_dir)],
        capture_output=True,
        env=_KEYED_ENV,
    )


def _run_pack(bundle_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(_PILOT_DIR / "payroll_re_derivation.py"), "--bundle-dir", str(bundle_dir)],
        capture_output=True,
    )


def test_happy_path(tmp_path):
    bundle = tmp_path / "bundle"
    _build.build(bundle)
    proc = _full_verify(bundle)
    assert proc.returncode == 0, proc.stderr.decode()
    assert proc.stdout.decode().strip() == "PASS"


def test_tamper_input_byte_caught_end_to_end(tmp_path):
    bundle = tmp_path / "bundle"
    _build.build(bundle)

    # Flip acting_days on E0003 in the input CSV without fixing the manifest SHA.
    csv_path = bundle / "data" / "pay_events.csv"
    text = csv_path.read_text().replace("E0003,AS-01,AS-03,7,", "E0003,AS-01,AS-03,9,")
    csv_path.write_text(text)

    proc = _full_verify(bundle)
    assert proc.returncode == 1
    assert b"bad_file_sha" in proc.stderr.lower()


def test_tamper_clawback_caught_by_rederivation(tmp_path):
    bundle = tmp_path / "bundle"
    _build.build(bundle)

    # Forge the books: zero out E0008's clawback to hide the $400 overpayment.
    # The pinned inputs (issued_net) and rules are untouched, so the re-derivation
    # pack recomputes the correct net, finds issued - correct = 40000 != 0, and
    # rejects. This is the Phoenix reconciliation point: the amount owed must be
    # re-derivable, not merely hashed.
    ledger_path = bundle / "payload" / "paychecks.json"
    ledger = json.loads(ledger_path.read_text())
    for rec in ledger:
        if rec["employee_id"] == "E0008":
            rec["clawback_cents"] = 0
    ledger_path.write_text(json.dumps(ledger, indent=2), encoding="utf-8")

    proc = _run_pack(bundle)
    assert proc.returncode == 1
    assert b"clawback_cents mismatch" in proc.stderr
    assert b"E0008" in proc.stderr


def test_tamper_net_caught_by_rederivation(tmp_path):
    bundle = tmp_path / "bundle"
    _build.build(bundle)

    # Inflate E0005's net pay directly in the ledger. The pack recomputes net
    # from rules+events and rejects the doctored value.
    ledger_path = bundle / "payload" / "paychecks.json"
    ledger = json.loads(ledger_path.read_text())
    for rec in ledger:
        if rec["employee_id"] == "E0005":
            rec["net_cents"] += 9999
    ledger_path.write_text(json.dumps(ledger, indent=2), encoding="utf-8")

    proc = _run_pack(bundle)
    assert proc.returncode == 1
    assert b"net_cents mismatch" in proc.stderr


def test_tamper_coverage_accounting_caught_by_sum_invariant(tmp_path):
    bundle = tmp_path / "bundle"
    _build.build(bundle)

    # Understate the withheld population so the books appear fully paid.
    # CoverageSumInvariantCheck must reject: issued + withheld != eligible.
    from audit_bundle.coverage.sum_invariant_plugin import CoverageSumInvariantCheck

    cov_path = bundle / "coverage" / "period_2026_05.json"
    cov = json.loads(cov_path.read_text())
    cov["n_withheld"] = 0
    cov["withheld_reason_breakdown"] = {}
    cov_path.write_text(json.dumps(cov, indent=2, sort_keys=True), encoding="utf-8")

    result = CoverageSumInvariantCheck().check(bundle, None)
    assert result.ok is False
    assert result.reason_code == "COVERAGE_SUM_MISMATCH"
