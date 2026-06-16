"""test_pandemic_benefit_eligibility_minimal.py — happy path + tamper tests.

Gate 3 of the v-kernel-pilot four-gate criteria. Tests:

  happy path                       — 5 eligible applicants approved, 3 ineligible denied;
                                     verifier re-derives all decisions correctly
  ineligible applicant approved    — APP-006 has prior_income < $5,000 floor; disbursement
                                     system marks APPROVED; verifier catches mismatch
                                     [PANDEMIC_ELIGIBILITY_REDERIVATION_MISMATCH]
  benefit amount inflation         — eligible applicant's amount inflated; verifier catches
  file SHA tamper                  — applicants.json modified without manifest update; caught
                                     by FileIntegrityManySmall [bad_file_sha]
  signature tamper                 — decision edited after signing without re-signing; caught
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PILOT_DIR = _HERE.parent / "examples" / "pandemic_benefit_eligibility_minimal"
_PKG_ROOT = _HERE.parent

for p in (str(_PKG_ROOT), str(_PILOT_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_pack = _load("pandemic_eligibility_pack", _PILOT_DIR / "pandemic_eligibility_rederivation.py")
_build = _load("pandemic_benefit_build", _PILOT_DIR / "_build_bundle.py")


def _full_verify(bundle_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(_PILOT_DIR / "verify.py"), "--bundle-dir", str(bundle_dir)],
        capture_output=True,
    )


def _key(bundle_dir: Path) -> bytes:
    return bytes.fromhex(
        (bundle_dir / "spec" / "disbursement_hmac_key.hex").read_text().strip()
    )


def _load_decisions(bundle_dir: Path) -> list:
    return json.loads((bundle_dir / "payload" / "disbursement_decisions.json").read_text())


def _write_decisions(bundle_dir: Path, decisions: list) -> None:
    """Rewrite disbursement_decisions.json AND re-stamp its manifest SHA so the
    re-derivation plugin (not file integrity) is what adjudicates the mutation."""
    path = bundle_dir / "payload" / "disbursement_decisions.json"
    path.write_text(json.dumps(decisions, indent=2), encoding="utf-8")
    man_path = bundle_dir / "manifest.json"
    man = json.loads(man_path.read_text())
    man["files"]["payload/disbursement_decisions.json"] = (
        hashlib.sha256(path.read_bytes()).hexdigest()
    )
    man_path.write_text(json.dumps(man, indent=2), encoding="utf-8")


def _load_applicants(bundle_dir: Path) -> list:
    return json.loads((bundle_dir / "data" / "applicants.json").read_text())


def _write_applicants(bundle_dir: Path, applicants: list) -> None:
    """Rewrite applicants.json AND re-stamp its manifest SHA."""
    path = bundle_dir / "data" / "applicants.json"
    path.write_text(json.dumps(applicants, indent=2), encoding="utf-8")
    man_path = bundle_dir / "manifest.json"
    man = json.loads(man_path.read_text())
    man["files"]["data/applicants.json"] = hashlib.sha256(path.read_bytes()).hexdigest()
    man_path.write_text(json.dumps(man, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_happy_path(tmp_path):
    """Build a bundle and verify it. All 8 decisions must re-derive correctly.
    5 applicants eligible -> APPROVED; 3 ineligible -> DENIED."""
    bundle = tmp_path / "bundle"
    _build.build(bundle)
    proc = _full_verify(bundle)
    assert proc.returncode == 0, proc.stderr.decode()
    assert b"PASS" in proc.stdout

    # Spot-check the verifier's own re-derivation ledger.
    err, ledger = _pack._verify(bundle)
    assert err is None, err
    verdicts = {r["applicant_id"]: r["verifier_verdict"] for r in ledger}

    # Eligible applicants
    assert verdicts["APP-001"] == _pack.APPROVED   # $52k/yr, lost income
    assert verdicts["APP-002"] == _pack.APPROVED   # $26k/yr, gig worker, zero income
    assert verdicts["APP-003"] == _pack.APPROVED   # $39k/yr, self-employed, minimal income
    assert verdicts["APP-004"] == _pack.APPROVED   # $78k/yr, employed, income dropped
    assert verdicts["APP-005"] == _pack.APPROVED   # exactly $5k/yr (minimum floor)

    # Ineligible applicants
    assert verdicts["APP-006"] == _pack.DENIED     # $4k/yr — below $5,000 floor
    assert verdicts["APP-007"] == _pack.DENIED     # income did NOT drop below threshold
    assert verdicts["APP-008"] == _pack.DENIED     # week 30 — outside eligibility window


# ---------------------------------------------------------------------------
# Tamper test: ineligible applicant approved
# ---------------------------------------------------------------------------


def test_ineligible_applicant_approved_is_caught(tmp_path):
    """Core tamper test.

    APP-006 has prior_income_cents=400000 ($4,000/yr) — below the $5,000 minimum floor,
    so the rule set yields DENIED. We mutate the applicant's attested prior_income to
    400000 (already ineligible) but mark the disbursement decision as APPROVED and
    re-sign it with the bundled key (valid signature). We also re-stamp the applicants
    file SHA in the manifest so file-integrity is clean.

    The verifier must still catch this: it re-derives DENIED from the attested attributes
    and the published rule set, finds APPROVED in the bundle, and returns result.ok=False
    with PANDEMIC_ELIGIBILITY_REDERIVATION_MISMATCH in the failures.
    """
    bundle = tmp_path / "bundle"
    _build.build(bundle)
    key = _key(bundle)

    # APP-006's prior_income is already $4,000 (ineligible). Mutate the decision to
    # APPROVED and re-sign — the file content is now internally consistent but wrong.
    decisions = _load_decisions(bundle)
    for dec in decisions:
        if dec["applicant_id"] == "APP-006":
            dec["verdict"] = _pack.APPROVED
            dec["weekly_benefit_cents"] = 23077   # some plausible-looking amount
            dec.pop("signature", None)
            dec["signature"] = _pack.sign_decision(dec, key)
    _write_decisions(bundle, decisions)

    proc = _full_verify(bundle)
    assert proc.returncode == 1, "expected FAIL — ineligible applicant should have been caught"
    stderr = proc.stderr.decode()
    assert "PANDEMIC_ELIGIBILITY_REDERIVATION_MISMATCH" in stderr, (
        f"expected PANDEMIC_ELIGIBILITY_REDERIVATION_MISMATCH in stderr, got: {stderr}"
    )
    assert "APP-006" in stderr


# ---------------------------------------------------------------------------
# Tamper test: benefit amount inflation
# ---------------------------------------------------------------------------


def test_benefit_amount_inflation_is_caught(tmp_path):
    """An eligible applicant (APP-001) has their weekly benefit amount inflated in the
    decision. The verifier re-derives the correct amount, finds a mismatch, and rejects."""
    bundle = tmp_path / "bundle"
    _build.build(bundle)
    key = _key(bundle)

    decisions = _load_decisions(bundle)
    for dec in decisions:
        if dec["applicant_id"] == "APP-001":
            dec["weekly_benefit_cents"] += 100000   # inflate by $1,000/week
            dec.pop("signature", None)
            dec["signature"] = _pack.sign_decision(dec, key)
    _write_decisions(bundle, decisions)

    proc = _full_verify(bundle)
    assert proc.returncode == 1
    stderr = proc.stderr.decode()
    assert "PANDEMIC_ELIGIBILITY_REDERIVATION_MISMATCH" in stderr
    assert "APP-001" in stderr


# ---------------------------------------------------------------------------
# Tamper test: file SHA tamper (no manifest update)
# ---------------------------------------------------------------------------


def test_file_sha_tamper_caught(tmp_path):
    """Modify applicants.json without updating the manifest SHA — caught by
    FileIntegrityManySmall."""
    bundle = tmp_path / "bundle"
    _build.build(bundle)

    # Edit a field directly without touching the manifest.
    applicants_path = bundle / "data" / "applicants.json"
    text = applicants_path.read_text().replace('"APP-001"', '"APP-001-TAMPERED"')
    assert "APP-001-TAMPERED" in text
    applicants_path.write_text(text)

    proc = _full_verify(bundle)
    assert proc.returncode == 1
    # The file-integrity plugin fires: stderr contains manifest_sha/computed_sha mismatch detail.
    assert b"manifest_sha" in proc.stderr.lower() or b"file_integrity" in proc.stderr.lower()


# ---------------------------------------------------------------------------
# Tamper test: signature tamper (no re-sign)
# ---------------------------------------------------------------------------


def test_signature_tamper_rejected(tmp_path):
    """Edit a decision field after signing without re-signing — caught by the
    signature check in the re-derivation pack."""
    bundle = tmp_path / "bundle"
    _build.build(bundle)

    decisions = _load_decisions(bundle)
    decisions[0]["period_week"] = 99   # mutate a field without re-signing
    _write_decisions(bundle, decisions)  # updates manifest SHA so file-integrity is clean

    proc = _full_verify(bundle)
    assert proc.returncode == 1
    assert b"SIGNATURE_INVALID" in proc.stderr
