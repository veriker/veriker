"""test_provenance_upgrade_minimal.py — gates for the honest S1 signed-upgrade pilot.

Proves the provenance_upgrade_minimal bundle exercises a REAL verifier-signed,
single-tier rigor-stamp upgrade end-to-end:

  (happy)  build + bare veriker/cli/verify.py            -> PASS, and the C14 stamp_lattice
                                                    plugin ADMITS 1 signed upgrade
  (tamper) demo/run_upgrade_demo.py self-checks  -> 1 honest PASS + 4 rejections

The verifier key is the disclosed synthetic demo secret, injected via the
subprocess env exactly as veriker/cli/verify.py's _load_verifier_recheck_key() reads it.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT = _PKG_ROOT / "examples" / "provenance_upgrade_minimal"
_DEMO_KEY = "demo-vkernel-verifier-secret-0123456789abcdef"


def _env() -> dict:
    env = dict(os.environ)
    env["VKERNEL_VERIFIER_HMAC_KEY"] = _DEMO_KEY
    return env


def _build(tmp_path: Path) -> Path:
    bundle = tmp_path / "bundle"
    proc = subprocess.run(
        [sys.executable, str(_PILOT / "_build_bundle.py"), "--out-dir", str(bundle)],
        capture_output=True,
        text=True,
        env=_env(),
    )
    assert proc.returncode == 0, f"build failed: {proc.stderr}"
    return bundle


def test_happy_path_build_and_verify(tmp_path):
    bundle = _build(tmp_path)
    proc = subprocess.run(
        [sys.executable, str(_PKG_ROOT / "veriker" / "cli" / "verify.py"), "--bundle-dir", str(bundle)],
        capture_output=True,
        text=True,
        env=_env(),
    )
    assert proc.returncode == 0, f"verify failed: {proc.stdout}\n{proc.stderr}"
    assert "PASS" in proc.stdout
    assert "plugin:stamp_lattice" in proc.stdout


def test_upgrade_is_actually_admitted(tmp_path):
    """In-process: the C14 plugin must ADMIT exactly one verifier-signed upgrade
    (not silently no-op the way an all-null-stamp bundle does)."""
    bundle = _build(tmp_path)
    from audit_bundle.bundle_manifest import BundleManifest
    from audit_bundle.discharge.verifier_signing import VerifierSigningKey
    from audit_bundle.plugins.stamp_lattice import StampLatticeCheck

    raw = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    manifest = BundleManifest(
        schema_version=raw["schema_version"],
        bundle_id=raw["bundle_id"],
        created_at=raw["created_at"],
        files=raw["files"],
        spec_files=raw["spec_files"],
        cross_refs=raw["cross_refs"],
        payload=raw["payload"],
        typed_checks=raw["typed_checks"],
        dispatch_records=tuple(raw["dispatch_records"]),
        aggregate_stamp=raw.get("aggregate_stamp"),
    )
    key = VerifierSigningKey.from_secret_bytes(_DEMO_KEY.encode("utf-8"))
    result = StampLatticeCheck(recheck_key=key).check(bundle, manifest)

    assert result.ok is True, result.detail
    assert result.reason_code == "PASS"
    assert "1 verifier-signed upgrade" in result.detail
    # Aggregate is pinned to the weakest UN-upgraded row, not laundered up.
    assert raw["aggregate_stamp"] == "COMPOSED_HYPOTHESIS"


def test_tamper_scenarios_all_rejected(tmp_path):
    """The demo runner self-verifies 1 honest PASS + 4 tamper rejections."""
    _build(tmp_path)  # ensure the on-disk bundle exists for the demo runner
    proc = subprocess.run(
        [sys.executable, str(_PILOT / "demo" / "run_upgrade_demo.py")],
        capture_output=True,
        text=True,
        env=_env(),
    )
    assert proc.returncode == 0, f"demo failed:\n{proc.stdout}\n{proc.stderr}"
    assert "ALL SCENARIOS BEHAVED AS EXPECTED" in proc.stdout
