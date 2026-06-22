"""Round-trip integration tests for examples/fintech_audit_minimal.

Test flow:
  1. Build a clean bundle from synthetic fixtures into a temp directory.
  2. Run the verifier with the pilot's plugin set.
  3. Assert result.ok is True and stdout contains "PASS".
  4. Tamper test A: mutate a transaction field value so the re-derived verdict
     differs from the bundled verdict. Assert result.ok is False with
     POLICY_REDERIVATION_MISMATCH in the failures.
  5. Tamper test B: mutate a transaction file's bytes so its SHA-256 no longer
     matches the manifest. Assert result.ok is False with BAD_FILE_SHA.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path setup — mirrors the auditor-independence pattern
# ---------------------------------------------------------------------------

_PKG_ROOT = Path(__file__).resolve().parents[3]   # v-kernel-audit-bundle/
_PILOT_DIR = _PKG_ROOT / "examples" / "fintech_audit_minimal"

if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

# ---------------------------------------------------------------------------
# Lazy imports (after path setup)
# ---------------------------------------------------------------------------

from examples.fintech_audit_minimal._build_bundle import build  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from PolicyRuleReDerivationCheck import PolicyRuleReDerivationCheck  # noqa: E402


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(plugins=[
        FileIntegrityManySmall(),
        PolicyRuleReDerivationCheck(),
    ])


# ---------------------------------------------------------------------------
# Gate 2 smoke: verify.py script produces "PASS" on stdout
# ---------------------------------------------------------------------------


def test_verify_script_prints_pass(tmp_path: Path) -> None:
    """verify.py --bundle-dir <clean_bundle> must exit 0 and print PASS."""
    bundle_dir = tmp_path / "fintech_bundle_script"
    build(bundle_dir)

    verify_script = _PILOT_DIR / "verify.py"
    result = subprocess.run(
        [sys.executable, str(verify_script), "--bundle-dir", str(bundle_dir)],
        capture_output=True,
        timeout=60,
    )
    stdout = result.stdout.decode("utf-8", errors="replace")
    assert result.returncode == 0, (
        f"verify.py exited {result.returncode}; stderr: "
        f"{result.stderr.decode('utf-8', errors='replace')[:400]}"
    )
    assert "PASS" in stdout, f"Expected 'PASS' in stdout; got: {stdout!r}"


# ---------------------------------------------------------------------------
# Happy-path
# ---------------------------------------------------------------------------


def test_clean_bundle_passes(tmp_path: Path) -> None:
    """build + verify on a clean bundle must return result.ok == True."""
    bundle_dir = tmp_path / "fintech_bundle"
    build(bundle_dir)
    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is True, (
        f"expected ok=True; failures: {result.failures}"
    )


def test_bundle_contains_expected_verdicts(tmp_path: Path) -> None:
    """payload/policy_verdicts.json must contain both matched and NOT_APPLICABLE verdicts."""
    bundle_dir = tmp_path / "fintech_bundle_v"
    build(bundle_dir)
    verdicts = json.loads(
        (bundle_dir / "payload" / "policy_verdicts.json").read_text(encoding="utf-8")
    )
    verdict_values = [v["verdict"] for v in verdicts]
    assert any(v != "NOT_APPLICABLE" for v in verdict_values), (
        "Expected at least one matched verdict"
    )
    assert any(v == "NOT_APPLICABLE" for v in verdict_values), (
        "Expected at least one NOT_APPLICABLE verdict"
    )


def test_bundle_fragment_anchors_present(tmp_path: Path) -> None:
    """manifest.json must include fragment_anchors for matched condition fields."""
    bundle_dir = tmp_path / "fintech_bundle_f"
    build(bundle_dir)
    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    anchors = manifest.get("fragment_anchors", {})
    assert len(anchors) > 0, "Expected at least one fragment anchor in manifest"
    # Every anchor must parse as a ByteOffsetFragment (kind=byte_offset)
    for anchor_name, frag_dict in anchors.items():
        assert frag_dict.get("kind") == "byte_offset", (
            f"Anchor {anchor_name!r} has unexpected kind: {frag_dict.get('kind')!r}"
        )
        assert frag_dict.get("start", -1) >= 0
        assert frag_dict.get("end", 0) > frag_dict.get("start", 0)


# ---------------------------------------------------------------------------
# Tamper test A — mutate verdict so re-derivation disagrees
# ---------------------------------------------------------------------------


def test_tamper_verdict_fails(tmp_path: Path) -> None:
    """Flipping a verdict value in payload/policy_verdicts.json must trigger
    POLICY_REDERIVATION_MISMATCH (the re-derived verdict won't match)."""
    bundle_dir = tmp_path / "fintech_bundle_tamper_a"
    build(bundle_dir)

    # Flip the first non-NOT_APPLICABLE verdict to something wrong
    verdicts_path = bundle_dir / "payload" / "policy_verdicts.json"
    verdicts = json.loads(verdicts_path.read_text(encoding="utf-8"))

    tampered = False
    for rec in verdicts:
        if rec["verdict"] != "NOT_APPLICABLE":
            rec["verdict"] = "ALLOWED"   # wrong value; re-derivation will disagree
            tampered = True
            break
    assert tampered, "Fixture must contain at least one non-NOT_APPLICABLE verdict"

    verdicts_path.write_bytes(
        json.dumps(verdicts, indent=2, sort_keys=True).encode("utf-8")
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "Expected ok=False after tampering verdict value"
    )
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    # The outer VerifyFailure.reason_code is always 'plugin_failed'; the inner
    # re-derivation error text is embedded in the detail field.
    assert "POLICY_REDERIV" in combined or "VERDICT MISMATCH" in combined, (
        f"Expected POLICY_REDERIV or VERDICT MISMATCH in failures; got: {result.failures}"
    )


# ---------------------------------------------------------------------------
# Tamper test B — mutate transaction bytes so SHA check fails
# ---------------------------------------------------------------------------


def test_tamper_transaction_sha_fails(tmp_path: Path) -> None:
    """Mutating a transaction file's bytes so SHA-256 no longer matches the manifest
    must trigger BAD_FILE_SHA from FileIntegrityManySmall."""
    bundle_dir = tmp_path / "fintech_bundle_tamper_b"
    build(bundle_dir)

    # Overwrite txn-001.json with slightly different bytes
    txn_path = bundle_dir / "transactions" / "txn-001.json"
    original = txn_path.read_bytes()
    # Replace amount to change bytes without breaking JSON parse
    tampered = original.replace(b"95000.0", b"95001.0")
    assert tampered != original, "Tamper did not change bytes — check amount field"
    txn_path.write_bytes(tampered)

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "Expected ok=False after tampering transaction bytes"
    )
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    assert "BAD_FILE_SHA" in combined or "POLICY_REDERIV" in combined, (
        f"Expected BAD_FILE_SHA or POLICY_REDERIV in failures; got: {result.failures}"
    )


# ---------------------------------------------------------------------------
# Re-derivation pack standalone
# ---------------------------------------------------------------------------


def test_re_derivation_pack_exits_zero(tmp_path: Path) -> None:
    """policy_re_derivation.py --bundle-dir <clean_bundle> must exit 0."""
    bundle_dir = tmp_path / "fintech_bundle_rd"
    build(bundle_dir)

    pack = _PILOT_DIR / "policy_re_derivation.py"
    result = subprocess.run(
        [sys.executable, str(pack), "--bundle-dir", str(bundle_dir)],
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        f"policy_re_derivation.py exited {result.returncode}; stderr: "
        f"{result.stderr.decode('utf-8', errors='replace')[:400]}"
    )


def test_re_derivation_pack_fails_on_tampered_verdict(tmp_path: Path) -> None:
    """policy_re_derivation.py must exit non-zero when verdict is wrong."""
    bundle_dir = tmp_path / "fintech_bundle_rd_tamper"
    build(bundle_dir)

    verdicts_path = bundle_dir / "payload" / "policy_verdicts.json"
    verdicts = json.loads(verdicts_path.read_text(encoding="utf-8"))
    for rec in verdicts:
        if rec["verdict"] != "NOT_APPLICABLE":
            rec["verdict"] = "WRONG"
            break
    verdicts_path.write_bytes(
        json.dumps(verdicts, indent=2, sort_keys=True).encode("utf-8")
    )

    pack = _PILOT_DIR / "policy_re_derivation.py"
    result = subprocess.run(
        [sys.executable, str(pack), "--bundle-dir", str(bundle_dir)],
        capture_output=True,
        timeout=60,
    )
    assert result.returncode != 0, (
        "Expected non-zero exit from policy_re_derivation.py on tampered verdict"
    )
