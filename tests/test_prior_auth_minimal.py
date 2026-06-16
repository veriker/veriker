"""Round-trip integration test for examples/prior_auth_minimal/verify.py.

Test flow:
  1. Import _build_bundle.build from the pilot directory.
  2. Build the bundle into a tmp_path.
  3. Run the verifier with the pilot's plugin set.
  4. Assert result.ok is True.
  5. Tamper test A: mutate clinical/findings.jsonl to shift the decision-tree
     verdict; re-align manifest SHA so FileIntegrityManySmall passes.
  6. Re-run verifier — assert result.ok is False with PRIOR_AUTH_REDERIVATION_MISMATCH.
  7. Tamper test B: flip provider_verdict in a provenance row WITHOUT recomputing
     its HMAC; re-align manifest SHA so FileIntegrityManySmall passes.
  8. Re-run verifier — assert result.ok is False with
     PRIOR_AUTH_PROVIDER_ATTESTATION_INVALID.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths + dynamic import of pilot modules
# ---------------------------------------------------------------------------

_PKG_ROOT = Path(__file__).resolve().parents[1]  # v-kernel-audit-bundle/
_PILOT_DIR = _PKG_ROOT / "examples" / "prior_auth_minimal"

# Insert pkg root so audit_bundle.* imports work in the test process.
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# Insert pilot dir so PriorAuthReDerivationCheck can be imported directly.
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))


def _import_module_from_path(name: str, path: Path):
    """Dynamically import a module from an absolute path."""
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_build_bundle_mod = _import_module_from_path(
    "prior_auth_minimal._build_bundle",
    _PILOT_DIR / "_build_bundle.py",
)
_check_mod = _import_module_from_path(
    "PriorAuthReDerivationCheck",
    _PILOT_DIR / "PriorAuthReDerivationCheck.py",
)

from audit_bundle.plugins.dispatch_record_wellformed import (
    DispatchRecordWellformedCheck,
)
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck
from audit_bundle.verifier import BundleVerifier

PriorAuthReDerivationCheck = _check_mod.PriorAuthReDerivationCheck


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            PriorAuthReDerivationCheck(),
            DispatchRecordWellformedCheck(
                op_kinds_admitted=frozenset(
                    {"MEDICAL_NECESSITY_EVAL", "PROVIDER_ATTEST", "COMPUTE"}
                )
            ),
            StampLatticeCheck(),
        ]
    )


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _realign_manifest_sha(bundle_dir: Path, rel_path: str) -> None:
    """Recompute the SHA of a mutated file and update manifest.files in place."""
    fpath = bundle_dir / rel_path
    new_sha = _sha256_file(fpath)
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][rel_path] = new_sha
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Happy path: clean bundle
# ---------------------------------------------------------------------------


def test_prior_auth_minimal_build_and_verify(tmp_path: Path) -> None:
    """Build a fresh bundle and verify it — result.ok must be True."""
    bundle_dir = tmp_path / "prior_auth_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is True, "Expected result.ok=True; failures:\n" + "\n".join(
        f"  [{f.check_name}] {f.reason_code}: {f.detail}" for f in result.failures
    )


def test_prior_auth_minimal_manifest_has_clinical_finding_fragments(
    tmp_path: Path,
) -> None:
    """The built manifest must contain OpaqueFragment(kind_tag=clinical_finding) anchors."""
    bundle_dir = tmp_path / "prior_auth_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    anchors = manifest.get("fragment_anchors", {})

    clinical_frags = [
        v
        for v in anchors.values()
        if v.get("kind") == "opaque" and v.get("kind_tag") == "clinical_finding"
    ]
    assert len(clinical_frags) >= 3, (
        f"Expected >= 3 OpaqueFragment(kind_tag=clinical_finding) anchors; "
        f"got {len(clinical_frags)}"
    )


def test_prior_auth_minimal_manifest_has_dispatch_records(tmp_path: Path) -> None:
    """The built manifest must contain the three expected op kinds."""
    bundle_dir = tmp_path / "prior_auth_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    records = manifest.get("dispatch_records", [])
    kinds = {r.get("op", {}).get("kind") for r in records}

    assert "MEDICAL_NECESSITY_EVAL" in kinds, (
        f"Expected MEDICAL_NECESSITY_EVAL dispatch record; found kinds: {kinds}"
    )
    assert "PROVIDER_ATTEST" in kinds, (
        f"Expected PROVIDER_ATTEST dispatch record; found kinds: {kinds}"
    )
    assert "COMPUTE" in kinds, f"Expected COMPUTE dispatch record; found kinds: {kinds}"


def test_prior_auth_minimal_manifest_has_decision_provenance_log(
    tmp_path: Path,
) -> None:
    """The built manifest must reference decision_provenance_log."""
    bundle_dir = tmp_path / "prior_auth_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    prov_log = manifest.get("decision_provenance_log")

    assert prov_log is not None, (
        "Expected decision_provenance_log to be set in manifest"
    )
    assert (bundle_dir / prov_log).exists(), (
        f"decision_provenance_log={prov_log!r} referenced in manifest does not exist"
    )


def test_prior_auth_minimal_provenance_rows_count(tmp_path: Path) -> None:
    """The provenance log must have one row per decision."""
    bundle_dir = tmp_path / "prior_auth_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    decisions = json.loads(
        (bundle_dir / "payload" / "prior_auth_decisions.json").read_text(
            encoding="utf-8"
        )
    )
    prov_path = bundle_dir / "payload" / "decision_provenance.jsonl"
    rows = [
        json.loads(line)
        for line in prov_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(rows) == len(decisions), (
        f"Expected {len(decisions)} provenance rows; got {len(rows)}"
    )


# ---------------------------------------------------------------------------
# Tamper A: mutate clinical_finding content → PRIOR_AUTH_REDERIVATION_MISMATCH
# ---------------------------------------------------------------------------


def test_prior_auth_minimal_tamper_finding_fails_rederivation(tmp_path: Path) -> None:
    """Mutating a diagnosis in clinical/findings.jsonl must cause
    PRIOR_AUTH_REDERIVATION_MISMATCH even when the manifest SHA is re-aligned."""
    bundle_dir = tmp_path / "prior_auth_tampered_a"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    # Mutate first request's diagnoses to an unknown code so rule-MRI-spine stops firing
    findings_path = bundle_dir / "clinical" / "findings.jsonl"
    lines = findings_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 1
    first_req = json.loads(lines[0])
    first_req["diagnoses"] = ["Z99.99"]  # unknown code — no rule will match
    lines[0] = json.dumps(first_req, sort_keys=True)
    findings_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Re-align manifest SHA so FileIntegrityManySmall passes and doesn't mask the failure
    _realign_manifest_sha(bundle_dir, "clinical/findings.jsonl")

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "Expected result.ok=False after tampering clinical/findings.jsonl"
    )

    reason_codes = [f.reason_code for f in result.failures]
    detail_texts = [f.detail for f in result.failures]
    combined = " ".join(reason_codes + detail_texts).upper()
    assert "PRIOR_AUTH_REDERIVATION_MISMATCH" in combined, (
        f"Expected PRIOR_AUTH_REDERIVATION_MISMATCH in failures; "
        f"got reason_codes={reason_codes!r}"
    )


# ---------------------------------------------------------------------------
# Tamper B: flip provider_verdict without recomputing HMAC →
#           PRIOR_AUTH_PROVIDER_ATTESTATION_INVALID
# ---------------------------------------------------------------------------


def test_prior_auth_minimal_tamper_verdict_fails_attestation(tmp_path: Path) -> None:
    """Flipping provider_verdict in a provenance row without recomputing its HMAC must
    cause PRIOR_AUTH_PROVIDER_ATTESTATION_INVALID even when the manifest SHA is
    re-aligned (distinct from FileSHAMismatch)."""
    bundle_dir = tmp_path / "prior_auth_tampered_b"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    # Find a row with provider_verdict='approve' and flip it to 'deny'
    prov_path = bundle_dir / "payload" / "decision_provenance.jsonl"
    lines = prov_path.read_text(encoding="utf-8").splitlines()

    flipped = False
    for i, line in enumerate(lines):
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("provider_verdict") == "approve":
            row["provider_verdict"] = "deny"  # flip without recomputing HMAC
            lines[i] = json.dumps(row, sort_keys=True)
            flipped = True
            break

    assert flipped, "No 'approve' row found in provenance log to tamper"
    prov_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Re-align manifest SHA so FileIntegrityManySmall does NOT catch this first
    _realign_manifest_sha(bundle_dir, "payload/decision_provenance.jsonl")

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "Expected result.ok=False after flipping provider_verdict without recomputing HMAC"
    )

    reason_codes = [f.reason_code for f in result.failures]
    detail_texts = [f.detail for f in result.failures]
    combined = " ".join(reason_codes + detail_texts).upper()
    assert "PRIOR_AUTH_PROVIDER_ATTESTATION_INVALID" in combined, (
        f"Expected PRIOR_AUTH_PROVIDER_ATTESTATION_INVALID in failures; "
        f"got reason_codes={reason_codes!r}, details={detail_texts!r}"
    )
