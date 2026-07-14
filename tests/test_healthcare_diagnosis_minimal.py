"""Round-trip integration test for examples/healthcare_diagnosis_minimal.

Test flow:
  1. Import _build_bundle.build from the pilot directory dynamically (so the
     test does not depend on the pilot being a Python package).
  2. Build the bundle into a tmp_path (out-of-tree fresh build).
  3. Run the verifier with the pilot's plugin set (file_integrity_many_small +
     re_derivation_invocation + HealthcareDiagnosisReDerivationCheck).
  4. Assert result.ok is True on the clean bundle.
  5. Tamper-confidence: mutate payload/diagnosis.json confidence + re-align the
     manifest SHA so file integrity passes but the re-derivation catches the
     numerical mismatch.
  6. Tamper-symptom-sha: mutate inputs/symptoms.json severity WITHOUT updating
     the manifest SHA, so file_integrity_many_small catches the SHA divergence.

All three test cases match the SKILL.md tamper-test discipline (one SHA-bypass
catch, one re-derivation catch).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

# Suppress .pyc generation so the pilot dir stays clean even if a test triggers
# a pyc-write into __pycache__ inside the bundle.
sys.dont_write_bytecode = True

# ---------------------------------------------------------------------------
# Paths + dynamic import of pilot modules
# ---------------------------------------------------------------------------

_PKG_ROOT = Path(__file__).resolve().parents[1]  # v-kernel-audit-bundle/
_PILOT_DIR = _PKG_ROOT / "examples" / "healthcare_diagnosis_minimal"

if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
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
    "healthcare_diagnosis_minimal._build_bundle",
    _PILOT_DIR / "_build_bundle.py",
)
_hcd_check_mod = _import_module_from_path(
    "HealthcareDiagnosisReDerivationCheck",
    _PILOT_DIR / "HealthcareDiagnosisReDerivationCheck.py",
)

from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.re_derivation_invocation import ReDerivationInvocationCheck  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402

HealthcareDiagnosisReDerivationCheck = (
    _hcd_check_mod.HealthcareDiagnosisReDerivationCheck
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_verifier() -> BundleVerifier:
    """Pilot plugin set: file integrity + re-derivation (substrate + pilot)."""
    return BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            ReDerivationInvocationCheck(pack_filename="healthcare_diagnosis_pack.py", permit_execution=True),
            HealthcareDiagnosisReDerivationCheck(),
        ]
    )


def _build_clean(tmp_path: Path) -> Path:
    """Build a fresh bundle out-of-tree (--out-dir to tmp_path)."""
    bundle_dir = tmp_path / "hcd_bundle"
    _build_bundle_mod.build(bundle_dir)
    return bundle_dir


def _canonical_bytes(obj) -> bytes:
    return (
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _patch_manifest_sha(manifest_path: Path, rel: str, new_sha: str) -> None:
    """Re-align manifest.files[rel] to new_sha — used in tamper tests where we
    want file_integrity to pass and re-derivation to catch the divergence."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][rel] = new_sha
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Happy-path test
# ---------------------------------------------------------------------------


def test_clean_bundle_passes(tmp_path: Path) -> None:
    """Build + verify on a clean bundle must return result.ok == True."""
    bundle_dir = _build_clean(tmp_path)
    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is True, (
        f"expected ok=True on clean bundle; failures: {result.failures}"
    )


def test_clean_bundle_shape(tmp_path: Path) -> None:
    """Bundle layout: 4 ICD-10 candidates, ~10 OpaqueFragment evidence anchors."""
    bundle_dir = _build_clean(tmp_path)
    manifest = json.loads((bundle_dir / "manifest.json").read_text("utf-8"))
    diagnosis = json.loads(
        (bundle_dir / "payload" / "diagnosis.json").read_text("utf-8")
    )

    assert len(diagnosis) == 4, f"expected 4 ICD-10 candidates; got {len(diagnosis)}"

    anchors = manifest.get("fragment_anchors", {})
    assert 8 <= len(anchors) <= 12, (
        f"expected ~10 evidence anchors (8..12); got {len(anchors)}"
    )
    # Every anchor must be an OpaqueFragment with the icd10_evidence_anchor kind_tag.
    for key, a in anchors.items():
        assert a["kind"] == "opaque", f"anchor {key} not OpaqueFragment: {a}"
        assert a["kind_tag"] == "icd10_evidence_anchor", (
            f"anchor {key} kind_tag wrong: {a['kind_tag']!r}"
        )
        for required in ("rule_id", "symptom_id", "icd10_code"):
            assert required in a["locator"], (
                f"anchor {key} locator missing {required}: {a['locator']!r}"
            )

    # Manifest typed_checks names the two registered substrate plugins.
    tc = manifest.get("typed_checks", [])
    assert "file_integrity_many_small" in tc
    assert "re_derivation_invocation" in tc


# ---------------------------------------------------------------------------
# Tamper tests — minimum 3 per SKILL.md
# ---------------------------------------------------------------------------


def test_tamper_confidence_fails(tmp_path: Path) -> None:
    """Mutating an ICD-10 candidate's confidence (with manifest SHA re-aligned)
    must cause re-derivation mismatch — file_integrity passes, re-derivation fails."""
    bundle_dir = _build_clean(tmp_path)

    diag_path = bundle_dir / "payload" / "diagnosis.json"
    diagnosis = json.loads(diag_path.read_text(encoding="utf-8"))
    # Pick the first candidate and inflate its confidence by a large delta so
    # the re-derivation cannot round-trip back to it.
    diagnosis[0]["confidence"] = round(float(diagnosis[0]["confidence"]) + 99.0, 6)
    tampered_bytes = _canonical_bytes(diagnosis)
    diag_path.write_bytes(tampered_bytes)

    _patch_manifest_sha(
        bundle_dir / "manifest.json",
        "payload/diagnosis.json",
        hashlib.sha256(tampered_bytes).hexdigest(),
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False after inflating a candidate's confidence"
    )
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures).upper()
    assert (
        "HCD_REDER_FAIL" in combined
        or "RE_DERIVATION_MISMATCH" in combined
        or "HEALTHCARE_REDERIVATION_MISMATCH" in combined
    ), f"expected re-derivation failure; got: {result.failures}"


def test_tamper_symptom_sha_fails(tmp_path: Path) -> None:
    """Mutating inputs/symptoms.json severity WITHOUT updating manifest SHA
    must cause file_integrity to catch the SHA divergence."""
    bundle_dir = _build_clean(tmp_path)

    sym_path = bundle_dir / "inputs" / "symptoms.json"
    symptoms = json.loads(sym_path.read_text(encoding="utf-8"))
    # Drop fever (sym-002) severity from 4 to 1 — rule-J18 and rule-A49 should
    # stop firing once the re-derivation runs. But manifest SHA is NOT updated
    # so file_integrity catches it first.
    for s in symptoms:
        if s["symptom_id"] == "sym-002":
            s["severity"] = 1
            break
    sym_path.write_bytes(_canonical_bytes(symptoms))
    # Intentionally do NOT update the manifest SHA — file_integrity must fail.

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False after mutating symptoms.json without re-aligning manifest SHA"
    )
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures).upper()
    assert "BAD_FILE_SHA" in combined or "FILE_INTEGRITY" in combined, (
        f"expected BAD_FILE_SHA / file_integrity failure; got: {result.failures}"
    )


def test_tamper_symptom_severity_with_sha_realigned_fails(tmp_path: Path) -> None:
    """Bonus: mutate symptoms severity AND re-align the manifest SHA — now
    file_integrity passes but re-derivation catches the change because the
    bundled diagnosis was built against the ORIGINAL severities."""
    bundle_dir = _build_clean(tmp_path)

    sym_path = bundle_dir / "inputs" / "symptoms.json"
    symptoms = json.loads(sym_path.read_text(encoding="utf-8"))
    # Drop fever severity 4 -> 1; this changes confidence of any rule using sym-002
    # AND likely stops rule-J18 / rule-A49 from firing in re-derivation.
    for s in symptoms:
        if s["symptom_id"] == "sym-002":
            s["severity"] = 1
            break
    tampered_bytes = _canonical_bytes(symptoms)
    sym_path.write_bytes(tampered_bytes)
    _patch_manifest_sha(
        bundle_dir / "manifest.json",
        "inputs/symptoms.json",
        hashlib.sha256(tampered_bytes).hexdigest(),
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False — re-derivation must catch the severity mutation"
    )
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures).upper()
    assert (
        "HCD_REDER_FAIL" in combined
        or "RE_DERIVATION_MISMATCH" in combined
        or "HEALTHCARE_REDERIVATION_MISMATCH" in combined
    ), f"expected re-derivation failure; got: {result.failures}"
