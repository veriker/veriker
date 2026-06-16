"""Round-trip integration test for examples/pe_engineering_signoff_minimal/verify.py.

Test flow:
  1. Import _build_bundle.build from the pilot directory.
  2. Build the bundle into a tmp_path.
  3. Run the verifier with the pilot's plugin set.
  4. Assert result.ok is True.

  Structural checks:
  5. Manifest must contain OpaqueFragment(kind_tag=engineering_assumption) anchors (>= 5).
  6. Manifest must contain the three expected dispatch op kinds.
  7. Manifest must reference decision_provenance_log.
  8. Provenance log must have one row per analysis.
  9. All three verdict states must be present (stamped_unconditional, stamped_with_limitations,
     refused).

  Tamper test A — re-derivation surface:
  10. Mutate load_N in inputs/analyses.json to shift σ_max and FoS.
  11. Re-align manifest SHA so FileIntegrityManySmall passes.
  12. Re-run verifier — assert result.ok is False with PE_ENGINEERING_REDERIVATION_MISMATCH.

  Tamper test B — PE-stamp HMAC surface:
  13. Flip stamp_verdict in a pe_stamp_provenance row from stamped_unconditional to refused
      WITHOUT recomputing its HMAC; re-align manifest SHA.
  14. Re-run verifier — assert result.ok is False with PE_STAMP_INVALID.
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
_PILOT_DIR = _PKG_ROOT / "examples" / "pe_engineering_signoff_minimal"

# Insert pkg root so audit_bundle.* imports work in the test process.
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# Insert pilot dir so PeEngineeringSignoffReDerivationCheck can be imported directly.
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
    "pe_engineering_signoff_minimal._build_bundle",
    _PILOT_DIR / "_build_bundle.py",
)
_check_mod = _import_module_from_path(
    "PeEngineeringSignoffReDerivationCheck",
    _PILOT_DIR / "PeEngineeringSignoffReDerivationCheck.py",
)

from audit_bundle.plugins.dispatch_record_wellformed import (
    DispatchRecordWellformedCheck,
)
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck
from audit_bundle.verifier import BundleVerifier

PeEngineeringSignoffReDerivationCheck = _check_mod.PeEngineeringSignoffReDerivationCheck


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            PeEngineeringSignoffReDerivationCheck(),
            DispatchRecordWellformedCheck(
                op_kinds_admitted=frozenset({"FEA_SOLVE", "PE_STAMP", "COMPUTE"})
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


def test_pe_engineering_signoff_minimal_build_and_verify(tmp_path: Path) -> None:
    """Build a fresh bundle and verify it — result.ok must be True."""
    bundle_dir = tmp_path / "pe_eng_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is True, "Expected result.ok=True; failures:\n" + "\n".join(
        f"  [{f.check_name}] {f.reason_code}: {f.detail}" for f in result.failures
    )


def test_pe_engineering_signoff_minimal_manifest_has_engineering_assumption_fragments(
    tmp_path: Path,
) -> None:
    """The built manifest must contain OpaqueFragment(kind_tag=engineering_assumption) anchors."""
    bundle_dir = tmp_path / "pe_eng_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    anchors = manifest.get("fragment_anchors", {})

    eng_frags = [
        v
        for v in anchors.values()
        if v.get("kind") == "opaque" and v.get("kind_tag") == "engineering_assumption"
    ]
    assert len(eng_frags) >= 5, (
        f"Expected >= 5 OpaqueFragment(kind_tag=engineering_assumption) anchors; "
        f"got {len(eng_frags)}"
    )


def test_pe_engineering_signoff_minimal_manifest_has_dispatch_records(
    tmp_path: Path,
) -> None:
    """The built manifest must contain the three expected op kinds."""
    bundle_dir = tmp_path / "pe_eng_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    records = manifest.get("dispatch_records", [])
    kinds = {r.get("op", {}).get("kind") for r in records}

    assert "FEA_SOLVE" in kinds, (
        f"Expected FEA_SOLVE dispatch record; found kinds: {kinds}"
    )
    assert "PE_STAMP" in kinds, (
        f"Expected PE_STAMP dispatch record; found kinds: {kinds}"
    )
    assert "COMPUTE" in kinds, f"Expected COMPUTE dispatch record; found kinds: {kinds}"


def test_pe_engineering_signoff_minimal_manifest_has_decision_provenance_log(
    tmp_path: Path,
) -> None:
    """The built manifest must reference decision_provenance_log."""
    bundle_dir = tmp_path / "pe_eng_bundle"
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


def test_pe_engineering_signoff_minimal_provenance_rows_count(tmp_path: Path) -> None:
    """The provenance log must have one row per analysis."""
    bundle_dir = tmp_path / "pe_eng_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    outputs = json.loads(
        (bundle_dir / "payload" / "engineering_analyses.json").read_text(
            encoding="utf-8"
        )
    )
    prov_path = bundle_dir / "payload" / "pe_stamp_provenance.jsonl"
    rows = [
        json.loads(line)
        for line in prov_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(rows) == len(outputs), (
        f"Expected {len(outputs)} provenance rows; got {len(rows)}"
    )


def test_pe_engineering_signoff_minimal_all_three_verdict_states(
    tmp_path: Path,
) -> None:
    """Provenance log must cover stamped_unconditional, stamped_with_limitations, refused."""
    bundle_dir = tmp_path / "pe_eng_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    prov_path = bundle_dir / "payload" / "pe_stamp_provenance.jsonl"
    rows = [
        json.loads(line)
        for line in prov_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    verdicts = {r["stamp_verdict"] for r in rows}

    assert "stamped_unconditional" in verdicts, (
        f"Expected stamped_unconditional in verdicts; got {verdicts}"
    )
    assert "stamped_with_limitations" in verdicts, (
        f"Expected stamped_with_limitations in verdicts; got {verdicts}"
    )
    assert "refused" in verdicts, f"Expected refused in verdicts; got {verdicts}"


# ---------------------------------------------------------------------------
# Tamper A: mutate load_N → PE_ENGINEERING_REDERIVATION_MISMATCH
# ---------------------------------------------------------------------------


def test_pe_engineering_signoff_minimal_tamper_load_fails_rederivation(
    tmp_path: Path,
) -> None:
    """Mutating load_N in inputs/analyses.json must cause PE_ENGINEERING_REDERIVATION_MISMATCH
    even when the manifest SHA is re-aligned."""
    bundle_dir = tmp_path / "pe_eng_tampered_a"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    # Mutate first analysis's load_N to change σ_max and FoS
    analyses_path = bundle_dir / "inputs" / "analyses.json"
    analyses = json.loads(analyses_path.read_text(encoding="utf-8"))
    assert len(analyses) >= 1
    original_load = analyses[0]["load_N"]
    analyses[0]["load_N"] = original_load * 10.0  # 10x load → very different stress
    analyses_path.write_text(
        json.dumps(analyses, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    # Re-align manifest SHA so FileIntegrityManySmall passes and doesn't mask the failure
    _realign_manifest_sha(bundle_dir, "inputs/analyses.json")

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "Expected result.ok=False after tampering inputs/analyses.json load_N"
    )

    reason_codes = [f.reason_code for f in result.failures]
    detail_texts = [f.detail for f in result.failures]
    combined = " ".join(reason_codes + detail_texts).upper()
    assert "PE_ENGINEERING_REDERIVATION_MISMATCH" in combined, (
        f"Expected PE_ENGINEERING_REDERIVATION_MISMATCH in failures; "
        f"got reason_codes={reason_codes!r}"
    )


# ---------------------------------------------------------------------------
# Tamper B: flip stamp_verdict without recomputing HMAC → PE_STAMP_INVALID
# ---------------------------------------------------------------------------


def test_pe_engineering_signoff_minimal_tamper_stamp_verdict_fails_attestation(
    tmp_path: Path,
) -> None:
    """Flipping stamp_verdict in a provenance row without recomputing its HMAC must
    cause PE_STAMP_INVALID even when the manifest SHA is re-aligned
    (distinct from FileSHAMismatch)."""
    bundle_dir = tmp_path / "pe_eng_tampered_b"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    # Find a row with stamp_verdict='stamped_unconditional' and flip to 'refused'
    prov_path = bundle_dir / "payload" / "pe_stamp_provenance.jsonl"
    lines = prov_path.read_text(encoding="utf-8").splitlines()

    flipped = False
    for i, line in enumerate(lines):
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("stamp_verdict") == "stamped_unconditional":
            row["stamp_verdict"] = "refused"  # flip without recomputing HMAC
            lines[i] = json.dumps(row, sort_keys=True)
            flipped = True
            break

    assert flipped, "No 'stamped_unconditional' row found in provenance log to tamper"
    prov_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Re-align manifest SHA so FileIntegrityManySmall does NOT catch this first
    _realign_manifest_sha(bundle_dir, "payload/pe_stamp_provenance.jsonl")

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "Expected result.ok=False after flipping stamp_verdict without recomputing HMAC"
    )

    reason_codes = [f.reason_code for f in result.failures]
    detail_texts = [f.detail for f in result.failures]
    combined = " ".join(reason_codes + detail_texts).upper()
    assert "PE_STAMP_INVALID" in combined, (
        f"Expected PE_STAMP_INVALID in failures; "
        f"got reason_codes={reason_codes!r}, details={detail_texts!r}"
    )
