"""test_pharmacophore_fit_minimal.py — happy-path + tamper tests for pharmacophore_fit_minimal.

Mirrors the test structure of test_combi_screen_minimal.py:
- Build the bundle from scratch into a tmp_path
- Verify it passes (PASS / exit 0)
- Apply tampers, re-align manifest, re-verify, assert failure with expected reason

Runs as part of the pilot's four-gate success criteria (gate 3).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

_PRODUCT_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PRODUCT_ROOT / "examples" / "pharmacophore_fit_minimal"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_VERIFY_SCRIPT = _PILOT_DIR / "verify.py"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, cwd=_PRODUCT_ROOT)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _re_align_manifest_sha(bundle_dir: Path, rel_path: str) -> None:
    """Re-write the manifest with the post-tamper SHA for the given file."""
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    file_bytes = (bundle_dir / rel_path).read_bytes()
    manifest["files"][rel_path] = _sha256(file_bytes)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Build + verify (happy path)
# ---------------------------------------------------------------------------


def test_build_and_verify_pass(tmp_path: Path) -> None:
    bundle_dir = tmp_path / "pharma_fit_bundle"

    build = _run([sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(bundle_dir)])
    assert build.returncode == 0, (
        f"build failed: stdout={build.stdout!r}, stderr={build.stderr!r}"
    )

    verify = _run([sys.executable, str(_VERIFY_SCRIPT), "--bundle-dir", str(bundle_dir)])
    assert verify.returncode == 0, (
        f"verify failed: stdout={verify.stdout!r}, stderr={verify.stderr!r}"
    )
    assert b"PASS" in verify.stdout


def test_bundle_structure(tmp_path: Path) -> None:
    """Sanity-check the bundle has the expected files + counts."""
    bundle_dir = tmp_path / "pharma_fit_bundle"
    build = _run([sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(bundle_dir)])
    assert build.returncode == 0

    # Expected files present
    assert (bundle_dir / "manifest.json").exists()
    assert (bundle_dir / "inputs" / "pharmacophore_template.json").exists()
    assert (bundle_dir / "inputs" / "candidate_conformers.json").exists()
    assert (bundle_dir / "inputs" / "fit_config.json").exists()
    assert (bundle_dir / "payload" / "spatial_fit_result.json").exists()

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "vcp-v1.1-canary4"
    assert manifest["bundle_id"] == "pharmacophore-fit-minimal-rc"
    assert manifest["typed_checks"] == [
        "file_integrity_many_small",
        "pharmacophore_fit_re_derivation",
        "dispatch_record_wellformed",
    ]
    # 10 advanced compounds → 10 OpaqueFragment anchors
    assert len(manifest["fragment_anchors"]) == 10
    for anchor in manifest["fragment_anchors"].values():
        assert anchor["kind"] == "opaque"
        assert anchor["kind_tag"] == "candidate_conformer"
        assert set(anchor["locator"].keys()) == {"compound_id"}
    # 1 dispatch record with op.kind=PHARMACOPHORE_FIT
    assert len(manifest["dispatch_records"]) == 1
    rec = manifest["dispatch_records"][0]
    assert rec["schema_version"] == "0.1"
    assert rec["op"]["kind"] == "PHARMACOPHORE_FIT"

    payload = json.loads(
        (bundle_dir / "payload" / "spatial_fit_result.json").read_text(encoding="utf-8")
    )
    assert payload["candidate_count"] == 20
    assert payload["scored_count"] == 20
    assert payload["advanced_count"] == 10
    assert len(payload["ledger"]) == 20
    assert len(payload["ranked"]) == 20
    assert len(payload["advanced"]) == 10
    # Ranked is RMSD-ascending
    rmsds = [e["rmsd"] for e in payload["ranked"]]
    assert rmsds == sorted(rmsds)
    # Advanced set are the 10 lowest RMSDs
    advanced_cids = {e["compound_id"] for e in payload["advanced"]}
    top10_ranked = {e["compound_id"] for e in payload["ranked"][:10]}
    assert advanced_cids == top10_ranked


# ---------------------------------------------------------------------------
# Tamper tests
# ---------------------------------------------------------------------------


def test_tamper_feature_position_caught_by_sha(tmp_path: Path) -> None:
    """Mutate a candidate's feature position WITHOUT re-aligning manifest SHA;
    file_integrity_many_small fires BAD_FILE_SHA first."""
    bundle_dir = tmp_path / "pharma_fit_bundle"
    _run([sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(bundle_dir)])

    conf_path = bundle_dir / "inputs" / "candidate_conformers.json"
    d = json.loads(conf_path.read_text(encoding="utf-8"))
    d["candidates"][0]["features"][0]["position"][0] += 1.0
    conf_path.write_text(
        json.dumps(d, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    verify = _run([sys.executable, str(_VERIFY_SCRIPT), "--bundle-dir", str(bundle_dir)])
    assert verify.returncode == 1
    assert b"bad_file_sha" in verify.stderr


def test_tamper_feature_position_caught_by_rederivation(tmp_path: Path) -> None:
    """Mutate a candidate's feature position AND re-align manifest SHA;
    pharmacophore_fit_re_derivation must fire PHARMACOPHORE_FIT_REDERIVATION_MISMATCH."""
    bundle_dir = tmp_path / "pharma_fit_bundle"
    _run([sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(bundle_dir)])

    conf_path = bundle_dir / "inputs" / "candidate_conformers.json"
    d = json.loads(conf_path.read_text(encoding="utf-8"))
    # Shift first feature of last candidate by 5 Å — large enough to change rank
    d["candidates"][-1]["features"][0]["position"][0] += 5.0
    conf_path.write_text(
        json.dumps(d, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    _re_align_manifest_sha(bundle_dir, "inputs/candidate_conformers.json")

    verify = _run([sys.executable, str(_VERIFY_SCRIPT), "--bundle-dir", str(bundle_dir)])
    assert verify.returncode == 1
    assert b"PHARMACOPHORE_FIT_REDERIVATION_MISMATCH" in verify.stderr


def test_tamper_swap_advanced_compound(tmp_path: Path) -> None:
    """Quietly swap a hit out of the advanced set in the payload + re-align SHA;
    re-derivation must catch it via advanced-set mismatch."""
    bundle_dir = tmp_path / "pharma_fit_bundle"
    _run([sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(bundle_dir)])

    result_path = bundle_dir / "payload" / "spatial_fit_result.json"
    d = json.loads(result_path.read_text(encoding="utf-8"))
    # Replace last advanced entry with a non-advanced compound_id from the ledger.
    non_advanced_cids = [
        e["compound_id"] for e in d["ledger"] if not e["advanced"]
    ]
    assert non_advanced_cids, "expected at least one non-advanced compound"
    d["advanced"][-1]["compound_id"] = non_advanced_cids[0]
    result_path.write_text(
        json.dumps(d, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    _re_align_manifest_sha(bundle_dir, "payload/spatial_fit_result.json")

    verify = _run([sys.executable, str(_VERIFY_SCRIPT), "--bundle-dir", str(bundle_dir)])
    assert verify.returncode == 1
    assert b"PHARMACOPHORE_FIT_REDERIVATION_MISMATCH" in verify.stderr


def test_tamper_mutate_bundled_rmsd(tmp_path: Path) -> None:
    """Mutate a bundled rmsd value in the ledger + re-align SHA;
    re-derivation must catch the per-candidate RMSD mismatch."""
    bundle_dir = tmp_path / "pharma_fit_bundle"
    _run([sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(bundle_dir)])

    result_path = bundle_dir / "payload" / "spatial_fit_result.json"
    d = json.loads(result_path.read_text(encoding="utf-8"))
    # Halve the rmsd of the first ledger entry — a meaningful divergence
    original_rmsd = d["ledger"][0]["rmsd"]
    d["ledger"][0]["rmsd"] = round(original_rmsd / 2.0, 6)
    result_path.write_text(
        json.dumps(d, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    _re_align_manifest_sha(bundle_dir, "payload/spatial_fit_result.json")

    verify = _run([sys.executable, str(_VERIFY_SCRIPT), "--bundle-dir", str(bundle_dir)])
    assert verify.returncode == 1
    assert b"PHARMACOPHORE_FIT_REDERIVATION_MISMATCH" in verify.stderr


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
