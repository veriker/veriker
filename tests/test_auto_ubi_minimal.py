"""Round-trip integration test for examples/auto_ubi_minimal/verify.py.

Test flow:
  1. Import _build_bundle.build from the pilot directory.
  2. Build the bundle into a tmp_path.
  3. Run the verifier with the pilot's plugin set.
  4. Assert result.ok is True.

  5. Structural tests — manifest fragment anchors and dispatch records.

  6. Tamper test (SHA): mutate a trip record's hard_brakes count so the
     trips.jsonl SHA changes. Assert the verifier returns result.ok is False
     with FileSHAMismatch / bad_file_sha in the failures list.
     This exercises FileIntegrityManySmall (§C9) tamper-evidence on telematics inputs.

  7. Tamper test (re-derivation): mutate trips.jsonl AND update manifest SHA so
     FileIntegrityManySmall passes, but the re-derived features no longer match the
     bundled rating_decisions.json. Assert result.ok is False with
     AUTO_UBI_REDERIVATION_MISMATCH surfaced.
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
_PILOT_DIR = _PKG_ROOT / "examples" / "auto_ubi_minimal"

# Insert pkg root so audit_bundle.* imports work in the test process.
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# Insert pilot dir so AutoUBIReDerivationCheck can be imported directly.
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
    "auto_ubi_minimal._build_bundle",
    _PILOT_DIR / "_build_bundle.py",
)
_ubi_check_mod = _import_module_from_path(
    "AutoUBIReDerivationCheck",
    _PILOT_DIR / "AutoUBIReDerivationCheck.py",
)

from audit_bundle.plugins.dispatch_record_wellformed import (
    DispatchRecordWellformedCheck,
)
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck
from audit_bundle.verifier import BundleVerifier

AutoUBIReDerivationCheck = _ubi_check_mod.AutoUBIReDerivationCheck


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            AutoUBIReDerivationCheck(),
            DispatchRecordWellformedCheck(
                op_kinds_admitted=frozenset({"RATE_TABLE_LOOKUP", "COMPUTE"})
            ),
            StampLatticeCheck(),
        ]
    )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Happy path: clean bundle
# ---------------------------------------------------------------------------


def test_auto_ubi_minimal_build_and_verify(tmp_path: Path) -> None:
    """Build a fresh bundle and verify it — result.ok must be True."""
    bundle_dir = tmp_path / "auto_ubi_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is True, "Expected result.ok=True; failures:\n" + "\n".join(
        f"  [{f.check_name}] {f.reason_code}: {f.detail}" for f in result.failures
    )


def test_auto_ubi_minimal_manifest_has_opaque_fragments(tmp_path: Path) -> None:
    """The built manifest must contain OpaqueFragment (kind_tag=telematics_trip) anchors."""
    bundle_dir = tmp_path / "auto_ubi_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    anchors = manifest.get("fragment_anchors", {})

    opaque_ubi = [
        v
        for v in anchors.values()
        if v.get("kind") == "opaque" and v.get("kind_tag") == "telematics_trip"
    ]
    assert len(opaque_ubi) >= 10, (
        f"Expected >= 10 OpaqueFragment(kind_tag=telematics_trip) anchors; "
        f"got {len(opaque_ubi)}"
    )


def test_auto_ubi_minimal_manifest_has_dispatch_records(tmp_path: Path) -> None:
    """The built manifest must contain both RATE_TABLE_LOOKUP and COMPUTE dispatch records."""
    bundle_dir = tmp_path / "auto_ubi_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    records = manifest.get("dispatch_records", [])

    kinds = {r.get("op", {}).get("kind") for r in records}
    assert "RATE_TABLE_LOOKUP" in kinds, (
        f"Expected a dispatch_record with op.kind=RATE_TABLE_LOOKUP; found kinds: {kinds}"
    )
    assert "COMPUTE" in kinds, (
        f"Expected a dispatch_record with op.kind=COMPUTE; found kinds: {kinds}"
    )


def test_auto_ubi_minimal_rating_tiers_coverage(tmp_path: Path) -> None:
    """The bundle must include both low_mileage_discount and high_risk_surcharge tiers."""
    bundle_dir = tmp_path / "auto_ubi_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    decisions = json.loads(
        (bundle_dir / "payload" / "rating_decisions.json").read_text(encoding="utf-8")
    )
    tiers = {d["tier"] for d in decisions}
    assert "low_mileage_discount" in tiers, (
        f"Expected low_mileage_discount tier in decisions; tiers present: {tiers}"
    )
    assert "high_risk_surcharge" in tiers, (
        f"Expected high_risk_surcharge tier in decisions; tiers present: {tiers}"
    )


# ---------------------------------------------------------------------------
# Tamper test 1: SHA tamper — mutate trip record to break FileIntegrityManySmall
# ---------------------------------------------------------------------------


def test_auto_ubi_minimal_tamper_trips_sha_fails_verification(tmp_path: Path) -> None:
    """Mutating trips.jsonl without updating the manifest SHA must cause result.ok=False
    with bad_file_sha in the failures list (FileIntegrityManySmall §C9)."""
    bundle_dir = tmp_path / "auto_ubi_tampered_sha"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    # Overwrite the first trip record's hard_brakes to a large number
    trips_path = bundle_dir / "telematics" / "trips.jsonl"
    lines = trips_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 1
    first_trip = json.loads(lines[0])
    first_trip["hard_brakes"] = 999
    lines[0] = json.dumps(first_trip, sort_keys=True)
    trips_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Do NOT update manifest SHA — this is the tamper test for FileIntegrityManySmall

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "Expected result.ok=False after SHA-tamper of telematics/trips.jsonl"
    )
    reason_codes = [f.reason_code for f in result.failures]
    detail_texts = [f.detail for f in result.failures]
    combined = " ".join(reason_codes + detail_texts).lower()
    assert "bad_file_sha" in combined or "sha" in combined, (
        f"Expected bad_file_sha / SHA mismatch in failures; "
        f"got reason_codes={reason_codes!r}"
    )


# ---------------------------------------------------------------------------
# Tamper test 2: re-derivation tamper — update SHA but break feature invariant
# ---------------------------------------------------------------------------


def test_auto_ubi_minimal_tamper_trips_rederivation_fails(tmp_path: Path) -> None:
    """Mutating trips.jsonl AND updating the manifest SHA must cause result.ok=False
    with AUTO_UBI_REDERIVATION_MISMATCH surfaced (re-derivation invariant broken)."""
    bundle_dir = tmp_path / "auto_ubi_tampered_redev"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    # Overwrite the first trip record's hard_brakes so re-derived features drift
    # from the bundled rating_decisions.json
    trips_path = bundle_dir / "telematics" / "trips.jsonl"
    lines = trips_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 1
    first_trip = json.loads(lines[0])
    first_trip["hard_brakes"] = 999
    lines[0] = json.dumps(first_trip, sort_keys=True)
    trips_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Update manifest.files SHA so FileIntegrityManySmall does not mask the
    # re-derivation failure with a SHA mismatch first
    new_sha = _sha256(trips_path.read_bytes())
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["telematics/trips.jsonl"] = new_sha
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "Expected result.ok=False after re-derivation tamper of telematics/trips.jsonl"
    )
    reason_codes = [f.reason_code for f in result.failures]
    detail_texts = [f.detail for f in result.failures]
    combined = " ".join(reason_codes + detail_texts).upper()
    assert "AUTO_UBI_REDERIVATION_MISMATCH" in combined, (
        f"Expected AUTO_UBI_REDERIVATION_MISMATCH in failure reason_codes or detail; "
        f"got reason_codes={reason_codes!r}, detail snippets={detail_texts!r}"
    )
