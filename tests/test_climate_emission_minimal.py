"""Round-trip integration test for examples/climate_emission_minimal.

Mirrors test_healthcare_diagnosis_minimal.py — four tests covering
shape + tamper-discipline for Scope-3 emission attribution.

Tests:
  1. test_clean_bundle_passes              — happy-path build + verify.
  2. test_clean_bundle_shape               — 8 suppliers, total > 0,
                                              OpaqueFragment anchors well-formed.
  3. test_tamper_supplier_chain_sha_fails  — mutate supplier_chain.json without
                                              realigning manifest SHA → file_integrity catches.
  4. test_tamper_payload_total_fails       — mutate total_scope3_kg_co2e and
                                              realign manifest SHA → re-derivation catches.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "climate_emission_minimal"

if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))


def _import_module_from_path(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_build_bundle_mod = _import_module_from_path(
    "climate_emission_minimal._build_bundle",
    _PILOT_DIR / "_build_bundle.py",
)
_ce_check_mod = _import_module_from_path(
    "ClimateEmissionReDerivationCheck",
    _PILOT_DIR / "ClimateEmissionReDerivationCheck.py",
)

from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.re_derivation_invocation import ReDerivationInvocationCheck  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402

ClimateEmissionReDerivationCheck = _ce_check_mod.ClimateEmissionReDerivationCheck


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            ReDerivationInvocationCheck(pack_filename="climate_emission_pack.py", permit_execution=True),
            ClimateEmissionReDerivationCheck(),
        ]
    )


def _build_clean(tmp_path: Path) -> Path:
    bundle_dir = tmp_path / "ce_bundle"
    _build_bundle_mod.build(bundle_dir)
    return bundle_dir


def _canonical_bytes(obj) -> bytes:
    return (
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _patch_manifest_sha(manifest_path: Path, rel: str, new_sha: str) -> None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][rel] = new_sha
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )


def test_clean_bundle_passes(tmp_path: Path) -> None:
    bundle_dir = _build_clean(tmp_path)
    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is True, (
        f"expected ok=True on clean bundle; failures: {result.failures}"
    )


def test_clean_bundle_shape(tmp_path: Path) -> None:
    bundle_dir = _build_clean(tmp_path)
    manifest = json.loads((bundle_dir / "manifest.json").read_text("utf-8"))
    report = json.loads(
        (bundle_dir / "payload" / "emission_report.json").read_text("utf-8")
    )

    assert report["aggregation_method"] == "sum"
    assert len(report["attributions"]) == 8, (
        f"expected 8 supplier attributions; got {len(report['attributions'])}"
    )
    assert float(report["total_scope3_kg_co2e"]) > 0, (
        "total_scope3_kg_co2e must be positive for non-trivial fixtures"
    )

    anchors = manifest.get("fragment_anchors", {})
    assert len(anchors) == 8, (
        f"expected 8 anchors (one per supplier); got {len(anchors)}"
    )
    for key, a in anchors.items():
        assert a["kind"] == "opaque", f"anchor {key} not OpaqueFragment: {a}"
        assert a["kind_tag"] == "supplier_emission_anchor", (
            f"anchor {key} kind_tag wrong: {a['kind_tag']!r}"
        )
        for required in ("vendor_id", "factor_source", "tier"):
            assert required in a["locator"], (
                f"anchor {key} locator missing {required}: {a['locator']!r}"
            )

    tc = manifest.get("typed_checks", [])
    assert "file_integrity_many_small" in tc
    assert "re_derivation_invocation" in tc


def test_tamper_supplier_chain_sha_fails(tmp_path: Path) -> None:
    """Mutate inputs/supplier_chain.json without realigning manifest SHA.
    file_integrity_many_small must catch the SHA divergence."""
    bundle_dir = _build_clean(tmp_path)

    chain_path = bundle_dir / "inputs" / "supplier_chain.json"
    chain = json.loads(chain_path.read_text(encoding="utf-8"))
    # Inflate the first supplier's activity_amount by 999x — any change works.
    chain[0]["activity_amount"] = float(chain[0]["activity_amount"]) * 999.0
    chain_path.write_bytes(_canonical_bytes(chain))
    # Intentionally do NOT update manifest SHA.

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False after mutating supplier_chain.json without re-aligning manifest SHA"
    )
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures).upper()
    assert "BAD_FILE_SHA" in combined or "FILE_INTEGRITY" in combined, (
        f"expected BAD_FILE_SHA / file_integrity failure; got: {result.failures}"
    )


def test_tamper_payload_total_fails(tmp_path: Path) -> None:
    """Mutate total_scope3_kg_co2e AND realign manifest SHA.
    file_integrity passes; re-derivation pack catches the mismatch."""
    bundle_dir = _build_clean(tmp_path)

    report_path = bundle_dir / "payload" / "emission_report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    original_total = float(report["total_scope3_kg_co2e"])
    # Inflate the total by 1_000_000 kg CO2e — bigger than any per-supplier sum.
    report["total_scope3_kg_co2e"] = round(original_total + 1_000_000.0, 6)
    tampered_bytes = _canonical_bytes(report)
    report_path.write_bytes(tampered_bytes)

    _patch_manifest_sha(
        bundle_dir / "manifest.json",
        "payload/emission_report.json",
        hashlib.sha256(tampered_bytes).hexdigest(),
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is False, "expected ok=False after inflating total_scope3_kg_co2e"
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures).upper()
    assert (
        "CEM_REDER_FAIL" in combined
        or "RE_DERIVATION_MISMATCH" in combined
        or "CLIMATE_EMISSION_REDERIVATION_MISMATCH" in combined
    ), f"expected re-derivation failure; got: {result.failures}"
