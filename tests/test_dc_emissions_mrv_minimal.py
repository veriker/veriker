"""Round-trip integration test for examples/dc_emissions_mrv_minimal.

Mirrors test_climate_emission_minimal.py — four tests covering shape +
tamper discipline for the data-center NSR + embodied-carbon pilot.

Tests:
  1. test_clean_bundle_passes              — happy-path build + verify.
  2. test_clean_bundle_shape               — 2 sources + 5 materials, every
                                              criteria pollutant has positive
                                              total tpy, overall classification
                                              == synthetic_minor, OpaqueFragment
                                              anchors well-formed (7 total).
  3. test_tamper_emission_sources_sha_fails — mutate emission_sources.json
                                              without realigning manifest SHA →
                                              file_integrity catches.
  4. test_tamper_payload_total_fails       — mutate NOx total_tpy + realign
                                              manifest SHA → re-derivation
                                              pack catches.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "dc_emissions_mrv_minimal"

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
    "dc_emissions_mrv_minimal._build_bundle",
    _PILOT_DIR / "_build_bundle.py",
)
_check_mod = _import_module_from_path(
    "DCEmissionsMRVReDerivationCheck",
    _PILOT_DIR / "DCEmissionsMRVReDerivationCheck.py",
)

from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.re_derivation_invocation import ReDerivationInvocationCheck  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402

DCEmissionsMRVReDerivationCheck = _check_mod.DCEmissionsMRVReDerivationCheck


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            ReDerivationInvocationCheck(pack_filename="dc_emissions_mrv_pack.py", permit_execution=True),
            DCEmissionsMRVReDerivationCheck(),
        ]
    )


def _build_clean(tmp_path: Path) -> Path:
    bundle_dir = tmp_path / "dcmrv_bundle"
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
    submission = json.loads(
        (bundle_dir / "payload" / "nsr_submission.json").read_text("utf-8")
    )

    assert submission["aggregation_method"] == "sum"
    assert submission["facility_id"] == "DC-SYN-001"
    assert submission["overall_classification"] == "synthetic_minor", (
        f"expected synthetic_minor on clean fixtures; got "
        f"{submission['overall_classification']!r}"
    )

    criteria = submission["criteria_pollutants"]
    for poll in ("NOx", "CO", "PM", "NMHC"):
        c = criteria[poll]
        assert float(c["total_tpy"]) > 0, f"{poll} total_tpy must be > 0"
        assert c["classification"] == "synthetic_minor", (
            f"{poll} expected synthetic_minor; got {c['classification']!r} "
            f"at total {c['total_tpy']}"
        )
        assert len(c["per_source_tpy"]) == 2, (
            f"{poll} expected 2 per-source contributions; got "
            f"{len(c['per_source_tpy'])}"
        )

    emb = submission["embodied_carbon"]
    assert len(emb["per_material_kg_co2e"]) == 5
    assert float(emb["total_kg_co2e"]) > 0

    anchors = manifest.get("fragment_anchors", {})
    assert len(anchors) == 7, (
        f"expected 7 anchors (2 sources + 5 materials); got {len(anchors)}"
    )
    source_anchors = [
        a for a in anchors.values() if a["kind_tag"] == "nsr_emission_source_anchor"
    ]
    material_anchors = [
        a
        for a in anchors.values()
        if a["kind_tag"] == "embodied_carbon_material_anchor"
    ]
    assert len(source_anchors) == 2
    assert len(material_anchors) == 5
    for a in source_anchors:
        for required in (
            "source_id",
            "source_type",
            "factor_source",
            "factor_basis",
            "citation_authority",
            "citation_url",
        ):
            assert required in a["locator"], (
                f"source anchor locator missing {required}: {a['locator']!r}"
            )
        # citation_url must look like a URL (hardening: not a placeholder)
        assert a["locator"]["citation_url"].startswith(("http://", "https://")), (
            f"source anchor citation_url not a URL: {a['locator']['citation_url']!r}"
        )
    for a in material_anchors:
        for required in (
            "material_id",
            "epd_source",
            "unit",
            "citation_authority",
            "citation_url",
        ):
            assert required in a["locator"], (
                f"material anchor locator missing {required}: {a['locator']!r}"
            )
        assert a["locator"]["citation_url"].startswith(("http://", "https://")), (
            f"material anchor citation_url not a URL: {a['locator']['citation_url']!r}"
        )

    tc = manifest.get("typed_checks", [])
    assert "file_integrity_many_small" in tc
    assert "re_derivation_invocation" in tc


def test_tamper_emission_sources_sha_fails(tmp_path: Path) -> None:
    """Mutate inputs/emission_sources.json without realigning manifest SHA.
    file_integrity_many_small must catch the SHA divergence."""
    bundle_dir = _build_clean(tmp_path)

    sources_path = bundle_dir / "inputs" / "emission_sources.json"
    sources = json.loads(sources_path.read_text(encoding="utf-8"))
    # Triple the diesel genset count — any change works.
    for s in sources:
        if s["source_type"] == "diesel_genset_tier4f":
            s["count"] = int(s["count"]) * 3
            break
    sources_path.write_bytes(_canonical_bytes(sources))
    # Intentionally do NOT update manifest SHA.

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False after mutating emission_sources.json without "
        "realigning manifest SHA"
    )
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures).upper()
    assert "BAD_FILE_SHA" in combined or "FILE_INTEGRITY" in combined, (
        f"expected BAD_FILE_SHA / file_integrity failure; got: {result.failures}"
    )


def test_tamper_payload_total_fails(tmp_path: Path) -> None:
    """Mutate criteria_pollutants.NOx.total_tpy AND realign manifest SHA.
    file_integrity passes; re-derivation pack catches the mismatch."""
    bundle_dir = _build_clean(tmp_path)

    submission_path = bundle_dir / "payload" / "nsr_submission.json"
    submission = json.loads(submission_path.read_text(encoding="utf-8"))
    original_total = float(submission["criteria_pollutants"]["NOx"]["total_tpy"])
    # Shave 5 tpy off — keeps classification == synthetic_minor (so the
    # mismatch is on total_tpy alone, not classification + total).
    submission["criteria_pollutants"]["NOx"]["total_tpy"] = round(
        original_total - 5.0, 6
    )
    tampered_bytes = _canonical_bytes(submission)
    submission_path.write_bytes(tampered_bytes)

    _patch_manifest_sha(
        bundle_dir / "manifest.json",
        "payload/nsr_submission.json",
        hashlib.sha256(tampered_bytes).hexdigest(),
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is False, "expected ok=False after mutating NOx total_tpy"
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures).upper()
    assert (
        "DCMRV_REDER_FAIL" in combined
        or "RE_DERIVATION_MISMATCH" in combined
        or "DC_EMISSIONS_MRV_REDERIVATION_MISMATCH" in combined
    ), f"expected re-derivation failure; got: {result.failures}"


def test_tamper_citation_strip_fails(tmp_path: Path) -> None:
    """Strip the citation_url from one emission source AND realign manifest SHA.
    file_integrity passes; re-derivation pack catches CITATION_MISSING because
    provenance is load-bearing — a permit submission with an EF that cannot be
    traced to its regulatory authority is rejected by design."""
    bundle_dir = _build_clean(tmp_path)

    sources_path = bundle_dir / "inputs" / "emission_sources.json"
    sources = json.loads(sources_path.read_text(encoding="utf-8"))
    # Blank one source's citation_url — the kind of failure a sloppy export
    # from an LCA tool or permit-application generator would produce.
    sources[0]["citation"]["document_url"] = ""
    tampered_bytes = _canonical_bytes(sources)
    sources_path.write_bytes(tampered_bytes)

    _patch_manifest_sha(
        bundle_dir / "manifest.json",
        "inputs/emission_sources.json",
        hashlib.sha256(tampered_bytes).hexdigest(),
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is False, "expected ok=False after stripping citation_url"
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures).upper()
    assert "CITATION_MISSING" in combined or "DCMRV_REDER_FAIL" in combined, (
        f"expected CITATION_MISSING / DCMRV_REDER_FAIL; got: {result.failures}"
    )
