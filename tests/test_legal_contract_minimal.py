"""Round-trip integration test for examples/legal_contract_minimal.

Mirrors test_healthcare_diagnosis_minimal.py — three tamper-discipline tests
plus a shape test on the clean bundle.

Tests:
  1. test_clean_bundle_passes        — happy-path build + verify.
  2. test_clean_bundle_shape         — 8 clauses, OpaqueFragment anchors well-formed.
  3. test_tamper_precedent_fails     — mutate a case_cite in payload (SHA realigned
                                       so file_integrity passes); re-derivation catches.
  4. test_tamper_clauses_sha_fails   — mutate inputs/clauses.json WITHOUT realigning
                                       manifest SHA; file_integrity catches.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "legal_contract_minimal"

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
    "legal_contract_minimal._build_bundle",
    _PILOT_DIR / "_build_bundle.py",
)
_lc_check_mod = _import_module_from_path(
    "LegalContractReDerivationCheck",
    _PILOT_DIR / "LegalContractReDerivationCheck.py",
)

from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.re_derivation_invocation import ReDerivationInvocationCheck  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402

LegalContractReDerivationCheck = _lc_check_mod.LegalContractReDerivationCheck


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            ReDerivationInvocationCheck(pack_filename="legal_contract_pack.py", permit_execution=True),
            LegalContractReDerivationCheck(),
        ]
    )


def _build_clean(tmp_path: Path) -> Path:
    bundle_dir = tmp_path / "lc_bundle"
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
    result_payload = json.loads(
        (bundle_dir / "payload" / "retrieval_result.json").read_text("utf-8")
    )

    assert len(result_payload) == 8, (
        f"expected 8 clause entries; got {len(result_payload)}"
    )

    anchors = manifest.get("fragment_anchors", {})
    assert 5 <= len(anchors) <= 30, (
        f"expected 5..30 evidence anchors; got {len(anchors)}"
    )
    for key, a in anchors.items():
        assert a["kind"] == "opaque", f"anchor {key} not OpaqueFragment: {a}"
        assert a["kind_tag"] == "legal_precedent_anchor", (
            f"anchor {key} kind_tag wrong: {a['kind_tag']!r}"
        )
        for required in ("clause_id", "case_cite"):
            assert required in a["locator"], (
                f"anchor {key} locator missing {required}: {a['locator']!r}"
            )

    tc = manifest.get("typed_checks", [])
    assert "file_integrity_many_small" in tc
    assert "re_derivation_invocation" in tc


def test_tamper_precedent_fails(tmp_path: Path) -> None:
    """Mutate the first case_cite in payload + re-align manifest SHA.
    file_integrity passes; re-derivation catches the divergence."""
    bundle_dir = _build_clean(tmp_path)

    result_path = bundle_dir / "payload" / "retrieval_result.json"
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    # Replace the first non-empty case_cites list's first entry with a wrong cite.
    for entry in payload:
        if entry["case_cites"]:
            entry["case_cites"][0] = "Zzz v. Tampered, 999 F.3d 999 (Tamper Cir. 9999)"
            break
    tampered_bytes = _canonical_bytes(payload)
    result_path.write_bytes(tampered_bytes)

    _patch_manifest_sha(
        bundle_dir / "manifest.json",
        "payload/retrieval_result.json",
        hashlib.sha256(tampered_bytes).hexdigest(),
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False after mutating a case_cite (re-derivation should catch)"
    )
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures).upper()
    assert (
        "LC_REDER_FAIL" in combined
        or "RE_DERIVATION_MISMATCH" in combined
        or "LEGAL_CONTRACT_REDERIVATION_MISMATCH" in combined
    ), f"expected re-derivation failure; got: {result.failures}"


def test_tamper_clauses_sha_fails(tmp_path: Path) -> None:
    """Mutate inputs/clauses.json WITHOUT realigning manifest SHA.
    file_integrity_many_small must catch the SHA divergence."""
    bundle_dir = _build_clean(tmp_path)

    clauses_path = bundle_dir / "inputs" / "clauses.json"
    clauses = json.loads(clauses_path.read_text(encoding="utf-8"))
    # Mutate one clause's keywords; re-derivation would also fail, but
    # file_integrity should catch the SHA divergence first.
    clauses[0]["query_keywords"] = ["tampered_keyword"]
    clauses_path.write_bytes(_canonical_bytes(clauses))
    # Intentionally do NOT update manifest SHA.

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False after mutating clauses.json without re-aligning manifest SHA"
    )
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures).upper()
    assert "BAD_FILE_SHA" in combined or "FILE_INTEGRITY" in combined, (
        f"expected BAD_FILE_SHA / file_integrity failure; got: {result.failures}"
    )
