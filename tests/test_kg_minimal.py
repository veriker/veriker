"""Round-trip integration test for examples/kg_minimal/verify.py.

Test flow:
  1. Import _build_bundle.build from the pilot directory.
  2. Build the bundle into a tmp_path.
  3. Run the verifier with the pilot's plugin set.
  4. Assert result.ok is True.
  5. Tamper test: mutate kg/triples.jsonl to break a path edge.
  6. Re-run the verifier.
  7. Assert result.ok is False and KG_REDERIVATION_MISMATCH in failures.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths + dynamic import of pilot modules
# ---------------------------------------------------------------------------

_PKG_ROOT = Path(__file__).resolve().parents[1]  # v-kernel-audit-bundle/
_PILOT_DIR = _PKG_ROOT / "examples" / "kg_minimal"

# Insert pkg root so audit_bundle.* imports work in the test process.
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# Insert pilot dir so KgReDerivationCheck can be imported directly.
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
    "kg_minimal._build_bundle",
    _PILOT_DIR / "_build_bundle.py",
)
_kg_check_mod = _import_module_from_path(
    "KgReDerivationCheck",
    _PILOT_DIR / "KgReDerivationCheck.py",
)

from audit_bundle.plugins.dispatch_record_wellformed import (
    DispatchRecordWellformedCheck,
)
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck
from audit_bundle.verifier import BundleVerifier

KgReDerivationCheck = _kg_check_mod.KgReDerivationCheck


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            KgReDerivationCheck(),
            DispatchRecordWellformedCheck(
                op_kinds_admitted=frozenset({"GRAPH_QUERY", "COMPUTE"})
            ),
            StampLatticeCheck(),
        ]
    )


# ---------------------------------------------------------------------------
# Happy path: clean bundle
# ---------------------------------------------------------------------------


def test_kg_minimal_build_and_verify(tmp_path: Path) -> None:
    """Build a fresh bundle and verify it — result.ok must be True."""
    bundle_dir = tmp_path / "kg_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is True, f"Expected result.ok=True; failures:\n" + "\n".join(
        f"  [{f.check_name}] {f.reason_code}: {f.detail}" for f in result.failures
    )


def test_kg_minimal_manifest_has_opaque_fragments(tmp_path: Path) -> None:
    """The built manifest must contain at least 3 OpaqueFragment (kind_tag=kg_triple) anchors."""
    bundle_dir = tmp_path / "kg_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    anchors = manifest.get("fragment_anchors", {})

    opaque_kg = [
        v
        for v in anchors.values()
        if v.get("kind") == "opaque" and v.get("kind_tag") == "kg_triple"
    ]
    assert len(opaque_kg) >= 3, (
        f"Expected >= 3 OpaqueFragment(kind_tag=kg_triple) anchors; got {len(opaque_kg)}"
    )


def test_kg_minimal_manifest_has_graph_query_dispatch(tmp_path: Path) -> None:
    """The built manifest must contain a dispatch_record with op.kind=GRAPH_QUERY."""
    bundle_dir = tmp_path / "kg_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    records = manifest.get("dispatch_records", [])

    kinds = [r.get("op", {}).get("kind") for r in records]
    assert "GRAPH_QUERY" in kinds, (
        f"Expected a dispatch_record with op.kind=GRAPH_QUERY; found kinds: {kinds}"
    )


# ---------------------------------------------------------------------------
# Tamper path: break a path edge in kg/triples.jsonl
# ---------------------------------------------------------------------------


def test_kg_minimal_tamper_triples_fails_verification(tmp_path: Path) -> None:
    """Mutating kg/triples.jsonl to break a path edge must cause result.ok=False
    with KG_REDERIVATION_MISMATCH reported in the failures."""
    bundle_dir = tmp_path / "kg_tampered"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    # Overwrite the first triple (Alice knows Bob) with a bogus edge
    triples_path = bundle_dir / "kg" / "triples.jsonl"
    lines = triples_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 1
    lines[0] = json.dumps(
        {"subject": "ex:Alice", "predicate": "ex:knows", "object": "ex:NOBODY"}
    )
    triples_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Also update manifest.files SHA for the triples file so FileIntegrityManySmall
    # does not mask the re-derivation failure with a SHA mismatch first.
    import hashlib

    new_sha = hashlib.sha256(triples_path.read_bytes()).hexdigest()
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["kg/triples.jsonl"] = new_sha
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "Expected result.ok=False after tampering kg/triples.jsonl"
    )
    # The BundleVerifier wraps plugin failures as reason_code="plugin_failed"
    # with the PluginResult detail (stderr snippet) in the failure's detail string.
    # kg_re_derivation.py emits [KG_REDERIVATION_MISMATCH] on stderr on mismatch,
    # which is captured by KgReDerivationCheck and surfaced in PluginResult.detail,
    # which in turn appears in the VerifyFailure.detail text.
    reason_codes = [f.reason_code for f in result.failures]
    detail_texts = [f.detail for f in result.failures]
    combined = " ".join(reason_codes + detail_texts).upper()
    assert "KG_REDERIVATION_MISMATCH" in combined, (
        f"Expected KG_REDERIVATION_MISMATCH in failure reason_codes or detail; "
        f"got reason_codes={reason_codes!r}, detail snippets={detail_texts!r}"
    )
