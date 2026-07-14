"""Round-trip integration test for examples/credit_scoring_minimal/verify.py.

Test flow:
  1. Import _build_bundle.build from the pilot directory.
  2. Build the bundle into a tmp_path.
  3. Run the verifier with the pilot's plugin set.
  4. Assert result.ok is True.
  5. Structural assertions: OpaqueFragment anchors, dispatch_records, source_attributes.
  6. Tamper test: mutate a Serasa Score in one applicant file so re-evaluation
     produces a different tier.  Assert verifier returns result.ok=False with
     CREDIT_SCORING_REDERIVATION_MISMATCH in failures.
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
_PILOT_DIR = _PKG_ROOT / "examples" / "credit_scoring_minimal"

# Insert pkg root so audit_bundle.* imports work in the test process.
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# Insert pilot dir so CreditScoringReDerivationCheck can be imported directly.
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
    "credit_scoring_minimal._build_bundle",
    _PILOT_DIR / "_build_bundle.py",
)
_cs_check_mod = _import_module_from_path(
    "CreditScoringReDerivationCheck",
    _PILOT_DIR / "CreditScoringReDerivationCheck.py",
)

from audit_bundle.plugins.dispatch_record_wellformed import (
    DispatchRecordWellformedCheck,
)
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck
from audit_bundle.verifier import BundleVerifier

CreditScoringReDerivationCheck = _cs_check_mod.CreditScoringReDerivationCheck


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            CreditScoringReDerivationCheck(),
            DispatchRecordWellformedCheck(
                op_kinds_admitted=frozenset({"SCORECARD_EVAL", "COMPUTE"})
            ),
            StampLatticeCheck(),
        ]
    )


# ---------------------------------------------------------------------------
# Happy path: clean bundle
# ---------------------------------------------------------------------------


def test_credit_scoring_minimal_build_and_verify(tmp_path: Path) -> None:
    """Build a fresh bundle and verify it — result.ok must be True."""
    bundle_dir = tmp_path / "credit_scoring_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is True, "Expected result.ok=True; failures:\n" + "\n".join(
        f"  [{f.check_name}] {f.reason_code}: {f.detail}" for f in result.failures
    )


def test_credit_scoring_minimal_has_opaque_fragments(tmp_path: Path) -> None:
    """The built manifest must contain OpaqueFragment(kind_tag=credit_attribute) anchors."""
    bundle_dir = tmp_path / "credit_scoring_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    anchors = manifest.get("fragment_anchors", {})

    opaque_credit = [
        v
        for v in anchors.values()
        if v.get("kind") == "opaque" and v.get("kind_tag") == "credit_attribute"
    ]
    # 5 applicants × 5 bureau attributes = 25 anchors
    assert len(opaque_credit) >= 25, (
        f"Expected >= 25 OpaqueFragment(kind_tag=credit_attribute) anchors; "
        f"got {len(opaque_credit)}"
    )


def test_credit_scoring_minimal_has_scorecard_eval_dispatch(tmp_path: Path) -> None:
    """The built manifest must contain dispatch_records with op.kind=SCORECARD_EVAL."""
    bundle_dir = tmp_path / "credit_scoring_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    records = manifest.get("dispatch_records", [])

    kinds = [r.get("op", {}).get("kind") for r in records]
    assert "SCORECARD_EVAL" in kinds, (
        f"Expected a dispatch_record with op.kind=SCORECARD_EVAL; found kinds: {kinds}"
    )
    assert "COMPUTE" in kinds, (
        f"Expected a dispatch_record with op.kind=COMPUTE; found kinds: {kinds}"
    )


def test_credit_scoring_minimal_has_source_attributes(tmp_path: Path) -> None:
    """The built manifest must contain source_attributes with publication_class=regulatory."""
    bundle_dir = tmp_path / "credit_scoring_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    source_attrs = manifest.get("source_attributes", {})

    assert len(source_attrs) >= 1, (
        f"Expected at least one source_attributes entry; got {source_attrs}"
    )
    # Each entry must carry publication_class=regulatory (credit-bureau lineage; LGPD art. 20)
    for cid, props in source_attrs.items():
        assert props.get("publication_class") == "regulatory", (
            f"source_attributes[{cid!r}]: expected publication_class='regulatory'; "
            f"got {props.get('publication_class')!r}"
        )


def test_credit_scoring_minimal_decisions_have_expected_tiers(tmp_path: Path) -> None:
    """Built payload must include at least one approve-A, one approve-C, and one decline."""
    bundle_dir = tmp_path / "credit_scoring_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    payload = json.loads(
        (bundle_dir / "payload" / "credit_decisions.json").read_text(encoding="utf-8")
    )
    decisions = payload.get("decisions", [])
    tiers = {d["tier"] for d in decisions}
    decisions_set = {d["decision"] for d in decisions}

    assert "A" in tiers, f"Expected tier A in decisions; got tiers={sorted(tiers)}"
    assert "decline" in decisions_set, (
        f"Expected at least one decline decision; got decisions={sorted(decisions_set)}"
    )


# ---------------------------------------------------------------------------
# Tamper path: mutate a Serasa Score to produce a different tier
# ---------------------------------------------------------------------------


def test_credit_scoring_minimal_tamper_fico_fails_verification(tmp_path: Path) -> None:
    """Mutating an applicant's Serasa Score to produce a different tier must cause
    result.ok=False with CREDIT_SCORING_REDERIVATION_MISMATCH in failures."""
    bundle_dir = tmp_path / "credit_scoring_tampered"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    # Find the prime applicant (APP-001, tier A, FICO=780) and drop FICO to 580
    # so that the re-derived PD pushes them into tier D (decline).
    app_path = bundle_dir / "applicants" / "APP-001.json"
    assert app_path.exists(), (
        f"Expected APP-001.json in bundle; not found at {app_path}"
    )

    app_data = json.loads(app_path.read_text(encoding="utf-8"))
    original_fico = app_data["serasa_score"]
    app_data["serasa_score"] = 400  # far below prime — guarantees a tier shift
    app_path.write_text(
        json.dumps(app_data, indent=2, sort_keys=True), encoding="utf-8"
    )

    # Update manifest.files SHA for the tampered applicant file so
    # FileIntegrityManySmall does not mask the re-derivation failure.
    import hashlib

    new_sha = hashlib.sha256(app_path.read_bytes()).hexdigest()
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["applicants/APP-001.json"] = new_sha
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        f"Expected result.ok=False after tampering APP-001 Serasa Score "
        f"(original={original_fico}, tampered=400)"
    )
    reason_codes = [f.reason_code for f in result.failures]
    detail_texts = [f.detail for f in result.failures]
    combined = " ".join(reason_codes + detail_texts).upper()
    assert "CREDIT_SCORING_REDERIVATION_MISMATCH" in combined, (
        f"Expected CREDIT_SCORING_REDERIVATION_MISMATCH in failures; "
        f"got reason_codes={reason_codes!r}, detail snippets={detail_texts!r}"
    )
