"""Round-trip integration test for examples/pii_redaction_minimal/verify.py.

Test flow:
  1. Import _build_bundle.build from the pilot directory.
  2. Build the bundle into tmp_path.
  3. Run the verifier with the pilot's plugin set.
  4. Assert result.ok is True and PII_REDACTION_REDERIVED in successes.
  5. Tamper test A: mutate bioes_logits.json so a different tag wins Viterbi.
  6. Re-run; assert result.ok is False.
  7. Tamper test B: mutate bias_vector in redaction_output.json.
  8. Re-run; assert result.ok is False.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "pii_redaction_minimal"

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
    "pii_redaction_minimal._build_bundle",
    _PILOT_DIR / "_build_bundle.py",
)
_check_mod = _import_module_from_path(
    "PIIRedactionReDerivationCheck",
    _PILOT_DIR / "PIIRedactionReDerivationCheck.py",
)

from audit_bundle.plugins.dispatch_record_wellformed import (
    DispatchRecordWellformedCheck,
)
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck
from audit_bundle.verifier import BundleVerifier

PIIRedactionReDerivationCheck = _check_mod.PIIRedactionReDerivationCheck


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            PIIRedactionReDerivationCheck(),
            DispatchRecordWellformedCheck(
                op_kinds_admitted=frozenset({"REDACT", "COMPUTE"})
            ),
            StampLatticeCheck(),
        ]
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_pii_redaction_build_and_verify(tmp_path: Path) -> None:
    """Build a clean bundle and verify it — result.ok must be True, and the
    plugin directly returns PII_REDACTION_REDERIVED on success."""
    bundle_dir = tmp_path / "pii_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is True, "Expected result.ok=True; failures:\n" + "\n".join(
        f"  [{f.check_name}] {f.reason_code}: {f.detail}" for f in result.failures
    )

    # Plugin's own success reason_code is not exposed via VerifyResult (only failures
    # propagate). Invoke the plugin directly to confirm the contracted success code.
    from audit_bundle.verifier import _load_manifest

    direct = PIIRedactionReDerivationCheck().check(
        bundle_dir, _load_manifest(bundle_dir)
    )
    assert direct.ok is True
    assert direct.reason_code == "PII_REDACTION_REDERIVED", (
        f"Expected PII_REDACTION_REDERIVED; got {direct.reason_code}: {direct.detail}"
    )


def test_pii_redaction_manifest_has_pii_span_fragments(tmp_path: Path) -> None:
    """Built manifest must contain OpaqueFragment(kind_tag=pii_span) anchors."""
    bundle_dir = tmp_path / "pii_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    anchors = manifest.get("fragment_anchors", {})

    pii_frags = [
        v
        for v in anchors.values()
        if v.get("kind") == "opaque" and v.get("kind_tag") == "pii_span"
    ]
    assert len(pii_frags) >= 3, (
        f"Expected >= 3 OpaqueFragment(kind_tag=pii_span) anchors; got {len(pii_frags)}"
    )


def test_pii_redaction_manifest_has_redact_dispatch(tmp_path: Path) -> None:
    """Built manifest must contain a dispatch_record with op.kind=REDACT."""
    bundle_dir = tmp_path / "pii_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    records = manifest.get("dispatch_records", [])
    kinds = [r.get("op", {}).get("kind") for r in records]
    assert "REDACT" in kinds, (
        f"Expected a dispatch_record with op.kind=REDACT; found kinds: {kinds}"
    )


# ---------------------------------------------------------------------------
# Tamper test A: flip logits so Viterbi decodes a different tag sequence
# ---------------------------------------------------------------------------


def test_pii_redaction_tamper_logits_fails(tmp_path: Path) -> None:
    """Mutating bioes_logits.json so the gold tag is no longer the Viterbi
    argmax must cause result.ok=False with PII_REDACTION_REDERIVATION_MISMATCH."""
    bundle_dir = tmp_path / "pii_tamper_logits"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    logits_path = bundle_dir / "payload" / "bioes_logits.json"
    logits_obj = json.loads(logits_path.read_text(encoding="utf-8"))
    logits = logits_obj["logits"]

    # Target tokens inside the bundled spans. Token 0 in the synthetic fixture
    # is "Contact" — background O — so mutating it leaves the decode unchanged.
    output_obj = json.loads(
        (bundle_dir / "payload" / "redaction_output.json").read_text(encoding="utf-8")
    )
    span_token_indices = [
        i
        for s in output_obj["spans"]
        for i in range(s["token_start"], s["token_end"] + 1)
    ]
    assert span_token_indices, "fixture must have at least one in-span token"
    for idx in span_token_indices:
        for j in range(33):
            logits[idx][j] = 0.0
        logits[idx][32] = 5.0  # force O on every in-span token
    logits_obj["logits"] = logits

    new_bytes = (json.dumps(logits_obj, indent=2) + "\n").encode("utf-8")
    logits_path.write_bytes(new_bytes)

    # Update manifest SHA so FileIntegrityManySmall doesn't mask the re-derivation failure
    import hashlib

    new_sha = hashlib.sha256(new_bytes).hexdigest()
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["payload/bioes_logits.json"] = new_sha
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "Expected result.ok=False after mutating bioes_logits.json"
    )
    combined = " ".join(
        [f.reason_code for f in result.failures] + [f.detail for f in result.failures]
    ).upper()
    assert "PII_REDACTION_REDERIVATION_MISMATCH" in combined, (
        f"Expected PII_REDACTION_REDERIVATION_MISMATCH in failures; got {result.failures}"
    )


# ---------------------------------------------------------------------------
# Tamper test B: mutate bias_vector so original spans are no longer Viterbi argmax
# ---------------------------------------------------------------------------


def test_pii_redaction_tamper_bias_vector_fails(tmp_path: Path) -> None:
    """Mutating bias_vector in redaction_output.json to strongly penalise span_entry
    causes Viterbi to prefer O everywhere, so derived spans != bundled spans."""
    bundle_dir = tmp_path / "pii_tamper_bias"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    output_path = bundle_dir / "payload" / "redaction_output.json"
    output_obj = json.loads(output_path.read_text(encoding="utf-8"))

    # Large negative span_entry bias (index 1) makes starting any span very
    # costly; Viterbi will prefer O for all tokens, yielding zero spans.
    output_obj["bias_vector"] = [0.0, -100.0, 0.0, 0.0, 0.0, 0.0]

    new_bytes = (json.dumps(output_obj, indent=2) + "\n").encode("utf-8")
    output_path.write_bytes(new_bytes)

    # Update manifest SHA
    import hashlib

    new_sha = hashlib.sha256(new_bytes).hexdigest()
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["payload/redaction_output.json"] = new_sha
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, "Expected result.ok=False after mutating bias_vector"
    combined = " ".join(
        [f.reason_code for f in result.failures] + [f.detail for f in result.failures]
    ).upper()
    assert "PII_REDACTION_REDERIVATION_MISMATCH" in combined, (
        f"Expected PII_REDACTION_REDERIVATION_MISMATCH in failures; got {result.failures}"
    )
