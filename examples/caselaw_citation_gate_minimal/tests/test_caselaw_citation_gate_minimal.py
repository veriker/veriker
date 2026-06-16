"""tests/test_caselaw_citation_gate_minimal.py — tamper + §4a attack tests.

Covers five surfaces:

  1. Happy path: honest build -> verify -> result.ok is True (the honest
     ROUTE_TO_HUMAN verdict re-derives over the mixed fixture).

  2. Hide-the-fabrication: flip outputs/gate_verdict.json decision to
     AUTO_APPROVE AND reseal its manifest SHA, so file-integrity passes and the
     ONLY thing that fires is the re-derivation -> REDERIVATION_MISMATCH. This is
     the headline: you cannot claim AUTO_APPROVE while hiding a fabricated /
     misquoted citation.

  3. Hide-one-misquote (granularity): flip ONLY C-03's claimed status from
     MISQUOTE to ROOTED (keep decision ROUTE_TO_HUMAN), reseal SHA -> the
     recompute disagrees per-citation -> REDERIVATION_MISMATCH. Proves the
     comparison is over the whole verdict object, not just the top-line decision.

  4. Evidence tamper: change a byte in corpus/rooted_records.json WITHOUT
     updating manifest.files -> BAD_FILE_SHA (file_integrity_many_small).

  5. Weaker-spec substitution (Axis-1 anchor): ship a `set`-comparator spec in
     the bundle (resealing manifest.spec_files), but the auditor SpecAnchor is
     computed from the COMMITTED `exact` spec -> the substituted spec's SHA is
     not anchored -> AnchorViolation, fail-closed.

Auditor-independence sys.path shim: parents[2] of the test file is the
v-kernel-audit-bundle package root; the pilot's primitive module lives in
parents[1].
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# sys.path setup (auditor-independence: no installed package required)
# ---------------------------------------------------------------------------

_TEST_DIR = Path(__file__).resolve().parent
_PILOT_DIR = _TEST_DIR.parent
_PKG_ROOT = _PILOT_DIR.parents[1]  # …/v-kernel-audit-bundle

if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.rederivation.registry import register_primitive  # noqa: E402
from audit_bundle.rederivation.spec_binding import SpecAnchor  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
import caselaw_gate_recompute as _prim_mod  # noqa: E402

# Register the primitive once per process (idempotent).
register_primitive(_prim_mod.CaselawGateRecompute())

_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "caselaw_gate.spec.json"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build(out_dir: Path) -> None:
    """Run the real _build_bundle.py to produce a fresh bundle in out_dir."""
    subprocess.run(
        [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(out_dir)],
        capture_output=True,
        check=True,
    )


def _anchor_from_committed_spec() -> SpecAnchor:
    """Derive the auditor SpecAnchor from the COMMITTED source spec file."""
    raw = _SPEC_SRC.read_bytes()
    doc = json.loads(raw)
    return SpecAnchor(allowed={doc["spec_id"]: hashlib.sha256(raw).hexdigest()})


def _verifier(anchor: SpecAnchor | None = None) -> BundleVerifier:
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()],
        spec_anchor=anchor if anchor is not None else _anchor_from_committed_spec(),
    )


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _reseal_file_sha(bundle_dir: Path, rel: str, new_bytes: bytes) -> None:
    """Write new_bytes to bundle_dir/rel AND update manifest.files[rel] so
    file-integrity passes — used to isolate the re-derivation surface."""
    (bundle_dir / rel).write_bytes(new_bytes)
    manifest_path = bundle_dir / "manifest.json"
    m = json.loads(manifest_path.read_bytes())
    m["files"][rel] = hashlib.sha256(new_bytes).hexdigest()
    manifest_path.write_bytes(json.dumps(m, indent=2, sort_keys=True).encode("utf-8"))


# ---------------------------------------------------------------------------
# Test 1 — Happy path
# ---------------------------------------------------------------------------


def test_honest_pass(tmp_path):
    """Build + verify with the honest claimed verdict -> result.ok is True."""
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)
    result = _verifier().verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


# ---------------------------------------------------------------------------
# Test 2 — Hide the fabrication: claim AUTO_APPROVE -> REDERIVATION_MISMATCH
# ---------------------------------------------------------------------------


def test_hidden_fabrication_fails_rederivation(tmp_path):
    """Producer flips the gate decision to AUTO_APPROVE (and resets every
    citation status to ROOTED) to hide the misquote + fabrication, then reseals
    the claimed-value SHA. File-integrity passes; only the re-derivation catches
    the lie -> REDERIVATION_MISMATCH, and NOT a file-SHA failure."""
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)

    claim_path = bundle_dir / "outputs" / "gate_verdict.json"
    doc = json.loads(claim_path.read_bytes())
    doc["value"]["decision"] = "AUTO_APPROVE"
    for c in doc["value"]["citations"]:
        c["status"] = "ROOTED"
    new_bytes = (json.dumps({"value": doc["value"]}, indent=2, sort_keys=True) + "\n").encode()
    _reseal_file_sha(bundle_dir, "outputs/gate_verdict.json", new_bytes)

    result = _verifier().verify(bundle_dir)
    assert not result.ok, "Expected FAIL after claiming AUTO_APPROVE"
    rc = _reason_codes(result)
    assert "REDERIVATION_MISMATCH" in rc, f"Expected REDERIVATION_MISMATCH; got {rc!r}"
    # The re-derivation (not file integrity) must be the catching mechanism.
    assert "bad_file_sha" not in rc and "plugin_failed" not in rc, (
        f"file-integrity should pass after reseal; got {rc!r}"
    )


# ---------------------------------------------------------------------------
# Test 3 — Granularity: hide ONE misquote -> REDERIVATION_MISMATCH
# ---------------------------------------------------------------------------


def test_hidden_single_misquote_fails_rederivation(tmp_path):
    """Producer flips only C-03's claimed status MISQUOTE -> ROOTED (keeping the
    decision ROUTE_TO_HUMAN, since C-04 is still UNRESOLVED), reseals the SHA.
    The recompute disagrees on that one record -> REDERIVATION_MISMATCH. Proves
    the comparison covers the whole verdict object, not just the decision."""
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)

    claim_path = bundle_dir / "outputs" / "gate_verdict.json"
    doc = json.loads(claim_path.read_bytes())
    for c in doc["value"]["citations"]:
        if c["id"] == "C-03":
            assert c["status"] == "MISQUOTE", "fixture precondition: C-03 is MISQUOTE"
            c["status"] = "ROOTED"
    assert doc["value"]["decision"] == "ROUTE_TO_HUMAN"
    new_bytes = (json.dumps({"value": doc["value"]}, indent=2, sort_keys=True) + "\n").encode()
    _reseal_file_sha(bundle_dir, "outputs/gate_verdict.json", new_bytes)

    result = _verifier().verify(bundle_dir)
    assert not result.ok, "Expected FAIL after hiding the C-03 misquote"
    rc = _reason_codes(result)
    assert "REDERIVATION_MISMATCH" in rc, f"Expected REDERIVATION_MISMATCH; got {rc!r}"
    assert "bad_file_sha" not in rc and "plugin_failed" not in rc, (
        f"file-integrity should pass after reseal; got {rc!r}"
    )


# ---------------------------------------------------------------------------
# Test 4 — Evidence tamper: corpus byte changed, manifest NOT updated
# ---------------------------------------------------------------------------


def test_evidence_tamper_fails_file_sha(tmp_path):
    """Change a byte in corpus/rooted_records.json (flip the Recentive holding
    from 'ineligible' to 'eligible') WITHOUT updating manifest.files. The stale
    manifest SHA -> BAD_FILE_SHA from file_integrity_many_small."""
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)

    corpus_path = bundle_dir / "corpus" / "rooted_records.json"
    tampered = corpus_path.read_bytes().replace(
        b"is patent ineligible under section 101",
        b"is patent eligible   under section 101",
    )
    assert tampered != corpus_path.read_bytes(), "tamper precondition: byte changed"
    corpus_path.write_bytes(tampered)  # NOT resealed

    result = _verifier().verify(bundle_dir)
    assert not result.ok, "Expected FAIL after corpus tamper"
    rc = _reason_codes(result)
    assert "bad_file_sha" in rc or "plugin_failed" in rc, (
        f"Expected a file-integrity failure; got {rc!r}"
    )


# ---------------------------------------------------------------------------
# Test 5 — Weaker-spec substitution -> AnchorViolation (Axis-1)
# ---------------------------------------------------------------------------


def test_weak_spec_substitution_fails_anchor(tmp_path):
    """Producer ships a `set`-comparator spec in the bundle (a weaker comparison
    than the auditor's `exact`), resealing manifest.spec_files so SHA-pinning
    passes. The auditor SpecAnchor is computed from the COMMITTED `exact` spec,
    so the substituted spec's SHA is not anchored -> AnchorViolation."""
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)

    weak_spec = json.loads(_SPEC_SRC.read_bytes())
    weak_spec["types"]["caselaw_gate_verdict"]["comparator"] = {"kind": "set"}
    weak_bytes = (json.dumps(weak_spec, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()

    spec_path = bundle_dir / "spec" / "caselaw_gate.spec.json"
    spec_path.write_bytes(weak_bytes)
    manifest_path = bundle_dir / "manifest.json"
    m = json.loads(manifest_path.read_bytes())
    m["spec_files"]["caselaw_gate.spec.json"] = hashlib.sha256(weak_bytes).hexdigest()
    manifest_path.write_bytes(json.dumps(m, indent=2, sort_keys=True).encode("utf-8"))

    result = _verifier(_anchor_from_committed_spec()).verify(bundle_dir)
    assert not result.ok, "Expected FAIL: substituted spec is not authoritative"
    rc = _reason_codes(result)
    assert "AnchorViolation" in rc, (
        f"Expected AnchorViolation; got {rc!r}\n"
        f"{[(f.check_name, f.reason_code, f.detail) for f in result.failures]}"
    )
