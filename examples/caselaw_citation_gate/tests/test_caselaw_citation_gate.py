"""tests/test_caselaw_citation_gate.py -- tamper + §4a attack tests.

Verbatim-rooted successor to caselaw_citation_gate_minimal's tests. Same five
surfaces, now over a corpus whose misquote yardstick is the court's actual opinion
text (corpus/rooted_records.json, captured by _root_corpus.py with provenance):

  1. Happy path: honest build -> verify -> result.ok is True (the honest
     ROUTE_TO_HUMAN verdict re-derives over the mixed fixture).

  2. Hide-the-fabrication: flip outputs/gate_verdict.json decision to AUTO_APPROVE
     AND reseal its manifest SHA, so file-integrity passes and the ONLY thing that
     fires is the re-derivation -> REDERIVATION_MISMATCH.

  3. Hide-one-misquote (granularity): flip ONLY the MISQUOTE assertion's claimed
     status to ROOTED (keep decision ROUTE_TO_HUMAN), reseal SHA -> the recompute
     disagrees per-citation -> REDERIVATION_MISMATCH.

  4. Evidence tamper: change a byte in corpus/rooted_records.json WITHOUT updating
     manifest.files -> BAD_FILE_SHA (file_integrity_many_small).

  5. Weaker-spec substitution (Axis-1 anchor): ship a `set`-comparator spec in the
     bundle (resealing manifest.spec_files), but the auditor SpecAnchor is computed
     from the COMMITTED `exact` spec -> the substituted spec's SHA is not anchored
     -> AnchorViolation, fail-closed.

The MISQUOTE / UNRESOLVED assertion ids are discovered from the honest verdict
rather than hard-coded, so the tests stay valid as the rooted fixture evolves.
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

from audit_bundle.gate.ed25519_verdict_signing import Ed25519VerifierKey  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.rederivation.registry import register_primitive  # noqa: E402
from audit_bundle.rederivation.spec_binding import SpecAnchor  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from CaselawGateAttestationCheck import CaselawGateAttestationCheck  # noqa: E402
import caselaw_gate_kb_recompute as _prim_mod  # noqa: E402

# Register the primitive once per process (idempotent).
register_primitive(_prim_mod.CaselawGateKbRecompute())

_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "caselaw_gate_kb.spec.json"
_SPEC_BASENAME = _SPEC_SRC.name
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
        plugins=[FileIntegrityManySmall(), CaselawGateAttestationCheck()],
        spec_anchor=anchor if anchor is not None else _anchor_from_committed_spec(),
    )


# Typed-check plugin failures surface with reason_code="plugin_failed" and the
# specific code embedded in the detail string; the spec-pinned dispatch surfaces
# REDERIVATION_MISMATCH directly. Harvest both (belt-and-suspenders idiom).
_DETAIL_CODES = (
    "CASELAW_GATE_ATTESTATION_INVALID",
    "CASELAW_GATE_ATTESTATION_PUBKEY_MISSING",
    "CASELAW_GATE_ATTESTATION_MALFORMED",
    "REDERIVATION_MISMATCH",
)


def _reason_codes(result) -> set[str]:
    codes: set[str] = set()
    for f in result.failures:
        codes.add(f.reason_code)
        detail = f.detail or ""
        for c in _DETAIL_CODES:
            if c in detail:
                codes.add(c)
    return codes


def _reseal_file_sha(bundle_dir: Path, rel: str, new_bytes: bytes) -> None:
    """Write new_bytes to bundle_dir/rel AND update manifest.files[rel] so
    file-integrity passes — used to isolate the re-derivation surface."""
    (bundle_dir / rel).write_bytes(new_bytes)
    manifest_path = bundle_dir / "manifest.json"
    m = json.loads(manifest_path.read_bytes())
    m["files"][rel] = hashlib.sha256(new_bytes).hexdigest()
    manifest_path.write_bytes(json.dumps(m, indent=2, sort_keys=True).encode("utf-8"))


def _claimed_verdict(bundle_dir: Path) -> dict:
    return json.loads((bundle_dir / "outputs" / "gate_verdict.json").read_bytes())[
        "value"
    ]


def _first_id_with_status(verdict: dict, status: str) -> str:
    for c in verdict["citations"]:
        if c["status"] == status:
            return c["id"]
    raise AssertionError(f"fixture precondition: no citation with status {status!r}")


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
    """Producer flips the gate decision to AUTO_APPROVE (and resets every citation
    status to ROOTED) to hide the misquote + fabrication, then reseals the
    claimed-value SHA. File-integrity passes; only the re-derivation catches the
    lie -> REDERIVATION_MISMATCH, and NOT a file-SHA failure."""
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)

    claim_path = bundle_dir / "outputs" / "gate_verdict.json"
    doc = json.loads(claim_path.read_bytes())
    doc["value"]["decision"] = "AUTO_APPROVE"
    for c in doc["value"]["citations"]:
        c["status"] = "ROOTED"
    new_bytes = (
        json.dumps({"value": doc["value"]}, indent=2, sort_keys=True) + "\n"
    ).encode()
    _reseal_file_sha(bundle_dir, "outputs/gate_verdict.json", new_bytes)

    result = _verifier().verify(bundle_dir)
    assert not result.ok, "Expected FAIL after claiming AUTO_APPROVE"
    rc = _reason_codes(result)
    assert "REDERIVATION_MISMATCH" in rc, f"Expected REDERIVATION_MISMATCH; got {rc!r}"
    # The forged verdict ALSO breaks the Ed25519 attestation (signed over the
    # honest verdict) -- both surfaces independently reject it. File-integrity
    # still passes (the output SHA was resealed).
    assert "CASELAW_GATE_ATTESTATION_INVALID" in rc, (
        f"signed receipt should also reject; got {rc!r}"
    )
    assert "bad_file_sha" not in rc, (
        f"file-integrity should pass after reseal; got {rc!r}"
    )


# ---------------------------------------------------------------------------
# Test 3 — Granularity: hide ONE misquote -> REDERIVATION_MISMATCH
# ---------------------------------------------------------------------------


def test_hidden_single_misquote_fails_rederivation(tmp_path):
    """Producer flips only the MISQUOTE assertion's claimed status to ROOTED
    (keeping the decision ROUTE_TO_HUMAN, since an UNRESOLVED remains), reseals the
    SHA. The recompute disagrees on that one record -> REDERIVATION_MISMATCH.
    Proves the comparison covers the whole verdict object, not just the decision."""
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)

    honest = _claimed_verdict(bundle_dir)
    misquote_id = _first_id_with_status(honest, "MISQUOTE")

    claim_path = bundle_dir / "outputs" / "gate_verdict.json"
    doc = json.loads(claim_path.read_bytes())
    for c in doc["value"]["citations"]:
        if c["id"] == misquote_id:
            c["status"] = "ROOTED"
    assert doc["value"]["decision"] == "ROUTE_TO_HUMAN"
    new_bytes = (
        json.dumps({"value": doc["value"]}, indent=2, sort_keys=True) + "\n"
    ).encode()
    _reseal_file_sha(bundle_dir, "outputs/gate_verdict.json", new_bytes)

    result = _verifier().verify(bundle_dir)
    assert not result.ok, "Expected FAIL after hiding the misquote"
    rc = _reason_codes(result)
    assert "REDERIVATION_MISMATCH" in rc, f"Expected REDERIVATION_MISMATCH; got {rc!r}"
    # The mutated verdict also fails the Ed25519 attestation; file-integrity passes.
    assert "CASELAW_GATE_ATTESTATION_INVALID" in rc, (
        f"signed receipt should also reject; got {rc!r}"
    )
    assert "bad_file_sha" not in rc, (
        f"file-integrity should pass after reseal; got {rc!r}"
    )


# ---------------------------------------------------------------------------
# Test 4 — Evidence tamper: corpus byte changed, manifest NOT updated
# ---------------------------------------------------------------------------


def test_evidence_tamper_fails_file_sha(tmp_path):
    """Change a byte in corpus/rooted_records.json (mutate a common word in the
    rooted opinion text) WITHOUT updating manifest.files. The stale manifest SHA
    -> BAD_FILE_SHA from file_integrity_many_small."""
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)

    corpus_path = bundle_dir / "corpus" / "rooted_records.json"
    original = corpus_path.read_bytes()
    tampered = original.replace(b" the ", b" teh ", 1)
    assert tampered != original, "tamper precondition: a byte changed"
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
    passes. The auditor SpecAnchor is computed from the COMMITTED `exact` spec, so
    the substituted spec's SHA is not anchored -> AnchorViolation."""
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)

    weak_spec = json.loads(_SPEC_SRC.read_bytes())
    weak_spec["types"]["caselaw_gate_verdict"]["comparator"] = {"kind": "set"}
    weak_bytes = (
        json.dumps(weak_spec, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode()

    spec_path = bundle_dir / "spec" / _SPEC_BASENAME
    spec_path.write_bytes(weak_bytes)
    manifest_path = bundle_dir / "manifest.json"
    m = json.loads(manifest_path.read_bytes())
    m["spec_files"][_SPEC_BASENAME] = hashlib.sha256(weak_bytes).hexdigest()
    manifest_path.write_bytes(json.dumps(m, indent=2, sort_keys=True).encode("utf-8"))

    result = _verifier(_anchor_from_committed_spec()).verify(bundle_dir)
    assert not result.ok, "Expected FAIL: substituted spec is not authoritative"
    rc = _reason_codes(result)
    assert "AnchorViolation" in rc, (
        f"Expected AnchorViolation; got {rc!r}\n"
        f"{[(f.check_name, f.reason_code, f.detail) for f in result.failures]}"
    )


# ---------------------------------------------------------------------------
# Test 6 — Attestation isolated: corrupt the signature, reseal its file SHA
# ---------------------------------------------------------------------------


def test_attestation_signature_tamper_isolated(tmp_path):
    """Flip a byte in the Ed25519 signature and reseal attestation file SHA, so
    file-integrity passes AND the re-derivation passes (verdict + evidence are
    untouched). ONLY the C16 attestation check fires -> CASELAW_GATE_ATTESTATION_
    INVALID. Proves the signed receipt is an independently load-bearing surface,
    not a restatement of the re-derivation."""
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)

    rel = "attestation/gate_attestation.json"
    doc = json.loads((bundle_dir / rel).read_bytes())
    sig = doc["signature"]
    doc["signature"] = sig[:-1] + ("0" if sig[-1] != "0" else "1")  # still valid hex
    new_bytes = (
        json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode()
    _reseal_file_sha(bundle_dir, rel, new_bytes)

    result = _verifier().verify(bundle_dir)
    assert not result.ok, "Expected FAIL after signature tamper"
    rc = _reason_codes(result)
    assert "CASELAW_GATE_ATTESTATION_INVALID" in rc, (
        f"Expected attestation INVALID; got {rc!r}"
    )
    # Isolation: re-derivation and file-integrity must still pass (only the signed
    # receipt fires) -- proving the attestation is an independent surface.
    assert "REDERIVATION_MISMATCH" not in rc, (
        f"verdict untouched, re-derivation should pass; {rc!r}"
    )
    assert "bad_file_sha" not in rc, (
        f"file-integrity should pass after reseal; got {rc!r}"
    )


# ---------------------------------------------------------------------------
# Test 7 — Pubkey swap (forge-resistance): attacker swaps the trust anchor
# ---------------------------------------------------------------------------


def test_pubkey_swap_fails_attestation(tmp_path):
    """Attacker substitutes their OWN public key at attestation/gate_verifier_
    pubkey.hex and reseals its file SHA, but cannot reproduce the original
    gate-authority signature (they lack the private key). The C16 check verifies
    the committed signature against the swapped key and fails ->
    CASELAW_GATE_ATTESTATION_INVALID, while the re-derivation still passes. This
    is the forge-resistance property: holding (or swapping in) a public key is not
    enough to mint a verdict. (In-bundle anchor; full third-party trust = C18.)"""
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)

    # A different, VALID keypair (any 32-byte seed is a valid Ed25519 private key);
    # commit its public key as the swapped trust anchor.
    attacker_key = Ed25519VerifierKey.from_hex("ab" * 32)
    new_bytes = (attacker_key.public_key().to_hex() + "\n").encode("utf-8")
    _reseal_file_sha(bundle_dir, "attestation/gate_verifier_pubkey.hex", new_bytes)

    result = _verifier().verify(bundle_dir)
    assert not result.ok, "Expected FAIL after pubkey swap"
    rc = _reason_codes(result)
    assert "CASELAW_GATE_ATTESTATION_INVALID" in rc, (
        f"Expected attestation INVALID; got {rc!r}"
    )
    assert "REDERIVATION_MISMATCH" not in rc, (
        f"verdict untouched, re-derivation should pass; {rc!r}"
    )
