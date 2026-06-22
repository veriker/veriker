"""Round-trip integration test for examples/scrabble_minimal/verify.py.

Test flow:
  1. Import _build_bundle.build from the pilot directory.
  2. Build the bundle into a tmp_path.
  3. Run the verifier with the pilot's plugin set.
  4. Assert result.ok is True.
  5. Manifest-shape assertions: OpaqueFragment(kind_tag=lexical_entry) anchor
     present + dispatch_records carry EDITION_RESOLVE and MEMBERSHIP_LOOKUP.
  6. Tamper test 1: byte-flip a wordlist file -> SHA mismatch (caught by
     FileIntegrityManySmall, NOT by ScrabbleReDerivationCheck).
  7. Tamper test 2: rewrite payload edition_cited (preserving wordlist SHAs;
     re-stamp manifest.files for ruling.json so file integrity does not mask
     the re-derivation failure) -> SCRABBLE_EDITION_MISMATCH.
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
_PILOT_DIR = _PKG_ROOT / "examples" / "scrabble_minimal"

# Insert pkg root so audit_bundle.* imports work in the test process.
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# Insert pilot dir so ScrabbleReDerivationCheck can be imported directly.
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
    "scrabble_minimal._build_bundle",
    _PILOT_DIR / "_build_bundle.py",
)
_scrabble_check_mod = _import_module_from_path(
    "ScrabbleReDerivationCheck",
    _PILOT_DIR / "ScrabbleReDerivationCheck.py",
)

from audit_bundle.plugins.dispatch_record_wellformed import (
    DispatchRecordWellformedCheck,
)
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck
from audit_bundle.verifier import BundleVerifier

ScrabbleReDerivationCheck = _scrabble_check_mod.ScrabbleReDerivationCheck


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            ScrabbleReDerivationCheck(),
            DispatchRecordWellformedCheck(
                op_kinds_admitted=frozenset(
                    {"EDITION_RESOLVE", "MEMBERSHIP_LOOKUP", "COMPUTE"}
                )
            ),
            StampLatticeCheck(),
        ]
    )


def _restamp_manifest_file(bundle_dir: Path, rel_path: str) -> None:
    """Recompute manifest.files[rel_path] SHA from the on-disk bytes."""
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    new_sha = hashlib.sha256((bundle_dir / rel_path).read_bytes()).hexdigest()
    manifest["files"][rel_path] = new_sha
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_scrabble_minimal_build_and_verify(tmp_path: Path) -> None:
    """Build a fresh bundle and verify it — result.ok must be True."""
    bundle_dir = tmp_path / "scrabble_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is True, f"Expected result.ok=True; failures:\n" + "\n".join(
        f"  [{f.check_name}] {f.reason_code}: {f.detail}" for f in result.failures
    )


def test_scrabble_minimal_manifest_has_lexical_entry_anchor(tmp_path: Path) -> None:
    """The built manifest must contain at least 1 OpaqueFragment(kind_tag=lexical_entry) anchor."""
    bundle_dir = tmp_path / "scrabble_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    anchors = manifest.get("fragment_anchors", {})

    opaque_lex = [
        v
        for v in anchors.values()
        if v.get("kind") == "opaque" and v.get("kind_tag") == "lexical_entry"
    ]
    assert len(opaque_lex) >= 1, (
        f"Expected >= 1 OpaqueFragment(kind_tag=lexical_entry) anchor; "
        f"got {len(opaque_lex)}"
    )


def test_scrabble_minimal_manifest_has_resolve_and_lookup_dispatch(
    tmp_path: Path,
) -> None:
    """The built manifest must contain dispatch_records with op.kind in
    {EDITION_RESOLVE, MEMBERSHIP_LOOKUP}."""
    bundle_dir = tmp_path / "scrabble_bundle"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    records = manifest.get("dispatch_records", [])

    kinds = {r.get("op", {}).get("kind") for r in records}
    assert "EDITION_RESOLVE" in kinds, (
        f"Expected dispatch_record with op.kind=EDITION_RESOLVE; found kinds: {kinds}"
    )
    assert "MEMBERSHIP_LOOKUP" in kinds, (
        f"Expected dispatch_record with op.kind=MEMBERSHIP_LOOKUP; found kinds: {kinds}"
    )


# ---------------------------------------------------------------------------
# Tamper path 1: byte-flip a wordlist file (SHA-level tamper)
# ---------------------------------------------------------------------------


def test_scrabble_minimal_tamper_wordlist_byte_flip_fails(tmp_path: Path) -> None:
    """Mutating bytes of a wordlist file must cause result.ok=False with
    a file_integrity (bad_file_sha) failure surfaced by FileIntegrityManySmall.

    We deliberately do NOT re-stamp manifest.files here — the tamper is
    detected at the SHA layer before the re-derivation plugin runs.
    """
    bundle_dir = tmp_path / "scrabble_tampered_bytes"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    wordlist_path = bundle_dir / "dictionaries" / "synthetic_csw_beta.txt"
    raw = wordlist_path.read_bytes()
    # Flip a single byte in the body (preserve trailing LF so the file still parses)
    assert len(raw) > 5
    flipped = bytes([raw[0] ^ 0x01]) + raw[1:]
    wordlist_path.write_bytes(flipped)

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "Expected result.ok=False after byte-flipping a wordlist file"
    )
    reason_codes = [f.reason_code for f in result.failures]
    assert "bad_file_sha" in reason_codes, (
        f"Expected bad_file_sha in failure reason_codes; got {reason_codes!r}"
    )


# ---------------------------------------------------------------------------
# Tamper path 2: rewrite edition_cited in payload (re-derivation tamper)
# ---------------------------------------------------------------------------


def test_scrabble_minimal_tamper_edition_cited_fails(tmp_path: Path) -> None:
    """Rewriting payload.ruling edition_cited so it disagrees with the timeline-
    resolved edition must cause result.ok=False with SCRABBLE_EDITION_MISMATCH
    surfaced by ScrabbleReDerivationCheck.

    We MUST re-stamp manifest.files for payload/ruling.json so file integrity
    does not mask the re-derivation failure with a SHA mismatch first
    (mirrors the kg_minimal tamper-test pattern)."""
    bundle_dir = tmp_path / "scrabble_tampered_edition"
    bundle_dir.mkdir()
    _build_bundle_mod.build(bundle_dir)

    ruling_path = bundle_dir / "payload" / "ruling.json"
    ruling = json.loads(ruling_path.read_text(encoding="utf-8"))
    # Original: jurisdiction=WESPA-INTL, edition_cited=synthetic_csw_beta (correct).
    # Swap to synthetic_twl_v2 — that's a NASPA-NA edition; timeline will
    # not match it for jurisdiction=WESPA-INTL.
    assert ruling["edition_cited"] == "synthetic_csw_beta"
    ruling["edition_cited"] = "synthetic_twl_v2"
    ruling_path.write_text(
        json.dumps(ruling, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _restamp_manifest_file(bundle_dir, "payload/ruling.json")

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "Expected result.ok=False after rewriting payload.edition_cited"
    )
    reason_codes = [f.reason_code for f in result.failures]
    detail_texts = [f.detail for f in result.failures]
    combined = " ".join(reason_codes + detail_texts).upper()
    assert "SCRABBLE_EDITION_MISMATCH" in combined, (
        f"Expected SCRABBLE_EDITION_MISMATCH in failure reason_codes or detail; "
        f"got reason_codes={reason_codes!r}, detail snippets={detail_texts!r}"
    )
