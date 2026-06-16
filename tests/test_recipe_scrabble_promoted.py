"""tests/test_recipe_scrabble_promoted.py — the `scrabble` shape is PROMOTED into
the shippable core registry (RECIPE_BOOK.md).

Two things are proven, deliberately without a tautology:

  GENERIC SAFE PATH. The bundle is verified by a BARE BundleVerifier under an
  auditor SpecAnchor with NO demo-local register_primitive and WITHOUT importing
  the primitive module at all. The only thing that resolves the recompute is the
  core registry auto-registration (run_spec_pinned_dispatch ->
  _ensure_primitives_loaded -> import primitives -> scrabble self-registers). If
  scrabble were not promoted, the dispatch would fail UNKNOWN_PRIMITIVE.

  PRODUCER-FAITHFULNESS (not f(x)==f(x)). The producer's claimed ruling is
  derived from the PRODUCER's own emitted artifact (payload/ruling.json) — an
  INDEPENDENT code path from the verifier's primitives/scrabble.py. The claimed
  {edition_cited, word, is_legal} is constructed by reading `edition_cited` and
  `word` directly from the producer's payload/ruling.json, and mapping
  `ruling == "legal"` to `is_legal`. The verifier recomputes its ruling
  independently from the committed timeline + dispute + wordlists and compares.
  An honest PASS proves the two independent derivation paths agree — if they ever
  drift, this test FAILS. The claim is never routed through the verifier's own
  compute_ruling.

Run SOLO — shared bundle basenames collide in one pytest process.

Surfaces:
  1. Honest bundle -> PASS (generic safe path AND producer-faithfulness).
  2. Tampered claimed value (flip is_legal) -> REDERIVATION_MISMATCH.
  3. Tampered committed input (remove the disputed word from the resolved wordlist)
     -> REDERIVATION_MISMATCH (manifest SHA re-aligned so FileIntegrity does not
     preempt the dispatch mismatch).

For (2)/(3) the manifest file SHA is re-aligned so FileIntegrity does not fire
first — isolating the re-derivation mismatch from a plain integrity failure.

Stdlib-only orchestration; the build runs the pilot's real producer _build_bundle.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

import hashlib  # noqa: E402

# NOTE: the verifier's recompute primitive (primitives/scrabble.py) is deliberately
# NOT imported here. The claim is derived from the producer artifact, and the
# primitive must resolve ONLY via dispatch's core auto-registration.
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.dispatch_record_wellformed import (  # noqa: E402
    DispatchRecordWellformedCheck,
)
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from examples._spec_pinned_overlay import apply_overlay, compute_anchor  # noqa: E402

_PILOT_DIR = _PKG_ROOT / "examples" / "scrabble_minimal"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "scrabble.spec.json"
_OUTPUT_ID = "scrabble_ruling"
_TYPE_KEY = "scrabble_ruling"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _ruling_from_producer_payload(bundle_dir: Path) -> dict:
    """Extract the representative ruling claim {edition_cited, word, is_legal}
    from the PRODUCER's independently-emitted payload/ruling.json.

    This is the anti-tautology source: the producer's own output, not the
    verifier's compute_ruling. The producer sets `ruling` to "legal"/"illegal"
    and records `edition_cited` + `word` directly; we map ruling -> is_legal
    here without calling any verifier code.
    """
    payload = json.loads((bundle_dir / "payload" / "ruling.json").read_bytes())
    return {
        "edition_cited": payload["edition_cited"],
        "word": payload["word"],
        "is_legal": payload["ruling"] == "legal",
    }


def _build(out_dir: Path, *, claimed_override=None):
    """Build a spec-pinned scrabble bundle producer-side. Returns (bundle, anchor).

    The base bundle is produced by the pilot's real _build_bundle.py (dictionaries/,
    editions/jurisdiction_timeline.json, disputes/D-0001.json, payload/ruling.json,
    manifest.json). The HONEST claimed ruling is derived from the producer's OWN
    emitted payload/ruling.json — an independent code path from the verifier
    primitive. The generic β overlay then adds the auditor spec, the producer
    claimed-value file, and manifest.outputs.
    """
    subprocess.run(
        [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(out_dir)],
        check=True,
        capture_output=True,
    )
    # Producer-side claim: read the producer's independently-emitted payload/ruling.json.
    claimed = _ruling_from_producer_payload(out_dir)
    if claimed_override is not None:
        claimed = claimed_override
    apply_overlay(
        out_dir,
        spec_src_path=_SPEC_SRC,
        output_id=_OUTPUT_ID,
        type_key=_TYPE_KEY,
        claimed_value=claimed,
    )
    # Match manifest.typed_checks to the minimal plugin set we run (the verifier
    # rejects a typed_checks name with no matching plugin instance).
    mp = out_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["typed_checks"] = ["file_integrity_many_small"]
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))
    return out_dir, compute_anchor(_SPEC_SRC)


def _realign_file_sha(bundle_dir: Path, rel: str) -> None:
    """Recompute and store the manifest SHA for one file so FileIntegrity does not
    fire before the re-derivation dispatch can be observed."""
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][rel] = _sha256((bundle_dir / rel).read_bytes())
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))


def _verify(bundle_dir: Path, anchor):
    # BARE verifier: FileIntegrity + spec-pinned dispatch under the auditor anchor.
    # NO register_primitive — the recompute resolves only via the CORE registry.
    return BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            # The bundle carries dispatch_records; verify()'s stamp-claims
            # coverage guard fails closed unless C15 well-formedness and the
            # C14 lattice claim are both evaluated (2026-06-12). Orthogonal
            # to what this test proves (core-registry recompute path).
            DispatchRecordWellformedCheck(op_kinds_admitted=frozenset({"EDITION_RESOLVE", "MEMBERSHIP_LOOKUP", "COMPUTE"})),
            StampLatticeCheck(),
        ],
        spec_anchor=anchor,
    ).verify(bundle_dir)


def test_promoted_generic_safe_path_and_faithfulness_pass(tmp_path):
    # Honest PASS proves BOTH: the generic verifier resolves scrabble via core
    # auto-registration (no import, no demo registration), AND the verifier's
    # recompute agrees with the producer's independent payload/ruling.json.
    bundle_dir, anchor = _build(tmp_path / "bundle")
    result = _verify(bundle_dir, anchor)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_promoted_tampered_value_fails(tmp_path):
    # Flip is_legal in the producer's claimed ruling — a different object than
    # the honest re-derivation.
    bundle_dir, anchor = _build(tmp_path / "bundle")
    claim_path = bundle_dir / "outputs" / f"{_OUTPUT_ID}.json"
    doc = json.loads(claim_path.read_bytes())
    honest = doc["value"]
    tampered = dict(honest)
    tampered["is_legal"] = not honest["is_legal"]
    doc["value"] = tampered
    assert doc["value"] != honest
    claim_path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    _realign_file_sha(bundle_dir, f"outputs/{_OUTPUT_ID}.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_promoted_tampered_edition_resolution_fails(tmp_path):
    # Negative control for the EDITION-RESOLUTION step (the [start, end) date-window
    # lookup in primitives/scrabble.py). Mutate the committed
    # editions/jurisdiction_timeline.json so a DIFFERENT WESPA-INTL edition resolves
    # at the dispute timestamp (2024-08-15): extend synthetic_csw_alpha's window to
    # cover the timestamp and push synthetic_csw_beta's start past it. The verifier
    # then re-derives edition_cited=synthetic_csw_alpha (ZARFY is absent there, so
    # is_legal=False), diverging from the producer's honest claim
    # {synthetic_csw_beta, ZARFY, True}. The producer payload is NOT regenerated.
    bundle_dir, anchor = _build(tmp_path / "bundle")
    claimed = _ruling_from_producer_payload(bundle_dir)
    assert claimed["edition_cited"] == "synthetic_csw_beta"
    assert claimed["is_legal"] is True

    tl_rel = "editions/jurisdiction_timeline.json"
    tl_path = bundle_dir / tl_rel
    timeline = json.loads(tl_path.read_bytes())
    for entry in timeline["authorities"]["WESPA-INTL"]:
        if entry["edition"] == "synthetic_csw_alpha":
            entry["end"] = None  # alpha now open-ended -> covers 2024-08-15
        elif entry["edition"] == "synthetic_csw_beta":
            entry["start"] = "2099-01-01T00:00:00Z"  # beta no longer active
    tl_path.write_bytes(json.dumps(timeline, indent=2, sort_keys=True).encode("utf-8"))
    _realign_file_sha(bundle_dir, tl_rel)

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_promoted_tampered_input_fails(tmp_path):
    # Mutate the committed wordlist so membership re-derives is_legal=False,
    # diverging from the honest claimed value (True for ZARFY in synthetic_csw_beta).
    bundle_dir, anchor = _build(tmp_path / "bundle")
    claimed = _ruling_from_producer_payload(bundle_dir)
    assert claimed["is_legal"] is True  # ZARFY is in synthetic_csw_beta
    assert claimed["edition_cited"] == "synthetic_csw_beta"

    # Remove the disputed word from its resolved edition's wordlist.
    word = claimed["word"]
    wl_rel = f"dictionaries/{claimed['edition_cited']}.txt"
    wl_path = bundle_dir / wl_rel
    lines = wl_path.read_text(encoding="utf-8").splitlines()
    new_lines = [ln for ln in lines if ln.strip().upper() != word]
    assert len(new_lines) < len(lines), "fixture: disputed word not found in wordlist"
    new_bytes = ("\n".join(new_lines) + "\n").encode("utf-8")
    wl_path.write_bytes(new_bytes)
    _realign_file_sha(bundle_dir, wl_rel)

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)
