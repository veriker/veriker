"""tests/test_recipe_audio_promoted.py — the `audio` shape (frame-energy VAD
boundary pairs) is PROMOTED into the shippable core registry (RECIPE_BOOK.md).

Two things are proven, deliberately without a tautology:

  GENERIC SAFE PATH. The bundle is verified by a BARE BundleVerifier under an
  auditor SpecAnchor with NO demo-local register_primitive and WITHOUT importing
  the primitive module at all. The only thing that resolves the recompute is the
  core registry auto-registration (run_spec_pinned_dispatch ->
  _ensure_primitives_loaded -> import primitives -> audio self-registers). If it
  were not promoted, dispatch would fail UNKNOWN_PRIMITIVE.

  PRODUCER-FAITHFULNESS (not f(x)==f(x)). The producer's claimed boundary set is
  read from the producer's OWN emitted payload/transcript.json segments
  (segment_id/text dropped, only [start_frame, end_frame] pairs kept), NOT the
  verifier's recompute. The verifier re-runs the frame-energy VAD over the
  committed audio/samples.bin under spec/segmentation.json and compares
  order-independently (`set`). An honest PASS proves the producer's segmentation
  and the verifier's re-derivation agree on the committed exemplar — if the two
  copies drift, this test FAILS. The claim is never routed through
  compute_vad_boundaries.

Run SOLO — shared bundle basenames collide in one pytest process.

Surfaces:
  1. Honest bundle -> PASS (generic safe path AND producer-faithfulness).
  2. Tampered claimed value (shift one boundary pair) -> REDERIVATION_MISMATCH.
  3. Tampered committed input (zero out audio/samples.bin so every frame is below
     threshold → the VAD re-derives an EMPTY boundary set) -> REDERIVATION_MISMATCH.
     audio/ is a regular committed file; manifest.files is re-aligned so
     FileIntegrity does not fire first.

Stdlib-only orchestration; the build runs the pilot's real producer _build_bundle.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# NOTE: the verifier's recompute primitive (primitives/audio.py) is deliberately
# NOT imported here. The claim is derived from the producer artifact, and the
# primitive must resolve ONLY via dispatch's core auto-registration.
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from examples._spec_pinned_overlay import apply_overlay, compute_anchor  # noqa: E402

_PILOT_DIR = _PKG_ROOT / "examples" / "audio_minimal"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "audio.spec.json"
_OUTPUT_ID = "audio_vad_boundaries"
_TYPE_KEY = "audio_vad_boundaries"
_AUDIO_REL = "audio/samples.bin"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _build(out_dir: Path, *, claimed_override=None):
    """Build a spec-pinned audio bundle producer-side.

    The base bundle is produced by the pilot's real _build_bundle.py (audio/samples.bin,
    spec/segmentation.json, payload/transcript.json, manifest). The HONEST claimed
    boundary set is read from the producer's OWN payload/transcript.json segments —
    independent of the verifier's compute_vad_boundaries.
    """
    subprocess.run(
        [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(out_dir)],
        check=True,
        capture_output=True,
    )
    transcript = json.loads((out_dir / "payload" / "transcript.json").read_bytes())
    claimed = [[s["start_frame"], s["end_frame"]] for s in transcript["segments"]]
    if claimed_override is not None:
        claimed = claimed_override
    apply_overlay(
        out_dir,
        spec_src_path=_SPEC_SRC,
        output_id=_OUTPUT_ID,
        type_key=_TYPE_KEY,
        claimed_value=claimed,
    )
    mp = out_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["typed_checks"] = ["file_integrity_many_small"]
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))
    return out_dir, compute_anchor(_SPEC_SRC)


def _realign_file_sha(bundle_dir: Path, rel: str) -> None:
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][rel] = _sha256((bundle_dir / rel).read_bytes())
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))


def _verify(bundle_dir: Path, anchor):
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()], spec_anchor=anchor
    ).verify(bundle_dir)


def test_promoted_generic_safe_path_and_faithfulness_pass(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    result = _verify(bundle_dir, anchor)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_promoted_tampered_value_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    claim_path = bundle_dir / "outputs" / f"{_OUTPUT_ID}.json"
    doc = json.loads(claim_path.read_bytes())
    honest = doc["value"]
    assert honest, "expected at least one boundary pair in the honest claim"
    # Shift the end_frame of the first boundary pair by +1 (producer lies).
    doc["value"] = [list(pair) for pair in honest]
    doc["value"][0][1] = doc["value"][0][1] + 1
    assert doc["value"] != honest
    claim_path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    _realign_file_sha(bundle_dir, f"outputs/{_OUTPUT_ID}.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert _reason_codes(result) == {"REDERIVATION_MISMATCH"}, _reason_codes(result)


def test_promoted_tampered_input_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Zero out the committed PCM (same length, so n_frames is unchanged): every
    # frame energy becomes 0 < threshold → the VAD re-derives an EMPTY boundary
    # set, diverging from the (honest) non-empty claimed set.
    audio_path = bundle_dir / _AUDIO_REL
    n = len(audio_path.read_bytes())
    audio_path.write_bytes(b"\x00" * n)
    _realign_file_sha(bundle_dir, _AUDIO_REL)

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert _reason_codes(result) == {"REDERIVATION_MISMATCH"}, _reason_codes(result)
