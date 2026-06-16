"""tests/test_audio_spec_pinned.py — Axis-2 spec-pinned dispatch tests for the
per-dir migration of examples/audio_minimal.

Representative output: the set of VAD segment boundaries in payload/transcript.json —
the unordered SET of [start_frame, end_frame] pairs (segment_id and text are NOT
compared; only boundary pairs are auditable). It is recomputed by a
frame-energy-threshold VAD over the committed int16 little-endian PCM bytes in
audio/samples.bin under spec/segmentation.json, mirroring the legacy
audio_re_derivation pack's _run_vad EXACTLY. Comparator: `set` (no params,
order-independent). NOTE: the set-comparator mismatch surfaces under the dispatch's
REDERIVATION_MISMATCH reason code (the dispatch wraps the comparator result).

Covers the required surfaces (S0 disclosed-method exit gate):
  1. Honest bundle -> PASS under a real auditor SpecAnchor.
  2. Tampered claimed value (drop/alter a boundary pair) -> FAIL
     (REDERIVATION_MISMATCH).
  3. Tampered input (mutate the committed PCM so a segment boundary shifts;
     re-align manifest SHA so FileIntegrity does not fire first) -> FAIL
     (REDERIVATION_MISMATCH).
  4. No auditor anchor while the bundle declares outputs -> fail-closed
     (AnchorViolation).
  5. §4a attack: producer ships a spec the auditor did NOT anchor (same spec_id,
     but a DIFFERENT primitive_id -> different bytes -> different SHA). The auditor
     anchor is computed from the COMMITTED spec, so the substituted spec's SHA is
     not anchored -> fail-closed (AnchorViolation).
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "audio_minimal"
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# The pilot's recompute module + spec-pinned harness are loaded by path so this
# test does not depend on cwd.
_load("audio_recompute", _PILOT_DIR / "audio_recompute.py")
_spc = _load("audio_spec_pinned_check", _PILOT_DIR / "spec_pinned_check.py")


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def test_honest_pass(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_tampered_value_fails(tmp_path):
    # Producer claims a DIFFERENT boundary set than the honest re-derivation:
    # alter the first pair's end_frame (5 -> 6) so the claimed set no longer
    # matches the VAD-recomputed set.
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        claimed_override=[[0, 6], [10, 15], [20, 25], [30, 35], [40, 45]],
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_tampered_input_fails(tmp_path):
    # Build honest, then perturb the COMMITTED PCM so a boundary SHIFTS. Frames are
    # frame_size=160 samples. Zeroing frame 2 (samples 320..479) of the first voiced
    # run [0,5) drops that frame's energy below threshold, splitting the run: frames
    # 0,1 form a 2-frame run (< min_segment_frames=5, dropped) and frames 3,4 form a
    # 2-frame run (also dropped). The first boundary pair [0,5] disappears from the
    # re-derived set while the honest claimed set still contains it -> mismatch.
    # Re-align the manifest SHA so FileIntegrityManySmall (step-2) does not fire
    # before dispatch — isolate the re-derivation mismatch.
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    samples_path = bundle_dir / "audio" / "samples.bin"
    raw = bytearray(samples_path.read_bytes())
    # int16 LE: sample k occupies bytes [2k, 2k+2). Zero samples 320..479 (frame 2).
    for k in range(320, 480):
        raw[2 * k] = 0
        raw[2 * k + 1] = 0
    new_bytes = bytes(raw)
    samples_path.write_bytes(new_bytes)

    # audio/samples.bin is a payload file recorded in manifest.files; re-align its
    # SHA so FileIntegrityManySmall does not fire before dispatch.
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_text("utf-8"))
    m["files"]["audio/samples.bin"] = hashlib.sha256(new_bytes).hexdigest()
    mp.write_text(json.dumps(m, indent=2, sort_keys=True), encoding="utf-8")

    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_no_anchor_fails_closed(tmp_path):
    bundle_dir = _spc.build_spec_pinned(tmp_path / "bundle")
    result = _spc.make_verifier(anchor=None).verify(bundle_dir)
    assert not result.ok
    assert "AnchorViolation" in _reason_codes(result), _reason_codes(result)


def test_substituted_spec_fails_closed(tmp_path):
    # §4a attack: producer ships a spec the auditor did NOT anchor. Same spec_id,
    # but a DIFFERENT primitive_id -> different bytes -> different SHA. The auditor
    # anchor is computed from the COMMITTED spec, so the substituted spec's SHA is
    # not anchored -> fail-closed.
    other_spec = json.dumps(
        {
            "spec_id": "audio.v1",
            "types": {
                "audio_vad_boundaries": {
                    "primitive_id": "some_other_unanchored_primitive",
                    "comparator": {"kind": "set"},
                }
            },
        }
    ).encode("utf-8")
    bundle_dir = _spc.build_spec_pinned(
        tmp_path / "bundle",
        claimed_override=[[0, 5], [10, 15], [20, 25], [30, 35], [40, 45]],
        spec_bytes_override=other_spec,
    )
    anchor = _spc.anchor_from_committed_spec()
    result = _spc.make_verifier(anchor).verify(bundle_dir)
    assert not result.ok
    codes = _reason_codes(result)
    assert "AnchorViolation" in codes, codes
