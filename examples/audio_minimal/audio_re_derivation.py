#!/usr/bin/env python3
"""audio_re_derivation.py — stdlib re-derivation pack for VAD audio domain.

Re-derives speech-segment boundaries from committed int16 PCM bytes using
the committed VAD spec. Asserts the bundled transcript matches frame-for-frame.

the audit-bundle contract §C6 (re-derivation pack — domain-agnostic substrate).
AB4: stdlib only — json and bytes manipulation; no struct, no numpy, no wave.

Reads:
  spec/segmentation.json      — VAD parameters (schema vad-v1)
  audio/samples.bin           — 16-bit signed little-endian PCM
  payload/transcript.json     — segment boundary list produced by the model

Re-derivation:
  1. Validate spec schema == "vad-v1".
  2. Unpack int16 samples from raw bytes (no struct — pure int.from_bytes).
  3. Compute per-frame energy: sum(s*s) over each frame of frame_size samples.
  4. Walk frames, accumulate consecutive above-threshold runs of >= min_segment_frames.
  5. Compare derived segment list against payload/transcript.json on
     (segment_id, start_frame, end_frame). The "text" field is informational
     and is NOT compared — only boundary values constitute the auditable claim.
  6. Exit 0 on match; exit 1 with [AUDIO_REDER_FAIL] <description> on stderr.

Usage:
    python audio_re_derivation.py --bundle-dir /path/to/bundle
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Sample unpacking — stdlib only, no struct
# ---------------------------------------------------------------------------


def _unpack_int16_le(raw: bytes) -> list[int]:
    """Unpack little-endian int16 samples from raw bytes without struct."""
    if len(raw) % 2 != 0:
        raise ValueError(
            f"raw bytes length {len(raw)} is not a multiple of 2 (expected int16 pairs)"
        )
    samples: list[int] = []
    for i in range(len(raw) // 2):
        samples.append(int.from_bytes(raw[2 * i:2 * i + 2], "little", signed=True))
    return samples


# ---------------------------------------------------------------------------
# VAD re-derivation
# ---------------------------------------------------------------------------


def _run_vad(samples: list[int], spec: dict) -> list[dict]:
    """Return list of segment dicts from spec-declared VAD parameters.

    Each dict: {"segment_id": int, "start_frame": int, "end_frame": int}
    start_frame inclusive, end_frame exclusive.
    """
    fs: int = spec["frame_size"]
    threshold: int = spec["energy_threshold"]
    min_seg: int = spec["min_segment_frames"]
    n_samples: int = spec["n_samples"]
    n_frames: int = n_samples // fs

    # Compute per-frame energy
    energies: list[int] = []
    for f in range(n_frames):
        frame = samples[f * fs:(f + 1) * fs]
        energies.append(sum(s * s for s in frame))

    # Walk frames, accumulate consecutive above-threshold runs
    above = [e >= threshold for e in energies]
    segments: list[dict] = []
    seg_id = 1
    start: int | None = None
    run_len = 0

    for f, a in enumerate(above):
        if a:
            if start is None:
                start = f
            run_len += 1
        else:
            if start is not None and run_len >= min_seg:
                segments.append({
                    "segment_id": seg_id,
                    "start_frame": start,
                    "end_frame": f,
                })
                seg_id += 1
            start = None
            run_len = 0

    # Flush last run
    if start is not None and run_len >= min_seg:
        segments.append({
            "segment_id": seg_id,
            "start_frame": start,
            "end_frame": n_frames,
        })

    return segments


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _verify(bundle_dir: Path) -> str | None:
    """Return an error description on mismatch, or None on success."""
    spec_path = bundle_dir / "spec" / "segmentation.json"
    audio_path = bundle_dir / "audio" / "samples.bin"
    transcript_path = bundle_dir / "payload" / "transcript.json"

    for p, label in [
        (spec_path, "spec/segmentation.json"),
        (audio_path, "audio/samples.bin"),
        (transcript_path, "payload/transcript.json"),
    ]:
        if not p.exists():
            return f"{label} absent from bundle_dir {bundle_dir}"

    # Load spec
    try:
        spec: dict = json.loads(spec_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return f"failed to read spec/segmentation.json: {exc}"

    if spec.get("schema") != "vad-v1":
        return (
            f"spec schema mismatch: expected 'vad-v1', "
            f"got {spec.get('schema')!r}"
        )

    # Load raw audio
    try:
        raw = audio_path.read_bytes()
    except OSError as exc:
        return f"failed to read audio/samples.bin: {exc}"

    n_samples = spec["n_samples"]
    expected_bytes = n_samples * 2
    if len(raw) != expected_bytes:
        return (
            f"audio/samples.bin length mismatch: "
            f"expected {expected_bytes} bytes ({n_samples} int16), got {len(raw)}"
        )

    try:
        samples = _unpack_int16_le(raw)
    except ValueError as exc:
        return f"failed to unpack audio/samples.bin: {exc}"

    # Load bundled transcript
    try:
        transcript: dict = json.loads(transcript_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return f"failed to read payload/transcript.json: {exc}"

    bundled_segments: list[dict] = transcript.get("segments", [])

    # Re-derive segments
    derived_segments = _run_vad(samples, spec)

    # Compare counts
    if len(derived_segments) != len(bundled_segments):
        return (
            f"segment count mismatch: derived={len(derived_segments)}, "
            f"bundled={len(bundled_segments)}"
        )

    # Compare each segment on (segment_id, start_frame, end_frame)
    # text field is informational and is not compared.
    for idx, (derived, bundled) in enumerate(zip(derived_segments, bundled_segments)):
        for key in ("segment_id", "start_frame", "end_frame"):
            d_val = derived.get(key)
            b_val = bundled.get(key)
            if d_val != b_val:
                return (
                    f"segment index {idx} field {key!r} mismatch: "
                    f"derived={d_val!r}, bundled={b_val!r}"
                )

    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audio VAD re-derivation check for audio audit bundles"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    error = _verify(bundle_dir)
    if error is None:
        return 0

    print(f"[AUDIO_REDER_FAIL] {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
