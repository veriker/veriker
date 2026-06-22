"""_build_bundle.py — build a deterministic audio_minimal audit bundle.

Generates a synthetic int16 PCM waveform with alternating voiced/silent regions,
runs a frame-energy-threshold VAD to derive speech-segment boundaries, and emits
a standards-compliant manifest.

Usage (from v-kernel-audit-bundle root):
    python examples/audio_minimal/_build_bundle.py --out-dir /tmp/audio_bundle

Outputs:
  <out-dir>/audio/samples.bin       (8000 int16 samples, little-endian, 16000 bytes)
  <out-dir>/spec/segmentation.json  (VAD parameters)
  <out-dir>/payload/transcript.json (derived segment boundary list)
  <out-dir>/manifest.json

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.emitter import BundleContent, write_bundle  # noqa: E402

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "audio-minimal-rc"
_CREATED_AT = "2026-05-09T00:00:00Z"
_TYPED_CHECKS = [
    "spec_sha_pin",
    "file_integrity_many_small",
    "audio_re_derivation",
]

# ---------------------------------------------------------------------------
# VAD spec constants (mirrored in spec/segmentation.json)
# ---------------------------------------------------------------------------

_SPEC = {
    "schema": "vad-v1",
    "frame_size": 160,
    "energy_threshold": 1000000,
    "min_segment_frames": 5,
    "sample_rate_hz": 16000,
    "n_samples": 8000,
}


# ---------------------------------------------------------------------------
# Waveform generator — deterministic alternating voiced/silent regions
#
# For sample index i in 0..7999:
#   voiced  (i // 800) % 2 == 0: sample = ((i * 7) % 6000) - 3000   (~±3000)
#   silent  otherwise:           sample = ((i * 3) % 100) - 50       (~±50)
#
# With frame_size=160 and 8000 samples we get 50 frames total.
# Every 800 samples = 5 frames flips between voiced and silent.
# Result: 5 voiced segments at frames [0,5), [10,15), [20,25), [30,35), [40,45).
# Voiced frame energy ~18M-972M >> threshold 1,000,000.
# Silent frame energy ~127K-138K << threshold 1,000,000.
# ---------------------------------------------------------------------------


def _generate_samples() -> list[int]:
    """Return 8000 int16 samples as a Python list of ints."""
    samples: list[int] = []
    for i in range(8000):
        if (i // 800) % 2 == 0:
            s = ((i * 7) % 6000) - 3000
        else:
            s = ((i * 3) % 100) - 50
        samples.append(s)
    return samples


def _samples_to_bytes(samples: list[int]) -> bytes:
    """Pack int16 samples as little-endian bytes."""
    parts: list[bytes] = []
    for s in samples:
        parts.append(s.to_bytes(2, "little", signed=True))
    return b"".join(parts)


# ---------------------------------------------------------------------------
# VAD — frame-energy threshold segmentation
# ---------------------------------------------------------------------------


def _run_vad(samples: list[int], spec: dict) -> list[dict]:
    """Return list of segment dicts from spec-declared VAD parameters.

    Each segment: {"segment_id": int, "start_frame": int, "end_frame": int,
                   "text": str}
    start_frame inclusive, end_frame exclusive.
    text is a deterministic placeholder; boundary values are the auditable claim.
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
                    "text": f"synthetic_segment_{seg_id}",
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
            "text": f"synthetic_segment_{seg_id}",
        })

    return segments


def build(out_dir: Path) -> None:
    # ---- generate audio/samples.bin bytes ----
    samples = _generate_samples()
    raw_bytes = _samples_to_bytes(samples)

    # ---- generate spec/segmentation.json bytes ----
    spec_bytes = json.dumps(_SPEC, indent=2).encode("utf-8")

    # ---- derive segments ----
    segments = _run_vad(samples, _SPEC)
    assert len(segments) == 5, (
        f"Expected 5 voiced segments, got {len(segments)}: {segments}"
    )

    # ---- generate payload/transcript.json bytes ----
    transcript = {"segments": segments}
    transcript_bytes = json.dumps(transcript, indent=2).encode("utf-8")

    # ---- emit via the reference-emitter SDK ----
    # spec/ tree is owned by spec_files (walked by SpecShaPinCheck), not files
    # (which FileIntegrityManySmall skips for spec/). The two plugins cover
    # disjoint trees by construction.
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "audio/samples.bin": raw_bytes,
            "payload/transcript.json": transcript_bytes,
        },
        spec_files={"segmentation.json": spec_bytes},
        typed_checks=_TYPED_CHECKS,
    )
    manifest = write_bundle(out_dir, content)
    files = manifest["files"]

    print(f"Bundle written to {out_dir}")
    print(f"  samples          : {len(samples)} int16")
    print(f"  raw bytes        : {len(raw_bytes)}")
    print(f"  voiced segments  : {len(segments)}")
    print(f"  manifest files   : {len(files)}")
    print(f"  manifest         : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic audio_minimal audit bundle"
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        type=Path,
        help="Destination directory (created if absent)",
    )
    args = parser.parse_args()
    try:
        build(args.out_dir.resolve())
    except AssertionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
