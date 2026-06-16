"""audio_recompute — verifier-side VAD segment-boundary re-derivation.

Axis-2 value-return form of the audio re-derivation, PROMOTED into the shippable
core registry (RECIPE_BOOK.md, shape `audio`). The generic verifier recomputes
the representative output on the SAFE spec-pinned path: no subprocess, no
bundle-supplied code — the VAD traversal lives HERE in verifier-distribution code
and the comparator comes from the auditor-anchored spec.

Re-derivation primitive (one sentence):
    boundaries = the set of [start_frame, end_frame] pairs produced by a
    frame-energy-threshold VAD over the committed int16 little-endian PCM bytes
    in audio/samples.bin under spec/segmentation.json (frame_size,
    energy_threshold, min_segment_frames, n_samples).

The VAD MIRRORS the legacy pack's _run_vad EXACTLY: int16 little-endian unpack
via int.from_bytes (no struct); per-frame energy = sum(s*s) over frame_size
samples; walk frames accumulating consecutive runs whose energy >=
energy_threshold; emit a [start, end] pair (start inclusive, end exclusive) for
every run of length >= min_segment_frames, flushing a trailing run at n_frames.
Only the boundary pair is the auditable claim — segment_id and text are NOT
re-derived or compared. The auditor's SHA-pinned spec binds the output type
"audio_vad_boundaries" to this primitive_id and to a `set` comparator (no params
— order-independent collection equality). A producer cannot weaken the traversal
without changing the primitive_id, which the anchor would reject.

Comparator scope (honest limitation): `set` equality is multiplicity-blind —
it compares the boundary pairs as a Python set, so a duplicated pair would not
be distinguished from a single occurrence. This is acceptable for THIS shape
because VAD boundary pairs are distinct by construction: the traversal emits at
most one [start, end) per consecutive above-threshold run and the runs are
disjoint and strictly increasing in frame index, so no legitimate boundary set
contains a duplicate. The choice trades multiplicity-sensitivity for
order-independence between producer and verifier; it is NOT a general claim that
the comparator would catch a multiplicity attack on a shape whose values can
repeat.

Faithfulness (verifier-side reimplementation — Gate B):
  - compute_vad_boundaries mirrors the producer pack's _run_vad EXACTLY. The
    promoted test derives the honest claim from the producer's OWN emitted
    payload/transcript.json segment boundaries — NOT from this module — so an
    honest PASS proves the verifier reproduces the producer's segmentation
    (not f(x)==f(x)).

Stdlib-only (§C5 core verify() path): json is stdlib; the int16 unpack uses
int.from_bytes (no struct dependency).
"""

from __future__ import annotations

from pathlib import Path

from ...admission import admit_json_file
from ...plugin import ParsedInputs, RecomputedValue
from ..registry import register_primitive


# ---------------------------------------------------------------------------
# Canonical computation (shared by the builder and the verifier — ONE source)
# ---------------------------------------------------------------------------


def _unpack_int16_le(raw: bytes) -> list[int]:
    """Unpack little-endian int16 samples from raw bytes without struct.

    Mirrors the legacy audio_re_derivation._unpack_int16_le byte-for-byte.
    """
    if len(raw) % 2 != 0:
        raise ValueError(
            f"raw bytes length {len(raw)} is not a multiple of 2 (expected int16 pairs)"
        )
    samples: list[int] = []
    for i in range(len(raw) // 2):
        samples.append(int.from_bytes(raw[2 * i : 2 * i + 2], "little", signed=True))
    return samples


def _run_vad_boundaries(samples: list[int], spec: dict) -> list[list[int]]:
    """Return the list of [start_frame, end_frame] boundary pairs.

    Mirrors the legacy audio_re_derivation._run_vad EXACTLY, but returns ONLY
    the boundary pairs (start inclusive, end exclusive) — segment_id/text are
    not re-derived. Builder and verifier share this ONE definition so the honest
    boundaries and the re-derivation cannot drift.
    """
    fs: int = spec["frame_size"]
    threshold: int = spec["energy_threshold"]
    min_seg: int = spec["min_segment_frames"]
    n_samples: int = spec["n_samples"]
    n_frames: int = n_samples // fs

    # Compute per-frame energy
    energies: list[int] = []
    for f in range(n_frames):
        frame = samples[f * fs : (f + 1) * fs]
        energies.append(sum(s * s for s in frame))

    # Walk frames, accumulate consecutive above-threshold runs
    above = [e >= threshold for e in energies]
    boundaries: list[list[int]] = []
    start: int | None = None
    run_len = 0

    for f, a in enumerate(above):
        if a:
            if start is None:
                start = f
            run_len += 1
        else:
            if start is not None and run_len >= min_seg:
                boundaries.append([start, f])
            start = None
            run_len = 0

    # Flush last run
    if start is not None and run_len >= min_seg:
        boundaries.append([start, n_frames])

    return boundaries


def compute_vad_boundaries(raw: bytes, spec: dict) -> list[list[int]]:
    """Canonical boundary recompute. Unpacks int16 PCM then runs the VAD.

    Returns the [start_frame, end_frame] pairs as a list (the `set` comparator
    compares it order-independently against the claimed collection).
    """
    samples = _unpack_int16_le(raw)
    return _run_vad_boundaries(samples, spec)


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered at import for the core registry)
# ---------------------------------------------------------------------------


class AudioRecompute:
    """Verifier-side primitive for re-deriving the VAD boundary-pair collection."""

    primitive_id: str = "audio_recompute"

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        """Recompute the boundary pairs from the committed PCM bytes + VAD spec.

        Returns the recomputed VALUE only; the auditor-anchored `set` comparator
        decides agreement order-independently.
        """
        bundle_dir: Path = inputs.bundle_dir

        spec_path = bundle_dir / "spec" / "segmentation.json"
        if not spec_path.is_file():
            raise FileNotFoundError(
                f"spec/segmentation.json not found in bundle at {bundle_dir}"
            )
        spec = admit_json_file(spec_path)
        if spec.get("schema") != "vad-v1":
            raise ValueError(
                f"spec schema mismatch: expected 'vad-v1', got {spec.get('schema')!r}"
            )

        audio_path = bundle_dir / "audio" / "samples.bin"
        if not audio_path.is_file():
            raise FileNotFoundError(
                f"audio/samples.bin not found in bundle at {bundle_dir}"
            )
        raw = audio_path.read_bytes()

        value = compute_vad_boundaries(raw, spec)
        return RecomputedValue(
            value=value,
            detail=(
                f"re-derived {len(value)} VAD boundary pair(s) via frame-energy "
                f"threshold (frame_size={spec.get('frame_size')!r} "
                f"energy_threshold={spec.get('energy_threshold')!r} "
                f"min_segment_frames={spec.get('min_segment_frames')!r}) -> {value!r}"
            ),
        )


register_primitive(AudioRecompute())
