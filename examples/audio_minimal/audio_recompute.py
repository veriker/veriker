"""audio_recompute.py — re-export shim for the PROMOTED primitive.

The audio re-derivation primitive has been promoted into the shippable core
registry: audit_bundle/rederivation/primitives/audio.py (RECIPE_BOOK.md, shape
`audio`). The VAD traversal now lives in verifier-DISTRIBUTION code and the
generic verifier carries it — a third party running the generic verifier against
an audio bundle recomputes on the SAFE spec-pinned path with no demo-local code.

This module is kept as a thin re-export so the existing per-dir call sites
(spec_pinned_check.py, tests/test_audio_spec_pinned.py) import the SAME
`compute_vad_boundaries` / class object that the core registry uses. Sharing ONE
definition is the point: the honest producer claim and the verifier's
re-derivation cannot drift, and registering `AudioRecompute()` from a call site
is idempotent with the core auto-registration (same class object —
register_primitive raises only on same-id/DIFFERENT-class).

Importing this module now requires audit_bundle on sys.path (the core package).
Every real call site already puts the package root on sys.path.
"""

from __future__ import annotations

from audit_bundle.rederivation.primitives.audio import (  # noqa: F401
    AudioRecompute,
    _run_vad_boundaries,
    _unpack_int16_le,
    compute_vad_boundaries,
)

__all__ = [
    "AudioRecompute",
    "_run_vad_boundaries",
    "_unpack_int16_le",
    "compute_vad_boundaries",
]
