"""spectra_span_recompute — verifier-side text-span re-derivation primitive.

Axis-2 value-return form of the Spectra EXTRACTIVE stamper invariant (the fused
examples/spectra_minimal/span_re_derivation.py, split into recompute + compare).

recompute(): reads the producer's pointer inputs/span_claim.json
{source_cid, fragment_id}, loads corpus/<source_cid>.txt, segments it into
sentences, and RETURNS the source fragment text. It does NOT compare. The
verifier's text_normalized[spectra_v1] comparator then checks the producer's
claimed span (outputs/<id>.json) normalizes-equal to this re-derived source
fragment — so a tampered/hallucinated span fails closed.

Stdlib-only.
"""

from __future__ import annotations

import re
from pathlib import Path

from ...admission import admit_json_file
from ...plugin import ParsedInputs, RecomputedValue
from ..registry import register_primitive
from ._safepath import resolve_within

# Sentence terminator mirroring span_re_derivation.py::_SENT_END (decimal
# exception). Duplicated verifier-side per AB4 — this module is the authority.
_SENT_END = re.compile(r"(?<!\d)[.!?]+(?!\d)")


def _sentence_segments(text: str) -> list[str]:
    parts = _SENT_END.split(text)
    return [p.strip() for p in parts if p.strip()]


class SpectraSpanRecompute:
    primitive_id: str = "spectra_span_recompute"

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        bundle_dir: Path = inputs.bundle_dir
        claim_path = bundle_dir / "inputs" / "span_claim.json"
        claim = admit_json_file(claim_path)
        source_cid = claim["source_cid"]
        fragment_id = int(claim["fragment_id"])

        # source_cid is bundle-controlled; contain the read inside corpus/ so a
        # hostile "../../etc/passwd" or absolute path can't steer an arbitrary
        # host-file read (mirrors build.py/scrabble.py resolve_within). Escape
        # raises ValueError -> RECOMPUTE_ERROR (fail closed).
        corpus_path = resolve_within(bundle_dir / "corpus", f"{source_cid}.txt")
        doc_text = corpus_path.read_text(encoding="utf-8")
        fragments = _sentence_segments(doc_text)
        if fragment_id < 0 or fragment_id >= len(fragments):
            raise ValueError(
                f"fragment_id={fragment_id} out of range "
                f"(corpus/{source_cid}.txt has {len(fragments)} fragment(s))"
            )
        return RecomputedValue(
            value=fragments[fragment_id],
            detail=f"source fragment {fragment_id} of corpus/{source_cid}.txt",
        )


register_primitive(SpectraSpanRecompute())
