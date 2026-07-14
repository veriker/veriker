"""audit_bundle/output_modes/ve_pipeline.py — VE-mode constrained-generation wrapper.

CONTRACT class: domain pilots subclass and override segment detection.
Canary version accepts pre-segmented JSON input for directly testable correctness.

K1 lock (the mesh pilot §Output mode policy): VE constrained
to quote-supported content; unsupported synthesis is SUPPRESSED, not labeled.

PRODUCER-SIDE scope note: this pipeline is emitter scaffolding an honest
producer applies to its OWN model output before minting a bundle. It is NOT a
trust boundary — the producer is untrusted in the V-Kernel threat model, and a
dishonest producer can skip this class entirely. The trust-bearing check is the
verifier's: attestable fragment anchors are re-derived from frozen snapshots by
``plugins/fragment_attestation.py``, and ``BundleVerifier.verify()`` fails
closed on any present-but-unverified quote claim. What this class buys an
honest producer is that its model cannot launder synthesized text past it by
stamping a quote-supporting CID — the RES-06 scenario: segment text is checked
verbatim (under the SAME versioned canonicalization the verifier uses) against
the stamped source, so producer-side suppression and verifier-side attestation
agree by construction.
"""

from __future__ import annotations

import json
from typing import Callable

from .mode import ModeSignal, OutputMode
from audit_bundle.fragments.attestable import normalize_text
from audit_bundle.retrieval.three_set import ThreeSetView


class VEPipeline:
    """Verified Extractive post-processor — suppresses any segment whose text is
    not a verbatim (canonicalized) span of its stamped quote-supporting source.

    Canary contract: raw_output is JSON
      {'segments': [{'text': str, 'stamped_source_cid': str | None}, ...]}
    Production subclasses override _parse_segments for real model output formats.
    """

    def __init__(
        self,
        generation_constraints: tuple[str, ...] = (
            "quote_supported_only",
            "abstain_on_ambiguity",
        ),
    ) -> None:
        self.generation_constraints = generation_constraints

    def _parse_segments(self, raw_output: str) -> list[dict]:
        """Parse raw_output into segment dicts (canary: JSON input).

        Production subclasses override to handle real model output formats.
        """
        parsed = json.loads(raw_output)
        return parsed["segments"]

    def post_process(
        self,
        raw_output: str,
        three_set: ThreeSetView,
        source_text_lookup: Callable[[str], str],
    ) -> str:
        """Suppress all segments not backed by a VERIFIED verbatim quote.

        K1 suppression rules (ALL must hold to retain a segment):
          1. stamped_source_cid is not None
          2. stamped_source_cid is in three_set.quote_supporting
          3. the segment text occurs VERBATIM in source_text_lookup(cid),
             compared under the verifier's versioned text canonicalization
             (``fragments.attestable.normalize_text``,
             TEXT_CANONICALIZATION_VERSION) — a stamped CID is a claim, not a
             pass; the text must actually be a quote of the stamped source
             (RES-06: a synthesized segment carrying a quote-supporting CID
             label is suppressed, the label alone keeps nothing).

        Fail-closed: a source_text_lookup that raises or returns a non-str for
        a stamped CID suppresses the segment (a quote that cannot be checked
        is not retained); a segment whose canonicalized text is empty asserts
        no falsifiable quote and is suppressed.

        Retained segments are concatenated in order; suppressed segments leave
        no trace in the output (not labeled — VE is strict by design).

        Parameters
        ----------
        raw_output
            Pre-segmented JSON string (canary form).
        three_set
            ThreeSetView for this output; quote_supporting is the authority
            on WHICH sources may be quoted (the text check is the authority
            on WHETHER the segment actually quotes one).
        source_text_lookup
            Callable from source_cid to that source's text — the producer's
            own frozen snapshot view. Consulted for every retained segment;
            lookup failure suppresses (never retains-unverified).
        """
        segments = self._parse_segments(raw_output)
        quote_supporting_set = set(three_set.quote_supporting)
        source_canon_cache: dict[str, str | None] = {}
        kept: list[str] = []
        for segment in segments:
            cid = segment.get("stamped_source_cid")
            if cid is None:
                continue
            if cid not in quote_supporting_set:
                continue
            segment_canon = normalize_text(segment["text"])
            if not segment_canon:
                continue  # nothing falsifiable claimed — suppress
            if cid not in source_canon_cache:
                try:
                    source_text = source_text_lookup(cid)
                except Exception:  # noqa: BLE001 — unverifiable => suppress
                    source_text = None
                source_canon_cache[cid] = (
                    normalize_text(source_text)
                    if isinstance(source_text, str)
                    else None
                )
            source_canon = source_canon_cache[cid]
            if source_canon is None or segment_canon not in source_canon:
                continue  # not a verbatim quote of the stamped source — suppress
            kept.append(segment["text"])
        return "".join(kept)

    def emit_signal(self) -> ModeSignal:
        """Return the ModeSignal locking this pipeline's mode and constraints."""
        return ModeSignal(
            mode=OutputMode.VE,
            generation_constraints=self.generation_constraints,
        )
