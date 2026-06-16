"""Deterministic sentence ID resolver for audit_bundle fragment addressing.

v1 segmenter: regex-based, decimal-number-aware. Splits on sentence-terminal
punctuation followed by whitespace, but uses a negative lookbehind on digit
sequences so that '17.4' is not split at '17.' (the W1-W2 stamper bug
surfaced in simple_sentence_match.json fixtures).

Known v1 limitations (spec-acknowledged):
  - Abbreviations like 'Dr.' or 'St.' will be treated as sentence boundaries.
  - Mid-sentence ellipsis ('...') may produce unexpected splits.
  - Decimal numbers are protected but edge cases remain (e.g. list items like
    '1. First item').

Domain pilots that hit these edge cases should bundle a SegmenterMismatch
coverage row rather than misclassify. The v2 segmenter (nltk.PunktSentenceTokenizer)
is W4-scope, NOT W3.

SEGMENTER_VERSION is exposed so per-bundle SegmenterMismatch checks can detect
when a stored fragment was produced by a different segmenter than the current
runtime.
"""

from __future__ import annotations

import re

from audit_bundle.fragments.fragment_id import BadFragmentID, ByteOffsetFragment

SEGMENTER_VERSION = "0.1-decimal-aware-regex"

# Sentence-terminal punctuation: one or more [.!?], followed by whitespace,
# but NOT when the punctuation is a decimal point (digit before + digit after).
# Negative lookbehind: (?<!\d) — don't split when preceded by a digit.
# Negative lookahead:  (?!\d) — don't split when the char after whitespace is
#   a digit that continues the number (handles '17.4 is high' vs 'Done. 4 items').
# The lookahead deliberately does NOT protect 'Done. 4 items' from splitting;
# that ambiguity is a spec-known limitation of the v1 regex approach.
_SENTENCE_SPLIT_RE = re.compile(r"(?<!\d)[.!?]+(?!\d)\s+")


def segment_sentences(text: str) -> list[tuple[int, int, str]]:
    """Split *text* into sentences and return (start_byte, end_byte, sentence_text) tuples.

    Byte offsets are UTF-8 encoded positions into the original text.
    Whitespace runs within a sentence are collapsed to single spaces.
    The returned list is non-empty for any non-empty text input.
    """
    if not text:
        return []

    # Split on sentence boundaries; keep the split position info via finditer.
    # We reconstruct spans manually to track byte offsets.
    raw_sentences: list[str] = []
    char_starts: list[int] = []

    prev_end = 0
    for m in _SENTENCE_SPLIT_RE.finditer(text):
        # Include the punctuation in the current sentence.
        sentence_raw = text[prev_end : m.end()].rstrip()
        if sentence_raw:
            raw_sentences.append(sentence_raw)
            char_starts.append(prev_end)
        prev_end = m.end()

    # Tail (last sentence after the final boundary, or the whole text if no split).
    tail = text[prev_end:].strip()
    if tail:
        raw_sentences.append(tail)
        char_starts.append(prev_end)

    if not raw_sentences:
        # Nothing split cleanly — treat entire stripped text as one sentence.
        stripped = text.strip()
        if stripped:
            raw_sentences = [stripped]
            char_starts = [text.index(stripped)]
        else:
            return []

    result: list[tuple[int, int, str]] = []

    for raw, char_start in zip(raw_sentences, char_starts):
        # Collapse internal whitespace runs to a single space.
        sentence_text = " ".join(raw.split())

        # Map character start → byte start by encoding the prefix.
        byte_start = len(text[:char_start].encode("utf-8"))
        byte_end = byte_start + len(sentence_text.encode("utf-8"))

        result.append((byte_start, byte_end, sentence_text))

    return result


def resolve_sentence_id(text: str, sentence_index: int) -> tuple[int, int, str]:
    """Return the *sentence_index*-th sentence tuple from *text*.

    Raises BadFragmentID if *sentence_index* is out of range.
    """
    sentences = segment_sentences(text)
    if sentence_index < 0 or sentence_index >= len(sentences):
        raise BadFragmentID(
            f"sentence_index {sentence_index} out of range for text with "
            f"{len(sentences)} sentence(s)"
        )
    return sentences[sentence_index]


def resolve_byte_offset(text: str, fragment: ByteOffsetFragment) -> str:
    """Return the substring of *text* identified by *fragment*'s byte offsets.

    Offsets are UTF-8 byte positions (half-open: [start, end)).
    Raises BadFragmentID if the bounds fall outside the encoded text length.
    """
    encoded = text.encode("utf-8")
    if fragment.start >= len(encoded) or fragment.end > len(encoded):
        raise BadFragmentID(
            f"ByteOffsetFragment [{fragment.start}, {fragment.end}) out of "
            f"bounds for text of {len(encoded)} UTF-8 byte(s)"
        )
    return encoded[fragment.start : fragment.end].decode("utf-8")
