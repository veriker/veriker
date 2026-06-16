"""scrabble_recompute — verifier-side Scrabble dictionary-adjudication re-derivation.

Axis-2 value-return form of the scrabble_minimal re-derivation, PROMOTED into the
shippable core registry (RECIPE_BOOK.md, shape `scrabble dictionary adjudication
(lexical-membership)`). This recompute computes dictionary MEMBERSHIP
(is_legal = word in the resolved edition's wordlist) — it does NOT compute
tile scoring, multipliers, or bingo bonuses. The generic
verifier recompute the representative output on the SAFE spec-pinned path: no
subprocess, no bundle-supplied code — the recompute rule lives HERE in verifier-
distribution code and the comparator + tolerance come from the auditor-anchored spec.

Re-derivation primitive (one sentence):
    ruling = resolve(jurisdiction, timestamp) -> effective edition via the committed
    timeline, then test word membership in that edition's wordlist;
    emit {edition_cited, word, is_legal}.

The representative re-derived output is the ruling object {edition_cited, word,
is_legal} obtained by:
  1. resolving the effective edition for (jurisdiction, timestamp) from the
     committed jurisdiction_timeline.json: the entry whose [start, end) window
     contains the timestamp (end=None is open-ended);
  2. loading the resolved edition's wordlist from dictionaries/<edition>.txt;
  3. testing whether the uppercased, stripped word is in the wordlist's stripped
     non-empty lines.

The resolution + membership rule is FIXED in this primitive — the primitive_id
("scrabble_recompute") IS the rule. The auditor's SHA-pinned spec binds the output
type "scrabble_ruling" to this primitive_id and to an `exact` comparator (element-
wise equality of the {edition_cited, word, is_legal} object); a producer cannot
weaken the resolution or membership check without changing the primitive_id / spec
SHA, which the anchor rejects.

Faithfulness note: the computation is entirely integer/boolean/string — no float
arithmetic, no summation-order sensitivity. The output is deterministic given the
committed inputs (timeline JSON, dispute JSON, wordlist file). The `exact` comparator
is correct: re-derivation always produces the same boolean is_legal and the same
string fields for the same inputs.

Stdlib-only (§C5 core verify() path).
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ...admission import admit_json_file
from ...plugin import ParsedInputs, RecomputedValue
from ..registry import register_primitive
from ._safepath import resolve_within


# ---------------------------------------------------------------------------
# Canonical computation. The pilot's examples/scrabble_minimal/scrabble_recompute.py
# is a thin re-export of THIS module (one shared definition, not an independent
# copy) — so the per-dir call sites and the core registry are value-identical by
# construction (kept in sync, not independently re-derived). The output is a dict
# of two strings + a bool; there are no serialized bytes to be "byte-identical".
# ---------------------------------------------------------------------------


def _parse_iso(ts: str) -> datetime:
    """Parse an ISO-8601 timestamp with trailing 'Z' to a tz-aware datetime.

    Mirrors examples/scrabble_minimal/scrabble_recompute._parse_iso EXACTLY.
    """
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts).astimezone(timezone.utc)


def _read_wordlist(path: Path) -> set[str]:
    """Return the set of stripped non-empty uppercase words in a wordlist file.

    Mirrors examples/scrabble_minimal/scrabble_recompute._read_wordlist EXACTLY.
    """
    return {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }


def compute_ruling(bundle_dir: Path, timeline: dict, dispute: dict) -> dict:
    """Canonical Scrabble dictionary-adjudication re-derivation.

    Mirrors examples/scrabble_minimal/scrabble_recompute.compute_ruling EXACTLY:

      1. Resolve the effective edition for (jurisdiction, timestamp): the timeline
         entry whose [start, end) window contains the timestamp (end=None is open).
      2. Read the resolved edition's wordlist file from the bundle.
      3. is_legal = uppercased word in the wordlist's stripped non-empty lines.

    Returns the representative ruling object {edition_cited, word, is_legal}.

    Fail-closed: raises KeyError/TypeError/ValueError/FileNotFoundError if the
    timeline/dispute are malformed, the jurisdiction is unknown, no edition is
    active at the timestamp, or the resolved wordlist is missing.
    """
    authorities = timeline["authorities"]
    if not isinstance(authorities, dict):
        raise TypeError("timeline 'authorities' must be a dict")

    word = str(dispute["word"]).strip().upper()
    jurisdiction = dispute["jurisdiction"]
    ts = _parse_iso(dispute["timestamp"])

    if jurisdiction not in authorities:
        raise KeyError(
            f"jurisdiction {jurisdiction!r} not in timeline; "
            f"known: {sorted(authorities.keys())}"
        )

    resolved_entry = None
    for entry in authorities[jurisdiction]:
        start = _parse_iso(entry["start"])
        end = _parse_iso(entry["end"]) if entry["end"] is not None else None
        if start <= ts and (end is None or ts < end):
            resolved_entry = entry
            break
    if resolved_entry is None:
        raise ValueError(
            f"no edition active for jurisdiction={jurisdiction!r} "
            f"at timestamp={dispute['timestamp']!r}"
        )

    edition_cited = resolved_entry["edition"]
    # wordlist_file is timeline-controlled (bundle data): contain the read inside
    # the bundle so a hostile timeline cannot steer it to an out-of-tree file via
    # '..' or an absolute path. Fails closed (ValueError -> RECOMPUTE_ERROR).
    wordlist_path = resolve_within(bundle_dir, resolved_entry["wordlist_file"])
    if not wordlist_path.is_file():
        raise FileNotFoundError(
            f"wordlist file {resolved_entry['wordlist_file']!r} for "
            f"edition={edition_cited!r} not present in bundle"
        )

    is_legal = word in _read_wordlist(wordlist_path)
    return {"edition_cited": edition_cited, "word": word, "is_legal": is_legal}


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered at import for the core registry)
# ---------------------------------------------------------------------------


class ScrabbleRecompute:
    """Verifier-side primitive for re-deriving the Scrabble ruling object.

    Registered into the core registry on import (self-registration trigger
    via primitives/__init__.py). Third parties running the generic verifier
    against a scrabble_minimal bundle resolve this primitive automatically —
    no demo-local register_primitive call, no bundle-supplied code.
    """

    primitive_id: str = "scrabble_recompute"

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        """Recompute the ruling from the committed timeline + dispute + wordlists.

        Returns the ruling VALUE only — does not read any acceptance epsilon and
        does not compare; the auditor-anchored `exact` comparator decides agreement
        against outputs/<id>.json.
        """
        bundle_dir: Path = inputs.bundle_dir

        timeline_path = bundle_dir / "editions" / "jurisdiction_timeline.json"
        dispute_path = bundle_dir / "disputes" / "D-0001.json"
        if not timeline_path.is_file():
            raise FileNotFoundError(
                f"editions/jurisdiction_timeline.json not found in bundle at {bundle_dir}"
            )
        if not dispute_path.is_file():
            raise FileNotFoundError(
                f"disputes/D-0001.json not found in bundle at {bundle_dir}"
            )

        timeline = admit_json_file(timeline_path)
        dispute = admit_json_file(dispute_path)
        if not isinstance(timeline, dict) or "authorities" not in timeline:
            raise ValueError(
                "editions/jurisdiction_timeline.json: missing required 'authorities'"
            )

        value = compute_ruling(bundle_dir, timeline, dispute)
        return RecomputedValue(
            value=value,
            detail=(
                f"re-derived ruling word={value['word']!r} -> "
                f"is_legal={value['is_legal']!r} under edition={value['edition_cited']!r}"
            ),
        )


register_primitive(ScrabbleRecompute())
