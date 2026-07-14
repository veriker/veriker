"""scrabble_recompute.py — re-export shim for the PROMOTED scrabble primitive.

The scrabble re-derivation primitive has been promoted into the shippable core
registry: audit_bundle/rederivation/primitives/scrabble.py (RECIPE_BOOK.md,
shape `scrabble dictionary adjudication (lexical-membership)`). The recompute
rule computes dictionary MEMBERSHIP (is_legal = word in the resolved edition's
wordlist) — not tile scoring. It now lives in verifier-DISTRIBUTION code and the
generic verifier carries it — a third party running the generic verifier against
a scrabble_minimal bundle recomputes on the SAFE spec-pinned path with no
demo-local code.

This module is kept as a thin re-export so the existing per-dir call sites
(spec_pinned_check.py, tests/test_scrabble_spec_pinned.py) import the SAME
`compute_ruling`, `ScrabbleRecompute`, `_parse_iso`, and `_read_wordlist` the
core registry uses. This is a shared single definition kept in SYNC — not an
independent re-derivation. Sharing ONE definition is the point: these call sites
and the core registry stay value-identical by construction, and registering
`ScrabbleRecompute()` here is idempotent with the core auto-registration
(identical class object). The producer-faithfulness anti-tautology guarantee
comes from the test sourcing its honest claim from the PRODUCER's emitted
artifact (payload/ruling.json), NOT from this shared compute path.

Importing this module now requires audit_bundle on sys.path (the core package).
Every real call site already puts the package root on sys.path.
"""

from __future__ import annotations

from audit_bundle.rederivation.primitives.scrabble import (  # noqa: F401
    ScrabbleRecompute,
    _parse_iso,
    _read_wordlist,
    compute_ruling,
)

__all__ = [
    "ScrabbleRecompute",
    "compute_ruling",
    "_parse_iso",
    "_read_wordlist",
]
