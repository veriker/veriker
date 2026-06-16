"""caselaw_gate_recompute.py — verifier-side case-law citation credibility-gate
re-derivation primitive.

Axis-2 value-return form (SPEC_PINNED_DISPATCH_ARCHITECTURE §3.3). Self-contained
per-dir pilot on spec-pinned dispatch: the recompute primitive lives HERE
(verifier-distribution code, registered from the pilot's verify.py), NOT in
audit_bundle/rederivation/primitives/.

DOMAIN
------
An AI legal assistant (the producer) drafts a filing and asserts a set of
supporting citations, then claims an overall gate decision:

    AUTO_APPROVE      — every asserted citation is rooted; safe to file as-is.
    ROUTE_TO_HUMAN    — at least one citation is unresolved or misquoted;
                        a human must review before filing.

The credibility gate re-derives that decision from committed evidence. For each
asserted citation, in assertion order:

    UNRESOLVED   the normalized reporter cite is ABSENT from the rooted
                 court-record corpus  -> possible fabrication (default-deny).
    MISQUOTE     the cite resolves, but the producer's quoted holding is NOT
                 found verbatim (after normalization) in the rooted record's
                 holding text -> real source, fabricated/inverted quote.
    ROOTED       the cite resolves AND the quoted holding is a normalized
                 substring of the rooted holding text.

    decision = AUTO_APPROVE  iff  every citation is ROOTED, else ROUTE_TO_HUMAN.

This is the DEWR "real source / fabricated quote" rejection shape and the
scrabble_minimal "resolve-then-membership" shape, pointed at case law.

SCOPE (honest framing — read this before believing more than is claimed)
------------------------------------------------------------------------
The verifier proves the gate decision is RE-DERIVABLE and TAMPER-EVIDENT under
the auditor-anchored rule: given THIS rooted corpus, a producer cannot claim
AUTO_APPROVE while hiding a fabricated or misquoted citation — the recompute
disagrees and dispatch fails closed.

It does NOT establish that the corpus itself is genuine — that the listed cases
are real court records is a TRUST-ROOT concern (corpus genuineness, out of scope
for the verifier's re-derivation). At v0.1 the corpus is
a committed fixture of real, public U.S. patent cases; in production the corpus
is replaced by a trust-root resolver against a rooted authority (e.g.
CourtListener / PACER). The bundle shape and verification protocol are identical;
only the corpus provenance upgrades. (See README "What this proves / does not".)

Stdlib-only (§C5 contract). This module is importable WITHOUT audit_bundle on
sys.path (the RecomputedValue import is deferred into recompute()), so the
spec-pinned builder can import compute_gate_verdict() standalone.
"""

from __future__ import annotations

import json
from pathlib import Path

# Status constants — also the verdict vocabulary the `exact` comparator sees.
ROOTED = "ROOTED"
UNRESOLVED = "UNRESOLVED"
MISQUOTE = "MISQUOTE"

AUTO_APPROVE = "AUTO_APPROVE"
ROUTE_TO_HUMAN = "ROUTE_TO_HUMAN"

_CORPUS_REL = "corpus/rooted_records.json"
_ASSERTIONS_REL = "assertions/citation_assertions.json"


# ---------------------------------------------------------------------------
# Normalization — internal to the resolve/misquote logic (NOT the comparator).
# ---------------------------------------------------------------------------


def _norm(text: str) -> str:
    """Casefold + collapse all runs of whitespace to a single space + strip.

    Applied to reporter cites (for corpus membership) and to holding text (for
    the verbatim-misquote substring test). Deliberately conservative: it does
    NOT strip punctuation, so "573 U.S. 208" and "573 us 208" do NOT collide.
    """
    return " ".join(str(text).casefold().split())


# ---------------------------------------------------------------------------
# Canonical computation (shared by the builder and the verifier — ONE source)
# ---------------------------------------------------------------------------


def compute_gate_verdict(corpus: list, assertions: list) -> dict:
    """Canonical case-law credibility-gate re-derivation.

    `corpus`     — list of rooted records, each with at least `reporter_cite`
                   and `holding_text`.
    `assertions` — list of producer-asserted citations, each with `id`,
                   `reporter_cite`, and `quoted_holding`.

    Returns the representative verdict object:

        {
          "decision": "AUTO_APPROVE" | "ROUTE_TO_HUMAN",
          "citations": [ {"id", "reporter_cite", "status"}, ... ]  # assertion order
        }

    Builder and verifier share this ONE definition so the honest claimed verdict
    and the re-derivation cannot drift.

    Fail-closed: raises ValueError/TypeError/KeyError if the corpus or assertion
    records are malformed (the verifier must not invent a verdict).
    """
    if not isinstance(corpus, list):
        raise TypeError("corpus must be a JSON array of rooted records")
    if not isinstance(assertions, list):
        raise TypeError("assertions must be a JSON array of asserted citations")

    # Index the rooted corpus by normalized reporter cite. A duplicate cite in
    # the corpus is a fixture defect — fail closed rather than silently pick one.
    index: dict[str, dict] = {}
    for rec in corpus:
        if not isinstance(rec, dict):
            raise TypeError(f"corpus record not an object: {rec!r}")
        key = _norm(rec["reporter_cite"])
        if key in index:
            raise ValueError(f"duplicate reporter_cite in corpus: {rec['reporter_cite']!r}")
        index[key] = rec

    citations: list[dict] = []
    for a in assertions:
        if not isinstance(a, dict):
            raise TypeError(f"assertion not an object: {a!r}")
        cite = a["reporter_cite"]
        rec = index.get(_norm(cite))
        if rec is None:
            status = UNRESOLVED
        else:
            quoted = _norm(a["quoted_holding"])
            holding = _norm(rec["holding_text"])
            if quoted and quoted in holding:
                status = ROOTED
            else:
                status = MISQUOTE
        citations.append(
            {
                "id": a["id"],
                "reporter_cite": cite,
                "status": status,
            }
        )

    decision = (
        AUTO_APPROVE
        if citations and all(c["status"] == ROOTED for c in citations)
        else ROUTE_TO_HUMAN
    )
    return {"decision": decision, "citations": citations}


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered from the pilot's verify.py before verify)
# ---------------------------------------------------------------------------


class CaselawGateRecompute:
    """Verifier-side primitive re-deriving the citation credibility-gate verdict."""

    primitive_id: str = "caselaw_gate_recompute"

    def recompute(self, inputs, pack_section: dict):
        """Recompute the gate verdict from the committed corpus + assertions.

        inputs.bundle_dir is a read-only Path. pack_section carries
        {output_id, type, params} from the auditor's spec binding. Returns a
        RecomputedValue carrying the verdict object; the verifier's `exact`
        comparator compares it to the producer's claimed verdict.
        """
        # Deferred import keeps this module importable standalone (builder use).
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        bundle_dir: Path = inputs.bundle_dir
        corpus_path = bundle_dir / _CORPUS_REL
        assertions_path = bundle_dir / _ASSERTIONS_REL
        for p in (corpus_path, assertions_path):
            if not p.is_file():
                raise FileNotFoundError(f"required evidence missing in bundle: {p}")

        corpus = json.loads(corpus_path.read_bytes())
        assertions = json.loads(assertions_path.read_bytes())

        verdict = compute_gate_verdict(corpus, assertions)
        n_rooted = sum(1 for c in verdict["citations"] if c["status"] == ROOTED)
        return RecomputedValue(
            value=verdict,
            detail=(
                f"re-derived gate over {len(verdict['citations'])} citation(s): "
                f"{n_rooted} rooted -> decision={verdict['decision']}"
            ),
        )
