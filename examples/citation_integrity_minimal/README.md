# `citation_integrity_minimal` — L8 fragment-attestation, packaged

A multi-citation **citation-integrity** demonstration of the L8 fragment-attestation
engine. A set of ~4 synthetic citations quotes two admitted source documents; each
citation emits a per-quote `fragment_anchor` (a locator + `content_selector.exact`)
bound to its source snapshot. The standard verifier (`veriker/cli/verify.py`,
`FragmentAttestationCheck` — **default-ON**, no `typed_checks` entry needed) re-derives
every cited span from the **frozen snapshot bytes** and asserts the quote matches its
source under a deterministic, versioned text normalization (NFC + casefold +
punctuation-drop + whitespace-collapse — case/punctuation/whitespace-insensitive, **not**
byte-exact).

This widens the single-citation proof to a
realistic citation *set*, exercises **both** locked resolver kinds (byte-offset AND
sentence-ID), and adds the fail-closed edges the single-citation test doesn't cover.

## What it shows

| # | mutation (one anchor changed from the all-genuine baseline) | result |
|---|---|---|
| 0 | none — all ~4 citations match their source (byte-offset + sentence-ID) | **PASS** `FRAGMENTS_ATTESTED` |
| 1 | one byte-offset citation's quote replaced with a plausible fabrication | **FAIL** `FRAGMENT_MISQUOTE` |
| 2 | one byte-offset anchor's `end` pushed past the snapshot length | **FAIL** `FRAGMENT_OFFSET_OUT_OF_BOUNDS` |
| 3 | the sentence-ID anchor stamped with a drifted `segmenter_version` | **FAIL** `SEGMENTER_MISMATCH` |
| 4 | one anchor's `source_cid` not declared in `manifest.snapshots` | **FAIL** `FRAGMENT_SOURCE_UNRESOLVABLE` |
| 5 | the genuine sentence-ID citation alone | **PASS** `FRAGMENTS_ATTESTED` |

Headline: a citation set verifies clean only when **every** quote matches its admitted
source under the deterministic text normalization (above); any single fabricated quote,
out-of-bounds offset, or
stale-segmenter anchor fails the **whole bundle** closed — deterministically, no model,
no answer key.

## Run

```
python -m pytest examples/citation_integrity_minimal/tests/test_citation_integrity.py -q
```

## The honest claim (read this)

This proves citation **INTEGRITY / re-derivability**: the quoted bytes match the cited
span of the admitted source, **deterministically, with no LLM, auditor-reproducible**.
The source snapshot IS the ground truth — there is no answer key.

It does **NOT**:
- prove the source is **true** in the world — adjudicating input-fact truth is the
  domain expert / auditor's job, not the verifier's (a faithfully-quoted falsehood still
  PASSes, correctly: faithful quotation of a wrong source is exactly what
  citation-integrity attests, and nothing more);
- mean "**compliant**" with any standard — it is evidence-for-a-control, never a
  compliance verdict;
- attempt **W3C TextQuoteSelector relocation**. The selector `prefix`/`suffix` relocation
  fields are never exercised; this is a **same-snapshot** demonstration only. Relocating a
  quote across structure drift is genuine unsolved research, orthogonal to misquote
  detection, and correctly deferred (ADR D3.b).

The two source passages are synthetic, demo-only prose (NOT verbatim from any real
publication), so this pilot carries no named-firm or private content and is safe on any
surface.

## Engine (reused, untouched)

- `audit_bundle/plugins/fragment_attestation.py` — the default-ON enforcing plugin.
- `audit_bundle/fragments/fragment_id.py` — the FragmentID tagged-union.
- `audit_bundle/fragments/sentence_segmenter.py` — the deterministic segmenter + resolvers.
- ADR: `the internal design notes` (D1–D7).
- Build scope: `the internal design notes`.
