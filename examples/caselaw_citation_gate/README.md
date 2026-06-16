# caselaw_citation_gate — verbatim-rooted case-law citation credibility gate

**Axis-2 spec-pinned dispatch pilot. Synthetic producer; real court opinions. NOT legal advice.**

An AI legal assistant (the *producer*) drafts a filing, asserts a set of supporting
citations each with a quoted holding, and claims an overall gate decision. The
verifier re-derives that decision from committed evidence and fails closed if the
claim does not reconcile:

| status | meaning |
|---|---|
| `ROOTED` | the cite resolves in the rooted corpus **and** the quoted holding appears **verbatim** in the court's opinion text |
| `MISQUOTE` | the cite resolves, but the quoted holding is **not** found verbatim — real source, fabricated/inverted quote (the *Mata v. Avianca* shape) |
| `UNRESOLVED` | the cite is **absent** from the rooted corpus — possible fabrication, *or* a real authority still in the human-root queue (default-deny **to a human**, never auto-reject) |

`decision = AUTO_APPROVE` iff **every** citation is `ROOTED`, else `ROUTE_TO_HUMAN`.

## Why this exists — the fix over `caselaw_citation_gate_minimal`

This is the successor recommended in
`nexi-patent-redhat/docs/0-proposed/CREDIBILITY_GATE_VKERNEL_INTEGRATION_ASSESSMENT.md`.
The `_minimal` pilot's misquote yardstick (`holding_text`) was a **human paraphrase**
of each holding, so its check verified one producer's quote against *another
producer's paraphrase* — the **load-bearing open question / circularity** the
assessment flagged.

Here the yardstick is `rooted_text`: a **verbatim span of the court's actual
opinion**, fetched from CourtListener and frozen with provenance. The gate now proves
*"the producer's quote appears in the court's own words,"* not *"matches our summary
of them."* The rooter's only judgment is **identity** (is this the right opinion for
the cite), which is auditable via the per-record provenance — not *"what is the
holding,"* which would re-introduce the paraphrase circularity.

## The seam (two halves; only the first touches the network)

```
_root_corpus.py  (producer-side, run ONCE, network)        verify.py  (auditor, OFFLINE)
─────────────────────────────────────────────────         ──────────────────────────────
kb_citations.json  (§101 shard authorities)                reads frozen corpus + assertions
  ├─ Authority A: CourtListener citation-lookup              └─ re-derives the gate verdict
  │     ├─ status 200            → fetch opinion text  ┐
  │     └─ status 300 (unanimous → disambiguate)       ├→ corpus/rooted_records.json
  ├─ Authority B: CAP / Harvard (static.case.law)      │     (primary rooted_text + verbatim
  │     └─ official bound reporter → additional_roots ─┘      provenance + independent roots)
  └─ resolves on NEITHER → human_root_queue.json  (route to human, NOT reject)
```

`verify.py` **never touches the network.** It re-derives over the frozen, committed
corpus. The network rooting happened once and is auditable per record
(`provenance.cluster_id` / `opinion_id` / `cluster_url` / `retrieved_at`).

## The live rooting run (§101 shard, 13 reporter-cited authorities)

`python _root_corpus.py` roots all **13 / 13** authorities with verbatim opinion text
and an **empty human-root queue** — across two independent authorities:

- **11 rooted directly from CourtListener** `status 200` (Mayo, Electric Power Group,
  Enfish, DDR, McRO, Berkheimer, SAP, Two-Way Media, Ancora, TecSec, Recentive).
- **Alice + Bilski rooted by closing the original gap** (see the self-correction below).
- **2 records carry a second, independent root** (Bilski + Mayo are corroborated by
  the Caselaw Access Project's official bound-reporter text — `root_count = 2`).

### Self-correction: Alice & Bilski were never truly unrootable

The first cut of this rooter accepted *only* `status 200` and routed Alice + Bilski to
the human queue as "UNRESOLVED_BY_COURTLISTENER", with the README claiming
"CourtListener does not index Alice." That was **too strict and slightly overstated**.
The cached lookup already held both clusters as `status 300` (Multiple Choices) whose
candidates *unanimously agreed* on case identity (`Alice Corp. v. CLS Bank Int'l`
2014-06-19; `Bilski v. Kappos` 2010-06-28). Two fixes close the gap, each honest:

1. **300-disambiguation (CourtListener-internal).** A `300` whose candidate clusters
   all share one normalized `(case_name, date_filed)` is a duplicate-import, not a real
   ambiguity — safe to accept. Alice's U.S. cite (`573 U.S. 208`) still `404`s, but its
   S.Ct. **parallel** `134 S. Ct. 2347` returns a unanimous `300` → **Alice roots**.
   Bilski's `561 U.S. 593` likewise. (The exact case the daemon's `404 → REJECT` rule
   false-flagged now *correctly roots*, while still routing genuine gaps to a human.)

2. **CAP / Harvard — an organizationally-independent second authority.** For every
   U.S.-Reports authority the rooter also queries `static.case.law` (the official bound
   reporters, Harvard 2018 batch, no auth) and attaches the result as an
   `additional_roots` entry. **Bilski (vol 561) and Mayo (vol 566) gain an independent
   second root.** **Alice cannot** — its volume **573 is exactly one past CAP's coverage**
   (max U.S. vol = 572), recorded as `cap_status: beyond_cap_coverage`. So Alice is
   *single-rooted* (CourtListener only), flagged honestly. That coverage edge **is** the
   Trust-root lesson: no single authority — not even the official-reporter digitization — is
   complete; multi-rooting raises confidence, it does not eliminate the trust-root.

### The honest assertions fixture then exercises every path

| id | cite | producer's quote | status |
|---|---|---|---|
| A-01 | 830 F.3d 1350 (Electric Power Group) | verbatim span of the opinion | `ROOTED` |
| A-02 | 874 F.3d 1329 (Two-Way Media) | verbatim span of the opinion | `ROOTED` |
| A-03 | 134 F.4th 1205 (Recentive) | inverted: "…is patent **eligible** under §101" | `MISQUOTE` |
| A-04 | 142 F.4th 880 (Synapse AI) | — | `UNRESOLVED` (fabricated case) |
| A-05 | 573 U.S. 208 (Alice) | verbatim Alice holding (generic-computer) | `ROOTED` (was the false-flag) |
| A-06 | **130 S. Ct. 3218** (Bilski, **parallel** cite) | verbatim Bilski holding | `ROOTED` (multi-rooted record) |

→ honest decision **`ROUTE_TO_HUMAN`** (A-03 misquote + A-04 fabrication still bite),
and it re-derives. Two things to note:

- **A-05** is the headline: Alice, the case the daemon false-flagged as fabricated, now
  **roots correctly** and its genuine holding validates **verbatim** against the real
  opinion text — fail-safe became correct-positive without ever auto-rejecting.
- **A-06** cites Bilski by its **parallel** S.Ct. reporter `130 S. Ct. 3218`, not its
  canonical `561 U.S. 593`, and still resolves — exercising the **parallel-cite indexing**
  (a record is reachable by *any* of its `cites`) over a **multi-rooted** record.

## What this proves / does NOT prove

**Proves** (given THIS rooted corpus): the gate decision is **re-derivable** and
**tamper-evident** under the auditor-anchored rule. A producer cannot claim
`AUTO_APPROVE` while hiding a misquoted or fabricated citation — the recompute
disagrees and dispatch fails closed (see tests 2–3). Evidence tamper trips
`BAD_FILE_SHA` (test 4); a weaker substituted spec trips `AnchorViolation` (test 5).

**Signed receipt (§C16, Ed25519).** The gate authority signs the verdict —
bound to the decision, every per-citation status (in order), and the SHA-256 of
the corpus and assertions — with an Ed25519 private key; `verify.py`'s
`CaselawGateAttestationCheck` verifies it against the **public-only** key committed
at `attestation/gate_verifier_pubkey.hex`. This adds a property the re-derivation
does not: a downstream consumer can confirm the verdict was produced by the gate
authority **without re-running the re-derivation and without holding the corpus**,
and **cannot forge** a new verdict (it holds only the public key). A corrupted
signature (test 6) or a swapped trust anchor (test 7) fires
`CASELAW_GATE_ATTESTATION_INVALID` *in isolation* — re-derivation and file-integrity
still pass — proving the signed receipt is an independent surface.

> **Honest scope of the signature** (mirrors the C16 module's own register): the
> pubkey here is an **in-bundle synthetic anchor** pinned by file-integrity, and the
> signing key is a fixed test seed. This gives tamper-evidence + forge-resistance
> against a public-key holder. It does **not** give *third-party-auditable identity*
> — an external auditor verifying without trusting a NEXI-published key. That
> requires binding the public key to a Sigstore/Fulcio identity (**C18**, posture-
> deferred). "Forge-proof against a key holder" is a strictly weaker, true claim
> than "third-party-auditable." In production the verify key resolves via a trust-root
> key registry, not from inside the bundle.

**Does NOT prove** that the rooting itself is correct — that each `rooted_text` is the
genuine, complete opinion for its cite is a **trust-root concern** (corpus
genuineness, out of scope for the verifier's re-derivation),
*mitigated* by per-record CourtListener provenance but **not machine-proven**.
The gate grounds citations against a rooted corpus and the verifier attests the
gate ran and re-derives — it does not establish corpus genuineness on its own.
Specifically:

- **No single authority is a sufficient sole rooting authority.** CourtListener's
  citation-lookup has coverage edges (Alice's U.S. cite `404`s; several cites return
  ambiguous `300`s), and the independent CAP/Harvard digitization has its own edge
  (Alice's volume 573 is one past its coverage). This pilot roots over **two**
  independent authorities with parallel-cite + 300-disambiguation logic and still keeps
  the human-root queue for anything both miss — `root_count` and `cap_status` on each
  record make the trust-root posture auditable. Multi-rooting is mitigation, not proof:
  a record corroborated by two unrelated digitizations is harder to fabricate, but
  genuineness of the rooting remains a trust-root concern, not machine-proven.
- **Verbatim-quote mode only.** The gate validates that a producer's **quotation**
  appears in the opinion. It does **not** validate a **paraphrased characterization**
  of a holding — that needs semantic/NLI judgment, which is not deterministically
  re-derivable and is out of scope by design. (Most KB shard prose is paraphrase; this
  gate is for the *filing-assistant quoting the court*, not for grading summaries.)
- **Scope is the §101 shard (13 cites), not all 197 KB authorities.** The other 14
  shards are the documented scale path; rooting them is the same `_root_corpus.py` run
  over a larger `kb_citations.json`, bounded by CourtListener's 50/hour
  citation-lookup limit (this pilot uses **one** batched call).

## Reproduce

```bash
# Rooting (network; needs COURTLISTENER_TOKEN in a gitignored .env beside the script).
# Run once; output is committed frozen evidence. Cached in _root_cache/ (gitignored).
python examples/caselaw_citation_gate/_root_corpus.py            # uses cache if present
python examples/caselaw_citation_gate/_root_corpus.py --refresh  # re-fetch

# Build + verify (OFFLINE — no token, no network):
python examples/caselaw_citation_gate/_build_bundle.py --out-dir /tmp/clg_kb_bundle
python examples/caselaw_citation_gate/verify.py --bundle-dir /tmp/clg_kb_bundle   # -> PASS
python -m pytest examples/caselaw_citation_gate/tests/ -q                          # -> 5 passed
```

## Files

- `kb_citations.json` — producer input: the §101 shard's reporter-cited authorities
  (each with `reporter_cite` + `parallel_cites`).
- `_root_corpus.py` — producer-side trust-root rooter (network; run once): CourtListener
  (200 + unanimous-300 disambiguation) **and** an independent CAP/Harvard cross-root.
- `corpus/rooted_records.json` — frozen verbatim corpus + provenance (committed
  evidence). Each record carries `cites` (parallel-cite index keys), `resolved_via`,
  `provenance` (primary root), `additional_roots` (independent corroborating
  authorities), `root_count`, and `cap_status` where relevant.
- `human_root_queue.json` — authorities that resolve on *neither* authority
  (route-to-human, never auto-reject). **Empty** for the §101 shard after the
  multi-root fix; the mechanism + the CAP coverage edge prove it can be non-empty.
- `assertions/citation_assertions.json` — producer's asserted (cite, quoted_holding) pairs.
- `caselaw_gate_kb_recompute.py` — the shared recompute primitive (resolve + verbatim misquote).
- `spec_pinned/caselaw_gate_kb.spec.json` — the auditor's binding spec (`exact` comparator).
- `caselaw_verdict_binding.py` — shared canonical signed-bytes encoding (signer + verifier).
- `CaselawGateAttestationCheck.py` — §C16 ATTEST plugin: verifies the Ed25519 verdict signature.
- `attestation/gate_attestation.json` + `attestation/gate_verifier_pubkey.hex` — the signed receipt + committed public verify key.
- `_build_bundle.py` / `verify.py` / `tests/` — build, verify, and the 7 attack/tamper tests.

Synthetic producer; the asserted filing and the fabricated `Synapse AI` case are
invented for demonstration. The court opinions are real and provenanced. No law firm
is a customer; used internally to harden filings **with** counsel.
