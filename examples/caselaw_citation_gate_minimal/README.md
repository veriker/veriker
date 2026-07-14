# caselaw_citation_gate_minimal — Case-Law Citation Credibility Gate

**Axis-2 spec-pinned dispatch pilot.** Demonstrates the V-Kernel audit-bundle
integrator on a legal-AI domain: an AI legal assistant asserts supporting
citations and a gate decision, and the verifier **re-derives that decision** from
committed evidence — resolving each cite against a rooted court-record corpus and
screening each quoted holding for fabrication.

This is the single-citation
"real source / fabricated quote" rejection shape and the
[`scrabble_minimal`](../scrabble_minimal) "resolve-then-membership" adjudication
shape, pointed at case law.

## The gate

For each asserted citation, in order:

| Status | Condition |
|---|---|
| `UNRESOLVED` | the reporter cite is **absent** from the rooted corpus — possible fabrication (default-deny) |
| `MISQUOTE` | the cite **resolves**, but the producer's quoted holding is **not found** (after normalization) in the rooted record's holding text — real source, fabricated/inverted quote |
| `ROOTED` | the cite resolves **and** the quoted holding is a normalized substring of the rooted holding text |

`decision = AUTO_APPROVE` iff **every** citation is `ROOTED`, else `ROUTE_TO_HUMAN`.

## The honest fixture (it deliberately bites)

| Cite | Case | Status | Why |
|---|---|---|---|
| `573 U.S. 208` | Alice Corp. v. CLS Bank | `ROOTED` | quote matches the rooted holding |
| `43 F.4th 1207` | Thaler v. Vidal | `ROOTED` | quote matches the rooted holding |
| `134 F.4th 1205` | Recentive Analytics v. Fox | `MISQUOTE` | cited for the **opposite** of its real holding — "patent **eligible**" vs. the rooted "patent **ineligible** under section 101" |
| `142 F.4th 880` | "Synapse AI v. Cortex Labs" | `UNRESOLVED` | **fabricated** — no such case exists |

So the honest gate decision is **`ROUTE_TO_HUMAN`**, and that verdict re-derives
exactly. The point: a producer **cannot** claim `AUTO_APPROVE` while hiding the
misquote and the fabrication — the recompute disagrees and dispatch fails closed.

The six corpus records are real, public U.S. patent cases (Alice, In re Cellect,
Recentive, Thaler, Minerva, Therasense); the holding texts are accurate
paraphrases. "Synapse AI v. Cortex Labs, 142 F.4th 880" is a deliberately
synthetic fabrication used to demonstrate `UNRESOLVED`.

## Quick start

```bash
# from the v-kernel-audit-bundle root
python examples/caselaw_citation_gate_minimal/_build_bundle.py --out-dir /tmp/clg_bundle
python examples/caselaw_citation_gate_minimal/verify.py --bundle-dir /tmp/clg_bundle
# -> PASS  (the honest ROUTE_TO_HUMAN verdict re-derives)
```

## Tamper flows (all fail closed)

1. **Hide the fabrication / flip the decision** — edit `outputs/gate_verdict.json`
   so `value.decision` becomes `AUTO_APPROVE` (or flip a `MISQUOTE`/`UNRESOLVED`
   status to `ROOTED`). The recompute yields the honest `ROUTE_TO_HUMAN` verdict
   → `REDERIVATION_MISMATCH`.
2. **Doctor the evidence** — change a byte in `corpus/rooted_records.json` or
   `assertions/citation_assertions.json` without updating `manifest.files`
   → `BAD_FILE_SHA` (`file_integrity_many_small`).
3. **Ship a weaker spec** — replace the bundle's `spec/caselaw_gate.spec.json`
   with one the auditor did not anchor (different primitive, or `set`/looser
   comparator). Its SHA is not in the auditor's `SpecAnchor` → `AnchorViolation`.

## What this proves / what it does NOT

**Proves:** given **this** rooted corpus, the gate decision is **re-derivable**
and **tamper-evident** under the auditor-anchored rule. The auditor pins the
*method* (resolve + misquote-check + `exact` comparator) in a SHA-pinned spec;
the producer cannot weaken it. This is the verifier-separated-from-producer
thesis (NEXIVERIFY) applied to IP work.

**Does NOT prove the corpus is genuine.** That the listed cases are real court
records is a **trust-root concern** (corpus genuineness, out of scope for the
verifier's re-derivation), not a V-Kernel re-derivation
claim — V cannot, by itself, establish an external fact like "this case exists."
At v0.1 the corpus is a committed fixture of real public cases; in production it
is replaced by a **trust-root resolver** against a rooted authority (e.g.
CourtListener / PACER). The bundle shape and verification protocol are identical;
only the corpus provenance upgrades. Equivalently: the gate grounds citations
against a rooted corpus and the verifier attests the gate ran and re-derives —
corpus genuineness rests on the external rooted authority, not the verifier.

## Files

| File | Role |
|---|---|
| `corpus/rooted_records.json` | rooted court-record corpus (trust root; SHA-pinned evidence) |
| `assertions/citation_assertions.json` | producer's asserted citations (SHA-pinned evidence) |
| `caselaw_gate_recompute.py` | `compute_gate_verdict()` + `CaselawGateRecompute` primitive (ONE shared definition) |
| `spec_pinned/caselaw_gate.spec.json` | auditor's binding spec — pins primitive + `exact` comparator |
| `outputs/gate_verdict.json` | producer's claimed verdict `{"value": {...}}` (written by the build) |
| `_build_bundle.py` | builds a deterministic bundle |
| `verify.py` | registers the primitive + `SpecAnchor`, runs `BundleVerifier` |
| `tests/` | happy-path PASS + three tamper tests + dispatch-liveness guard |

Synthetic data; no law firm or vendor is a customer. Not legal advice.
