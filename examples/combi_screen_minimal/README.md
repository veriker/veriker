# combi_screen_minimal — Combinatorial Drug-Screening Audit Bundle

Minimal domain pilot: a combinatorial drug-discovery screening run bundled for
V-Kernel audit verification (the audit-bundle contract §C5, C6, C9, C15).

## The selection-path traceability story

Combinatorial screening produces a published shortlist — the compounds advanced
to synthesis or assay. What the shortlist hides is **everything that was looked
at and rejected**: the full enumerated library, the filters applied, the scores,
and the ranking that produced the advanced set. A reviewer (regulator, partner,
internal QA) who sees only the shortlist cannot tell whether a promising compound
was silently dropped, whether the filter thresholds were applied as declared, or
whether the ranking was honest.

The V-Kernel audit bundle is exactly that receipt:

> A screening run enumerates a compound library from committed building blocks,
> filters via Lipinski rule-of-5, scores survivors with a committed seeded
> surrogate docking function, ranks by predicted binding affinity, and advances
> the top-K. The bundle contains the COMPLETE screened-and-rejected ledger —
> every compound examined, why each was rejected, what scored, and what advanced.
> A verifier re-enumerates the library, re-applies the filter, re-scores, re-ranks,
> and asserts the full ledger AND the advanced set match byte-for-byte.

"Show everything you looked at, not just what you published."

## HONEST FRAMING

- The scoring function is a **deterministic synthetic surrogate** for a docking
  engine (AutoDock Vina class: Monte Carlo + BFGS), with the seed committed so
  the stochastic step is reproducible. It is **NOT real docking** and makes **NO
  claim of physical binding accuracy**.
- What **IS** demonstrated: the selection-path receipt — the complete library,
  the filters applied, the scores, the ranking, the advanced set, and the
  **complete reject ledger**. The substrate claim is that the screening **shape**
  (enumerate → filter → score → rank → advance) is verifiable inside a V-Kernel
  audit bundle.
- **OUT OF SCOPE:** whether an advanced compound actually binds. Production
  integrators replace the surrogate scorer with AutoDock Vina (Monte Carlo + BFGS
  with a committed seed) or a determinism-mode ML docking model; the bundle shape
  and verification protocol are identical.

Domain basis: Pagadala, Syed & Tuszynski (2017), "Software for molecular docking:
a review", *Biophysical Reviews* 9:91–102.

## Re-derivation primitive

Re-enumerate the combinatorial library as the Cartesian product of the committed
building-block lists, re-apply the Lipinski filter, re-score every survivor with
the committed seeded scoring function, re-rank by predicted affinity, and assert:

1. The full pass/reject ledger matches entry-by-entry (`compound_id`, `smiles`,
   `mw`, `logp`, `hbd`, `hba`, `filter_status`, `score`, `rank`, `advanced`).
2. `enumerated_count` / `passed_count` / `advanced_count` match.
3. The advanced top-K set matches the payload.

The scoring function is 100% stdlib: `sha256(compound_id + "|" + seed)` mapped to
the affinity range plus a small deterministic property term. No numpy/scipy.

## Prerequisites

Python 3.11+. No third-party dependencies.
Run all commands from the **v-kernel-audit-bundle root**.

## Step 1 — Build the bundle

```bash
python examples/combi_screen_minimal/_build_bundle.py --out-dir /tmp/combi_screen_bundle
```

Expected output:

```
Bundle written to /tmp/combi_screen_bundle
  target           : NEXI-T-XPA-ERCC1
  enumerated       : 150
  passed filter    : 137
  advanced (top-K) : 10
  fragment anchors : 10 OpaqueFragment (kind_tag=combi_compound)
  dispatch records : 1 (op.kind=DOCK_SCREEN)
  manifest files   : 4
  manifest         : /tmp/combi_screen_bundle/manifest.json
```

5 scaffolds × 6 R1 × 5 R2 = **150** enumerated compounds.

## Step 2 — Verify

```bash
python examples/combi_screen_minimal/verify.py --bundle-dir /tmp/combi_screen_bundle
```

Expected stdout: `PASS`. Exit code 0.

Three TypedCheck plugins run in order:

| Plugin                          | Contract clause                                                       |
|---------------------------------|-----------------------------------------------------------------------|
| `file_integrity_many_small`     | §C9 per-file SHA walk with named reason codes                         |
| `combi_screen_re_derivation`    | §C6 enumerate→filter→score→rank→advance re-derivation, full ledger     |
| `dispatch_record_wellformed`    | §C15 op-kind + effect well-formedness (`op_kinds_admitted={DOCK_SCREEN, COMPUTE}`) |

## Step 3 — Tamper-flow demos

### Delete a rejected compound from the ledger (the money test)

The whole point of the bundle is the **complete** reject ledger. Drop one rejected
compound and re-align the manifest SHA — the re-derivation pack re-enumerates the
full Cartesian product, finds the ledger one row short, and fires
`COMBI_SCREEN_REDERIVATION_MISMATCH` (ledger length mismatch). You cannot quietly
disappear a compound you looked at.

### Mutate a score in the payload

Change a survivor's `score` and re-align the manifest SHA — re-derivation re-scores
from the committed seed and fires `COMBI_SCREEN_REDERIVATION_MISMATCH`.

If the manifest SHA is **not** re-aligned, `file_integrity_many_small` catches the
tamper first with `BAD_FILE_SHA`. Either way the verifier returns exit code `1`.

## Fragment anchors

The bundle uses `OpaqueFragment` (the V-Kernel open-extension fragment type) — one
anchor per advanced compound:

| Anchor key       | kind_tag         | Locator fields  |
|------------------|------------------|-----------------|
| `advanced-01` … `advanced-10` | `combi_compound` | `compound_id`   |

Substrate validates shape only; semantic validation (SMILES validity, docking
realism) is out of scope by design — see HONEST FRAMING.

## File layout

```
examples/combi_screen_minimal/
├── _build_bundle.py                   # synthesizes library + builds audit bundle
├── verify.py                          # runs all three TypedCheck plugins
├── CombiScreenReDerivationCheck.py    # TypedCheck plugin (subprocess wrapper)
├── combi_screen_re_derivation.py      # re-derivation implementation (stdlib only)
└── README.md

Pilot pytest (happy-path + tamper tests) lives at PRODUCT-ROOT:
tests/test_combi_screen_minimal.py
```
