# pharmacophore_fit_minimal — Spatial-Fit RMSD Audit Bundle

Minimal domain pilot: a pharmacophore-based virtual-screening spatial-fit step
bundled for V-Kernel audit verification (the audit-bundle contract §C5, C6, C9, C15).

## The selection-defensibility story

Virtual-screening pipelines that use pharmacophore matching report a ranked list
of compounds whose 3D feature positions align well with a target's pharmacophore
hypothesis. What's hidden in the published list is **the geometry of the
alignment**: which specific candidate features were paired with which
pharmacophore features, what 3D distance each pair contributed, and whether the
ranking faithfully reflects those distances. A reviewer who sees only the
shortlist cannot tell whether a candidate's reported RMSD actually corresponds
to the bundled coordinates, or whether a more-favored candidate was silently
boosted past a less-favored one.

The V-Kernel audit bundle is exactly that receipt:

> A pharmacophore-fit step receives a pharmacophore template (N features at 3D
> positions with chemical types) and a set of candidate conformers (each with
> its own features + a feature-mapping back to the template). It computes per-
> candidate RMSD over paired features, ranks ascending, and advances the
> top-N. The bundle commits the COMPLETE per-candidate fit ledger — every
> candidate's per-pair distances, aggregate RMSD, rank, and advance status —
> plus the ranked list and the advanced set. A verifier re-runs the RMSD math
> from the committed 3D coordinates + mappings and asserts the full ledger,
> ranking, and advanced set match byte-for-byte.

"Show every distance you measured, not just the ones in the shortlist."

## HONEST FRAMING

- The candidate conformers are a **deterministic synthetic surrogate** for real
  3D conformers (RDKit ETKDG / OMEGA / Corina output). Positions are generated
  from a committed noise seed so the bundle is reproducible. **NO claim** of
  physical conformer realism is made.
- The pharmacophore template is also synthetic (5 hardcoded features:
  HBD / HBA / aromatic / hydrophobic / HBD). Production templates come from MOE /
  Phase / LigandScout / RDKit pharmacophore-extraction tooling.
- What **IS** demonstrated: spatial-fit RMSD over paired 3D feature positions
  as a re-derivation primitive. This is a distinct computational shape from
  `combi_screen_minimal` (enumerate / filter / score / rank) and
  `lifesci_binding_minimal` (single-pair fingerprint scoring). Per-pair
  distances are bundled alongside the aggregate RMSD so reviewers can audit
  which features contribute most to the fit.
- **OUT OF SCOPE:** real 3D conformer generation; target-protein pocket
  geometry; pharmacophore feature extraction from co-crystal structures. Those
  are production-time work, replaced 1:1 in real integrations.

Domain basis: pharmacophore-based virtual screening — the spatial-fit stage of
a multi-stage compu-chem virtual-screening pipeline. Substrate claim is
target-agnostic; the same scaffold serves any future N-domain demo paper in
computational drug discovery.

## Re-derivation primitive

Re-compute per-candidate spatial-fit RMSD from committed pharmacophore feature
positions + candidate feature positions + per-candidate feature-mapping. Re-rank
survivors by RMSD ascending (ties broken by `compound_id`). Assert:

1. Each candidate's `rmsd`, `paired_count`, and per-pair `distance` values match
   the bundled ledger entry.
2. Each candidate's `rank` and `advanced` flag match the re-ranked order.
3. The bundled `ranked` list (ordered by RMSD ascending) matches re-ranking.
4. The bundled `advanced` set (top-N `compound_id`s) matches re-derivation.
5. `candidate_count`, `scored_count`, and `advanced_count` match.

Math is `dx² + dy² + dz²` summed over paired features, mean over paired count,
square root for RMSD — 100% stdlib (`math.sqrt`). No numpy / scipy.

## Prerequisites

Python 3.11+. No third-party dependencies.
Run all commands from the **v-kernel-audit-bundle root**.

## Step 1 — Build the bundle

```bash
python examples/pharmacophore_fit_minimal/_build_bundle.py --out-dir /tmp/pharma_fit_bundle
```

Expected output:

```
Bundle written to /tmp/pharma_fit_bundle
  pharmacophore_id : PHARMA-A-01
  template features: 5
  candidates       : 20
  scored           : 20
  advanced (top-N) : 10
  best fit         : CAND-00 (RMSD <float>)
  cutoff (top-N)   : RMSD <float>
  fragment anchors : 10 OpaqueFragment (kind_tag=candidate_conformer)
  dispatch records : 1 (op.kind=PHARMACOPHORE_FIT)
  manifest files   : 4
  manifest         : /tmp/pharma_fit_bundle/manifest.json
```

By construction `CAND-00..CAND-04` are good fits (small noise), `CAND-05..CAND-14`
are medium fits, `CAND-15..CAND-19` are poor fits — top-N=10 should advance the
first 10 by `compound_id`.

## Step 2 — Verify

```bash
python examples/pharmacophore_fit_minimal/verify.py --bundle-dir /tmp/pharma_fit_bundle
```

Expected stdout: `PASS`. Exit code 0.

Three TypedCheck plugins run in order:

| Plugin                              | Contract clause                                                          |
|-------------------------------------|--------------------------------------------------------------------------|
| `file_integrity_many_small`         | §C9 per-file SHA walk with named reason codes                            |
| `pharmacophore_fit_re_derivation`   | §C6 spatial-fit RMSD re-derivation, full ledger + ranked + advanced      |
| `dispatch_record_wellformed`        | §C15 op-kind + effect well-formedness (`op_kinds_admitted={PHARMACOPHORE_FIT, COMPUTE}`) |

## Step 3 — Tamper-flow demos

### Mutate a candidate's feature position (the money test)

The whole point of the bundle is the **paired-distance ledger**. Shift one
candidate's feature position by 1.0 Å and re-align the manifest SHA — the
re-derivation pack re-computes RMSD from the mutated position, finds the new
RMSD differs from the bundled value, and fires
`PHARMACOPHORE_FIT_REDERIVATION_MISMATCH`. You cannot adjust an alignment
geometry without it showing in the re-derivation.

```python
import json, pathlib
p = pathlib.Path('/tmp/pharma_fit_bundle/inputs/candidate_conformers.json')
d = json.loads(p.read_text())
d['candidates'][0]['features'][0]['position'][0] += 1.0   # shift X by 1 Å
p.write_text(json.dumps(d, indent=2, sort_keys=True, ensure_ascii=False) + '\n')
```

Re-run the verifier:

```bash
python examples/pharmacophore_fit_minimal/verify.py --bundle-dir /tmp/pharma_fit_bundle
```

Expected exit code: `1`. Stderr includes `BAD_FILE_SHA` (SHA mismatch caught
first) or `PHARMACOPHORE_FIT_REDERIVATION_MISMATCH` (if manifest SHA was
re-aligned to the tampered input).

### Quietly swap a hit out of the advanced set

Replace one entry in `advanced[]` with a different `compound_id` and re-align
the manifest SHA — re-derivation re-ranks from scratch and fires
`PHARMACOPHORE_FIT_REDERIVATION_MISMATCH` (advanced-set mismatch). You cannot
disappear a hit you ranked, or promote one you didn't.

## Fragment anchors

The bundle uses `OpaqueFragment` (the V-Kernel open-extension fragment type) —
one anchor per advanced candidate:

| Anchor key                    | kind_tag              | Locator fields  |
|-------------------------------|-----------------------|-----------------|
| `advanced-01` … `advanced-10` | `candidate_conformer` | `compound_id`   |

Substrate validates shape only; semantic validation (feature-type taxonomy,
3D-coordinate validity) is the responsibility of the
`PharmacophoreFitReDerivationCheck` plugin and is intentionally minimal at this
pilot stage — see HONEST FRAMING.

## File layout

```
examples/pharmacophore_fit_minimal/
├── _build_bundle.py                          # synthesizes template + candidates + builds audit bundle
├── verify.py                                 # runs all three TypedCheck plugins
├── PharmacophoreFitReDerivationCheck.py      # TypedCheck plugin (subprocess wrapper)
├── pharmacophore_fit_re_derivation.py        # re-derivation implementation (stdlib only)
├── pilot.json                                # pilot v1 metadata
└── README.md

Pilot pytest (happy-path + tamper tests) lives at PRODUCT-ROOT:
tests/test_pharmacophore_fit_minimal.py
```
