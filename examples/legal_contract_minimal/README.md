# legal_contract_minimal — V-Kernel S0 pilot

Domain: **legal / counterparty risk** — contract-clause precedent retrieval.

Re-derivation primitive (one sentence): for each clause (sorted by `clause_id`),
rank all precedents by keyword-overlap count (desc) with stable tiebreak by
`case_cite` (asc); keep precedents with overlap ≥ 1; assert the per-clause
`case_cites` list (order + content) matches the bundled `payload/retrieval_result.json`
exactly.

## Quick start

```bash
cd v-kernel-audit-bundle

# Build the bundle in-place (cli/verify.py canonical mode):
python examples/legal_contract_minimal/_build_bundle.py
python cli/verify.py --bundle-dir examples/legal_contract_minimal/    # PASS

# Or build out-of-tree + use the pilot-local verify.py wrapper:
python examples/legal_contract_minimal/_build_bundle.py --out-dir /tmp/legal_bundle
python examples/legal_contract_minimal/verify.py --bundle-dir /tmp/legal_bundle   # PASS

# Pilot pytest:
python -m pytest tests/test_legal_contract_minimal.py -v
```

## Tamper-flow demo

Two failure modes the bundle catches:

```bash
# (1) SHA bypass — mutate inputs without re-aligning the manifest SHA.
#     file_integrity_many_small (§C9) catches it.
python examples/legal_contract_minimal/_build_bundle.py --out-dir /tmp/legal_bundle
python -c "open('/tmp/legal_bundle/inputs/clauses.json','rb+').seek(10); ..."  # mutate a byte
python examples/legal_contract_minimal/verify.py --bundle-dir /tmp/legal_bundle  # FAIL: BAD_FILE_SHA

# (2) Re-derivation bypass — mutate payload AND re-align manifest SHA.
#     file_integrity passes but the re-derivation pack catches the divergence.
#     (See tests/test_legal_contract_minimal.py for the patch-manifest helper.)
```

## File layout

| File | Purpose |
|---|---|
| `_build_bundle.py` | Manifest construction; embeds `re_derive/legal_contract_pack.py` source for self-containment. |
| `verify.py` | Pilot-local verifier shell — registers `FileIntegrityManySmall`, `ReDerivationInvocationCheck(pack_filename="legal_contract_pack.py")`, and `LegalContractReDerivationCheck`. |
| `LegalContractReDerivationCheck.py` | TypedCheck plugin wrapping the subprocess call to the re-derivation pack (pilot-local; cli/verify.py route uses the substrate's `ReDerivationInvocationCheck` against the same pack). |
| `re_derive/legal_contract_pack.py` | Stdlib-only re-derivation pack (AB4 — no audit_bundle imports). Built into the bundle by `_build_bundle.py`. |
| `inputs/clauses.json` | (generated) 8 synthetic contract clauses with `query_keywords`. |
| `inputs/precedents.json` | (generated) 12 synthetic precedent cases with `keywords`. |
| `payload/retrieval_result.json` | (generated) Per-clause `case_cites` list — what the integrator's retrieval system returned. |
| `manifest.json` | (generated) Bundle manifest. `OpaqueFragment(kind_tag="legal_precedent_anchor")` per (clause_id, case_cite) hit. |

## Fragment kind

`OpaqueFragment(kind_tag="legal_precedent_anchor")` — substrate validates shape only;
semantic validation is owned by `LegalContractReDerivationCheck` (and the substrate's
`ReDerivationInvocationCheck` when invoked via `cli/verify.py`).

## Production integration

Replace the keyword-overlap ranker in `_build_bundle.py` / `re_derive/legal_contract_pack.py`
with the production retrieval implementation (embedding nearest-neighbour in determinism mode,
or whatever the integrator ships). The bundle shape and verification protocol stay identical;
only the ranking function changes.

## Patent context

Demonstrates the V-Kernel S0 integrator on legal-domain retrieval. One row in the
N-domain demonstration table of `the internal design notes`
(orchestrator updates the portfolio after merge).
