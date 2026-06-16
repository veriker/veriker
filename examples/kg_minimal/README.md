# kg_minimal — Knowledge-Graph Reasoning Audit Bundle Pilot

Domain pilot: BFS path-query over a synthetic RDF-style knowledge graph, bundled
for V-kernel audit verification (the audit-bundle contract §C5, C6, C9, C15).

Exercises two extension surfaces opened in commit `d1d80a5e`:
- `OpaqueFragment(source_cid, kind_tag="kg_triple", locator={...})` — one fragment
  anchor per path edge in the query result.
- `DispatchRecordWellformedCheck(op_kinds_admitted=frozenset({"GRAPH_QUERY", "COMPUTE"}))` —
  admits the new `GRAPH_QUERY` op kind introduced by this domain pilot.

## Prerequisites

Python 3.10+. No third-party dependencies.
Run all commands from the **v-kernel-audit-bundle root**.

## Build the bundle

```bash
python examples/kg_minimal/_build_bundle.py --out-dir /tmp/kg_bundle
```

Expected output:

```
Bundle written to /tmp/kg_bundle
  kg triples       : 12
  manifest files   : 2
  fragment anchors : 3 OpaqueFragment (kind_tag=kg_triple)
  dispatch records : 1 (op.kind=GRAPH_QUERY)
  manifest         : /tmp/kg_bundle/manifest.json
```

## Verify the bundle

```bash
python examples/kg_minimal/verify.py --bundle-dir /tmp/kg_bundle
```

Expected stdout: `PASS`. Exit code 0.

Three TypedCheck plugins run in order:

| Plugin                        | Contract clause                          |
|-------------------------------|------------------------------------------|
| `file_integrity_many_small`   | §C9 per-file SHA walk                    |
| `kg_re_derivation`            | §C6 KG path-query re-derivation          |
| `dispatch_record_wellformed`  | §C15 op-kind + effect well-formedness    |

## Tamper-flow demo

Overwrite a path edge in `kg/triples.jsonl` to break the re-derivation:

```bash
# Overwrite triples with a bad edge (Alice knows nobody)
python -c "
import json, pathlib
p = pathlib.Path('/tmp/kg_bundle/kg/triples.jsonl')
lines = p.read_text().splitlines()
lines[0] = json.dumps({'subject': 'ex:Alice', 'predicate': 'ex:knows', 'object': 'ex:NOBODY'})
p.write_text('\n'.join(lines) + '\n')
"
python examples/kg_minimal/verify.py --bundle-dir /tmp/kg_bundle
```

Expected exit code: `1`. Expected stderr contains `KG_REDERIVATION_MISMATCH`.

## File layout

```
examples/kg_minimal/
├── _build_bundle.py          # builds the deterministic bundle
├── verify.py                 # runs all three TypedCheck plugins
├── KgReDerivationCheck.py    # domain plugin (C6 KG re-derivation)
├── kg_re_derivation.py       # re-derivation implementation (stdlib only)
├── README.md
├── kg/
│   └── triples.jsonl         # 12 deterministic RDF-style triples
└── payload/
    └── query_result.json     # BFS path-query result (ex:Alice → ex:knows)
```
