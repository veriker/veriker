# scrabble_minimal — Tournament-Scrabble Dictionary Adjudication Audit Bundle Pilot

Domain pilot: tournament-Scrabble word-legality adjudication, bundled for V-kernel
audit verification (the audit-bundle contract §C5, C6, C9, C15).

A ruling answers the question *"is word X legal under jurisdiction J at timestamp T?"*
The bundle commits to (a) the authority/edition timeline, (b) the wordlist file
the ruling cites, and (c) the dispute record. The verifier re-resolves
(jurisdiction, timestamp) → edition via the timeline and re-checks word
membership against the cited wordlist; any divergence between the bundled
ruling and the re-derived ruling fails the bundle.

Exercises two extension surfaces from the audit-bundle substrate:

- `OpaqueFragment(source_cid, kind_tag="lexical_entry", locator={...})` — one
  fragment anchor per disputed word, locating it in its cited edition.
- `DispatchRecordWellformedCheck(op_kinds_admitted=frozenset({"EDITION_RESOLVE", "MEMBERSHIP_LOOKUP", "COMPUTE"}))` —
  admits the two new op kinds for the (timeline → wordlist) lookup chain.

## Note on synthetic dictionaries

The bundled wordlists (`synthetic_csw_*`, `synthetic_twl_*`) are deliberately
tiny made-up word sets, not real CSW or TWL lexicons. Real CSW/TWL wordlists
are commercially licensed by Collins and Hasbro; the substrate proof does not
require real lexicons. The IP question for any production deployment (license
CSW directly, use a SOWPODS-derivative, etc.) is a downstream concern and is
out of scope for this pilot.

## Prerequisites

Python 3.10+. No third-party dependencies.
Run all commands from the **v-kernel-audit-bundle root**.

## Build the bundle

```bash
python examples/scrabble_minimal/_build_bundle.py --out-dir /tmp/scrabble_bundle
```

Expected output (paraphrased):

```
Bundle written to /tmp/scrabble_bundle
  dictionaries     : 4 synthetic editions
  manifest files   : 7
  fragment anchors : 1 OpaqueFragment (kind_tag=lexical_entry)
  dispatch records : 2 (EDITION_RESOLVE + MEMBERSHIP_LOOKUP)
  ruling           : ZARFY -> legal under WESPA-INTL
  manifest         : /tmp/scrabble_bundle/manifest.json
```

## Verify the bundle

```bash
python examples/scrabble_minimal/verify.py --bundle-dir /tmp/scrabble_bundle
```

Expected stdout: `PASS`. Exit code 0.

Three TypedCheck plugins run in order:

| Plugin                        | Contract clause                          |
|-------------------------------|------------------------------------------|
| `file_integrity_many_small`   | §C9 per-file SHA walk                    |
| `scrabble_re_derivation`      | §C6 timeline + membership re-derivation  |
| `dispatch_record_wellformed`  | §C15 op-kind + effect well-formedness    |

## Tamper-flow demos

### Tamper 1 — byte-flip a wordlist (SHA-level)

```bash
python -c "
import pathlib
p = pathlib.Path('/tmp/scrabble_bundle/dictionaries/synthetic_csw_beta.txt')
raw = p.read_bytes()
p.write_bytes(bytes([raw[0] ^ 0x01]) + raw[1:])
"
python examples/scrabble_minimal/verify.py --bundle-dir /tmp/scrabble_bundle
```

Expected exit code: `1`. Expected stderr contains `bad_file_sha`.

### Tamper 2 — rewrite cited edition (re-derivation level)

```bash
python -c "
import json, pathlib, hashlib
p = pathlib.Path('/tmp/scrabble_bundle/payload/ruling.json')
r = json.loads(p.read_text())
r['edition_cited'] = 'synthetic_twl_v2'  # was synthetic_csw_beta
p.write_text(json.dumps(r, indent=2, sort_keys=True) + '\n')
m = pathlib.Path('/tmp/scrabble_bundle/manifest.json')
mj = json.loads(m.read_text())
mj['files']['payload/ruling.json'] = hashlib.sha256(p.read_bytes()).hexdigest()
m.write_text(json.dumps(mj, indent=2, sort_keys=True))
"
python examples/scrabble_minimal/verify.py --bundle-dir /tmp/scrabble_bundle
```

Expected exit code: `1`. Expected stderr contains `SCRABBLE_EDITION_MISMATCH`.

The two tamper surfaces are independent: byte-tamper on a wordlist is caught
by `file_integrity_many_small` before the re-derivation plugin runs;
SHA-preserving semantic tamper (claiming a different edition in the payload)
is caught by `scrabble_re_derivation` after the timeline lookup disagrees
with the cited edition.

## File layout

```
examples/scrabble_minimal/
├── _build_bundle.py                # builds the deterministic bundle
├── verify.py                       # runs all three TypedCheck plugins
├── ScrabbleReDerivationCheck.py    # domain plugin (C6 re-derivation)
├── scrabble_re_derivation.py       # re-derivation implementation (stdlib only)
├── README.md
├── dictionaries/
│   ├── synthetic_csw_alpha.txt     # WESPA-INTL 2021-04-01 -> 2024-01-01
│   ├── synthetic_csw_beta.txt      # WESPA-INTL 2024-01-01 -> present
│   ├── synthetic_twl_v1.txt        # NASPA-NA 2006-03-01 -> 2014-04-01
│   └── synthetic_twl_v2.txt        # NASPA-NA 2014-04-01 -> present
├── editions/
│   └── jurisdiction_timeline.json  # authority -> edition effective windows
├── disputes/
│   └── D-0001.json                 # input dispute record
└── payload/
    └── ruling.json                 # adjudication ruling output
```
