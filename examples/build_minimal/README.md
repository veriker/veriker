# build_minimal — Deterministic Build/Recipe Audit Bundle

Domain pilot: re-execution of a deterministic build recipe (concat → canonical
gzip) bundled for V-kernel audit verification (the audit-bundle contract §C5,
C6, C9).

Demonstrates the domain-agnostic S0 integrator on **deterministic build/recipe
execution** — the Nix / Bazel / reproducible-builds shape. The re-derivation
primitive is "re-execute the recipe against the committed inputs and assert
the produced artifact bytes equal the bundled artifact bytes." Closes the
substrate's coverage of multi-step deterministic compute pipelines (distinct
from `bom_minimal`'s single-pass graph resolution and `dp_minimal`'s seeded
stochastic single-step).

## Prerequisites

Python 3.10+. No third-party dependencies.
Run all commands from the **v-kernel-audit-bundle root**.

## Step 1 — Build the bundle

```bash
python examples/build_minimal/_build_bundle.py --out-dir /tmp/build_bundle
```

Expected output:

```
Bundle written to /tmp/build_bundle
  source files       : 3
  recipe steps       : 2
  final artifact     : combined.txt.gz (NN bytes)
  manifest files     : 5
  manifest           : /tmp/build_bundle/manifest.json
```

## Step 2 — Verify

```bash
python examples/build_minimal/verify.py --bundle-dir /tmp/build_bundle
```

Expected stdout: `PASS`. Exit code 0.

Two TypedCheck plugins run in order:

| Plugin                      | Contract clause                              |
|-----------------------------|----------------------------------------------|
| `file_integrity_many_small` | §C9 per-file SHA walk                        |
| `build_re_derivation`       | §C6 build-recipe re-execution + byte equality |

## Step 3 — Tamper-flow demo

Mutate one source file's content. The recipe still references the same source
path, but its bytes have changed, so re-derivation produces a different
artifact than the bundled one.

```bash
# Linux / macOS
echo "tampered alpha source" > /tmp/build_bundle/sources/a.txt

# Windows PowerShell equivalent
python -c "import pathlib; pathlib.Path(r'C:\tmp\build_bundle\sources\a.txt').write_bytes(b'tampered alpha source\n')"
```

Re-run the verifier:

```bash
python examples/build_minimal/verify.py --bundle-dir /tmp/build_bundle
```

Expected exit code: `1`. The `file_integrity_many_small` plugin will report
the SHA mismatch on `sources/a.txt` first (the manifest pinned the original
SHA at bundle-creation time); restoring the SHA but keeping the tampered
content moves the failure to `build_re_derivation` reporting
`BUILD_REDERIVATION_MISMATCH` because the gzip output bytes diverge from the
bundled artifact.

## Determinism notes

The recipe is byte-stable across CPython ≥3.10 on every supported platform
because:

- Source files are written LF-only (the builder calls `write_bytes` on
  explicit `\n`-terminated content; no platform line-ending defaults).
- The `concat` rule pins separator and encoding.
- The `gzip` rule pins `mtime=0` and `compresslevel=6`. Stdlib `gzip.GzipFile`
  with these settings emits a fixed header (no FNAME, no FCOMMENT, mtime=0)
  and `zlib`'s level-6 deflate is deterministic.

If a future Python release changes the deterministic floor of `zlib` deflate,
the test will flag the regression immediately.

## File layout

```
examples/build_minimal/
├── _build_bundle.py          # builds sources + recipe + executes recipe + manifest
├── verify.py                 # runs FileIntegrityManySmall + BuildReDerivationCheck
├── BuildReDerivationCheck.py # domain plugin (C6 build re-derivation)
├── build_re_derivation.py    # re-derivation implementation (stdlib only)
├── README.md                 # this file
├── sources/                  # (generated) 3-file deterministic source tree
│   ├── a.txt
│   ├── b.txt
│   └── c.txt
├── recipe/
│   └── build_recipe.json     # (generated) two-step deterministic recipe
└── payload/
    └── artifacts/
        └── combined.txt.gz   # (generated) final built artifact
```
