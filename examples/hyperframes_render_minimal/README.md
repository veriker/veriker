# hyperframes_render_minimal — HTML→MP4 deterministic-render audit bundle

Domain pilot: V-kernel audit bundle for a third-party deterministic renderer
(HeyGen HyperFrames v0.6.52, Apache 2.0). Demonstrates that the domain-agnostic
S0 integrator handles a **shell-out re-derivation** where the deterministic
function is an external CLI tool with non-Python dependencies (Node, Chrome
headless shell, ffmpeg), not a pure-Python computation like
`audio_minimal` or `aml_txn_monitoring_minimal`.

Same pattern as `build_real_compiler_minimal` (which shells to `py_compile`)
but with a heavier external toolchain. The re-derivation pack itself is
stdlib-only Python; the rendering tools it invokes are pinned in
`spec/tooling.json`.

## Why this pilot exists

HyperFrames advertises bit-identical MP4 output for the same HTML + same
toolchain. This pilot turns that informal claim into a V-kernel-verifiable
property: every emitted bundle re-renders to the committed sha256 or the
verifier reports `HYPERFRAMES_REDERIVATION_MISMATCH`.

## Prerequisites

- Python 3.10+
- Node ≥ 22 on PATH (`node --version`)
- ffmpeg on PATH (`ffmpeg -version`)
- npx with internet access on first run (HyperFrames + Chrome headless
  shell + Inter font fetch are cached after first build)

All commands run from the **v-kernel-audit-bundle root**.

## Step 1 — Build the bundle

```bash
python examples/hyperframes_render_minimal/_build_bundle.py --out-dir /tmp/hf_bundle
```

Expected output:

```
Bundle written to /tmp/hf_bundle
  schema_version : vcp-v1.1-canary4
  bundle_id      : hyperframes-render-minimal-rc
  output_mp4_sha : <hex prefix>...
  manifest files : 4
  spec_files     : 1
```

First build is ~30 s (npx + Chrome download). Subsequent builds ~6–8 s.

## Step 2 — Verify

```bash
python examples/hyperframes_render_minimal/verify.py --bundle-dir /tmp/hf_bundle
```

Expected stdout: `PASS`. Exit code 0.

Three TypedCheck plugins run in order:

| Plugin                          | Contract clause                                                          |
|---------------------------------|--------------------------------------------------------------------------|
| `spec_sha_pin`                  | §C1 per-file SHA walk over `spec/`                                       |
| `file_integrity_many_small`     | §C9 per-file SHA walk over `files/`                                      |
| `hyperframes_re_derivation`     | §C6 HTML→MP4 re-derivation via pinned HyperFrames + Chrome + ffmpeg      |

## Step 3 — Tamper-flow demo

Mutate one byte in `source/index.html`, re-align its manifest SHA so
`file_integrity_many_small` passes, and the re-derivation plugin catches the
divergence in isolation because the re-rendered MP4 sha256 no longer matches
the committed sha256:

```bash
python -c "
import hashlib, json, pathlib
bd = pathlib.Path('/tmp/hf_bundle')
p = bd / 'source/index.html'
text = p.read_text(encoding='utf-8')
p.write_text(text.replace('V-Kernel + HyperFrames', 'V-Kernel and HyperFrames'), encoding='utf-8')
m = json.loads((bd / 'manifest.json').read_text())
m['files']['source/index.html'] = hashlib.sha256(p.read_bytes()).hexdigest()
(bd / 'manifest.json').write_text(json.dumps(m, indent=2, sort_keys=True))
"
```

Re-run the verifier:

```bash
python examples/hyperframes_render_minimal/verify.py --bundle-dir /tmp/hf_bundle
```

Expected exit code: `1`. The `hyperframes_re_derivation` plugin reports
`HYPERFRAMES_REDERIVATION_MISMATCH` because re-rendering the tampered HTML
produces a different MP4 (different opening title text → different pixel
bytes → different sha256).

## File layout

```
examples/hyperframes_render_minimal/
├── README.md                          (this file)
├── pilot.json
├── _build_bundle.py                   (renders fixture + assembles bundle)
├── fixture/
│   ├── index.html                     (~3s title-card composition)
│   ├── hyperframes.json
│   └── package.json
├── hyperframes_re_derivation.py       (stdlib re-derivation pack)
├── HyperFramesReDerivationCheck.py    (TypedCheck wrapper)
└── verify.py                          (pilot verifier entry)
```

## Round-trip test

```bash
python -m pytest tests/test_hyperframes_render_minimal.py -v
```

Three test cases:
- `test_clean_bundle_passes` — build + verify → `ok=True`.
- `test_tamper_index_html_fails_rederivation` — flip a byte in `source/index.html`,
  re-align manifest SHA → verifier returns `ok=False` with
  `HYPERFRAMES_REDERIVATION_MISMATCH`.
- `test_tamper_tooling_spec_fails_spec_sha` — append whitespace to
  `spec/tooling.json` without re-aligning `manifest.spec_files` →
  `SPEC_SHA_MISMATCH` from `SpecShaPinCheck`.

The clean-pass and re-derivation tamper cases each invoke a live HyperFrames
render, so the full pytest run takes 30–60 s on a warm cache.
