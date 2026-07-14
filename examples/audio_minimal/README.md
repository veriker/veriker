# audio_minimal — VAD Audio Segment Boundary Audit Bundle

Domain pilot: deterministic VAD (voice activity detection) segment-boundary
derivation bundled for V-kernel audit verification
(the audit-bundle contract §C5, C6, C9).

Demonstrates the domain-agnostic S0 integrator on **ASR-shape segment boundary
detection** — re-derivation where the computation is frame-energy-threshold VAD
over a committed int16 PCM buffer, producing an audit-trail-able transcript
boundary list. The shape any audio-AI / call-center / accessibility audience
recognizes.

## Prerequisites

Python 3.10+. No third-party dependencies.
Run all commands from the **v-kernel-audit-bundle root**.

## Step 1 — Build the bundle

```bash
python examples/audio_minimal/_build_bundle.py --out-dir /tmp/audio_bundle
```

Expected output:

```
Bundle written to /tmp/audio_bundle
  samples          : 8000 int16
  raw bytes        : 16000
  voiced segments  : 5
  manifest files   : 2
  manifest         : /tmp/audio_bundle/manifest.json
```

## Step 2 — Verify

```bash
python examples/audio_minimal/verify.py --bundle-dir /tmp/audio_bundle
```

Expected stdout: `PASS`. Exit code 0.

Two TypedCheck plugins run in order:

| Plugin                      | Contract clause                            |
|-----------------------------|--------------------------------------------|
| `file_integrity_many_small` | §C9 per-file SHA walk                      |
| `audio_re_derivation`       | §C6 VAD segment-boundary re-derivation     |

## Step 3 — Tamper-flow demo

Zero out 1600 bytes (800 int16 samples) spanning the second voiced region
(frames 10–14, samples 1600–2399), turning it silent so the re-derived
segment count drops from 5 to 4. Then re-align the manifest SHA:

```bash
python -c "
import hashlib, json, pathlib
bd = pathlib.Path('/tmp/audio_bundle')
p = bd / 'audio/samples.bin'
raw = bytearray(p.read_bytes())
# Zero out samples 1600..2399 (bytes 3200..4799) — voiced region 2
raw[3200:4800] = b'\x00' * 1600
p.write_bytes(bytes(raw))
# Re-align manifest SHA for audio/samples.bin
m = json.loads((bd / 'manifest.json').read_text())
m['files']['audio/samples.bin'] = hashlib.sha256(bytes(raw)).hexdigest()
(bd / 'manifest.json').write_text(json.dumps(m, indent=2))
"
```

Re-run the verifier:

```bash
python examples/audio_minimal/verify.py --bundle-dir /tmp/audio_bundle
```

Expected exit code: `1`. The `audio_re_derivation` plugin reports
`AUDIO_REDERIVATION_MISMATCH` because re-deriving VAD over the tampered
buffer yields 4 segments while the committed transcript claims 5.

## File layout

```
examples/audio_minimal/
├── _build_bundle.py          # synthesizes waveform + runs VAD + writes manifest
├── verify.py                 # runs FileIntegrityManySmall + AudioReDerivationCheck
├── AudioReDerivationCheck.py # domain plugin (C6 VAD re-derivation)
├── audio_re_derivation.py    # re-derivation implementation (stdlib only)
├── README.md                 # this file
├── audio/
│   └── samples.bin           # (generated) 16000 bytes — 8000 int16 PCM samples
├── spec/
│   └── segmentation.json     # (committed) VAD parameters (schema vad-v1)
└── payload/
    └── transcript.json       # (generated) 5 speech-segment boundary records
```

## Design notes

- **text field**: `transcript.json` segments carry a deterministic placeholder
  string (`"synthetic_segment_N"`). The `audio_re_derivation.py` pack does NOT
  compare `text` — only `segment_id`, `start_frame`, and `end_frame` constitute
  the auditable boundary claim. This matches real ASR deployments where text is
  the (non-deterministic) model output but boundary alignment is verifiable.
- **Stdlib only**: `audio_re_derivation.py` uses only `json`, `pathlib`, and
  `int.from_bytes` — no `struct`, no `wave`, no NumPy. This satisfies C5
  auditor-independence (the re-derivation pack can be inspected and run anywhere).
- **Energy threshold margin**: voiced frames min ~18.9M vs silent frames max ~138K,
  giving a >130× margin over the declared threshold of 1,000,000. The threshold
  can be tuned over two orders of magnitude without changing segment output.
