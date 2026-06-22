# streaming_minimal — V-Kernel Event-Time Streaming Pilot

Domain-specific demonstration of the S0 audit-bundle integrator on event-time
tumbling-window aggregation. This pilot forces the **substrate stateful question**:
does the V-Kernel re-derivation primitive generalize from byte-equal output
comparison to state-machine state matching a committed checkpoint?

## Substrate Decision Forced

**v0.1 state model:** per-window-aggregate state — a list of `{window_start_ms,
window_end_ms, aggregate, event_count}` records derived by replaying a committed
timestamped event stream through tumbling-window aggregation.

**The key distinction from prior pilots:** the re-derivation primitive here is NOT
"re-run a function and compare output bytes." It is "replay the event stream,
advance per-window state machine, assert the final per-window state matches the
committed checkpoint." This is the Flink/Kafka Streams pattern — auditors verify
*state* not *bytes*.

### Future state shapes (deferred)

At v0.1, the state model is restricted to stateless-per-window aggregates.
The following are deferred to future schema versions:

- **Per-key state** (e.g. per-user session windows, keyed aggregations) — requires
  a state backend description in the spec and a keyed-replay primitive.
- **Exactly-once side-effects** — wiring to the effect calculus (EFFECT_CALCULUS.md
  §C15) to audit that stateful side-effects (e.g. Kafka commits, DB writes) match
  declared effects.
- **Watermark progression** — auditing that the watermark advances correctly and
  late events are handled per the declared late-event policy. At v0.1, only `"drop"`
  is implemented; `"include"` is reserved and rejects with
  `STREAMING_LATE_EVENT_POLICY_VIOLATED`.

### Reference semantics

- **Apache Flink event-time semantics:** events are bucketed by their embedded
  `timestamp_ms` field (event time), not by wall-clock processing time. This
  matches Flink's `TumblingEventTimeWindows` behavior.
- **Chandy-Lamport snapshot pattern:** the bundled `payload/checkpoint.json` is
  a Chandy-Lamport-style checkpoint of the per-window state machine — a consistent
  cut of distributed state that the verifier can replay from the committed input.

## Bundle Layout

```
streaming_minimal/
  events/
    stream.jsonl            1000 events: {"event_id", "timestamp_ms", "value"}
  spec/
    segmentation.json       windowing parameters (schema: streaming-tumbling-v1)
  payload/
    checkpoint.json         per-window aggregate state (the auditable claim)
  manifest.json
```

The `spec/` tree is owned by `manifest.spec_files` and verified by `SpecShaPinCheck`.
The `events/` and `payload/` trees are owned by `manifest.files` and verified by
`FileIntegrityManySmall`. The two plugins cover disjoint trees by construction.

## Event Generator

1000 deterministic events at 100 ms spacing:

```
event_id    = i
timestamp_ms = i * 100         (events 0..599 in window 0; 600..999 in window 1)
value        = (i * 7) % 200 - 100   (integer in [-100, 99])
```

With `window_size_ms=60000` and 1000 events:
- **Window 0:** `[0ms, 60000ms)` — 600 events, `sum=-300`
- **Window 1:** `[60000ms, 120000ms)` — 400 events, `sum=-200`

## Quick Start

From the `v-kernel-audit-bundle` root:

```bash
# Build bundle
python examples/streaming_minimal/_build_bundle.py --out-dir /tmp/streaming_bundle

# Verify bundle
python examples/streaming_minimal/verify.py --bundle-dir /tmp/streaming_bundle
# → PASS

# Run tests
python -m pytest tests/test_streaming_minimal.py -v
```

## Tamper Flow Demo

### Content tamper (re-derivation catch)

Push event 599's timestamp from 59900 ms to 60000 ms. This moves event 599
from window 0 to window 1, changing both window aggregates and event counts.
Re-align the `events/stream.jsonl` SHA in the manifest so `FileIntegrityManySmall`
passes — the failure is caught exclusively by `StreamingReDerivationCheck`.

Expected result: `ok=False`, reason `STREAMING_REDERIVATION_MISMATCH`.

### Spec tamper (SpecShaPinCheck catch)

Append trailing whitespace to `spec/segmentation.json`. Do NOT realign
`manifest.spec_files`. The parsed JSON is semantically identical so
re-derivation still passes — the failure is caught exclusively by `SpecShaPinCheck`.

Expected result: `ok=False`, reason `SPEC_SHA_MISMATCH` or `missing_spec_blob`.

## Plugin Registration

Three plugins registered in `verify.py`:

| Plugin | Contract | Scope |
|---|---|---|
| `SpecShaPinCheck` | §C1 | `spec/` tree |
| `FileIntegrityManySmall` | §C9 | `events/` + `payload/` (skips `spec/`) |
| `StreamingReDerivationCheck` | §C6 | stateful re-derivation via subprocess |

## Files

| File | Purpose |
|---|---|
| `_build_bundle.py` | Generate 1000 deterministic events, compute checkpoint, write manifest |
| `verify.py` | Register plugins, wrap BundleVerifier, print PASS/FAIL |
| `streaming_re_derivation.py` | Stdlib-only re-derivation pack (subprocess target) |
| `StreamingReDerivationCheck.py` | TypedCheck plugin wrapping the subprocess |
| `README.md` | This file |
| `../../tests/test_streaming_minimal.py` | Round-trip + content-tamper + spec-tamper tests |
