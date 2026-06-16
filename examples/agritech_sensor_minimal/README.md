# agritech_sensor_minimal — V-Kernel S0 Audit-Bundle Pilot

**Domain:** Agritech soil-sensor fusion  
**Re-derivation primitive:** Re-fuse predicted yield score from raw sensor time-series bytes using a committed linear-weighted formula; assert byte-for-byte reproducibility.

---

## Story

Soil sensors stream four channels over a 48-hour window:

| Channel | Unit | Description |
|---|---|---|
| `soil_moisture_pct` | % | Volumetric soil moisture |
| `soil_temp_c` | °C | Soil temperature at 10 cm depth |
| `npk_ppm` | ppm | Combined nitrogen-phosphorus-potassium reading |
| `rainfall_mm` | mm | Cumulative rainfall per hour |

A model fuses the sensor stream into a **yield-score forecast** and a confidence band. The audit bundle captures the raw input bytes (`inputs/sensor_stream.json`), the committed fusion weights (`payload/fusion_weights.json`), and the model output (`payload/yield_forecast.json`). An independent verifier re-runs the same deterministic formula from the raw bytes and asserts the score matches to within 1e-5.

---

## Formula

```
yield_score = w_soil_moisture * mean(soil_moisture_pct)
            + w_soil_temp     * mean(soil_temp_c)
            + w_npk           * mean(npk_ppm)
            + w_rainfall      * sum(rainfall_mm)
            + bias

confidence_band = [yield_score * 0.9, yield_score * 1.1]
```

Weights are committed in `payload/fusion_weights.json` so re-derivation never requires an out-of-band source. All arithmetic is stdlib-only (`builtins` + `round`).

---

## Quick-start

```bash
cd veriker

# Build
python examples/agritech_sensor_minimal/_build_bundle.py --out-dir /tmp/agritech_bundle

# Verify (must print PASS)
python examples/agritech_sensor_minimal/verify.py --bundle-dir /tmp/agritech_bundle

# Run pilot tests
python -m pytest examples/agritech_sensor_minimal/tests/test_agritech_sensor_minimal.py -v

# Regression suite (must also pass)
python -m pytest tests/test_fragments.py tests/test_dispatch_record_wellformed.py -q
```

---

## Tamper demo

```bash
# Tamper: overwrite a sensor reading so re-derivation diverges
python - <<'EOF'
import json; p = "/tmp/agritech_bundle/inputs/sensor_stream.json"
d = json.load(open(p)); d["samples"][0]["soil_moisture_pct"] += 50.0
open(p,"w").write(json.dumps(d))
EOF

# Verifier must now report FAIL
python examples/agritech_sensor_minimal/verify.py --bundle-dir /tmp/agritech_bundle
# → FAIL  [file_integrity_many_small] BAD_FILE_SHA ...
```

---

## File layout

```
examples/agritech_sensor_minimal/
  _build_bundle.py             — synthesise fixtures + emit manifest
  verify.py                    — register plugins + wrap BundleVerifier
  yield_fusion_re_derivation.py — stdlib-only re-derivation pack (C5 AB4)
  YieldFusionReDerivationCheck.py — TypedCheck plugin (subprocess wrapper)
  README.md                    — this file
  tests/
    __init__.py
    test_agritech_sensor_minimal.py — happy-path + tamper tests
```

---

## Fragment kind

Each of the 48 sensor samples is anchored with a `TimestampSampleFragment`:

```json
{
  "kind": "timestamp_sample",
  "source_cid": "sha256:<hash-of-sensor_stream.json>",
  "timestamp_iso": "2026-05-03T00:00:00Z",
  "sensor_id": "composite_field_A",
  "sample_index": 0
}
```

---

## Pilot scope

- Verification-only (no dispatch_records)
- No cross-system wiring — this pilot only re-derives the claimed output
- Synthetic data only; designed for live demo at WebSummit Vancouver 2026-05-11
