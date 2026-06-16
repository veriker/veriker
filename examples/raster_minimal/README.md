# raster_minimal — Geospatial Raster Zonal Aggregation Audit Bundle

Domain pilot: deterministic zonal raster aggregation bundled for V-kernel
audit verification (the audit-bundle contract §C5, C6, C9).

Demonstrates the domain-agnostic S0 integrator on **geospatial / raster zonal
aggregation** — re-derivation where the underlying computation is a ray-casting
point-in-polygon test over a committed integer raster, proving the substrate
generalizes to GIS / earth-observation / logistics shapes.

## Prerequisites

Python 3.10+. No third-party dependencies.
Run all commands from the **v-kernel-audit-bundle root**.

## Step 1 — Build the bundle

```bash
python examples/raster_minimal/_build_bundle.py --out-dir /tmp/raster_bundle
```

Expected output:

```
Bundle written to /tmp/raster_bundle
  raster shape      : 32×32 int8
  polygon vertices  : 6
  in-polygon cells  : <N>
  zonal sum         : <S>
  manifest files    : 2
  manifest          : /tmp/raster_bundle/manifest.json
```

## Step 2 — Verify

```bash
python examples/raster_minimal/verify.py --bundle-dir /tmp/raster_bundle
```

Expected stdout: `PASS`. Exit code 0.

Two TypedCheck plugins run in order:

| Plugin                      | Contract clause                              |
|-----------------------------|----------------------------------------------|
| `file_integrity_many_small` | §C9 per-file SHA walk                        |
| `raster_re_derivation`      | §C6 raster zonal re-derivation (ray-casting) |

## Step 3 — Tamper-flow demo

Mutate one raster cell value by overwriting a byte in `raster/grid.bin`:

```bash
python -c "
import pathlib, hashlib, json
p = pathlib.Path('/tmp/raster_bundle/raster/grid.bin')
data = bytearray(p.read_bytes())
data[0] = (data[0] + 1) % 256   # flip cell (0,0)
p.write_bytes(bytes(data))

# Re-align the manifest SHA so FileIntegrityManySmall passes
sha = hashlib.sha256(bytes(data)).hexdigest()
mp = pathlib.Path('/tmp/raster_bundle/manifest.json')
m = json.loads(mp.read_text())
m['files']['raster/grid.bin'] = sha
mp.write_text(json.dumps(m, indent=2))
"

python examples/raster_minimal/verify.py --bundle-dir /tmp/raster_bundle
```

Expected exit code: `1`. The `raster_re_derivation` plugin will report
`RASTER_REDERIVATION_MISMATCH` because the re-derived zonal sum no longer
matches the bundled payload.

## Re-derivation primitive

Re-run a ray-casting point-in-polygon test against every cell of the committed
integer raster using the committed polygon vertices, sum the in-polygon cell
values, and assert the bundled aggregate matches.

## File layout

```
examples/raster_minimal/
├── _build_bundle.py           # builds raster + spec + payload + manifest
├── verify.py                  # runs FileIntegrityManySmall + RasterReDerivationCheck
├── RasterReDerivationCheck.py # domain plugin (C6 raster re-derivation)
├── raster_re_derivation.py    # re-derivation implementation (stdlib only)
├── README.md                  # this file
├── raster/
│   └── grid.bin               # (generated) 32×32 int8 raster, 1024 bytes
├── spec/
│   └── zonal_query.json       # (generated) polygon + aggregator spec
└── payload/
    └── zonal_result.json      # (generated) in_polygon_cell_count + sum
```

## Polygon shape

L-shaped hexagon with 6 vertices (pixel-corner coordinates in [0..32] × [0..32]):

```
(4,4) → (20,4) → (20,12) → (12,12) → (12,28) → (4,28)
```

This shape is non-convex (concave at vertex (20,12)→(12,12)→(12,28)), exercising
the ray-casting logic with a genuine concavity rather than a trivial bounding box.
