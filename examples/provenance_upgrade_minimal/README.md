# provenance_upgrade_minimal

The canonical **honest** demonstration of patent **S1** — *Tamper-Evident
Provenance Labeling by a Monotone-Minimum Rigor Lattice with Signed Single-Tier
Upgrades* — running end-to-end through the bare default verifier
(`veriker/cli/verify.py`).

## Why this pilot exists

Before this pilot, the S1 mechanism (`audit_bundle/plugins/stamp_lattice.py` +
`audit_bundle/discharge/verifier_signing.py`) was exercised only by:

- the unit-test suite (`tests/test_stamp_lattice*.py`), and
- the adversarial soak corpus (`examples/soak_known_bad/0*_stamp_*`,
  `1*_stamp_upgrade_*`) — all **negative** cases.

No honest shipped bundle carried a real verifier-signed stamp upgrade. The one
positive bundle with `dispatch_records` (`gxp_part11_minimal`) leaves every
`stamp_observed` null and declares no `aggregate_stamp`, so the lattice plugin
runs as a structural no-op. This pilot closes that gap: a real, admitted,
single-tier upgrade on an honest bundle that verifies clean.

## The story

A two-step AI extraction over a hash-pinned source table
(`spec/source_table.json` — a small Q1 financials table):

| record | op | enters at | becomes | why |
|---|---|---|---|---|
| 0 | `COMPUTE / extract_total` | `COMPOSED_HYPOTHESIS` | **`TARGET`** | verifier recomputed `sum(line_items)` and the extracted total matched → it **signs** a single-tier upgrade |
| 1 | `COMPUTE / extract_footnote` | `COMPOSED_HYPOTHESIS` | `COMPOSED_HYPOTHESIS` | prose claim, no deterministic predicate → not upgraded |

`aggregate_stamp = min(effective) = min(TARGET, COMPOSED_HYPOTHESIS) =
COMPOSED_HYPOTHESIS`.

The bundle therefore shows **both** halves of S1 in one artifact:

1. **Rule 2 — signed, single-tier upgrade as the sole path up.** Record 0 rises
   exactly one tier, and only because a verifier-signed `stamp_upgrade` record
   exists. The upgrade is HMAC-bound to `(bundle_id, record_idx=0, from, to)`;
   the producer cannot raise its own label.
2. **Rule 1 — monotone-minimum, no trust-laundering.** Even though one row was
   legitimately upgraded, the aggregate is **pinned to the weakest un-upgraded
   row** — the bundle cannot be presented at the higher tier.

## Verifier key

Per the S1 disclosure, the upgrade is signed under the **verifier** key (held by
the verifier, not the producer). The build script plays that verifier
upgrade-signing step and reads `VKERNEL_VERIFIER_HMAC_KEY` exactly as
`veriker/cli/verify.py`'s `_load_verifier_recheck_key()` does, so the signature
re-verifies at verify time. The demo secret is disclosed and synthetic
(Standing Order #9: **not** a real secret).

## Run it

```bash
export VKERNEL_VERIFIER_HMAC_KEY="demo-vkernel-verifier-secret-0123456789abcdef"

# build
python examples/provenance_upgrade_minimal/_build_bundle.py \
    --out-dir examples/provenance_upgrade_minimal/bundle

# verify through the bare default verifier
python veriker/cli/verify.py --bundle-dir examples/provenance_upgrade_minimal/bundle
#   -> PASS (11 checks); plugin:stamp_lattice admits "1 verifier-signed upgrade"

# prove the negative invariants bite (1 honest PASS + 4 tamper rejections)
python examples/provenance_upgrade_minimal/demo/run_upgrade_demo.py
```

### Tamper scenarios (`demo/run_upgrade_demo.py`)

| # | tamper | reason code |
|---|---|---|
| 0 | honest signed upgrade | `PASS` (1 upgrade admitted) |
| 1 | verify with **no** verifier key | `STAMP_UPGRADE_FORGED` (fail-closed, defense 4) |
| 2 | strip the signature | `STAMP_UPGRADE_FORGED` (defense 5) |
| 3 | forge a multi-tier `to_stamp` in the body | `STAMP_UPGRADE_FORGED` (HMAC body-mismatch) |
| 4 | launder `aggregate_stamp` up to `TARGET` | `STAMP_AGGREGATE_ROUNDUP_DETECTED` (Rule 1) |

## Scope notes

- **`predicate_satisfied`, not `discharged`.** This pilot uses the
  `predicate_satisfied` upgrade reason, which exercises Rule 2 plus per-record
  defenses 1–7 with no coupling to the C16 refinement-discharge / Z3 path. The
  `discharged` reason (which additionally exercises defense 8, the
  proof-linkage cross-check) is covered by
  `tests/test_stamp_lattice_multirow.py::test_happy_path_signed_upgrade_passes`.
- **Synthetic data.** The source table, extraction, and verifier key are all
  synthetic demo material. This is a substrate demonstration, not a customer
  deployment.
