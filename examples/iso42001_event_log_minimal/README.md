# iso42001_event_log_minimal — ISO/IEC 42001 A.6 Event-Log Integrity Re-Derivation

A V-Kernel S0 audit-bundle pilot (Axis-2 spec-pinned dispatch) for the **ISO/IEC
42001:2023 Annex A.6** sub-control *"AI-System Recording of Event Logs"*.

## What it demonstrates

A 42001-conforming AIMS keeps operational event logs and commits a tamper-evident
digest over them. Unlike the A.6 **V&V** pilot (which re-derives a numeric
metric), this one re-derives an **integrity digest**: the head of a SHA-256
hash chain folded over the ordered events —

```
h_0 = sha256(GENESIS)
h_i = sha256( h_{i-1} || sha256(canonical(event_i)) )
head = h_n
```

Because the chain folds order in, **any** tamper — editing a field, reordering,
inserting, or deleting an event — changes the head. The disclosed head is
compared with the `exact` comparator (hex-string equality).

This is the genuinely different *shape* among the 42001 pilots: a digest
re-derivation, not a metric re-derivation.

## Claim boundary (read this)

Proves the disclosed head digest is **re-derivable from the declared log** and
the log is **internally tamper-evident** under the auditor's pinned chaining
rule. It does **NOT** prove the log is **complete** (a curator could withhold an
event *before* committing the head — chaining defends against post-hoc tamper,
not pre-commitment omission), the recorded actions are truthful, or that the org
**satisfies** the A.6 logging control (which needs the logging *process* the
AIMS owns). 42001 controls are satisfied by process; this is a **record-quality /
tamper-evidence enhancement**, not a gap-filler. Synthetic data; no customer.

## Quick start (from `v-kernel-audit-bundle` root)

```bash
python examples/iso42001_event_log_minimal/_build_bundle.py --out-dir /tmp/iso42001_log_bundle
python examples/iso42001_event_log_minimal/verify.py --bundle-dir /tmp/iso42001_log_bundle
# -> PASS (the disclosed head re-derives from the events)
```

## File layout

| File | Purpose |
|---|---|
| `_build_bundle.py` | Writes the event log, computes the honest head digest, writes the claimed-value file + manifest. |
| `iso42001_event_log_recompute.py` | The `ReDerivationPrimitive` (SHA-256 chain fold, pinned genesis) + shared compute fn. |
| `verify.py` | Registers the primitive, anchors the committed spec, runs `BundleVerifier`. |
| `spec_pinned/iso42001_event_log.spec.json` | Auditor binding spec (type → primitive_id + `exact`). |
| `inputs/event_log.json` | Frozen synthetic ordered event log (6 events). |
| `outputs/log_chain_head_digest.json` | *(built)* the producer's disclosed head digest. |
| `tests/test_iso42001_event_log_minimal.py` | Chain-property unit + happy path + 4 tamper/attack surfaces. |

## Tamper / attack surfaces covered

1. **Digest mutation** — doctor the claimed head → `REDERIVATION_MISMATCH`.
2. **Event field tamper** — edit an event `action` without updating the manifest
   → `BAD_FILE_SHA` + `REDERIVATION_MISMATCH`.
3. **Event reorder** — swap two events (order-sensitive chain) → `BAD_FILE_SHA` +
   `REDERIVATION_MISMATCH`.
4. **Substitute spec** — producer ships an unanchored spec → `AnchorViolation`.

## Substrate exercised

Axis-2 spec-pinned dispatch (`audit_bundle/rederivation/`): `register_primitive`,
`SpecAnchor` from committed spec bytes, the `exact` comparator over a re-derived
digest. **New domain, not a new shape** — reuses the recompute-and-compare shape
of `climate_emission_minimal` / the FEA pilot.
