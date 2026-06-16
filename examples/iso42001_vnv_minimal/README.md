# iso42001_vnv_minimal — ISO/IEC 42001 A.6 V&V Metric Re-Derivation

A V-Kernel S0 audit-bundle pilot (Axis-2 spec-pinned dispatch) for the
**ISO/IEC 42001:2023 Annex A.6** sub-control *"AI-System Verification and
Validation"*.

## What it demonstrates

A 42001-conforming AI Management System (AIMS) reports model-validation metrics
in its V&V records. Today an auditor takes the reported number — e.g. *"holdout
ROC-AUC = 0.95"* — on the organization's word: the test-set evidence and the
metric computation are not independently re-checkable.

This pilot makes the reported metric **re-derivable and tamper-evident**:

- the **auditor** anchors a SHA-pinned spec that fixes *how* the AUC is
  recomputed (tie-averaged Mann-Whitney rank-AUC) and the agreement tolerance
  (`scalar_epsilon`, ε = 1e-9);
- the **producer** (the org being audited) bundles the declared test set and its
  claimed AUC;
- the **verifier** recomputes the AUC from the declared `(label, score)` pairs
  and compares. A doctored claimed metric, a tampered test-set file, or a
  producer-substituted weaker spec all **fail closed**.

Honest AUC for the shipped synthetic fixture: **0.953125** (16 items, 8 pos / 8
neg, deliberate score overlap → sub-perfect).

## Claim boundary (read this)

This proves the reported metric is **re-derivable from the declared inputs** and
tamper-evident under the auditor's pinned method. It does **NOT** prove:

- that the model is good or fit for purpose;
- that the test set is representative, complete, or correctly labelled;
- that the organization **satisfies** the A.6 control — that requires the V&V
  *process*, human judgement, and governance the AIMS owns, none of which a
  re-derivation can supply.

Re-derivability / internal-consistency is the defensible claim. 42001 controls
are satisfied by an organization's documented, operated processes; this artifact
is a **record-quality / tamper-evidence enhancement** on the V&V metric an A.6
program already records — not a control-coverage gap-filler. The data is
synthetic; there is no customer.

## Re-derivation primitive (one sentence)

ROC-AUC over the declared `(label, score)` pairs computed as the tie-averaged
Mann-Whitney U statistic
`AUC = (R_pos − n_pos·(n_pos+1)/2) / (n_pos · n_neg)`.

The method is **fixed in the verifier's primitive code** (`iso42001_auc_recompute`);
the auditor's spec binds the output type `model_validation_auc` to that
`primitive_id` and the `scalar_epsilon` tolerance. A producer cannot substitute a
more flattering AUC definition or widen the tolerance without changing the spec's
SHA, which the auditor's anchor would reject.

## Quick start (from `v-kernel-audit-bundle` root)

```bash
# Build the bundle
python examples/iso42001_vnv_minimal/_build_bundle.py --out-dir /tmp/iso42001_vnv_bundle

# Verify (prints PASS, exit 0)
python examples/iso42001_vnv_minimal/verify.py --bundle-dir /tmp/iso42001_vnv_bundle

# Tamper demo: inflate the claimed AUC and re-align its SHA, then re-verify
python - <<'PY'
import json, hashlib, pathlib
b = pathlib.Path("/tmp/iso42001_vnv_bundle")
cp = b / "outputs" / "model_validation_auc.json"
d = json.loads(cp.read_bytes()); d["value"] = float(d["value"]) + 0.04
nb = json.dumps({"value": d["value"]}, indent=2).encode(); cp.write_bytes(nb)
mp = b / "manifest.json"; m = json.loads(mp.read_bytes())
m["files"]["outputs/model_validation_auc.json"] = hashlib.sha256(nb).hexdigest()
mp.write_bytes(json.dumps(m, indent=2).encode())
print("inflated claimed AUC by +0.04")
PY
python examples/iso42001_vnv_minimal/verify.py --bundle-dir /tmp/iso42001_vnv_bundle
# -> FAIL, REDERIVATION_MISMATCH: you cannot doctor the reported metric.
```

## File layout

| File | Purpose |
|---|---|
| `_build_bundle.py` | Synthesizes the bundle: writes the test set, computes the honest AUC, writes the claimed-value file + manifest. |
| `iso42001_auc_recompute.py` | The `ReDerivationPrimitive` (`iso42001_auc_recompute`) — tie-aware rank-AUC. Shared with the builder so the two cannot drift. |
| `verify.py` | Registers the primitive, builds the auditor `SpecAnchor` from the **committed** spec, runs `BundleVerifier`. |
| `spec_pinned/iso42001_vnv.spec.json` | The auditor's binding spec (type → primitive_id + comparator). SHA-anchored. |
| `inputs/test_set.json` | Frozen synthetic V&V holdout (per-item label + model score). |
| `outputs/model_validation_auc.json` | *(built)* the producer's claimed value `{"value": …}`. |
| `tests/test_iso42001_vnv_minimal.py` | Happy path + 3 tamper surfaces + a unit test on the AUC math. |

## Tamper surfaces covered by the tests

1. **Metric mutation** — inflate the claimed AUC (+0.05), re-align its manifest
   SHA → `REDERIVATION_MISMATCH`.
2. **Test-set tamper** — edit a score in `inputs/test_set.json` without updating
   the manifest → `BAD_FILE_SHA` *and* `REDERIVATION_MISMATCH`.
3. **Weaker-spec substitution** — producer ships a spec with ε = 1e30 that would
   accept any value; the auditor anchor (ε = 1e-9) does not list its SHA →
   `AnchorViolation`, fail-closed.

## Substrate exercised

Axis-2 spec-pinned dispatch (`audit_bundle/rederivation/`): `register_primitive`,
`SpecAnchor` from committed spec bytes, `scalar_epsilon` comparator,
`manifest.outputs` + `outputs/<id>.json` claimed-value file. This is a **new
domain**, not a new re-derivation shape — it reuses the recompute-and-compare
shape demonstrated by `climate_emission_minimal` / the FEA pilot.
