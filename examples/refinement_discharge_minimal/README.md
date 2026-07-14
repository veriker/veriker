# refinement_discharge_minimal

The canonical **honest** demonstration of patent **S2** — *Verifier-Controlled
Discharge of Proof Obligations with a Retained Producer-Claim Divergence Record*
— running end-to-end through the bare default verifier (`veriker/cli/verify.py`) with a
**real Z3 re-execution on a green run**.

## Why this pilot exists

Before this pilot, the S2 mechanism (contract **C16** —
`audit_bundle/plugins/refinement_discharge.py` +
`audit_bundle/discharge/{verifier_signing,z3_runner,smtlib_parser,context_substitution}.py`)
was exercised only by:

- the unit-test suite (`tests/test_discharge/test_refinement_discharge_v0_2.py`,
  `test_integration_horizon_u1_shapley.py`), and
- the adversarial soak corpus (`examples/soak_known_bad/2[6-9]_*`,
  `3[0-1]_*`) — all **negative** cases that drive the reject paths.

No honest shipped bundle carried a real verifier-signed `discharged` status that
the verifier's **own Z3 re-run agrees with**. The elaborate cross-pillar pilot
(`eidas_eudi_minimal`) exercises the C18/C19 trust-extension family, not C16.
This pilot closes that gap: the first **demo bundle** (vs unit tests + soak
fixtures) to drive the Z3 discharge path on a **green** run.

## The story

An AI cost/impact attribution over a hash-pinned allocation table
(`spec/allocation_table.json`). The attribution claims that the per-edge
contributions sum to the declared total — the formal property named verbatim in
the S2 disclosure: *"the per-edge attributions sum to the total impact."* It is
carried as an SMT-LIB proof obligation in QF_LIA:

```
(= (+ e0 e1 e2) total)        context: e0=4200, e1=3500, e2=2300, total=10000
```

| record | op | claim | verifier action |
|---|---|---|---|
| 0 | `COMPUTE / edge_attribution_sum` | `discharged` (verifier-signed) | pins the obligation by digest → retains the producer claim → re-parses + substitutes context + **re-runs Z3 offline** (`unsat` on the negation = DISCHARGED) → **agrees** → admits |

The bundle shows all four S2 steps on one artifact:

1. **Step 1 — pin the obligation by content digest.** `proofs/edge_attribution_sum.smt2`
   is content-addressed in `manifest.files`; the verifier confirms the digest
   before admitting the proof.
2. **Step 2 — retain the producer-asserted status.** The producer's
   `discharge_status` is read and carried for comparison, never trusted as
   authoritative.
3. **Step 3 — independent offline re-execution.** The verifier re-parses the
   refinement, substitutes the bundle's context, and re-runs Z3 itself. Only a
   **verifier-key-signed** status is admitted; the producer cannot self-sign.
4. **Step 4 — compare.** The verifier-determined status (`discharged`) **agrees**
   with the producer's signed claim → the bundle verifies clean.

The **disagreement** branch — Step 4's signed *divergence record*, which is the
patent's claimed advance — is demonstrated by `demo/run_discharge_demo.py`
scenario 4 (below).

## Verifier key

Per the S2 disclosure, the discharge status is signed under the **verifier** key
(held by the verifier, not the producer). The build script plays that verifier
signing step and reads `VKERNEL_VERIFIER_HMAC_KEY` exactly as `veriker/cli/verify.py`'s
`_load_verifier_recheck_key()` does, so the signature re-verifies at verify
time. The demo secret is disclosed and synthetic (Standing Order #9: **not** a
real secret).

## Run it

```bash
export VKERNEL_VERIFIER_HMAC_KEY="demo-vkernel-verifier-secret-0123456789abcdef"

# build (drives a REAL Z3 re-run; refuses to ship if Z3 disagrees or is absent)
python examples/refinement_discharge_minimal/_build_bundle.py \
    --out-dir examples/refinement_discharge_minimal/bundle

# verify through the bare default verifier — no pilot-specific code on the path
python veriker/cli/verify.py --bundle-dir examples/refinement_discharge_minimal/bundle
#   -> PASS; plugin:refinement_discharge admits "1 verifier-signed, 1 re-discharged"

# or the focused pilot wrapper (same default plugin set)
python examples/refinement_discharge_minimal/verify.py \
    --bundle-dir examples/refinement_discharge_minimal/bundle

# prove the mechanism bites: 1 honest PASS + 3 tamper rejections + 1 retained divergence record
python examples/refinement_discharge_minimal/demo/run_discharge_demo.py
```

### Demo scenarios (`demo/run_discharge_demo.py`)

| # | scenario | reason code |
|---|---|---|
| 0 | honest signed discharge; **real Z3 re-run agrees** | `PASS` (1 re-discharged) |
| 1 | verify with **no** verifier key | `DISCHARGE_STATUS_FORGED` (fail-closed) |
| 2 | strip the verifier signature | `DISCHARGE_STATUS_FORGED` |
| 3 | claim a wrong `obligation_sha` (obligation is digest-pinned) | `PROOF_OBLIGATION_SHA_MISMATCH` |
| 4 | sign `discharged` over a context whose `total` is wrong → verifier's Z3 re-run finds `FAILED` | `DISCHARGE_STATUS_VERIFIER_DIVERGENCE` + **signed divergence record retained to `events.jsonl`, re-verifies** (retain-and-still-reject) |

## How the verifier re-runs the proof

The re-run formula is the record's `outputs[0].type.refine`
(`(= (+ e0 e1 e2) total)`); the obligation **file** is the digest-pinned,
human-readable statement of the same property. The verifier substitutes
`proof.recheck_context` into the formula, asserts the **negation**, and runs Z3:
`unsat` ⇒ the refinement is universally true on that context ⇒ `discharged`. The
signature binds `(bundle_id, record_idx, proof.kind, obligation_sha,
refine-text-sha, recheck-context-sha)` so a signature cannot be replayed across
bundles, rows, formulas, contexts, or prover kinds.

## Scope notes

- **C16-focused.** This pilot exercises S2 / C16 (refinement discharge) and the
  universal precondition checks (file-integrity, spec-pin, C15
  well-formedness). The record's `stamp_observed` is null and no
  `aggregate_stamp` is declared, so the C14 lattice plugin runs as a structural
  no-op — the S1 lattice mechanism has its own honest pilot
  (`provenance_upgrade_minimal`). The S1↔S2 link (a `discharged`-reason stamp
  upgrade pointing at a real C16 discharge) is an interoperability feature, not
  exercised here.
- **Real Z3, no fake.** The build and the demo use `pick_default_invoker()` —
  the in-process `z3-solver` module (or the `z3` binary if on PATH). The build
  refuses to ship if Z3 is unavailable or disagrees. (The unit suite uses a
  scripted `FakeZ3Invoker` to drive crash/timeout paths deterministically; this
  pilot does not.)
- **Synthetic data.** The allocation table, attribution, and verifier key are
  all synthetic demo material. This is a substrate demonstration, not a customer
  deployment.
