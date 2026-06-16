# Threat model — spec-pinned type dispatch (as-built)

**Scope:** the `audit_bundle/rederivation/` re-derivation subset of the verifier
— spec-pinned, auditor-anchored, recompute-then-compare dispatch over
`manifest.outputs`. This is the **as-built** companion to the spec-pinned
dispatch architecture design §4/§4a. It is updated **in lockstep** with the
substrate (this file lands in the
same commit as the code it describes — a stale threat model is worse than none).

**Trust frame:** the verifier does **not** trust the producer. The producer
authors the manifest (output `type` claims + `conforms_to`) and ships the bundle
(inputs, claimed outputs, spec copies). The **auditor** supplies, at
`BundleVerifier` construction and never via the manifest: a `SpecAnchor`
(`spec_id -> required SHA`) and an optional `role_policy` (`output_id ->
required type`). Recompute primitives + comparator kinds are
verifier-distribution code, registry-resident, never bundle-supplied.

## Engagement / inert boundary

The dispatch step is **inert** unless `manifest.outputs` is non-empty (0/56
baseline manifests carry it, so every legacy bundle is unaffected and needs no
anchor). When it engages it **strictly supersedes** legacy name-dispatch for the
covered outputs and AND-aggregates into the same failure list — never `any()`
across the two paths (§4a.7). Aggregation is `all(no failures)`; a cardinality
guard asserts one evaluated result per declared output so `all([])` can never
read `True` on an empty/skipped set (§4a.8).

## Attack table (as-built)

| # | Attack | Defense (as-built) | Reason code | Test |
|---|---|---|---|---|
| 1 | Producer names a lax primitive **inside a pinned spec** | `primitive_id` lives in the spec → editing it changes the spec SHA → step-2 spec-SHA pin + the auditor anchor both break | `MALFORMED_SPEC` / `AnchorViolation` | unit |
| 2 | Producer loosens tolerance **inside a pinned spec** | `comparator.params` live in the spec → same SHA break | `AnchorViolation` | `test_attack_weaker_spec_substitution_fails` |
| 3 | Producer **selects a weaker pinned spec** via `conforms_to` / by shipping a substituted spec | Authority is the auditor anchor `(spec_id, SHA)`, **not** the manifest. A substituted spec has a SHA the anchor does not list → not authoritative → no authoritative set → fail-closed. `conforms_to` is a non-load-bearing hint; resolution searches **all** anchored specs and fails closed on ambiguity (§4a.1/4a.2). | `AnchorViolation` / `AmbiguousTypeBinding` | `test_attack_weaker_spec_substitution_fails`, `test_unanchored_spec_is_not_authoritative`, `test_ambiguous_type_across_two_anchored_specs` |
| 4 | Producer **claims a weaker type** sharing a primitive | (a) the anchored spec set is **rejected at load** if any `primitive_id` is bound by >=2 types with non-identical comparators (monotone-strictness — no weaker sibling can exist to substitute to); (b) an auditor `role_policy` independently rejects a substituted type (§4a.3). | `MonotoneStrictnessViolation` / `ROLE_POLICY_VIOLATION` | `test_attack_monotone_strictness_rejects_weakening_sibling`, `test_attack_role_policy_rejects_substituted_type` |
| 5 | Producer **omits an output entry** entirely | C19 coverage invariant, file-presence-triggered on `outputs/`: `set(manifest.outputs[].output_id) == set(outputs/*.json)`. Leaving the output file but dropping its entry fails closed (§4a.4). | `COVERAGE_MISMATCH` | `test_attack_omitted_output_entry_fails` |
| 6 | Producer ships a primitive **in the bundle** | Primitives are registry-resident verifier code; an unregistered `primitive_id` is fail-closed. There is **one** registry namespace — no separate `custom:<id>` governance path (§4a.5). | `UNKNOWN_PRIMITIVE` | unit (registry) |
| 7 | Producer supplies an **arbitrary normalization profile / structured schema** ("code in disguise") | `text_normalized` profiles + `structured` schemas resolve to verifier-implemented allowlisted ids only; unknown ids fail closed at spec load (§4a.6). | `MALFORMED_SPEC` / `UnknownComparatorParam` | `test_validate_params_closed_world_*`, `test_parse_spec_rejects_unknown_comparator_param_at_load` |
| 8 | Producer **tampers the claimed value** | Comparator compares the verifier's recomputed value against the claimed value; a mismatch fails closed. | `REDERIVATION_MISMATCH` | `test_tampered_value_fails` |
| 9 | Producer **claims a type no spec defines** | Resolution fails closed on an unknown type. | `UNKNOWN_TYPE` | `test_tampered_type_unknown_fails` |
| 10 | Dispatch engaged with **no auditor anchor** | The producer's manifest alone would select authority — refused. | `AnchorViolation` | `test_no_anchor_fails_closed` |
| 11 | A primitive **raises** mid-recompute | Wrapped try/except → recorded failure; never crashes the verifier (fail-closed, not fail-stop). | `RECOMPUTE_ERROR` | (covered by malformed-input paths) |
| 12 | Producer **steers a verifier-side read out of the bundle** via a bundle-data-named path (build recipe `inputs`, scrabble timeline `wordlist_file`) — `../` traversal, an absolute path, or a symlink under the bundle | "Bundle data, not code" requires bundle data cannot steer arbitrary reads. Both file-naming sinks route through `_safepath.resolve_within`, which resolves the join (following `..`/symlinks, letting an absolute path discard the root) and asserts containment inside the declared root; an escape raises → fail-closed before the read. Mirrors the dispatch `output_id` containment defense. | `RECOMPUTE_ERROR` | `test_primitive_path_containment.py` |
| 13 | Producer **launders a non-finite value** — commits an input that OVERFLOWS the producer's (faithfully mirrored) binary64 arithmetic to `inf`/`nan` and claims that value. stdlib `json` round-trips `Infinity`/`NaN`, so claim and recompute "agree", and `exact` (`inf == inf` is True) / `structured` / `set` would bless it GREEN. | Dispatch applies a **non-finite boundary before every comparator** (`_first_nonfinite_path` over both the recomputed value and the claimed value, walking nested lists/dicts iteratively). Any `inf`/`-inf`/`nan` on either side is a fail-closed REJECT: a non-finite result is never a verifiable compliance claim and is not portably reproducible. Lifts the per-operand guard `scalar_epsilon` already had to the chokepoint, so it holds for ALL comparator kinds. | `NON_FINITE_VALUE` | `test_dispatch_nonfinite_value_fail_closed.py` |

## Residual / out-of-scope (deliberate, not silent)

- **Authority of the anchor itself.** The `SpecAnchor` is trusted as the
  auditor's distribution artifact (supplied at construction). Distributing it
  (signed allowlist vs. per-audit required-SHA vs. verifier-bundled file) is an
  operational/deployment concern, not enforced here. The mechanism this code
  provides is: *given* an anchor, the producer cannot author or select around
  it.
- **Monotone-strictness instantiation.** The as-built rule is the conservative
  reading — types sharing a `primitive_id` must carry an **identical**
  comparator (no strength variation at all). A graded partial order
  (equally-or-more-strict) is a documented future generalization; the identical
  rule is sound and strictly stronger for the substitution attack.
- **Coverage source.** Coverage is checked against the `outputs/` file
  enumeration. Outputs that exist in neither `outputs/` nor `manifest.outputs`
  (a genuinely absent output) are a cross-host / causal-chain (C19) concern, out
  of scope for this single-bundle dispatch step.

## Phasing (logged, NOT a silent cap)

Step-7 shipped **three exemplar primitives** spanning the comparison space
(`spectra_span_recompute` → text_normalized, `climate_emission_recompute` →
exact, `fea_vonmises_recompute` → scalar_epsilon), since joined by the three GACI
index primitives and `tabular_recompute` (→ exact) — **7 registered** as of this
revision. These **enable** the claim that spec-pinned dispatch is a running
component. The remaining corpus primitives (the `set` / `structured` /
`custom`-tail comparison classes in `S0_SUBSTRATE_MAP.md` §4) are migrated over
the provisional window as **conformance**, not enablement — a deliberate, logged
phasing tracked per computation shape in `RECIPE_BOOK.md` (the promotion loop +
tracker), not a silent cap. The comparator registry already implements all 5
generic kinds; the phasing is per-primitive, not per-comparator.
