# Offline Verifier Contract

Normative contract for the stdlib-only verifier surface. Every clause below is
enforced by a named test — the tests are the teeth; this document is the index.
If a clause and the code disagree, the enforcing test is red and the release is
blocked, or the contract is wrong and must be amended in the same change.

## Scope

Two verifier faces share one verdict model:

| Face | Entry point | Dependency posture |
|------|-------------|--------------------|
| Core library | `audit_bundle.verifier.BundleVerifier.verify()` | stdlib-only at import; all third-party crypto behind function-local deferred imports |
| Offline CLI | `veriker/cli/verify.py` | stdlib-only at module load; same deferred-import rule |

"Stdlib-only" means: a bare Python interpreter with **no third-party packages
installed** can import both faces and verify a bundle. Dependency-bearing
verification (Ed25519 envelope checks, COSE, TUF, Z3 dispatch) is the
*substrate path* — reached only through deferred imports, and only additive on
top of a structural verdict, never a substitute for one.

## Clauses

**C-1. Offline.** Verification reads only the bundle directory and verifier-held
anchors. No network I/O on the verdict path.
One qualified exception: for UNSEALED bundles whose spec pin has no offline
`spec/` copy, spec-hash pinning may fall back to the git history surrounding
`bundle_dir` (integrity-safe — the blob must hash to the manifest-pinned
SHA-256 before use — and always disclosed in `Completeness.disclosures`;
disable with `allow_spec_git_fallback=False`). SEALED bundles never take the
fallback: a signed pin with no signed offline copy is a structured
`sealed_spec_offline_copy_missing` REJECT — a sealed verdict is a function of
the bundle plus injected policy, never of the verifier host.
*Enforced by:* `tests/test_spec_git_fallback_disclosure.py`.

**C-2. Import boundary.** The core library path and `veriker/cli/verify.py` import
successfully under a hook that blocks every non-stdlib, non-first-party module.
A new top-level third-party import on either face is a contract break.
*Enforced by:* `tests/test_stdlib_import_boundary.py` (import-cleanliness
tests + blocker self-test).

**C-3. Structural verification only.** The stdlib path concludes on manifest
admission, schema shape, path containment, per-file SHA-256, spec-hash pinning,
cross-refs, and conservation/set-closure. It never claims signature, trust-root,
or solver-backed verification.

**C-4. Tri-state verdict.** `OK | REJECT | ERROR`, with `ERROR` discriminated
into CRASH vs INCOMPLETE (`audit_bundle.verdict.ErrorKind`). CLI exits:
0 = OK, 1 = REJECT (artifact bad), 2 = ERROR (could not conclude). A caller
keying on `exit != 0` reads both failure classes as "not certified".

**C-5. No silent upgrade.** Evidence that is present but not evaluated by this
build must surface as ERROR/INCOMPLETE (exit 2), never ride a green verdict:

- DSSE-sealed bundle, no crypto importable → `DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO`
- Extension receipt with no registered handler → `EXTENSION_RECEIPT_NOT_EVALUATED`
- Bundle-supplied re-derivation pack, not executed → `RE_DERIVATION_NOT_EXECUTED`
- Cross-host evidence without a wired cross-host verifier → ERROR (per-edge
  coverage accounting: `present − verified == ∅` or no conclusion)

*Enforced by:* the deps-absent fixtures in `tests/test_stdlib_import_boundary.py`,
plus `tests/test_extension_receipt_exit_code.py` and
`tests/test_cli_library_verdict_divergence.py` in the normal environment.

**C-6. Machine-readable completeness.** A verdict carries structured
`Completeness` (`layers`, `deep_validation`, `disclosures`) and typed
`reasons[]` — consumers never parse prose to learn what a green verdict does
NOT include.

**C-7. Immutable parsed inputs.** Parsed manifests are deep-frozen at the parse
boundary before any check sees them.
*Enforced by:* `tests/test_manifest_deep_immutability.py`,
`tests/test_frozen_field_ratchet.py`.

**C-8. Substrate is additive, not implied.** The stdlib face says
"structurally sound / not / cannot conclude". Cryptographic trust statements
come only from the substrate path with the trust root injected by the
integrator (the public-key allowlist is never inside the bundle). Combining
the two faces into an acceptance decision is downstream policy, not a verifier
claim.

**C-9. Numeric model — mirror the producer, reject the non-finite.** A
re-derivation primitive recomputes the producer's arithmetic *faithfully*: it
reproduces the producer's exact numeric model (native IEEE-754 `binary64` where
the producer used it), it does **not** re-cast the computation into a "safer"
`Decimal`/fixed-point model. A verifier that computed in a different number
system than the producer would diverge on legitimate bundles and fail to detect
tampering on the producer's own terms — faithfulness, not a chosen
representation, is the contract. The price of `binary64` faithfulness is bounded
by two rails: (a) tolerance for a primitive whose recompute calls a
cross-platform-non-deterministic libm transcendental (e.g. `math.log`) is
carried in the auditor-anchored spec as a `scalar_epsilon` comparator, optionally
tagged with a documentary `numeric_model` (`binary64_exact` /
`binary64_libm_tolerated`) so an auditor can tell a reasoned margin from an
accidental coercion; and (b) a **non-finite boundary** applied before every
comparator — any `inf`/`-inf`/`nan` in the recomputed value *or* the producer's
claimed value (walked through nested structures) is a fail-closed `REJECT`
(`NON_FINITE_VALUE`), because a non-finite result is never a verifiable
compliance claim (it signals overflow or a degenerate input) and stdlib `json`
will otherwise round-trip `Infinity`/`NaN` straight through a value-equality
comparator.
*Enforced by:* `tests/test_dispatch_nonfinite_value_fail_closed.py`,
`tests/test_comparator_numeric_model.py`.

**C-10. Registry discipline — bootstrap-time population, per-run snapshot,
single execution.** Pluggable registries (extension-receipt handlers, typed
checks, re-derivation primitives, comparators) are populated only by
verifier-DISTRIBUTION code at import/bootstrap; bundle-supplied code never
runs in the verifier process on the default path, so nothing an artifact
carries can reach a registration function. The registries are deliberately
NOT defended against in-process concurrent mutation — code positioned to call
a registration function is positioned to patch `verify()` itself, so that is
outside the threat model. What the verifier DOES guarantee is per-run
coherence: one `verify()` run reads ONE snapshot of the receipt-handler
registry and evaluates every receipt kind against it, each handler executes
exactly ONCE per run, and the CLI presents the dispositions recorded on the
verdict face (FAIL / NOT_EVALUATED as reason legs, PASS as a prefixed
disclosure) rather than re-executing handlers — a single verdict artifact can
never mix two registry states or two handler runs. A receipt kind present in
the manifest with no recorded disposition is `EXTENSION_RECEIPT_UNACCOUNTED`
(could-not-conclude, exit 2), never a silent pass. Which handlers a given
BUILD registers may legitimately differ — that difference is disclosed on the
verdict face as `NOT_EVALUATED` / exit 2 (C-5), never silently absorbed.
*Enforced by:* `tests/test_extension_receipt_registry.py` (snapshot immunity,
single-execution counter, unaccounted-kind fail-closed),
`tests/test_extension_receipt_exit_code.py`.

**C-11. One artifact per verdict — the sealed snapshot.** A verdict is a
conjunction of checks; the conjunction is meaningful only over ONE immutable
byte-set. `verify()` therefore materializes a verifier-private sealed copy of
`bundle_dir` before any verdict-influencing read (including the manifest
read) and runs every step against that copy: the strict-SHA walk over the
snapshot binds the snapshot's bytes to the manifest pins in that same
snapshot, so a mutation racing the copy either yields the pinned artifact or
a REJECT — never a verdict whose legs each passed on different bytes. A
bundle that cannot be read as one stable artifact (entry vanishing or
changing kind mid-copy, post-copy re-walk drift) is a structured
`SNAPSHOT_SOURCE_UNSTABLE` REJECT; an unreplicable node type (socket/device)
is `SNAPSHOT_UNSUPPORTED_NODE`; a verifier-side materialization failure
(tempdir, ENOSPC) is a clean could-not-conclude ERROR
(`SNAPSHOT_MATERIALIZATION_FAILED`), never blamed on the bundle. The copy is
verifier-held scratch (C-1's offline scope is unchanged — no network, no
host state beyond the temp directory). Opt-out is loud:
`unsafe_in_place=True` / `--unsafe-in-place` reads `bundle_dir` live and
stamps every completeness-bearing verdict face with an in-place disclosure a
strict consumer can refuse.
*Enforced by:* `tests/test_sealed_snapshot.py` (mid-run-swap coherence,
in-place split demonstration + disclosure stamp, node-type vocabulary,
non-quiescence REJECT vs materialization ERROR, cleanup).

## Terminology

Definitional, not a clause: this section fixes what each verb *claims* so an
auditor never has to infer trust semantics from a function name alone. API
names use these verbs in exactly these senses; a new API that bends one is a
doc bug or a naming bug, fix whichever is wrong.

- **admit** — bounded parsing of untrusted bytes before anything looks at
  their meaning (`audit_bundle.admission`: `admit_bytes` / `admit_obj` /
  `admit_json_file` / `admit_jsonl_file` — size, depth, and shape ceilings,
  fail-closed). Admission claims only "safe to parse", never "true".
- **validate** — structural/closed-world checks on an already-admitted value
  (`validate_manifest`, `validate_event_cddl`, …). Raises or rejects on
  malformed shape; makes no claim that the content is correct or trusted.
- **verify** — the verdict-producing act: evaluate evidence against
  verifier-held anchors and recomputation, concluding `OK | REJECT | ERROR`
  (C-4). Only `verify*` APIs mint trust conclusions.
- **re-derive** — recompute the producer's claimed computation from the
  bundled inputs and compare against the claimed output (Axis-2;
  `rederivation/primitives/`, `re_derivation` plugins), mirroring the
  producer's numeric model per C-9. Stronger than checking bytes: it re-earns
  the claim, not just the hash.
- **discharge** — conclude one SMT refinement obligation via a solver backend
  (C16, `audit_bundle.discharge`). Only `verifier_signing.sign_and_write` may
  set `proof.discharge_status` past `not-attempted`; unsigned non-trivial
  statuses are `DISCHARGE_STATUS_FORGED`.
- **sign** — covers two different trust claims, and the scheme is named, not
  implied. `*_hmac` (gate verdicts, the v0.2 discharge signer, single-org
  cross-host authenticators) = symmetric **tamper-evidence within a trust
  domain**: any key holder can mint, so it is NOT non-repudiation. `*_ed25519`
  / `*_cose` (gate verdicts, DSSE envelopes, cross-org authenticators) =
  asymmetric **non-repudiation** bound to a signer identity. Where both
  schemes exist for the same artifact (gate verdicts, cross-host
  authenticators), the suffix disambiguates; single-scheme signers state
  their scheme and its limits in the module docstring.
- **attest** — a party other than this verifier vouches for evidence the
  verifier cannot recompute (C17 attested serving, C19.B cross-org
  authenticators). Verification checks the attestation artifact; it does not
  thereby claim the attested fact independently.
- **seal** — wrap a canonical claim set in a DSSE envelope
  (`dsse.envelope.sign_envelope`, Ed25519). A sealed bundle whose seal cannot
  be checked is C-5 ERROR, never silently green.
- **proof** — noun only, two senses: (a) Merkle inclusion/consistency proofs
  from a transparency log (Rekor / STH gossip); (b) the manifest's refinement
  `proof` block, whose `discharge_status` is verifier-set (see *discharge*).
  No API here claims to "prove" anything beyond these two senses.

## Amending

A change that loosens any clause must update this file and the enforcing test
in the same commit, and must be called out in the release notes for the next
release. A change that tightens a clause only needs the test.
