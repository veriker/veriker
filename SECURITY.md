# Security policy

This document describes the Veriker audit-bundle substrate's vulnerability disclosure process, supported versions, and what is in / out of scope for a security report. It follows the [GitHub disclosure conventions](https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository) and the substrate's calibration discipline: substrate-grade, not enterprise-grade. The full security posture — security brief, threat model, and security target — is maintained in the project's security documentation.

---

## Reporting a vulnerability

**Preferred channel:** email the maintainer with subject prefix `[VERIKER SECURITY]`.

- **Contact:** `security@nexiverify.com`
- **PGP:** key fingerprint TBD (will be published here once generated)
- **Acknowledgement:** initial acknowledgement within **3 business days** of receipt
- **First substantive response:** within **10 business days** of receipt, including triage verdict (in-scope vs out-of-scope vs need-more-info) and a target embargo date

Please do NOT open a public GitHub issue for security reports. The substrate is mirrored to a private GitHub repository for supply-chain attestation purposes only; public issues there would defeat the embargo.

---

## What we want in a report

A useful report includes:

1. **Affected versions** — substrate `schema_version` or commit SHA if you reproduced against a specific build.
2. **Reproduction** — a minimal bundle (or bundle-fragment) that exhibits the issue, plus the exact verifier command + output.
3. **Impact** — what security property does this break? Map to a named security property from the security brief (§6 SP-1 through SP-10) or known limitation (§9 L1 through L12) if you can.
4. **Severity, if you've assigned one** — CVSS v3.1 base + vector string is appreciated but not required. We will assign our own if you don't.
5. **Discoverer credit preference** — name + affiliation if you want public credit in the advisory; "anonymous" is also fine.

---

## Embargo timeline

**Default embargo: 90 days from acknowledgement.**

- **Day 0:** acknowledgement; triage begins.
- **Day 0-14:** triage + fix design.
- **Day 14-60:** fix implementation + regression test + (for protocol-affecting changes) internal tribunal review.
- **Day 60-83:** coordinated-disclosure window — affected deployments (if any are identified) are notified, given the patch + advisory under embargo.
- **Day 83-90:** advisory finalized; embargo released; advisory published.
- **Day 90+:** public advisory + patch in the next release.

We may **shorten** the embargo (with reporter agreement) if the issue is being actively exploited, or **extend** it (with reporter agreement) if coordination requires it. Extensions are not unilateral; we will tell you why and ask before adjusting.

We commit to publishing an advisory even for **honest-null** results — if a reported issue is determined to be out-of-scope or working-as-designed, we publish the analysis so the reporter's work is acknowledged and the rationale is on the record.

---

## Advisory format

Public advisories follow CVE-style structure:

```
Advisory ID:        VERIKER-YYYY-NNNN
Severity:           Critical / High / Medium / Low / Informational
CVSS v3.1:          <vector + score>
Affected versions:  <schema_version range or commit-SHA range>
Discovered by:      <reporter credit, or "anonymous">
Reported:           <date>
Fixed in commit:    <SHA>
Released in:        <next-tag>

## Summary
<one-paragraph plain-English description>

## Impact
<which security property is broken, which deployments are at risk, blast radius>

## Workaround
<actions a deployment can take before upgrading; "none" is a valid answer>

## Fix
<what the fix does, link to the commit + the regression test>

## Timeline
<acknowledgement, triage, fix landed, coordinated disclosure, public release>

## References
<RFC sections, internal-doc cross-refs IF the report does not reveal internal-only information, related CVEs>
```

Advisories will be published in the project's security documentation and, where appropriate, shared with affected deployments under NDA.

---

## Supported versions

| Schema version | Status | Notes |
|---|---|---|
| `vcp-v1.1-canary4` | **Supported** (current) | Active development branch; security fixes land here first |
| `vcp-v1.1` | Supported | Predecessor schema; security fixes back-ported on best-effort basis |
| `legacy` | Out-of-band only | Pre-v1.1 envelope variant; no security fixes — migrate to vcp-v1.1 |

Schema version is enforced by `audit_bundle/bundle_manifest.py::_VALID_SCHEMA_VERSIONS`. The full field-level schema is in `MANIFEST_SCHEMA.md` at this repository root.

---

## Code execution in the verify path

**The default verify path NEVER executes bundle-supplied code.** This is a load-bearing property of the threat model "can an untrusted artifact cause code execution on the auditor's machine?" — the answer is **no** by default.

- **Safe re-derivation (default).** Re-derivation is performed by *spec-pinned dispatch* (`audit_bundle/rederivation/`): the recompute primitives and comparators are **verifier-distribution code, registry-resident, never bundle-supplied**. A bundle declares *what* to recompute (`manifest.outputs` + an auditor-supplied `SpecAnchor`); it cannot supply the code that runs. An unregistered primitive id fails closed (`UNKNOWN_PRIMITIVE`). See `audit_bundle/rederivation/THREAT_MODEL.md`.

- **Legacy re-derivation packs are opt-in and unsafe.** A bundle may ship a `re_derive/*_pack.py` — bundle-supplied Python that `ReDerivationInvocationCheck` runs via subprocess. Executing it is **arbitrary local code execution**: a malicious pack can read/write files, inspect env, spawn subprocesses, or simply `exit(0)` without re-deriving anything (the producer would be grading its own homework). Therefore:
  - `veriker/cli/verify.py` executes a pack **only** under the explicit `--unsafe-run-bundle-pack` flag (default OFF).
  - With the flag OFF, a present pack is **not executed** and the verdict is `ERROR` (exit `2`, "could not conclude") — re-derivation is the core verified property, so leaving it unevaluated is **not** a green verdict. The CLI prints a `NOT-RUN` row + an `INCOMPLETE` summary so exit-code-only consumers cannot overread it as covered.
  - At the library layer, `ReDerivationInvocationCheck(..., permit_execution=...)` requires the trust decision as a keyword with **no default** — every call site must state it.
  - Use `--unsafe-run-bundle-pack` **only** for bundles from a trusted producer or on a disposable host. Never on untrusted bundles.

> Offline operation prevents *network* exfiltration only if the environment truly blocks the network; it does **not** prevent local file/process tampering. The protection above is that the untrusted bundle's code does not run at all in the default path.

---

## Path containment in the verify path

**A bundle cannot steer a verifier-side read outside `bundle_dir`.** Manifest path fields (`files`, `snapshots`, `spec_files`, `decision_provenance_log`, `retrieval_trace_log`, per-record `obligation_uri` / `wordlist_file`, …) are *bundle-controlled data*. The naive `bundle_dir / rel_path` join does **not** defend the tree: pathlib absolutizes when `rel_path` is absolute (`Path("/bundle") / "/etc/passwd" == Path("/etc/passwd")`) and does not normalize `..`. Every read of a bundle-controlled path therefore routes through `_safe_bundle_path(bundle_dir, rel_path)` (`audit_bundle/bundle_manifest.py`), which resolves the join and fail-closes (`UnsafeBundlePath`) when the result escapes `bundle_dir.resolve()` or targets a directory.

- **The guard lives at the read site, not only at a central validator.** `BundleVerifier.verify()` *aggregates* failures across steps rather than short-circuiting on the first, and the plugin step runs *before* deep manifest validation. So a plugin that reads a bundle-controlled path must apply the containment guard itself — a later validator appending a failure does not stop the earlier unsafe read. Every plugin that dereferences a manifest path does so via `_safe_bundle_path` (`fragment_attestation`, `file_integrity_many_small`, `refinement_discharge`, `spec_sha_pin`, `source_attributes_consistency`).
- **Convention for new plugins:** never raw-join a bundle-controlled path; call `_safe_bundle_path` and surface `UnsafeBundlePath` as a structured `*_UNSAFE_PATH` REJECT. (A 2026-06-10 redteam finding caught `source_attributes_consistency` raw-joining `decision_provenance_log` — the one manifest-controlled read site that had been missed when the guard was added to its siblings; closed with `PROVENANCE_LOG_UNSAFE_PATH` + a path-escape regression test.)

---

## Input admission on bundle-file reads

The admission gate (`audit_bundle/admission.py`) bounds input **size**, JSON **depth**, and per-collection **cardinality** so a hostile-shaped input is a cheap pre-parse REJECT rather than an expensive `RecursionError` / large allocation. `manifest.json` passes through it at the verify entry point; **every other bundle-controlled JSON read in the package goes through the shared loaders** — `admit_json_file(path)` for a single-value JSON file, `admit_jsonl_file(path)` for a line-delimited `.jsonl` file (size-bound, then depth-bound each line before parsing it, then bound the row count), `iter_admitted_jsonl_tolerant(path)` for the skip-malformed line scans (per-line depth-bound, oversize fails closed). A **ratchet test** (`tests/test_bundle_json_admission_ratchet.py`) scans the **entire `audit_bundle/` package recursively** and fails CI on a raw `json.loads(<file read>)` or a `json.loads`-bearing loop over `<file read>.splitlines()`; the allowlist is path-keyed and every entry carries its justification (currently: the C18 TUF client, which reads operator-side trust-store metadata, and `verifier.py`, whose manifest read is pre-admitted at the verify() boundary).

*Scope history (2026-06-11, RES-02):* the first ratchet scanned only `rederivation/primitives/` + `plugins/`, non-recursively — and the next redteam round found the **producer-claimed value** (`outputs/<id>.json`, `rederivation/dispatch.py`) read raw, one directory above the scan root, with `plugins/reference/` escaping via the non-recursive glob. The grep-driven completion of that sweep also fixed a sharper defect in the two tolerant line scanners (`bundle_manifest` policy-stamp scan, C9.1 attribution scans): a per-line depth bomb raised `RecursionError`, which **escaped** their `(JSONDecodeError, ValueError)` tolerance and crashed the verifier instead of being skipped like any other malformed line. Self-contained reference verifiers (`plugins/reference/`) carry a duplicated inline bounded loader rather than importing the package, preserving their stdlib-only/standalone contract.

What this is and is not, against the scope above:

- **Depth / cardinality on attacker-controlled shape** is the in-scope concern this addresses — a depth-bomb input file is rejected by the byte scan *before* `json.loads` can recurse.
- **A merely large-but-valid file** ("legitimate-shaped but expensive") remains an **operator** rate-limiting concern, *out of scope* per the list above. The loaders still apply the manifest's 16 MiB ceiling as a sanity bound, and note the per-file SHA-256 integrity walk (`_sha256_file`) reads each `manifest.files` entry in full regardless — so size is bounded by operator policy, not by these loaders. Reads that are **not JSON parses** (audio/raster binary payloads, CSV data, SHA integrity reads) stay raw `read_bytes()` by design — they are not recursion vectors, and the ratchet does not flag them.
- **The final backstop is unconditional.** Independently of admission, a `RecursionError`/`MemoryError` is an `Exception` subclass caught by the dispatch boundary (→ `RECOMPUTE_ERROR`) and the plugin boundary (→ classified ERROR), never an unhandled escape (`verdict.py` `fail_closed`). The loaders make the common case a *cheap, localized* REJECT before that backstop is reached — they are a coherence/cost improvement layered on a fail-closed property that already held.
- **Convention for new code anywhere in the package:** read bundle JSON via `admit_json_file` (single value), `admit_jsonl_file` (`.jsonl`), or `iter_admitted_jsonl_tolerant` (skip-malformed scans), never raw `json.loads(path.read_bytes())` — the ratchet enforces this package-wide. The ratchet is AST-based and cannot see variable indirection, file-handle iteration, or bytes-fed parses (documented in its docstring) — review those shapes by hand.

---

## Read binding under mid-run mutation (TOCTOU on the verify path)

A verdict is a **conjunction of checks that each read bundle files at separate instants**. The verifier does *not* assume `bundle_dir` is quiescent while `verify()` runs — that assumption is exactly what a shared/mutable directory, a concurrent regeneration job, or an active adversary violates, and the codebase treats mid-run mutation as in-scope (the manifest is read **once** at the verify entry and carried forward; file reads go through a no-follow/no-block open with a post-open regular-file recheck so a stat→read object swap is refused at open time, never followed or hung on).

**The whole-class closure (2026-06-11): `verify()` runs against a sealed snapshot.** Before any verdict-influencing read — including the manifest read — `verify()` materializes a verifier-private copy of `bundle_dir` (`audit_bundle/snapshot.py`) and runs **every** step against that copy. The strict-SHA walk over the snapshot binds the snapshot's bytes to the manifest pins *in that same snapshot*, so the verdict is a conjunction over **one immutable byte-set by construction**: a mutation racing the copy either produced a snapshot that satisfies the pins (in which case it *is* the pinned artifact) or one that mismatches (REJECT). This is the only mechanism that can cover the **append-only file class**, which deliberately carries no byte pin for read-site binding to bind against — per-read digest binding upgrades individual checks, but only whole-tree coherence makes the conjunction itself coherent. The former "verify a sealed copy you control" operational posture is thereby mechanical, not prose.

Snapshot semantics, briefly: regular files are copied through the same no-follow/no-block open as the integrity walk; symlinks are replicated (an absolute in-tree target is re-anchored onto the snapshot root so the as-built contained-symlink tolerance survives relocation; escapes stay verbatim and still reject); FIFOs are replicated unopened (`mkfifo` + `chmod 0`) so the conservation gate's non-regular rejection face is unchanged; sockets/devices fail closed (`SNAPSHOT_UNSUPPORTED_NODE`). A source entry that vanishes or changes kind mid-copy — including a post-copy re-walk that observes a different path set (the readdir/rename race) — is a structured REJECT (`SNAPSHOT_SOURCE_UNSTABLE`): the bundle could not be read as one stable artifact. A destination-side failure (tempdir creation, ENOSPC) is a clean could-not-conclude ERROR (`SNAPSHOT_MATERIALIZATION_FAILED`), never blamed on the bundle. **Bytes are the only verdict-bearing property** — no check reads mtime/inode/xattr semantics (the DSSE set-closure walk compares its own pre/post fstats for swap detection, never absolute metadata), so the copy normalizing those is in-contract. The copy transiently doubles the bundle's disk footprint; that is an operator-capacity concern (point `TMPDIR` at a scratch volume), the same scope boundary as the admission loaders' size doctrine above.

**Opt-out is loud:** `BundleVerifier(unsafe_in_place=True)` / `--unsafe-in-place` skips the copy and reads `bundle_dir` live; every completeness-bearing verdict face that lane emits carries a **disclosure** that mid-run-mutation coherence rests on the caller having sealed the directory. A strict downstream consumer can refuse stamped verdicts.

The content-level discipline retained underneath (defense in depth, and the rule for any reader that ever runs outside `verify()`'s snapshot lane):

- **A check whose verdict claim *names* a pin (a CID or SHA) must bind the bytes it actually read to that pin at its own read site — never defer the binding to another check's separate read of the same path.** Two independent reads of one path are not the same bytes under mutation; two reads each bound to the same collision-resistant digest are.
- **Bound-at-read-site today:** the strict-SHA integrity walk and the deep snapshot-CID validator (each hashes its own read by construction); `spec_sha_pin`; `refinement_discharge` (`PROOF_OBLIGATION_SHA_MISMATCH` — SHA over the obligation bytes it read); `fragment_attestation` (`FRAGMENT_SOURCE_CID_MISMATCH` — CID recomputed over the snapshot bytes the quote is attested against, closing the 2026-06-11 BLOCK-02 split).
- **Convention for new checks:** if your `PluginResult` detail or reason semantics reference a manifest digest, recompute that digest over the exact bytes you read (after `_safe_bundle_path` + the no-follow open) and fail closed on mismatch with a structured `*_MISMATCH` reject.

---

## Append-only logs and historical continuity

**"Append-only" is a writer-API convention, not a structural tamper-evidence claim — and the structural claim exists, one layer up, where it can actually bind.** The producer-side JSONL writers (`event_stream.append_event`, `source_registry.decision_provenance.record_decision`) never rewrite prior rows, but the growing local file is plain bytes on the producer's disk: a local process with write access can truncate, rewrite, or reorder it. Reviewers repeatedly propose per-row sequence numbers + previous-row hashes inside these writers; that recommendation is **deliberately not built**, because the named adversary — the same local process — recomputes an unanchored chain in the same write. An unanchored hash chain over a locally rewritable file is record-quality theater, not tamper-evidence.

The guarantees, per layer:

| Layer | Guarantee | Mechanism |
| --- | --- | --- |
| Post-mint (log inside a bundle) | truncation / rewrite / reordering of the log is a verifier **REJECT** | bytes digest-pinned by `manifest.files` sha256 (STRICT_SHA), set-closed under DSSE seal; undeclared files are `EXTRA_FILE_NOT_IN_MANIFEST` (conservation gate) |
| Pre-mint continuity **as a verifiable claim** | truncation, reordering, and duplicates in the event history are rejected by the verifier | C19 Layer A (`extensions/c19/layer_a_counter.py`): per-chain **monotonic counters**, **prev-event hash chain**, event-hash **Merkle root** bound into `causal_chain.layer_a` — anchored, so the chain is not locally recomputable; `verify_chain_integrity` enforces exactly this list |
| Pre-mint, no Layer A | continuity is honestly **UNCLAIMED** | the declared-append-only ownership class guarantees `ATTRIBUTION_KEY_COVERAGE` with `PRODUCER_DECLARED` authority (`integrity_ownership`) — every record carries its attribution key; nothing asserts the history is complete |

A compliance pilot whose control *requires* proven log continuity is therefore a Layer A (or premium trusted-time / cross-org) bundle by construction — the open tier does not silently upgrade an append-mode file into a continuity claim. This is the same per-surface honesty discipline as the clock/replay map below: the question "is this log's history intact?" is answered by *which guarantee the bundle carries*, never by the writer's API shape. Reader-side, the verdict-path consumer of these logs (`source_attributes_consistency`'s replay-completeness leg) reads through the admission loaders above and structurally rejects malformed or truncated-mid-line tails (`PROVENANCE_LOG_UNREADABLE`) rather than streaming past them.

---

## Clocks and determinism (replay map)

**The replay guarantee is per-surface, not global.** Some verifier surfaces promise *deterministic replay* — same inputs (and, where time matters, same recorded time) → same verdict. Others are *wall-clock by nature*, because the question they answer is inherently "now" (is this trust material fresh **today**?). Reviewers repeatedly ask why one surface injects and records its clock while another reads the wall directly; this table is the answer. A surface is only a determinism finding if it is in the "replayable" rows **and** reads an unrecorded wall clock.

| Surface | Clock source | Replayable? | Where the time lives |
| --- | --- | --- | --- |
| Offline bundle verification — `BundleVerifier.verify()` / `veriker/cli/verify.py` | none — the verify walk reads no wall clock¹ ² | **yes** — pure function of bundle bytes + verifier config | n/a |
| DSSE revocation check (verify step 4) — `revocation.is_revoked` | caller-injected `verifier_now` (required) | **yes** — verdict records `(revocation_list_hash, verifier_now)` | `RevocationVerdict` |
| Gate verdict verification — `gate.verdict_signing.verify_*` + ed25519 twin | none — the action-bound verifiers read no wall clock: `now_epoch` is a **required** argument (the former wall-clock default was removed 2026-06-11 after four independent reviews flagged it) | **yes** — pure function of arguments; the driving clock is echoed in the structured `ActionGateVerdictCheck` result, so the verdict records its own reproducibility | `not_after` is in the signed tuple; the caller owns its `now` and the result carries the `(now_epoch, not_after)` pair |
| C19 cross-host edge timeliness (RADI-bounded inequality, ack bounds) | no verifier clock — bundle-carried timestamp evidence only (shape-checked at v0.3; strict mode crypto-verifies against pinned Roughtime roots) | **yes** — pure function of bundle bytes + verifier config | in-bundle `timestamp_evidence` |
| C18 verifier supply-chain fetch — `c18_tuf_client.load_bundled_root` pre-checks + `fetch_release_manifest` | host wall clock — both our freshness pre-checks **and** python-tuf's authoritative protocol checks downstream | **no, by design** — a live network feed refresh is not a verdict surface and is not replayable | TUF `trust_dir` persists last-seen metadata versions (rollback/freeze state) |

¹ Strengthened 2026-06-10: previously two plugins appended wall-clock-stamped rows to `bundle_dir/events.jsonl` during verify. The conservation gate made that self-poisoning (a verifier-written file classifies UNOWNED surplus → the NEXT verification of the same bundle flipped RED), so verify() is now fully read-only: those signals ride the verdict face (`Completeness.disclosures`), the retained C16 Fork A divergence record stamps a deterministic `unrecorded` sentinel by default (injectable seam for callers that want a real observation time), and `tests/test_verify_readonly_ratchet.py` pins both the no-write invariant and byte-identical re-run verdicts.

² Z3 recheck determinism (2026-06-10, external-review finding → tribunal-ratified fix): the C16 Z3 re-discharge inside verify() previously budgeted by **wall clock** (Z3 `timeout` parameter + an `elapsed ≥ 0.95×timeout` classification heuristic), which made borderline obligations machine-speed-dependent — a contradiction of this row by the table's own criterion. The budget is now Z3's `rlimit` (deterministic abstract resource counter: same Z3 version + same input + same rlimit → same outcome on any machine); wall clock survives only as an OS-level crash guard whose firing is an infrastructure error, never a verdict outcome. Residual caveats, honestly held: (a) rlimit determinism is **per Z3 version** — records can pin their minting policy (`recheck_context.__solver_policy__`, HMAC-bound) and a mismatch under version skew is `DISCHARGE_STATUS_NOT_CONFIRMED` (clean-ERROR), never a forgery verdict; (b) claim-vs-replay comparison runs on the coarse lattice {discharged, failed, not_proved} because Z3 reason strings are not stable enough to bear verdict weight; (c) a pinned rlimit below the verifier floor on a not-proved claim is `DISCHARGE_UNDER_RESOURCED` — the floor blocks producer-steered under-resourcing. See `audit_bundle/plugins/REASON_CODES.md` and the `refinement_discharge` module docstring for the full three-cell matrix.

Why the supply-chain row is **not** injected: the freshness pre-checks run immediately ahead of python-tuf's own expiry/protocol checks, which use the host clock with no public injection seam. Injecting only our half would split the clock within one validation pass — two different "now"s — a coherence regression dressed as a determinism improvement. Wall clock is also the semantically correct clock for every caller of these checks (release tooling, image-build validation): the question asked is "is this root fresh *now*."

---

## Verifier-identity trust boundary (C18)

**Two different questions, two different verifiers.** `BundleVerifier.verify()` answers *"is this bundle internally valid?"* — a pure function of the bundle bytes. It does **not**, and structurally **cannot**, answer *"is the verifier binary/container that produced or packaged this evidence the genuine, untampered release?"* That second question is the **verifier-identity** question, and its trust assertion lives **host-side and out-of-band** from `verify()`: TUF fetches the expected image digest, and `cosign` / `crane` (`veriker/cli/host_digest_verify.py`) check the running container's actual digest against it. Reviewers repeatedly conflate the two; this section is the boundary.

The reason the boundary is hard — and why it is the way it is — is that **a compromised verifier cannot be trusted to attest to itself.** Any in-container self-check is producer-controlled: a tampered verifier simply self-reports `passed`. So the bundle's `evidence.verifier_identity.verifier_self_check_status` is a **tripwire signal, never a trust assertion**, and the verify path treats it accordingly:

- **`verifier_self_check_status="failed"` is surfaced as a disclosure, not a verdict.** The tripwire plugin (`audit_bundle/plugins/verifier_identity_tripwire.py`) emits a `VERIFIER_IDENTITY_DIVERGENCE` disclosure on the verdict face and **still returns `ok=True`**. It does **not** by itself REJECT, and it does **not** mutate the bundle (the read-only-verify invariant holds). Forcing an in-core REJECT on a self-reported `failed` would be security theater: it gates on a value the adversary controls, while a tampered verifier reporting `passed` would sail through. The signal's job is to get a human to run the host-side check, not to substitute for it.
- **Structural / hash mismatches DO reject.** The structural verifier (`audit_bundle/extensions/c18_verifier_identity.py`) emits `VERIFIER_IDENTITY_FIELD_MISSING`, `VERIFIER_IDENTITY_OCI_DIGEST_MALFORMED`, `VERIFIER_IDENTITY_REKOR_INCLUSION_PROOF_MALFORMED`, and `VERIFIER_IDENTITY_RELEASE_MANIFEST_MISMATCH` (the last on a **hash recomputation** of the bundled `release_manifest.json`, fail-closed if unreadable). These are structural facts about the bundle, not self-reports, so they compose into the verdict as failures.
- **The in-bundle `rekor_inclusion_proof` field is shape-checked only at v0.3** — the C18 structural verifier checks its shape (no Merkle-inclusion fold, no STH consistency, no freshness), so a shape-valid proof *carried in the bundle* is **not** by itself evidence of log inclusion. Real, cryptographic Rekor inclusion verification now exists host-side via `host_digest_verify --rekor-bundle` (`veriker/cli/host_digest_verify.py`): it re-derives the entry's RFC 6962 inclusion proof to bind the logged leaf to the checkpoint root **and** verifies the log checkpoint's ECDSA P-256 signature against the pinned `rekor.sigstore.dev` key, fail-closed (exit 7). Consumer-side `cosign verify-blob` against the public Rekor log remains the other path (Step 1 of the 4-step flow documented at `receipts.vkernel.dev`). What is **not yet live** is a signed release to point either at: the C18 TUF roots are still synthetic and no hardware-signed release has been cut, so the documented page carries its own "not yet live" banner; the end-to-end flow becomes runnable at the C18 key ceremony + first signed release. Do not present the in-bundle shape check as "transparency-log inclusion verified" — that property comes from the host-side `--rekor-bundle` verification (or cosign), never from the bundle field alone.
- **Public releases MUST run and retain the host-side result.** For ordinary local bundle verification, `host_digest_verify` is optional — you are checking bundle validity, not adopting a release. For a public-release ceremony it is the **required** verifier-identity trust mechanism, and its output is retained alongside the bundle as the binding evidence that the verifier identity matches the release trust root.

The framing to keep: *the bundle verifier answers whether the bundle is internally valid; the host digest verifier answers whether the verifier binary/container identity is bound to the release trust root.* A green `verify()` over a bundle whose `verifier_self_check_status` is `failed` is **expected and correct** — the green attests to bundle validity, the `VERIFIER_IDENTITY_DIVERGENCE` disclosure flags the identity question, and the host-side digest check is what answers it.

---

## In scope

A report is **in scope** if it concerns the substrate code under this product directory and demonstrates:

- A **crypto-forge bypass** — a bundle that verifies green but should not (any tamper-then-verify-success path).
- A **fail-closed violation** — an input that causes the verifier to raise an unhandled exception (`SP-8` discipline).
- A **parser-differential attack** — two consumers of the same bundle bytes reach different verdicts (CBOR / COSE encoding ambiguity).
- A **cross-protocol replay** — a signature minted under one protocol's external_aad verifying under another's.
- An **algorithmic-DoS** — input that causes super-linear verifier runtime on attacker-controlled size.
- A **non-repudiation bypass** — a producer demonstrating they signed a bundle without their actual key material.
- Any other violation of a named security property in the security brief §6 or a tighter-than-acknowledged behavior of a known limitation in §9.

---

## Out of scope

The following are **NOT** in scope for a security report. Reports in these categories will be acknowledged and closed without an advisory.

- **DoS via legitimate-shaped but expensive bundles.** A bundle with millions of edges + events is computationally legitimate; rate-limiting is the operator's responsibility, not the substrate's. (See security brief §4.3.)
- **Side-channel attacks against the Python verifier** — timing, power, EM. Python is not constant-time; the substrate acknowledges this as `§9 L3` and the mitigation path is a future Rust port. A first-pass wrapper-layer audit closed one digest-equality discipline gap and documented the inherent-Python residuals; constant-time-execution verification is **explicitly NOT a substrate-level claim** at v0.4.
- **Quantum cryptanalysis** of Ed25519 / SHA-256. The substrate acknowledges no PQ readiness as `§9 L7`; v0.5+ is the conjectured migration path.
- **Supply chain attack on pyca/cryptography or cbor2.** These are upstream library issues; report directly to those projects. The substrate's mitigation is outside scope (SLSA + Sigstore Fulcio binding).
- **Compromise of the verifier binary itself.** OS-level code signing is assumed (`§10 A1`); a tampered verifier binary defeats the substrate's TCB by design.
- **Compromised-producer attacks** where the attacker has the producer's signing key material. This is the inherent trust limit of any signature-based system; the substrate acknowledges it as `§9 L10`.
- **The plaintext-recovery oracle on payload_hash at v0.3** (`§9 L5`). This is a known issue with a documented mitigation available today (route PII through the redaction interface) and a designed fix path targeted for v0.4 (an HMAC-not-hash migration; the design is scoped but pre-ratification, so no release date is committed). New reports of the same class against v0.3 will be acknowledged as duplicates.
- **The single-host-edge silent-accept** (`§9 L6`, T20 in security brief §4.2). Crypto soundness is pinned (K_send ≠ K_ack via HKDF info-label separation); the trust-model question is open and tribunal-bound — not a substrate-code defect.
- **Bug reports without a security impact.** Non-security bugs go through the normal issue process (report privately to the maintainer; do NOT open a public issue if the substrate is in your supply chain at this maturity tier).

If a report straddles the in-scope/out-of-scope boundary, default to reporting; we will triage and tell you the verdict + the rationale.

---

## Reporter recognition

We publish a **Hall of Fame** for security researchers whose reports led to substrate hardening, alongside the project's security documentation. Recognition is opt-in — the report's discoverer credit preference governs.

We do NOT operate a paid bug bounty at v0.4. The substrate is pre-pilot; a bounty program is L3 work (paired with a maturity tier that has paying customers underwriting it). If the substrate's posture changes, this section will be updated.

---

## Cross-references

- **Security brief, threat model + security target, and side-channel audit:** maintained in the project's security documentation (available to deployments under NDA).
- **Manifest schema:** `MANIFEST_SCHEMA.md` (this repo root)
- **Reason-code catalog:** `audit_bundle/plugins/REASON_CODES.md`

---

## Document version

- **Initial publication:** 2026-05-26
- **Next scheduled review:** at the next v0.X tag, or when the contact email / PGP key changes, or when the embargo timeline is renegotiated
