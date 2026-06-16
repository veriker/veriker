# Verifier fuzzing — parse boundary + path safety

Coverage-guided fuzzing of the reference verifier: inputs are mutated by
libfuzzer (via atheris), and the oracle is the fail-closed contract —
`BundleVerifier.verify()` must never raise; a verifier that returns success on a
malformed or out-of-contract input is a bug. The pytest suites in this directory
codify the threat model directly and run without atheris.

## Suites

| File | Role |
|---|---|
| `atheris_verify_manifest.py` | Coverage-guided harness; fuzzes raw `manifest.json` bytes against `BundleVerifier().verify()`. Crash-oracle: any uncaught exception. |
| `atheris_verify_cose_sig.py` | Layer 1: byte fuzz of `verify_cross_host_authenticator_cose` (K / preimage / cose_bytes via `FuzzedDataProvider`). Crash-oracle only. |
| `atheris_verify_cose_bundle.py` | Layer 2: signature-bypass finder. Pins a deterministic Ed25519 keypair + preimage + canonical envelope; the mutator perturbs `cose_bytes`. Oracle: acceptance of anything byte-different from the canonical envelope is a bypass. |
| `atheris_verify_cose_layer3.py` | Layer 3: structure-aware CBOR mutator. Decodes the canonical envelope into its 4 slots, picks a slot + mutation type, re-encodes (with an optional re-sign arm for an attacker-chosen `Sig_structure`). Same oracle as Layer 2. |
| `atheris_differential_pycose.py` | Atheris-driven `pycose`-vs-production differential (two arms: raw-bytes + structure-aware). Oracle splits divergences by direction: production=PASS / pycose=FAIL **raises** (a verifier bug pycose caught); production=FAIL / pycose=PASS is counted, not raised (the known pycose-side-gap class — trailing bytes, non-empty unprotected, etc.). |
| `atheris_layer4_cross_protocol.py` | Layer 4: cross-protocol differential. Runs BOTH `verify_cross_host_authenticator_cose` and `verify_emergency_offline_root_signature` against the SAME mutated envelope; oracle raises only on **both PASS** (a cross-protocol replay window). Reuses Layer 3's structure-aware mutator. |
| `atheris_layer5_chain_invariants.py` | Layer 5: chain-validator regression fuzzer. Pins a canonical 2-event chain; the mutator applies one of several invariant-breaking ops on `event[1]` (counter skip/equal/zero/neg, counter log-index drift, `prev_event_hash` mutation, duplicate `event_id`, invalid `event_kind`) and re-signs the event so the per-event signature still passes. Oracle: every op MUST trip a chain-level `LayerAVerificationError`; any returned success is a regression in `verify_chain_integrity` or the event-kind dispatcher. |
| `test_manifest_shape_contract.py` | Pytest regressions for the parse-boundary shape guard. |
| `test_manifest_path_safety.py` | Pytest regressions for `_safe_bundle_path`. |
| `test_cose_bundle_slot_safety.py` | Pytest regressions for the COSE_Sign1 slot-type / trailing-bytes / empty-unprotected / mixed-key-survival / oversized-protected-header guards. |
| `test_cose_bundle_layer3.py` | Pytest regressions for the outer-canonical-encoding guard. |
| `corpus/manifest/seed_*.json` | Curated seed corpus for the manifest harness. |
| `corpus/cose/seed_*.bin` | Curated seed corpus for Layer 1 (K \|\| preimage \|\| cose_bytes layout). |
| `corpus/cose_bundle/seed_*.bin` | Curated seed corpus for Layer 2 (canonical envelope + structural variants). |
| `corpus/cose_bundle_layer3/*.bin` | Curated seed corpus for Layer 3 (canonical envelope + variants; the libfuzzer-grown corpus accumulates during runs). |
| `crashes/<surface>/crash-*` | Saved reproducers; each corresponds to a pytest regression case. |

## Running

Dependencies live in the product's `pip install -e ".[dev]"`; atheris is an
extra: `pip install atheris` (requires a libfuzzer-capable Python — wheels exist
for cp311/cp312 manylinux, otherwise `clang` to build from source).

```bash
# from the repo root, with .venv active:
.venv/bin/python tests/fuzz/atheris_verify_manifest.py \
    -max_total_time=120 \
    -print_final_stats=1 \
    -artifact_prefix=tests/fuzz/crashes/manifest/ \
    tests/fuzz/corpus/manifest/
```

Common libfuzzer flags (after `Setup()`, passed through):

- `-max_total_time=N` — seconds to fuzz before stopping
- `-runs=N` — hard cap on iterations (use `-runs=1 <path>` to replay one input)
- `-artifact_prefix=DIR/` — where to write crash/timeout/oom artifacts
- `-print_final_stats=1` — summary at exit

To replay a saved crash through the patched code (single-shot, no mutation):

```bash
.venv/bin/python tests/fuzz/atheris_verify_manifest.py \
    -runs=1 \
    tests/fuzz/crashes/manifest/crash-<hash>
```

The pytest suites do not require atheris and run as part of the normal
`pytest tests/fuzz/` collection.

## Crypto-core test-vector coverage

Coverage-guided fuzzing surfaces *unknown* bug classes; pinned test vectors
catch *known* bug classes (RFC-conformance deltas, library-correctness
regressions). The two are complementary — fuzzing alone cannot say "your HKDF is
RFC 5869-conformant" (it has no oracle for "correct"); vectors alone cannot say
"no input class breaks the verifier" (they only cover the vectors). The substrate
carries both.

| File | Vectors | Pass | What it pins |
|---|---|---|---|
| `tests/test_hkdf_rfc5869_vectors.py` | RFC 5869 Appendix A.1/A.2/A.3 (SHA-256) | 13/13 | Hand-rolled `_hkdf_extract` / `_hkdf_expand` byte-equal to the RFC reference PRK + OKM; empty-salt → HashLen-zeros substitution; `derive_event_signature_key` against a hand-computed RFC chain; `_CTX_EVENT` verbatim-literal pin. SHA-1 cases A.4/A.5/A.6 omitted (substrate is SHA-256-only). |
| `tests/test_wycheproof_ed25519.py` | Wycheproof Ed25519 (`testvectors_v1/ed25519_test.json` @ commit `e0df04e0`) | 278/278 | Layer 1 pyca/cryptography primitive oracle (tripwire — if any "valid" fails or any "invalid" verifies, the library is broken); Layer 2 substrate envelope-consumer rejection — "invalid" vectors wrapped into both `verify_emergency_offline_root_signature` and `verify_cross_host_authenticator_cose` envelopes, all rejected; fresh-key round-trip smoke for both envelope paths. |

## What is NOT covered

Honest scope limits of the fuzz + vector cascade:

- **Single-host edge key-derivation soundness** when `sender_host == receiver_host`.
- **Cross-bundle nonce / `challenge_token` uniqueness enforcement** — there is no
  current cross-bundle check; if a nonce is reused, the chosen-message window opens.
- **Side-channel resistance.** Python is hard to constant-time; some error paths
  branch on key material. Not audited here.
- **Formal cryptographic protocol verification.** The composition of
  cross-host-receipt + counter-chain + Merkle-root has no machine-checked proof
  (would require a Tamarin / ProVerif effort).
- **External cryptographer review.** No in-house substitute for this.
