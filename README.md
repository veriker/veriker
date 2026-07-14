<div align="center">

# Veriker

**Recompute the answer — don't trust the claim.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Verify](https://img.shields.io/badge/verify-offline_·_stdlib--only-success.svg)](#-how-it-works)
[![Verdict](https://img.shields.io/badge/verdict-OK_·_REJECT_·_ERROR-informational.svg)](#-the-verdict-ok--reject--error)

**[Quick start](#-quick-start)** · **[How it works](#-how-it-works)** · **[The verdict](#-the-verdict-ok--reject--error)** · **[Producing bundles](#-producing-bundles--the-emitter-sdk)** · **[Scope and honesty](#-scope-and-honesty)**

A composable, domain-agnostic verifier for **re-derivable, attested artifacts**.
You hand it a self-contained *audit bundle* — a manifest, the input snapshots, and
a re-derivation rule — and it **independently recomputes the declared output and
checks it against what was committed**, returning a structured verdict made of many
small checks instead of one opaque pass/fail.

</div>

---

```console
$ python examples/citation_integrity_minimal/build_bundle.py --out-dir /tmp/citation_bundle
$ veriker --bundle-dir /tmp/citation_bundle
PASS  file_integrity
PASS  spec_sha_pinning
PASS  cross_refs
PASS  plugin:spec_sha_pin
PASS  plugin:file_integrity_many_small
PASS  plugin:fragment_attestation
PASS  plugin:coverage_sum_invariant
PASS  plugin:source_attributes_consistency
PASS  plugin:three_set_sum_invariant
PASS  plugin:dispatch_record_wellformed
PASS  plugin:stamp_lattice
PASS  plugin:refinement_discharge

PASS  (12 check(s) passed)
$ echo $?
0

$ echo ' (tampered)' >> /tmp/citation_bundle/snapshots/src-welfare-001.txt   # one byte moves

$ veriker --bundle-dir /tmp/citation_bundle
FAIL  file_integrity                    [bad_file_sha] 'snapshots/src-welfare-001.txt':
      manifest_sha='89b92b23…' computed_sha='48fa2a73…'
…
FAIL  (3 failures across 12 check(s))
$ echo $?
1
```

> Real output from the **citation-integrity** pilot (long digests elided for width).
> The source a citation claims to quote changed by one byte — two independent
> integrity checks catch it, the verdict is `REJECT`, exit `1`. A verdict is
> **recomputed, never asserted**: each line is a property the verifier re-derived
> itself, and a cited source can never silently drift from the answer that stands
> on it.

---

## 💡 Concept

> [!NOTE]
> **A hash proves bytes didn't change. It does not prove the answer.** An output is
> only trustworthy if it is the correct result of running a *declared* computation
> over *declared* inputs — and a checksum tells you nothing when something drifts.
> An audit bundle commits *the inputs, the rule, and the claimed output*; this
> verifier **re-derives the output and compares**, offline, with nothing but the
> bundle directory.

Tampering with an input, swapping the rule, or shipping a weaker specification all
**fail closed** — and the verifier distinguishes "the artifact is bad" from "I
couldn't conclude," so a green result can never be faked by crashing the checker.

This is the **open tier** (Apache-2.0): the verifier, the bundle format, the
substrate, the producer SDK, and a set of generic domain pilots. It stands
alone — it imports no closed-tier code, and the core verify path needs **no
network and no third-party packages** at audit time (stdlib only).

---

## ✨ Features

| | |
|---|---|
| 🔁 **Recompute, don't attest** | When a bundle declares outputs, the verifier re-derives the representative output with a **verifier-side primitive** and compares it to the committed value under a pinned comparator (`exact`, `scalar_epsilon`, `set`, `text_normalized`, `structured`). |
| 🧾 **Self-contained bundles** | A bundle is a directory — manifest + SHA-pinned specs + input snapshots + claimed outputs. The verifier reads **no outside state**. |
| 🚦 **Tri-state verdict** | `OK` (0) / `REJECT` (1) / `ERROR` (2). "The artifact is bad" is never conflated with "the verifier couldn't conclude" — and neither is ever silently an `OK`. |
| 🔬 **Localized failures** | Every property is its own check with its own reason — a failure points at exactly what broke, not at one opaque boolean. |
| 🐍 **Offline, stdlib-only verify** | The core verify path makes no network calls and imports no third-party packages at audit time. |
| 🔒 **Untrusted-bundle posture** | The core path **never executes bundle-supplied code**. Running a bundle's own re-derivation pack is an explicit, flagged opt-in for trusted hosts only. |
| 🧰 **Producer SDK** | `audit_bundle.emitter` assembles verifier-conformant bundles (canonical, sorted, digest-matched manifests) with pluggable timestamp / causal-chain / attestation seams. |
| 🧪 **Pilot gallery** | Self-contained example domains — text extraction, sensor fusion, lockfile resolution, graph traversal, deterministic builds, tabular SQL aggregates, ML inference, streaming windows, and more — each with its own tests. |

---

## 🚀 Quick start

Install the verifier from PyPI:

```bash
pip install veriker          # the offline bundle verifier — Python ≥ 3.11
```

That gives you the `veriker` command (`veriker --bundle-dir <dir>`, equivalently
`python -m veriker`). To build and run the example pilots below — or to develop —
clone the repo and install from source instead:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"          # Python ≥ 3.11; includes the pilots under examples/
```

Build a pilot — here, a **citation-integrity** bundle that proves an AI/RAG
answer actually quotes its cited sources (no LLM in the loop: the verifier
re-derives every cited span from the frozen source snapshots and checks each
quote against its source under a deterministic, versioned text normalization —
case-, whitespace-, and punctuation-insensitive, not byte-exact) — and verify
it:

```bash
python examples/citation_integrity_minimal/build_bundle.py --out-dir /tmp/citation_bundle
veriker --bundle-dir /tmp/citation_bundle    # exit 0, 12 checks PASS
```

Then tamper with any committed snapshot and re-run `verify` — it fails closed
with exit `1`, as in the demo above.

<details>
<summary><b>More pilots, more shapes</b> — every <code>examples/</code> entry is one computation shape</summary>

Each pilot under `examples/` is a self-contained bundle builder plus its own
`tests/`, demonstrating one computation shape end-to-end: text extraction,
sensor fusion, lockfile resolution, graph traversal, seed-pinned release,
deterministic build & compilation, raster aggregation, tabular SQL aggregates,
integer- and float-ML inference, audio segmentation, event-time streaming
windows, and more. Each pilot's README states the exact property it
demonstrates — and the explicit limits of that claim.

```bash
ls examples/
python examples/<name>/build_bundle.py --help
```

</details>

---

## 🔍 How it works

A **bundle** is a directory the verifier can read with no outside state:

```
bundle/
├── manifest.json     # files + SHA-256 digests, spec pins, declared outputs, typed checks
├── spec/             # the SHA-pinned specification(s) the manifest commits to
├── <inputs>/         # the committed input snapshots (corpus, lockfile, traces, …)
└── outputs/          # the claimed output value(s) the verifier will re-derive and compare
```

The verifier runs **built-in steps** (file integrity, spec-SHA pinning,
cross-references) plus a set of **typed-check plugins**, and — when the bundle
declares outputs — **re-derivation dispatch**: it recomputes the representative
output with a verifier-side primitive and compares it to the committed value under
a pinned comparator (`exact`, `scalar_epsilon`, `set`, `text_normalized`,
`structured`). Every check is reported on its own line so a failure points at
exactly which property broke.

**How is this different from a checksum?** A checksum answers "are these the same
bytes?" This answers "is this output the deterministic result of *this* rule over
*these* inputs, and does every committed invariant still hold?" — and it localizes
the answer to individual checks.

---

## 🚦 The verdict: OK / REJECT / ERROR

The verifier is **tri-state**, and the distinction is load-bearing:

| Verdict  | Exit | Meaning |
|----------|:----:|---------|
| `OK`     | `0`  | every gating check passed. |
| `REJECT` | `1`  | the *artifact* failed a check — tampering, drift, a forged field. |
| `ERROR`  | `2`  | the *verifier* could not conclude — e.g. a bundle **claims** a re-derivation but the pack was not executed, or an external dependency is absent. **Never silently an `OK`.** |

There is no `ERROR → retry → accept` path: both `REJECT` and `ERROR` are non-zero
(not certified). New automation can split "artifact is bad" (`1`) from "verifier
couldn't conclude / file a bug" (`2`); old scripts keying on `exit != 0` stay
correct. `REJECT` is about the input; `ERROR` is about the verifier — so a
crafted verifier-crashing input can't be laundered into a fake `REJECT`.

Automation that wants more than the exit code can pass
`--verdict-out verdict.json`: the verifier writes the full verdict face as JSON
on **every** exit path — state and exit code, machine-stable reason codes, which
validation layers ran, honest disclosures a green verdict still carries, and the
SHA-256 of the manifest it judged. It is an **unsigned operational artifact**
(the file says so in its `note` field): trust comes from deterministically
re-running the verifier on the bundle, never from the file itself.

> [!WARNING]
> **Untrusted bundles:** the core path never executes bundle-supplied code.
> Running a bundle's own `re_derive/*_pack.py` is arbitrary local code execution
> and is gated behind `--unsafe-run-bundle-pack` (trusted/disposable hosts only).
> The safe alternative — spec-pinned dispatch — runs re-derivation with
> verifier-side primitives and is described below.

---

## 🧰 Producing bundles — the emitter SDK

The producer side is the open SDK at **`audit_bundle.emitter`**. It assembles a
verifier-conformant bundle (canonical, sorted, newline-terminated manifest with
matching digests) and exposes pluggable hook seams:

```python
from audit_bundle.emitter import (
    BundleContent, write_bundle, assemble_manifest,
    TimestampProvider, CausalChainEmitter, AttestationProvider,
    StaticTimestampProvider, NullCausalChainEmitter, NullAttestationProvider,
)
```

The open defaults (`Static*` / `Null*`) emit a clean baseline bundle with no
network calls. The `*Provider` interfaces are the extension points where richer
timestamp / causal-chain / attestation implementations plug in. Every pilot under
`examples/` builds its bundle this way — see any pilot's `build_bundle.py` (some
are named `_build_bundle.py`) for a worked example, and
`tests/test_emitter_sdk.py` for the conformance contract.

### Spec-pinned dispatch (how pilots self-verify)

Each pilot proves its published output is the deterministic recompute of its
committed input under an *auditor-pinned* comparator. The auditor binding is the
pilot's committed `spec_pinned/<domain>.spec.json` — which primitive recomputes
the representative output, and the comparator kind. The auditor's anchor is
derived from the committed spec **bytes**, not from the bundle's own copy, so a
bundle that ships a weaker spec yields a digest the anchor does not list and
verification fails closed.

<details>
<summary><b>Two wiring styles for this anchored dispatch</b> in <code>examples/</code></summary>

You will see two styles, distinguished by whether a `spec_pinned_check.py` is
present:

- **Current** — the anchored dispatch is consumed directly in the pilot's own
  `verify.py` via a `SpecAnchor` and exercised by its `tests/`; there is no
  standalone driver. E.g. `caselaw_citation_gate_minimal`, `iso42001_vnv_minimal`.
- **Legacy** — the anchored dispatch is a standalone `spec_pinned_check.py`
  build→verify driver alongside the pilot's test. E.g. `tabular_minimal`,
  `raster_minimal`. Here the pilot's own `verify.py` is a **separate entry point**
  that runs the pilot's re-derivation check, not the `SpecAnchor` dispatch. Either
  way the acceptance criterion is resolved on the **auditor's** side — an exact
  recompute match, or the tolerance pinned in the committed
  `spec_pinned/<domain>.spec.json` — never a producer-asserted value.

New pilots should follow the **Current** style.

</details>

---

## 📁 Repository layout

| Path | What |
|------|------|
| `cli/` | Command-line tools: `verify` (the **bundle** verifier — answers "is this bundle internally valid?") and `host_digest_verify` (the **verifier-identity** check, wrapping `cosign` / `crane` to bind a running container's image digest to the TUF-fetched release digest). For ordinary local bundle verification `host_digest_verify` is optional; for a **public-release ceremony it is the required verifier-identity trust mechanism** and its result must be run and retained — `verify()` cannot answer the identity question itself. **Pre-ceremony:** the C18 TUF roots are still synthetic and no hardware-signed release has been cut, so the full TUF-gated identity flow is **not yet live** (it becomes runnable at the C18 key ceremony + first signed release). See [SECURITY.md](SECURITY.md) → "Verifier-identity trust boundary (C18)". |
| `audit_bundle/` | The substrate — bundle format and manifest, the verifier, the producer `emitter` SDK, typed-check plugins, extensions, discharge, fragments, and coverage. |
| `coverage/` | Closed-world coverage plugin (sum-invariant grading). |
| `examples/` | Generic domain pilots — each a self-contained bundle plus its own `tests/`. |
| `tests/` | The open verifier + substrate test suite. |
| [`MANIFEST_SCHEMA.md`](MANIFEST_SCHEMA.md) | The bundle manifest schema. |
| [`VERIFIER_CONTRACT.md`](VERIFIER_CONTRACT.md) | The normative offline-verifier contract — every clause indexed to the test that enforces it. |

## 🧪 Run the tests

```bash
pip install -e ".[dev]"
pytest                          # the open verifier + substrate suite
pytest examples/<name>/tests/   # a single pilot's suite (run per-example)
```

Each pilot under `examples/` ships its own `tests/` package and is invoked
separately — the suites are isolated by design.

---

## 🧭 Scope and honesty

Every pilot's data is **synthetic**. A pilot demonstrates that the substrate can
*re-derive* a declared output and detect tampering or drift against committed
inputs — it is **evidence for a verification property, never a claim that a real
deployment is "compliant"** with any named standard. The check proves the value is
the deterministic output of the *committed* computation over the *committed* input
under the auditor's comparator; it is **not** a claim that the computation or the
input are themselves correct, and a pilot's self-check re-runs the producer's own
re-derivation pack (a round-trip), not an independent re-implementation. Read each
pilot's README for the exact property it demonstrates and the explicit limits of
that claim.

The verifier's own guarantees are held to the same standard:
[`VERIFIER_CONTRACT.md`](VERIFIER_CONTRACT.md) states them as a normative
contract — offline, stdlib-only import boundary, structural-only scope,
tri-state verdict, no silent upgrade of unevaluated evidence — and indexes
every clause to the test that enforces it. The stdlib-only claim itself is
ratcheted: the test suite imports the verifier and re-verifies bundles under
an import hook that blocks every third-party package.

---

## 🔒 Security · Contributing · License

- **Security** — see [SECURITY.md](SECURITY.md) to report a vulnerability.
- **Contributing** — issues and pull requests are welcome; see
  [CONTRIBUTING.md](CONTRIBUTING.md) (we use the DCO, not a CLA). New pilots
  follow the *Current* spec-pinned wiring above; run `pytest` before submitting.
- **Governance & trademark** — [GOVERNANCE.md](GOVERNANCE.md),
  [TRADEMARK.md](TRADEMARK.md), and our [no-relicense pledge](NO-RELICENSE.md).
- **License** — Apache License 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE).

---

Veriker is built and maintained by the team at Nexi Technologies, Inc. We also
build [NEXIVERIFY](https://nexiverify.com), a commercial audit-trail product for
regulated teams. Veriker is and remains free and open under Apache-2.0 — see our
[no-relicense pledge](NO-RELICENSE.md).

---

<div align="center">

**Recompute the answer — don't trust the claim.**

Apache-2.0 · offline verify · stdlib-only at audit time

</div>
