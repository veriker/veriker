# content_provenance_minimal — Content Provenance Audit Bundle Pilot

## SCOPE BOUNDARY (read first)

**This proves WHAT a system produced and that the content has NOT been altered since
it was signed by its stated producer.  It is NOT truth-detection and NOT a
disinformation classifier.  A factually FALSE but unaltered, correctly-signed piece
of content PASSES this check — that is by design and out of scope.**

## Honest claim

> A published content artifact carries a producer-signed manifest binding it to its
> producer identity and generation inputs; the verifier re-confirms the artifact's
> bytes match the signed hash and the provenance chain is intact.  Any post-signing
> alteration fails closed.  Synthetic producer key; local-only demo.

## What this demonstrates

This pilot demonstrates **structural re-derivation of content provenance for AI-era
information integrity** — the C2PA-style problem.  A synthetic news-style text
artifact is produced by a synthetic AI writing system, signed with a producer HMAC
key, and wrapped in a provenance manifest declaring the producer identity and
generation inputs.  The audit bundle binds:

- the published content bytes (`artifact/content.txt`)
- the producer-signed provenance manifest (`artifact/provenance.json`)
- the verification payload (`payload/provenance_result.json`:
  content_sha, provenance_sha, producer_id, generation_inputs, producer_hmac)

...such that an independent verifier can:

1. Re-hash `artifact/content.txt` and assert the SHA matches both the payload's
   `content_sha` and the `content_sha` field inside the provenance manifest.
2. Re-compute `HMAC-SHA256(synthetic_key, content_bytes)` and assert it matches
   the `producer_hmac` field in the provenance manifest — detecting any post-signing
   alteration to the content bytes.
3. Assert the provenance chain fields (`producer_id`, `generation_inputs`) are
   intact and match between the payload and the manifest.

**Fail-closed on tamper**: any modification to content bytes, the provenance
manifest, or the payload provenance_result causes a `CONTENT_PROVENANCE_ALTERED`
failure.

## Honest scope and limitations

**Synthetic fixtures only.**  The content text and provenance manifest are
deterministic synthetic constructs generated at build time.  No real AI model was
invoked and no real publisher is involved.

**Does NOT detect factual inaccuracy.**  The check verifies content provenance
(unaltered bytes from the declared producer), not factual truth.  See scope
boundary above.

**Does NOT validate a real C2PA or COSE signature.**  The signing primitive used
here is HMAC-SHA256 with a hardcoded synthetic key — a structural stand-in that
demonstrates the binding pattern without requiring a real public-key infrastructure.
Production deployment would replace this with an ed25519 or ECDSA producer signing
key and a proper trust anchor.

**The synthetic producer key is NOT a secret.**  It is a hardcoded constant in both
`_build_bundle.py` and `content_provenance_re_derivation.py` for reproducibility.
A production system would load the key from a secure store.

**Does NOT bind to a real transparency log.**  The bundle carries no Sigstore Rekor
entries, no SCITT transparency receipts, and no external timestamp anchors.

## False-but-unaltered scope boundary — explicit test

The test suite (`tests/test_content_provenance_minimal.py`) includes a test named
`test_false_content_passes_provenance_check`.  This test:

1. Builds a bundle with the standard (factually fabricated) news article.
2. Runs the verifier.
3. Asserts the result is **PASS** (`result.ok is True`).

This is the correct behavior.  The verifier proves provenance, not truth.  The
article's claim about a battery breakthrough is fabricated, but because the bytes
are unaltered and the producer HMAC is valid, the provenance check passes.  This
is explicitly by design and documents the scope boundary.

## Prerequisites

Python 3.10+.  No third-party dependencies.
Run all commands from the **v-kernel-audit-bundle root**.

## Step 1 — Build the bundle

```bash
python examples/content_provenance_minimal/_build_bundle.py --out-dir /tmp/content_prov_bundle
```

Expected output:

```
Bundle written to /tmp/content_prov_bundle
  content artifact : artifact/content.txt (... bytes)
  content sha256   : <hex>
  producer id      : NexiWriter/1.0-synthetic
  producer hmac    : hmac-sha256:<first 16 chars>...
  provenance       : artifact/provenance.json
  payload          : payload/provenance_result.json
  manifest         : /tmp/content_prov_bundle/manifest.json
```

## Step 2 — Verify

```bash
python examples/content_provenance_minimal/verify.py --bundle-dir /tmp/content_prov_bundle
```

Expected stdout: `PASS — content provenance verified: ...`.  Exit code 0.

Two TypedCheck plugins run in order:

| Plugin                                 | Contract clause                           |
|----------------------------------------|-------------------------------------------|
| `file_integrity_many_small`            | §C9 per-file SHA walk                     |
| `content_provenance_re_derivation`     | §C6 content provenance re-derivation      |

## Step 3 — Tamper-flow demo

Overwrite the content file with garbage bytes:

```bash
printf "TAMPERED_CONTENT" > /tmp/content_prov_bundle/artifact/content.txt
```

Re-run the verifier:

```bash
python examples/content_provenance_minimal/verify.py --bundle-dir /tmp/content_prov_bundle
```

Expected exit code: `1`.  The verifier detects:
- `BAD_FILE_SHA` from `file_integrity_many_small` (content hash no longer matches manifest)
- `CONTENT_PROVENANCE_ALTERED` from `content_provenance_re_derivation` (SHA + HMAC mismatch)

## File layout

```
examples/content_provenance_minimal/
├── _build_bundle.py                        # builds the audit bundle from synthetic fixtures
├── verify.py                               # runs TypedCheck plugins; exits 0 on PASS
├── ContentProvenanceReDerivationCheck.py   # TypedCheck plugin (subprocess wrapper)
├── content_provenance_re_derivation.py     # re-derivation implementation (stdlib only)
├── pilot.json                              # pilot metadata
└── README.md                               # this file

tests/
└── test_content_provenance_minimal.py      # happy-path + tamper + scope-boundary tests
```

## AI-era disinformation context

This pilot supports the "AI-era disinformation" brief slide with an honest claim:
the V-Kernel substrate can prove content provenance (who produced what and that it
is unaltered), which is a necessary but not sufficient condition for information
integrity.  Truth-detection is explicitly out of scope and requires a separate,
domain-specific fact-checking layer.

The provenance layer and fact-checking layers are complementary: provenance proves
"this content came from this system unaltered," fact-checking proves "this claim is
accurate."  Neither subsumes the other.
