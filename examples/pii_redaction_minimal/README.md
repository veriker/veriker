# pii_redaction_minimal — PII Redaction Audit Bundle Pilot

Domain pilot: deterministic re-derivation of PII spans produced by OpenAI Privacy
Filter (Apache 2.0, released 2026-04-22) using a stdlib constrained-Viterbi decode
over a bundled BIOES logits tensor.

**This is a SHAPE pilot (verification-only).** It extends the S0
demonstration table by one new re-derivation shape (constrained-Viterbi over a
classifier output tensor). It does not wire any cross-system integration.

Exercises two V-Kernel extension surfaces:
- `OpaqueFragment(source_cid, kind_tag="pii_span", locator={token_start, token_end})`
  — one fragment anchor per PII span in the redaction output.
- `DispatchRecordWellformedCheck(op_kinds_admitted=frozenset({"REDACT", "COMPUTE"}))`
  — admits the new `REDACT` op kind introduced by this domain pilot.

## Prerequisites

Python 3.10+. No third-party dependencies.
Run all commands from the **v-kernel-audit-bundle root**.

## Quick-start

```bash
# Build
python examples/pii_redaction_minimal/_build_bundle.py --out-dir /tmp/pii_bundle

# Verify
python examples/pii_redaction_minimal/verify.py --bundle-dir /tmp/pii_bundle
# Expected stdout: PASS

# Tests
python -m pytest tests/test_pii_redaction_minimal.py -v
python -m pytest tests/test_fragments.py tests/test_dispatch_record_wellformed.py -q
```

On Windows use a writable temp dir (e.g. `%TEMP%`) if `/tmp` is unavailable:
```powershell
python examples/pii_redaction_minimal/_build_bundle.py --out-dir $env:TEMP\pii_bundle
python examples/pii_redaction_minimal/verify.py --bundle-dir $env:TEMP\pii_bundle
```

## Three TypedCheck plugins

| Plugin | Contract clause |
|---|---|
| `file_integrity_many_small` | §C9 per-file SHA walk |
| `pii_redaction_re_derivation` | §C6 constrained-Viterbi re-derivation |
| `dispatch_record_wellformed` | §C15 op-kind + effect well-formedness |

## Re-derivation primitive

> Given a BIOES logits tensor [seq_len × 33] and a 6-float transition-bias vector,
> constrained-Viterbi decoding deterministically produces the bundled BIOES tag
> sequence and aggregated spans.

The model (OpenAI Privacy Filter, 1.5B/50M-active MoE) is treated as an upstream
black-box. V verifies: given the model output (logits) + the policy (bias vector),
the spans are reproducible without re-running the 1.5B-param model.

## BIOES state space

33 states: 8 categories × 4 BIOES offsets (B=0, I=1, E=2, S=3) + O=32.

Categories (index order): private_person, private_address, private_email,
private_phone, private_url, private_date, account_number, secret.

Transition constraints:
- From O / E_c / S_c: may go to O, any B_c, any S_c
- From B_c: must go to I_c or E_c (same category)
- From I_c: must go to I_c or E_c (same category)

Bias-vector mapping (6 floats, additive log-priors on transition classes):

| Index | Name | Applied on |
|---|---|---|
| 0 | background_persistence | O→O |
| 1 | span_entry | O/E/S → B or S (starting a new span) |
| 2 | span_continuation | B→I, I→I |
| 3 | span_closure | B→E, I→E |
| 4 | boundary_to_boundary | E/S → B/S (end one span, start another) |
| 5 | category_switch_penalty | additional cost when boundary_to_boundary changes category |

## Tamper-flow demo

```bash
python examples/pii_redaction_minimal/_build_bundle.py --out-dir /tmp/pii_bundle

# Flip logits at token 0 so Viterbi picks O instead of the intended B tag
python -c "
import json, hashlib, pathlib
p = pathlib.Path('/tmp/pii_bundle/payload/bioes_logits.json')
obj = json.loads(p.read_text())
for j in range(33): obj['logits'][0][j] = 0.0
obj['logits'][0][32] = 5.0
new_bytes = (json.dumps(obj, indent=2) + '\n').encode()
p.write_bytes(new_bytes)
# Patch manifest SHA so re-derivation failure fires (not SHA mismatch)
mp = pathlib.Path('/tmp/pii_bundle/manifest.json')
m = json.loads(mp.read_text())
m['files']['payload/bioes_logits.json'] = hashlib.sha256(new_bytes).hexdigest()
mp.write_text(json.dumps(m, indent=2, sort_keys=True))
"
python examples/pii_redaction_minimal/verify.py --bundle-dir /tmp/pii_bundle
# Expected: exit 1, stderr contains PII_REDACTION_REDERIVATION_MISMATCH
```

## File layout

```
examples/pii_redaction_minimal/
├── _build_bundle.py                  # builds the deterministic bundle
├── verify.py                         # runs all three TypedCheck plugins
├── PIIRedactionReDerivationCheck.py  # domain plugin (C6 re-derivation)
├── pii_redaction_re_derivation.py    # stdlib constrained-Viterbi pack
├── README.md
└── payload/                          # written by _build_bundle.py into --out-dir
    ├── bioes_logits.json             # seq_len × 33 float logits
    ├── tokens.json                   # tokenization
    ├── redaction_output.json         # spans, redacted_text, bias_vector, HMAC
    └── dispatch_records.jsonl        # human-readable mirror (not loaded by verifier)
```

## Out-of-scope / future-integration notes

This is a **SHAPE pilot only**. The following surfaces are referenced
for future wiring but are NOT implemented here:

- **C26 redaction interface**: reserves the manifest fields for inbound-masking
  and export-redaction (interface reservation; not yet implemented).
  When C26 lands, a future integration variant of this pilot would route the
  redaction verdict through a dispatch/receipt path and surface the receipt
  via the admission layer.

- **§C9.1 append-only file pinning**: the `model_sha` field in
  `payload/redaction_output.json` carries a placeholder SHA. Production wiring
  would pin the actual HuggingFace checkpoint SHA via §C9.1 so the verifier can
  assert the model has not been swapped since the bundle was sealed.

- **mask_inbound v0.4**: a future inbound-masking layer where the
  `redact_inbound` verdict adds HMAC-of-original receipts for tool results.
  The `input_text_hmac` field in this pilot is the same primitive applied to the
  raw input text; a full integration would route that through an
  inbound-masking path.
