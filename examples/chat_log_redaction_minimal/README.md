# chat_log_redaction_minimal

V-Kernel S0 audit-bundle pilot — privacy / unstructured-chat PII redaction domain.

Demonstrates the audit-bundle integrator on a multi-turn chat transcript:
a deterministic regex + entity-dictionary redaction policy scans the transcript,
produces byte-offset spans `(start_byte, end_byte, entity_kind)`, builds a
redacted output, and records `redacted_output_sha`. An independent verifier
re-runs the identical scan and asserts the span list and SHA match exactly.

Fragment kind exercised: `ByteOffsetFragment` — one fragment per redacted span
(half-open `[start, end)` byte range in the UTF-8 transcript blob).

---

## Quick-start

```bash
# From the v-kernel-audit-bundle root:
cd v-kernel-audit-bundle

# 1. Build into a fresh directory
python examples/chat_log_redaction_minimal/_build_bundle.py --out-dir /tmp/chat_bundle

# 2. Verify
python examples/chat_log_redaction_minimal/verify.py --bundle-dir /tmp/chat_bundle
# Expected output: PASS

# 3. Or use the substrate top-level CLI (in-place build)
python examples/chat_log_redaction_minimal/_build_bundle.py  # in-place
python cli/verify.py --bundle-dir examples/chat_log_redaction_minimal/
# Expected: PASS (... check(s) passed)

# 4. Run the pilot pytest suite
python -m pytest tests/test_chat_log_redaction_minimal.py -v
```

---

## Tamper-flow demo

Two failure modes are exercised by the test suite:

### (a) Edit one byte in transcript — caught by FileIntegrityManySmall

```bash
# After a clean build to /tmp/chat_bundle:
python -c "
p = open('/tmp/chat_bundle/inputs/transcript.txt', 'rb').read()
open('/tmp/chat_bundle/inputs/transcript.txt', 'wb').write(p[:10] + b'X' + p[11:])
"
python examples/chat_log_redaction_minimal/verify.py --bundle-dir /tmp/chat_bundle
# FAIL: [file_integrity_many_small] BAD_FILE_SHA: inputs/transcript.txt ...
```

### (b) Modify redaction_policy.json — re-derivation produces different span list

```bash
# Re-build cleanly first, then swap the EMAIL pattern to something that matches nothing:
python examples/chat_log_redaction_minimal/_build_bundle.py --out-dir /tmp/chat_bundle
python -c "
import json, hashlib
p = '/tmp/chat_bundle/inputs/redaction_policy.json'
policy = json.load(open(p))
policy['regex_patterns']['EMAIL'] = r'NOMATCH'
new_bytes = (json.dumps(policy, sort_keys=True, separators=(',',':')) + '\n').encode()
open(p, 'wb').write(new_bytes)
# Re-align manifest SHA so file_integrity passes:
mp = '/tmp/chat_bundle/manifest.json'
m = json.load(open(mp))
m['files']['inputs/redaction_policy.json'] = hashlib.sha256(new_bytes).hexdigest()
open(mp, 'w').write(json.dumps(m, indent=2, sort_keys=True))
"
python examples/chat_log_redaction_minimal/verify.py --bundle-dir /tmp/chat_bundle
# FAIL: re-derivation mismatch — span count differs because EMAIL matches are missing
```

---

## File layout

```
chat_log_redaction_minimal/
  _build_bundle.py                    synthesize transcript + policy; run redaction; write bundle
  verify.py                           pilot-local verifier (registers 3 plugins)
  ChatLogRedactionReDerivationCheck.py  TypedCheck plugin wrapping the stdlib pack
  README.md                           this file
  inputs/
    transcript.txt                    raw synthetic multi-turn chat (UTF-8)
    redaction_policy.json             {regex_patterns, entity_dict}
  payload/
    redaction_result.json             {spans: [...], redacted_output_sha: "..."}
  re_derive/
    chat_log_redaction_pack.py        stdlib-only re-derivation pack (AB4 compliant)
```

---

## Design notes

- **Re-derivation primitive**: re-scan transcript bytes with regex patterns + entity-dict
  (same algorithm, same order), resolve overlaps with greedy-cover rule, compute
  redacted output SHA. Exit 0 iff spans and SHA match bundled payload exactly.
- **AB4 compliance**: `re_derive/chat_log_redaction_pack.py` is stdlib-only; zero
  `audit_bundle` imports. Auditor can run it without installing any dependencies.
- **Salvage note**: this pilot was first attempted by the nexi-pilot-drainer 3 times
  (3 × OpenRouter dispatches, $6.25 burned). Rebuilt via Claude Code subagent on
  subscription burn using `healthcare_diagnosis_minimal` as skeleton reference.
