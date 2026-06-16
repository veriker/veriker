# secops_alert_minimal — V-Kernel Audit-Bundle Pilot: AI Security Alert Classification

Domain: SOC / AI-security alert classification.

**The story:** An AI security model receives a raw log line from a SIEM and
classifies it as `TRUE_POSITIVE`, `SUSPICIOUS`, or `FALSE_POSITIVE` by running
a rule set of regex patterns with weighted severity scores. The audit bundle
captures the log line, the matched rule definitions, the dispatch record showing
which rule-feed the model consulted, and the final classification payload. The
verifier re-runs the exact rule set against the bundled log line and asserts the
classification is reproducible byte-for-byte — without calling any external model.

## Files

```
secops_alert_minimal/
  _build_bundle.py                    Builder — writes inputs, payload, manifest
  verify.py                           Verifier — registers plugins, prints PASS/FAIL
  alert_classification_re_derivation.py  Stdlib-only re-derivation pack (contract C5)
  AlertClassificationReDerivationCheck.py  TypedCheck plugin wrapping the pack
  README.md                           This file
  tests/__init__.py
  tests/test_secops_alert_minimal.py  Pytest suite (happy-path + tamper + dispatch tests)
```

## Quick-start

```bash
cd veriker

# Build
python examples/secops_alert_minimal/_build_bundle.py --out-dir /tmp/secops_bundle

# Verify
python examples/secops_alert_minimal/verify.py --bundle-dir /tmp/secops_bundle
# → PASS

# Pytest
python -m pytest examples/secops_alert_minimal/tests/test_secops_alert_minimal.py -v
```

## Bundle structure

```
<bundle>/
  inputs/alert_log.txt              Raw SIEM log lines (alert-001 = line 0)
  inputs/rule_set.json              Rule definitions (rule_id, regex, weight)
  payload/alert_classification.json Classification payload
  payload/dispatch_records.jsonl    Human-inspection copy (not fed to verifier)
  manifest.json                     Canonical manifest with dispatch_records in-manifest
```

## Re-derivation primitive

Rule-replay: `alert_classification_re_derivation.py` reads the bundled
`inputs/alert_log.txt` and `inputs/rule_set.json`, re-runs every regex against
the raw log line, recomputes `aggregate_score` using committed weights and
thresholds, and asserts byte-for-byte equality against
`payload/alert_classification.json`. No external model is called.

Score thresholds (committed in both build and re-derivation pack):
- `aggregate_score >= 7` → `TRUE_POSITIVE`
- `aggregate_score >= 3` → `SUSPICIOUS`
- `aggregate_score < 3`  → `FALSE_POSITIVE`

## Dispatch records story (C15)

Two dispatch records are written into `manifest.json["dispatch_records"]`
(not a sidecar — the verifier reads them directly from the manifest):

| # | op.kind        | predicates            | meaning                             |
|---|----------------|-----------------------|-------------------------------------|
| 0 | `RETRIEVAL`    | matched rule_ids list | Rule-feed fetch — which rules fired |
| 1 | `ALERT_CLASSIFY` | `[final_label]`     | Model classification op outcome     |

`DispatchRecordWellformedCheck` is registered in `verify.py` with a custom
`op_kinds_admitted=frozenset({"ALERT_CLASSIFY", "RETRIEVAL", "COMPUTE"})`.
`ALERT_CLASSIFY` is a new domain-specific op kind not in the substrate default
enum — passing a custom frozenset is the extension mechanism (per
`dispatch_record_wellformed.py` constructor docs and SKILL.md §5).

The re-derivation pack (`alert_classification_re_derivation.py`) additionally
cross-checks `dispatch_records[0].predicates == matched_rule_ids` and
`dispatch_records[1].predicates == [final_label]`, tying the dispatch
records to the re-derivation outcome.

## Tamper-flow demo

```bash
# After building the bundle:
python -c "
import json, hashlib
from pathlib import Path
p = Path('/tmp/secops_bundle/payload/alert_classification.json')
d = json.loads(p.read_text())
d['final_label'] = 'FALSE_POSITIVE'
p.write_text(json.dumps(d, indent=2))
# Update manifest SHA so file-integrity passes — isolates the re-derivation check
m = Path('/tmp/secops_bundle/manifest.json')
mdata = json.loads(m.read_text())
mdata['files']['payload/alert_classification.json'] = hashlib.sha256(p.read_bytes()).hexdigest()
m.write_text(json.dumps(mdata, indent=2))
"
python examples/secops_alert_minimal/verify.py --bundle-dir /tmp/secops_bundle
# → FAIL: [typed_check_plugins:alert_classification_re_derivation] plugin_failed
#         [ALERT_REDER_FAIL] ALERT_REDERIVATION_MISMATCH final_label mismatch: ...
```

## Fragments

`ByteOffsetFragment` anchors are emitted for each matched-rule span within the
alert log file bytes. Each anchor name is `alert-001-match-<rule_id_lower>`.
These fragments record exactly which byte range of the raw log line triggered
each rule — enabling downstream auditors to point at the specific evidence.

## Extension surfaces exercised

- `ByteOffsetFragment` (standard well-known kind)
- `DispatchRecordWellformedCheck(op_kinds_admitted=...)` with domain-specific
  `ALERT_CLASSIFY` op kind (constructor-pluggable extension per C15 contract)
