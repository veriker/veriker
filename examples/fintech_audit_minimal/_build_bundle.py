"""_build_bundle.py — build a deterministic fintech_audit_minimal audit bundle.

Synthesizes 3 transactions and 2 policy rules, evaluates each rule against each
transaction, and emits a standards-compliant manifest with policy-verdict payloads
and ByteOffsetFragment anchors over matched condition fields.

Story: "A bank's model claims transaction T conforms to policy P. The audit-bundle
contains the transaction record + policy rules. The verifier re-runs the rule
predicate over the bundled transaction and asserts the model's verdict is
reproducible byte-for-byte from inputs."

Brazilian regulatory framing (verified 2026-05-29 — citations in the deck's
inter_regulatory_backbone_2026-05-29.md): the rules model a bank's internal
transaction-screening controls. The restricted-jurisdiction rule reflects
Lei nº 13.810/2019, under which Brazil enforces UN Security Council (CSNU)
sanctions; the large-transaction rule is an illustrative internal review
threshold (the bank's own number, not a statutory figure). Amounts are in BRL.

Usage (from v-kernel-audit-bundle root):
    python examples/fintech_audit_minimal/_build_bundle.py --out-dir /tmp/fintech_bundle

Outputs:
  <out-dir>/transactions/<txn_id>.json   (one file per transaction)
  <out-dir>/policies/<rule_id>.json      (one file per policy rule)
  <out-dir>/payload/policy_verdicts.json (verdict list)
  <out-dir>/manifest.json

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.emitter import BundleContent, write_bundle
from audit_bundle.fragments.fragment_id import ByteOffsetFragment, fragment_to_canonical_dict

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "fintech-audit-minimal-rc"
_CREATED_AT = "2026-05-10T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
    "policy_rule_re_derivation",
]

# ---------------------------------------------------------------------------
# Synthetic fixtures — 3 transactions, 2 policy rules
# ---------------------------------------------------------------------------

# Each transaction is a flat JSON with exactly these fields (order matters for
# deterministic byte-offset computation — we use json.dumps with sort_keys=True
# then encode UTF-8 to get reproducible offsets).

_TRANSACTIONS = [
    {
        "txn_id": "txn-001",
        "amount_brl": 95000.00,
        "counterparty_id": "cpty-alpha",
        "counterparty_country": "US",
        "instrument_type": "equity",
        "timestamp": "2026-05-10T08:30:00Z",
    },
    {
        "txn_id": "txn-002",
        "amount_brl": 12500.00,
        "counterparty_id": "cpty-beta",
        "counterparty_country": "IR",
        "instrument_type": "bond",
        "timestamp": "2026-05-10T09:15:00Z",
    },
    {
        "txn_id": "txn-003",
        "amount_brl": 500.00,
        "counterparty_id": "cpty-gamma",
        "counterparty_country": "GB",
        "instrument_type": "equity",
        "timestamp": "2026-05-10T10:00:00Z",
    },
]

# Each policy rule: conditions are AND-ed; verdict_if_match is the verdict when
# all conditions hold.  Each condition: {field, op, value} where op is one of
# {gt, lt, eq, ne, in, not_in}.

_POLICIES = [
    {
        "rule_id": "rule-large-tx",
        "name": "Large Transaction Threshold",
        "conditions": [
            {"field": "amount_brl", "op": "gt", "value": 50000},
        ],
        "verdict_if_match": "REVIEW_REQUIRED",
    },
    {
        "rule_id": "rule-restricted-jurisdiction",
        "name": "Restricted Jurisdiction (UN/CSNU sanctions; Lei 13.810/2019)",
        "conditions": [
            {"field": "counterparty_country", "op": "in", "value": ["IR", "KP"]},
        ],
        "verdict_if_match": "BLOCKED",
    },
]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(obj: dict) -> bytes:
    """Deterministic JSON bytes: sort_keys, compact separators, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _eval_condition(txn: dict, cond: dict) -> bool:
    """Evaluate a single condition against a transaction record."""
    field = cond["field"]
    op = cond["op"]
    threshold = cond["value"]
    actual = txn.get(field)
    if actual is None:
        return False
    if op == "gt":
        return float(actual) > float(threshold)
    if op == "lt":
        return float(actual) < float(threshold)
    if op == "eq":
        return actual == threshold
    if op == "ne":
        return actual != threshold
    if op == "in":
        return actual in threshold
    if op == "not_in":
        return actual not in threshold
    raise ValueError(f"Unknown op: {op!r}")


def _eval_policy(txn: dict, policy: dict) -> tuple[bool, list[str]]:
    """Return (matched: bool, matched_condition_fields: list[str])."""
    matched_fields: list[str] = []
    for cond in policy["conditions"]:
        if _eval_condition(txn, cond):
            matched_fields.append(cond["field"])
        else:
            # All conditions must match (AND semantics)
            return False, []
    return True, matched_fields


def _field_byte_span(txn_bytes: bytes, field_name: str) -> tuple[int, int]:
    """Return the [start, end) byte offsets of the field *value* in txn_bytes.

    The canonical JSON is sorted-key compact, so field keys appear in
    alphabetical order.  We locate the value span by finding the key string
    followed by ':' then the value up to the next ',' or '}'.
    """
    import re

    # Match the value for this field: `"field_name":VALUE` where VALUE is a
    # JSON number, string, or array (simplified for flat records).
    pattern = re.compile(
        rb'"' + re.escape(field_name.encode("utf-8")) + rb'"\s*:\s*'
        + rb'([^,}]+)'
    )
    m = pattern.search(txn_bytes)
    if m is None:
        raise ValueError(f"Field {field_name!r} not found in canonical JSON bytes")
    # Group 1 is the raw value bytes (without trailing comma/brace)
    val_start = m.start(1)
    val_end = m.end(1)
    # Strip trailing whitespace
    while val_end > val_start and txn_bytes[val_end - 1:val_end] in (b" ", b"\t", b"\n"):
        val_end -= 1
    return val_start, val_end


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    files_bytes: dict[str, bytes] = {}
    fragment_anchors: dict[str, dict] = {}

    # Build transaction file bytes and CID map
    txn_cids: dict[str, str] = {}  # txn_id -> "sha256:<hex>"
    for txn in _TRANSACTIONS:
        txn_bytes = _canonical_json(txn)
        sha = _sha256(txn_bytes)
        rel = f"transactions/{txn['txn_id']}.json"
        files_bytes[rel] = txn_bytes
        txn_cids[txn["txn_id"]] = f"sha256:{sha}"

    # Build policy file bytes
    policy_cids: dict[str, str] = {}  # rule_id -> "sha256:<hex>"
    for policy in _POLICIES:
        policy_bytes = _canonical_json(policy)
        sha = _sha256(policy_bytes)
        rel = f"policies/{policy['rule_id']}.json"
        files_bytes[rel] = policy_bytes
        policy_cids[policy["rule_id"]] = f"sha256:{sha}"

    # Evaluate all (txn, policy) pairs and build verdict list + fragment anchors
    verdicts: list[dict] = []
    for txn in _TRANSACTIONS:
        txn_id = txn["txn_id"]
        txn_bytes = _canonical_json(txn)
        source_cid = txn_cids[txn_id]

        for policy in _POLICIES:
            rule_id = policy["rule_id"]
            matched, matched_fields = _eval_policy(txn, policy)

            verdict_value = policy["verdict_if_match"] if matched else "NOT_APPLICABLE"
            verdict_record = {
                "txn_id": txn_id,
                "rule_id": rule_id,
                "matched_conditions": matched_fields,
                "verdict": verdict_value,
            }
            verdicts.append(verdict_record)

            # Add ByteOffsetFragment anchors for each matched condition field
            for field_name in matched_fields:
                try:
                    start, end = _field_byte_span(txn_bytes, field_name)
                except ValueError:
                    continue
                frag = ByteOffsetFragment(
                    source_cid=source_cid,
                    start=start,
                    end=end,
                )
                anchor_key = f"{txn_id}-{rule_id}-{field_name}"
                fragment_anchors[anchor_key] = fragment_to_canonical_dict(frag)

    # Build verdict payload bytes
    verdicts_bytes = json.dumps(verdicts, indent=2, sort_keys=True).encode("utf-8")
    files_bytes["payload/policy_verdicts.json"] = verdicts_bytes

    # Validate: at least one verdict must be a match and at least one NOT_APPLICABLE
    verdict_values = [v["verdict"] for v in verdicts]
    assert any(v != "NOT_APPLICABLE" for v in verdict_values), (
        "Expected at least one matched verdict; check fixture design"
    )
    assert any(v == "NOT_APPLICABLE" for v in verdict_values), (
        "Expected at least one NOT_APPLICABLE verdict; check fixture design"
    )

    # --- Emit via the reference-emitter SDK (scaffold + digests + manifest). ---
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files=files_bytes,
        typed_checks=_TYPED_CHECKS,
        extra_manifest_fields={
            "fragment_anchors": fragment_anchors,
        },
    )
    write_bundle(out_dir, content)

    matched_count = sum(1 for v in verdicts if v["verdict"] != "NOT_APPLICABLE")
    print(f"Bundle written to {out_dir}")
    print(f"  transactions     : {len(_TRANSACTIONS)}")
    print(f"  policies         : {len(_POLICIES)}")
    print(f"  verdicts         : {len(verdicts)} ({matched_count} matched, "
          f"{len(verdicts) - matched_count} not-applicable)")
    print(f"  fragment anchors : {len(fragment_anchors)}")
    print(f"  manifest files   : {len(files_bytes)}")
    print(f"  manifest         : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic fintech_audit_minimal audit bundle"
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        type=Path,
        help="Destination directory (created if absent)",
    )
    args = parser.parse_args()
    try:
        build(args.out_dir.resolve())
    except AssertionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
