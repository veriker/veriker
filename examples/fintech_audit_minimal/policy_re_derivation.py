#!/usr/bin/env python3
"""policy_re_derivation.py — stdlib re-derivation pack for fintech policy-audit domain.

Re-evaluates each policy verdict in payload/policy_verdicts.json by:
  1. Loading the transaction record from transactions/<txn_id>.json
  2. Loading the policy rule from policies/<rule_id>.json
  3. Re-running every condition predicate over the transaction fields
  4. Asserting that the re-derived verdict and matched_conditions match the
     bundled values byte-for-byte.

the audit-bundle contract §C6 (domain-agnostic re-derivation substrate) + AB4.
Stdlib only — no v-kernel-audit-bundle imports, no third-party dependencies.

Exit codes:
  0  all verdicts verified (or no payload to verify)
  1  first mismatch found; description written to stderr
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Condition evaluation — mirrors _build_bundle.py (AB4: duplicate-don't-import)
# ---------------------------------------------------------------------------


def _eval_condition(txn: dict, cond: dict) -> bool:
    """Evaluate a single condition dict against transaction dict.

    Supported ops: gt, lt, eq, ne, in, not_in.
    Returns False if the field is absent from the transaction.
    """
    field = cond.get("field")
    op = cond.get("op")
    threshold = cond.get("value")
    if field is None or op is None:
        return False
    # Validate the op BEFORE the tolerant try-block below: a raise from inside
    # it would be swallowed by `except ValueError` and silently become False.
    # Mirrors the producer's fail-closed `raise ValueError("Unknown op: ...")`
    # — an unevaluable policy condition is never treated as evaluated.
    if op not in ("gt", "lt", "eq", "ne", "in", "not_in"):
        raise ValueError(f"Unknown op: {op!r}")
    actual = txn.get(field)
    if actual is None:
        return False
    try:
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
    except (TypeError, ValueError):
        return False
    return False


def _eval_policy(txn: dict, policy: dict) -> tuple[bool, list[str]]:
    """Return (all_matched: bool, matched_fields: list[str]).

    Conditions are AND-ed: if any condition fails, (False, []) is returned.
    On full match, returns (True, list of field names from matched conditions).
    """
    matched_fields: list[str] = []
    for cond in policy.get("conditions", []):
        if _eval_condition(txn, cond):
            matched_fields.append(cond["field"])
        else:
            return False, []
    return True, matched_fields


# ---------------------------------------------------------------------------
# Verdict re-derivation
# ---------------------------------------------------------------------------


def _check_verdict(bundle_dir: Path, rec: dict, idx: int) -> str | None:
    """Re-derive a single verdict record. Returns error string or None on match."""
    txn_id = rec.get("txn_id")
    rule_id = rec.get("rule_id")
    bundled_matched = rec.get("matched_conditions")
    bundled_verdict = rec.get("verdict")

    if any(x is None for x in (txn_id, rule_id, bundled_matched, bundled_verdict)):
        return (
            f"verdict[{idx}]: malformed record — "
            f"missing one of txn_id/rule_id/matched_conditions/verdict"
        )

    # Load transaction
    txn_path = bundle_dir / "transactions" / f"{txn_id}.json"
    if not txn_path.exists():
        return f"verdict[{idx}]: transaction file not found: transactions/{txn_id}.json"
    try:
        txn = json.loads(txn_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return f"verdict[{idx}]: failed to read transactions/{txn_id}.json: {exc}"

    # Load policy
    policy_path = bundle_dir / "policies" / f"{rule_id}.json"
    if not policy_path.exists():
        return f"verdict[{idx}]: policy file not found: policies/{rule_id}.json"
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return f"verdict[{idx}]: failed to read policies/{rule_id}.json: {exc}"

    # Re-derive verdict
    matched, rederived_fields = _eval_policy(txn, policy)
    rederived_verdict = (
        policy.get("verdict_if_match", "MATCH") if matched else "NOT_APPLICABLE"
    )

    # Compare verdict
    if rederived_verdict != bundled_verdict:
        return (
            f"verdict[{idx}]: verdict mismatch for txn_id={txn_id!r} rule_id={rule_id!r}\n"
            f"  bundled  verdict: {bundled_verdict!r}\n"
            f"  rederived verdict: {rederived_verdict!r}"
        )

    # Compare matched_conditions (order-independent: sort both)
    if sorted(rederived_fields) != sorted(bundled_matched):
        return (
            f"verdict[{idx}]: matched_conditions mismatch for "
            f"txn_id={txn_id!r} rule_id={rule_id!r}\n"
            f"  bundled  matched_conditions: {sorted(bundled_matched)!r}\n"
            f"  rederived matched_conditions: {sorted(rederived_fields)!r}"
        )

    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Policy-rule re-derivation check for fintech audit bundles"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    verdicts_path = bundle_dir / "payload" / "policy_verdicts.json"
    if not verdicts_path.exists():
        # Bundle opted out of re-derivation — not a failure
        return 0

    try:
        records: list = json.loads(verdicts_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(
            f"policy_re_derivation: failed to read payload/policy_verdicts.json: {exc}",
            file=sys.stderr,
        )
        return 1

    if not isinstance(records, list):
        print(
            "policy_re_derivation: payload/policy_verdicts.json must be a JSON array",
            file=sys.stderr,
        )
        return 1

    for idx, rec in enumerate(records):
        error = _check_verdict(bundle_dir, rec, idx)
        if error is not None:
            print(error, file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
