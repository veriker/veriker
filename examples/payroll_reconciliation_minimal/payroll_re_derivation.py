#!/usr/bin/env python3
"""payroll_re_derivation.py — stdlib re-derivation pack for the payroll domain.

Re-computes each issued paycheck AND each overpayment/clawback amount from the
pinned pay-rules spec + pinned pay-event inputs, and asserts the bundled
paycheck ledger matches. This is the V-Kernel answer to the central Phoenix
failure documented by the Auditor General: the government could not say *why* a
given paycheck was computed the way it was, and — when clawing back $3.57B in
overpayments — could not reconcile individual pay files or substantiate the
amount owed. Here every cent is re-derivable from spec + inputs.

the audit-bundle contract §C6 (re-derivation pack — domain-agnostic substrate).
AB4: stdlib only — csv, json, argparse, sys, pathlib. No imports from audit_bundle.

Reads:
  spec/pay_rules.json         — pinned pay rules (payroll-rules-v1 schema)
  data/pay_events.csv         — committed per-employee pay events (input snapshot)
  payload/paychecks.json      — bundled paycheck ledger to verify against

For each bundled paycheck:
  1. Re-derive gross/tax/pension/net (integer cents) from rules + the matching
     pay event. Assert each equals the bundled value.
  2. Re-derive clawback_cents = issued_net_cents - net_cents (correct net).
     Assert it equals the bundled clawback_cents. A positive value is owed back
     by the employee (overpayment); negative is owed to the employee.

Exits 0 on full match; 1 with [PAYROLL_REDER_FAIL] <description> on stderr on
the first mismatch.

Usage:
    python payroll_re_derivation.py --bundle-dir /path/to/bundle
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Deterministic integer-cents pay engine (AB4: duplicated, not imported, so the
# verifier re-derives independently of whatever produced the bundle).
# ---------------------------------------------------------------------------


def _rhu(num: int, den: int) -> int:
    """Round half up over non-negative integers: rhu(num, den)."""
    if num < 0:
        raise ValueError(f"_rhu expects non-negative numerator, got {num}")
    return (num + den // 2) // den


def _compute_pay(rules: dict, ev: dict) -> dict:
    """Re-derive a single paycheck (all values in integer cents) from rules + event."""
    classifications: dict = rules["classifications"]
    ppy: int = int(rules["periods_per_year"])
    period_days: int = int(rules["period_days"])
    tax_bps: int = int(rules["tax_rate_bps"])
    pension_bps: int = int(rules["pension_rate_bps"])

    home = ev["home_classification"]
    if home not in classifications:
        raise KeyError(f"home_classification {home!r} not in pinned rules")
    home_annual_cents = int(classifications[home]["annual_salary"]) * 100

    base_cents = _rhu(home_annual_cents, ppy)

    # Acting pay: extra pay for working a higher classification for part of the
    # period. (The acting/retro cases are the ~40% Phoenix could not automate.)
    acting_cls = ev.get("acting_classification") or ""
    acting_days = int(ev.get("acting_days") or 0)
    acting_uplift_cents = 0
    if acting_cls:
        if acting_cls not in classifications:
            raise KeyError(f"acting_classification {acting_cls!r} not in pinned rules")
        acting_annual_cents = int(classifications[acting_cls]["annual_salary"]) * 100
        delta = acting_annual_cents - home_annual_cents
        if delta < 0:
            delta = 0  # acting never reduces pay
        acting_uplift_cents = _rhu(delta * acting_days, ppy * period_days)

    # Retroactive pay: salary-increase delta owed over a number of past periods.
    retro_old = int(ev.get("retro_old_salary") or 0)
    retro_new = int(ev.get("retro_new_salary") or 0)
    retro_periods = int(ev.get("retro_periods") or 0)
    retro_cents = 0
    if retro_periods and retro_new > retro_old:
        retro_delta_cents = (retro_new - retro_old) * 100
        retro_cents = _rhu(retro_delta_cents * retro_periods, ppy)

    gross_cents = base_cents + acting_uplift_cents + retro_cents
    tax_cents = _rhu(gross_cents * tax_bps, 10000)
    pension_cents = _rhu(gross_cents * pension_bps, 10000)
    net_cents = gross_cents - tax_cents - pension_cents

    return {
        "gross_cents": gross_cents,
        "tax_cents": tax_cents,
        "pension_cents": pension_cents,
        "net_cents": net_cents,
    }


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _verify(bundle_dir: Path) -> str | None:
    """Return an error description on mismatch, or None on success."""
    rules_path = bundle_dir / "spec" / "pay_rules.json"
    events_path = bundle_dir / "data" / "pay_events.csv"
    ledger_path = bundle_dir / "payload" / "paychecks.json"

    if not rules_path.exists():
        return f"spec/pay_rules.json absent from bundle_dir {bundle_dir}"
    if not events_path.exists():
        return f"data/pay_events.csv absent from bundle_dir {bundle_dir}"
    if not ledger_path.exists():
        return f"payload/paychecks.json absent from bundle_dir {bundle_dir}"

    try:
        rules: dict = json.loads(rules_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return f"failed to read spec/pay_rules.json: {exc}"

    if rules.get("schema") != "payroll-rules-v1":
        return f"rules schema mismatch: expected 'payroll-rules-v1', got {rules.get('schema')!r}"

    # Index pay events by employee_id
    try:
        rows = list(csv.DictReader(events_path.read_bytes().decode("utf-8").splitlines()))
    except Exception as exc:  # noqa: BLE001 — stdlib pack, surface any parse error
        return f"failed to parse data/pay_events.csv: {exc}"
    events: dict[str, dict] = {r["employee_id"]: r for r in rows}

    try:
        ledger: list = json.loads(ledger_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return f"failed to read payload/paychecks.json: {exc}"
    if not isinstance(ledger, list):
        return "payload/paychecks.json must be a JSON array"

    for idx, rec in enumerate(ledger):
        try:
            emp = rec["employee_id"]
            bundled_gross = int(rec["gross_cents"])
            bundled_tax = int(rec["tax_cents"])
            bundled_pension = int(rec["pension_cents"])
            bundled_net = int(rec["net_cents"])
            issued_net = int(rec["issued_net_cents"])
            bundled_clawback = int(rec["clawback_cents"])
        except (KeyError, TypeError, ValueError) as exc:
            return f"paycheck[{idx}]: malformed record — {exc}"

        ev = events.get(emp)
        if ev is None:
            return f"paycheck[{idx}] {emp}: no matching pay event in data/pay_events.csv"
        if (ev.get("status") or "").strip() != "paid":
            return (
                f"paycheck[{idx}] {emp}: paycheck issued but pay event status is "
                f"{ev.get('status')!r} (expected 'paid')"
            )

        try:
            derived = _compute_pay(rules, ev)
        except (KeyError, ValueError) as exc:
            return f"paycheck[{idx}] {emp}: re-derivation failed — {exc}"

        for fld, bundled in (
            ("gross_cents", bundled_gross),
            ("tax_cents", bundled_tax),
            ("pension_cents", bundled_pension),
            ("net_cents", bundled_net),
        ):
            if derived[fld] != bundled:
                return (
                    f"paycheck[{idx}] {emp}: {fld} mismatch — "
                    f"re-derived={derived[fld]} bundled={bundled}"
                )

        # The reconciliation invariant Phoenix could not satisfy: the amount
        # owed back (or owed to) is provably issued minus correct.
        expected_clawback = issued_net - derived["net_cents"]
        if expected_clawback != bundled_clawback:
            return (
                f"paycheck[{idx}] {emp}: clawback_cents mismatch — "
                f"issued_net({issued_net}) - correct_net({derived['net_cents']}) "
                f"= {expected_clawback}, but bundled clawback_cents={bundled_clawback}"
            )

    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Payroll re-derivation check for paycheck/clawback audit bundles"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    error = _verify(args.bundle_dir.resolve())
    if error is None:
        return 0
    print(f"[PAYROLL_REDER_FAIL] {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
