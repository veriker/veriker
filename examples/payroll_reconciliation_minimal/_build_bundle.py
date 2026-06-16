"""_build_bundle.py — build a deterministic payroll_reconciliation_minimal bundle.

Synthesizes a small government-style payroll period modeled on the Phoenix
failure, computes each paycheck and each overpayment/clawback amount from a
pinned pay-rules spec, and emits a standards-compliant audit bundle.

The fixtures deliberately exercise the case classes that sank Phoenix:
  - plain base pay (the cases Phoenix mostly handled),
  - acting pay and retroactive pay (the ~40% of transactions Phoenix could not
    process automatically),
  - an overpaid and an underpaid employee (the clawback population the
    government later could not reconcile — it could not substantiate the amount
    owed), and
  - two withheld employees (so the closed-world pay-population accounting is
    non-trivial: eligible == issued + withheld).

Usage (from v-kernel-audit-bundle root):
    python examples/payroll_reconciliation_minimal/_build_bundle.py --out-dir /tmp/payroll_bundle

Outputs:
  <out-dir>/spec/pay_rules.json        (pinned pay rules — owned by spec_files)
  <out-dir>/data/pay_events.csv        (per-employee pay events — input snapshot)
  <out-dir>/payload/paychecks.json     (computed paycheck + clawback ledger)
  <out-dir>/coverage/period_2026_05.json  (closed-world pay-population row, C4)
  <out-dir>/status_change_log.jsonl    (append-only correction/retraction trail, C7)
  <out-dir>/manifest.json

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.discharge.context_substitution import substitute  # noqa: E402
from audit_bundle.discharge.smtlib_parser import parse_refinement  # noqa: E402
from audit_bundle.discharge.verifier_signing import (  # noqa: E402
    VerifierSigningKey,
    sign_and_write,
)
from audit_bundle.discharge.z3_runner import (  # noqa: E402
    Z3Status,
    discharge,
    pick_default_invoker,
)
from audit_bundle.emitter import BundleContent, write_bundle  # noqa: E402

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "payroll-reconciliation-minimal-rc"
_CREATED_AT = "2026-05-28T00:00:00Z"
_TYPED_CHECKS = [
    "spec_sha_pin",
    "file_integrity_many_small",
    "payroll_re_derivation",
    "coverage_sum_invariant",
    "dispatch_record_wellformed",
    "refinement_discharge",
]

# ---------------------------------------------------------------------------
# S2 / C16 — paycheck conservation invariant (SMT-Z3 refinement discharge).
#
# The per-paycheck arithmetic already computed in _compute_pay (gross =
# base + acting_uplift + retro; net = gross - tax - pension) is exact-integer
# cents, so it lives natively in QF_LIA. We carry it as a refinement obligation
# bound to one representative paycheck — E0006, the acting + retro case, whose
# base / uplift / retro are all non-zero so the conservation property is
# non-trivial. The verifier re-parses the formula, substitutes the integer-cents
# context, and re-executes Z3 OFFLINE on a green build; only a verifier-key-
# signed 'discharged' status is admitted (the producer cannot self-sign).
# ---------------------------------------------------------------------------

# The paycheck the conservation obligation is bound to. Chosen because base +
# acting uplift + retro are all non-zero (an acting + retroactive-raise period),
# so the gross-decomposition equality is the full Phoenix-flavored case, not the
# trivial base-only one.
_S2_EMPLOYEE_ID = "E0006"

# The refinement obligation: gross decomposes into its three components AND net
# is gross minus the two deductions. QF_LIA (linear integer arithmetic over
# cents) — the decidable fragment the verifier admits.
_REFINEMENT = (
    "(and (= gross (+ base uplift retro)) "
    "(= net (- (- gross tax) pension)))"
)
_LOGIC = "QF_LIA"

# Human-readable, digest-pinned statement of the same property (proofs/). The
# C16 re-run formula is the record's outputs[0].type.refine; this file is the
# pinned-by-digest companion (S2 Step 1). They state the same invariant.
_OBLIGATION_TEXT = (
    "; payroll_reconciliation_minimal — paycheck conservation invariant (S2)\n"
    "; property: gross = base + acting_uplift + retro  AND  net = gross - tax - pension\n"
    f"; bound to paycheck {_S2_EMPLOYEE_ID} (acting + retro period; all gross components non-zero)\n"
    "(and (= gross (+ base uplift retro)) (= net (- (- gross tax) pension)))\n"
)

# ---------------------------------------------------------------------------
# Pinned pay rules (payroll-rules-v1). Salaries are annual dollars.
# ---------------------------------------------------------------------------

_RULES = {
    "schema": "payroll-rules-v1",
    "period_days": 14,
    "periods_per_year": 26,
    "tax_rate_bps": 2200,
    "pension_rate_bps": 850,
    "classifications": {
        "AS-01": {"annual_salary": 52000},
        "AS-03": {"annual_salary": 68000},
        "PM-04": {"annual_salary": 91000},
        "EX-01": {"annual_salary": 124000},
    },
}

# ---------------------------------------------------------------------------
# Synthetic pay events. clawback_offset_cents is applied to the correct net to
# fabricate the issued (possibly wrong) amount: >0 overpaid, <0 underpaid.
# ---------------------------------------------------------------------------

_EVENTS = [
    # employee, home, acting, acting_days, retro_old, retro_new, retro_periods, status, withheld_reason, clawback_offset
    ("E0001", "AS-01", "",      0,     0,     0, 0, "paid",     "",                       0),
    ("E0002", "AS-03", "",      0,     0,     0, 0, "paid",     "",                       0),
    ("E0003", "AS-01", "AS-03", 7,     0,     0, 0, "paid",     "",                       0),  # acting, half period
    ("E0004", "AS-03", "PM-04", 14,    0,     0, 0, "paid",     "",                       0),  # acting, full period
    ("E0005", "AS-01", "",      0, 50000, 52000, 5, "paid",     "",                       0),  # retro
    ("E0006", "PM-04", "EX-01", 10, 88000, 91000, 3, "paid",    "",                       0),  # acting + retro
    ("E0007", "EX-01", "",      0,     0,     0, 0, "paid",     "",                       0),
    ("E0008", "AS-03", "",      0,     0,     0, 0, "paid",     "",                   40000),  # OVERPAID by $400.00
    ("E0009", "AS-01", "AS-03", 3,     0,     0, 0, "paid",     "",                  -12500),  # UNDERPAID by $125.00
    ("E0010", "PM-04", "",      0,     0,     0, 0, "paid",     "",                       0),
    ("E0011", "AS-03", "",      0,     0,     0, 0, "withheld", "UNDER_REVIEW",           0),
    ("E0012", "",      "",      0,     0,     0, 0, "withheld", "MISSING_CLASSIFICATION", 0),
]

_EVENT_COLUMNS = [
    "employee_id",
    "home_classification",
    "acting_classification",
    "acting_days",
    "retro_old_salary",
    "retro_new_salary",
    "retro_periods",
    "status",
    "withheld_reason",
]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_verifier_key() -> VerifierSigningKey:
    """Construct the verifier signing key the SAME way veriker/cli/verify.py's
    _load_verifier_recheck_key() does: VKERNEL_VERIFIER_HMAC_KEY (UTF-8 bytes),
    default verifier_id 'v-kernel-default'. Guarantees the S2 discharge
    signature re-verifies at verify time. The demo secret is disclosed +
    synthetic (Standing Order #9)."""
    secret = os.environ.get("VKERNEL_VERIFIER_HMAC_KEY")
    if not secret:
        raise AssertionError(
            "VKERNEL_VERIFIER_HMAC_KEY is not set. The S2 paycheck-conservation "
            "discharge status is VERIFIER-signed; export the same demo secret the "
            "verifier loads, e.g.\n"
            '  export VKERNEL_VERIFIER_HMAC_KEY='
            '"demo-vkernel-verifier-secret-0123456789abcdef"'
        )
    return VerifierSigningKey.from_secret_bytes(secret.encode("utf-8"))


def _rhu(num: int, den: int) -> int:
    if num < 0:
        raise ValueError(f"_rhu expects non-negative numerator, got {num}")
    return (num + den // 2) // den


def _compute_pay(home, acting_cls, acting_days, retro_old, retro_new, retro_periods) -> dict:
    cls = _RULES["classifications"]
    ppy = _RULES["periods_per_year"]
    period_days = _RULES["period_days"]
    home_annual_cents = cls[home]["annual_salary"] * 100

    base_cents = _rhu(home_annual_cents, ppy)

    acting_uplift_cents = 0
    if acting_cls:
        delta = cls[acting_cls]["annual_salary"] * 100 - home_annual_cents
        if delta < 0:
            delta = 0
        acting_uplift_cents = _rhu(delta * acting_days, ppy * period_days)

    retro_cents = 0
    if retro_periods and retro_new > retro_old:
        retro_cents = _rhu((retro_new - retro_old) * 100 * retro_periods, ppy)

    gross = base_cents + acting_uplift_cents + retro_cents
    tax = _rhu(gross * _RULES["tax_rate_bps"], 10000)
    pension = _rhu(gross * _RULES["pension_rate_bps"], 10000)
    net = gross - tax - pension
    return {
        "base_cents": base_cents,
        "acting_uplift_cents": acting_uplift_cents,
        "retro_cents": retro_cents,
        "gross_cents": gross,
        "tax_cents": tax,
        "pension_cents": pension,
        "net_cents": net,
    }


def _events_to_csv_bytes() -> bytes:
    lines = [",".join(_EVENT_COLUMNS)]
    for row in _EVENTS:
        (emp, home, acting, adays, rold, rnew, rper, status, wreason, _off) = row
        lines.append(
            ",".join(str(v) for v in (emp, home, acting, adays, rold, rnew, rper, status, wreason))
        )
    return "\n".join(lines).encode("utf-8")


def build(out_dir: Path) -> None:
    # S2 / C16 preconditions: the discharge status is verifier-signed and the
    # verifier re-executes REAL Z3, so refuse to build without both.
    key = _load_verifier_key()
    invoker = pick_default_invoker()
    if invoker is None:
        raise AssertionError(
            "no Z3 invoker available: install the z3-solver Python package or "
            "put the z3 binary on PATH. This pilot demonstrates a REAL Z3 "
            "re-execution of the paycheck conservation invariant; it does not "
            "ship a fake."
        )

    # ---- spec/pay_rules.json bytes ----
    rules_bytes = json.dumps(_RULES, indent=2, sort_keys=True).encode("utf-8")

    # ---- data/pay_events.csv bytes ----
    events_bytes = _events_to_csv_bytes()

    # ---- payload/paychecks.json bytes (computed ledger) ----
    ledger: list[dict] = []
    n_eligible = len(_EVENTS)
    n_issued = 0
    n_withheld = 0
    withheld_breakdown: dict[str, int] = {}
    s2_pay: dict | None = None  # the chosen paycheck's full component breakdown

    for (emp, home, acting, adays, rold, rnew, rper, status, wreason, offset) in _EVENTS:
        if status == "withheld":
            n_withheld += 1
            withheld_breakdown[wreason] = withheld_breakdown.get(wreason, 0) + 1
            continue
        n_issued += 1
        pay = _compute_pay(home, acting, adays, rold, rnew, rper)
        if emp == _S2_EMPLOYEE_ID:
            s2_pay = pay
        correct_net = pay["net_cents"]
        issued_net = correct_net + offset  # offset fabricates the disbursed amount
        ledger.append({
            "employee_id": emp,
            "home_classification": home,
            "gross_cents": pay["gross_cents"],
            "tax_cents": pay["tax_cents"],
            "pension_cents": pay["pension_cents"],
            "net_cents": correct_net,
            "issued_net_cents": issued_net,
            "clawback_cents": issued_net - correct_net,
        })

    payload_bytes = json.dumps(ledger, indent=2).encode("utf-8")

    assert n_issued + n_withheld == n_eligible, "internal accounting drift"

    # ---- coverage/period_2026_05.json bytes (closed-world pay population, C4) ----
    coverage_row = {
        "tick_id": "pay-period-2026-05-A",
        "n_eligible": n_eligible,
        "n_issued": n_issued,
        "n_withheld": n_withheld,
        "withheld_reason_breakdown": withheld_breakdown,
    }
    coverage_bytes = json.dumps(coverage_row, indent=2, sort_keys=True).encode("utf-8")

    # ---- status_change_log.jsonl bytes (append-only correction trail, C7) ----
    # A Phoenix-flavored churn: an overpayment correction that is later disputed
    # and retracted pending reconciliation, plus a supplementary payment for an
    # underpayment. Immutable, timestamped — exactly the trail Phoenix lacked.
    events_log = [
        {
            "event_id": "pay-evt-001",
            "output_id": "E0008-2026-05",
            "event_type": "CORRECT",
            "timestamp": "2026-05-15T00:00:00Z",
            "reason": "overpayment of 40000 cents identified; clawback scheduled",
            "prev_event_id": None,
        },
        {
            "event_id": "pay-evt-002",
            "output_id": "E0009-2026-05",
            "event_type": "SUPERSEDE",
            "timestamp": "2026-05-16T00:00:00Z",
            "reason": "underpayment of 12500 cents; supplementary payment supersedes original",
            "prev_event_id": None,
        },
        {
            "event_id": "pay-evt-003",
            "output_id": "E0008-2026-05",
            "event_type": "RETRACT",
            "timestamp": "2026-05-20T00:00:00Z",
            "reason": "clawback disputed by employee; correction retracted pending file reconciliation",
            "prev_event_id": "pay-evt-001",
        },
    ]
    log_bytes = (
        "\n".join(json.dumps(e, sort_keys=True, separators=(",", ":")) for e in events_log) + "\n"
    ).encode("utf-8")

    # ---- proofs/payroll_conservation.smt2 bytes + S2 / C16 discharge record ----
    assert s2_pay is not None, (
        f"S2 invariant employee {_S2_EMPLOYEE_ID!r} was not issued a paycheck; "
        "cannot bind the conservation obligation"
    )

    obligation_uri = "proofs/payroll_conservation.smt2"
    obligation_bytes = _OBLIGATION_TEXT.encode("utf-8")
    obligation_sha = _sha256(obligation_bytes)

    # The dispatch context the verifier substitutes into the refinement before
    # re-running Z3. Integer cents + the logic marker (QF_LIA). Bound into the
    # verifier signature AND re-run at verify time.
    recheck_context = {
        "base": s2_pay["base_cents"],
        "uplift": s2_pay["acting_uplift_cents"],
        "retro": s2_pay["retro_cents"],
        "gross": s2_pay["gross_cents"],
        "tax": s2_pay["tax_cents"],
        "pension": s2_pay["pension_cents"],
        "net": s2_pay["net_cents"],
        "__logic__": _LOGIC,
    }

    parsed = parse_refinement(_REFINEMENT)
    script = substitute(parsed, recheck_context, logic=_LOGIC)
    z3_result = discharge(script.text, timeout_s=5.0, invoker=invoker)
    assert z3_result.status is Z3Status.DISCHARGED, (
        f"Z3 did not discharge the paycheck conservation invariant "
        f"({z3_result.status}: {z3_result.raw_output[:200]}); this build only "
        "ships an HONEST bundle where the obligation genuinely holds"
    )

    discharge_record = {
        "schema_version": "0.1",
        "op": {"kind": "COMPUTE", "name": "paycheck_conservation"},
        "inputs": [],
        "outputs": [
            {
                "name": "paycheck",
                "type": {"base": "Int", "refine": _REFINEMENT},
            }
        ],
        "effect": {},
        "predicates": [],
        "stamp_declared": "INTERNAL_BENCHMARK",
        "stamp_observed": None,
        "proof": {
            "kind": "smt-z3",
            "obligation_uri": obligation_uri,
            "obligation_sha": obligation_sha,
            "discharge_status": "not-attempted",
            "recheck_context": recheck_context,
        },
    }
    # Verifier signs the status it just computed (discharged). The signature
    # binds (bundle_id, record_idx, proof.kind, obligation_sha, refine-text,
    # recheck-context) — a sig copied to another bundle/record/formula/context
    # fails to re-verify.
    discharge_record = sign_and_write(
        discharge_record,
        key=key,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
        record_idx=0,
    )

    # --- Emit via the reference-emitter SDK ---
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "data/pay_events.csv": events_bytes,
            "payload/paychecks.json": payload_bytes,
            "coverage/period_2026_05.json": coverage_bytes,
            "status_change_log.jsonl": log_bytes,
            obligation_uri: obligation_bytes,
        },
        spec_files={
            "pay_rules.json": rules_bytes,
        },
        cross_refs={},
        payload={},
        typed_checks=_TYPED_CHECKS,
        extra_manifest_fields={
            "dispatch_records": [discharge_record],
        },
    )
    write_bundle(out_dir, content)

    total_clawback = sum(r["clawback_cents"] for r in ledger)
    print(f"Bundle written to {out_dir}")
    print(f"  eligible employees : {n_eligible}")
    print(f"  paychecks issued   : {n_issued}")
    print(f"  withheld           : {n_withheld} {withheld_breakdown}")
    print(f"  net clawback (cents): {total_clawback}")
    print(f"  status-change events: {len(events_log)}")
    print(f"  S2 invariant        : {_REFINEMENT}  [{_LOGIC}]")
    print(
        f"  S2 paycheck         : {_S2_EMPLOYEE_ID}  "
        f"base={s2_pay['base_cents']} uplift={s2_pay['acting_uplift_cents']} "
        f"retro={s2_pay['retro_cents']} gross={s2_pay['gross_cents']} "
        f"tax={s2_pay['tax_cents']} pension={s2_pay['pension_cents']} "
        f"net={s2_pay['net_cents']}"
    )
    print(
        f"  Z3 re-run           : {z3_result.status.value}  "
        f"(invoker={z3_result.invoker_kind})"
    )
    print("  discharge_status    : not-attempted --[verifier-signed]--> discharged")
    print(f"  obligation_sha      : {obligation_sha[:16]}…  (pinned in manifest.files)")
    print(f"  verifier_id         : {key.verifier_id}")
    print(f"  manifest files     : 5")
    print(f"  manifest           : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic payroll_reconciliation_minimal audit bundle"
    )
    parser.add_argument("--out-dir", required=True, type=Path, help="Destination directory")
    args = parser.parse_args()
    try:
        build(args.out_dir.resolve())
    except AssertionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
