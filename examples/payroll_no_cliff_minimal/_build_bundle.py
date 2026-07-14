"""_build_bundle.py — build a deterministic payroll_no_cliff_minimal bundle.

The S2 / C16 case where the verifier must SEARCH, not compare — the example that
answers "how is this different from checking x ∈ [a,b]?".

The obligation is a *safety property of a withholding schedule over its entire
income domain*, not a bound on one produced number:

    no income cliff — for ALL earnings g1 ≤ g2 in [0, cap],
    take-home(g1) ≤ take-home(g2)

i.e. earning a dollar more must never reduce take-home pay. This is the classic
marginal-rate / welfare-cliff bug: a bracket implemented as "whole income at the
top bracket's rate," or a marginal rate above 100%, makes a higher earner take
home LESS at a boundary.

Why this is not x ∈ [a,b], and not re-derivation either:
  - There is no single produced value to bound. The claim quantifies over the
    whole continuous earnings domain.
  - You CANNOT verify it by checking the paychecks present in the bundle (those
    are finitely many points); a cliff can hide between any two of them.
  - The verifier leaves g1 and g2 as FREE variables and asks Z3 whether ANY pair
    in the domain violates monotonicity. `unsat` of that search ⇒ the schedule is
    cliff-free everywhere (DISCHARGED). This is a search over an infinite domain,
    decided symbolically — a comparison `a ≤ x ≤ b` cannot express it.

The four-bracket schedule is encoded directly in the obligation formula. To keep
the reasoning exact integer arithmetic (no rounding, no division — which keeps Z3
fast and the proof airtight), the property is stated on take-home scaled by 100:

    net100(g) = 100*g − tax100(g)      where tax100(g) = 100 * tax(g)

and tax100 is the marginal-bracket sum WITHOUT the ÷100, so every term is
literal-rate × (income portion). Monotonicity of net100 is identical to
monotonicity of take-home (scaling by a positive constant preserves order). Each
bracket's slope is (100 − rate); the schedule is cliff-free iff every marginal
rate ≤ 100.

Usage (from v-kernel-audit-bundle root, with the demo verifier key exported):
    export VKERNEL_VERIFIER_HMAC_KEY="demo-vkernel-verifier-secret-0123456789abcdef"
    python examples/payroll_no_cliff_minimal/_build_bundle.py \
        --out-dir examples/payroll_no_cliff_minimal/bundle

Exit codes:
  0  success
  1  assertion failure, missing verifier key, or Z3 unavailable
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
_BUNDLE_ID = "payroll-no-cliff-minimal-rc"
_CREATED_AT = "2026-05-31T00:00:00Z"

_TYPED_CHECKS = [
    "spec_sha_pin",
    "file_integrity_many_small",
    "dispatch_record_wellformed",
    "refinement_discharge",
]

# Bracket thresholds + domain cap, in integer cents per pay period.
_T1 = 5_000_000     # $50,000.00
_T2 = 10_000_000    # $100,000.00
_CAP = 20_000_000   # $200,000.00 — the audited earnings domain [0, CAP]

# The HONEST marginal rates (percent). All ≤ 100 ⇒ cliff-free everywhere.
_RATES = (15, 22, 29)

_LOGIC = "QF_LIA"


def _net100(v: str, r1: int, r2: int, r3: int) -> str:
    """SMT-LIB expression for 100×take-home at earnings `v` under a 3-bracket
    marginal schedule. No division (exact integer) — see module docstring."""
    tax100 = (
        f"(ite (<= {v} {_T1}) "
        f"(* {v} {r1}) "
        f"(ite (<= {v} {_T2}) "
        f"(+ (* {_T1} {r1}) (* (- {v} {_T1}) {r2})) "
        f"(+ (* {_T1} {r1}) (+ (* (- {_T2} {_T1}) {r2}) (* (- {v} {_T2}) {r3})))))"
    )
    return f"(- (* 100 {v}) {tax100})"


def monotone_formula(r1: int, r2: int, r3: int) -> str:
    """The no-cliff obligation: for all g1 ≤ g2 in [0, CAP], net100 is
    non-decreasing. g1 and g2 are FREE — the verifier searches the domain."""
    pre = (
        f"(and (>= g1 0) (<= g1 {_CAP}) (>= g2 0) (<= g2 {_CAP}) (<= g1 g2))"
    )
    return f"(=> {pre} (<= {_net100('g1', r1, r2, r3)} {_net100('g2', r1, r2, r3)}))"


_REFINEMENT = monotone_formula(*_RATES)


def obligation_text(formula: str, rates: tuple[int, int, int]) -> str:
    r1, r2, r3 = rates
    return (
        "; payroll_no_cliff_minimal — withholding-schedule monotonicity (S2)\n"
        "; safety property: NO INCOME CLIFF — earning more never reduces take-home.\n"
        f";   for all earnings g1 <= g2 in [0, {_CAP}] cents:  take-home(g1) <= take-home(g2)\n"
        f";   3-bracket marginal schedule (cents): [0,{_T1}]@{r1}%  "
        f"({_T1},{_T2}]@{r2}%  ({_T2},inf)@{r3}%\n"
        "; quantified over the ENTIRE domain; g1, g2 are free — the verifier\n"
        "; searches for any violating pair, it does not compare a single value.\n"
        f"{formula}\n"
    )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_verifier_key() -> VerifierSigningKey:
    """Construct the verifier signing key the SAME way veriker/cli/verify.py's
    _load_verifier_recheck_key() does. The demo secret is disclosed + synthetic
    (Standing Order #9)."""
    secret = os.environ.get("VKERNEL_VERIFIER_HMAC_KEY")
    if not secret:
        raise AssertionError(
            "VKERNEL_VERIFIER_HMAC_KEY is not set. The S2 no-cliff discharge "
            "status is VERIFIER-signed; export the same demo secret the verifier "
            "loads, e.g.\n"
            '  export VKERNEL_VERIFIER_HMAC_KEY='
            '"demo-vkernel-verifier-secret-0123456789abcdef"'
        )
    return VerifierSigningKey.from_secret_bytes(secret.encode("utf-8"))


def build(out_dir: Path) -> None:
    key = _load_verifier_key()
    invoker = pick_default_invoker()
    if invoker is None:
        raise AssertionError(
            "no Z3 invoker available: install the z3-solver Python package or "
            "put the z3 binary on PATH. This pilot demonstrates a REAL Z3 search "
            "over the earnings domain; it does not ship a fake."
        )

    r1, r2, r3 = _RATES

    # spec/ — the pinned schedule definition.
    schedule = {
        "schedule_id": "withholding-2026",
        "unit": "cents_per_period",
        "kind": "marginal",
        "brackets": [
            {"from": 0, "to": _T1, "marginal_rate_pct": r1},
            {"from": _T1, "to": _T2, "marginal_rate_pct": r2},
            {"from": _T2, "to": None, "marginal_rate_pct": r3},
        ],
    }
    schedule_bytes = json.dumps(schedule, indent=2, sort_keys=True).encode("utf-8")

    # payload/ — the producer's claim: this schedule is cliff-free on [0, CAP].
    claim = {
        "schedule_id": "withholding-2026",
        "domain_cap_cents": _CAP,
        "safety_property": (
            "no income cliff: for all gross g1 <= g2 in [0, cap], "
            "take-home(g1) <= take-home(g2)"
        ),
        "note": (
            "proven by the verifier over the ENTIRE domain via Z3 search, NOT "
            "over any enumerated paychecks — a cliff could hide between any two "
            "sampled incomes"
        ),
    }
    claim_bytes = json.dumps(claim, indent=2).encode("utf-8")

    # proofs/ — the SMT-LIB obligation, pinned by digest in manifest.files.
    obligation_uri = "proofs/no_cliff.smt2"
    obligation_bytes = obligation_text(_REFINEMENT, _RATES).encode("utf-8")
    obligation_sha = _sha256(obligation_bytes)

    # The dispatch context: g1 and g2 are FREE (sort-declared), so Z3 ranges
    # over the whole domain instead of evaluating a fixed value. No concrete
    # values — every schedule constant is a literal inside the formula.
    recheck_context = {
        "__sorts__": {"g1": "Int", "g2": "Int"},
        "__logic__": _LOGIC,
    }

    # --- The verifier's role: search the domain with Z3, sign IFF cliff-free. -
    parsed = parse_refinement(_REFINEMENT)
    script = substitute(parsed, recheck_context, logic=_LOGIC)
    z3_result = discharge(script.text, timeout_s=10.0, invoker=invoker)
    assert z3_result.status is Z3Status.DISCHARGED, (
        f"Z3 found an income cliff in the shipped schedule "
        f"({z3_result.status}: {z3_result.raw_output[:200]}); this build only "
        "ships an HONEST schedule that is monotone over the whole domain"
    )

    record = {
        "schema_version": "0.1",
        "op": {"kind": "COMPUTE", "name": "withholding_no_cliff"},
        "inputs": [],
        "outputs": [
            {
                "name": "withholding_schedule",
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
    record = sign_and_write(
        record,
        key=key,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
        record_idx=0,
    )

    # --- Emit via the reference-emitter SDK (scaffold + digests + manifest). ---
    # The verifier-signed SMT discharge record is deterministic domain output;
    # it rides through as a pilot-carried manifest field (no live causal-chain
    # witness), so it is supplied via extra_manifest_fields rather than a hook.
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "payload/no_cliff_claim.json": claim_bytes,
            obligation_uri: obligation_bytes,
        },
        spec_files={"withholding_schedule.json": schedule_bytes},
        typed_checks=_TYPED_CHECKS,
        extra_manifest_fields={"dispatch_records": [record]},
    )
    write_bundle(out_dir, content)

    print(f"Bundle written to {out_dir}")
    print(f"  schedule (cents)    : [0,{_T1}]@{r1}%  ({_T1},{_T2}]@{r2}%  ({_T2},inf)@{r3}%")
    print(f"  domain audited      : [0, {_CAP}]  (g1, g2 FREE — Z3 searches all pairs)")
    print(f"  property            : no income cliff (take-home non-decreasing)")
    print(f"  Z3 search           : {z3_result.status.value}  (invoker={z3_result.invoker_kind})")
    print("  discharge_status    : not-attempted --[verifier-signed]--> discharged")
    print(f"  obligation_sha      : {obligation_sha[:16]}…  (pinned in manifest.files)")
    print(f"  verifier_id         : {key.verifier_id}")
    print(f"  manifest            : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic payroll_no_cliff_minimal audit bundle"
    )
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        out_dir = args.out_dir.resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        build(out_dir)
    except AssertionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
