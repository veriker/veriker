"""_build_bundle.py — build a deterministic payroll_acting_discretion_minimal bundle.

The S2 / C16 case that RE-DERIVATION CANNOT REACH — and therefore the one where
verifier-controlled discharge is a genuine upgrade rather than a weaker echo of a
re-derivation check.

Story — a government **acting-pay placement** under a collective agreement.

  An employee whose substantive classification is AS-03 acts in a higher
  classification (PM-04). The agreement sets the acting rate **at management
  discretion** within a band — there is NO single correct number a verifier
  could recompute. These discretionary acting/retroactive transactions are
  exactly the ~40% of cases the Phoenix automated system could not process and
  the Auditor General could not reconcile: not because the math was hard, but
  because there was no canonical amount to check the disbursed one against.

  Re-derivation (§C6, the payroll_reconciliation_minimal story) is the wrong
  tool here: there is no function `f(rules, inputs) -> acting_rate`. The rate is
  a free choice inside a polytope. The ONLY verifiable claim is an admissibility
  PROPERTY, and that is precisely what S2 / C16 discharges:

      (and (>= acting_rate band_min)        ; (a) at least the PM-04 band minimum
           (<= acting_rate band_max)        ; (b) at most the PM-04 band maximum
           (>= acting_rate raise_floor)     ; (c) >= substantive * 1.04 (min raise)
           (<= acting_rate windfall_ceiling)) ; (d) <= substantive * 1.40 (anti-windfall)

  The four bounds are spec-derived (re-derivable from the pinned rules + the
  substantive rate); the acting_rate itself is the irreducibly-discretionary
  decision. The verifier re-parses the obligation, substitutes the integer-cents
  context, and re-executes Z3 OFFLINE: `unsat` on the negation ⇒ the chosen rate
  lies in the admissible band ⇒ DISCHARGED. Only a verifier-key-signed status is
  admitted (the producer cannot self-sign).

  The fraud this catches — and re-derivation structurally cannot — is the
  out-of-band placement: a buddy-deal acting rate that sits *inside the raw
  classification band* but breaches the anti-windfall cap (over-payment), or one
  that falls below the band minimum (under-payment). There is no "correct rate"
  to compare against; only the band-membership property bites. See
  demo legs in tests/.

Usage (from v-kernel-audit-bundle root, with the demo verifier key exported):
    export VKERNEL_VERIFIER_HMAC_KEY="demo-vkernel-verifier-secret-0123456789abcdef"
    python examples/payroll_acting_discretion_minimal/_build_bundle.py \
        --out-dir examples/payroll_acting_discretion_minimal/bundle

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
_BUNDLE_ID = "payroll-acting-discretion-minimal-rc"
_CREATED_AT = "2026-05-31T00:00:00Z"

_TYPED_CHECKS = [
    "spec_sha_pin",
    "file_integrity_many_small",
    "dispatch_record_wellformed",
    "refinement_discharge",
]

# ---------------------------------------------------------------------------
# Pinned acting-pay rules (acting-pay-rules-v1). Salaries are annual dollars.
# These bound the discretionary band; they do NOT pick a point in it.
# ---------------------------------------------------------------------------

_RULES = {
    "schema": "acting-pay-rules-v1",
    "periods_per_year": 26,
    "substantive": {"classification": "AS-03", "annual_salary": 68000},
    "acting": {
        "classification": "PM-04",
        "band_min_annual": 85000,
        "band_max_annual": 97000,
    },
    # Collective-agreement uplift bounds, as integer percent of the substantive
    # per-period rate. raise_min: at least a 4% promotional raise. windfall_max:
    # no more than a 40% jump (the anti-windfall guard).
    "raise_min_pct": 104,
    "windfall_max_pct": 140,
}

# The management decision — the producer's discretionary output. NOT a function
# of the rules; any value in the admissible band is legitimate. 350000 ¢
# ($3,500.00 / period) sits comfortably inside [326923, 366153].
_CHOSEN_ACTING_RATE_CENTS = 350000

_EMPLOYEE_ID = "E2207"

# The refinement obligation — the agreement's four-clause admissibility band.
# QF_LIA (linear integer arithmetic over cents).
_REFINEMENT = (
    "(and (>= acting_rate band_min) (<= acting_rate band_max) "
    "(>= acting_rate raise_floor) (<= acting_rate windfall_ceiling))"
)
_LOGIC = "QF_LIA"

# Human-readable, digest-pinned statement of the same property (proofs/). The
# C16 re-run formula is the record's outputs[0].type.refine; this file is the
# pinned-by-digest companion (S2 Step 1).
_OBLIGATION_TEXT = (
    "; payroll_acting_discretion_minimal — discretionary acting-pay band membership (S2)\n"
    "; collective-agreement clause: the acting rate is set at MANAGEMENT DISCRETION\n"
    "; (there is no single re-derivable correct value) but MUST satisfy:\n"
    ";   (a) acting_rate >= PM-04 band minimum\n"
    ";   (b) acting_rate <= PM-04 band maximum\n"
    ";   (c) acting_rate >= substantive * 1.04   (minimum promotional raise)\n"
    ";   (d) acting_rate <= substantive * 1.40   (anti-windfall cap)\n"
    "; only this admissibility property is checkable; re-derivation has no answer.\n"
    "(and (>= acting_rate band_min) (<= acting_rate band_max) "
    "(>= acting_rate raise_floor) (<= acting_rate windfall_ceiling))\n"
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _rhu(num: int, den: int) -> int:
    """Round half up (non-negative)."""
    if num < 0:
        raise ValueError(f"_rhu expects non-negative numerator, got {num}")
    return (num + den // 2) // den


def _load_verifier_key() -> VerifierSigningKey:
    """Construct the verifier signing key the SAME way veriker/cli/verify.py's
    _load_verifier_recheck_key() does: VKERNEL_VERIFIER_HMAC_KEY (UTF-8 bytes),
    default verifier_id 'v-kernel-default'. Guarantees the S2 discharge
    signature re-verifies at verify time. The demo secret is disclosed +
    synthetic (Standing Order #9)."""
    secret = os.environ.get("VKERNEL_VERIFIER_HMAC_KEY")
    if not secret:
        raise AssertionError(
            "VKERNEL_VERIFIER_HMAC_KEY is not set. The S2 acting-band discharge "
            "status is VERIFIER-signed; export the same demo secret the verifier "
            "loads, e.g.\n"
            '  export VKERNEL_VERIFIER_HMAC_KEY='
            '"demo-vkernel-verifier-secret-0123456789abcdef"'
        )
    return VerifierSigningKey.from_secret_bytes(secret.encode("utf-8"))


def _band_edges() -> dict:
    """Derive the four admissibility bounds from the pinned rules + substantive
    rate. These ARE re-derivable (a verifier could recompute them); the acting
    rate placed within them is NOT."""
    ppy = _RULES["periods_per_year"]
    substantive_period = _rhu(_RULES["substantive"]["annual_salary"] * 100, ppy)
    band_min = _rhu(_RULES["acting"]["band_min_annual"] * 100, ppy)
    band_max = _rhu(_RULES["acting"]["band_max_annual"] * 100, ppy)
    raise_floor = substantive_period * _RULES["raise_min_pct"] // 100
    windfall_ceiling = substantive_period * _RULES["windfall_max_pct"] // 100
    return {
        "substantive_period": substantive_period,
        "band_min": band_min,
        "band_max": band_max,
        "raise_floor": raise_floor,
        "windfall_ceiling": windfall_ceiling,
    }


def build(out_dir: Path) -> None:
    # S2 / C16 preconditions: the discharge status is verifier-signed and the
    # verifier re-executes REAL Z3, so refuse to build without both.
    key = _load_verifier_key()
    invoker = pick_default_invoker()
    if invoker is None:
        raise AssertionError(
            "no Z3 invoker available: install the z3-solver Python package or "
            "put the z3 binary on PATH. This pilot demonstrates a REAL Z3 "
            "re-execution of the acting-band membership property; it does not "
            "ship a fake."
        )

    edges = _band_edges()
    acting_rate = _CHOSEN_ACTING_RATE_CENTS

    # The admissible band is the intersection of the classification band and the
    # uplift bounds. The honest build only ships an in-band decision.
    eff_min = max(edges["band_min"], edges["raise_floor"])
    eff_max = min(edges["band_max"], edges["windfall_ceiling"])
    assert eff_min <= eff_max, (
        f"agreement bounds are infeasible (eff_min={eff_min} > eff_max={eff_max}); "
        "no discretionary rate could satisfy all four clauses"
    )
    assert eff_min <= acting_rate <= eff_max, (
        f"chosen acting_rate={acting_rate} is outside the admissible band "
        f"[{eff_min}, {eff_max}]; this build only ships an HONEST in-band decision"
    )

    # spec/ — the pinned rules that bound the band.
    rules_bytes = json.dumps(_RULES, indent=2, sort_keys=True).encode("utf-8")

    # payload/ — the producer's discretionary placement decision.
    placement = {
        "employee_id": _EMPLOYEE_ID,
        "substantive_classification": _RULES["substantive"]["classification"],
        "acting_classification": _RULES["acting"]["classification"],
        "substantive_rate_cents": edges["substantive_period"],
        "acting_rate_cents": acting_rate,
        "admissible_band_cents": {"min": eff_min, "max": eff_max},
        "band_source": (
            "intersection of the PM-04 per-period classification band and the "
            "4%–40% acting-uplift bounds; the rate within it is management discretion"
        ),
        "in_band": True,
    }
    payload_bytes = json.dumps(placement, indent=2).encode("utf-8")

    # proofs/ — the SMT-LIB obligation, pinned by digest in manifest.files.
    obligation_uri = "proofs/acting_band.smt2"
    obligation_bytes = _OBLIGATION_TEXT.encode("utf-8")
    obligation_sha = _sha256(obligation_bytes)

    # The dispatch context the verifier substitutes into the refinement before
    # re-running Z3. Integer cents + the logic marker (QF_LIA). Bound into the
    # verifier signature AND re-run at verify time.
    recheck_context = {
        "acting_rate": acting_rate,
        "band_min": edges["band_min"],
        "band_max": edges["band_max"],
        "raise_floor": edges["raise_floor"],
        "windfall_ceiling": edges["windfall_ceiling"],
        "__logic__": _LOGIC,
    }

    # --- The verifier's role: re-run Z3, then sign the discharge IF it holds. -
    parsed = parse_refinement(_REFINEMENT)
    script = substitute(parsed, recheck_context, logic=_LOGIC)
    z3_result = discharge(script.text, timeout_s=5.0, invoker=invoker)
    assert z3_result.status is Z3Status.DISCHARGED, (
        f"Z3 did not discharge the acting-band membership property "
        f"({z3_result.status}: {z3_result.raw_output[:200]}); this build only "
        "ships an HONEST bundle where the chosen rate is genuinely in-band"
    )

    record = {
        "schema_version": "0.1",
        "op": {"kind": "COMPUTE", "name": "acting_pay_band_membership"},
        "inputs": [],
        "outputs": [
            {
                "name": "acting_placement",
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

    # --- Emit via the reference-emitter SDK ---
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "payload/placement.json": payload_bytes,
            obligation_uri: obligation_bytes,
        },
        spec_files={
            "acting_pay_rules.json": rules_bytes,
        },
        cross_refs={},
        payload={},
        typed_checks=_TYPED_CHECKS,
        extra_manifest_fields={
            "dispatch_records": [record],
        },
    )
    write_bundle(out_dir, content)

    print(f"Bundle written to {out_dir}")
    print(f"  employee            : {_EMPLOYEE_ID}  (AS-03 acting PM-04)")
    print(f"  substantive (¢/per) : {edges['substantive_period']}")
    print(
        "  admissible band (¢) : "
        f"[{eff_min}, {eff_max}]  "
        f"(class band [{edges['band_min']}, {edges['band_max']}] ∩ "
        f"uplift [{edges['raise_floor']}, {edges['windfall_ceiling']}])"
    )
    print(f"  discretionary rate  : {acting_rate}  (in-band — re-derivation has no answer here)")
    print(f"  refinement          : {_REFINEMENT}  [{_LOGIC}]")
    print(
        f"  Z3 re-run           : {z3_result.status.value}  "
        f"(invoker={z3_result.invoker_kind})"
    )
    print("  discharge_status    : not-attempted --[verifier-signed]--> discharged")
    print(f"  obligation_sha      : {obligation_sha[:16]}…  (pinned in manifest.files)")
    print(f"  verifier_id         : {key.verifier_id}")
    print(f"  manifest            : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic payroll_acting_discretion_minimal audit bundle"
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
