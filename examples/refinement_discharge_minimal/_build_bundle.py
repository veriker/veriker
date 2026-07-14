"""_build_bundle.py — build a deterministic refinement_discharge_minimal bundle.

The canonical HONEST demonstration of patent **S2** — *Verifier-Controlled
Discharge of Proof Obligations with a Retained Producer-Claim Divergence Record*
— running end-to-end through the bare default verifier (`veriker/cli/verify.py`) with a
REAL Z3 re-execution on a green run.

Prior to this pilot, S2 / contract C16 (`RefinementDischargeCheck` +
`audit_bundle/discharge/{verifier_signing,z3_runner,smtlib_parser,
context_substitution}.py`) was exercised only by:

  - the unit-test suite (`tests/test_discharge/test_refinement_discharge_v0_2.py`
    + `test_integration_horizon_u1_shapley.py`), and
  - the adversarial soak corpus (`examples/soak_known_bad/2[6-9]_*`,
    `3[0-1]_*`) — all NEGATIVE cases that drive the reject paths.

No honest shipped bundle carried a real verifier-signed `discharged` status that
the verifier's own Z3 re-run AGREES with. This pilot closes that gap: the first
demo bundle (vs unit tests + soak fixtures) to drive the Z3 discharge path on a
GREEN run.

Story — an AI cost/impact attribution over a hash-pinned allocation table:

  Record 0  COMPUTE / edge_attribution_sum
      An attribution step claims that the per-edge contributions sum to the
      declared total impact — the formal property named verbatim in the S2
      disclosure ("the per-edge attributions sum to the total impact"). The
      property is carried as an SMT-LIB proof obligation:

          (= (+ e0 e1 e2) total)

      with the dispatch context e0=4200, e1=3500, e2=2300, total=10000 in
      QF_LIA. The verifier:
        1. pins the obligation file by content digest (S2 Step 1),
        2. retains the producer-asserted discharge_status (S2 Step 2),
        3. re-parses the refinement, substitutes the context, and re-executes
           Z3 OFFLINE — which returns `unsat` on the negation, i.e. DISCHARGED
           (S2 Step 3), and
        4. compares: the verifier-determined status AGREES with the producer's
           claim, so the bundle verifies clean (S2 Step 4, agreement branch).

      Only a verifier-key-signed discharge_status is admitted as authoritative;
      the producer cannot self-sign. This script plays the verifier's signing
      step and reads VKERNEL_VERIFIER_HMAC_KEY exactly as veriker/cli/verify.py's
      _load_verifier_recheck_key() does, so the signature re-verifies at verify
      time. The demo secret is disclosed + synthetic (Standing Order #9).

The DISAGREEMENT branch (S2 Step 4, the divergence-record artifact that is the
patent's claimed advance) is demonstrated by demo/run_discharge_demo.py, which
flips one context value so the verifier's Z3 re-run CONTRADICTS the signed claim
and a signed `events.jsonl` divergence record is retained — retain-and-still-
reject.

Usage (from v-kernel-audit-bundle root, with the demo verifier key exported):
    export VKERNEL_VERIFIER_HMAC_KEY="demo-vkernel-verifier-secret-0123456789abcdef"
    python examples/refinement_discharge_minimal/_build_bundle.py \
        --out-dir examples/refinement_discharge_minimal/bundle

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
_BUNDLE_ID = "refinement-discharge-minimal-rc"
_CREATED_AT = "2026-05-31T00:00:00Z"

_TYPED_CHECKS = [
    "spec_sha_pin",
    "file_integrity_many_small",
    "dispatch_record_wellformed",
    "refinement_discharge",
]

# The refinement obligation — the S2 disclosure's own worked example: "the
# per-edge attributions sum to the total impact." Lives in QF_LIA (linear
# integer arithmetic), the decidable fragment the verifier admits.
_REFINEMENT = "(= (+ e0 e1 e2) total)"
_LOGIC = "QF_LIA"

# The hash-pinned allocation table the attribution was derived from. The edge
# contributions sum to total exactly — an HONEST producer.
_ALLOCATION_TABLE = {
    "source": "nexi:demo:ImpactAllocationQ1",
    "period": "2026-Q1",
    "edges": [
        {"edge_id": "e0", "label": "Acquisition", "contribution": 4200},
        {"edge_id": "e1", "label": "Retention", "contribution": 3500},
        {"edge_id": "e2", "label": "Expansion", "contribution": 2300},
    ],
    "total_impact": 10000,
}

# The dispatch context the verifier substitutes into the refinement before
# re-running Z3. Integer literals + the logic marker (QF_LIA). This is the
# recheck_context bound into the verifier signature AND re-run at verify time.
_RECHECK_CONTEXT = {
    "e0": 4200,
    "e1": 3500,
    "e2": 2300,
    "total": 10000,
    "__logic__": _LOGIC,
}

# The SMT-LIB obligation file carried IN the bundle and pinned by digest. Its
# bytes are content-addressed in manifest.files; the verifier confirms the
# digest before admitting the proof (S2 Step 1). The re-run formula itself is
# the record's outputs[0].type.refine (the obligation file is the human-
# readable, digest-pinned statement of the same property).
_OBLIGATION_TEXT = (
    "; refinement_discharge_minimal — per-edge attribution sum invariant (S2)\n"
    "; property: the per-edge attributions sum to the total impact\n"
    "(= (+ e0 e1 e2) total)\n"
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_verifier_key() -> VerifierSigningKey:
    """Construct the verifier signing key the SAME way veriker/cli/verify.py's
    _load_verifier_recheck_key() does: VKERNEL_VERIFIER_HMAC_KEY (UTF-8 bytes),
    default verifier_id 'v-kernel-default'. Guarantees the discharge signature
    re-verifies at verify time."""
    secret = os.environ.get("VKERNEL_VERIFIER_HMAC_KEY")
    if not secret:
        raise AssertionError(
            "VKERNEL_VERIFIER_HMAC_KEY is not set. The S2 discharge status is "
            "VERIFIER-signed; export the same demo secret the verifier loads, "
            "e.g.\n"
            "  export VKERNEL_VERIFIER_HMAC_KEY="
            '"demo-vkernel-verifier-secret-0123456789abcdef"'
        )
    return VerifierSigningKey.from_secret_bytes(secret.encode("utf-8"))


def build(out_dir: Path) -> None:
    key = _load_verifier_key()

    invoker = pick_default_invoker()
    if invoker is None:
        raise AssertionError(
            "no Z3 invoker available: install the z3-solver Python package or "
            "put the z3 binary on PATH. This pilot demonstrates a REAL Z3 "
            "re-execution; it does not ship a fake."
        )

    # spec/ — the pinned allocation table the attribution was derived from.
    source_bytes = json.dumps(_ALLOCATION_TABLE, indent=2, sort_keys=True).encode(
        "utf-8"
    )

    # proofs/ — the SMT-LIB obligation, pinned by digest in manifest.files.
    obligation_uri = "proofs/edge_attribution_sum.smt2"
    obligation_bytes = _OBLIGATION_TEXT.encode("utf-8")
    obligation_sha = _sha256(obligation_bytes)

    # payload/ — the producer's attribution output.
    recomputed_total = sum(e["contribution"] for e in _ALLOCATION_TABLE["edges"])
    attribution = {
        "source_sha256": _sha256(source_bytes),
        "edge_attribution": {
            e["edge_id"]: e["contribution"] for e in _ALLOCATION_TABLE["edges"]
        },
        "total_impact": _ALLOCATION_TABLE["total_impact"],
    }
    payload_bytes = json.dumps(attribution, indent=2).encode("utf-8")

    # --- The verifier's role: re-run Z3, then sign the discharge IF it holds. -
    # This mirrors the real verifier path. Parse → substitute context → Z3.
    # ONLY a status the verifier itself computed is signed; the producer cannot
    # mint its own 'discharged'.
    parsed = parse_refinement(_REFINEMENT)
    script = substitute(parsed, _RECHECK_CONTEXT, logic=_LOGIC)
    z3_result = discharge(script.text, timeout_s=5.0, invoker=invoker)
    assert z3_result.status is Z3Status.DISCHARGED, (
        f"Z3 did not discharge the sum invariant ({z3_result.status}: "
        f"{z3_result.raw_output[:200]}); this build only ships an HONEST bundle "
        "where the obligation genuinely holds"
    )
    assert recomputed_total == _ALLOCATION_TABLE["total_impact"], (
        "allocation table is internally inconsistent; refusing to ship"
    )

    # Pin the minting solver policy into the (HMAC-bound) recheck_context so
    # a rechecking verifier can replay under the SAME budget/seed/version and
    # earn forgery-semantics authority on mismatch (determinism doctrine
    # 2026-06-10). Without the pin the record still verifies, but a mismatch
    # downgrades to NOT_CONFIRMED instead of a divergence REJECT.
    minting_context = dict(_RECHECK_CONTEXT)
    minting_context["__solver_policy__"] = invoker.solver_policy()

    record_0 = {
        "schema_version": "0.1",
        "op": {"kind": "COMPUTE", "name": "edge_attribution_sum"},
        "inputs": [],
        "outputs": [
            {
                "name": "attribution",
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
            "recheck_context": minting_context,
        },
    }
    # Verifier signs the discharge status it just computed (discharged). The
    # signature binds (bundle_id, record_idx, proof.kind, obligation_sha,
    # refine-text, recheck-context) — a sig copied to another bundle/record/
    # formula/context fails to re-verify.
    record_0 = sign_and_write(
        record_0,
        key=key,
        discharge_status="discharged",
        z3_status="discharged",
        bundle_id=_BUNDLE_ID,
        record_idx=0,
        # Freeze the signature timestamp to the bundle's build instant. Without
        # this, sign_and_write falls back to _now_iso8601_utc() (verifier_signing
        # .py), re-signing with wall-clock time on every rebuild → the MAC and
        # timestamp_utc churn. Reusing _CREATED_AT keeps timestamp_utc == created_at
        # (never later), satisfying the stamp_lattice STAMP_UPGRADE_OUT_OF_ORDER rule.
        timestamp_utc=_CREATED_AT,
    )

    dispatch_records = [record_0]

    # --- Emit via the reference-emitter SDK ---
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            obligation_uri: obligation_bytes,
            "payload/attribution.json": payload_bytes,
        },
        spec_files={
            "allocation_table.json": source_bytes,
        },
        cross_refs={},
        payload={},
        typed_checks=_TYPED_CHECKS,
        extra_manifest_fields={
            "dispatch_records": dispatch_records,
        },
    )
    write_bundle(out_dir, content)

    print(f"Bundle written to {out_dir}")
    print(f"  refinement          : {_REFINEMENT}  [{_LOGIC}]")
    print(
        "  context             : "
        f"e0={_RECHECK_CONTEXT['e0']} e1={_RECHECK_CONTEXT['e1']} "
        f"e2={_RECHECK_CONTEXT['e2']} total={_RECHECK_CONTEXT['total']}"
    )
    print(f"  recomputed sum      : {recomputed_total}  (== total: holds)")
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
        description="Build a deterministic refinement_discharge_minimal audit bundle"
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
