"""run_discharge_demo.py — prove the S2 / C16 refinement-discharge mechanism on
the honest refinement_discharge_minimal bundle: one PASS plus four scenarios,
including the DIVERGENCE branch that is the patent's claimed advance (the signed
divergence record retained to events.jsonl — retain-and-still-reject).

Run (from v-kernel-audit-bundle root, with the demo verifier key exported):
    export VKERNEL_VERIFIER_HMAC_KEY="demo-vkernel-verifier-secret-0123456789abcdef"
    python examples/refinement_discharge_minimal/_build_bundle.py \
        --out-dir examples/refinement_discharge_minimal/bundle
    python examples/refinement_discharge_minimal/demo/run_discharge_demo.py

Each scenario builds an in-memory manifest from the on-disk bundle, mutates ONE
thing, and runs the C16 RefinementDischargeCheck with a REAL in-process Z3
invoker. The honest bundle PASSes (Z3 re-run agrees); every tamper is rejected
with a specific reason code. The divergence scenario additionally confirms a
signed, re-verifiable divergence record was retained.

Exit code 0 iff all scenarios behaved as expected.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[3]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.discharge.verifier_signing import (  # noqa: E402
    DIVERGENCE_RECORD_KIND,
    verify_divergence_record,
)
from audit_bundle.discharge.z3_runner import InProcessZ3Invoker  # noqa: E402
from audit_bundle.plugins import _load_verifier_recheck_key  # noqa: E402
from audit_bundle.plugins.refinement_discharge import (  # noqa: E402
    RefinementDischargeCheck,
)

_BUNDLE = _PKG_ROOT / "examples/refinement_discharge_minimal/bundle"
_BUNDLE_ID = "refinement-discharge-minimal-rc"


class _Manifest:
    """Minimal manifest stub carrying the two fields C16 reads."""

    def __init__(self, dispatch_records, bundle_id=_BUNDLE_ID):
        self.dispatch_records = tuple(dispatch_records)
        self.bundle_id = bundle_id


def _run(records, *, key, bundle_dir, invoker=None):
    plugin = RefinementDischargeCheck(recheck_key=key, recheck_invoker=invoker)
    r = plugin.check(bundle_dir, _Manifest(records))
    return r.ok, r.reason_code, r.detail


def main() -> int:
    if not os.environ.get("VKERNEL_VERIFIER_HMAC_KEY"):
        print(
            "ERROR: export VKERNEL_VERIFIER_HMAC_KEY first "
            '(e.g. "demo-vkernel-verifier-secret-0123456789abcdef")',
            file=sys.stderr,
        )
        return 1
    if not (_BUNDLE / "manifest.json").exists():
        print("ERROR: build the bundle first (see module docstring)", file=sys.stderr)
        return 1

    key = _load_verifier_recheck_key()
    base = json.loads((_BUNDLE / "manifest.json").read_text(encoding="utf-8"))
    records = base["dispatch_records"]

    failures = 0

    # 0 — HONEST: verifier-signed 'discharged'; Z3 re-run AGREES → admitted.
    ok, code, detail = _run(
        copy.deepcopy(records), key=key, bundle_dir=_BUNDLE,
        invoker=InProcessZ3Invoker(),
    )
    expect = ok and code == "PASS" and "re-discharged" in detail
    print(f"[0] honest signed discharge (Z3 agrees) -> ok={ok} {code}")
    print(f"      {detail}")
    failures += 0 if expect else 1

    # 1 — FAIL-CLOSED: no verifier key wired. A non-trivial status cannot be
    #     admitted without a key (defense D3).
    okn, coden, _ = _run(
        copy.deepcopy(records), key=None, bundle_dir=_BUNDLE,
        invoker=InProcessZ3Invoker(),
    )
    expect = (not okn) and coden == "DISCHARGE_STATUS_FORGED"
    print(f"[1] no verifier key (fail-closed)       -> ok={okn} {coden}  (expect FORGED)")
    failures += 0 if expect else 1

    # 2 — FORGED: strip the verifier signature. Unsigned non-trivial status
    #     is forged (defense D4).
    m = copy.deepcopy(records)
    del m[0]["proof"]["verifier_signature"]
    ok2, code2, _ = _run(m, key=key, bundle_dir=_BUNDLE, invoker=InProcessZ3Invoker())
    expect = (not ok2) and code2 == "DISCHARGE_STATUS_FORGED"
    print(f"[2] stripped signature                  -> ok={ok2} {code2}  (expect FORGED)")
    failures += 0 if expect else 1

    # 3 — OBLIGATION TAMPER: claim a different obligation_sha than the pinned
    #     file's bytes (defense D2 — the obligation is pinned by digest).
    m = copy.deepcopy(records)
    m[0]["proof"]["obligation_sha"] = "b" * 64
    ok3, code3, _ = _run(m, key=key, bundle_dir=_BUNDLE, invoker=InProcessZ3Invoker())
    expect = (not ok3) and code3 == "PROOF_OBLIGATION_SHA_MISMATCH"
    print(f"[3] obligation-digest tamper            -> ok={ok3} {code3}  (expect SHA_MISMATCH)")
    failures += 0 if expect else 1

    # 4 — DIVERGENCE (the claimed advance): the producer signs 'discharged' over
    #     a context whose total is wrong (9999, not 10000). The verifier's OWN
    #     Z3 re-run finds a counterexample → FAILED, contradicting the signed
    #     claim. A signed divergence record is retained to events.jsonl AND the
    #     verdict still fails closed (retain-and-still-reject).
    #
    #     NB: this re-signs under the demo key (legitimately — the divergence is
    #     in the CONTEXT vs the claim, not a forged MAC) and runs in a temp copy
    #     so the shipped honest bundle stays clean.
    from audit_bundle.discharge.verifier_signing import sign_and_write

    with tempfile.TemporaryDirectory() as td:
        tmp_bundle = Path(td) / "bundle"
        shutil.copytree(_BUNDLE, tmp_bundle)
        base_rec = copy.deepcopy(records[0])
        # Reset to an unsigned record, flip the context total, re-sign 'discharged'.
        base_rec["proof"]["discharge_status"] = "not-attempted"
        base_rec["proof"].pop("verifier_signature", None)
        base_rec["proof"]["recheck_context"] = {
            **base_rec["proof"]["recheck_context"],
            "total": 9999,  # the lie: edges still sum to 10000
        }
        diverged = sign_and_write(
            base_rec, key=key,
            discharge_status="discharged", z3_status="discharged",
            bundle_id=_BUNDLE_ID, record_idx=0,
        )
        ok4, code4, detail4 = _run(
            [diverged], key=key, bundle_dir=tmp_bundle,
            invoker=InProcessZ3Invoker(),
        )
        verdict_ok = (not ok4) and code4 == "DISCHARGE_STATUS_VERIFIER_DIVERGENCE"

        # Confirm the divergence record was RETAINED and re-verifies.
        events_path = tmp_bundle / "events.jsonl"
        retained = events_path.exists()
        record_reverifies = False
        if retained:
            last = events_path.read_text(encoding="utf-8").strip().splitlines()[-1]
            event = json.loads(last)
            det = event.get("detail", {})
            record_reverifies = (
                event.get("kind") == "DISCHARGE_STATUS_VERIFIER_DIVERGENCE"
                and det.get("record_kind") == DIVERGENCE_RECORD_KIND
                and det.get("producer_claimed") == "discharged"
                and det.get("verifier_computed") == "failed"
                and verify_divergence_record(
                    det, key=key, bundle_id=_BUNDLE_ID, record_idx=0
                )
            )
        expect = verdict_ok and retained and record_reverifies
        print(
            f"[4] verifier-vs-claim divergence        -> ok={ok4} {code4}  "
            "(expect VERIFIER_DIVERGENCE)"
        )
        print(
            f"      divergence record retained={retained} "
            f"re-verifies={record_reverifies} (retain-and-still-reject)"
        )
        failures += 0 if expect else 1

    print()
    if failures == 0:
        print(
            "ALL SCENARIOS BEHAVED AS EXPECTED "
            "(1 honest PASS with real Z3 + 3 tamper rejections + 1 retained divergence record)"
        )
        return 0
    print(f"{failures} scenario(s) did NOT behave as expected")
    return 1


if __name__ == "__main__":
    sys.exit(main())
