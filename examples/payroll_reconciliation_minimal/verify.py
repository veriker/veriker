"""verify.py — payroll_reconciliation_minimal domain pilot bundle verifier.

the audit-bundle contract §C5 (auditor independence). Runs as a standalone
script from any working directory; inserts the v-kernel-audit-bundle package
root into sys.path so no PYTHONPATH manipulation is required by the caller.

Registers the four pilot-specific plugins plus the substrate C14/C15/C16 set:
  SpecShaPinCheck              §C1 — pay-rules spec SHA pinning
  FileIntegrityManySmall       §C9 — per-file SHA walk over manifest.files
  PayrollReDerivationCheck     §C6 — paycheck + clawback re-derivation (local pack)
  CoverageSumInvariantCheck    §C4 — n_issued + n_withheld == n_eligible (pay population)
  default_post_w3_plugin_set() §C14/§C15/§C16 — the SAME C14 lattice +
                               C15 dispatch-record well-formedness + C16
                               refinement-discharge trio veriker/cli/verify.py wires.
                               This is what drives the S2 paycheck-conservation
                               discharge: C16 admits the verifier-signed
                               'discharged' status and re-executes Z3 to confirm
                               the conservation invariant re-discharges.

The S2 discharge status is VERIFIER-signed, so VKERNEL_VERIFIER_HMAC_KEY must be
exported — without it the C16 check fails closed (DISCHARGE_STATUS_FORGED). The
same headline is runnable through the bare CLI with no pilot code:

    python veriker/cli/verify.py --bundle-dir examples/payroll_reconciliation_minimal/bundle

The append-only correction/retraction trail (status_change_log.jsonl) is bundled
and SHA-pinned via manifest.files (so it is tamper-evident), but C7 append-only
enforcement is a substrate concern not wired as a per-pilot typed_check here —
mirroring spectra_minimal / tabular_minimal, which likewise leave it to the
substrate event-stream layer (audit_bundle/event_stream.py).

Usage:
    export VKERNEL_VERIFIER_HMAC_KEY="demo-vkernel-verifier-secret-0123456789abcdef"
    python examples/payroll_reconciliation_minimal/verify.py --bundle-dir <path>

Exit codes:
    0  PASS — all checks passed
    1  FAIL — one or more checks failed (details printed to stderr) or missing key
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# §C5 auditor-independence: locate pkg root relative to this file so the script
# is runnable from any cwd without external PYTHONPATH configuration.
# Layout: examples/payroll_reconciliation_minimal/verify.py → parents[2] = pkg root.
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# PayrollReDerivationCheck lives alongside this script (AB4 — duplicate-don't-import).
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from audit_bundle.plugins import default_post_w3_plugin_set
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck
from audit_bundle.verifier import BundleVerifier
from audit_bundle.coverage.sum_invariant_plugin import CoverageSumInvariantCheck
from PayrollReDerivationCheck import PayrollReDerivationCheck


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Payroll-reconciliation audit bundle verifier (AUDIT_BUNDLE_CONTRACT §C5)"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    if not os.environ.get("VKERNEL_VERIFIER_HMAC_KEY"):
        print(
            "FAIL\n  export VKERNEL_VERIFIER_HMAC_KEY first "
            '(e.g. "demo-vkernel-verifier-secret-0123456789abcdef"). The S2 '
            "paycheck-conservation discharge status is verifier-signed; without "
            "the key the C16 check fails closed (DISCHARGE_STATUS_FORGED).",
            file=sys.stderr,
        )
        return 1

    # default_post_w3_plugin_set() loads VKERNEL_VERIFIER_HMAC_KEY + a Z3 invoker
    # internally — the SAME wiring veriker/cli/verify.py uses (C15 well-formedness, C14
    # lattice, C16 refinement-discharge over the S2 paycheck conservation invariant).
    plugins = [
        SpecShaPinCheck(),
        FileIntegrityManySmall(),
        PayrollReDerivationCheck(),
        CoverageSumInvariantCheck(),
        *default_post_w3_plugin_set(),
    ]
    verifier = BundleVerifier(plugins=plugins)
    result = verifier.verify(bundle_dir)

    if result.ok:
        print("PASS")
        return 0

    print("FAIL", file=sys.stderr)
    for failure in result.failures:
        print(
            f"  [{failure.check_name}] {failure.reason_code}: {failure.detail}",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    sys.exit(main())
