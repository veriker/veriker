"""verify.py — credit_scoring_minimal domain pilot bundle verifier.

the audit-bundle contract §C5 (auditor independence). Runs as a standalone
script from any working directory; inserts the v-kernel-audit-bundle package
root into sys.path so no PYTHONPATH manipulation is required by the caller.

Registers three plugins:
  FileIntegrityManySmall            §C9 — per-file SHA walk with named reason codes
  CreditScoringReDerivationCheck    §C6 — credit-scoring PD + tier re-derivation (local pack)
  DispatchRecordWellformedCheck     §C15 — op-kind + effect well-formedness
    (op_kinds_admitted=frozenset({"SCORECARD_EVAL", "COMPUTE"}) admits the new
     domain-specific SCORECARD_EVAL kind introduced by this pilot)

Brazilian regulatory mapping:
  LGPD art. 20 (IN FORCE) — the re-derivation produces the "clear information on
    the criteria and procedures" a data subject may demand for an automated credit
    decision; bundle_id + created_at + typed_checks are the auditable model record
  PL 2338/2023 (BILL — credit = "high-risk") — the bundle is the
    algorithmic-impact / explainability artifact the pending framework would expect
  source_attributes on the bureau-snapshot CID carries publication_class="regulatory"
    (Serasa / Boa Vista / SPC style credit-bureau provenance, emitted at build time)

Usage:
    python examples/credit_scoring_minimal/verify.py --bundle-dir <path>

Exit codes:
    0  PASS — all checks passed
    1  FAIL — one or more checks failed (details printed to stderr)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# §C5 auditor-independence: locate pkg root relative to this file so the
# script is runnable from any cwd without external PYTHONPATH configuration.
# Layout: examples/credit_scoring_minimal/verify.py → parents[2] = pkg root.
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# CreditScoringReDerivationCheck lives alongside this script (AB4 — duplicate-don't-import).
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from audit_bundle.plugins.dispatch_record_wellformed import (
    DispatchRecordWellformedCheck,
)
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck
from audit_bundle.verifier import BundleVerifier
from CreditScoringReDerivationCheck import CreditScoringReDerivationCheck


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Credit-scoring-minimal audit bundle verifier (AUDIT_BUNDLE_CONTRACT §C5)"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    plugins = [
        FileIntegrityManySmall(),
        CreditScoringReDerivationCheck(),
        DispatchRecordWellformedCheck(
            op_kinds_admitted=frozenset({"SCORECARD_EVAL", "COMPUTE"})
        ),
        StampLatticeCheck(),
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
