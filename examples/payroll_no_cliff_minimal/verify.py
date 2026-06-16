"""verify.py — verify the payroll_no_cliff_minimal bundle through the SAME
default plugin set the bare CLI verifier (`veriker/cli/verify.py`) uses.

No pilot-local pack: the obligation is a whole-domain monotonicity property the
verifier proves with a Z3 search over free earnings variables, so S2 / C16
(`RefinementDischargeCheck`, already substrate) does the work. The headline runs
through the bare CLI with zero pilot code:

    python veriker/cli/verify.py --bundle-dir examples/payroll_no_cliff_minimal/bundle

Usage (from v-kernel-audit-bundle root, with the demo verifier key exported):
    export VKERNEL_VERIFIER_HMAC_KEY="demo-vkernel-verifier-secret-0123456789abcdef"
    python examples/payroll_no_cliff_minimal/verify.py \
        --bundle-dir examples/payroll_no_cliff_minimal/bundle

Exit codes:
  0  PASS
  1  FAIL (one or more checks failed) or missing verifier key
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.plugins import default_post_w3_plugin_set  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import (  # noqa: E402
    FileIntegrityManySmall,
)
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402


def verify(bundle_dir: Path) -> int:
    if not os.environ.get("VKERNEL_VERIFIER_HMAC_KEY"):
        print(
            "ERROR: export VKERNEL_VERIFIER_HMAC_KEY first "
            '(e.g. "demo-vkernel-verifier-secret-0123456789abcdef"). The S2 '
            "no-cliff discharge status is verifier-signed; without the key the "
            "C16 check fails closed (DISCHARGE_STATUS_FORGED).",
            file=sys.stderr,
        )
        return 1

    plugins = [
        FileIntegrityManySmall(),
        SpecShaPinCheck(),
        *default_post_w3_plugin_set(),
    ]
    result = BundleVerifier(plugins=plugins).verify(bundle_dir)

    if result.ok:
        print(f"PASS — {bundle_dir}")
        print(
            "  S2 / C16 refinement_discharge: verifier-signed 'discharged' "
            "admitted; Z3 re-searched the whole earnings domain and found no "
            "income cliff (re-discharged) — a for-all property no range check "
            "can express"
        )
        return 0

    print(f"FAIL — {bundle_dir}")
    for f in result.failures:
        print(f"  [{f.check_name}] {f.reason_code}: {f.detail}")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the payroll_no_cliff_minimal bundle (S2 / C16)"
    )
    parser.add_argument("--bundle-dir", required=True, type=Path)
    args = parser.parse_args()
    return verify(args.bundle_dir.resolve())


if __name__ == "__main__":
    sys.exit(main())
