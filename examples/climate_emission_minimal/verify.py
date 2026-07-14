"""verify.py — climate_emission_minimal domain pilot bundle verifier.

the audit-bundle contract §C5 (auditor independence). Runs as a standalone
script from any working directory; inserts the v-kernel-audit-bundle package
root into sys.path so no PYTHONPATH manipulation is required by the caller.

Registers three plugins:
  FileIntegrityManySmall                    §C9 — per-file SHA walk
  ReDerivationInvocationCheck               §C6 — subprocess invocation of climate_emission_pack.py
  ClimateEmissionReDerivationCheck          §C6 — Scope-3 supply-chain re-derivation

The top-level cli/verify.py works against this same bundle without this wrapper:
its auto-detected ReDerivationInvocationCheck plugin picks up
re_derive/climate_emission_pack.py and runs the same re-derivation.

Usage:
    python examples/climate_emission_minimal/verify.py --bundle-dir <path>

Exit codes:
    0  PASS — all checks passed
    1  FAIL — one or more checks failed (details printed to stderr)
"""

from __future__ import annotations

import argparse
import sys

# Suppress .pyc generation: the verifier imports the pilot's TypedCheck plugin
# module from inside the bundle directory it's verifying. Without this,
# CPython drops __pycache__/<mod>.pyc into the bundle, which then trips
# file_integrity_many_small Pass 3 (EXTRA_FILE_NOT_IN_MANIFEST). Mirrors the
# same defense in cli/verify.py.
sys.dont_write_bytecode = True

from pathlib import Path  # noqa: E402

# §C5 auditor-independence: locate pkg root relative to this file.
# Layout: examples/climate_emission_minimal/verify.py → parents[2] = pkg root.
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# ClimateEmissionReDerivationCheck lives alongside this script
# (AB4 — duplicate-don't-import pattern).
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.re_derivation_invocation import ReDerivationInvocationCheck  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from ClimateEmissionReDerivationCheck import ClimateEmissionReDerivationCheck  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "climate_emission_minimal audit bundle verifier (AUDIT_BUNDLE_CONTRACT §C5)"
        )
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
        ReDerivationInvocationCheck(pack_filename="climate_emission_pack.py", permit_execution=True),
        ClimateEmissionReDerivationCheck(),
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
