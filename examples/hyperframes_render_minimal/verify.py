"""verify.py — hyperframes_render_minimal domain pilot bundle verifier.

the audit-bundle contract §C5 (auditor independence). Runs as a standalone
script from any working directory; inserts the v-kernel-audit-bundle package
root into sys.path so no PYTHONPATH manipulation is required.

Registers three plugins:
  SpecShaPinCheck                §C1 — spec-file SHA pinning (walks manifest.spec_files)
  FileIntegrityManySmall         §C9 — per-file SHA walk over manifest.files (skips spec/)
  HyperFramesReDerivationCheck   §C6 — re-renders the bundled composition and
                                       compares the resulting MP4 sha256 to
                                       manifest.payload.output_mp4_sha256.

Re-derivation is slow (live Chrome render + ffmpeg encode), so HyperFrames
verifications take 5–30 s depending on cache warmth — the substrate's strict
re-derivation guarantee in exchange for end-to-end cryptographic reproducibility.

Usage:
    python examples/hyperframes_render_minimal/verify.py --bundle-dir <path>

Exit codes:
    0  PASS — all checks passed
    1  FAIL — one or more checks failed (details printed to stderr)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck
from audit_bundle.verifier import BundleVerifier
from HyperFramesReDerivationCheck import HyperFramesReDerivationCheck


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "hyperframes_render_minimal audit bundle verifier "
            "(AUDIT_BUNDLE_CONTRACT §C5)"
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
        SpecShaPinCheck(),
        FileIntegrityManySmall(),
        HyperFramesReDerivationCheck(),
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
