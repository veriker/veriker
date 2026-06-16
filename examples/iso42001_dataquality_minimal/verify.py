"""verify.py — iso42001_dataquality_minimal domain pilot bundle verifier.

the audit-bundle contract §C5 (auditor independence). Registers the
Iso42001DataQualityRecompute primitive (type-switching across the three A.7
quality metrics) and verifies a multi-output spec-pinned bundle. The auditor's
SpecAnchor is derived from the COMMITTED spec file, NOT the bundle's copy.

Usage:
    python examples/iso42001_dataquality_minimal/verify.py --bundle-dir <path>

Exit codes:
    0  PASS    1  FAIL
"""

from __future__ import annotations

import argparse
import hashlib
import sys

sys.dont_write_bytecode = True

from pathlib import Path  # noqa: E402

_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import iso42001_dataquality_recompute as _prim_mod  # noqa: E402

from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.rederivation.registry import register_primitive  # noqa: E402
from audit_bundle.rederivation.spec_binding import SpecAnchor  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402

register_primitive(_prim_mod.Iso42001DataQualityRecompute())

_SPEC_SRC = _HERE / "spec_pinned" / "iso42001_dataquality.spec.json"


def _build_anchor() -> SpecAnchor:
    raw = _SPEC_SRC.read_bytes()
    import json as _json  # noqa: PLC0415

    doc = _json.loads(raw)
    return SpecAnchor(allowed={doc["spec_id"]: hashlib.sha256(raw).hexdigest()})


def main() -> int:
    parser = argparse.ArgumentParser(
        description="iso42001_dataquality_minimal audit bundle verifier (§C5)"
    )
    parser.add_argument("--bundle-dir", required=True, type=Path)
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    verifier = BundleVerifier(
        plugins=[FileIntegrityManySmall()], spec_anchor=_build_anchor()
    )
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
