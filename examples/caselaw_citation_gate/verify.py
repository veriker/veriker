"""verify.py -- caselaw_citation_gate domain pilot bundle verifier.

the audit-bundle contract §C5 (auditor independence). Runs as a standalone script
from any working directory; inserts the v-kernel-audit-bundle package root into
sys.path so no PYTHONPATH manipulation is required by the caller.

Registers the CaselawGateKbRecompute primitive via the verifier registry API (NOT
by editing audit_bundle/rederivation/primitives/). The primitive is defined in the
pilot module and registered here, after audit_bundle is on sys.path.

Plugins:
  FileIntegrityManySmall       §C9  -- per-file SHA walk + extra-file detection
  CaselawGateAttestationCheck  §C16 -- ATTEST: gate authority Ed25519 signature
                                       over the verdict + evidence binding
                                       (forge-resistant; verifier holds public key only)

Spec-pinned dispatch (Axis-2):
  The auditor's SpecAnchor is derived from the COMMITTED spec file
  (spec_pinned/caselaw_gate_kb.spec.json) -- NOT from the bundle's spec/ copy.
  A producer who ships a weaker spec in the bundle gets a SHA the anchor does not
  list, so it is not authoritative and dispatch fails closed.

The re-derivation NEVER touches the network: it reads the frozen, verbatim-rooted
corpus committed into the bundle. The network rooting happened once, in
_root_corpus.py (producer-side), and is auditable via per-record provenance.

Usage:
    python examples/caselaw_citation_gate/verify.py --bundle-dir <path>

Exit codes:
    0  PASS -- all checks passed
    1  FAIL -- one or more checks failed (details printed to stderr)
"""

from __future__ import annotations

import argparse
import hashlib
import sys

# Suppress .pyc generation: the verifier imports the pilot's primitive module from
# inside the pilot directory. Without this, CPython may drop __pycache__/<mod>.pyc
# into the bundle, which trips Pass 3 of file_integrity_many_small.
sys.dont_write_bytecode = True

from pathlib import Path  # noqa: E402

# §C5 auditor-independence: locate pkg root relative to this file.
# Layout: examples/caselaw_citation_gate/verify.py -> parents[2] = pkg root.
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# The primitive module lives alongside this script (AB4-style local import).
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import caselaw_gate_kb_recompute as _prim_mod  # noqa: E402

from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.rederivation.registry import register_primitive  # noqa: E402
from audit_bundle.rederivation.spec_binding import SpecAnchor  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from CaselawGateAttestationCheck import CaselawGateAttestationCheck  # noqa: E402

# Register the primitive AFTER audit_bundle is importable. The primitive module keeps
# its RecomputedValue import deferred, so it stays importable standalone in
# _build_bundle.py without audit_bundle on sys.path.
register_primitive(_prim_mod.CaselawGateKbRecompute())

# ---------------------------------------------------------------------------
# Auditor's SpecAnchor -- derived from the COMMITTED spec file, not the bundle.
# ---------------------------------------------------------------------------

_SPEC_SRC = _HERE / "spec_pinned" / "caselaw_gate_kb.spec.json"


def _build_anchor() -> SpecAnchor:
    """Build the auditor's SpecAnchor from the committed spec bytes."""
    raw = _SPEC_SRC.read_bytes()
    import json as _json  # noqa: PLC0415

    doc = _json.loads(raw)
    spec_id = doc["spec_id"]
    sha = hashlib.sha256(raw).hexdigest()
    return SpecAnchor(allowed={spec_id: sha})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "caselaw_citation_gate audit bundle verifier (AUDIT_BUNDLE_CONTRACT §C5)"
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
        CaselawGateAttestationCheck(),
    ]
    anchor = _build_anchor()
    verifier = BundleVerifier(plugins=plugins, spec_anchor=anchor)
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
