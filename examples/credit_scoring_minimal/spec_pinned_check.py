"""spec_pinned_check.py — self-contained Axis-2 spec-pinned dispatch for credit_scoring.

Per-dir migration of the credit_scoring_minimal pilot onto the disclosed spec-pinned,
auditor-anchored, in-process recompute-then-compare method (S0). This is ADDITIVE:
the legacy bundle (_build_bundle.py + CreditScoringReDerivationCheck.py +
credit_scoring_re_derivation.py) and its verify.py / test are untouched, and no
committed manifest gains an `outputs` array — the spec-pinned bundle is built to a
fresh directory here, so the substrate's "0 committed manifests declare outputs"
inertness invariant is preserved.

What it demonstrates:
  - The auditor pins the binding (type -> primitive_id + comparator) in a
    SHA-anchored spec (spec_pinned/credit_scoring.spec.json).
  - The verifier re-derives the representative output (the ordered per-applicant
    categorical verdict list — [applicant_id, tier, decision] triples) IN-PROCESS
    via the registered primitive, and compares with the generic `exact` comparator.
    No subprocess, no bundle-supplied code.
  - Honest bundle -> PASS; tampered claimed list or tampered input (an applicant
    attribute mutated so a verdict flips) -> FAIL (REDERIVATION_MISMATCH); no
    auditor anchor / substituted spec -> fail-closed (AnchorViolation).

The legacy manifest carries dispatch_records + fragment_anchors + source_attributes
(the dispatch-record / fragment-anchor surface from the original build). The overlay leaves those intact and
only ADDS outputs[]/spec_files/files[outputs/…] and OVERRIDES typed_checks: the
spec-pinned verifier runs FileIntegrityManySmall + step-5 dispatch only, so
typed_checks must name exactly the registered plugin set -> ["file_integrity_many_small"].

Usage:
    python examples/credit_scoring_minimal/spec_pinned_check.py
        # build a spec-pinned bundle in a temp dir + verify under the anchor
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

# Legacy builder (lays down model/applicants/payload/manifest) + the shared
# canonical compute function (imported standalone — no audit_bundle needed).
# Load the pilot's legacy builder by PATH under a pilot-unique module name.
# A bare `import _build_bundle` collides across pilots in a shared interpreter
# (every pilot ships a _build_bundle.py), caching the wrong builder.
import importlib.util as _ilu  # noqa: E402


def _load_legacy_build():
    _s = _ilu.spec_from_file_location(
        "credit_scoring__legacy_build_bundle", _HERE / "_build_bundle.py"
    )
    _m = _ilu.module_from_spec(_s)
    _s.loader.exec_module(_m)
    return _m.build


_build_legacy_bundle = _load_legacy_build()
from credit_scoring_recompute import (  # noqa: E402
    _load_sorted_applicants,
    compute_verdict_list,
)

_OUTPUT_ID = "credit_scoring_verdict_list"
_TYPE_KEY = "credit_scoring_verdict_list"
_SPEC_SRC = _HERE / "spec_pinned" / "credit_scoring.spec.json"
_SPEC_BASENAME = _SPEC_SRC.name


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_spec_pinned(
    out_dir: Path,
    *,
    claimed_override: object = None,
    spec_bytes_override: bytes | None = None,
) -> Path:
    """Build a spec-pinned credit_scoring bundle in out_dir. Reuses the legacy
    builder for model/applicants/payload, then overlays the β shape: an auditor
    spec under spec/, a producer claimed-value file under outputs/, a
    manifest.outputs entry, and a typed_checks set matching the spec-pinned
    verifier's plugin set.

    The *_override hooks let tests inject attacks (tampered claim / weak spec).
    Returns the bundle directory.
    """
    out_dir = out_dir.resolve()
    _build_legacy_bundle(out_dir)

    spec_dir = out_dir / "spec"
    outputs_dir = out_dir / "outputs"
    spec_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)

    # --- Auditor spec under spec/<basename> (committed bytes, unless overridden). ---
    spec_bytes = (
        spec_bytes_override if spec_bytes_override is not None else _SPEC_SRC.read_bytes()
    )
    (spec_dir / _SPEC_BASENAME).write_bytes(spec_bytes)
    spec_sha = _sha256(spec_bytes)

    # --- Honest claimed value = the auditor's own canonical recompute. ---
    scorecard = json.loads((out_dir / "model" / "scorecard.json").read_bytes())
    threshold_table = json.loads(
        (out_dir / "model" / "threshold_table.json").read_bytes()
    )
    applicants = _load_sorted_applicants(out_dir / "applicants")
    claimed = compute_verdict_list(applicants, scorecard, threshold_table)
    if claimed_override is not None:
        claimed = claimed_override
    claim_bytes = json.dumps({"value": claimed}, indent=2).encode("utf-8")
    (outputs_dir / f"{_OUTPUT_ID}.json").write_bytes(claim_bytes)
    claim_sha = _sha256(claim_bytes)

    # --- Overlay the manifest: outputs[] + spec_files + files + typed_checks. ---
    # Leave the legacy fields (dispatch_records, fragment_anchors, …) intact;
    # only ADD the spec-pinned surface and OVERRIDE typed_checks.
    manifest_path = out_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][f"outputs/{_OUTPUT_ID}.json"] = claim_sha
    manifest["spec_files"] = {_SPEC_BASENAME: spec_sha}
    manifest["outputs"] = [
        {
            "output_id": _OUTPUT_ID,
            "type": _TYPE_KEY,
            "conforms_to": f"spec/{_SPEC_BASENAME}",
        }
    ]
    # The spec-pinned verifier runs FileIntegrityManySmall + step-5 dispatch only;
    # typed_checks must match the registered plugin set (verifier enforces this).
    manifest["typed_checks"] = ["file_integrity_many_small"]
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
    return out_dir


def anchor_from_committed_spec():
    """Build the auditor SpecAnchor from the COMMITTED source spec bytes."""
    from audit_bundle.rederivation.spec_binding import SpecAnchor  # noqa: PLC0415

    raw = _SPEC_SRC.read_bytes()
    doc = json.loads(raw)
    return SpecAnchor(allowed={doc["spec_id"]: _sha256(raw)})


def make_verifier(anchor=None):
    """Construct the spec-pinned verifier: FileIntegrity + step-5 dispatch under
    the auditor anchor. Registers the in-dir primitive first."""
    from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: PLC0415
    from audit_bundle.plugins.dispatch_record_wellformed import (  # noqa: PLC0415
        DispatchRecordWellformedCheck,
    )
    from audit_bundle.plugins.stamp_lattice import StampLatticeCheck  # noqa: PLC0415
    from audit_bundle.rederivation.registry import register_primitive  # noqa: PLC0415
    from audit_bundle.verifier import BundleVerifier  # noqa: PLC0415
    from credit_scoring_recompute import CreditScoringRecompute  # noqa: PLC0415

    register_primitive(CreditScoringRecompute())
    return BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            # The bundle carries dispatch_records; verify()'s stamp-claims
            # coverage guard fails closed unless C15 well-formedness and the
            # C14 lattice claim are both evaluated (2026-06-12).
            DispatchRecordWellformedCheck(op_kinds_admitted=frozenset({"SCORECARD_EVAL", "COMPUTE"})),
            StampLatticeCheck(),
        ],
        spec_anchor=anchor,
    )


def main() -> int:
    argparse.ArgumentParser(
        description="Build + spec-pinned-verify the credit_scoring exemplar"
    ).parse_args()
    with tempfile.TemporaryDirectory() as td:
        bundle_dir = build_spec_pinned(Path(td) / "bundle")
        anchor = anchor_from_committed_spec()
        result = make_verifier(anchor).verify(bundle_dir)
        if result.ok:
            print("PASS  credit_scoring  (spec-pinned dispatch)")
            return 0
        print("FAIL  credit_scoring  (spec-pinned dispatch)", file=sys.stderr)
        for f in result.failures:
            print(f"    [{f.check_name}] {f.reason_code}: {f.detail}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
