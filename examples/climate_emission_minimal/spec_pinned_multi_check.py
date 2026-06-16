"""spec_pinned_multi_check.py — multi-output coverage-invariant (§4a.4 / C19)
demonstration, composed from the climate_emission_minimal pilot's TWO already
auditor-anchored outputs.

A SINGLE spec-pinned bundle declaring TWO genuine outputs, both re-derived from
the SAME inputs/supplier_chain.json, each bound by a SEPARATE committed auditor
spec, spanning TWO comparator kinds:

  output A  climate-total-scope3   type climate_total_scope3   (exact)
            primitive climate_emission_recompute  (compute_total -> scalar)
            spec spec_pinned/climate.spec.json     (spec_id climate.emission.v1)

  output B  climate-attribution    type climate_attribution    (structured)
            primitive climate_attribution_recompute (compute_attribution -> list)
            spec spec_pinned/climate_emission.spec.json (spec_id climate_emission.v1)

The auditor SpecAnchor allows BOTH spec_ids (built from the committed bytes).
This exercises, over a GENUINE multi-output declared set:
  - the coverage invariant (§4a.4 / C19): manifest.outputs must cover EXACTLY the
    outputs/<id>.json files present — otherwise "omit the check" degenerates to
    "omit the output entry";
  - the cardinality guard (§4a.8): exactly one result per declared output;
  - per-output isolation: tampering ONE output's value fails ONLY that output's
    re-derivation, while the other still re-derives.

ADDITIVE: reuses the pilot's existing primitives and committed specs verbatim; no
new primitive, no new spec, and the bundle is built to a temp dir so no committed
manifest gains an `outputs` array (inertness invariant preserved).

Stdlib-only orchestration. Example tooling, not verifier substrate.

Usage:
    python examples/climate_emission_minimal/spec_pinned_multi_check.py
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util as _ilu
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


def _load_legacy_build():
    _s = _ilu.spec_from_file_location(
        "climate_emission_minimal__legacy_build_bundle_multi", _HERE / "_build_bundle.py"
    )
    _m = _ilu.module_from_spec(_s)
    _s.loader.exec_module(_m)
    return _m.build


_build_legacy_bundle = _load_legacy_build()
from climate_attribution_recompute import compute_attribution  # noqa: E402
from audit_bundle.rederivation.primitives.climate_emission import compute_total  # noqa: E402

# --- output A: scalar total (exact) ---
_OUT_A_ID = "climate-total-scope3"
_OUT_A_TYPE = "climate_total_scope3"
_SPEC_A_SRC = _HERE / "spec_pinned" / "climate.spec.json"

# --- output B: per-vendor attribution list (structured) ---
_OUT_B_ID = "climate-attribution"
_OUT_B_TYPE = "climate_attribution"
_SPEC_B_SRC = _HERE / "spec_pinned" / "climate_emission.spec.json"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_multi_output(
    out_dir: Path,
    *,
    omit_entry: str | None = None,
    drop_file: str | None = None,
    tamper_output: tuple[str, object] | None = None,
) -> Path:
    """Build a TWO-output spec-pinned climate bundle in out_dir.

    Control hooks (applied after the honest build):
      omit_entry=<output_id>   drop that output's manifest.outputs ENTRY but keep
                               its outputs/<id>.json file (present-but-undeclared:
                               the §4a.4 "omit the check by omitting the entry").
      drop_file=<output_id>    delete that output's file AND its manifest.files
                               entry but keep its manifest.outputs entry
                               (declared-but-absent).
      tamper_output=(id,val)   write a tampered claimed value for one output
                               (per-output isolation: only that output's
                               re-derivation fails).
    """
    out_dir = out_dir.resolve()
    _build_legacy_bundle(out_dir)

    spec_dir = out_dir / "spec"
    outputs_dir = out_dir / "outputs"
    spec_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)

    chain = json.loads((out_dir / "inputs" / "supplier_chain.json").read_bytes())

    # --- Lay down BOTH committed auditor specs under spec/<basename>. ---
    spec_a_bytes = _SPEC_A_SRC.read_bytes()
    spec_b_bytes = _SPEC_B_SRC.read_bytes()
    (spec_dir / _SPEC_A_SRC.name).write_bytes(spec_a_bytes)
    (spec_dir / _SPEC_B_SRC.name).write_bytes(spec_b_bytes)

    # --- Honest claimed values = the auditors' own canonical recomputes. ---
    claim_a = compute_total(chain)
    claim_b = compute_attribution(chain)
    if tamper_output is not None and tamper_output[0] == _OUT_A_ID:
        claim_a = tamper_output[1]
    if tamper_output is not None and tamper_output[0] == _OUT_B_ID:
        claim_b = tamper_output[1]

    a_bytes = json.dumps({"value": claim_a}, indent=2).encode("utf-8")
    b_bytes = json.dumps({"value": claim_b}, indent=2).encode("utf-8")
    (outputs_dir / f"{_OUT_A_ID}.json").write_bytes(a_bytes)
    (outputs_dir / f"{_OUT_B_ID}.json").write_bytes(b_bytes)

    # --- Overlay the manifest. ---
    manifest_path = out_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][f"outputs/{_OUT_A_ID}.json"] = _sha256(a_bytes)
    manifest["files"][f"outputs/{_OUT_B_ID}.json"] = _sha256(b_bytes)
    manifest["spec_files"] = {
        _SPEC_A_SRC.name: _sha256(spec_a_bytes),
        _SPEC_B_SRC.name: _sha256(spec_b_bytes),
    }
    manifest["outputs"] = [
        {"output_id": _OUT_A_ID, "type": _OUT_A_TYPE, "conforms_to": f"spec/{_SPEC_A_SRC.name}"},
        {"output_id": _OUT_B_ID, "type": _OUT_B_TYPE, "conforms_to": f"spec/{_SPEC_B_SRC.name}"},
    ]
    manifest["typed_checks"] = ["file_integrity_many_small"]

    # --- Control: omit an output ENTRY (keep file -> present-but-undeclared). ---
    if omit_entry is not None:
        manifest["outputs"] = [o for o in manifest["outputs"] if o["output_id"] != omit_entry]

    # --- Control: drop an output FILE + its files entry (keep entry -> declared-but-absent). ---
    if drop_file is not None:
        (outputs_dir / f"{drop_file}.json").unlink()
        manifest["files"].pop(f"outputs/{drop_file}.json", None)

    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )
    return out_dir


def anchor_from_committed_specs():
    """Build the auditor SpecAnchor allowing BOTH committed spec_ids."""
    from audit_bundle.rederivation.spec_binding import SpecAnchor  # noqa: PLC0415

    a = json.loads(_SPEC_A_SRC.read_bytes())
    b = json.loads(_SPEC_B_SRC.read_bytes())
    return SpecAnchor(
        allowed={
            a["spec_id"]: _sha256(_SPEC_A_SRC.read_bytes()),
            b["spec_id"]: _sha256(_SPEC_B_SRC.read_bytes()),
        }
    )


def make_verifier(anchor=None):
    """Construct the spec-pinned verifier with BOTH primitives registered."""
    from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: PLC0415
    from audit_bundle.rederivation.registry import register_primitive  # noqa: PLC0415
    from audit_bundle.verifier import BundleVerifier  # noqa: PLC0415
    from climate_attribution_recompute import ClimateAttributionRecompute  # noqa: PLC0415
    from audit_bundle.rederivation.primitives.climate_emission import (  # noqa: PLC0415
        ClimateEmissionRecompute,
    )

    register_primitive(ClimateEmissionRecompute())
    register_primitive(ClimateAttributionRecompute())
    return BundleVerifier(plugins=[FileIntegrityManySmall()], spec_anchor=anchor)


def main() -> int:
    argparse.ArgumentParser(
        description="Build + spec-pinned-verify the climate multi-output (§529) demo"
    ).parse_args()
    with tempfile.TemporaryDirectory() as td:
        bundle_dir = build_multi_output(Path(td) / "bundle")
        result = make_verifier(anchor_from_committed_specs()).verify(bundle_dir)
        if result.ok:
            print("PASS  climate multi-output  (2 outputs, exact + structured, §4a.4 coverage)")
            return 0
        print("FAIL  climate multi-output", file=sys.stderr)
        for f in result.failures:
            print(f"    [{f.check_name}] {f.reason_code}: {f.detail}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
