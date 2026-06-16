"""_build_bundle.py — build a deterministic pe_engineering_signoff_minimal audit bundle.

Writes a PE-stamp-on-AI-engineering-analysis domain bundle into --out-dir:
  inputs/analyses.json                  (3 deterministic cantilever-beam analyses,
                                          each with geometry + load + material inputs)
  payload/engineering_analyses.json     (computed stress/FoS/verdict per analysis)
  payload/pe_stamp_provenance.jsonl     (PE-stamp attestation log — the differentiating feature)
  payload/attestation_key.hex           (synthetic HMAC key committed to bundle for re-verification)
  manifest.json

Exercises three V-Kernel extension points:
  OpaqueFragment(source_cid, kind_tag="engineering_assumption", locator={...})
    — one fragment anchor per PE-confirmed assumption (material property, boundary
      condition, load model, safety-factor selection)
  decision_provenance_log               — manifest field binding PE-stamp HMAC-attestations
                                          to each engineering-analysis verdict
  DispatchRecordWellformedCheck(op_kinds_admitted=frozenset({
      "FEA_SOLVE", "PE_STAMP", "COMPUTE"
  }))                                   — admits domain-specific op kinds for this pilot

Regulatory / credentialing anchors:
  California Board for Professional Engineers Land Surveyors & Geologists (CA-BPELSG)
  Texas Board of Professional Engineers and Land Surveyors (TX-TBPELS)
  Florida Board of Professional Engineers (FL-FBPE)
  NCEES Model Law — professional engineer standard of care and stamp liability.

Re-derivation primitive:
  σ_max = (P * L) * c / I  where c = height/2, I = (width * height^3) / 12
  factor_of_safety = yield_stress_Pa / σ_max
  verdict = "pass" if FoS >= safety_factor else "fail"

Usage (from v-kernel-audit-bundle root):
    python examples/pe_engineering_signoff_minimal/_build_bundle.py --out-dir /tmp/pe_engineering_signoff_bundle

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import hashlib
import hmac as _hmac
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.emitter import BundleContent, write_bundle
from audit_bundle.fragments.fragment_id import (
    OpaqueFragment,
    fragment_to_canonical_dict,
)

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "pe-engineering-signoff-minimal-rc"
_CREATED_AT = "2026-05-19T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
    "pe_engineering_signoff_re_derivation",
    "dispatch_record_wellformed",
]

# -----------------------------------------------------------------------
# Synthetic HMAC key for PE-stamp attestation — kept in bundle for re-verify.
# In production this would be a HSM-backed key tied to the PE's PKI certificate
# (e.g. NCEES Record + state-board-issued certificate); for the demo pilot it is
# a deterministic synthetic secret that the bundle carries so the verifier can
# re-compute every attestation HMAC from first principles.
# -----------------------------------------------------------------------
_ATTESTATION_KEY = b"synthetic-pe-stamp-key-ncees-state-board-2026-05-19"

# -----------------------------------------------------------------------
# Synthetic cantilever-beam analyses — 3 cases
# Each captures: length_m, load_N, cross_section, material
# -----------------------------------------------------------------------
_ANALYSES: list[dict] = [
    {
        "analysis_id": "ANL-2026-001",
        "description": "Steel W-section cantilever — overhead crane runway beam",
        "length_m": 3.5,
        "load_N": 45000.0,
        "cross_section": {
            "height_m": 0.254,
            "width_m": 0.102,
        },
        "material": {
            "name": "ASTM_A992_steel",
            "E_GPa": 200.0,
            "yield_stress_MPa": 345.0,
            "safety_factor": 1.67,
        },
    },
    {
        "analysis_id": "ANL-2026-002",
        "description": "Aluminum extrusion cantilever — solar panel mounting arm",
        "length_m": 1.2,
        "load_N": 800.0,
        "cross_section": {
            "height_m": 0.060,
            "width_m": 0.040,
        },
        "material": {
            "name": "6061-T6_aluminum",
            "E_GPa": 68.9,
            "yield_stress_MPa": 276.0,
            "safety_factor": 2.0,
        },
    },
    {
        "analysis_id": "ANL-2026-003",
        "description": "A36 steel cantilever — proposed sign structure (refused: load model incomplete)",
        "length_m": 5.0,
        "load_N": 12000.0,
        "cross_section": {
            "height_m": 0.150,
            "width_m": 0.080,
        },
        "material": {
            "name": "ASTM_A36_steel",
            "E_GPa": 200.0,
            "yield_stress_MPa": 250.0,
            "safety_factor": 2.0,
        },
    },
]

# -----------------------------------------------------------------------
# Synthetic PE roster — one PE per analysis
# pe_license_id format: {STATE}-PE-{DISCIPLINE_PREFIX}{NUMBER}
# -----------------------------------------------------------------------
_PE_ROSTER: list[dict] = [
    {
        "pe_license_id": "CA-PE-S12345",
        "state_board_code": "CA-BPELSG",
        "license_expiration": "2027-06-30",
        "pe_name_abbrev": "J. Harrington, PE",
    },
    {
        "pe_license_id": "TX-PE-E98765",
        "state_board_code": "TX-TBPELS",
        "license_expiration": "2027-09-30",
        "pe_name_abbrev": "M. Okonkwo, PE",
    },
    {
        "pe_license_id": "FL-PE-A45678",
        "state_board_code": "FL-FBPE",
        "license_expiration": "2027-12-31",
        "pe_name_abbrev": "S. Ramirez, PE",
    },
]

# Stamp verdicts — cover all three required states:
#   stamped_unconditional, stamped_with_limitations, refused
_STAMP_VERDICTS: list[str] = [
    "stamped_unconditional",
    "stamped_with_limitations",
    "refused",
]

_LIMITATIONS: list[list[str]] = [
    [],  # unconditional — no limitations
    [
        "Analysis assumes uniform load distribution; field measurements required before fabrication",
        "Material certificate required; assumed 6061-T6 grade not verified against supplied stock",
    ],
    [
        "Stamp refused: wind load model is incomplete — dynamic gust factors not computed",
        "Stamp refused: connection detail at wall bracket not included in analysis scope",
    ],
]

_STAMP_TIMESTAMPS: list[str] = [
    "2026-05-19T09:00:00Z",
    "2026-05-19T09:15:00Z",
    "2026-05-19T09:30:00Z",
]


# -----------------------------------------------------------------------
# Re-derivation logic (mirrored in pe_engineering_signoff_re_derivation.py)
# -----------------------------------------------------------------------


def _compute_max_bending_stress(analysis: dict) -> float:
    """σ_max = (P * L) * c / I  for a rectangular cross section.

    c = height / 2 (distance from neutral axis to extreme fiber)
    I = (width * height^3) / 12  (second moment of area for rectangle)
    """
    P = analysis["load_N"]
    L = analysis["length_m"]
    h = analysis["cross_section"]["height_m"]
    w = analysis["cross_section"]["width_m"]
    c = h / 2.0
    I = (w * h**3) / 12.0
    return (P * L * c) / I


def _compute_factor_of_safety(analysis: dict, max_stress_pa: float) -> float:
    """FoS = yield_stress_Pa / sigma_max"""
    yield_stress_pa = analysis["material"]["yield_stress_MPa"] * 1e6
    return yield_stress_pa / max_stress_pa


def _compute_verdict(analysis: dict, fos: float) -> str:
    return "pass" if fos >= analysis["material"]["safety_factor"] else "fail"


def _compute_analysis_summary_hash(analysis_output: dict) -> str:
    """SHA-256 of the canonical JSON of the analysis output the PE stamp covers."""
    canonical = json.dumps(analysis_output, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _compute_stamp_hmac(
    pe_license_id: str,
    state_board_code: str,
    license_expiration: str,
    analysis_id: str,
    analysis_summary_hash: str,
    stamp_verdict: str,
    limitations_list: list[str],
    stamp_timestamp: str,
    key: bytes,
) -> str:
    """HMAC-SHA256 of canonical-JSON of the 8-field stamp payload."""
    payload = {
        "analysis_id": analysis_id,
        "analysis_summary_hash": analysis_summary_hash,
        "license_expiration": license_expiration,
        "limitations_list": limitations_list,
        "pe_license_id": pe_license_id,
        "stamp_timestamp": stamp_timestamp,
        "stamp_verdict": stamp_verdict,
        "state_board_code": state_board_code,
    }
    msg = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _hmac.new(key, msg, hashlib.sha256).hexdigest()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# -----------------------------------------------------------------------
# Bundle builder
# -----------------------------------------------------------------------


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Build inputs/analyses.json bytes
    # ------------------------------------------------------------------
    analyses_text = json.dumps(_ANALYSES, indent=2, sort_keys=True) + "\n"
    analyses_bytes = analyses_text.encode("utf-8")

    # ------------------------------------------------------------------
    # Build payload/attestation_key.hex bytes
    # ------------------------------------------------------------------
    key_hex = _ATTESTATION_KEY.hex()
    attestation_key_bytes = (key_hex + "\n").encode("utf-8")

    # ------------------------------------------------------------------
    # Compute analysis outputs + build PE stamp provenance log
    # ------------------------------------------------------------------
    analysis_outputs: list[dict] = []
    provenance_rows: list[dict] = []

    for i, analysis in enumerate(_ANALYSES):
        max_stress_pa = _compute_max_bending_stress(analysis)
        fos = _compute_factor_of_safety(analysis, max_stress_pa)
        structural_verdict = _compute_verdict(analysis, fos)

        analysis_output = {
            "analysis_id": analysis["analysis_id"],
            "max_bending_stress_Pa": max_stress_pa,
            "factor_of_safety": fos,
            "structural_verdict": structural_verdict,
        }
        analysis_outputs.append(analysis_output)

        pe = _PE_ROSTER[i]
        stamp_verdict = _STAMP_VERDICTS[i]
        limitations_list = _LIMITATIONS[i]
        stamp_timestamp = _STAMP_TIMESTAMPS[i]

        analysis_summary_hash = _compute_analysis_summary_hash(analysis_output)

        attest_hmac = _compute_stamp_hmac(
            pe_license_id=pe["pe_license_id"],
            state_board_code=pe["state_board_code"],
            license_expiration=pe["license_expiration"],
            analysis_id=analysis["analysis_id"],
            analysis_summary_hash=analysis_summary_hash,
            stamp_verdict=stamp_verdict,
            limitations_list=limitations_list,
            stamp_timestamp=stamp_timestamp,
            key=_ATTESTATION_KEY,
        )

        provenance_rows.append(
            {
                "analysis_id": analysis["analysis_id"],
                "pe_license_id": pe["pe_license_id"],
                "state_board_code": pe["state_board_code"],
                "license_expiration": pe["license_expiration"],
                "analysis_summary_hash": analysis_summary_hash,
                "stamp_verdict": stamp_verdict,
                "limitations_list": limitations_list,
                "stamp_timestamp": stamp_timestamp,
                "attestation_hmac": attest_hmac,
            }
        )

    # Build payload/engineering_analyses.json bytes
    eng_analyses_text = json.dumps(analysis_outputs, indent=2, sort_keys=True) + "\n"
    eng_analyses_bytes = eng_analyses_text.encode("utf-8")

    # Build payload/pe_stamp_provenance.jsonl bytes
    provenance_lines = [json.dumps(row, sort_keys=True) for row in provenance_rows]
    provenance_text = "\n".join(provenance_lines) + "\n"
    provenance_bytes = provenance_text.encode("utf-8")

    # ------------------------------------------------------------------
    # OpaqueFragment anchors — one per PE-confirmed engineering assumption
    # kind_tag="engineering_assumption"; locator = {assumption_id, analysis_id}
    # source_cid derived from inputs/analyses.json SHA
    # ------------------------------------------------------------------
    analyses_cid = f"sha256:{_sha256(analyses_bytes)}"
    fragment_anchors: dict[str, dict] = {}

    for analysis in _ANALYSES:
        aid = analysis["analysis_id"]

        # Anchor each material property as an engineering assumption
        for prop in ["E_GPa", "yield_stress_MPa", "safety_factor"]:
            assumption_id = f"{aid}-material-{prop}"
            frag = OpaqueFragment(
                source_cid=analyses_cid,
                kind_tag="engineering_assumption",
                locator={
                    "assumption_id": assumption_id,
                    "analysis_id": aid,
                    "assumption_type": "material_property",
                    "property": prop,
                    "value": str(analysis["material"][prop]),
                },
            )
            fragment_anchors[assumption_id] = fragment_to_canonical_dict(frag)

        # Anchor the load model as an engineering assumption
        assumption_id = f"{aid}-load-model"
        frag = OpaqueFragment(
            source_cid=analyses_cid,
            kind_tag="engineering_assumption",
            locator={
                "assumption_id": assumption_id,
                "analysis_id": aid,
                "assumption_type": "load_model",
                "load_N": str(analysis["load_N"]),
                "load_type": "point_load_at_tip",
            },
        )
        fragment_anchors[assumption_id] = fragment_to_canonical_dict(frag)

        # Anchor boundary condition (fixed cantilever) as an engineering assumption
        assumption_id = f"{aid}-boundary-condition"
        frag = OpaqueFragment(
            source_cid=analyses_cid,
            kind_tag="engineering_assumption",
            locator={
                "assumption_id": assumption_id,
                "analysis_id": aid,
                "assumption_type": "boundary_condition",
                "condition": "fixed_cantilever_at_root",
            },
        )
        fragment_anchors[assumption_id] = fragment_to_canonical_dict(frag)

    assert len(fragment_anchors) >= 5, (
        f"Expected >= 5 OpaqueFragment anchors; got {len(fragment_anchors)}"
    )

    # ------------------------------------------------------------------
    # dispatch_records — three op kinds exercising C15
    # COMPUTE: fixture prep / metadata
    # FEA_SOLVE: the engineering-stress computation step (one per analysis)
    # PE_STAMP: the PE-stamp attestation binding step (one per analysis)
    # ------------------------------------------------------------------
    dispatch_records = [
        {
            "schema_version": "0.1",
            "op": {
                "kind": "COMPUTE",
                "name": "pe_engineering_fixture_prep",
            },
            "inputs": [],
            "outputs": [],
            "effect": {},
            "locale": "en-US",
            "predicates": [],
            "stamp_declared": "INTERNAL_BENCHMARK",
            "stamp_observed": None,
        },
    ]

    for analysis in _ANALYSES:
        dispatch_records.append(
            {
                "schema_version": "0.1",
                "op": {
                    "kind": "FEA_SOLVE",
                    "name": f"cantilever_bending_stress_{analysis['analysis_id']}",
                },
                "inputs": [],
                "outputs": [],
                "effect": {},
                "locale": "en-US",
                "predicates": [],
                "stamp_declared": "INTERNAL_BENCHMARK",
                "stamp_observed": None,
            }
        )
        dispatch_records.append(
            {
                "schema_version": "0.1",
                "op": {
                    "kind": "PE_STAMP",
                    "name": f"pe_attestation_binding_{analysis['analysis_id']}",
                },
                "inputs": [],
                "outputs": [],
                "effect": {},
                "locale": "en-US",
                "predicates": [],
                "stamp_declared": "INTERNAL_BENCHMARK",
                "stamp_observed": None,
            }
        )

    # ------------------------------------------------------------------
    # Emit via the reference-emitter SDK (scaffold + digests + manifest).
    # decision_provenance_log references the JSONL path relative to bundle root
    # ------------------------------------------------------------------
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "inputs/analyses.json": analyses_bytes,
            "payload/engineering_analyses.json": eng_analyses_bytes,
            "payload/pe_stamp_provenance.jsonl": provenance_bytes,
            "payload/attestation_key.hex": attestation_key_bytes,
        },
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=_TYPED_CHECKS,
        extra_manifest_fields={
            "fragment_anchors": fragment_anchors,
            "dispatch_records": dispatch_records,
            "decision_provenance_log": "payload/pe_stamp_provenance.jsonl",
        },
    )
    write_bundle(out_dir, content)

    print(f"Bundle written to {out_dir}")
    print(f"  cantilever analyses  : {len(_ANALYSES)}")
    print(f"  analysis outputs     : {len(analysis_outputs)}")
    print(f"  provenance rows      : {len(provenance_rows)}")
    print(
        f"  fragment anchors     : {len(fragment_anchors)} OpaqueFragment (kind_tag=engineering_assumption)"
    )
    print(
        f"  dispatch records     : {len(dispatch_records)} (COMPUTE + FEA_SOLVE×3 + PE_STAMP×3)"
    )
    print(f"  stamp verdicts       : {[r['stamp_verdict'] for r in provenance_rows]}")
    print(f"  manifest             : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic pe_engineering_signoff_minimal audit bundle"
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        type=Path,
        help="Destination directory (created if absent)",
    )
    args = parser.parse_args()
    try:
        out_dir = args.out_dir.resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        build(out_dir)
    except AssertionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
