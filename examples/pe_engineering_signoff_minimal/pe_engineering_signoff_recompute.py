"""pe_engineering_signoff_recompute.py — verifier-side structural-signoff re-derivation primitive.

Axis-2 value-return form (SPEC_PINNED_DISPATCH_ARCHITECTURE §3.3). Self-contained
per-dir migration of the pe_engineering_signoff_minimal pilot onto spec-pinned
dispatch: the recompute primitive lives HERE (verifier-distribution code, registered
by the spec-pinned builder), NOT in audit_bundle/rederivation/primitives/.

Re-derivation primitive (one sentence):
    For each committed cantilever-beam analysis in inputs/analyses.json (in committed
    order), recompute sigma_max = (P * L) * c / I (c = height/2, I = width*height^3/12),
    factor_of_safety = yield_stress_Pa / sigma_max, and emit the CATEGORICAL verdict
    "pass" if FoS >= material.safety_factor else "fail" — the ordered verdict list.

over the committed analysis inputs (inputs/analyses.json) in the bundle. The bending
formula, the FoS ratio, and the pass/fail threshold rule are FIXED in this primitive —
the primitive_id ("pe_engineering_signoff_recompute") IS the rule. The auditor's
SHA-pinned spec binds the output type "pe_engineering_signoff_verdicts" to this
primitive_id and to an `exact` comparator (no params; an ordered list of primitive
strings compared element-wise). The FoS is a float, but the pinned representative
output is the categorical verdict list (exact-safe); the bundle's HMAC PE-stamp
attestation half is deliberately out of scope here. A producer cannot weaken the
threshold rule without changing the primitive_id, which the anchor rejects.

Stdlib-only (§C5 contract). This module is importable WITHOUT audit_bundle on
sys.path (the RecomputedValue import is deferred into recompute()), so the
spec-pinned builder can import compute_structural_verdicts() standalone.
"""

from __future__ import annotations

import json
from pathlib import Path


# ---------------------------------------------------------------------------
# Canonical computation (shared by the builder and the verifier — ONE source)
# ---------------------------------------------------------------------------


def _max_bending_stress(analysis: dict) -> float:
    """sigma_max = (P * L) * c / I for a rectangular cross section.

    c = height / 2 (distance from neutral axis to extreme fiber)
    I = (width * height^3) / 12 (second moment of area for rectangle)
    """
    P = analysis["load_N"]
    L = analysis["length_m"]
    h = analysis["cross_section"]["height_m"]
    w = analysis["cross_section"]["width_m"]
    c = h / 2.0
    I = (w * h**3) / 12.0
    return (P * L * c) / I


def _factor_of_safety(analysis: dict, max_stress_pa: float) -> float:
    """FoS = yield_stress_Pa / sigma_max."""
    yield_stress_pa = analysis["material"]["yield_stress_MPa"] * 1e6
    return yield_stress_pa / max_stress_pa


def compute_structural_verdicts(analyses: list) -> list[str]:
    """Canonical re-derivation of the ordered structural_verdict list. Mirrors the
    legacy pack's pe_engineering_signoff_re_derivation per-analysis verdict
    computation EXACTLY: for each analysis (in committed input order) recompute
    sigma_max, FoS, and the categorical verdict, threshold FoS >= safety_factor.

    Builder and verifier share this ONE definition so the honest claimed verdict
    list and the re-derivation cannot drift.

    Fail-closed: raises KeyError/TypeError/ZeroDivisionError if an analysis is
    missing required geometry/load/material fields or is otherwise malformed (the
    verifier must not invent a verdict).
    """
    if not isinstance(analyses, list):
        raise TypeError("inputs/analyses.json top-level must be a list of analyses")
    verdicts: list[str] = []
    for analysis in analyses:
        stress = _max_bending_stress(analysis)
        fos = _factor_of_safety(analysis, stress)
        verdict = "pass" if fos >= analysis["material"]["safety_factor"] else "fail"
        verdicts.append(verdict)
    return verdicts


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered before BundleVerifier)
# ---------------------------------------------------------------------------


class PeEngineeringSignoffRecompute:
    """Verifier-side primitive for re-deriving the ordered structural_verdict list."""

    primitive_id: str = "pe_engineering_signoff_recompute"

    def recompute(self, inputs, pack_section: dict):
        """Recompute the ordered structural_verdict list from the committed analysis
        inputs.

        inputs.bundle_dir is a read-only Path. pack_section carries
        {output_id, type, params} from the auditor's spec binding. Returns a
        RecomputedValue carrying the ordered list of categorical verdicts; the
        verifier's `exact` comparator compares it element-wise to the claimed value.
        """
        # Deferred import keeps this module importable standalone (builder use).
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        bundle_dir: Path = inputs.bundle_dir

        analyses_path = bundle_dir / "inputs" / "analyses.json"
        if not analyses_path.is_file():
            raise FileNotFoundError(
                f"inputs/analyses.json not found in bundle at {bundle_dir}"
            )
        analyses = json.loads(analyses_path.read_bytes())
        if not isinstance(analyses, list):
            raise ValueError("inputs/analyses.json: top-level must be a list")

        value = compute_structural_verdicts(analyses)
        return RecomputedValue(
            value=value,
            detail=(
                f"re-derived structural_verdict list ({len(value)} analyses) "
                f"from inputs/analyses.json: {value}"
            ),
        )
