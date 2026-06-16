"""dc_emissions_mrv_recompute.py — verifier-side embodied-carbon re-derivation primitive.

Axis-2 value-return form (SPEC_PINNED_DISPATCH_ARCHITECTURE §3.3). Self-contained
per-dir migration of the dc_emissions_mrv pilot onto spec-pinned dispatch: the
recompute primitive lives HERE (verifier-distribution code, registered by
verify.py / the spec-pinned builder), NOT in audit_bundle/rederivation/primitives/.

Re-derivation primitive (one sentence):
    total_embodied_kg_co2e = round(sum over materials of
        round(quantity * emission_factor_kg_co2e_per_unit, 6), 6)

over inputs/embodied_carbon_inventory.json. The aggregation rule (per-row 6dp
round, summed in list order, total 6dp round) is FIXED in this primitive — the
primitive_id ("dc_emissions_mrv_embodied_recompute") IS the rule. The auditor's
SHA-pinned spec binds the output type "dc_embodied_carbon_total" to this
primitive_id and to a scalar_epsilon comparator; a producer cannot weaken the
aggregation without changing the primitive_id, which the anchor would reject.

Stdlib-only (§C5 contract). This module is importable WITHOUT audit_bundle on
sys.path (the RecomputedValue import is deferred into recompute()), so the
spec-pinned builder can import compute_embodied_total() standalone.
"""

from __future__ import annotations

import json
from pathlib import Path


# ---------------------------------------------------------------------------
# Canonical computation (shared by the builder and the verifier — ONE source)
# ---------------------------------------------------------------------------


def compute_embodied_total(materials: list) -> float:
    """Canonical embodied-carbon total. Mirrors the legacy pack's
    _compute_embodied_carbon: per-material round(quantity*EF, 6), summed in list
    order, total rounded to 6dp. Builder and verifier share this ONE definition
    so the honest claimed total and the re-derivation cannot drift.

    Raises ValueError on empty input.
    """
    if not materials:
        raise ValueError("embodied_carbon_inventory is empty — cannot compute total")
    total = 0.0
    for m in materials:
        total += round(
            float(m["quantity"]) * float(m["emission_factor_kg_co2e_per_unit"]),
            6,
        )
    return round(total, 6)


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered by verify.py before BundleVerifier)
# ---------------------------------------------------------------------------


class DcEmissionsMrvEmbodiedRecompute:
    """Verifier-side primitive for re-deriving the total embodied carbon."""

    primitive_id: str = "dc_emissions_mrv_embodied_recompute"

    def recompute(self, inputs, pack_section: dict):
        """Recompute total embodied carbon from inputs/embodied_carbon_inventory.json.

        inputs.bundle_dir is a read-only Path. pack_section carries
        {output_id, type, params} from the auditor's spec binding. Returns a
        RecomputedValue carrying the scalar; the verifier's comparator compares.
        """
        # Deferred import keeps this module importable standalone (builder use).
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        bundle_dir: Path = inputs.bundle_dir
        inv_path = bundle_dir / "inputs" / "embodied_carbon_inventory.json"
        if not inv_path.is_file():
            raise FileNotFoundError(
                f"inputs/embodied_carbon_inventory.json not found in bundle at {bundle_dir}"
            )
        materials = json.loads(inv_path.read_bytes())
        if not isinstance(materials, list):
            raise ValueError(
                "inputs/embodied_carbon_inventory.json must be a JSON array"
            )
        value = compute_embodied_total(materials)
        return RecomputedValue(
            value=value,
            detail=f"re-derived total embodied carbon over {len(materials)} material(s)",
        )
