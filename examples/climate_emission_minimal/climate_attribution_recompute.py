"""climate_attribution_recompute.py — verifier-side per-vendor Scope-3
attribution re-derivation primitive (NEW in-dir primitive; does NOT collide
with the central audit_bundle/rederivation/primitives/climate_emission.py
"climate_emission_recompute", which returns the scalar total under `exact`).

Axis-2 value-return form (SPEC_PINNED_DISPATCH_ARCHITECTURE §3.3). Self-contained
per-dir migration of the climate_emission_minimal pilot onto spec-pinned
dispatch. The recompute primitive lives HERE (verifier-distribution code,
registered by the spec-pinned builder), NOT in audit_bundle/rederivation/.

Representative output: the per-vendor emission attribution LIST. Each record has
EXACTLY the allowlisted climate_attribution_v1 fields:
    {vendor_id, tier, attributed_kg_co2e}
where attributed_kg_co2e = round(activity_amount * emission_factor_kg_co2e_per_unit, 6).

`tier` is NOT derived — every supplier in inputs/supplier_chain.json carries an
explicit integer `tier` field (1..4), so it is read verbatim from the committed
evidence. vendor_id is read verbatim. The list is produced in supplier-chain
list order; the structured comparator compares the 3 fields field-wise over the
list in that order.

Stdlib-only (§C5 contract). This module is importable WITHOUT audit_bundle on
sys.path (the RecomputedValue import is deferred into recompute()), so the
spec-pinned builder can import compute_attribution() standalone.
"""

from __future__ import annotations

import json
from pathlib import Path


# ---------------------------------------------------------------------------
# Canonical computation (shared by the builder and the verifier — ONE source)
# ---------------------------------------------------------------------------


def compute_attribution(supplier_chain: list) -> list:
    """Canonical per-vendor Scope-3 attribution list. For each supplier in list
    order, produce a record with exactly the climate_attribution_v1 fields:
    {vendor_id, tier, attributed_kg_co2e=round(activity*factor, 6)}.

    `tier` is read verbatim from the supplier's explicit committed `tier` field
    (no derivation). Builder and verifier share this ONE definition so the honest
    claimed list and the re-derivation cannot drift.

    Raises ValueError on empty input.
    """
    if not supplier_chain:
        raise ValueError("supplier_chain is empty — cannot compute attribution")
    records = []
    for s in supplier_chain:
        attributed = round(
            float(s["activity_amount"]) * float(s["emission_factor_kg_co2e_per_unit"]),
            6,
        )
        records.append(
            {
                "vendor_id": s["vendor_id"],
                "tier": s["tier"],
                "attributed_kg_co2e": attributed,
            }
        )
    return records


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered by the spec-pinned builder before verify)
# ---------------------------------------------------------------------------


class ClimateAttributionRecompute:
    """Verifier-side primitive re-deriving the per-vendor attribution list."""

    primitive_id: str = "climate_attribution_recompute"

    def recompute(self, inputs, pack_section: dict):
        """Recompute the attribution list from inputs/supplier_chain.json.

        inputs.bundle_dir is a read-only Path. pack_section carries
        {output_id, type, params} from the auditor's spec binding. Returns a
        RecomputedValue carrying the list; the verifier's structured comparator
        compares it field-wise against the producer's claimed list.
        """
        # Deferred import keeps this module importable standalone (builder use).
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        bundle_dir: Path = inputs.bundle_dir
        chain_path = bundle_dir / "inputs" / "supplier_chain.json"
        if not chain_path.is_file():
            raise FileNotFoundError(
                f"inputs/supplier_chain.json not found in bundle at {bundle_dir}"
            )
        supplier_chain = json.loads(chain_path.read_bytes())
        if not isinstance(supplier_chain, list):
            raise ValueError("inputs/supplier_chain.json must be a JSON array")
        records = compute_attribution(supplier_chain)
        return RecomputedValue(
            value=records,
            detail=f"re-derived per-vendor attribution over {len(records)} supplier(s)",
        )
