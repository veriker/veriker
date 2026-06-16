"""combi_screen_recompute.py — verifier-side combinatorial-screen advanced-set re-derivation primitive.

Axis-2 value-return form (SPEC_PINNED_DISPATCH_ARCHITECTURE §3.3). Self-contained
per-dir migration of the combi_screen_minimal pilot onto spec-pinned dispatch: the
recompute primitive lives HERE (verifier-distribution code, registered by the
spec-pinned builder), NOT in audit_bundle/rederivation/primitives/.

Re-derivation primitive (one sentence):
    advanced_set = the unordered set of compound_ids advanced after re-enumerating
    the Cartesian product (scaffolds x r_groups_1 x r_groups_2), re-applying the
    Lipinski filter, re-scoring survivors with the committed seeded surrogate
    scorer, ranking survivors ASCENDING by score (ties by compound_id), and taking
    the top-K (= payload advanced_count).

The enumeration + filter + score + rank MIRROR the legacy pack's _run_screen and
the builder's run_screen EXACTLY (combi_screen_re_derivation.py / _build_bundle.py):
deterministic scaffolds->r1->r2 nesting; mw/logp rounded to 4 dp; first-failing
Lipinski rule; score = sha256(compound_id + '|' + str(seed)) mapped into the
affinity range plus a property term, rounded to 6 dp; survivors sorted by
(score, compound_id) ascending; top-K advanced. The auditor's SHA-pinned spec binds
the output type "combi_screen_advanced_set" to this primitive_id and a `set`
comparator (no params — order-independent collection equality). A producer cannot
weaken the screen without changing the primitive_id, which the anchor would reject.

Stdlib-only (§C5 contract). This module is importable WITHOUT audit_bundle on
sys.path (the RecomputedValue import is deferred into recompute()), so the
spec-pinned builder can import compute_advanced_set() standalone.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


# ---------------------------------------------------------------------------
# Scoring helpers — byte-for-byte identical to _build_bundle.py / the legacy pack
# ---------------------------------------------------------------------------


def _sha256_hex(s: str) -> int:
    """Return the integer value of sha256(s.encode()) — for deterministic float mapping."""
    digest = hashlib.sha256(s.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big")


def _score_compound(
    compound_id: str,
    seed: int,
    affinity_lo: float,
    affinity_hi: float,
    property_weight: float,
    mw: float,
    logp: float,
) -> float:
    raw = _sha256_hex(compound_id + "|" + str(seed))
    norm = raw / (2**64)
    base_score = affinity_lo + norm * (affinity_hi - affinity_lo)
    prop_term = -(mw / 500.0) * 0.5 - (logp / 5.0) * 0.5
    return base_score + property_weight * prop_term


def _lipinski_status(mw: float, logp: float, hbd: int, hba: int, cfg: dict) -> str:
    if mw > cfg["mw_max"]:
        return "rejected:mw"
    if logp > cfg["logp_max"]:
        return "rejected:logp"
    if hbd > cfg["hbd_max"]:
        return "rejected:hbd"
    if hba > cfg["hba_max"]:
        return "rejected:hba"
    return "passed"


# ---------------------------------------------------------------------------
# Canonical computation (shared by the builder-side check and the verifier — ONE source)
# ---------------------------------------------------------------------------


def compute_advanced_set(
    scaffolds: list[dict],
    r_groups_1: list[dict],
    r_groups_2: list[dict],
    filter_cfg: dict,
    scoring_cfg: dict,
    top_k: int,
) -> list[str]:
    """Canonical advanced-set recompute. Mirrors the legacy run_screen pipeline
    (enumerate -> Lipinski filter -> seeded score -> rank ascending -> advance top-K)
    and returns the advanced compound_ids as a list. The `set` comparator compares it
    order-independently against the claimed collection.
    """
    seed = scoring_cfg["seed"]
    affinity_lo, affinity_hi = scoring_cfg["affinity_range_kcal_mol"]
    prop_weight = scoring_cfg["property_weight"]

    ledger: list[dict] = []

    # Enumerate: deterministic order scaffolds->r1->r2
    for scaf in scaffolds:
        for r1 in r_groups_1:
            for r2 in r_groups_2:
                compound_id = f"{scaf['id']}__{r1['id']}__{r2['id']}"
                mw = round(scaf["mw_contrib"] + r1["mw_contrib"] + r2["mw_contrib"], 4)
                logp = round(
                    scaf["logp_contrib"] + r1["logp_contrib"] + r2["logp_contrib"], 4
                )
                hbd = scaf["hbd_contrib"] + r1["hbd_contrib"] + r2["hbd_contrib"]
                hba = scaf["hba_contrib"] + r1["hba_contrib"] + r2["hba_contrib"]

                filter_status = _lipinski_status(mw, logp, hbd, hba, filter_cfg)

                if filter_status == "passed":
                    score = round(
                        _score_compound(
                            compound_id,
                            seed,
                            affinity_lo,
                            affinity_hi,
                            prop_weight,
                            mw,
                            logp,
                        ),
                        6,
                    )
                else:
                    score = None

                ledger.append(
                    {
                        "compound_id": compound_id,
                        "filter_status": filter_status,
                        "score": score,
                    }
                )

    # Sort survivors ASCENDING by score, ties by compound_id ascending.
    survivors = [
        (e["score"], e["compound_id"], i)
        for i, e in enumerate(ledger)
        if e["score"] is not None
    ]
    survivors.sort(key=lambda x: (x[0], x[1]))

    advanced_ids: list[str] = [cid for (_score, cid, _idx) in survivors[:top_k]]
    return advanced_ids


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered before BundleVerifier)
# ---------------------------------------------------------------------------


class CombiScreenRecompute:
    """Verifier-side primitive for re-deriving the advanced (top-K) compound id set."""

    primitive_id: str = "combi_screen_recompute"

    def recompute(self, inputs, pack_section: dict):
        """Recompute the advanced set from the committed building blocks + configs +
        the payload's advanced_count (top-K).

        inputs.bundle_dir is a read-only Path. pack_section carries
        {output_id, type, params} from the auditor's spec binding. Returns a
        RecomputedValue carrying the advanced compound_id list; the verifier's `set`
        comparator compares it order-independently to the claimed value.
        """
        # Deferred import keeps this module importable standalone (builder use).
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        bundle_dir: Path = inputs.bundle_dir

        def _load(rel: str) -> dict:
            p = bundle_dir / rel
            if not p.is_file():
                raise FileNotFoundError(f"{rel} not found in bundle at {bundle_dir}")
            return json.loads(p.read_text(encoding="utf-8"))

        bb = _load("inputs/building_blocks.json")
        filter_cfg = _load("inputs/filter_config.json")
        scoring_cfg = _load("inputs/scoring_config.json")
        result = _load("payload/combi_screen_result.json")

        top_k = int(result["advanced_count"])

        value = compute_advanced_set(
            scaffolds=bb["scaffolds"],
            r_groups_1=bb["r_groups_1"],
            r_groups_2=bb["r_groups_2"],
            filter_cfg=filter_cfg,
            scoring_cfg=scoring_cfg,
            top_k=top_k,
        )
        return RecomputedValue(
            value=value,
            detail=(
                f"re-derived advanced set: enumerated "
                f"{len(bb['scaffolds'])}x{len(bb['r_groups_1'])}x{len(bb['r_groups_2'])} "
                f"compounds, Lipinski-filtered, seeded-scored, ranked, advanced top-{top_k} "
                f"-> {sorted(value)!r}"
            ),
        )
