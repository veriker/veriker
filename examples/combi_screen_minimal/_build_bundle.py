"""_build_bundle.py — build a deterministic combi_screen_minimal audit bundle.

Combinatorial drug-discovery screening domain pilot: enumerate a compound library
from building blocks, filter via Lipinski rule-of-5, score survivors with a seeded
surrogate docking function, rank by predicted binding affinity, and advance the
top-K compounds. The audit bundle captures the COMPLETE screened-and-rejected ledger
— every compound examined, why each was rejected, what scored and what advanced.

Domain basis: Pagadala, Syed & Tuszynski (2017), "Software for molecular docking:
a review", Biophysical Reviews 9:91-102.
AutoDock Vina uses Monte Carlo + BFGS; this pilot commits a seed so the stochastic
step is deterministically re-derivable.

Re-derivation primitive (one sentence):
  Re-enumerate the combinatorial library as the Cartesian product of committed
  building-block lists, re-apply the Lipinski filter, re-score every survivor with
  the committed seeded scoring function, re-rank by predicted affinity, and assert
  the full pass/reject ledger AND the advanced top-K set match the payload.

HONEST FRAMING:
  - The scoring function is a DETERMINISTIC SYNTHETIC SURROGATE for a docking engine
    (AutoDock Vina class: Monte Carlo + BFGS), with the seed committed so the
    stochastic step is reproducible. It is NOT real docking and makes NO claim of
    physical binding accuracy.
  - What IS demonstrated: the selection-path receipt — the complete library, the
    filters applied, the scores, the ranking, the advanced set, and the COMPLETE
    reject ledger. "Show everything you looked at, not just what you published."
  - OUT OF SCOPE: whether an advanced compound actually binds.

Usage (from v-kernel-audit-bundle root):
    python examples/combi_screen_minimal/_build_bundle.py --out-dir /tmp/combi_screen_bundle

Outputs:
  <out-dir>/inputs/building_blocks.json     — scaffold + R-group library
  <out-dir>/inputs/filter_config.json       — Lipinski thresholds
  <out-dir>/inputs/scoring_config.json      — surrogate scorer parameters (incl. seed)
  <out-dir>/payload/combi_screen_result.json — full ledger + advanced set
  <out-dir>/manifest.json

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.emitter import BundleContent, write_bundle
from audit_bundle.fragments.fragment_id import (
    OpaqueFragment,
    fragment_to_canonical_dict,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "combi-screen-minimal-rc"
_CREATED_AT = "2026-05-24T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
    "combi_screen_re_derivation",
    "dispatch_record_wellformed",
]

_TARGET_ID = "NEXI-T-XPA-ERCC1"
_TOP_K = 10

# ---------------------------------------------------------------------------
# Building blocks: 5 scaffolds x 6 R1 x 5 R2 = 150 enumerated compounds
# Each block: {"id", "smiles_fragment", "mw_contrib", "logp_contrib",
#              "hbd_contrib", "hba_contrib"}
# Values are synthetic but structurally plausible (drug-like ranges).
# ---------------------------------------------------------------------------

_SCAFFOLDS = [
    {
        "id": "SCAF-01",
        "smiles_fragment": "c1ccc2ncccc2c1",
        "mw_contrib": 129.16,
        "logp_contrib": 2.1,
        "hbd_contrib": 0,
        "hba_contrib": 1,
    },
    {
        "id": "SCAF-02",
        "smiles_fragment": "C1CCNCC1",
        "mw_contrib": 85.15,
        "logp_contrib": 0.3,
        "hbd_contrib": 1,
        "hba_contrib": 1,
    },
    {
        "id": "SCAF-03",
        "smiles_fragment": "c1ccc(cc1)C(=O)",
        "mw_contrib": 119.12,
        "logp_contrib": 1.8,
        "hbd_contrib": 0,
        "hba_contrib": 1,
    },
    {
        "id": "SCAF-04",
        "smiles_fragment": "C1CN(CCO1)",
        "mw_contrib": 87.12,
        "logp_contrib": -0.5,
        "hbd_contrib": 0,
        "hba_contrib": 2,
    },
    {
        "id": "SCAF-05",
        "smiles_fragment": "c1ccncc1",
        "mw_contrib": 79.10,
        "logp_contrib": 0.6,
        "hbd_contrib": 0,
        "hba_contrib": 1,
    },
]

_R_GROUPS_1 = [
    {
        "id": "R1-01",
        "smiles_fragment": "CC(=O)N",
        "mw_contrib": 57.05,
        "logp_contrib": -0.5,
        "hbd_contrib": 1,
        "hba_contrib": 1,
    },
    {
        "id": "R1-02",
        "smiles_fragment": "c1ccc(F)cc1",
        "mw_contrib": 95.10,
        "logp_contrib": 1.9,
        "hbd_contrib": 0,
        "hba_contrib": 0,
    },
    {
        "id": "R1-03",
        "smiles_fragment": "CC(C)OC",
        "mw_contrib": 73.11,
        "logp_contrib": 0.8,
        "hbd_contrib": 0,
        "hba_contrib": 1,
    },
    {
        "id": "R1-04",
        "smiles_fragment": "NCC(=O)O",
        "mw_contrib": 75.07,
        "logp_contrib": -1.0,
        "hbd_contrib": 2,
        "hba_contrib": 2,
    },
    {
        "id": "R1-05",
        "smiles_fragment": "CSc1ccccc1",
        "mw_contrib": 124.18,
        "logp_contrib": 2.8,
        "hbd_contrib": 0,
        "hba_contrib": 0,
    },
    {
        "id": "R1-06",
        "smiles_fragment": "C(F)(F)F",
        "mw_contrib": 68.02,
        "logp_contrib": 1.1,
        "hbd_contrib": 0,
        "hba_contrib": 0,
    },
]

_R_GROUPS_2 = [
    {
        "id": "R2-01",
        "smiles_fragment": "OCC",
        "mw_contrib": 45.06,
        "logp_contrib": -0.6,
        "hbd_contrib": 1,
        "hba_contrib": 1,
    },
    {
        "id": "R2-02",
        "smiles_fragment": "C(=O)OH",
        "mw_contrib": 44.03,
        "logp_contrib": -1.2,
        "hbd_contrib": 1,
        "hba_contrib": 2,
    },
    {
        "id": "R2-03",
        "smiles_fragment": "CN(C)",
        "mw_contrib": 43.07,
        "logp_contrib": 0.5,
        "hbd_contrib": 0,
        "hba_contrib": 1,
    },
    {
        "id": "R2-04",
        "smiles_fragment": "c1ccc(Cl)cc1",
        "mw_contrib": 111.55,
        "logp_contrib": 2.6,
        "hbd_contrib": 0,
        "hba_contrib": 0,
    },
    {
        "id": "R2-05",
        "smiles_fragment": "OCCO",
        "mw_contrib": 61.06,
        "logp_contrib": -1.5,
        "hbd_contrib": 2,
        "hba_contrib": 2,
    },
]

# ---------------------------------------------------------------------------
# Filter config (Lipinski rule-of-5)
# ---------------------------------------------------------------------------

_FILTER_CONFIG = {
    "mw_max": 500.0,
    "logp_max": 5.0,
    "hbd_max": 5,
    "hba_max": 10,
}

# ---------------------------------------------------------------------------
# Scoring config (surrogate docking parameters)
# ---------------------------------------------------------------------------

_SCORING_SEED = 8191
_SCORING_CONFIG = {
    "engine_surrogate": "vina_like_v0",
    "seed": _SCORING_SEED,
    "affinity_range_kcal_mol": [-12.0, -4.0],
    "property_weight": 0.05,
}

# ---------------------------------------------------------------------------
# PK config (stage 6: deterministic rule-based ADMET stand-in)
#
# HONEST FRAMING: not a real PK simulator. Transparent linear-coefficient
# formulas on top of the same molecular descriptors (MW, logP, HBD, HBA).
# Same honesty model as stage 3 — committed, reproducible, no claim of
# physiological accuracy. Production swap → ADMET-AI / DeepPK (determinism
# mode + committed weights) or a PBPK simulator (PK-Sim, etc.) given a
# committed seed.
# ---------------------------------------------------------------------------

_PK_CONFIG = {
    "predictor": "rule_based_admet_v0",
    "cl_base": 5.0,
    "cl_logp_coef": 2.5,
    "cl_mw_coef": 0.3,
    "cl_min": 0.5,
    "cl_max": 25.0,
    "vd_base": 0.8,
    "vd_logp_coef": 0.6,
    "vd_min": 0.3,
    "vd_max": 10.0,
    "f_intercept": 0.85,
    "f_mw_coef": 0.12,
    "f_hb_coef": 0.04,
    "f_logp_coef": 0.08,
    "f_logp_optimum_cap": 3.0,
    "admet_favorable_f_min": 0.5,
    "admet_favorable_t_half_min_h": 1.0,
    "admet_favorable_t_half_max_h": 24.0,
    "admet_favorable_cl_max": 15.0,
    "admet_unfavorable_f_max": 0.2,
    "admet_unfavorable_t_half_min_h": 0.5,
    "admet_unfavorable_t_half_max_h": 48.0,
    "admet_unfavorable_cl_min": 20.0,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
    """Deterministic surrogate docking score (kcal/mol).

    Maps sha256(compound_id + '|' + str(seed)) to [affinity_lo, affinity_hi],
    then adds a small deterministic property term. Lower (more negative) = stronger
    binding (AutoDock Vina convention). 100% stdlib-only.
    """
    raw = _sha256_hex(compound_id + "|" + str(seed))
    # Normalize to [0, 1)
    norm = raw / (2**64)
    # Map to affinity range
    base_score = affinity_lo + norm * (affinity_hi - affinity_lo)
    # Deterministic property term: lower MW + lower logP = slightly better score
    prop_term = -(mw / 500.0) * 0.5 - (logp / 5.0) * 0.5
    return base_score + property_weight * prop_term


def _lipinski_status(mw: float, logp: float, hbd: int, hba: int, cfg: dict) -> str:
    """Return 'passed' or 'rejected:<first-failing-rule>'."""
    if mw > cfg["mw_max"]:
        return "rejected:mw"
    if logp > cfg["logp_max"]:
        return "rejected:logp"
    if hbd > cfg["hbd_max"]:
        return "rejected:hbd"
    if hba > cfg["hba_max"]:
        return "rejected:hba"
    return "passed"


def _predict_pk(mw: float, logp: float, hbd: int, hba: int, cfg: dict) -> dict:
    """Deterministic rule-based ADMET stand-in (stage 6).

    Transparent linear coefficients over (MW, logP, HBD, HBA). Not a real PK
    simulator. Same honesty model as the docking stand-in at stage 3.
    100% stdlib-only.
    """
    cl_pred = (
        cfg["cl_base"]
        + cfg["cl_logp_coef"] * max(0.0, logp)
        - cfg["cl_mw_coef"] * (mw / 100.0)
    )
    cl_pred = max(cfg["cl_min"], min(cfg["cl_max"], cl_pred))

    vd_pred = cfg["vd_base"] + cfg["vd_logp_coef"] * logp
    vd_pred = max(cfg["vd_min"], min(cfg["vd_max"], vd_pred))

    # t_half (h) = 0.693 * Vd(L/kg) * 1000 / (CL(mL/min/kg) * 60)
    t_half = 0.693 * vd_pred * 1000.0 / (cl_pred * 60.0)

    logp_for_f = max(0.0, min(logp, cfg["f_logp_optimum_cap"]))
    f_oral = (
        cfg["f_intercept"]
        - cfg["f_mw_coef"] * (mw / 100.0)
        - cfg["f_hb_coef"] * (hbd + hba)
        + cfg["f_logp_coef"] * logp_for_f
    )
    f_oral = max(0.05, min(0.95, f_oral))

    if (
        f_oral >= cfg["admet_favorable_f_min"]
        and cfg["admet_favorable_t_half_min_h"]
        <= t_half
        <= cfg["admet_favorable_t_half_max_h"]
        and cl_pred <= cfg["admet_favorable_cl_max"]
    ):
        flag = "favorable"
    elif (
        f_oral < cfg["admet_unfavorable_f_max"]
        or t_half < cfg["admet_unfavorable_t_half_min_h"]
        or t_half > cfg["admet_unfavorable_t_half_max_h"]
        or cl_pred > cfg["admet_unfavorable_cl_min"]
    ):
        flag = "unfavorable"
    else:
        flag = "borderline"

    return {
        "cl_pred_ml_min_kg": round(cl_pred, 4),
        "vd_pred_l_kg": round(vd_pred, 4),
        "t_half_pred_h": round(t_half, 4),
        "f_oral_pred": round(f_oral, 4),
        "admet_flag": flag,
    }


# ---------------------------------------------------------------------------
# Core enumeration + screening logic (shared with re_derivation pack)
# ---------------------------------------------------------------------------


def run_screen(
    scaffolds: list[dict],
    r_groups_1: list[dict],
    r_groups_2: list[dict],
    filter_cfg: dict,
    scoring_cfg: dict,
    top_k: int,
    pk_cfg: dict,
) -> dict:
    """Run the full enumerate→filter→score→rank→advance→pk pipeline.

    Returns a dict with the ledger and advanced set. PK fields are populated
    only for advanced compounds (stage 6 runs on hits, not the whole library).
    """
    seed = scoring_cfg["seed"]
    affinity_lo, affinity_hi = scoring_cfg["affinity_range_kcal_mol"]
    prop_weight = scoring_cfg["property_weight"]
    engine = scoring_cfg["engine_surrogate"]

    ledger: list[dict] = []

    # Enumerate: deterministic order scaffolds→r1→r2
    for scaf in scaffolds:
        for r1 in r_groups_1:
            for r2 in r_groups_2:
                compound_id = f"{scaf['id']}__{r1['id']}__{r2['id']}"
                smiles = (
                    scaf["smiles_fragment"]
                    + r1["smiles_fragment"]
                    + r2["smiles_fragment"]
                )
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
                        "smiles": smiles,
                        "mw": mw,
                        "logp": logp,
                        "hbd": hbd,
                        "hba": hba,
                        "filter_status": filter_status,
                        "score": score,
                        "rank": None,
                        "advanced": False,
                        "pk": None,
                    }
                )

    # Sort survivors by score ASCENDING (most negative = strongest binding first);
    # ties broken by compound_id ascending.
    survivors = [
        (e["score"], e["compound_id"], i)
        for i, e in enumerate(ledger)
        if e["score"] is not None
    ]
    survivors.sort(key=lambda x: (x[0], x[1]))

    # Advance top-K
    advanced_list: list[dict] = []
    for rank_1indexed, (score, cid, ledger_idx) in enumerate(
        survivors[:top_k], start=1
    ):
        ledger[ledger_idx]["rank"] = rank_1indexed
        ledger[ledger_idx]["advanced"] = True
        # Stage 6: PK prediction on advanced compounds only
        e = ledger[ledger_idx]
        pk = _predict_pk(e["mw"], e["logp"], e["hbd"], e["hba"], pk_cfg)
        ledger[ledger_idx]["pk"] = pk
        advanced_list.append(
            {
                "compound_id": cid,
                "score": score,
                "rank": rank_1indexed,
                "pk": pk,
            }
        )

    enumerated_count = len(ledger)
    passed_count = len(survivors)
    advanced_count = len(advanced_list)

    return {
        "enumerated_count": enumerated_count,
        "passed_count": passed_count,
        "advanced_count": advanced_count,
        "ledger": ledger,
        "advanced": advanced_list,
    }


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # --- Prepare artifact bytes ---
    building_blocks = {
        "scaffolds": _SCAFFOLDS,
        "r_groups_1": _R_GROUPS_1,
        "r_groups_2": _R_GROUPS_2,
    }
    bb_bytes = (
        json.dumps(building_blocks, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    filter_bytes = (
        json.dumps(_FILTER_CONFIG, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    scoring_bytes = (
        json.dumps(_SCORING_CONFIG, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    pk_bytes = (
        json.dumps(_PK_CONFIG, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    # --- Run the screen ---
    screen = run_screen(
        scaffolds=_SCAFFOLDS,
        r_groups_1=_R_GROUPS_1,
        r_groups_2=_R_GROUPS_2,
        filter_cfg=_FILTER_CONFIG,
        scoring_cfg=_SCORING_CONFIG,
        top_k=_TOP_K,
        pk_cfg=_PK_CONFIG,
    )

    # --- Prepare payload bytes ---
    result_payload = {
        "target_id": _TARGET_ID,
        "enumerated_count": screen["enumerated_count"],
        "passed_count": screen["passed_count"],
        "advanced_count": screen["advanced_count"],
        "ledger": screen["ledger"],
        "advanced": screen["advanced"],
    }
    result_bytes = (
        json.dumps(result_payload, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    # --- OpaqueFragment anchors — one per advanced compound ---
    payload_cid = f"sha256:{_sha256(result_bytes)}"
    fragment_anchors: dict[str, dict] = {}
    for entry in screen["advanced"]:
        frag = OpaqueFragment(
            source_cid=payload_cid,
            kind_tag="combi_compound",
            locator={"compound_id": entry["compound_id"]},
        )
        anchor_key = f"advanced-{entry['rank']:02d}"
        fragment_anchors[anchor_key] = fragment_to_canonical_dict(frag)

    assert len(fragment_anchors) == screen["advanced_count"], (
        f"Expected {screen['advanced_count']} OpaqueFragment anchors; "
        f"got {len(fragment_anchors)}"
    )

    # --- dispatch_records — one DOCK_SCREEN record ---
    dispatch_records = [
        {
            "schema_version": "0.1",
            "op": {
                "kind": "DOCK_SCREEN",
                "name": "combi_library_dock_screen",
            },
            "inputs": [],
            "outputs": [],
            "effect": {},
            "locale": "en-US",
            "predicates": [],
            "stamp_declared": "INTERNAL_BENCHMARK",
            "stamp_observed": None,
        }
    ]

    # --- Emit via the reference-emitter SDK ---
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "inputs/building_blocks.json": bb_bytes,
            "inputs/filter_config.json": filter_bytes,
            "inputs/scoring_config.json": scoring_bytes,
            "inputs/pk_config.json": pk_bytes,
            "payload/combi_screen_result.json": result_bytes,
        },
        typed_checks=_TYPED_CHECKS,
        extra_manifest_fields={
            "fragment_anchors": fragment_anchors,
            "dispatch_records": dispatch_records,
        },
    )
    write_bundle(out_dir, content)

    pk_counts = {"favorable": 0, "borderline": 0, "unfavorable": 0}
    for e in screen["advanced"]:
        pk_counts[e["pk"]["admet_flag"]] += 1

    print(f"Bundle written to {out_dir}")
    print(f"  target           : {_TARGET_ID}")
    print(f"  enumerated       : {screen['enumerated_count']}")
    print(f"  passed filter    : {screen['passed_count']}")
    print(f"  advanced (top-K) : {screen['advanced_count']}")
    print(
        f"  pk predicted     : {screen['advanced_count']} advanced — "
        f"{pk_counts['favorable']} favorable / "
        f"{pk_counts['borderline']} borderline / "
        f"{pk_counts['unfavorable']} unfavorable"
    )
    print(
        f"  fragment anchors : {len(fragment_anchors)} OpaqueFragment (kind_tag=combi_compound)"
    )
    print(f"  dispatch records : 1 (op.kind=DOCK_SCREEN)")
    print(f"  manifest files   : 5")
    print(f"  manifest         : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic combi_screen_minimal audit bundle"
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        type=Path,
        help="Destination directory (created if absent)",
    )
    args = parser.parse_args()
    try:
        build(args.out_dir.resolve())
    except AssertionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
