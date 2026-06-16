#!/usr/bin/env python3
"""combi_screen_re_derivation.py — stdlib re-derivation pack for combi_screen_minimal.

Verifies that a combinatorial drug-discovery screening result is derivable from
the bundled inputs. the audit-bundle contract §C6 (domain generalization) +
AB4 (duplicate-don't-import).

Reads from --bundle-dir:
  inputs/building_blocks.json        — scaffold + R-group library
  inputs/filter_config.json          — Lipinski thresholds
  inputs/scoring_config.json         — scorer seed + parameters
  payload/combi_screen_result.json   — full ledger + advanced set to re-derive

Three invariants checked:
  1. Re-enumerate the Cartesian product (scaffolds x r_groups_1 x r_groups_2),
     re-apply Lipinski filter, re-score survivors with committed seed, re-rank —
     assert the full ledger matches entry-by-entry (compound_id, filter_status,
     score, rank, advanced for every enumerated compound).
  2. The advanced set in the payload matches the top-K entries from re-ranking.
  3. enumerated_count / passed_count / advanced_count match.

Exit 0 on full match; exit 1 on first mismatch with [COMBI_SCREEN_REDERIVATION_MISMATCH]
printed to stderr.

If any required input file is absent the bundle opted out of re-derivation — exits 0.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Scoring helpers — must be byte-for-byte identical to _build_bundle.py
# ---------------------------------------------------------------------------


def _sha256_hex(s: str) -> int:
    """Return the integer value of sha256(s.encode()) — for deterministic float mapping."""
    import hashlib

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


def _predict_pk(mw: float, logp: float, hbd: int, hba: int, cfg: dict) -> dict:
    """Deterministic rule-based ADMET stand-in (stage 6).

    MUST be byte-for-byte identical to _build_bundle.py:_predict_pk.
    """
    cl_pred = (
        cfg["cl_base"]
        + cfg["cl_logp_coef"] * max(0.0, logp)
        - cfg["cl_mw_coef"] * (mw / 100.0)
    )
    cl_pred = max(cfg["cl_min"], min(cfg["cl_max"], cl_pred))

    vd_pred = cfg["vd_base"] + cfg["vd_logp_coef"] * logp
    vd_pred = max(cfg["vd_min"], min(cfg["vd_max"], vd_pred))

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


def _run_screen(
    scaffolds: list[dict],
    r_groups_1: list[dict],
    r_groups_2: list[dict],
    filter_cfg: dict,
    scoring_cfg: dict,
    top_k: int,
    pk_cfg: dict,
) -> list[dict]:
    """Re-run the full screen; return the ledger with rank/advanced/pk populated."""
    seed = scoring_cfg["seed"]
    affinity_lo, affinity_hi = scoring_cfg["affinity_range_kcal_mol"]
    prop_weight = scoring_cfg["property_weight"]

    ledger: list[dict] = []

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

    # Sort survivors ASCENDING by score, ties by compound_id
    survivors = [
        (e["score"], e["compound_id"], i)
        for i, e in enumerate(ledger)
        if e["score"] is not None
    ]
    survivors.sort(key=lambda x: (x[0], x[1]))

    for rank_1indexed, (score, cid, ledger_idx) in enumerate(
        survivors[:top_k], start=1
    ):
        ledger[ledger_idx]["rank"] = rank_1indexed
        ledger[ledger_idx]["advanced"] = True
        # Stage 6: re-derive PK on advanced compounds
        e = ledger[ledger_idx]
        ledger[ledger_idx]["pk"] = _predict_pk(
            e["mw"], e["logp"], e["hbd"], e["hba"], pk_cfg
        )

    return ledger


# ---------------------------------------------------------------------------
# Load helpers
# ---------------------------------------------------------------------------


def _load_json(path: Path, label: str) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(
            f"[COMBI_SCREEN_REDERIVATION_MISMATCH] {label}: JSON parse error: {exc}",
            file=sys.stderr,
        )
        return False  # sentinel: exists but unreadable


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Combinatorial screening re-derivation check for combi_screen_minimal"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    inputs_dir = bundle_dir / "inputs"
    payload_dir = bundle_dir / "payload"

    bb_path = inputs_dir / "building_blocks.json"
    fc_path = inputs_dir / "filter_config.json"
    sc_path = inputs_dir / "scoring_config.json"
    pk_path = inputs_dir / "pk_config.json"
    result_path = payload_dir / "combi_screen_result.json"

    # If core files are missing, bundle opted out — not a failure
    if not bb_path.exists() and not result_path.exists():
        return 0

    bb = _load_json(bb_path, "inputs/building_blocks.json")
    fc = _load_json(fc_path, "inputs/filter_config.json")
    sc = _load_json(sc_path, "inputs/scoring_config.json")
    pk = _load_json(pk_path, "inputs/pk_config.json")
    result = _load_json(result_path, "payload/combi_screen_result.json")

    for label, val in [
        ("inputs/building_blocks.json", bb),
        ("inputs/filter_config.json", fc),
        ("inputs/scoring_config.json", sc),
        ("inputs/pk_config.json", pk),
        ("payload/combi_screen_result.json", result),
    ]:
        if val is False:
            return 1  # parse error already printed
        if val is None:
            print(
                f"[COMBI_SCREEN_REDERIVATION_MISMATCH] {label}: file absent",
                file=sys.stderr,
            )
            return 1

    # Extract inputs
    try:
        scaffolds = bb["scaffolds"]
        r_groups_1 = bb["r_groups_1"]
        r_groups_2 = bb["r_groups_2"]
        filter_cfg = fc
        scoring_cfg = sc
        pk_cfg = pk
        top_k = result["advanced_count"]
        bundled_ledger: list[dict] = result["ledger"]
        bundled_advanced: list[dict] = result["advanced"]
        bundled_enum_count: int = result["enumerated_count"]
        bundled_passed_count: int = result["passed_count"]
    except (KeyError, TypeError) as exc:
        print(
            f"[COMBI_SCREEN_REDERIVATION_MISMATCH] payload structure malformed: {exc}",
            file=sys.stderr,
        )
        return 1

    # Re-run the screen
    try:
        rederived_ledger = _run_screen(
            scaffolds=scaffolds,
            r_groups_1=r_groups_1,
            r_groups_2=r_groups_2,
            filter_cfg=filter_cfg,
            scoring_cfg=scoring_cfg,
            top_k=top_k,
            pk_cfg=pk_cfg,
        )
    except Exception as exc:
        print(
            f"[COMBI_SCREEN_REDERIVATION_MISMATCH] re-derivation raised exception: {exc}",
            file=sys.stderr,
        )
        return 1

    # Invariant 1: ledger length
    if len(rederived_ledger) != len(bundled_ledger):
        print(
            f"[COMBI_SCREEN_REDERIVATION_MISMATCH] ledger length mismatch: "
            f"re-derived={len(rederived_ledger)}, bundled={len(bundled_ledger)}",
            file=sys.stderr,
        )
        return 1

    # Invariant 2: enumerated_count
    if len(rederived_ledger) != bundled_enum_count:
        print(
            f"[COMBI_SCREEN_REDERIVATION_MISMATCH] enumerated_count mismatch: "
            f"re-derived={len(rederived_ledger)}, bundled={bundled_enum_count}",
            file=sys.stderr,
        )
        return 1

    # Invariant 3: per-compound ledger fields
    _COMPARE_FIELDS = (
        "compound_id",
        "smiles",
        "mw",
        "logp",
        "hbd",
        "hba",
        "filter_status",
        "score",
        "rank",
        "advanced",
        "pk",
    )
    _PK_FIELDS = (
        "cl_pred_ml_min_kg",
        "vd_pred_l_kg",
        "t_half_pred_h",
        "f_oral_pred",
        "admet_flag",
    )
    for i, (rd, bd) in enumerate(zip(rederived_ledger, bundled_ledger)):
        for field in _COMPARE_FIELDS:
            rd_val = rd.get(field)
            bd_val = bd.get(field)
            # PK is a nested dict (or None for non-advanced compounds)
            if field == "pk":
                if rd_val is None and bd_val is None:
                    continue
                if rd_val is None or bd_val is None:
                    print(
                        f"[COMBI_SCREEN_REDERIVATION_MISMATCH] ledger[{i}].pk: "
                        f"re-derived={rd_val!r}, bundled={bd_val!r}",
                        file=sys.stderr,
                    )
                    return 1
                for pk_field in _PK_FIELDS:
                    rd_pk = rd_val.get(pk_field)
                    bd_pk = bd_val.get(pk_field)
                    if isinstance(rd_pk, float) and isinstance(bd_pk, float):
                        if abs(rd_pk - bd_pk) > 1e-9:
                            print(
                                f"[COMBI_SCREEN_REDERIVATION_MISMATCH] "
                                f"ledger[{i}].pk.{pk_field}: "
                                f"re-derived={rd_pk!r}, bundled={bd_pk!r}",
                                file=sys.stderr,
                            )
                            return 1
                    elif rd_pk != bd_pk:
                        print(
                            f"[COMBI_SCREEN_REDERIVATION_MISMATCH] "
                            f"ledger[{i}].pk.{pk_field}: "
                            f"re-derived={rd_pk!r}, bundled={bd_pk!r}",
                            file=sys.stderr,
                        )
                        return 1
                continue
            # Float comparison: scores rounded to 6 dp in both build + re-derivation
            if isinstance(rd_val, float) and isinstance(bd_val, float):
                if abs(rd_val - bd_val) > 1e-9:
                    print(
                        f"[COMBI_SCREEN_REDERIVATION_MISMATCH] ledger[{i}].{field}: "
                        f"re-derived={rd_val!r}, bundled={bd_val!r}",
                        file=sys.stderr,
                    )
                    return 1
            elif rd_val != bd_val:
                print(
                    f"[COMBI_SCREEN_REDERIVATION_MISMATCH] ledger[{i}].{field}: "
                    f"re-derived={rd_val!r}, bundled={bd_val!r}",
                    file=sys.stderr,
                )
                return 1

    # Invariant 4: passed_count
    rederived_passed = sum(
        1 for e in rederived_ledger if e["filter_status"] == "passed"
    )
    if rederived_passed != bundled_passed_count:
        print(
            f"[COMBI_SCREEN_REDERIVATION_MISMATCH] passed_count mismatch: "
            f"re-derived={rederived_passed}, bundled={bundled_passed_count}",
            file=sys.stderr,
        )
        return 1

    # Invariant 5: advanced set
    rederived_advanced_ids = sorted(
        e["compound_id"] for e in rederived_ledger if e["advanced"]
    )
    bundled_advanced_ids = sorted(e["compound_id"] for e in bundled_advanced)
    if rederived_advanced_ids != bundled_advanced_ids:
        only_rederived = sorted(set(rederived_advanced_ids) - set(bundled_advanced_ids))
        only_bundled = sorted(set(bundled_advanced_ids) - set(rederived_advanced_ids))
        print(
            f"[COMBI_SCREEN_REDERIVATION_MISMATCH] advanced set mismatch:\n"
            f"  in re-derived but not bundled: {only_rederived}\n"
            f"  in bundled but not re-derived: {only_bundled}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
