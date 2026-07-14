#!/usr/bin/env python3
"""pharmacophore_fit_re_derivation.py — stdlib re-derivation pack for pharmacophore_fit_minimal.

Verifies that the spatial-fit RMSD ledger + ranked + advanced lists are derivable
from the bundled pharmacophore template + candidate conformers + feature mappings.
the audit-bundle contract §C6 (domain generalization) + AB4 (duplicate-don't-import).

Reads from --bundle-dir:
  inputs/pharmacophore_template.json    — pharmacophore features (positions + types)
  inputs/candidate_conformers.json      — K candidates with features + feature_mapping
  inputs/fit_config.json                — top_n + rmsd_decimal_places
  payload/spatial_fit_result.json       — ledger + ranked + advanced to re-derive

Five invariants checked:
  1. Per-candidate RMSD: re-compute from committed positions + feature_mapping,
     assert equality with bundled rmsd value (epsilon 1e-9).
  2. Per-pair distances: re-compute each distance value, assert equality.
  3. candidate_count / scored_count / advanced_count match.
  4. Ranked list: re-rank survivors by RMSD ascending (ties by compound_id),
     assert ordering + rank assignments match bundled ranked list.
  5. Advanced set: top-N compound_id set matches bundled advanced compound_id set
     (the "you cannot disappear a hit" invariant).

Exit 0 on full match; exit 1 on first mismatch with [PHARMACOPHORE_FIT_REDERIVATION_MISMATCH]
printed to stderr.

If core input/payload files are absent the bundle opted out of re-derivation — exits 0.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Math helpers — MUST be byte-for-byte identical to _build_bundle.py
# ---------------------------------------------------------------------------


def _compute_fit(
    pharma_features: list[dict],
    candidate: dict,
    decimal_places: int,
) -> dict:
    pf_by_id = {pf["feature_id"]: pf for pf in pharma_features}
    cf_by_id = {cf["feature_id"]: cf for cf in candidate["features"]}
    feature_mapping = candidate["feature_mapping"]

    pair_records: list[dict] = []
    sq_distances: list[float] = []
    for pf_id in sorted(feature_mapping.keys()):
        cf_id = feature_mapping[pf_id]
        pf = pf_by_id[pf_id]
        cf = cf_by_id[cf_id]
        dx = cf["position"][0] - pf["position"][0]
        dy = cf["position"][1] - pf["position"][1]
        dz = cf["position"][2] - pf["position"][2]
        d_sq = dx * dx + dy * dy + dz * dz
        sq_distances.append(d_sq)
        pair_records.append(
            {
                "pharmacophore_feature_id": pf_id,
                "candidate_feature_id": cf_id,
                "pharmacophore_type": pf["feature_type"],
                "candidate_type": cf["feature_type"],
                "type_match": pf["feature_type"] == cf["feature_type"],
                "distance": round(math.sqrt(d_sq), decimal_places),
            }
        )

    if not sq_distances:
        rmsd: float | None = None
    else:
        mean_sq = sum(sq_distances) / len(sq_distances)
        rmsd = round(math.sqrt(mean_sq), decimal_places)

    return {
        "compound_id": candidate["compound_id"],
        "paired_count": len(pair_records),
        "rmsd": rmsd,
        "pair_records": pair_records,
    }


def _run_spatial_fit(
    pharma_features: list[dict],
    candidates: list[dict],
    top_n: int,
    decimal_places: int,
) -> dict:
    fits = [_compute_fit(pharma_features, c, decimal_places) for c in candidates]

    survivors = [
        (e["rmsd"], e["compound_id"], i)
        for i, e in enumerate(fits)
        if e["rmsd"] is not None
    ]
    survivors.sort(key=lambda x: (x[0], x[1]))

    advanced_compound_ids: set[str] = set()
    # Ledger-level rank is only assigned to advanced compounds (rank 1..top_n);
    # non-advanced compounds carry rank=None in the bundled ledger. The
    # `ranked` list, by contrast, ranks ALL survivors 1..len(survivors).
    rank_by_compound_id: dict[str, int] = {}
    ranked_list: list[dict] = []
    for rank_1indexed, (rmsd, cid, _) in enumerate(survivors, start=1):
        ranked_list.append(
            {"compound_id": cid, "rmsd": rmsd, "rank": rank_1indexed}
        )
        if rank_1indexed <= top_n:
            rank_by_compound_id[cid] = rank_1indexed
            advanced_compound_ids.add(cid)

    return {
        "candidate_count": len(fits),
        "scored_count": len(survivors),
        "advanced_count": min(top_n, len(survivors)),
        "fits": fits,
        "ranked": ranked_list,
        "rank_by_compound_id": rank_by_compound_id,
        "advanced_compound_ids": advanced_compound_ids,
    }


# ---------------------------------------------------------------------------
# Load helpers
# ---------------------------------------------------------------------------


def _load_json(path: Path, label: str):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(
            f"[PHARMACOPHORE_FIT_REDERIVATION_MISMATCH] {label}: JSON parse error: {exc}",
            file=sys.stderr,
        )
        return False  # sentinel: exists but unreadable


def _approx_equal(a: float | None, b: float | None, eps: float = 1e-9) -> bool:
    if a is None and b is None:
        return True
    if a is None or b is None:
        return False
    return abs(a - b) <= eps


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Pharmacophore-fit re-derivation check for pharmacophore_fit_minimal"
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

    tmpl_path = inputs_dir / "pharmacophore_template.json"
    conf_path = inputs_dir / "candidate_conformers.json"
    cfg_path = inputs_dir / "fit_config.json"
    result_path = payload_dir / "spatial_fit_result.json"

    # If core files are missing, bundle opted out — not a failure
    if not tmpl_path.exists() and not result_path.exists():
        return 0

    tmpl = _load_json(tmpl_path, "inputs/pharmacophore_template.json")
    conf = _load_json(conf_path, "inputs/candidate_conformers.json")
    cfg = _load_json(cfg_path, "inputs/fit_config.json")
    result = _load_json(result_path, "payload/spatial_fit_result.json")

    for label, val in [
        ("inputs/pharmacophore_template.json", tmpl),
        ("inputs/candidate_conformers.json", conf),
        ("inputs/fit_config.json", cfg),
        ("payload/spatial_fit_result.json", result),
    ]:
        if val is False:
            return 1
        if val is None:
            print(
                f"[PHARMACOPHORE_FIT_REDERIVATION_MISMATCH] {label}: file absent",
                file=sys.stderr,
            )
            return 1

    try:
        pharma_features = tmpl["features"]
        candidates = conf["candidates"]
        top_n = cfg["top_n"]
        decimal_places = cfg["rmsd_decimal_places"]
        bundled_ledger: list[dict] = result["ledger"]
        bundled_ranked: list[dict] = result["ranked"]
        bundled_advanced: list[dict] = result["advanced"]
        bundled_candidate_count: int = result["candidate_count"]
        bundled_scored_count: int = result["scored_count"]
        bundled_advanced_count: int = result["advanced_count"]
    except (KeyError, TypeError) as exc:
        print(
            f"[PHARMACOPHORE_FIT_REDERIVATION_MISMATCH] payload/inputs malformed: {exc}",
            file=sys.stderr,
        )
        return 1

    # Re-run the spatial fit
    try:
        rederived = _run_spatial_fit(
            pharma_features=pharma_features,
            candidates=candidates,
            top_n=top_n,
            decimal_places=decimal_places,
        )
    except Exception as exc:
        print(
            f"[PHARMACOPHORE_FIT_REDERIVATION_MISMATCH] re-derivation raised "
            f"exception: {exc}",
            file=sys.stderr,
        )
        return 1

    # Invariant: candidate_count
    if rederived["candidate_count"] != bundled_candidate_count:
        print(
            f"[PHARMACOPHORE_FIT_REDERIVATION_MISMATCH] candidate_count mismatch: "
            f"re-derived={rederived['candidate_count']}, bundled={bundled_candidate_count}",
            file=sys.stderr,
        )
        return 1

    # Invariant: scored_count
    if rederived["scored_count"] != bundled_scored_count:
        print(
            f"[PHARMACOPHORE_FIT_REDERIVATION_MISMATCH] scored_count mismatch: "
            f"re-derived={rederived['scored_count']}, bundled={bundled_scored_count}",
            file=sys.stderr,
        )
        return 1

    # Invariant: advanced_count
    if rederived["advanced_count"] != bundled_advanced_count:
        print(
            f"[PHARMACOPHORE_FIT_REDERIVATION_MISMATCH] advanced_count mismatch: "
            f"re-derived={rederived['advanced_count']}, bundled={bundled_advanced_count}",
            file=sys.stderr,
        )
        return 1

    if len(rederived["fits"]) != len(bundled_ledger):
        print(
            f"[PHARMACOPHORE_FIT_REDERIVATION_MISMATCH] ledger length mismatch: "
            f"re-derived={len(rederived['fits'])}, bundled={len(bundled_ledger)}",
            file=sys.stderr,
        )
        return 1

    # Invariant: per-candidate RMSD + paired_count + per-pair distances + rank/advanced
    rank_by_cid = rederived["rank_by_compound_id"]
    advanced_cids = rederived["advanced_compound_ids"]
    for i, (rd, bd) in enumerate(zip(rederived["fits"], bundled_ledger)):
        if rd["compound_id"] != bd.get("compound_id"):
            print(
                f"[PHARMACOPHORE_FIT_REDERIVATION_MISMATCH] ledger[{i}].compound_id: "
                f"re-derived={rd['compound_id']!r}, bundled={bd.get('compound_id')!r}",
                file=sys.stderr,
            )
            return 1
        if rd["paired_count"] != bd.get("paired_count"):
            print(
                f"[PHARMACOPHORE_FIT_REDERIVATION_MISMATCH] ledger[{i}].paired_count: "
                f"re-derived={rd['paired_count']!r}, bundled={bd.get('paired_count')!r}",
                file=sys.stderr,
            )
            return 1
        if not _approx_equal(rd["rmsd"], bd.get("rmsd")):
            print(
                f"[PHARMACOPHORE_FIT_REDERIVATION_MISMATCH] ledger[{i}].rmsd: "
                f"re-derived={rd['rmsd']!r}, bundled={bd.get('rmsd')!r}",
                file=sys.stderr,
            )
            return 1
        # Per-pair distances
        bundled_pairs = bd.get("pair_records") or []
        if len(rd["pair_records"]) != len(bundled_pairs):
            print(
                f"[PHARMACOPHORE_FIT_REDERIVATION_MISMATCH] ledger[{i}].pair_records "
                f"length mismatch: re-derived={len(rd['pair_records'])}, "
                f"bundled={len(bundled_pairs)}",
                file=sys.stderr,
            )
            return 1
        for j, (rp, bp) in enumerate(zip(rd["pair_records"], bundled_pairs)):
            for field in (
                "pharmacophore_feature_id",
                "candidate_feature_id",
                "pharmacophore_type",
                "candidate_type",
                "type_match",
            ):
                if rp.get(field) != bp.get(field):
                    print(
                        f"[PHARMACOPHORE_FIT_REDERIVATION_MISMATCH] "
                        f"ledger[{i}].pair_records[{j}].{field}: "
                        f"re-derived={rp.get(field)!r}, bundled={bp.get(field)!r}",
                        file=sys.stderr,
                    )
                    return 1
            if not _approx_equal(rp.get("distance"), bp.get("distance")):
                print(
                    f"[PHARMACOPHORE_FIT_REDERIVATION_MISMATCH] "
                    f"ledger[{i}].pair_records[{j}].distance: "
                    f"re-derived={rp.get('distance')!r}, bundled={bp.get('distance')!r}",
                    file=sys.stderr,
                )
                return 1
        # Rank + advanced consistency
        cid = rd["compound_id"]
        expected_rank = rank_by_cid.get(cid)
        expected_advanced = cid in advanced_cids
        if bd.get("rank") != expected_rank:
            print(
                f"[PHARMACOPHORE_FIT_REDERIVATION_MISMATCH] ledger[{i}].rank: "
                f"re-derived={expected_rank!r}, bundled={bd.get('rank')!r}",
                file=sys.stderr,
            )
            return 1
        if bd.get("advanced") != expected_advanced:
            print(
                f"[PHARMACOPHORE_FIT_REDERIVATION_MISMATCH] ledger[{i}].advanced: "
                f"re-derived={expected_advanced!r}, bundled={bd.get('advanced')!r}",
                file=sys.stderr,
            )
            return 1

    # Invariant: ranked list matches in order
    if len(rederived["ranked"]) != len(bundled_ranked):
        print(
            f"[PHARMACOPHORE_FIT_REDERIVATION_MISMATCH] ranked length mismatch: "
            f"re-derived={len(rederived['ranked'])}, bundled={len(bundled_ranked)}",
            file=sys.stderr,
        )
        return 1
    for i, (rr, br) in enumerate(zip(rederived["ranked"], bundled_ranked)):
        if rr["compound_id"] != br.get("compound_id") or rr["rank"] != br.get("rank"):
            print(
                f"[PHARMACOPHORE_FIT_REDERIVATION_MISMATCH] ranked[{i}]: "
                f"re-derived={rr!r}, bundled={br!r}",
                file=sys.stderr,
            )
            return 1
        if not _approx_equal(rr["rmsd"], br.get("rmsd")):
            print(
                f"[PHARMACOPHORE_FIT_REDERIVATION_MISMATCH] ranked[{i}].rmsd: "
                f"re-derived={rr['rmsd']!r}, bundled={br.get('rmsd')!r}",
                file=sys.stderr,
            )
            return 1

    # Invariant: advanced set (compound_id set equality — order-independent)
    bundled_advanced_cids = sorted(e["compound_id"] for e in bundled_advanced)
    rederived_advanced_cids_sorted = sorted(advanced_cids)
    if bundled_advanced_cids != rederived_advanced_cids_sorted:
        only_rederived = sorted(set(rederived_advanced_cids_sorted) - set(bundled_advanced_cids))
        only_bundled = sorted(set(bundled_advanced_cids) - set(rederived_advanced_cids_sorted))
        print(
            f"[PHARMACOPHORE_FIT_REDERIVATION_MISMATCH] advanced set mismatch:\n"
            f"  in re-derived but not bundled: {only_rederived}\n"
            f"  in bundled but not re-derived: {only_bundled}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
