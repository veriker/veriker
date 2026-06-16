"""_build_bundle.py — build a deterministic pharmacophore_fit_minimal audit bundle.

Pharmacophore-based virtual screening domain pilot: given a pharmacophore feature
template + a set of candidate compound conformers + a per-candidate feature-mapping,
compute the spatial-fit RMSD between each candidate's mapped features and the
template features, rank candidates by RMSD (ascending), and advance the top-N.
The audit bundle commits the COMPLETE per-candidate RMSD + paired-distance ledger
plus the ranked + advanced lists — a verifier re-runs the RMSD math from the
committed 3D coordinates + feature-mapping and asserts byte-for-byte agreement.

Re-derivation primitive (one sentence):
  Re-compute per-candidate spatial-fit RMSD from committed pharmacophore feature
  positions, candidate feature positions, and feature-mappings; re-rank by RMSD
  ascending (ties by compound_id); assert the full per-candidate fit ledger AND
  the advanced top-N set match the payload.

HONEST FRAMING:
  - The candidate conformers are SYNTHETIC: positions deterministically generated
    from a committed noise seed so the bundle is reproducible. They are NOT real
    3D conformers from RDKit / OMEGA / Corina; the substrate claim is the
    *verification* primitive, not the conformer-generation primitive.
  - The pharmacophore feature template is also synthetic (5 features at hardcoded
    coordinates with HBD / HBA / aromatic / hydrophobic types). Production
    integrators derive the template from MOE / Phase / LigandScout / RDKit
    pharmacophore extraction; the bundle shape and verification protocol are
    identical.
  - What IS demonstrated: 3D feature-position alignment as a re-derivation
    primitive, distinct from the 2D fingerprint linear scorer (lifesci_binding)
    and the enumerate→filter→score→rank shape (combi_screen). Per-pair distances
    are bundled alongside the aggregate RMSD so reviewers can audit which
    features contribute to the fit.
  - OUT OF SCOPE: real 3D conformer generation, target-protein pocket geometry,
    pharmacophore feature extraction. Those are production-time work.

Domain basis: pharmacophore-based virtual screening — the spatial-fit half of a
full virtual-screening pipeline (pocket detection → similarity expansion →
pharmacophore extraction → SAMPLING → SPATIAL FIT → wash → docking →
cross-comparison). This pilot demonstrates the SPATIAL FIT stage in isolation;
combi_screen_minimal demonstrates the enumerate / filter / score / rank shape;
lifesci_binding_minimal demonstrates single-pair affinity scoring. Together they
cover the computational-shape diversity of computational drug discovery.

Usage (from v-kernel-audit-bundle root):
    python examples/pharmacophore_fit_minimal/_build_bundle.py --out-dir /tmp/pharma_fit_bundle

Outputs:
  <out-dir>/inputs/pharmacophore_template.json   — N pharmacophore features (positions + types)
  <out-dir>/inputs/candidate_conformers.json     — K candidates with features + per-candidate feature_mapping
  <out-dir>/inputs/fit_config.json               — metric, top_n, candidate_count, synthesis seed
  <out-dir>/payload/spatial_fit_result.json      — per-candidate RMSD + paired distances + ranked + advanced top-N
  <out-dir>/manifest.json

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "pharmacophore-fit-minimal-rc"
_CREATED_AT = "2026-05-27T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
    "pharmacophore_fit_re_derivation",
    "dispatch_record_wellformed",
]

_PHARMACOPHORE_ID = "PHARMA-A-01"

# ---------------------------------------------------------------------------
# Pharmacophore template: 5 features (target-agnostic synthetic positions).
# Real-world templates come from MOE / Phase / LigandScout pharmacophore
# extraction; here we hardcode positions + types so the bundle is reproducible.
# ---------------------------------------------------------------------------

_PHARMACOPHORE_FEATURES = [
    {
        "feature_id": "F1",
        "feature_type": "HBD",
        "position": [1.2, 0.0, 0.0],
        "tolerance": 1.0,
    },
    {
        "feature_id": "F2",
        "feature_type": "HBA",
        "position": [-2.5, 1.5, 0.5],
        "tolerance": 1.0,
    },
    {
        "feature_id": "F3",
        "feature_type": "aromatic",
        "position": [0.0, 3.0, 0.0],
        "tolerance": 1.2,
    },
    {
        "feature_id": "F4",
        "feature_type": "hydrophobic",
        "position": [3.5, -1.0, 1.0],
        "tolerance": 1.5,
    },
    {
        "feature_id": "F5",
        "feature_type": "HBD",
        "position": [-1.0, -2.5, -0.5],
        "tolerance": 1.0,
    },
]

# ---------------------------------------------------------------------------
# Fit config (top-N selection + synthesis seed for candidate generation)
# ---------------------------------------------------------------------------

_NOISE_SEED = 4096
_CANDIDATE_COUNT = 20
_TOP_N = 10
_RMSD_DECIMAL_PLACES = 6

_FIT_CONFIG = {
    "metric": "euclidean_rmsd",
    "top_n": _TOP_N,
    "candidate_count": _CANDIDATE_COUNT,
    "noise_seed": _NOISE_SEED,
    "rmsd_decimal_places": _RMSD_DECIMAL_PLACES,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _noise_scale_for_index(idx: int) -> float:
    """Deterministic per-candidate noise scaling.

    Indices 0..4   → 0.10..0.30 (good fits, RMSD ~0.1..0.5)
    Indices 5..14  → 0.30..1.50 (medium fits)
    Indices 15..19 → 1.50..3.00 (bad fits)
    """
    if idx < 5:
        return 0.10 + 0.05 * idx
    if idx < 15:
        return 0.30 + 0.12 * (idx - 5)
    return 1.50 + 0.30 * (idx - 15)


def _synthesize_candidate(
    compound_id: str,
    pharma_features: list[dict],
    noise_seed: int,
) -> dict:
    """Generate a candidate with deterministic per-feature 3D-position noise.

    Synthesis is reproducible from (compound_id, noise_seed) alone. The
    candidate's features 1:1-map to the pharmacophore features (same types),
    and the feature_mapping is constructed accordingly.
    """
    idx = int(compound_id.split("-")[1])
    noise_scale = _noise_scale_for_index(idx)
    digest = hashlib.sha256(f"{compound_id}|{noise_seed}".encode("utf-8")).digest()

    candidate_features: list[dict] = []
    feature_mapping: dict[str, str] = {}
    for i, pf in enumerate(pharma_features):
        b1 = digest[(i * 3 + 0) % len(digest)]
        b2 = digest[(i * 3 + 1) % len(digest)]
        b3 = digest[(i * 3 + 2) % len(digest)]
        nx = ((b1 - 128) / 128.0) * noise_scale
        ny = ((b2 - 128) / 128.0) * noise_scale
        nz = ((b3 - 128) / 128.0) * noise_scale
        cf_id = f"{compound_id}-FEAT-{i:02d}"
        candidate_features.append(
            {
                "feature_id": cf_id,
                "feature_type": pf["feature_type"],
                "position": [
                    round(pf["position"][0] + nx, _RMSD_DECIMAL_PLACES),
                    round(pf["position"][1] + ny, _RMSD_DECIMAL_PLACES),
                    round(pf["position"][2] + nz, _RMSD_DECIMAL_PLACES),
                ],
            }
        )
        feature_mapping[pf["feature_id"]] = cf_id

    return {
        "compound_id": compound_id,
        "features": candidate_features,
        "feature_mapping": feature_mapping,
    }


def _compute_fit(pharma_features: list[dict], candidate: dict) -> dict:
    """Compute per-pair distances + aggregate RMSD for one candidate.

    Iterates over feature_mapping keys in sorted order (lexicographic by
    pharmacophore feature_id) for deterministic ordering of pair_records.

    100% stdlib (math.sqrt). MUST be byte-for-byte identical between
    _build_bundle.py and pharmacophore_fit_re_derivation.py.
    """
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
                "distance": round(math.sqrt(d_sq), _RMSD_DECIMAL_PLACES),
            }
        )

    if not sq_distances:
        rmsd: float | None = None
    else:
        mean_sq = sum(sq_distances) / len(sq_distances)
        rmsd = round(math.sqrt(mean_sq), _RMSD_DECIMAL_PLACES)

    return {
        "compound_id": candidate["compound_id"],
        "paired_count": len(pair_records),
        "rmsd": rmsd,
        "pair_records": pair_records,
        "rank": None,
        "advanced": False,
    }


def run_spatial_fit(
    pharma_features: list[dict],
    candidates: list[dict],
    top_n: int,
) -> dict:
    """Run the full spatial-fit pipeline. Returns ledger + ranked + advanced."""
    ledger: list[dict] = [_compute_fit(pharma_features, c) for c in candidates]

    # Rank survivors by RMSD ascending (lower = better fit); ties by compound_id.
    survivors = [
        (e["rmsd"], e["compound_id"], i)
        for i, e in enumerate(ledger)
        if e["rmsd"] is not None
    ]
    survivors.sort(key=lambda x: (x[0], x[1]))

    advanced_list: list[dict] = []
    for rank_1indexed, (rmsd, cid, ledger_idx) in enumerate(
        survivors[:top_n], start=1
    ):
        ledger[ledger_idx]["rank"] = rank_1indexed
        ledger[ledger_idx]["advanced"] = True
        advanced_list.append(
            {
                "compound_id": cid,
                "rmsd": rmsd,
                "rank": rank_1indexed,
            }
        )

    ranked_list = [
        {"compound_id": cid, "rmsd": rmsd, "rank": rank_1indexed}
        for rank_1indexed, (rmsd, cid, _) in enumerate(survivors, start=1)
    ]

    return {
        "candidate_count": len(ledger),
        "scored_count": len(survivors),
        "advanced_count": len(advanced_list),
        "ledger": ledger,
        "ranked": ranked_list,
        "advanced": advanced_list,
    }


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # --- Synthesize candidates ---
    candidates = [
        _synthesize_candidate(f"CAND-{i:02d}", _PHARMACOPHORE_FEATURES, _NOISE_SEED)
        for i in range(_CANDIDATE_COUNT)
    ]

    # --- Build pharmacophore_template.json bytes ---
    template = {
        "pharmacophore_id": _PHARMACOPHORE_ID,
        "feature_count": len(_PHARMACOPHORE_FEATURES),
        "features": _PHARMACOPHORE_FEATURES,
    }
    tmpl_bytes = (
        json.dumps(template, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    # --- Build candidate_conformers.json bytes ---
    conformers = {"candidates": candidates}
    conf_bytes = (
        json.dumps(conformers, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    # --- Build fit_config.json bytes ---
    cfg_bytes = (
        json.dumps(_FIT_CONFIG, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    # --- Run the spatial fit ---
    fit = run_spatial_fit(
        pharma_features=_PHARMACOPHORE_FEATURES,
        candidates=candidates,
        top_n=_TOP_N,
    )

    # --- Build payload/spatial_fit_result.json bytes ---
    result_payload = {
        "pharmacophore_id": _PHARMACOPHORE_ID,
        "candidate_count": fit["candidate_count"],
        "scored_count": fit["scored_count"],
        "advanced_count": fit["advanced_count"],
        "ledger": fit["ledger"],
        "ranked": fit["ranked"],
        "advanced": fit["advanced"],
    }
    result_bytes = (
        json.dumps(result_payload, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    # --- OpaqueFragment anchors — one per advanced candidate ---
    payload_cid = f"sha256:{_sha256(result_bytes)}"
    fragment_anchors: dict[str, dict] = {}
    for entry in fit["advanced"]:
        frag = OpaqueFragment(
            source_cid=payload_cid,
            kind_tag="candidate_conformer",
            locator={"compound_id": entry["compound_id"]},
        )
        anchor_key = f"advanced-{entry['rank']:02d}"
        fragment_anchors[anchor_key] = fragment_to_canonical_dict(frag)

    assert len(fragment_anchors) == fit["advanced_count"], (
        f"Expected {fit['advanced_count']} OpaqueFragment anchors; "
        f"got {len(fragment_anchors)}"
    )

    # --- dispatch_records — one PHARMACOPHORE_FIT record ---
    dispatch_records = [
        {
            "schema_version": "0.1",
            "op": {
                "kind": "PHARMACOPHORE_FIT",
                "name": "spatial_rmsd_fit_eval",
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

    # --- Emit via the reference-emitter SDK (scaffold + digests + manifest). ---
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "inputs/pharmacophore_template.json": tmpl_bytes,
            "inputs/candidate_conformers.json": conf_bytes,
            "inputs/fit_config.json": cfg_bytes,
            "payload/spatial_fit_result.json": result_bytes,
        },
        typed_checks=_TYPED_CHECKS,
        extra_manifest_fields={
            "fragment_anchors": fragment_anchors,
            "dispatch_records": dispatch_records,
        },
    )
    write_bundle(out_dir, content)

    print(f"Bundle written to {out_dir}")
    print(f"  pharmacophore_id : {_PHARMACOPHORE_ID}")
    print(f"  template features: {len(_PHARMACOPHORE_FEATURES)}")
    print(f"  candidates       : {fit['candidate_count']}")
    print(f"  scored           : {fit['scored_count']}")
    print(f"  advanced (top-N) : {fit['advanced_count']}")
    if fit["advanced"]:
        best = fit["advanced"][0]
        worst_advanced = fit["advanced"][-1]
        print(
            f"  best fit         : {best['compound_id']} (RMSD {best['rmsd']:.4f})"
        )
        print(
            f"  cutoff (top-N)   : RMSD {worst_advanced['rmsd']:.4f}"
        )
    print(
        f"  fragment anchors : {len(fragment_anchors)} OpaqueFragment "
        f"(kind_tag=candidate_conformer)"
    )
    print("  dispatch records : 1 (op.kind=PHARMACOPHORE_FIT)")
    print(f"  manifest files   : {len(content.files)}")
    print(f"  manifest         : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic pharmacophore_fit_minimal audit bundle"
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
