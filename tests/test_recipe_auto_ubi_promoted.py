"""tests/test_recipe_auto_ubi_promoted.py — the `feature-aggregation → threshold-
classify` shape (Tier-3 #2 family D), PROMOTED into the shippable core registry
(RECIPE_BOOK.md). Family D is an AGGREGATION shape, NOT a decision-list: trips are
grouped per entity, a fixed feature vector is aggregated (sum/ratio reductions), and
a rate table classifies it into one categorical tier (high-risk surcharge first with
STRICT >, then low-mileage discount, else standard).

Two things are proven, deliberately without a tautology:

  GENERIC SAFE PATH. The bundle is verified by a BARE BundleVerifier under an
  auditor SpecAnchor with NO demo-local register_primitive and WITHOUT importing
  the primitive module at all. The recompute resolves ONLY via core
  auto-registration (run_spec_pinned_dispatch -> _ensure_primitives_loaded ->
  import primitives -> auto_ubi self-registers). If unpromoted, dispatch ->
  UNKNOWN_PRIMITIVE.

  PRODUCER-FAITHFULNESS (not f(x)==f(x)). The producer's claimed tier list is the
  {policyholder_id, tier} projection of the producer's OWN
  payload/rating_decisions.json — emitted by _build_bundle.py's inline
  _aggregate_features / _classify_tier, an INDEPENDENT code copy from the verifier's
  primitives/auto_ubi.py (disjointness enforced structurally by
  test_recipe_producer_verifier_disjoint.py). (The producer decisions additionally
  carry the float feature columns + adjustment_pct — all out of scope for this
  re-derivation and projected out; only the categorical tier remains so the `exact`
  comparator stays float-free.) The verifier re-derives its own tier list from the
  committed telematics/ + payload/rate_table.json and the `exact` comparator compares
  element-wise. An honest PASS proves the two independent aggregation+classification
  paths agree; the claim is never routed through the verifier's own compute_tier_list.

Run SOLO — shared bundle basenames collide in one pytest process.

Surfaces:
  1. Honest bundle -> PASS (generic safe path AND producer-faithfulness).
  2. Tampered claimed tier (flip PHD-001's tier) -> REDERIVATION_MISMATCH.
  3. Tampered committed input trip (raise T001-001 hard_brakes 0 -> 10 so PHD-001's
     hard_brake_per_mile crosses the surcharge threshold and the re-derived tier
     flips low_mileage_discount -> high_risk_surcharge, diverging from the honest
     claim) -> REDERIVATION_MISMATCH.
For (2)/(3) the manifest file SHA is re-aligned so FileIntegrity does not fire first.

Stdlib-only orchestration; the build runs the pilot's real producer _build_bundle.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# NOTE: the verifier's recompute primitive (primitives/auto_ubi.py) is deliberately
# NOT imported here. The claim is derived from the producer artifact, and the
# primitive must resolve ONLY via dispatch's core auto-registration.
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.dispatch_record_wellformed import (  # noqa: E402
    DispatchRecordWellformedCheck,
)
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from examples._spec_pinned_overlay import apply_overlay, compute_anchor  # noqa: E402

_PILOT_DIR = _PKG_ROOT / "examples" / "auto_ubi_minimal"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "auto_ubi.spec.json"
_PRODUCER_CLAIM_REL = "payload/rating_decisions.json"
_OUTPUT_ID = "auto_ubi_tier_list"
_TYPE_KEY = "auto_ubi_tier_list"
# The re-derived value's representative fields (categorical only — the float feature
# columns and adjustment_pct are out of scope).
_REDERIVED_FIELDS = ("policyholder_id", "tier")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _producer_claim(out_dir: Path) -> list:
    """The producer's INDEPENDENT rating decisions, projected to {policyholder_id,
    tier}. The producer emits them already sorted by policyholder_id."""
    decisions = json.loads((out_dir / _PRODUCER_CLAIM_REL).read_bytes())
    return [{k: rec[k] for k in _REDERIVED_FIELDS} for rec in decisions]


def _build(out_dir: Path, *, claimed_override=None):
    """Build a spec-pinned auto_ubi bundle producer-side. Returns (bundle, anchor).

    The base bundle is produced by the pilot's real _build_bundle.py (telematics/,
    payload/rate_table.json, payload/rating_decisions.json, manifest). The HONEST
    claim is the producer's OWN decisions projected to {policyholder_id, tier}. The
    generic β overlay then adds the auditor spec, the producer claimed-value file,
    and manifest.outputs.
    """
    subprocess.run(
        [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(out_dir)],
        check=True,
        capture_output=True,
    )
    claimed = _producer_claim(out_dir) if claimed_override is None else claimed_override
    apply_overlay(
        out_dir,
        spec_src_path=_SPEC_SRC,
        output_id=_OUTPUT_ID,
        type_key=_TYPE_KEY,
        claimed_value=claimed,
    )
    mp = out_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["typed_checks"] = ["file_integrity_many_small"]
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))
    return out_dir, compute_anchor(_SPEC_SRC)


def _realign_file_sha(bundle_dir: Path, rel: str) -> None:
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][rel] = _sha256((bundle_dir / rel).read_bytes())
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))


def _verify(bundle_dir: Path, anchor):
    # BARE verifier: FileIntegrity + spec-pinned dispatch under the auditor anchor.
    # NO register_primitive — the recompute resolves only via the CORE registry.
    return BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            # The bundle carries dispatch_records; verify()'s stamp-claims
            # coverage guard fails closed unless C15 well-formedness and the
            # C14 lattice claim are both evaluated (2026-06-12). Orthogonal
            # to what this test proves (core-registry recompute path).
            DispatchRecordWellformedCheck(op_kinds_admitted=frozenset({"RATE_TABLE_LOOKUP", "COMPUTE"})),
            StampLatticeCheck(),
        ],
        spec_anchor=anchor,
    ).verify(bundle_dir)


def test_promoted_generic_safe_path_and_faithfulness_pass(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    result = _verify(bundle_dir, anchor)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]
    # Sanity: the honest claim covers all 5 policyholders, sorted, with both a
    # discount and a surcharge tier present (the fixture spans the classifier).
    claim = json.loads((bundle_dir / "outputs" / f"{_OUTPUT_ID}.json").read_bytes())[
        "value"
    ]
    ids = [r["policyholder_id"] for r in claim]
    assert ids == sorted(ids) and len(ids) == 5, ids
    tiers = {r["tier"] for r in claim}
    assert "low_mileage_discount" in tiers and "high_risk_surcharge" in tiers, tiers


def test_promoted_tampered_value_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Flip the first claimed tier (PHD-001 honest = low_mileage_discount).
    claim_path = bundle_dir / "outputs" / f"{_OUTPUT_ID}.json"
    doc = json.loads(claim_path.read_bytes())
    rows = doc["value"]
    assert rows, "expected a non-empty claimed tier list"
    original = rows[0]["tier"]
    rows[0]["tier"] = "standard" if original != "standard" else "high_risk_surcharge"
    claim_path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    _realign_file_sha(bundle_dir, f"outputs/{_OUTPUT_ID}.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert _reason_codes(result) == {"REDERIVATION_MISMATCH"}, _reason_codes(result)


def test_promoted_tampered_input_trip_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # PHD-001 honestly classifies low_mileage_discount. Raise T001-001 hard_brakes
    # 0 -> 10: PHD-001's hard_brake_per_mile crosses the 0.04 surcharge threshold so
    # the re-derived tier flips to high_risk_surcharge, diverging from the honest
    # low_mileage_discount claim.
    trips_path = bundle_dir / "telematics" / "trips.jsonl"
    lines = [ln for ln in trips_path.read_text("utf-8").splitlines() if ln.strip()]
    out_lines: list[str] = []
    flipped = False
    for ln in lines:
        trip = json.loads(ln)
        if trip.get("trip_id") == "T001-001":
            assert trip["hard_brakes"] == 0, trip
            trip["hard_brakes"] = 10
            flipped = True
        out_lines.append(json.dumps(trip, sort_keys=True))
    assert flipped, "expected to find trip T001-001 to mutate"
    trips_path.write_bytes(("\n".join(out_lines) + "\n").encode("utf-8"))
    _realign_file_sha(bundle_dir, "telematics/trips.jsonl")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert _reason_codes(result) == {"REDERIVATION_MISMATCH"}, _reason_codes(result)


def test_promoted_loaders_fail_closed_on_missing_inputs(tmp_path):
    """The recompute loaders must raise (-> RECOMPUTE_ERROR at dispatch), never
    invent a tier list, when a committed input file is absent."""
    import pytest

    from audit_bundle.rederivation.primitives.auto_ubi import (
        _load_rate_table,
        _load_trips,
    )

    empty = tmp_path / "empty_bundle"
    empty.mkdir()
    with pytest.raises(FileNotFoundError):
        _load_trips(empty)
    with pytest.raises(FileNotFoundError):
        _load_rate_table(empty)


def _load_producer_module():
    """Load the pilot's producer _build_bundle.py by path (unique module name) so we
    can reach its INDEPENDENT inline _aggregate_features / _classify_tier. Module-level
    execution is just constants + function defs (build() is guarded by __main__)."""
    import importlib.util as ilu

    spec = ilu.spec_from_file_location(
        "auto_ubi__producer_for_agreement", _BUILD_SCRIPT
    )
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_core_and_producer_classify_agree_across_branches():
    """Faithfulness across classifier branches, not just the 5-policyholder fixture.

    Import the core primitive's _aggregate_features / _classify_tier / compute_tier_
    list HERE (not at module top — the Gate-B surfaces above must resolve the
    primitive only via core auto-registration) and the producer's INDEPENDENT inline
    copies, and assert they agree over: each surcharge condition at/above/below its
    STRICT-> boundary, low-mileage at/at-boundary/above, the standard fall-through,
    high-risk PRECEDENCE over low-mileage, and the sorted-policyholder ORDER (entity
    order != insertion order, so the sort key is discriminated). Proves the recompute
    mirrors the producer by construction.
    """
    from audit_bundle.rederivation.primitives.auto_ubi import (
        _aggregate_features as core_agg,
    )
    from audit_bundle.rederivation.primitives.auto_ubi import (
        _classify_tier as core_classify,
    )
    from audit_bundle.rederivation.primitives.auto_ubi import (
        compute_tier_list as core_tier_list,
    )

    producer = _load_producer_module()
    prod_agg = producer._aggregate_features
    # The producer's _classify_tier returns (tier, adjustment_pct); project to tier.
    prod_classify = lambda f, rt: producer._classify_tier(f, rt)[0]  # noqa: E731

    rate_table = {
        "tier_thresholds": {
            "annual_mileage_low_max": 7500,
            "annual_mileage_high_min": 15000,
            "hard_brake_per_mile_surcharge_threshold": 0.04,
            "harsh_accel_per_mile_surcharge_threshold": 0.03,
            "late_night_fraction_surcharge_threshold": 0.15,
        },
        # `tiers` is consumed only by the producer (for adjustment_pct); the core
        # classifier ignores it. Provide it so the producer copy runs.
        "tiers": {
            "low_mileage_discount": {"discount_pct": 15},
            "standard": {"discount_pct": 0},
            "high_risk_surcharge": {"surcharge_pct": 20},
        },
    }

    def trip(ph, miles, hb=0, ha=0, late=False, tid="t"):
        return {
            "trip_id": tid,
            "policyholder_id": ph,
            "distance_miles": miles,
            "hard_brakes": hb,
            "harsh_accels": ha,
            "late_night": late,
        }

    # --- _aggregate_features agreement on a representative entity. ---
    sample = [trip("P", 100.0, hb=2, ha=1, late=True), trip("P", 100.0, hb=0, ha=0)]
    fa_core = core_agg(sample)
    fa_prod = prod_agg(sample)
    assert fa_core == fa_prod, (fa_core, fa_prod)

    # --- _classify_tier across each branch (hand-built feature dicts). ---
    def feats(hbpm=0.0, hapm=0.0, lnf=0.0, annual=10000.0):
        return {
            "hard_brake_per_mile": hbpm,
            "harsh_accel_per_mile": hapm,
            "late_night_fraction": lnf,
            "annual_mileage_est": annual,
            "total_miles": 100.0,
            "trip_count": 5,
        }

    cases = [
        feats(hbpm=0.041),  # hard-brake just ABOVE 0.04 -> surcharge
        feats(hbpm=0.04),  # hard-brake AT 0.04 (strict >) -> not surcharge -> standard
        feats(hbpm=0.039),  # just BELOW -> standard
        feats(hapm=0.031),  # harsh-accel above 0.03 -> surcharge
        feats(hapm=0.03),  # AT boundary -> standard
        feats(lnf=0.151),  # late-night above 0.15 -> surcharge
        feats(lnf=0.15),  # AT boundary -> standard
        feats(annual=7500.0),  # annual AT low_max (<=) -> low_mileage_discount
        feats(annual=7500.01),  # just above low_max -> standard
        feats(annual=1000.0),  # well under -> low_mileage_discount
        feats(
            hbpm=0.05, annual=1000.0
        ),  # PRECEDENCE: low-mileage BUT high-risk -> surcharge
    ]
    for f in cases:
        assert core_classify(f, rate_table) == prod_classify(f, rate_table), f
    # Spot-check the precedence + boundary results explicitly (not just agreement).
    assert core_classify(feats(hbpm=0.04), rate_table) == "standard"
    assert core_classify(feats(annual=7500.0), rate_table) == "low_mileage_discount"
    assert (
        core_classify(feats(hbpm=0.05, annual=1000.0), rate_table)
        == "high_risk_surcharge"
    )

    # --- ORDER DISCRIMINATION (core property): emit in SORTED policyholder_id order,
    # NOT insertion/first-seen order. Insertion order P-3, P-1, P-2; sorted order
    # P-1, P-2, P-3. A recompute that (wrongly) emitted in insertion order would
    # differ. This is a property of the SHIPPING core (compute_tier_list); the
    # producer-faithfulness of the grouping/order on REAL data is proven separately,
    # against the producer's emitted artifact, by
    # test_core_recompute_matches_producer_emitted_artifact below.
    trips = [
        trip("P-3", 100.0, tid="a"),
        trip("P-1", 100.0, hb=10, tid="b"),  # high hard-brake -> surcharge
        trip("P-2", 1000.0, tid="c"),  # high mileage -> standard
    ]
    core_out = core_tier_list(trips, rate_table)
    assert [r["policyholder_id"] for r in core_out] == ["P-1", "P-2", "P-3"], core_out
    assert [r["policyholder_id"] for r in core_out] != ["P-3", "P-1", "P-2"], (
        "must NOT be insertion order"
    )

    # --- fail-closed parity: malformed input raises on BOTH copies. ---
    import pytest

    # Missing "distance_miles" -> KeyError on both aggregators.
    bad = [
        {
            "policyholder_id": "P",
            "hard_brakes": 0,
            "harsh_accels": 0,
            "late_night": False,
        }
    ]
    with pytest.raises(KeyError):
        core_agg(bad)
    with pytest.raises(KeyError):
        prod_agg(bad)
    # Numeric-STRING value -> TypeError on BOTH (bare arithmetic; the core does NOT
    # coerce, so it fails closed exactly as the producer does — the divergence an
    # earlier coercing draft would have introduced).
    str_trip = [trip("P", "100.0", tid="s")]
    with pytest.raises(TypeError):
        core_agg(str_trip)
    with pytest.raises(TypeError):
        prod_agg(str_trip)
    # Non-list trips -> TypeError on the core compute (isinstance guard).
    with pytest.raises(TypeError):
        core_tier_list(5, rate_table)


def test_core_recompute_matches_producer_emitted_artifact(tmp_path):
    """ARTIFACT faithfulness (closes the grouping/order gap): run the REAL producer
    build(), read its emitted payload/rating_decisions.json, and assert the core
    compute_tier_list over the committed telematics/rate_table inputs equals that
    artifact's {policyholder_id, tier} projection. This proves grouping + sorted-order
    faithfulness against the producer's EMITTED ARTIFACT (not a test-side paraphrase
    of build()). The core primitive is imported locally — the Gate-B dispatch surfaces
    above still resolve it only via core auto-registration.
    """
    from audit_bundle.rederivation.primitives.auto_ubi import (
        _load_rate_table,
        _load_trips,
        compute_tier_list,
    )

    bundle_dir = tmp_path / "bundle"
    subprocess.run(
        [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(bundle_dir)],
        check=True,
        capture_output=True,
    )
    decisions = json.loads((bundle_dir / _PRODUCER_CLAIM_REL).read_bytes())
    artifact_projection = [{k: d[k] for k in _REDERIVED_FIELDS} for d in decisions]

    trips = _load_trips(bundle_dir)
    rate_table = _load_rate_table(bundle_dir)
    core = compute_tier_list(trips, rate_table)
    assert core == artifact_projection, (core, artifact_projection)

    # FP-margin guard (the `exact`-on-categorical-tier soundness rests on the dataset
    # sitting clear of every threshold): PHD-001 honestly classifies low_mileage_
    # discount, so its annual estimate must be strictly under the low_max with margin.
    from audit_bundle.rederivation.primitives.auto_ubi import _aggregate_features

    by_ph: dict = {}
    for t in trips:
        by_ph.setdefault(t["policyholder_id"], []).append(t)
    phd001 = _aggregate_features(by_ph["PHD-001"])
    low_max = rate_table["tier_thresholds"]["annual_mileage_low_max"]
    assert phd001["annual_mileage_est"] < low_max * 0.95, phd001["annual_mileage_est"]
