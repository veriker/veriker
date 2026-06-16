"""auto_ubi_recompute — verifier-side per-entity feature-aggregation → tier-classify.

Axis-2 value-return form, PROMOTED into the shippable core registry (RECIPE_BOOK.md,
Tier-3 #2 family **D. feature-aggregation → threshold-classify** — an AGGREGATION
shape, NOT a decision-list: there is no per-rule replay; instead trips are grouped
per entity, a fixed feature vector is aggregated, and a rate table classifies it into
one categorical tier). The generic verifier recomputes the representative output on
the SAFE spec-pinned path: no subprocess, no bundle-supplied code.

Re-derivation primitive (one sentence):
    tier_list = ordered list, by SORTED policyholder_id, of {policyholder_id, tier}
        where each tier is the rate-table classification of the telematics features
        re-aggregated per policyholder from the committed telematics/trips.jsonl
        (annual-mileage estimate / hard-brake rate / harsh-accel rate / late-night
        fraction), evaluated against payload/rate_table.json — high-risk surcharge
        first (ANY of the three rate-per-mile / late-night thresholds exceeded,
        STRICT >), then low-mileage discount (annual estimate <= low_max), else
        standard.

Family D vs the decision-list families (A all-pairs / B first-match / C fire-and-
collect). Those replay a committed RULE LIST per record; family D has no rule list —
it AGGREGATES a fixed feature vector per entity (sum/ratio reductions over the
entity's trips) and runs a fixed classifier. The boundary inside family D is real:
the sibling `aml_txn_monitoring` aggregates over TEMPORAL SLIDING WINDOWS (max count
in any 24h / 7d window) + a peer z-score and classifies with a boolean ANY-of-
thresholds rule tree — a different aggregation vocabulary, input layout (3 inputs),
and output type (boolean). They share only the trivial group-by-id → aggregate →
classify → emit-ordered-list skeleton; the feature vocabulary IS the rule and is
domain-specific, so each is its OWN primitive (a single primitive would need a
bundle-supplied feature-DSL + threshold-tree config — the construct rejected at
cluster level because it relocates the rule into bundle config, diluting
"primitive_id IS the rule").

FP-drift safety. The aggregated features are floats (mileage sums, per-mile ratios),
but they are consumed ONLY to SELECT a categorical tier via threshold comparison;
the representative output is the categorical tier STRING (+ policyholder_id) — the
adjustment_pct and the float feature values are projected OUT, so the `exact`
comparator is float-free. This is sound only because the committed dataset sits well
clear of every threshold boundary (the categorical selection is deterministic for it);
a dataset balanced ON a threshold to ~1 ULP is out of scope for an `exact` tier claim.

The replay rule (feature aggregation + half-open rate-table classification with
high-risk precedence, sorted policyholder order) is FIXED here — the primitive_id
("auto_ubi_recompute") IS the rule. The auditor's SHA-pinned spec binds the output
type "auto_ubi_tier_list" to this primitive_id and to an `exact` comparator; a
producer cannot weaken the aggregation/classification without changing the
primitive_id, which the anchor rejects.

Faithfulness (Gate B). The promoted test derives the honest claim from the pilot's
OWN producer (examples/auto_ubi_minimal/_build_bundle.py emits
payload/rating_decisions.json from an independent inline copy of _aggregate_features /
_classify_tier — enforced disjoint by tests/test_recipe_producer_verifier_
disjoint.py), projected to {policyholder_id, tier}, never from this module. This
recompute MIRRORS that producer's _aggregate_features / _classify_tier (modulo the
projection to tier only and the producer's extra adjustment_pct) — asserted directly
by a core-vs-producer agreement test over each classifier branch (each surcharge
condition at/above/below its STRICT-> boundary, low-mileage at/at-boundary/above, the
standard fall-through, and high-risk PRECEDENCE over low-mileage) and the sorted-
policyholder ORDER (entity order != insertion order, so the sort key is discriminated),
PLUS a direct artifact-faithfulness test that runs the real producer build(), reads
its emitted payload/rating_decisions.json, and asserts compute_tier_list over the
committed inputs equals that artifact's {policyholder_id, tier} projection — so the
grouping/order faithfulness is proven against the producer's EMITTED ARTIFACT, not a
test-side paraphrase of build(). NOTE: the pilot's own spec_pinned_check.py computes
its claim via this shared recompute (a build->verify roundtrip demo) — that path is
NOT a producer-disjoint Gate-B proof (it is f(x)==f(x) by construction); the promoted
test is the Gate-B proof (claim from the producer artifact, primitive resolved only
via core auto-registration).

SCOPE / COVERAGE HONESTY. This safe-path check re-derives STRICTLY LESS than the
pilot's own (unsafe, subprocess) re_derive pack, which additionally re-checks the
float feature columns (total_miles, annual_mileage_est, the per-mile rates, late-
night fraction) and adjustment_pct. On this path a tampered float-feature column or
adjustment_pct inside rating_decisions.json is NOT caught — only a change to the
per-entity categorical tier (or the entity set/order) is. That is the deliberate
trade for the float-free `exact` tier claim.

Stdlib-only (§C5 core verify() path): json is stdlib.
"""

from __future__ import annotations

from pathlib import Path

from ...admission import admit_json_file, admit_jsonl_file
from ...plugin import ParsedInputs, RecomputedValue
from ..registry import register_primitive

# Observation window in days (used to project annual mileage). Must match the
# value in the producer _build_bundle.py.
_OBSERVATION_DAYS = 7
_DAYS_PER_YEAR = 365.25


# ---------------------------------------------------------------------------
# Feature aggregation + rate-table classification — MIRRORS the producer
# _build_bundle.py (_aggregate_features / _classify_tier) EXACTLY.
# ---------------------------------------------------------------------------


def _aggregate_features(trips: list[dict]) -> dict:
    """Aggregate telematics features from a list of trip dicts (stdlib only).

    Mirrors the producer's _aggregate_features EXACTLY, including its BARE arithmetic
    (no float()/int() coercion). This faithfulness matters: an earlier draft coerced
    the numeric fields, which made the core fail OPEN relative to the producer — on a
    numeric-string value (e.g. "8.2") the producer's `sum(t["distance_miles"] ...)`
    raises TypeError while a coercing core would silently succeed. Bare arithmetic
    here means both behave identically on every input (numeric works; a string raises
    TypeError on both; a missing key raises KeyError on both), and the agreement test
    asserts that parity.
    """
    total_miles = sum(t["distance_miles"] for t in trips)
    total_hard_brakes = sum(t["hard_brakes"] for t in trips)
    total_harsh_accels = sum(t["harsh_accels"] for t in trips)
    late_night_count = sum(1 for t in trips if t["late_night"])
    trip_count = len(trips)
    annual_mileage_est = total_miles * (_DAYS_PER_YEAR / _OBSERVATION_DAYS)
    hard_brake_per_mile = total_hard_brakes / total_miles if total_miles > 0 else 0.0
    harsh_accel_per_mile = total_harsh_accels / total_miles if total_miles > 0 else 0.0
    late_night_fraction = late_night_count / trip_count if trip_count > 0 else 0.0
    return {
        "total_miles": total_miles,
        "annual_mileage_est": annual_mileage_est,
        "hard_brake_per_mile": hard_brake_per_mile,
        "harsh_accel_per_mile": harsh_accel_per_mile,
        "late_night_fraction": late_night_fraction,
        "trip_count": trip_count,
    }


def _classify_tier(features: dict, rate_table: dict) -> str:
    """Apply rate-table thresholds to features; return the categorical tier name.

    Mirrors the producer's _classify_tier EXACTLY: high-risk check first (ANY of the
    three thresholds exceeded with STRICT >, overrides the low-mileage discount when
    triggered), then low-mileage discount (annual estimate <= low_max), else standard.
    Only the categorical tier label is returned (the producer additionally returns an
    adjustment_pct, which is out of scope for this re-derivation).
    """
    thresholds = rate_table["tier_thresholds"]

    is_high_risk = (
        features["hard_brake_per_mile"]
        > thresholds["hard_brake_per_mile_surcharge_threshold"]
        or features["harsh_accel_per_mile"]
        > thresholds["harsh_accel_per_mile_surcharge_threshold"]
        or features["late_night_fraction"]
        > thresholds["late_night_fraction_surcharge_threshold"]
    )
    if is_high_risk:
        return "high_risk_surcharge"

    is_low_mileage = (
        features["annual_mileage_est"] <= thresholds["annual_mileage_low_max"]
    )
    if is_low_mileage:
        return "low_mileage_discount"

    return "standard"


def compute_tier_list(trips: list[dict], rate_table: dict) -> list[dict]:
    """Canonical re-derivation of the ordered categorical tier list.

    Group trips by policyholder, then in SORTED policyholder_id order: aggregate
    features, classify the tier, emit {policyholder_id, tier}. Categorical output
    only (no adjustment_pct) — exact-safe.

    Fail-closed: raises TypeError if trips is not a list, and KeyError/TypeError if a
    trip or the rate table is malformed (missing policyholder_id / a feature field /
    tier_thresholds); the verifier must not invent a tier list. An EMPTY trip list is
    a pure reduction to [] (no policyholders → no tiers); the "no input → error" guard
    lives at the I/O boundary instead (recompute() raises ValueError on an empty
    trips.jsonl, and _load_trips raises FileNotFoundError on an absent file), so a
    third party cannot pass an empty-but-present input off as a successful re-derivation.
    """
    if not isinstance(trips, list):
        raise TypeError("trips must be a JSON array")

    trips_by_ph: dict[str, list[dict]] = {}
    for trip in trips:
        ph_id = trip["policyholder_id"]
        trips_by_ph.setdefault(ph_id, []).append(trip)

    tier_list: list[dict] = []
    for ph_id in sorted(trips_by_ph.keys()):
        features = _aggregate_features(trips_by_ph[ph_id])
        tier = _classify_tier(features, rate_table)
        tier_list.append({"policyholder_id": str(ph_id), "tier": str(tier)})
    return tier_list


def _load_trips(bundle_dir: Path) -> list[dict]:
    """Read telematics/trips.jsonl into a list of trip dicts (one per non-blank line)."""
    p = bundle_dir / "telematics" / "trips.jsonl"
    if not p.is_file():
        raise FileNotFoundError(
            f"telematics/trips.jsonl not found in bundle at {bundle_dir}"
        )
    trips = admit_jsonl_file(p)
    return trips


def _load_rate_table(bundle_dir: Path) -> dict:
    """Read payload/rate_table.json (the committed tier thresholds)."""
    p = bundle_dir / "payload" / "rate_table.json"
    if not p.is_file():
        raise FileNotFoundError(
            f"payload/rate_table.json not found in bundle at {bundle_dir}"
        )
    return admit_json_file(p)


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered at import for the core registry)
# ---------------------------------------------------------------------------


class AutoUbiRecompute:
    """Verifier-side primitive: re-derive the ordered per-policyholder tier list
    from the committed telematics trips + rate table."""

    primitive_id: str = "auto_ubi_recompute"

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        """Recompute the per-policyholder tier list from telematics/trips.jsonl and
        payload/rate_table.json. Returns the recomputed VALUE only; the auditor-
        anchored `exact` comparator decides agreement against the producer's claim.
        """
        bundle_dir: Path = inputs.bundle_dir
        trips = _load_trips(bundle_dir)
        if not trips:
            raise ValueError("telematics/trips.jsonl is empty — cannot re-derive")
        rate_table = _load_rate_table(bundle_dir)
        value = compute_tier_list(trips, rate_table)
        return RecomputedValue(
            value=value,
            detail=f"re-derived tier list over {len(value)} policyholder(s)",
        )


register_primitive(AutoUbiRecompute())
