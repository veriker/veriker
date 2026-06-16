"""iso42001_dataquality_recompute.py — verifier-side data-quality re-derivation.

Axis-2 value-return form (SPEC_PINNED_DISPATCH_ARCHITECTURE §3.3).

Domain: ISO/IEC 42001:2023 Annex A.7 (Data for AI Systems) — the data-quality
sub-controls (Quality of Data / Data Preparation). A 42001-conforming AIMS
reports data-quality figures for its training/eval datasets (e.g. "98% complete,
1.5% duplicates, 35% positive class"). Today an auditor takes those figures on
the org's word; the dataset and the statistics are not independently re-checked.

This is a MULTI-OUTPUT pilot: one type-switching primitive re-derives three
distinct quality metrics from the same declared dataset. Each metric is a
separate manifest.outputs entry bound (by the auditor's spec) to the SAME
primitive_id under the SAME scalar_epsilon comparator — which satisfies the
substrate's monotone-strictness invariant (a primitive bound by >=2 types must
carry an identical comparator).

Re-derivation rules (FIXED in this primitive — the primitive_id IS the rule):
  data_completeness_pct  = 100 · (# records with EVERY required field non-null)
                            ÷ (# records)
  data_duplicate_rate_pct = 100 · (# records − # distinct required-field tuples)
                            ÷ (# records)
  data_positive_rate_pct = 100 · (# records with label == 1)
                            ÷ (# records with non-null label)

Required fields: ("feature_a", "feature_b", "label"). "non-null" means the JSON
value is not null/None.

HONEST CLAIM BOUNDARY: proves the REPORTED data-quality figures are RE-DERIVABLE
from the declared dataset and tamper-evident under the auditor's pinned rules.
It does NOT prove the dataset is suitable, the labels are correct, or that the
organization satisfies the A.7 control (which needs the data-governance process
the AIMS owns). Synthetic data; no customer.

Stdlib-only (§C5 contract).
"""

from __future__ import annotations

import json
from pathlib import Path

_REQUIRED_FIELDS = ("feature_a", "feature_b", "label")

# Output type -> the metric it re-derives. The verifier dispatches on the
# auditor-pinned output type; an unknown type is fail-closed (ValueError).
_COMPLETENESS = "data_completeness_pct"
_DUPLICATE = "data_duplicate_rate_pct"
_POSITIVE = "data_positive_rate_pct"


# ---------------------------------------------------------------------------
# Canonical computations (shared by _build_bundle.py via direct import)
# ---------------------------------------------------------------------------


def _records(doc: dict) -> list:
    recs = doc.get("records")
    if not isinstance(recs, list) or not recs:
        raise ValueError("dataset must contain a non-empty 'records' array")
    return recs


def compute_completeness_pct(records: list) -> float:
    """Percent of records whose every required field is non-null."""
    if not records:
        raise ValueError("empty records — completeness undefined")
    complete = sum(
        1
        for r in records
        if all(r.get(f) is not None for f in _REQUIRED_FIELDS)
    )
    return 100.0 * complete / len(records)


def compute_duplicate_rate_pct(records: list) -> float:
    """Percent of records that are exact duplicates on the required-field tuple
    (i.e. (n - n_distinct) / n)."""
    if not records:
        raise ValueError("empty records — duplicate rate undefined")
    tuples = [tuple(r.get(f) for f in _REQUIRED_FIELDS) for r in records]
    # tuple elements (str/int/float/None) are hashable; no sort of adversarial
    # keys (§C9) — set() is order-independent and safe here.
    n_distinct = len(set(tuples))
    return 100.0 * (len(records) - n_distinct) / len(records)


def compute_positive_rate_pct(records: list) -> float:
    """Percent of label==1 among records with a non-null label."""
    labelled = [r for r in records if r.get("label") is not None]
    if not labelled:
        raise ValueError("no labelled records — positive rate undefined")
    positives = sum(1 for r in labelled if int(r["label"]) == 1)
    return 100.0 * positives / len(labelled)


# type -> canonical compute fn (the dispatch table the primitive switches on)
_METRIC_FNS = {
    _COMPLETENESS: compute_completeness_pct,
    _DUPLICATE: compute_duplicate_rate_pct,
    _POSITIVE: compute_positive_rate_pct,
}

ALL_METRIC_TYPES = tuple(_METRIC_FNS)


# ---------------------------------------------------------------------------
# ReDerivationPrimitive class (registered by verify.py before BundleVerifier)
# ---------------------------------------------------------------------------


class Iso42001DataQualityRecompute:
    """Verifier-side primitive; type-switches across the A.7 quality metrics."""

    primitive_id: str = "iso42001_dataquality_recompute"

    def recompute(self, inputs, pack_section: dict):
        """Recompute the metric named by pack_section['type'] from
        inputs/dataset.json. Fail-closed on an unknown type."""
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        type_key = pack_section.get("type")
        fn = _METRIC_FNS.get(type_key)
        if fn is None:
            raise ValueError(
                f"unknown data-quality metric type {type_key!r} "
                f"(known: {ALL_METRIC_TYPES!r})"
            )

        bundle_dir: Path = inputs.bundle_dir
        ds_path = bundle_dir / "inputs" / "dataset.json"
        if not ds_path.is_file():
            raise FileNotFoundError(
                f"inputs/dataset.json not found in bundle at {bundle_dir}"
            )
        doc = json.loads(ds_path.read_bytes())
        records = _records(doc)
        value = fn(records)
        return RecomputedValue(
            value=value,
            detail=f"re-derived {type_key} over {len(records)} records",
        )
