"""iso42001_fairness_recompute.py — verifier-side fairness-metric re-derivation.

Axis-2 value-return form (SPEC_PINNED_DISPATCH_ARCHITECTURE §3.3).

Domain: ISO/IEC 42001:2023 Annex A.5 (Assessing Impacts of AI Systems) — the
AI-system impact-assessment process. The QUANTIFIED part of an impact assessment
(a fairness / adverse-impact metric across protected groups) is the pilotable
slice; the qualitative judgement is not. A 42001-conforming AIMS discloses a
disparate-impact figure in its impact assessment; today an auditor takes it on
the org's word.

Re-derivation primitive (one sentence):
    disparate_impact_ratio = min(group selection rates) / max(group selection
    rates), the EEOC "four-fifths rule" statistic over the declared outcomes.

The method (min-rate / max-rate over per-group favorable-outcome rates) is FIXED
in this primitive — the primitive_id IS the rule. A producer cannot swap a more
flattering fairness definition (e.g. a privileged-group-favouring convention)
without changing the primitive_id, which the auditor's SHA-pinned spec rejects.

HONEST CLAIM BOUNDARY: proves the REPORTED fairness figure is RE-DERIVABLE from
the declared per-subject outcomes and tamper-evident under the auditor's pinned
rule. It does NOT prove the groups/outcomes are correctly recorded, that the
metric is the RIGHT fairness measure for the context, or that the org satisfies
the A.5 control (which needs the impact-assessment process the AIMS owns).
Synthetic data; no customer.

Stdlib-only (§C5 contract).
"""

from __future__ import annotations

import json
from pathlib import Path


# ---------------------------------------------------------------------------
# Canonical computation (shared by _build_bundle.py via direct import)
# ---------------------------------------------------------------------------


def compute_disparate_impact_ratio(records: list) -> float:
    """EEOC four-fifths disparate-impact ratio = min_rate / max_rate over the
    per-group favorable-outcome rates.

    Each record: {"group": <hashable>, "outcome": 0|1} (outcome 1 = favorable).
    Returns a float in (0, 1]. Raises ValueError on <2 groups, an empty group,
    or an all-zero max rate (ratio undefined).
    """
    if not records:
        raise ValueError("no outcome records — disparate impact undefined")

    totals: dict[object, int] = {}
    favorable: dict[object, int] = {}
    for r in records:
        g = r.get("group")
        if g is None:
            raise ValueError("every record must carry a non-null 'group'")
        outcome = int(r["outcome"])
        if outcome not in (0, 1):
            raise ValueError(f"outcome must be 0 or 1, got {outcome!r}")
        totals[g] = totals.get(g, 0) + 1
        favorable[g] = favorable.get(g, 0) + (1 if outcome == 1 else 0)

    if len(totals) < 2:
        raise ValueError("need >=2 groups to compute a disparate-impact ratio")

    rates = [favorable[g] / totals[g] for g in totals]
    max_rate = max(rates)
    if max_rate == 0.0:
        raise ValueError("max group selection rate is 0 — ratio undefined")
    return min(rates) / max_rate


# ---------------------------------------------------------------------------
# ReDerivationPrimitive class (registered by verify.py before BundleVerifier)
# ---------------------------------------------------------------------------


class Iso42001DisparateImpactRecompute:
    """Verifier-side primitive for re-deriving a disparate-impact ratio."""

    primitive_id: str = "iso42001_disparate_impact_recompute"

    def recompute(self, inputs, pack_section: dict):
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        bundle_dir: Path = inputs.bundle_dir
        path = bundle_dir / "inputs" / "outcomes.json"
        if not path.is_file():
            raise FileNotFoundError(
                f"inputs/outcomes.json not found in bundle at {bundle_dir}"
            )
        doc = json.loads(path.read_bytes())
        records = doc.get("outcomes")
        if not isinstance(records, list):
            raise ValueError("inputs/outcomes.json must contain an 'outcomes' array")
        value = compute_disparate_impact_ratio(records)
        n_groups = len({r.get("group") for r in records})
        return RecomputedValue(
            value=value,
            detail=f"re-derived disparate-impact ratio over {len(records)} subjects, {n_groups} groups",
        )
