"""dp_recompute — verifier-side differential-privacy (Laplace seeded-noise aggregate) re-derivation.

Axis-2 value-return form of the differential-privacy (Laplace seeded-noise
aggregate) re-derivation, PROMOTED into the shippable core registry
(RECIPE_BOOK.md). The generic verifier recomputes the representative output on
the SAFE spec-pinned path: no subprocess, no bundle-supplied code — the recompute
rule lives HERE in verifier-distribution code and the comparator + tolerance come
from the auditor-anchored spec.

Re-derivation primitive (one sentence):
    noised_count = float(true_count) + laplace_noise(scale = sensitivity / epsilon, seed)

where true_count is re-counted from data/dataset.jsonl under the committed
predicate (from payload/dp_release.json), and the Laplace variate is re-drawn
deterministically from random.Random(seed) by inverse-CDF:
    noise = -scale * sign(u - 0.5) * log(1 - 2*|u - 0.5|),  u = Random(seed).random().

This mirrors the legacy pack (dp_re_derivation.py / _build_bundle.py) EXACTLY:
same predicate-match, same _laplace_noise formula, same seed source. The seed,
epsilon, sensitivity and predicate are read from the COMMITTED bundle
(payload/dp_release.json), so the noise is reproducible from committed evidence.
The aggregation/noise rule is FIXED in this primitive — the primitive_id
("dp_recompute") IS the rule. The auditor's SHA-pinned spec binds the output
type "dp_noised_count" to this primitive_id and to a scalar_epsilon comparator;
a producer cannot weaken the rule without changing the primitive_id / spec SHA,
which the anchor rejects.

Comparator: scalar_epsilon=1e-6 (not exact). Justification is precise:
  - true_count is a plain integer (sum of predicate matches over committed rows).
    It is exactly reproducible across platforms; integer drift is always >= 1,
    which is >> 1e-6, so the tolerance does NOT mask meaningful count drift.
  - The noise term calls math.log, which is a transcendental function delegated
    to the C runtime's libm. Python makes NO guarantee that math.log is
    bit-identical across platforms (glibc vs macOS libm vs Windows CRT can
    differ by ~1 ULP). This is the one genuine reason noised_count is not
    exactly reproducible. 1e-6 is NOT a tight ULP bound — at the committed
    magnitude (~6.4) one double ULP is ~1e-15, so 1e-6 is a deliberately loose
    safety margin: many orders of magnitude larger than the cross-platform
    math.log wobble it needs to absorb, yet still far smaller than the smallest
    meaningful count-drift unit (an integer 1). That two-sided gap (>> ULP,
    << 1) is the point; the exact value of the margin is not load-bearing.
  - random.Random(seed) (Mersenne Twister) IS deterministic and bit-identical
    across CPython versions and platforms for a fixed seed; it does not
    contribute to the tolerance requirement.
  - NOTE — two distinct "epsilon"s: the comparator epsilon HERE (1e-6) is a
    VERIFICATION tolerance. It is unrelated to the DP mechanism's privacy-budget
    epsilon carried in payload/dp_release.json (which feeds scale = sensitivity /
    epsilon). Same word, different knob — do not conflate them.
  - The auditor spec (spec_pinned/dp.spec.json) tags this comparator with the
    optional annotation numeric_model=binary64_libm_tolerated, so an auditor can
    see at a glance that the tolerance is an INTENTIONAL libm margin (the math.log
    case above), not an accidental float coercion. The marker is documentary —
    it does not change pass/fail — and is closed-world-validated by the verifier
    (see audit_bundle/rederivation/comparators.py::_NUMERIC_MODELS).

Faithfulness (the only query classes this primitive re-derives):
  - Laplace mechanism only (name="laplace" in dp_release.json).
  - Predicate = flat key=value equality match over JSONL rows.
  - The noise seed, epsilon, sensitivity are ALL read from the committed
    payload/dp_release.json — not from any producer-supplied parameter outside
    the committed evidence.
  - Primitives raise ValueError on unsupported mechanism name or missing fields;
    the dispatch core records RECOMPUTE_ERROR, never crashes.

Stdlib-only (§C5 core verify() path; S0 is filed/frozen — flag any change to
the 4 S0 core-path limitations).
"""

from __future__ import annotations

import math
import random
from pathlib import Path

from ...admission import admit_json_file, admit_jsonl_file
from ...plugin import ParsedInputs, RecomputedValue
from ..registry import register_primitive


# ---------------------------------------------------------------------------
# Canonical computation — byte-identical to the producer's pack
# (examples/dp_minimal/_build_bundle.py _laplace_noise + count logic)
# ---------------------------------------------------------------------------


def compute_laplace_noise(scale: float, seed: int) -> float:
    """Draw one Laplace(0, scale) variate via inverse-CDF. Deterministic given
    seed. Mirrors the legacy pack's _laplace_noise EXACTLY:
        noise = -scale * sign(u - 0.5) * log(1 - 2*|u - 0.5|),  u = Random(seed).random().
    """
    u = random.Random(seed).random()
    sign = 1.0 if u >= 0.5 else -1.0
    return -scale * sign * math.log(1.0 - 2.0 * abs(u - 0.5))


def compute_noised_count(rows: list, release: dict) -> float:
    """Canonical DP noised-count recompute. Re-counts true_count from rows under
    the committed predicate, re-draws Laplace noise under the committed mechanism
    (laplace, scale = sensitivity / epsilon, seed), and returns
    float(true_count) + noise. Mirrors the legacy pack EXACTLY so the honest
    claimed value and the re-derivation share ONE definition and cannot drift.

    Raises ValueError on a non-laplace or malformed mechanism.
    """
    predicate: dict = release["query"]["predicate"]
    mechanism: dict = release["mechanism"]
    mech_name: str = mechanism["name"]
    if mech_name != "laplace":
        raise ValueError(
            f"unsupported mechanism {mech_name!r}; only 'laplace' is implemented"
        )
    epsilon = float(mechanism["epsilon"])
    sensitivity = float(mechanism["sensitivity"])
    seed = int(mechanism["seed"])

    def _matches(row: dict) -> bool:
        return all(row.get(k) == v for k, v in predicate.items())

    true_count = sum(1 for row in rows if _matches(row))
    scale = sensitivity / epsilon
    noise = compute_laplace_noise(scale=scale, seed=seed)
    return float(true_count) + noise


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered at import for the core registry)
# ---------------------------------------------------------------------------


class DpRecompute:
    """Verifier-side primitive for differential-privacy (Laplace seeded-noise
    aggregate) re-derivation of the noised_count.

    Reads payload/dp_release.json (committed mechanism parameters + predicate)
    and data/dataset.jsonl (committed rows) from the bundle, re-counts the true
    count under the predicate, re-draws the Laplace noise deterministically via
    math.log inverse-CDF, and returns float(true_count) + noise. Returns the
    VALUE only — reads no acceptance epsilon, makes no comparison; the
    auditor-anchored scalar_epsilon comparator (epsilon=1e-6 from the pinned spec)
    decides agreement against the claimed outputs/<id>.json.

    The scalar_epsilon tolerance is justified by math.log cross-platform
    non-reproducibility (see module docstring). The integer true_count is exactly
    reproducible; any count drift is >= 1 >> 1e-6 and cannot be masked.
    """

    primitive_id: str = "dp_recompute"

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        """Recompute the DP noised_count from committed bundle files."""
        bundle_dir: Path = inputs.bundle_dir

        release_path = bundle_dir / "payload" / "dp_release.json"
        if not release_path.is_file():
            raise FileNotFoundError(
                f"payload/dp_release.json not found in bundle at {bundle_dir}"
            )
        # Admission-bounded load (size/depth/cardinality) for the release blob —
        # same discipline as manifest.json; InputInadmissible propagates →
        # dispatch records RECOMPUTE_ERROR.
        release = admit_json_file(release_path)

        dataset_path = bundle_dir / "data" / "dataset.jsonl"
        if not dataset_path.is_file():
            raise FileNotFoundError(
                f"data/dataset.jsonl not found in bundle at {bundle_dir}"
            )
        # Admission-bounded JSONL load (size + per-line depth + row count) — same
        # discipline as the manifest; InputInadmissible propagates → RECOMPUTE_ERROR.
        rows = admit_jsonl_file(dataset_path)

        value = compute_noised_count(rows, release)
        return RecomputedValue(
            value=value,
            detail=f"re-derived DP noised_count over {len(rows)} dataset row(s)",
        )


register_primitive(DpRecompute())
