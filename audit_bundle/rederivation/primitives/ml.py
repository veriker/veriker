"""ml_recompute — verifier-side ML inference re-derivation primitive.

Axis-2 value-return form of the ml_minimal re-derivation, PROMOTED into the
shippable core registry (RECIPE_BOOK.md, shape `ML metric`). The generic
verifier recomputes the representative output on the SAFE spec-pinned path: no
subprocess, no bundle-supplied code — the recompute rule lives HERE in
verifier-distribution code and the comparator + tolerance come from the
auditor-anchored spec.

Re-derivation primitive (one sentence):
    predicted_classes = the integer argmax (lowest-index tie-break) of the
    integer logits logits[k] = sum(W[k][j]*x[j]) + b[k], re-executed per input
    sample over the committed weights (weights/model.json: linear-classifier-v1)
    and committed inputs (inputs/features.json).

The integer-only linear-classifier rule (logits = W@x + b, argmax, lowest-index
tie-break) is FIXED in this primitive — the primitive_id ("ml_recompute") IS the
rule. The auditor's SHA-pinned spec binds the output type "ml_prediction_classes"
to this primitive_id and to an `exact` comparator (element-wise list equality of
integer class indices); a producer cannot weaken the inference without changing
the primitive_id / spec SHA, which the anchor rejects.

Comparator: `exact`.
Justification: the computation is entirely integer-only (W[k][j], x[j], b[k]
are all integers; sum() accumulates integers; argmax returns an integer index).
There is NO floating-point arithmetic and NO summation-order divergence: integer
addition is associative and the result is identical regardless of evaluation
order. The output is an ordered list of integer class indices compared
element-wise. `exact` (not `scalar_epsilon`) is correct and safe for all
supported query classes. A model with float weights MUST NOT be registered under
this primitive_id; the recompute raises ValueError (fail-closed) if any element
of W, b, or the feature vectors is not an int.

Faithfulness (the only model classes this primitive re-derives):
  - schema = "linear-classifier-v1" only; unsupported schemas raise ValueError
    (fail-closed, never invent a prediction).
  - Integer type guard: all elements of W, b, and every feature vector must be
    plain Python int; floats or other types raise ValueError before any logit is
    computed (fail-closed, never silently do float arithmetic under `exact`).
  - logits[k] = sum(W[k][j]*x[j]) + b[k]: integer dot-product, matching the
    producer's _build_bundle._compute_logits.
  - argmax with lowest-index tie-break (list.index(max(...))), matching the
    producer's _build_bundle._argmax.
  - Shape validation is fail-closed (raises on mismatch); the verifier must not
    invent a prediction for a malformed model.

Implementation note — producer/verifier relationship:
  This primitive is a faithful verifier-side reimplementation of the producer's
  inference logic, maintained alongside it. The test suite catches output
  divergence (edit-drift) between the producer's emitted predictions and the
  verifier's recomputed class indices. It does not assert byte-level identity of
  source code or independence of implementation; shared-logic bugs that affect
  both paths equally would not be caught by the re-derivation test alone.

Stdlib-only (§C5 core verify() path).
"""

from __future__ import annotations

from pathlib import Path

from ...admission import admit_json_file
from ...plugin import ParsedInputs, RecomputedValue
from ..registry import register_primitive


# ---------------------------------------------------------------------------
# Canonical computation — verifier-side reimplementation matching the producer
# (examples/ml_minimal/_build_bundle._compute_logits / _argmax)
# ---------------------------------------------------------------------------


def _assert_all_int(values, label: str) -> None:
    """Fail-closed integer type guard.

    Raises ValueError if any element of `values` (a flat or nested list) is
    not a plain Python int. Must be called before any arithmetic so a producer
    committing float weights cannot silently drive float arithmetic under the
    `exact` comparator.
    """
    for i, v in enumerate(values):
        if isinstance(v, list):
            _assert_all_int(v, f"{label}[{i}]")
        elif not isinstance(v, int):
            raise ValueError(
                f"integer type guard: {label}[{i}] is {type(v).__name__!r}, "
                f"expected int; float weights are not permitted under "
                f"primitive_id='ml_recompute' (exact comparator requires "
                f"integer-only arithmetic)"
            )


def _compute_logits(W: list[list[int]], b: list[int], x: list[int]) -> list[int]:
    """Integer dot-product: logit[k] = sum(W[k][j]*x[j]) + b[k].

    Matches the producer's _build_bundle._compute_logits rule.
    """
    return [sum(W[k][j] * x[j] for j in range(len(x))) + b[k] for k in range(len(W))]


def _argmax(values: list[int]) -> int:
    """Argmax with lowest-index tie-break. Matches the producer's _argmax rule."""
    return values.index(max(values))


def compute_prediction_classes(
    model: dict, feature_vectors: list[list[int]]
) -> list[int]:
    """Canonical re-derivation of the predicted class index per input sample.

    Validates the model schema and shape, then re-executes the integer-only
    linear classifier over every input vector. Raises on unsupported schema or
    shape mismatch — the verifier must not invent a prediction.

    Returns the ordered list of integer class indices (one per input sample).
    """
    schema = model["schema"]
    n_features = int(model["n_features"])
    n_classes = int(model["n_classes"])
    W = model["W"]
    b = model["b"]

    if schema != "linear-classifier-v1":
        raise ValueError(
            f"unsupported model schema {schema!r}; only 'linear-classifier-v1' is implemented"
        )
    if len(W) != n_classes:
        raise ValueError(
            f"W has {len(W)} rows but n_classes={n_classes}; shape mismatch"
        )
    for k, row in enumerate(W):
        if len(row) != n_features:
            raise ValueError(
                f"W[{k}] has {len(row)} cols but n_features={n_features}; shape mismatch"
            )
    if len(b) != n_classes:
        raise ValueError(
            f"b has {len(b)} elements but n_classes={n_classes}; shape mismatch"
        )

    # Integer type guard — fail-closed before any arithmetic.
    # A float element in W, b, or any feature vector would silently perform
    # float arithmetic while `exact` remains bound; reject immediately.
    _assert_all_int(W, "W")
    _assert_all_int(b, "b")
    for fi, fv in enumerate(feature_vectors):
        _assert_all_int(fv, f"feature_vectors[{fi}]")

    classes: list[int] = []
    for x in feature_vectors:
        logits = _compute_logits(W, b, x)
        classes.append(_argmax(logits))
    return classes


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered at import for the core registry)
# ---------------------------------------------------------------------------


class MlRecompute:
    """Verifier-side primitive for re-deriving the predicted-class-index list."""

    primitive_id: str = "ml_recompute"

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        """Recompute the predicted class index list from committed weights + inputs.

        Returns the recomputed VALUE only — it reads no acceptance epsilon and
        does not compare; the auditor-anchored `exact` comparator decides
        agreement against outputs/<id>.json.
        """
        bundle_dir: Path = inputs.bundle_dir
        model_path = bundle_dir / "weights" / "model.json"
        features_path = bundle_dir / "inputs" / "features.json"
        if not model_path.is_file():
            raise FileNotFoundError(
                f"weights/model.json not found in bundle at {bundle_dir}"
            )
        if not features_path.is_file():
            raise FileNotFoundError(
                f"inputs/features.json not found in bundle at {bundle_dir}"
            )
        model = admit_json_file(model_path)
        if not isinstance(model, dict):
            raise ValueError("weights/model.json: top-level must be an object")
        feature_vectors = admit_json_file(features_path)
        if not isinstance(feature_vectors, list):
            raise ValueError("inputs/features.json: top-level must be a list")
        value = compute_prediction_classes(model, feature_vectors)
        return RecomputedValue(
            value=value,
            detail=(
                f"re-derived predicted classes ({len(value)} samples) "
                f"via integer-only linear classifier (schema={model['schema']!r})"
            ),
        )


register_primitive(MlRecompute())
