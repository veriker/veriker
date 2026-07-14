"""fp_ml_recompute — verifier-side floating-point ML logit re-derivation.

Axis-2 value-return form of the fp_ml re-derivation, PROMOTED into the shippable
core registry (RECIPE_BOOK.md, shape `floating-point ML`). The generic verifier
recomputes the representative output on the SAFE spec-pinned path: no subprocess,
no bundle-supplied code — the float32 aggregation rule lives HERE in
verifier-distribution code and the comparator + tolerance come from the
auditor-anchored spec.

Re-derivation primitive (one sentence):
    rep_logit = f32( sum(W[0][j] * x0[j] for j in range(n_features)) + b[0] )

i.e. the single representative scalar predictions[0].logits[0] — the class-0
logit for input feature vector 0 — over weights/model.json (linear-classifier-fp-v1)
and inputs/features.json. The float32 discipline is FIXED in this primitive: snap
to single precision at the serialization boundary via
    f32(v) = struct.unpack('f', struct.pack('f', v))[0]
while arithmetic accumulation is in Python double. This mirrors the legacy
fp_ml_re_derivation pack's _f32 + _compute_logits EXACTLY. The primitive_id
("fp_ml_recompute") IS the rule; the auditor's SHA-pinned spec binds the output
type "fp_ml_logit" to this primitive_id and to a scalar_epsilon(1e-9) comparator,
so a producer cannot weaken the aggregation without changing the primitive_id,
which the anchor would reject.

Faithfulness (verifier-side reimplementation — Gate B):
  - compute_rep_logit mirrors the producer pack's _compute_logits for (class 0,
    input 0): accumulate W[0][j]*x0[j] in Python double, add b[0], snap the final
    value to float32. The promoted test derives the honest claim from the
    producer's OWN emitted payload/predictions.json[0]["logits"][0] — NOT from
    this module — so an honest PASS proves the verifier reproduces the producer's
    serialized logit (not f(x)==f(x)).
  - scalar_epsilon (not exact): two float32-snapped doubles can differ at ULP
    scale across libm/accumulation-order; 1e-9 is the auditor-pinned tolerance,
    far below the float32 spacing of the logit magnitude here.

Stdlib-only (§C5 core verify() path): json / struct are stdlib.
"""

from __future__ import annotations

import struct
from pathlib import Path

from ...admission import admit_json_file
from ...plugin import ParsedInputs, RecomputedValue
from ..registry import register_primitive


# ---------------------------------------------------------------------------
# Float32 round-trip helper (mirrors the legacy pack's _f32 EXACTLY)
# ---------------------------------------------------------------------------


def _f32(x: float) -> float:
    """Snap a Python float to float32 precision via struct pack/unpack."""
    return struct.unpack("f", struct.pack("f", x))[0]


# ---------------------------------------------------------------------------
# Canonical computation (shared by the builder and the verifier — ONE source)
# ---------------------------------------------------------------------------


def compute_rep_logit(W: list, b: list, features: list) -> float:
    """Canonical representative logit = predictions[0].logits[0].

    Mirrors the legacy pack's _compute_logits for class 0, input 0: accumulate
    W[0][j]*x0[j] in Python double, add b[0], snap the final value to float32.
    Builder and verifier share this ONE definition so the honest claimed scalar
    and the re-derivation cannot drift.

    Raises ValueError on empty/malformed input.
    """
    if not features:
        raise ValueError("inputs/features.json has no feature vectors")
    if not W:
        raise ValueError("weights/model.json has no W rows")
    x0 = features[0]
    n_features = len(x0)
    return _f32(sum(W[0][j] * x0[j] for j in range(n_features)) + b[0])


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered at import for the core registry)
# ---------------------------------------------------------------------------


class FpMlRecompute:
    """Verifier-side primitive for re-deriving the representative float32 logit."""

    primitive_id: str = "fp_ml_recompute"

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        """Recompute predictions[0].logits[0] from weights/model.json + inputs/features.json.

        Returns the recomputed VALUE only; the auditor-anchored scalar_epsilon
        comparator decides agreement.
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
            raise ValueError("weights/model.json must be a JSON object")
        W = model.get("W")
        b = model.get("b")
        if not isinstance(W, list) or not isinstance(b, list):
            raise ValueError("weights/model.json 'W' and 'b' must be JSON arrays")

        features = admit_json_file(features_path)
        if not isinstance(features, list):
            raise ValueError("inputs/features.json must be a JSON array of vectors")

        value = compute_rep_logit(W, b, features)
        return RecomputedValue(
            value=value,
            detail="re-derived representative logit predictions[0].logits[0] (class 0, input 0)",
        )


register_primitive(FpMlRecompute())
