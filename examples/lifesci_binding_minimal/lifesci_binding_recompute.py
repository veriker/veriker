"""lifesci_binding_recompute.py — verifier-side binding-affinity re-derivation primitive.

Axis-2 value-return form (SPEC_PINNED_DISPATCH_ARCHITECTURE §3.3). Self-contained
per-dir migration of the lifesci_binding pilot onto spec-pinned dispatch: the
recompute primitive lives HERE (verifier-distribution code, registered by the
spec-pinned builder), NOT in audit_bundle/rederivation/primitives/.

Re-derivation primitive (one sentence):
    affinity_pred = round(
        dot(crc32_char_bucket_features(smiles_string, 32), w_compound)
      + dot(crc32_char_bucket_features(sequence, 32), w_target)
      + bias, 6)

over inputs/compound_descriptor.json (smiles_string), inputs/target_descriptor.json
(sequence), and payload/scoring_weights.json (w_compound[32], w_target[32], bias).
Feature hashing is STABLE across processes (zlib.crc32, not built-in hash()). The
hashing + scoring rule is FIXED in this primitive — the primitive_id
("lifesci_binding_recompute") IS the rule. The auditor's SHA-pinned spec binds the
output type "lifesci_binding_affinity" to this primitive_id and to a scalar_epsilon
comparator; a producer cannot weaken the rule without changing the primitive_id,
which the anchor would reject.

Stdlib-only (§C5 contract). This module is importable WITHOUT audit_bundle on
sys.path (the RecomputedValue import is deferred into recompute()), so the
spec-pinned builder can import compute_affinity_pred() standalone.
"""

from __future__ import annotations

import json
import zlib
from pathlib import Path

_N_BUCKETS = 32


# ---------------------------------------------------------------------------
# Canonical computation (shared by the builder and the verifier — ONE source)
# ---------------------------------------------------------------------------


def _stable_hash_mod(s: str, n: int) -> int:
    """Stable cross-process hash: zlib.crc32 of UTF-8 encoded string, mod n.

    Mirrors the legacy pack's _stable_hash_mod EXACTLY — built-in hash() is
    randomized per PYTHONHASHSEED and must NOT be used here.
    """
    return zlib.crc32(s.encode("utf-8")) % n


def _extract_features(sequence: str, n_buckets: int = _N_BUCKETS) -> list[int]:
    """Hash each character into a bucket and count occurrences. Length n_buckets."""
    features = [0] * n_buckets
    for char in sequence:
        features[_stable_hash_mod(char, n_buckets)] += 1
    return features


def _dot(a: list, b: list) -> float:
    """Dot product of two equal-length lists."""
    if len(a) != len(b):
        raise ValueError(f"dot product: length mismatch {len(a)} vs {len(b)}")
    return sum(ai * bi for ai, bi in zip(a, b))


def compute_affinity_pred(
    smiles_string: str,
    sequence: str,
    w_compound: list,
    w_target: list,
    bias: float,
    n_buckets: int = _N_BUCKETS,
) -> float:
    """Canonical binding-affinity prediction. Mirrors the legacy pack's
    predict_affinity + the builder's _predict_affinity: crc32 character-bucket
    feature hashing over the SMILES and target sequence, dot-producted against
    the committed weights, plus bias, rounded to 6dp. Builder and verifier share
    this ONE definition so the honest claimed value and the re-derivation cannot
    drift.
    """
    if len(w_compound) != n_buckets:
        raise ValueError(
            f"w_compound has {len(w_compound)} elements; expected {n_buckets}"
        )
    if len(w_target) != n_buckets:
        raise ValueError(
            f"w_target has {len(w_target)} elements; expected {n_buckets}"
        )
    compound_features = _extract_features(smiles_string, n_buckets)
    target_features = _extract_features(sequence, n_buckets)
    raw = _dot(compound_features, w_compound) + _dot(target_features, w_target) + bias
    return round(raw, 6)


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered by the spec-pinned builder before BundleVerifier)
# ---------------------------------------------------------------------------


class LifesciBindingRecompute:
    """Verifier-side primitive for re-deriving the binding-affinity prediction."""

    primitive_id: str = "lifesci_binding_recompute"

    def recompute(self, inputs, pack_section: dict):
        """Recompute affinity_pred from the committed inputs + scoring weights.

        inputs.bundle_dir is a read-only Path. pack_section carries
        {output_id, type, params} from the auditor's spec binding. Returns a
        RecomputedValue carrying the scalar; the verifier's comparator compares.
        """
        # Deferred import keeps this module importable standalone (builder use).
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        bundle_dir: Path = inputs.bundle_dir

        compound_path = bundle_dir / "inputs" / "compound_descriptor.json"
        if not compound_path.is_file():
            raise FileNotFoundError(
                f"inputs/compound_descriptor.json not found in bundle at {bundle_dir}"
            )
        target_path = bundle_dir / "inputs" / "target_descriptor.json"
        if not target_path.is_file():
            raise FileNotFoundError(
                f"inputs/target_descriptor.json not found in bundle at {bundle_dir}"
            )
        weights_path = bundle_dir / "payload" / "scoring_weights.json"
        if not weights_path.is_file():
            raise FileNotFoundError(
                f"payload/scoring_weights.json not found in bundle at {bundle_dir}"
            )

        compound = json.loads(compound_path.read_bytes())
        target = json.loads(target_path.read_bytes())
        weights = json.loads(weights_path.read_bytes())

        value = compute_affinity_pred(
            smiles_string=compound["smiles_string"],
            sequence=target["sequence"],
            w_compound=weights["w_compound"],
            w_target=weights["w_target"],
            bias=weights["bias"],
        )
        return RecomputedValue(
            value=value,
            detail=(
                f"re-derived binding affinity for compound={compound.get('compound_id')!r} "
                f"target={target.get('target_id')!r}"
            ),
        )
