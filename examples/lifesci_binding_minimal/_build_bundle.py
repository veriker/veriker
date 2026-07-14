"""_build_bundle.py — build a deterministic lifesci_binding_minimal audit bundle.

Drug-discovery domain pilot: a binding-affinity model predicts how strongly
compound C (identified by a SMILES-like string) binds to protein target T
(identified by an amino-acid sequence). The audit bundle captures the
compound descriptor, target descriptor, scoring weights, and predicted affinity
score — enough for a verifier to independently re-run the deterministic scoring
function and assert the result matches byte-for-byte.

Re-derivation primitive (one sentence):
  Re-compute compound_features + target_features via stable character-bucket
  hashing over the committed SMILES and sequence strings, then take the
  dot-product against committed weights + bias, and assert the result matches
  the bundled affinity_pred to 6 decimal places.

Why this matters for life-sciences:
  Drug-discovery submissions increasingly require end-to-end traceability:
  the regulator must be able to reproduce a model's prediction from the exact
  inputs the model saw, using only committed artifacts. The audit bundle is
  exactly that receipt. This pilot demonstrates the substrate claim on a
  synthetic (but structurally realistic) drug-binding scorer.

Feature hashing is STABLE across processes: uses zlib.crc32 (not Python's
built-in hash() which is randomized by PYTHONHASHSEED).

Usage (from v-kernel-audit-bundle root):
    python examples/lifesci_binding_minimal/_build_bundle.py --out-dir /tmp/lifesci_binding_bundle

Outputs:
  <out-dir>/inputs/compound_descriptor.json   — {compound_id, smiles_string}
  <out-dir>/inputs/target_descriptor.json     — {target_id, sequence}
  <out-dir>/payload/scoring_weights.json      — {w_compound[32], w_target[32], bias}
  <out-dir>/payload/binding_prediction.json   — {compound_id, target_id,
                                                  affinity_pred, confidence_band,
                                                  scoring_weights_sha256}
  <out-dir>/manifest.json

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zlib
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.emitter import BundleContent, write_bundle
from audit_bundle.fragments.fragment_id import OpaqueFragment, fragment_to_canonical_dict

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "lifesci-binding-minimal-rc"
_CREATED_AT = "2026-05-10T00:00:00Z"
_TYPED_CHECKS = ["file_integrity_many_small", "binding_affinity_re_derivation"]

_N_BUCKETS = 32

# Synthetic compound: a short SMILES-like string for demonstration.
# Compound NEXI-C001: resembles a small aromatic heterocycle.
_COMPOUND = {
    "compound_id": "NEXI-C001",
    "smiles_string": "c1ccccc1-N(CC)CC=O",
}

# Synthetic target: a 15-residue sub-sequence of a kinase-like protein.
# Target NEXI-T001: synthetic mini-sequence, not a real PDB entry.
_TARGET = {
    "target_id": "NEXI-T001",
    "sequence": "MKTAYIAKQRQISFV",
}

# Committed scoring weights (deterministic — do not modify without rebuilding the bundle).
# w_compound and w_target are integer-valued to avoid IEEE-754 platform concerns;
# bias is a small float for realism. Affinity is computed as:
#   affinity_pred = dot(compound_features, w_compound)
#                 + dot(target_features, w_target)
#                 + bias
_SCORING_WEIGHTS: dict = {
    "schema": "binding-affinity-scorer-v1",
    "n_buckets": _N_BUCKETS,
    "w_compound": [
        3, -1,  2,  1, -2,  4,  0,  1,  2, -3,  1,  0,  3,  2, -1,  1,
        0,  2, -2,  3,  1, -1,  0,  2,  1,  3, -1,  2,  0,  1, -2,  1,
    ],
    "w_target": [
        1,  2, -1,  3,  0,  2,  1, -2,  3,  1, -1,  2,  0,  3,  1,  2,
       -1,  0,  3,  1,  2, -1,  1,  0,  2,  3, -1,  1,  2,  0,  3, -1,
    ],
    "bias": 2.5,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _stable_hash_mod(s: str, n: int) -> int:
    """Stable cross-process hash: zlib.crc32 of UTF-8 string, mod n."""
    return zlib.crc32(s.encode("utf-8")) % n


def _extract_features(sequence: str, n_buckets: int = _N_BUCKETS) -> list[int]:
    """Hash each character into a bucket and count occurrences.

    Returns a list of length n_buckets. Uses zlib.crc32 for cross-process
    stability — Python's built-in hash() is randomized per PYTHONHASHSEED.
    """
    features = [0] * n_buckets
    for char in sequence:
        bucket = _stable_hash_mod(char, n_buckets)
        features[bucket] += 1
    return features


def _dot(a: list, b: list) -> float:
    """Dot product of two equal-length lists."""
    return sum(ai * bi for ai, bi in zip(a, b))


def _predict_affinity(
    smiles_string: str,
    sequence: str,
    w_compound: list,
    w_target: list,
    bias: float,
) -> float:
    """Deterministic affinity score: feature-hash dot-product + bias."""
    compound_features = _extract_features(smiles_string)
    target_features = _extract_features(sequence)
    return _dot(compound_features, w_compound) + _dot(target_features, w_target) + bias


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # --- Build compound descriptor bytes ---
    compound_bytes = (
        json.dumps(_COMPOUND, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    # --- Build target descriptor bytes ---
    target_bytes = (
        json.dumps(_TARGET, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    # --- Build scoring weights bytes ---
    weights_bytes = (
        json.dumps(_SCORING_WEIGHTS, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    weights_sha = _sha256(weights_bytes)

    # --- Compute affinity prediction ---
    w_compound = _SCORING_WEIGHTS["w_compound"]
    w_target = _SCORING_WEIGHTS["w_target"]
    bias = _SCORING_WEIGHTS["bias"]

    affinity_pred = _predict_affinity(
        smiles_string=_COMPOUND["smiles_string"],
        sequence=_TARGET["sequence"],
        w_compound=w_compound,
        w_target=w_target,
        bias=bias,
    )
    affinity_pred_rounded = round(affinity_pred, 6)

    # Confidence band: ±5% of abs(affinity_pred), informational only.
    confidence_half = round(abs(affinity_pred_rounded) * 0.05, 6)
    confidence_band = {
        "lower": round(affinity_pred_rounded - confidence_half, 6),
        "upper": round(affinity_pred_rounded + confidence_half, 6),
        "method": "synthetic_5pct",
    }

    prediction = {
        "compound_id": _COMPOUND["compound_id"],
        "target_id": _TARGET["target_id"],
        "affinity_pred": affinity_pred_rounded,
        "confidence_band": confidence_band,
        "scoring_weights_sha256": weights_sha,
    }
    prediction_bytes = (
        json.dumps(prediction, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")

    # --- OpaqueFragment anchors — one per input descriptor ---
    compound_cid = f"sha256:{_sha256(compound_bytes)}"
    target_cid = f"sha256:{_sha256(target_bytes)}"

    frag_compound = OpaqueFragment(
        source_cid=compound_cid,
        kind_tag="molecule_descriptor",
        locator={
            "compound_id": _COMPOUND["compound_id"],
            "descriptor_type": "smiles",
        },
    )
    frag_target = OpaqueFragment(
        source_cid=target_cid,
        kind_tag="protein_target_descriptor",
        locator={
            "target_id": _TARGET["target_id"],
            "descriptor_type": "amino_acid_sequence",
        },
    )

    fragment_anchors = {
        "compound-descriptor": fragment_to_canonical_dict(frag_compound),
        "target-descriptor": fragment_to_canonical_dict(frag_target),
    }

    # --- Emit via the reference-emitter SDK (scaffold + digests + manifest). ---
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "inputs/compound_descriptor.json": compound_bytes,
            "inputs/target_descriptor.json": target_bytes,
            "payload/scoring_weights.json": weights_bytes,
            "payload/binding_prediction.json": prediction_bytes,
        },
        typed_checks=_TYPED_CHECKS,
        extra_manifest_fields={
            "fragment_anchors": fragment_anchors,
        },
    )
    write_bundle(out_dir, content)

    print(f"Bundle written to {out_dir}")
    print(f"  compound         : {_COMPOUND['compound_id']} ({_COMPOUND['smiles_string']!r})")
    print(f"  target           : {_TARGET['target_id']} ({_TARGET['sequence']!r})")
    print(f"  affinity_pred    : {affinity_pred_rounded}")
    print(f"  confidence_band  : [{confidence_band['lower']}, {confidence_band['upper']}]")
    print(f"  weights_sha256   : {weights_sha[:16]}...")
    print(f"  fragment anchors : {len(fragment_anchors)} OpaqueFragment")
    print(f"  manifest files   : 4")
    print(f"  manifest         : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic lifesci_binding_minimal audit bundle"
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
