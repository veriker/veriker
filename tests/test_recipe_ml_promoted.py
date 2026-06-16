"""tests/test_recipe_ml_promoted.py — the `ML metric` shape is PROMOTED into the
shippable core registry (RECIPE_BOOK.md).

Two things are proven, deliberately without a tautology:

  GENERIC SAFE PATH. The bundle is verified by a BARE BundleVerifier under an
  auditor SpecAnchor with NO demo-local register_primitive and WITHOUT importing
  the primitive module at all. The only thing that resolves the recompute is the
  core registry auto-registration (run_spec_pinned_dispatch ->
  _ensure_primitives_loaded -> import primitives -> ml self-registers). If ml
  were not promoted, the dispatch would fail UNKNOWN_PRIMITIVE.

  PRODUCER-FAITHFULNESS (not f(x)==f(x)). The producer's claimed
  ml_prediction_classes list is extracted from the producer's OWN emitted
  payload/predictions.json — a list of {input_idx, logits, predicted_class}
  objects written by _build_bundle.py's integer-only linear classifier. The
  verifier recomputes its own predicted-class list from the committed weights +
  inputs and compares. An honest PASS therefore proves that the two separately
  maintained inference paths produce the same class indices — if they ever drift
  (edit-drift), this test FAILS. The claim is never routed through the
  verifier's own compute_prediction_classes.

Run SOLO — shared bundle basenames collide in one pytest process.

Surfaces:
  1. Honest bundle -> PASS (generic safe path AND producer-faithfulness).
  2. Tampered claimed value (increment one class index) -> REDERIVATION_MISMATCH.
  3. Tampered committed input (flip one feature value) -> REDERIVATION_MISMATCH.
  4. Float weight in model.json -> non-OK (integer type guard fires; a float
     element is rejected before any arithmetic so `exact` is never bound to a
     float computation).
For (2)/(3)/(4) the manifest file SHA is re-aligned so FileIntegrity does not
fire first — isolating the re-derivation failure from a plain integrity failure.
(Only the value-tamper is a failure FileIntegrity could NEVER catch: the
claimed-value file is producer-controlled and self-pinned; the re-derivation
dispatch is what catches it.)

Stdlib-only orchestration; the build runs the pilot's real producer _build_bundle.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# NOTE: the verifier's recompute primitive (primitives/ml.py) is deliberately
# NOT imported here. The claim is derived from the producer artifact, and the
# primitive must resolve ONLY via dispatch's core auto-registration.
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from examples._spec_pinned_overlay import apply_overlay, compute_anchor  # noqa: E402

import hashlib  # noqa: E402 (stdlib, needed for _realign_file_sha)

_PILOT_DIR = _PKG_ROOT / "examples" / "ml_minimal"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "ml.spec.json"
_OUTPUT_ID = "ml_prediction_classes"
_TYPE_KEY = "ml_prediction_classes"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _honest_classes_from_producer_artifact(bundle_dir: Path) -> list[int]:
    """Extract predicted_class from the producer's independently-emitted
    payload/predictions.json.

    This is the NO-TAUTOLOGY path: we read the producer's OWN artifact, NOT the
    verifier's compute_prediction_classes. An honest PASS proves the two
    independent code paths agree — if they drift, the test FAILS.
    """
    predictions = json.loads((bundle_dir / "payload" / "predictions.json").read_bytes())
    return [entry["predicted_class"] for entry in predictions]


def _build(out_dir: Path, *, claimed_override=None):
    """Build a spec-pinned ml bundle producer-side. Returns (bundle_dir, anchor).

    The base bundle is produced by the pilot's real _build_bundle.py
    (inputs/features.json, weights/model.json, payload/predictions.json,
    manifest). The HONEST claimed ml_prediction_classes list is extracted from
    the producer's independently-emitted payload/predictions.json — NOT by
    calling the verifier's compute_prediction_classes. The generic beta overlay
    then adds the auditor spec, the producer claimed-value file, and
    manifest.outputs.
    """
    subprocess.run(
        [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(out_dir)],
        check=True,
        capture_output=True,
    )
    # Producer-side claim: extract predicted_class from the producer's own
    # independently-emitted payload/predictions.json.
    claimed = _honest_classes_from_producer_artifact(out_dir)
    if claimed_override is not None:
        claimed = claimed_override
    apply_overlay(
        out_dir,
        spec_src_path=_SPEC_SRC,
        output_id=_OUTPUT_ID,
        type_key=_TYPE_KEY,
        claimed_value=claimed,
    )
    # Match manifest.typed_checks to the minimal plugin set we run (the verifier
    # rejects a typed_checks name with no matching plugin instance).
    mp = out_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["typed_checks"] = ["file_integrity_many_small"]
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))
    return out_dir, compute_anchor(_SPEC_SRC)


def _realign_file_sha(bundle_dir: Path, rel: str) -> None:
    """Recompute and store the manifest SHA for one file so FileIntegrity does not
    fire before the re-derivation dispatch can be observed."""
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][rel] = _sha256((bundle_dir / rel).read_bytes())
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))


def _verify(bundle_dir: Path, anchor):
    # BARE verifier: FileIntegrity + spec-pinned dispatch under the auditor anchor.
    # NO register_primitive — the recompute resolves only via the CORE registry.
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()], spec_anchor=anchor
    ).verify(bundle_dir)


def test_promoted_generic_safe_path_and_faithfulness_pass(tmp_path):
    # Honest PASS proves BOTH: the generic verifier resolves ml via core
    # auto-registration (no import, no demo registration), AND the verifier's
    # recompute agrees element-wise with the producer's independent predictions.
    bundle_dir, anchor = _build(tmp_path / "bundle")
    result = _verify(bundle_dir, anchor)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_promoted_tampered_value_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Increment one element of the producer's claimed class list.
    claim_path = bundle_dir / "outputs" / f"{_OUTPUT_ID}.json"
    doc = json.loads(claim_path.read_bytes())
    honest = list(doc["value"])
    # Flip the first class index (add 1, modulo a large number to avoid wrap-around issue)
    honest[0] = honest[0] + 1
    doc["value"] = honest
    claim_path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    _realign_file_sha(bundle_dir, f"outputs/{_OUTPUT_ID}.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_promoted_tampered_input_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Flip one feature value in inputs/features.json (changes the prediction for
    # the first sample when the logit margin is not enormous).
    features_path = bundle_dir / "inputs" / "features.json"
    feature_vectors = json.loads(features_path.read_bytes())
    # Mutate the first feature of the first vector by a large amount to ensure
    # at least one predicted class changes.
    feature_vectors[0][0] = feature_vectors[0][0] + 500
    features_path.write_bytes(json.dumps(feature_vectors, indent=2).encode("utf-8"))
    _realign_file_sha(bundle_dir, "inputs/features.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_promoted_float_weight_rejected(tmp_path):
    """Integer type guard fires when a producer commits float weights.

    A bundle whose model.json contains float weights (e.g. W[0][0] = 3.0) must
    NOT pass as OK — it would silently do float arithmetic while `exact` remains
    bound. The guard raises ValueError inside recompute, which the dispatch
    records as RECOMPUTE_ERROR (not a crash), and the result is not OK.
    """
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Corrupt one weight to a float — leave all other values identical so the
    # only trigger is the integer type guard, not a shape or schema mismatch.
    model_path = bundle_dir / "weights" / "model.json"
    model = json.loads(model_path.read_bytes())
    # Replace W[0][0] with its float equivalent (e.g. 3 -> 3.0).
    model["W"][0][0] = float(model["W"][0][0])
    model_path.write_bytes(json.dumps(model, indent=2).encode("utf-8"))
    _realign_file_sha(bundle_dir, "weights/model.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok, (
        "expected not-OK when float weight present; integer type guard must fire"
    )
    codes = _reason_codes(result)
    assert "RECOMPUTE_ERROR" in codes, (
        f"expected RECOMPUTE_ERROR from integer type guard; got {codes}"
    )
