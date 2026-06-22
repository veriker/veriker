"""tests/test_recipe_fp_ml_promoted.py — the `floating-point ML` shape (float32
linear-classifier logit) is PROMOTED into the shippable core registry
(RECIPE_BOOK.md).

Two things are proven, deliberately without a tautology:

  GENERIC SAFE PATH. The bundle is verified by a BARE BundleVerifier under an
  auditor SpecAnchor with NO demo-local register_primitive and WITHOUT importing
  the primitive module at all. The only thing that resolves the recompute is the
  core registry auto-registration (run_spec_pinned_dispatch ->
  _ensure_primitives_loaded -> import primitives -> fp_ml self-registers). If it
  were not promoted, dispatch would fail UNKNOWN_PRIMITIVE.

  PRODUCER-FAITHFULNESS (not f(x)==f(x)). The producer's claimed logit is read
  from the producer's OWN emitted payload/predictions.json ([0]["logits"][0]) —
  computed by _build_bundle.py's _compute_logits, a SEPARATE producer-side float32
  copy — NOT the verifier's recompute. The verifier re-derives the class-0 logit
  for input 0 (f32(sum(W[0][j]*x0[j]) + b[0])) over the committed weights/model.json
  and inputs/features.json, then compares under scalar_epsilon(1e-9). An honest PASS
  proves the producer copy and the verifier copy agree on the committed exemplar —
  if they drift beyond 1e-9, this test FAILS. The claim is never routed through
  the verifier's compute_rep_logit.

Run SOLO — shared bundle basenames collide in one pytest process.

Surfaces:
  1. Honest bundle -> PASS (generic safe path AND producer-faithfulness).
  2. Tampered claimed value (+1.0, far above epsilon) -> REDERIVATION_MISMATCH.
  3. Tampered committed input (perturb inputs/features.json[0][0] by +1.0 so the
     re-derived logit shifts well beyond epsilon) -> REDERIVATION_MISMATCH.
     inputs/ is a regular committed file; manifest.files is re-aligned so
     FileIntegrity does not fire first.

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

# NOTE: the verifier's recompute primitive (primitives/fp_ml.py) is deliberately
# NOT imported here. The claim is derived from the producer artifact, and the
# primitive must resolve ONLY via dispatch's core auto-registration.
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from examples._spec_pinned_overlay import apply_overlay, compute_anchor  # noqa: E402

_PILOT_DIR = _PKG_ROOT / "examples" / "fp_ml_minimal"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "fp_ml.spec.json"
_OUTPUT_ID = "fp_ml_logit"
_TYPE_KEY = "fp_ml_logit"
_FEATURES_REL = "inputs/features.json"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _build(out_dir: Path, *, claimed_override=None):
    """Build a spec-pinned fp_ml bundle producer-side.

    The base bundle is produced by the pilot's real _build_bundle.py
    (weights/model.json, inputs/features.json, payload/predictions.json, manifest).
    The HONEST claimed logit is read from the producer's OWN
    payload/predictions.json[0]["logits"][0] — independent of the verifier's
    compute_rep_logit.
    """
    subprocess.run(
        [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(out_dir)],
        check=True,
        capture_output=True,
    )
    predictions = json.loads((out_dir / "payload" / "predictions.json").read_bytes())
    claimed = predictions[0]["logits"][0]
    if claimed_override is not None:
        claimed = claimed_override
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
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()], spec_anchor=anchor
    ).verify(bundle_dir)


def test_promoted_generic_safe_path_and_faithfulness_pass(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    result = _verify(bundle_dir, anchor)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_promoted_tampered_value_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    claim_path = bundle_dir / "outputs" / f"{_OUTPUT_ID}.json"
    doc = json.loads(claim_path.read_bytes())
    honest = doc["value"]
    doc["value"] = honest + 1.0  # far above the 1e-9 tolerance
    assert doc["value"] != honest
    claim_path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    _realign_file_sha(bundle_dir, f"outputs/{_OUTPUT_ID}.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert _reason_codes(result) == {"REDERIVATION_MISMATCH"}, _reason_codes(result)


def test_promoted_tampered_input_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Perturb the first feature of input vector 0 by +1.0. The re-derived logit
    # f32(sum(W[0][j]*x0[j]) + b[0]) shifts by f32(W[0][0]) — well beyond the
    # 1e-9 tolerance — diverging from the (honest) claimed logit.
    feat_path = bundle_dir / _FEATURES_REL
    features = json.loads(feat_path.read_bytes())
    features[0][0] = features[0][0] + 1.0
    feat_path.write_bytes(
        (json.dumps(features, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    )
    _realign_file_sha(bundle_dir, _FEATURES_REL)

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert _reason_codes(result) == {"REDERIVATION_MISMATCH"}, _reason_codes(result)
