"""tests/test_recipe_dp_promoted.py — the differential-privacy (Laplace seeded-noise
aggregate) shape is PROMOTED into the shippable core registry (RECIPE_BOOK.md).

Two things are proven, deliberately without a tautology:

  GENERIC SAFE PATH. The bundle is verified by a BARE BundleVerifier under an
  auditor SpecAnchor with NO demo-local register_primitive and WITHOUT importing
  the primitive module at all. The only thing that resolves the recompute is the
  core registry auto-registration (run_spec_pinned_dispatch ->
  _ensure_primitives_loaded -> import primitives -> dp self-registers). If dp
  were not promoted, the dispatch would fail UNKNOWN_PRIMITIVE.

  PRODUCER-FAITHFULNESS (not f(x)==f(x)). The producer's claimed noised_count is
  read directly from the producer's OWN payload/dp_release.json["noised_count"] —
  emitted by _build_bundle.py's own _laplace_noise + count logic, an INDEPENDENT
  code copy from the verifier's primitives/dp.py compute_noised_count. The
  verifier recomputes its own noised_count from the committed dataset.jsonl and
  dp_release.json mechanism fields, and compares via scalar_epsilon. An honest
  PASS therefore proves the two independent noise computation paths agree within
  the auditor-anchored tolerance — if they ever drift, this test FAILS. The claim
  is never routed through the verifier's own compute_noised_count or
  compute_laplace_noise.

Run SOLO — shared bundle basenames collide in one pytest process.

Surfaces:
  1. Honest bundle -> PASS (generic safe path AND producer-faithfulness).
  2. Tampered claimed value (add large offset, well outside epsilon) -> REDERIVATION_MISMATCH.
  3. Tampered committed input (flip predicate match in dataset) -> REDERIVATION_MISMATCH.
  4. Sub-epsilon perturbation of claimed value (delta < epsilon) -> PASS.
     Exercises the scalar_epsilon tolerance lower bound: a perturbation within
     the tolerance window must not trigger a mismatch.
  5. Just-over-epsilon perturbation (delta = epsilon * 1.5) -> REDERIVATION_MISMATCH.
     Exercises the scalar_epsilon tolerance upper bound: a perturbation just
     outside the window must trigger a mismatch.
     Justification for the tested epsilon=1e-6: math.log is a transcendental
     function delegated to libm; cross-platform non-reproducibility is at most
     ±1 ULP at the expected magnitude (~5.0), well under 1e-6. true_count is a
     plain integer; any count drift is >= 1 >> 1e-6 so the tolerance does NOT
     mask meaningful input drift.
For (2)/(3)/(5) the manifest file SHA is re-aligned so FileIntegrity does not fire
first — isolating the re-derivation mismatch from a plain integrity failure.
(Only the value-tamper is a failure FileIntegrity could NEVER catch: the
claimed-value file is producer-controlled and self-pinned; the re-derivation
dispatch is what catches it.)

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

# NOTE: the verifier's recompute primitive (primitives/dp.py) is deliberately
# NOT imported here. The claim is derived from the producer artifact, and the
# primitive must resolve ONLY via dispatch's core auto-registration.
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from examples._spec_pinned_overlay import apply_overlay, compute_anchor  # noqa: E402

_PILOT_DIR = _PKG_ROOT / "examples" / "dp_minimal"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "dp.spec.json"
_OUTPUT_ID = "dp_noised_count"
_TYPE_KEY = "dp_noised_count"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _build(out_dir: Path, *, claimed_override=None):
    """Build a spec-pinned dp bundle producer-side. Returns (bundle_dir, anchor).

    The base bundle is produced by the pilot's real _build_bundle.py
    (data/dataset.jsonl, payload/dp_release.json, manifest). The HONEST claimed
    noised_count is read directly from payload/dp_release.json["noised_count"] —
    the producer's OWN emitted value, computed by an independent code copy from
    the verifier primitive. The generic β overlay then adds the auditor spec, the
    producer claimed-value file, and manifest.outputs.

    Gate B (no tautology): the claimed value is NEVER computed by calling the
    verifier's compute_noised_count. It comes from the producer's artifact.
    """
    subprocess.run(
        [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(out_dir)],
        check=True,
        capture_output=True,
    )
    # Producer-side claim: read the noised_count the producer independently
    # emitted into its dp_release.json. This is the producer's own code path —
    # NOT the verifier's recompute function.
    release = json.loads((out_dir / "payload" / "dp_release.json").read_bytes())
    claimed = release["noised_count"]
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
    # Honest PASS proves BOTH: the generic verifier resolves dp via core
    # auto-registration (no import, no demo registration), AND the verifier's
    # recompute agrees with the producer's independent dp_release.json noised_count
    # within the auditor-anchored scalar_epsilon tolerance.
    bundle_dir, anchor = _build(tmp_path / "bundle")
    result = _verify(bundle_dir, anchor)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_promoted_tampered_value_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Add a large offset to the producer's claimed noised_count — well outside the
    # scalar_epsilon tolerance — so the verifier catches the drift.
    claim_path = bundle_dir / "outputs" / f"{_OUTPUT_ID}.json"
    doc = json.loads(claim_path.read_bytes())
    honest = doc["value"]
    doc["value"] = honest + 9999.0
    assert doc["value"] != honest
    claim_path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    _realign_file_sha(bundle_dir, f"outputs/{_OUTPUT_ID}.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_promoted_tampered_input_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Flip the age_bucket of the first matching row in dataset.jsonl so the
    # verifier's re-count diverges from the producer's — producing a different
    # noised_count outside the epsilon tolerance.
    dataset_path = bundle_dir / "data" / "dataset.jsonl"
    release = json.loads((bundle_dir / "payload" / "dp_release.json").read_bytes())
    predicate = release["query"]["predicate"]

    lines = dataset_path.read_text(encoding="utf-8").splitlines()
    mutated = False
    new_lines = []
    for line in lines:
        if not mutated and line.strip():
            row = json.loads(line)
            # Find a row matching the predicate and flip one field so it no longer matches.
            if all(row.get(k) == v for k, v in predicate.items()):
                # Change age_bucket to something that won't match.
                row["age_bucket"] = "__tampered__"
                new_lines.append(json.dumps(row, ensure_ascii=False))
                mutated = True
                continue
        new_lines.append(line)

    assert mutated, "no matching row found to tamper — test setup error"
    dataset_path.write_bytes("\n".join(new_lines).encode("utf-8"))
    _realign_file_sha(bundle_dir, "data/dataset.jsonl")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


# ---------------------------------------------------------------------------
# Tolerance-boundary surfaces (exercises the scalar_epsilon=1e-6 binding)
# ---------------------------------------------------------------------------
# The auditor-anchored comparator is scalar_epsilon=1e-6. These two surfaces
# prove the tolerance is TESTED, not merely asserted:
#   - sub-epsilon delta MUST pass (tolerance is genuinely permissive within window)
#   - just-over-epsilon delta MUST fail (tolerance is genuinely enforced)
#
# Context: true_count is an integer (no float error there); noised_count adds
# math.log noise (transcendental, ±1 ULP cross-platform). epsilon=1e-6 is
# calibrated for that ULP window. Integer count drift is always >=1 >> 1e-6 and
# is never masked by this tolerance.
_SPEC_EPSILON = 1e-6


def test_promoted_sub_epsilon_perturbation_passes(tmp_path):
    """A claimed value perturbed by less than epsilon MUST pass the comparator.

    This proves the scalar_epsilon tolerance is genuinely permissive within its
    window — not degenerate (i.e., the comparator doesn't always reject).
    """
    bundle_dir, anchor = _build(tmp_path / "bundle")
    claim_path = bundle_dir / "outputs" / f"{_OUTPUT_ID}.json"
    doc = json.loads(claim_path.read_bytes())
    honest = doc["value"]
    # Delta strictly less than epsilon; picks half the window.
    sub_epsilon_delta = _SPEC_EPSILON * 0.5
    doc["value"] = honest + sub_epsilon_delta
    claim_path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    _realign_file_sha(bundle_dir, f"outputs/{_OUTPUT_ID}.json")

    result = _verify(bundle_dir, anchor)
    assert result.ok, (
        f"sub-epsilon perturbation ({sub_epsilon_delta!r}) should PASS "
        f"scalar_epsilon={_SPEC_EPSILON!r} but got failures: "
        f"{[(f.check_name, f.reason_code) for f in result.failures]}"
    )


def test_promoted_just_over_epsilon_perturbation_fails(tmp_path):
    """A claimed value perturbed by more than epsilon MUST fail with REDERIVATION_MISMATCH.

    This proves the scalar_epsilon tolerance is genuinely enforced — a drift
    just outside the window is not silently accepted.
    """
    bundle_dir, anchor = _build(tmp_path / "bundle")
    claim_path = bundle_dir / "outputs" / f"{_OUTPUT_ID}.json"
    doc = json.loads(claim_path.read_bytes())
    honest = doc["value"]
    # Delta strictly greater than epsilon; picks 1.5x the window.
    over_epsilon_delta = _SPEC_EPSILON * 1.5
    doc["value"] = honest + over_epsilon_delta
    claim_path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    _realign_file_sha(bundle_dir, f"outputs/{_OUTPUT_ID}.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok, (
        f"just-over-epsilon perturbation ({over_epsilon_delta!r}) should FAIL "
        f"scalar_epsilon={_SPEC_EPSILON!r} but result was OK"
    )
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)
