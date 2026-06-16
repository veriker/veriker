"""tests/test_recipe_raster_promoted.py — the `geospatial zonal count
(point-in-polygon)` shape is PROMOTED into the shippable core registry
(RECIPE_BOOK.md).

Two things are proven, deliberately without a tautology:

  GENERIC SAFE PATH. The bundle is verified by a BARE BundleVerifier under an
  auditor SpecAnchor with NO demo-local register_primitive and WITHOUT importing
  the primitive module at all. The only thing that resolves the recompute is the
  core registry auto-registration (run_spec_pinned_dispatch ->
  _ensure_primitives_loaded -> import primitives -> raster self-registers). If
  raster were not promoted, the dispatch would fail UNKNOWN_PRIMITIVE.

  PRODUCER-FAITHFULNESS (not f(x)==f(x)). The producer's claimed
  in_polygon_cell_count is the integer read from the producer's OWN
  payload/zonal_result.json — emitted by _build_bundle.py's _zonal_aggregate(),
  a SEPARATE producer-side copy of the ray-casting + counting logic (held in sync
  with the verifier's primitives/raster.py, not independently authored). The
  verifier recomputes its own count from the committed spec/zonal_query.json
  (polygon vertices + grid dimensions) and compares. An honest PASS therefore
  proves the producer copy and the verifier copy agree on the committed exemplar —
  if they ever drift, this test FAILS. The claim is never routed through the
  verifier's own compute_in_polygon_cell_count.

Run SOLO — shared bundle basenames collide in one pytest process.

Surfaces:
  1. Honest bundle -> PASS (generic safe path AND producer-faithfulness).
  2. Tampered claimed value (off by one integer) -> REDERIVATION_MISMATCH.
  3. Tampered committed input (shrink the polygon in spec/zonal_query.json so
     ray-casting re-derives a DIFFERENT count) -> REDERIVATION_MISMATCH.
     FileIntegrityManySmall skips spec/; manifest.spec_files["zonal_query.json"]
     is re-aligned so no integrity check fires — isolating the re-derivation
     mismatch. The auditor spec (raster.spec.json) is NOT re-aligned, so the
     anchor SHA still matches the committed spec — only the polygon changes.

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

# NOTE: the verifier's recompute primitive (primitives/raster.py) is deliberately
# NOT imported here. The claim is derived from the producer artifact, and the
# primitive must resolve ONLY via dispatch's core auto-registration.
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from examples._spec_pinned_overlay import apply_overlay, compute_anchor  # noqa: E402

_PILOT_DIR = _PKG_ROOT / "examples" / "raster_minimal"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "raster.spec.json"
_OUTPUT_ID = "raster_in_polygon_cell_count"
_TYPE_KEY = "raster_in_polygon_cell_count"


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _build(out_dir: Path, *, claimed_override=None):
    """Build a spec-pinned raster bundle producer-side. Returns (bundle, anchor).

    The base bundle is produced by the pilot's real _build_bundle.py (raster/grid.bin,
    spec/zonal_query.json, payload/zonal_result.json, manifest). The HONEST claimed
    in_polygon_cell_count is the integer read from the producer's OWN emitted
    payload/zonal_result.json — independent of the verifier's compute_in_polygon_cell_count.
    The generic β overlay then adds the auditor spec, the producer claimed-value file,
    and manifest.outputs.
    """
    subprocess.run(
        [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(out_dir)],
        check=True,
        capture_output=True,
    )
    # Producer-side claim: read the count from the producer's own emitted
    # payload/zonal_result.json. This is NOT the verifier's recompute — it is the
    # producer's own aggregation result (a separate producer-side code copy in
    # _build_bundle.py, held in sync with the verifier primitive).
    payload = json.loads((out_dir / "payload" / "zonal_result.json").read_bytes())
    claimed = payload["in_polygon_cell_count"]
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


def _realign_spec_file_sha(bundle_dir: Path, basename: str) -> None:
    """Recompute and store the manifest spec_files SHA for one spec file so that
    the spec-file integrity check does not fire before the re-derivation dispatch
    can be observed."""
    import hashlib

    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    new_sha = hashlib.sha256((bundle_dir / "spec" / basename).read_bytes()).hexdigest()
    m.setdefault("spec_files", {})[basename] = new_sha
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))


def _realign_file_sha(bundle_dir: Path, rel: str) -> None:
    """Recompute and store the manifest SHA for one file so FileIntegrity does not
    fire before the re-derivation dispatch can be observed."""
    import hashlib

    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][rel] = hashlib.sha256((bundle_dir / rel).read_bytes()).hexdigest()
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))


def _verify(bundle_dir: Path, anchor):
    # BARE verifier: FileIntegrity + spec-pinned dispatch under the auditor anchor.
    # NO register_primitive — the recompute resolves only via the CORE registry.
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()], spec_anchor=anchor
    ).verify(bundle_dir)


def test_promoted_generic_safe_path_and_faithfulness_pass(tmp_path):
    # Honest PASS proves BOTH: the generic verifier resolves raster via core
    # auto-registration (no import, no demo registration), AND the verifier's
    # recompute agrees with the producer's independent payload/zonal_result.json count.
    bundle_dir, anchor = _build(tmp_path / "bundle")
    result = _verify(bundle_dir, anchor)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_promoted_tampered_value_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Flip the claimed in_polygon_cell_count off by one (producer lies).
    claim_path = bundle_dir / "outputs" / f"{_OUTPUT_ID}.json"
    doc = json.loads(claim_path.read_bytes())
    honest = doc["value"]
    doc["value"] = honest + 1
    claim_path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    _realign_file_sha(bundle_dir, f"outputs/{_OUTPUT_ID}.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_promoted_tampered_input_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Shrink the COMMITTED polygon in spec/zonal_query.json so the ray-cast
    # re-derives a DIFFERENT count than the (honest) claimed value. The polygon
    # lives in spec/zonal_query.json, which FileIntegrityManySmall skips (spec/ is
    # excluded from file integrity). Re-align manifest.spec_files["zonal_query.json"]
    # so no spec-file hash mismatch fires — isolating the re-derivation mismatch.
    # The auditor spec (raster.spec.json) is unchanged, so the anchor SHA still
    # matches and the primitive dispatches correctly.
    spec_path = bundle_dir / "spec" / "zonal_query.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    # Shrink the L-shape's tall-left rectangle bottom edge from row 28 -> row 8,
    # removing many in-polygon cells → the re-derived count will be smaller than
    # the honest claimed count.
    spec["polygon"] = [
        [4, 4],
        [20, 4],
        [20, 12],
        [12, 12],
        [12, 8],
        [4, 8],
    ]
    spec_path.write_bytes(json.dumps(spec, indent=2).encode("utf-8"))
    _realign_spec_file_sha(bundle_dir, "zonal_query.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)
