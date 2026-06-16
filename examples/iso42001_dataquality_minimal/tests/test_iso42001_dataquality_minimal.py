"""tests/test_iso42001_dataquality_minimal.py — tamper + §4a attack tests.

ISO/IEC 42001 A.7 data-quality re-derivation (MULTI-OUTPUT). Surfaces:

  0. Unit: the three compute fns on the known fixture-shaped inputs.
  1. Happy path: build -> verify -> PASS (all 3 metrics re-derive).
  2. Per-metric mutation: inflate the claimed data_completeness_pct (+2.0),
     re-align its SHA -> REDERIVATION_MISMATCH. One doctored metric of three
     still fails the whole bundle (cardinality guard).
  3. Dataset tamper: drop a duplicate record's tuple so duplicate-rate changes,
     WITHOUT updating manifest.files -> BAD_FILE_SHA + REDERIVATION_MISMATCH.
  4. Coverage attack (multi-output specific): delete one outputs/*.json file and
     its manifest.outputs entry AND manifest.files entry -> COVERAGE_MISMATCH
     fires (omitting the output entry does not let the metric escape audit).
  5. Weaker-spec substitution -> AnchorViolation (Axis-1 anchor).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

_TEST_DIR = Path(__file__).resolve().parent
_PILOT_DIR = _TEST_DIR.parent
_PKG_ROOT = _PILOT_DIR.parents[1]

if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.rederivation.registry import register_primitive  # noqa: E402
from audit_bundle.rederivation.spec_binding import SpecAnchor  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
import iso42001_dataquality_recompute as _prim_mod  # noqa: E402

register_primitive(_prim_mod.Iso42001DataQualityRecompute())

_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "iso42001_dataquality.spec.json"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"


def _build(out_dir: Path) -> None:
    subprocess.run(
        [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(out_dir)],
        capture_output=True,
        check=True,
    )


def _anchor() -> SpecAnchor:
    raw = _SPEC_SRC.read_bytes()
    doc = json.loads(raw)
    return SpecAnchor(allowed={doc["spec_id"]: hashlib.sha256(raw).hexdigest()})


def _verifier(anchor: SpecAnchor | None = None) -> BundleVerifier:
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()],
        spec_anchor=anchor if anchor is not None else _anchor(),
    )


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


# ---------------------------------------------------------------------------
# 0. Unit on the three compute fns
# ---------------------------------------------------------------------------


def test_compute_fns_known_values():
    recs = [
        {"feature_a": "x", "feature_b": "y", "label": 1},
        {"feature_a": "x", "feature_b": "y", "label": 1},  # exact duplicate
        {"feature_a": None, "feature_b": "y", "label": 0},  # incomplete
        {"feature_a": "z", "feature_b": "w", "label": None},  # null label
    ]
    # completeness: 2 of 4 complete (rows 0,1) -> 50%
    assert _prim_mod.compute_completeness_pct(recs) == 50.0
    # duplicates: 4 records, distinct tuples = {(x,y,1),(None,y,0),(z,w,None)} = 3
    # -> (4-3)/4 = 25%
    assert _prim_mod.compute_duplicate_rate_pct(recs) == 25.0
    # positive rate: among 3 non-null-label records, 2 are label==1 -> 66.66..%
    assert abs(_prim_mod.compute_positive_rate_pct(recs) - (100.0 * 2 / 3)) < 1e-12


# ---------------------------------------------------------------------------
# 1. Happy path
# ---------------------------------------------------------------------------


def test_honest_pass(tmp_path):
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)
    result = _verifier().verify(bundle_dir)
    assert result.ok, [
        (f.check_name, f.reason_code, f.detail) for f in result.failures
    ]


# ---------------------------------------------------------------------------
# 2. Per-metric mutation
# ---------------------------------------------------------------------------


def test_one_metric_mutation_fails(tmp_path):
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)

    rel = "outputs/data_completeness_pct.json"
    p = bundle_dir / rel
    d = json.loads(p.read_bytes())
    nb = json.dumps({"value": float(d["value"]) + 2.0}, indent=2).encode("utf-8")
    p.write_bytes(nb)
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][rel] = hashlib.sha256(nb).hexdigest()
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))

    result = _verifier().verify(bundle_dir)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result)


# ---------------------------------------------------------------------------
# 3. Dataset tamper
# ---------------------------------------------------------------------------


def test_dataset_tamper_fails(tmp_path):
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)

    ds = bundle_dir / "inputs" / "dataset.json"
    doc = json.loads(ds.read_bytes())
    # Make r11 (a duplicate of r01) distinct -> duplicate-rate drops.
    for r in doc["records"]:
        if r["record_id"] == "r11":
            r["feature_a"] = "a1_DISTINCT"
            break
    ds.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    # Do NOT update manifest.files -> BAD_FILE_SHA.

    result = _verifier().verify(bundle_dir)
    assert not result.ok
    rc = _reason_codes(result)
    assert "bad_file_sha" in rc or "plugin_failed" in rc, rc
    assert "REDERIVATION_MISMATCH" in rc, rc


# ---------------------------------------------------------------------------
# 4. Coverage attack (multi-output specific)
# ---------------------------------------------------------------------------


def test_omit_output_entry_fails_coverage(tmp_path):
    """Drop one metric's manifest.outputs entry + its manifest.files entry but
    LEAVE the outputs/*.json file present -> the coverage invariant fires
    (present-but-undeclared). Omitting the output entry must not let a metric
    escape the audit."""
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)

    rel = "outputs/data_positive_rate_pct.json"
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["outputs"] = [o for o in m["outputs"] if o["output_id"] != "data_positive_rate_pct"]
    del m["files"][rel]  # so file-integrity doesn't fire on the orphan instead
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))

    result = _verifier().verify(bundle_dir)
    assert not result.ok
    rc = _reason_codes(result)
    assert "COVERAGE_MISMATCH" in rc, (
        f"Expected COVERAGE_MISMATCH; got {rc!r} | "
        f"{[(f.check_name, f.reason_code) for f in result.failures]}"
    )


# ---------------------------------------------------------------------------
# 5. Weaker-spec substitution -> AnchorViolation
# ---------------------------------------------------------------------------


def test_weak_spec_substitution_fails(tmp_path):
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)

    weak = json.dumps(
        {
            "spec_id": "iso42001.dataquality.v1",
            "types": {
                t: {
                    "primitive_id": "iso42001_dataquality_recompute",
                    "comparator": {"kind": "scalar_epsilon", "params": {"epsilon": 1e30}},
                }
                for t in (
                    "data_completeness_pct",
                    "data_duplicate_rate_pct",
                    "data_positive_rate_pct",
                )
            },
        }
    ).encode("utf-8")

    rel = "outputs/data_completeness_pct.json"
    nb = json.dumps({"value": 100.0}, indent=2).encode("utf-8")
    (bundle_dir / rel).write_bytes(nb)
    spec_path = bundle_dir / "spec" / "iso42001_dataquality.spec.json"
    spec_path.write_bytes(weak)

    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][rel] = hashlib.sha256(nb).hexdigest()
    m["spec_files"]["iso42001_dataquality.spec.json"] = hashlib.sha256(weak).hexdigest()
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))

    result = _verifier(_anchor()).verify(bundle_dir)
    assert not result.ok
    assert "AnchorViolation" in _reason_codes(result)
