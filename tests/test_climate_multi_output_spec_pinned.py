"""tests/test_climate_multi_output_spec_pinned.py — multi-output coverage-invariant
(§4a.4 / C19) + cardinality (§4a.8) demonstration over a GENUINE two-output bundle.

Composes the climate_emission_minimal pilot's two already auditor-anchored outputs
into one bundle (exact scalar total + structured per-vendor list), both re-derived
from the same inputs/supplier_chain.json under a SpecAnchor that allows both
committed spec_ids. Covers:

  1. Honest two-output bundle -> PASS (declared set == present set; both re-derive).
  2. Omitted output ENTRY (file present, no manifest.outputs entry) -> fail-closed
     COVERAGE_MISMATCH (present-but-undeclared): the §4a.4 raison d'être — "omit
     the check" must not degenerate to "omit the output entry".
  3. Declared-but-absent output (entry present, file removed) -> fail-closed
     COVERAGE_MISMATCH (declared-but-absent).
  4. Per-output isolation: tampering ONE output's value fails ONLY that output's
     re-derivation (REDERIVATION_MISMATCH), exactly once.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

sys.dont_write_bytecode = True

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PILOT_DIR = _PKG_ROOT / "examples" / "climate_emission_minimal"
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_load("climate_attribution_recompute", _PILOT_DIR / "climate_attribution_recompute.py")
_mc = _load("climate_multi_output_check", _PILOT_DIR / "spec_pinned_multi_check.py")


def _codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _coverage_failures(result):
    return [f for f in result.failures if f.check_name == "spec_pinned_dispatch:coverage"]


def test_honest_two_output_pass(tmp_path):
    bundle = _mc.build_multi_output(tmp_path / "b")
    result = _mc.make_verifier(_mc.anchor_from_committed_specs()).verify(bundle)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_omitted_output_entry_fails_closed(tmp_path):
    # Producer drops output B's manifest.outputs entry but ships its file — the
    # unchecked output would have failed; the coverage invariant catches it.
    bundle = _mc.build_multi_output(tmp_path / "b", omit_entry="climate-attribution")
    result = _mc.make_verifier(_mc.anchor_from_committed_specs()).verify(bundle)
    assert not result.ok
    assert "COVERAGE_MISMATCH" in _codes(result), _codes(result)
    cov = _coverage_failures(result)
    assert cov and "present-but-undeclared=['climate-attribution']" in cov[0].detail, cov


def test_declared_but_absent_fails_closed(tmp_path):
    # Producer keeps output B's entry but ships no file -> declared-but-absent.
    bundle = _mc.build_multi_output(tmp_path / "b", drop_file="climate-attribution")
    result = _mc.make_verifier(_mc.anchor_from_committed_specs()).verify(bundle)
    assert not result.ok
    assert "COVERAGE_MISMATCH" in _codes(result), _codes(result)
    cov = _coverage_failures(result)
    assert cov and "declared-but-absent=['climate-attribution']" in cov[0].detail, cov


def test_per_output_isolation_structured(tmp_path):
    # Tamper ONLY output B (structured list) -> only B's re-derivation fails.
    bundle = _mc.build_multi_output(
        tmp_path / "b",
        tamper_output=("climate-attribution", [{"vendor_id": "X", "tier": 1, "attributed_kg_co2e": 0.0}]),
    )
    result = _mc.make_verifier(_mc.anchor_from_committed_specs()).verify(bundle)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _codes(result), _codes(result)
    mismatches = [f for f in result.failures if f.reason_code == "REDERIVATION_MISMATCH"]
    assert len(mismatches) == 1, [f.check_name for f in mismatches]
    assert mismatches[0].check_name == "spec_pinned_dispatch:climate-attribution"


def test_per_output_isolation_exact(tmp_path):
    # Tamper ONLY output A (exact scalar) -> only A's re-derivation fails.
    bundle = _mc.build_multi_output(
        tmp_path / "b", tamper_output=("climate-total-scope3", 999999.0)
    )
    result = _mc.make_verifier(_mc.anchor_from_committed_specs()).verify(bundle)
    assert not result.ok
    mismatches = [f for f in result.failures if f.reason_code == "REDERIVATION_MISMATCH"]
    assert len(mismatches) == 1, [f.check_name for f in mismatches]
    assert mismatches[0].check_name == "spec_pinned_dispatch:climate-total-scope3"
