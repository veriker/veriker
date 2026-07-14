"""Tests for the OSS-boundary leak authority audit.

Mirrors the boundary-guard discipline: confirm GREEN today AND confirm each
detector actually fires, so a green result can't be green-by-being-broken.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

PRODUCT_ROOT = Path(__file__).resolve().parents[1]


def _load_leak_audit():
    path = PRODUCT_ROOT / "release" / "leak_audit.py"
    spec = importlib.util.spec_from_file_location("_leak_audit_under_test", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so @dataclass can resolve cls.__module__ during load.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class _FakeOss:
    """Minimal stand-in exposing the loader surface leak_audit reuses."""

    def __init__(self, excluded: set[str]):
        self._excluded = excluded

    def _load_premium_paths(self):
        return ()

    def _load_mirror_excludes(self):
        return ()

    def _excluded_rels(self, premium, mirror):
        return set(self._excluded)


def test_audit_is_green_today_fast():
    """Checks A + B are GREEN against the live authorities + filesystem."""
    L = _load_leak_audit()
    rep = L.audit(fast=True)
    assert not rep.red, rep.to_dict()


def test_sales_asset_list_parses():
    """The 'Sales-asset gated' bullet brace-expands to the documented pilots."""
    L = _load_leak_audit()
    paths = L.sales_asset_paths()
    # Asserted structurally + cross-validated against the operative exclusion set,
    # deliberately WITHOUT hardcoding firm-name literals (those would trip the
    # FIRM-T1 leak scan, since tests/ ships in the open export).
    assert len(paths) >= 9
    assert all("/" in p for p in paths), paths
    assert any(p.startswith("examples/") for p in paths)
    # Every parsed sales-asset path must be in the operative exclusion set — the
    # same property seal-check B enforces, which proves the parse is meaningful.
    oss = L._load_oss_export()
    excluded = L.operative_exclusions(oss)
    assert all(p in excluded for p in paths), [p for p in paths if p not in excluded]


def test_seal_detector_fires_on_unsealed_existing_asset(monkeypatch):
    """A sales-asset path that exists on disk but is NOT excluded is flagged."""
    L = _load_leak_audit()
    # README.md exists in the product root and is (correctly) not an exclusion.
    monkeypatch.setattr(L, "sales_asset_paths", lambda: ["README.md"])
    bad = L.unsealed_sales_assets(_FakeOss(excluded=set()))
    assert bad == ["README.md"], "seal detector failed to flag an unsealed asset"


def test_seal_detector_clean_when_excluded(monkeypatch):
    """The same asset, once in the exclusion set, is no longer flagged."""
    L = _load_leak_audit()
    monkeypatch.setattr(L, "sales_asset_paths", lambda: ["README.md"])
    assert L.unsealed_sales_assets(_FakeOss(excluded={"README.md"})) == []


def test_dead_entry_detector_fires():
    """An exclusion entry that does not exist on disk is reported as dead."""
    L = _load_leak_audit()
    dead = L.dead_exclusion_entries(
        _FakeOss(excluded={"examples/this_pilot_does_not_exist_xyz"})
    )
    assert dead == ["examples/this_pilot_does_not_exist_xyz"]


def test_dead_entry_detector_clean_for_real_path():
    L = _load_leak_audit()
    assert L.dead_exclusion_entries(_FakeOss(excluded={"README.md"})) == []
