"""Tests for the TypedCheck Protocol contract.

Covers:
  - Each of the 5 reference plugins satisfies isinstance(plugin, TypedCheck)
  - Each plugin carries the required Protocol attributes (name, applies_to_files)
  - Each plugin's check() returns a PluginResult with a valid reason_code on a
    minimal synthetic bundle
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from audit_bundle.plugin import PluginResult, TypedCheck
from audit_bundle.plugins.falsification_negative_test import (
    FalsificationNegativeTestCheck,
)
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.plugins.monotone_growth import MonotoneGrowthCheck
from audit_bundle.plugins.re_derivation_invocation import ReDerivationInvocationCheck
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck


# ---------------------------------------------------------------------------
# Minimal manifest stub — only carries fields plugins actually read
# ---------------------------------------------------------------------------


class _Manifest:
    def __init__(self, files=None, spec_files=None, typed_checks=None):
        self.files = files or {}
        self.spec_files = spec_files or {}
        self.typed_checks = typed_checks or []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Plugin instances for parametrised tests
# ---------------------------------------------------------------------------

_PLUGIN_INSTANCES = [
    SpecShaPinCheck(),
    FileIntegrityManySmall(),
    MonotoneGrowthCheck("2.0", "1.0"),
    FalsificationNegativeTestCheck(),
    ReDerivationInvocationCheck("pack.py", permit_execution=True),
]

_PLUGIN_IDS = [type(p).__name__ for p in _PLUGIN_INSTANCES]


# ---------------------------------------------------------------------------
# Protocol runtime-check: isinstance(plugin, TypedCheck)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("plugin", _PLUGIN_INSTANCES, ids=_PLUGIN_IDS)
def test_plugin_is_typed_check_instance(plugin) -> None:
    """Every reference plugin must satisfy isinstance(plugin, TypedCheck)."""
    assert isinstance(plugin, TypedCheck), (
        f"{type(plugin).__name__} is not a runtime instance of TypedCheck"
    )


@pytest.mark.parametrize("plugin", _PLUGIN_INSTANCES, ids=_PLUGIN_IDS)
def test_plugin_has_nonempty_name(plugin) -> None:
    """Every plugin must carry a non-empty string 'name' attribute."""
    assert isinstance(plugin.name, str), f"{type(plugin).__name__}.name is not a str"
    assert plugin.name, f"{type(plugin).__name__}.name is empty"


@pytest.mark.parametrize("plugin", _PLUGIN_INSTANCES, ids=_PLUGIN_IDS)
def test_plugin_applies_to_files_is_frozenset(plugin) -> None:
    """Every plugin must carry a frozenset 'applies_to_files' attribute."""
    assert isinstance(plugin.applies_to_files, frozenset), (
        f"{type(plugin).__name__}.applies_to_files is not a frozenset"
    )


def test_plugin_names_are_unique() -> None:
    """All five reference plugins must have distinct names."""
    names = [p.name for p in _PLUGIN_INSTANCES]
    assert len(names) == len(set(names)), f"duplicate plugin names: {names}"


# ---------------------------------------------------------------------------
# Mock-bundle: each plugin's check() returns a PluginResult with valid reason_code
# ---------------------------------------------------------------------------


def test_spec_sha_pin_check_returns_plugin_result(tmp_path: Path) -> None:
    """SpecShaPinCheck.check() returns a PluginResult on a minimal valid bundle."""
    content = b"spec content for contract test"
    (tmp_path / "spec").mkdir()
    (tmp_path / "spec" / "example.md").write_bytes(content)
    manifest = _Manifest(spec_files={"example.md": _sha256(content)})

    result = SpecShaPinCheck().check(tmp_path, manifest)

    assert isinstance(result, PluginResult)
    assert isinstance(result.ok, bool)
    assert isinstance(result.reason_code, str)
    assert result.reason_code  # non-empty
    assert result.ok is True
    assert result.reason_code == "PASS"


def test_file_integrity_many_small_check_returns_plugin_result(tmp_path: Path) -> None:
    """FileIntegrityManySmall.check() returns a PluginResult on a minimal valid bundle."""
    content = b"payload bytes"
    (tmp_path / "payload").mkdir()
    (tmp_path / "payload" / "out.txt").write_bytes(content)
    manifest = _Manifest(files={"payload/out.txt": _sha256(content)})

    # D5: Pass 3 is a shim over the core conservation gate — a direct check()
    # consumes a bound result (verify() binds it itself; here we mirror that).
    from audit_bundle.conservation import run_conservation

    plugin = FileIntegrityManySmall()
    plugin.bind_conservation(
        run_conservation(tmp_path, manifest, frozenset(), sealed=False)
    )
    result = plugin.check(tmp_path, manifest)

    assert isinstance(result, PluginResult)
    assert result.ok is True
    assert result.reason_code == "PASS"


def test_monotone_growth_check_returns_plugin_result(tmp_path: Path) -> None:
    """MonotoneGrowthCheck.check() returns a PluginResult on a minimal valid bundle."""
    (tmp_path / "corpus" / "2.0").mkdir(parents=True)
    (tmp_path / "previous_corpus" / "1.0").mkdir(parents=True)
    (tmp_path / "corpus" / "2.0" / "corpus.jsonl").write_text(
        json.dumps({"id": "c1"}) + "\n", encoding="utf-8"
    )
    (tmp_path / "previous_corpus" / "1.0" / "corpus.jsonl").write_text(
        json.dumps({"id": "c1"}) + "\n", encoding="utf-8"
    )

    result = MonotoneGrowthCheck("2.0", "1.0").check(tmp_path, _Manifest())

    assert isinstance(result, PluginResult)
    assert result.ok is True
    assert result.reason_code == "PASS"


def test_falsification_negative_test_check_returns_plugin_result(
    tmp_path: Path,
) -> None:
    """FalsificationNegativeTestCheck.check() returns a PluginResult on a minimal bundle."""
    rules_dir = tmp_path / "falsification_rules"
    rules_dir.mkdir()
    rule = {"trigger_expression": "x > 0", "falsify_if": "x > 0"}
    (rules_dir / "rule_01.json").write_text(json.dumps(rule), encoding="utf-8")

    result = FalsificationNegativeTestCheck().check(tmp_path, _Manifest())

    assert isinstance(result, PluginResult)
    assert result.ok is True
    # PROCEED_WITH_CAVEAT is deprecated emit-never (M6): an in-grammar
    # decidable rule is a plain PASS; out-of-grammar now fails closed.
    assert result.reason_code == "PASS"


def test_re_derivation_invocation_check_returns_plugin_result(tmp_path: Path) -> None:
    """ReDerivationInvocationCheck.check() returns a PluginResult when no pack present."""
    result = ReDerivationInvocationCheck(
        "energy_score_pack.py", permit_execution=True
    ).check(tmp_path, _Manifest())

    assert isinstance(result, PluginResult)
    assert result.ok is True
    assert result.reason_code == "NO_PACK"


# ---------------------------------------------------------------------------
# PluginResult structural invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("plugin", _PLUGIN_INSTANCES, ids=_PLUGIN_IDS)
def test_plugin_result_files_audited_is_tuple(plugin, tmp_path: Path) -> None:
    """check() must return a PluginResult where files_audited is a tuple of strings."""
    # Build the minimal setup each plugin needs to not raise before returning.
    _prepare_minimal_bundle(plugin, tmp_path)
    result = plugin.check(tmp_path, _Manifest())
    assert isinstance(result.files_audited, tuple)
    for item in result.files_audited:
        assert isinstance(item, str)


def _prepare_minimal_bundle(plugin, bundle_dir: Path) -> None:
    """Prepare the minimal on-disk structure each plugin needs for check() to return."""
    if isinstance(plugin, SpecShaPinCheck):
        pass  # empty spec_files → no files needed
    elif isinstance(plugin, FileIntegrityManySmall):
        # D5: the Pass-3 shim consumes a bound conservation result (a direct
        # check() without one hard-errors by design).
        from audit_bundle.conservation import run_conservation

        plugin.bind_conservation(
            run_conservation(bundle_dir, _Manifest(), frozenset(), sealed=False)
        )
    elif isinstance(plugin, MonotoneGrowthCheck):
        (bundle_dir / "corpus" / "2.0").mkdir(parents=True, exist_ok=True)
        (bundle_dir / "previous_corpus" / "1.0").mkdir(parents=True, exist_ok=True)
        (bundle_dir / "corpus" / "2.0" / "corpus.jsonl").write_text(
            json.dumps({"id": "seed"}) + "\n", encoding="utf-8"
        )
        (bundle_dir / "previous_corpus" / "1.0" / "corpus.jsonl").write_text(
            json.dumps({"id": "seed"}) + "\n", encoding="utf-8"
        )
    elif isinstance(plugin, FalsificationNegativeTestCheck):
        pass  # no rules dir → PASS immediately
    elif isinstance(plugin, ReDerivationInvocationCheck):
        pass  # no re_derive dir → NO_PACK immediately
