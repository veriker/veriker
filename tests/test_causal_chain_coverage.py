"""Tests for the causal_chain coverage guard (BLOCK-02).

The guard closes the WHOLE ``causal_chain`` field, not just ``layer_a``: a census
of the original ChatGPT BLOCK-02 finding showed FOUR unguarded sub-keys
(layer_a, counter_chain, layer_b_anchors, cross_host_edges) rode GREEN with
forged content; only cross_host_authenticators had a guard. These tests pin:

  1. the laundering regression — every present sub-key with no plugin coverage
     fails closed (could-not-conclude), and inert/empty causal_chain stays green;
  2. the universal-coverage contract — a plugin reporting the right content key
     keeps a verified sub-key green; a near-miss key does not;
  3. the ratchet — the documented substrate sub-key registry stays a subset of
     the names the profile-completeness policy already reasons about, so a new
     S19 sub-key cannot be registered for assurance grading without the coverage
     discipline knowing the name exists.
"""

from __future__ import annotations

import json
from pathlib import Path

from audit_bundle.causal_chain_coverage import (
    KNOWN_SUBSTRATE_SUBKEYS,
    accountable_causal_chain_keys,
    causal_chain_subkey_key,
    subkey_coverage,
)
from audit_bundle.plugin import PluginResult
from audit_bundle.verifier import BundleVerifier
from audit_bundle.verdict import VerdictState

_BASE = {
    "schema_version": "legacy",
    "bundle_id": "b",
    "created_at": "2026-06-11T00:00:00Z",
    "files": {},
    "spec_files": {},
    "cross_refs": {},
}


def _verify(tmp_path: Path, causal_chain, *, plugins=()):
    manifest = dict(_BASE)
    if causal_chain is not None:
        manifest["causal_chain"] = causal_chain
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    return BundleVerifier(plugins=plugins).verify(tmp_path)


class _CoverageStub:
    """Reports verified coverage for whatever causal_chain sub-keys are present
    (minus cross_host_authenticators) — stands in for a real substrate/pilot
    plugin that re-derived the chain."""

    name = "test_cc_coverage_stub"
    applies_to_files: frozenset[str] = frozenset()

    def check(self, bundle_dir, manifest) -> PluginResult:
        cc = getattr(manifest, "causal_chain", None)
        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail="stub",
            files_audited=(),
            verified_causal_chain_subkeys=accountable_causal_chain_keys(cc or {})[0],
        )


# --------------------------------------------------------------------------
# 1. Laundering regression — present-but-unverified fails closed
# --------------------------------------------------------------------------

_FORGED = {
    "layer_a": {
        "event_dag_merkle_root": "deadbeefnotahash",
        "chain_height": 99999,
        "events": [{"event_signature": "FORGED"}],
    },
    "counter_chain": {"forged": "chain", "height": 99},
    "layer_b_anchors": [{"anchor": "forged", "root": "deadbeef"}],
    "cross_host_edges": [{"forged": "edge"}],
    "future_unknown_subkey": {"x": 1},  # ratchet: unknown name, no plugin
}


def test_each_present_subkey_with_no_plugin_fails_closed(tmp_path):
    for name, value in _FORGED.items():
        v = _verify(tmp_path, {name: value})
        assert v.state is VerdictState.ERROR, f"{name} laundered to {v.state}"
        assert any(r.check_name == "causal_chain" for r in v.reasons), (
            f"{name}: expected a causal_chain reason, got {[r.check_name for r in v.reasons]}"
        )


def test_unknown_future_subkey_fails_closed_even_though_not_in_registry(tmp_path):
    """The strong ratchet: coverage is universal, so a sub-key name nobody has
    ever registered still fails closed when no plugin covers it (no allowlist
    hole)."""
    v = _verify(tmp_path, {"totally_new_s19z_subkey": {"root": "x"}})
    assert v.state is VerdictState.ERROR


def test_empty_or_absent_causal_chain_stays_green(tmp_path):
    for cc in (None, {}, {"layer_a": {}}, {"cross_host_authenticators": []}):
        v = _verify(tmp_path, cc)
        assert v.state is VerdictState.OK, f"{cc!r} should be inert, got {v.state}"


def test_cross_host_authenticators_not_double_jeopardized(tmp_path):
    """A present cross_host_authenticators edge is the ONE name this guard does
    not account for (it is verified edge-level by _step_cross_host_guard). The
    _CoverageStub reports NOTHING for it, yet this guard must not add a second
    causal_chain leg for it — the edge-level guard owns it."""
    cc = {"cross_host_authenticators": [{"forged": "edge"}]}
    v = _verify(tmp_path, cc, plugins=[_CoverageStub()])
    # It still fails — but via the cross-host guard, not this one.
    assert v.state is VerdictState.ERROR
    assert any(r.check_name == "cross_host_authenticators" for r in v.reasons)
    assert not any(r.check_name == "causal_chain" for r in v.reasons)


# --------------------------------------------------------------------------
# 2. Universal-coverage contract — a verifying plugin keeps it green
# --------------------------------------------------------------------------


def test_reported_coverage_keeps_verified_subkey_green(tmp_path):
    cc = {"layer_a": {"event_dag_merkle_root": "a" * 64, "chain_height": 1}}
    v = _verify(tmp_path, cc, plugins=[_CoverageStub()])
    assert v.state is VerdictState.OK


def test_coverage_of_a_different_value_does_not_satisfy(tmp_path):
    """Content keys bind to bytes: a plugin that verified some OTHER layer_a
    cannot launder THIS one."""

    class _WrongKeyStub:
        name = "wrong"
        applies_to_files: frozenset[str] = frozenset()

        def check(self, bundle_dir, manifest) -> PluginResult:
            return PluginResult(
                ok=True,
                reason_code="PASS",
                detail="",
                files_audited=(),
                verified_causal_chain_subkeys=subkey_coverage(
                    "layer_a", {"a different": "layer_a"}
                ),
            )

    cc = {"layer_a": {"event_dag_merkle_root": "b" * 64, "chain_height": 2}}
    v = _verify(tmp_path, cc, plugins=[_WrongKeyStub()])
    assert v.state is VerdictState.ERROR


def test_coverage_name_is_bound_into_the_key(tmp_path):
    """Coverage of layer_a must not be satisfiable by a plugin that verified the
    same bytes under a different sub-key name."""
    value = {"root": "x" * 64}
    assert causal_chain_subkey_key("layer_a", value) != causal_chain_subkey_key(
        "layer_b_anchors", value
    )


# --------------------------------------------------------------------------
# 3. Ratchet — substrate registry stays known to the coverage discipline
# --------------------------------------------------------------------------


def test_profile_registry_subkeys_are_known_substrate_subkeys():
    """If a new S19 sub-stream adds a causal_chain sub-key to the profile-
    completeness STRUCTURE_PATHS (assurance-grading registry) without adding it
    to KNOWN_SUBSTRATE_SUBKEYS, this fails — the documented substrate registry
    cannot silently drift away from the coverage discipline. (Runtime coverage
    is universal regardless, so this is belt-and-suspenders documentation pin.)"""
    from audit_bundle.extensions.c19.profile_completeness_policy import (
        STRUCTURE_PATHS,
    )

    registry_subkeys = {
        path[1]
        for path in STRUCTURE_PATHS.values()
        if len(path) >= 2 and path[0] == "causal_chain"
    }
    missing = registry_subkeys - KNOWN_SUBSTRATE_SUBKEYS
    assert not missing, (
        f"profile STRUCTURE_PATHS names causal_chain sub-key(s) {sorted(missing)} "
        "absent from KNOWN_SUBSTRATE_SUBKEYS — add them so the substrate registry "
        "and the coverage discipline stay aligned"
    )


def test_helper_excludes_only_cross_host_authenticators(tmp_path):
    cc = {
        "layer_a": {"root": "x"},
        "layer_b_anchors": [{"a": 1}],
        "cross_host_authenticators": [{"edge": 1}],
    }
    keys, n_unkeyable = accountable_causal_chain_keys(cc)
    assert n_unkeyable == 0
    assert keys == subkey_coverage("layer_a", cc["layer_a"]) | subkey_coverage(
        "layer_b_anchors", cc["layer_b_anchors"]
    )


def test_unkeyable_value_counts_as_uncoverable():
    # A non-JSON-serializable value (only reachable via a directly-constructed
    # manifest) is uncoverable and must be counted, never silently covered.
    keys, n_unkeyable = accountable_causal_chain_keys({"layer_a": {1, 2, 3}})
    assert keys == frozenset()
    assert n_unkeyable == 1
