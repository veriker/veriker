"""Plugin disclosures reach the LIBRARY verdict face (assurance labeling).

Why: a passing plugin's `detail` prose is dropped by verify() — before this,
C19's "v0.3 reference implementation / not Byzantine-safe under bilateral
collusion" limitation reached no surface a library consumer could read; a green
verdict backed by reference-grade cross-host evidence was indistinguishable
from a hardened one (redteam mirror finding, 2026-06-10). `Completeness.
disclosures` is the house channel for exactly this ("honest residuals a GREEN
verdict must still surface"); these tests pin the plugin→verdict wiring:

  PluginResult.disclosures → _step_typed_check_plugins (getattr, default ()) →
  Completeness.disclosures on the verdict verify() returns.

Surfacing only — a disclosure never changes pass/fail; that invariant is
asserted here too.
"""

from __future__ import annotations

from pathlib import Path

from audit_bundle.plugin import PluginResult
from audit_bundle.verdict import VerdictState
from audit_bundle.verifier import BundleVerifier


class _DisclosingCheck:
    """Stub plugin: passes, carries disclosures."""

    name = "disclosing_check"
    applies_to_files: frozenset[str] = frozenset()

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail="fine, with residuals",
            files_audited=(),
            disclosures=(
                "disclosing_check: residual A",
                "disclosing_check: residual B",
            ),
        )


class _LegacyResult:
    """A duck-typed result object with NO disclosures attribute (legacy)."""

    ok = True
    reason_code = "PASS"
    detail = ""
    files_audited: tuple[str, ...] = ()


class _LegacyCheck:
    name = "legacy_check"
    applies_to_files: frozenset[str] = frozenset()

    def check(self, bundle_dir: Path, manifest) -> _LegacyResult:
        return _LegacyResult()


class _IncompleteDisclosingCheck:
    """Could-not-conclude AND carries a disclosure — both must surface."""

    name = "incomplete_disclosing_check"
    applies_to_files: frozenset[str] = frozenset()

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        return PluginResult(
            ok=True,
            incomplete=True,
            reason_code="COULD_NOT_CONCLUDE",
            detail="external attestation absent",
            files_audited=(),
            disclosures=("incomplete_disclosing_check: residual C",),
        )


def _run_plugins(plugins) -> tuple[list, list, list]:
    """Drive _step_typed_check_plugins directly with stub plugins against an
    empty manifest surface (typed_checks=()), returning the three accumulators.
    Direct-step invocation keeps the test independent of building a full
    walk-passing bundle; the verify()→Completeness wiring is one call site
    (covered by the C19 integration tests in test_cross_host_peerreview.py)."""
    verifier = BundleVerifier(plugins=plugins)

    class _ManifestStub:
        typed_checks: list[str] = []

    failures: list = []
    incompletes: list = []
    disclosures: list = []
    verifier._step_typed_check_plugins(
        Path("."),
        _ManifestStub(),
        failures,
        incompletes,
        set(),  # cross_host_verified
        set(),  # fragment_anchors_verified
        set(),  # profiles_graded
        set(),  # dispatch_records_verified
        set(),  # stamp_claims_verified
        set(),  # causal_chain_subkeys_verified
        set(),  # layer_a_event_obligations_verified
        disclosures,
    )
    return failures, incompletes, disclosures


def test_passing_plugin_disclosures_are_accumulated():
    failures, incompletes, disclosures = _run_plugins([_DisclosingCheck()])
    assert failures == []
    assert incompletes == []
    assert disclosures == [
        "disclosing_check: residual A",
        "disclosing_check: residual B",
    ]


def test_legacy_result_without_attribute_contributes_nothing():
    failures, incompletes, disclosures = _run_plugins([_LegacyCheck()])
    assert failures == []
    assert disclosures == []


def test_incomplete_plugin_disclosures_still_surface():
    failures, incompletes, disclosures = _run_plugins([_IncompleteDisclosingCheck()])
    # The could-not-conclude leg is recorded AND the residual surfaces.
    assert len(incompletes) == 1
    assert incompletes[0].state is VerdictState.ERROR
    assert disclosures == ["incomplete_disclosing_check: residual C"]


def test_disclosures_never_change_classification():
    # Same plugin set with and without disclosures → identical failure/
    # incomplete classification (surfacing only).
    f1, i1, _ = _run_plugins([_DisclosingCheck(), _LegacyCheck()])
    f2, i2, _ = _run_plugins([_LegacyCheck()])
    assert f1 == f2 == []
    assert i1 == i2 == []
