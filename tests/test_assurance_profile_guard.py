"""Assurance-profile guard — the verifier never certifies the LABEL without
the grading behind it (ChatGPT BLOCK-01 profile downgrade, 2026-06-12).

The reproduced finding: a minimal bundle declaring
``assurance_profile: "regulated-high-assurance"`` with ZERO high-assurance
evidence returned ``VerdictState.OK`` from a plugin-less ``BundleVerifier()``
— the label was parsed, folded into tamper-evidence, and consulted by nothing.

These tests pin the guard semantics (tribunal-ratified 2026-06-12):
unknown → REJECT; conflict → REJECT; declared-but-ungraded →
could-not-conclude (clean-ERROR), NEVER a silent OK; verifier-held floor +
policy drive admission and required-structure presence; coverage is the
``(profile_id, policy_fingerprint)`` pair, so a grader against a DIFFERENT
policy does not satisfy a configured verifier.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from audit_bundle.extensions.c19.profile_completeness_policy import (
    PROFILE_DECLARATION_CONFLICT,
    PROFILE_DECLARED_BELOW_PINNED_FLOOR,
    PROFILE_DECLARED_BUT_UNGRADED,
    PROFILE_DECLARED_UNKNOWN,
    PROFILE_REQUIRED_STRUCTURE_ABSENT,
    CompletenessPolicy,
    ObligationLattice,
    Profile,
    builtin_profile_lattice,
    effective_declared_profile,
    policy_fingerprint,
)
from audit_bundle.causal_chain_coverage import accountable_causal_chain_keys
from audit_bundle.plugin import PluginResult
from audit_bundle.verdict import VerdictState
from audit_bundle.verifier import BundleVerifier


def _write_bundle(
    tmp_path: Path,
    *,
    assurance_profile: str | None = None,
    layer_a_profile: str | None = None,
    causal_chain_extra: dict | None = None,
) -> Path:
    """Minimal integrity-clean bundle (same shape as the verdict-out fixture)."""
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    corpus_dir = bundle_dir / "corpus"
    corpus_dir.mkdir()
    content = b"synthetic corpus entry for assurance-profile guard test"
    (corpus_dir / "entry0.txt").write_bytes(content)

    manifest: dict = {
        "schema_version": "legacy",
        "bundle_id": "assurance-profile-guard-test",
        "created_at": "2026-01-01T00:00:00Z",
        "files": {"corpus/entry0.txt": hashlib.sha256(content).hexdigest()},
        "spec_files": {},
        "cross_refs": {},
        "payload": {},
        "typed_checks": [],
        "per_output_manifests": [],
    }
    if assurance_profile is not None:
        manifest["assurance_profile"] = assurance_profile
    cc: dict = dict(causal_chain_extra or {})
    if layer_a_profile is not None:
        cc.setdefault("layer_a", {})["assurance_profile"] = layer_a_profile
    if cc:
        manifest["causal_chain"] = cc
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return bundle_dir


class _StubGrader:
    """Minimal grader plugin reporting (profile_id, fingerprint) coverage."""

    name = "stub_profile_grader"
    applies_to_files: frozenset[str] = frozenset()

    def __init__(self, profile_id: str, fingerprint: str) -> None:
        self._pair = (profile_id, fingerprint)

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail="stub grading",
            files_audited=(),
            graded_assurance_profiles=frozenset({self._pair}),
        )


class _CausalChainCoverageStub:
    """Reports coverage for whatever causal_chain sub-keys the bundle carries —
    stands in for the real layer_a verifier a regulated-high-assurance bundle
    wires. A present layer_a structure is required to be PRESENT by the profile
    policy AND VERIFIED by the causal_chain coverage guard (two distinct axes);
    these grading tests carry a bare layer_a label-holder, so this stub
    discharges the coverage axis to isolate the profile-grading behavior."""

    name = "stub_causal_chain_coverage"
    applies_to_files: frozenset[str] = frozenset()

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        cc = getattr(manifest, "causal_chain", None)
        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail="stub causal_chain coverage",
            files_audited=(),
            verified_causal_chain_subkeys=accountable_causal_chain_keys(cc or {})[0],
        )


def _reason_codes(verdict) -> list[str]:
    return [r.code for r in verdict.reasons]


def _details(verdict) -> str:
    return " | ".join(r.detail for r in verdict.reasons)


# --- the reproduced finding -------------------------------------------------


def test_declared_high_assurance_with_no_evidence_is_not_ok(tmp_path):
    """THE BLOCK-01 repro: plugin-less verify() must NOT return OK over a
    regulated-high-assurance label nothing graded."""
    bundle = _write_bundle(tmp_path, assurance_profile="regulated-high-assurance")
    verdict = BundleVerifier().verify(bundle)
    assert verdict.state is VerdictState.ERROR
    assert PROFILE_DECLARED_BUT_UNGRADED in _details(verdict)


def test_no_declaration_no_floor_is_inert(tmp_path):
    """Regression: a bundle declaring no profile, verifier holding no floor —
    nothing asserted, nothing owed, verdict unchanged."""
    bundle = _write_bundle(tmp_path)
    verdict = BundleVerifier().verify(bundle)
    assert verdict.state is VerdictState.OK
    assert not any("assurance_profile" in d for d in verdict.completeness.disclosures)


# --- admission against the canonical lattice (no config needed) -------------


def test_unknown_profile_id_rejects(tmp_path):
    bundle = _write_bundle(tmp_path, assurance_profile="ultra-mega-assurance")
    verdict = BundleVerifier().verify(bundle)
    assert verdict.state is VerdictState.REJECT
    assert PROFILE_DECLARED_UNKNOWN in _reason_codes(verdict)


def test_declaration_site_conflict_rejects(tmp_path):
    """Top-level and causal_chain.layer_a disagree → REJECT (a producer must
    not split-brain the claim across sites)."""
    bundle = _write_bundle(
        tmp_path,
        assurance_profile="regulated-high-assurance",
        layer_a_profile="production-standard",
    )
    verdict = BundleVerifier().verify(bundle)
    assert verdict.state is VerdictState.REJECT
    assert PROFILE_DECLARATION_CONFLICT in _reason_codes(verdict)


def test_nested_only_declaration_cannot_dodge_the_guard(tmp_path):
    """A label declared ONLY inside causal_chain.layer_a is still a label —
    the guard's canonical reader joins all declaration sites."""
    bundle = _write_bundle(tmp_path, layer_a_profile="regulated-high-assurance")
    verdict = BundleVerifier().verify(bundle)
    assert verdict.state is VerdictState.ERROR
    assert PROFILE_DECLARED_BUT_UNGRADED in _details(verdict)


def test_malformed_declaration_rejects(tmp_path):
    """A non-string declaration must REJECT, never silently coerce to absent
    (the pilot's old behavior). The PARSE boundary (_TOP_LEVEL_FIELD_SHAPES)
    owns this on the file path — the guard's own conflict branch is
    defense-in-depth for directly-constructed manifests (unit-covered in
    test_effective_declared_profile_reader)."""
    bundle_dir = _write_bundle(tmp_path)
    manifest = json.loads((bundle_dir / "manifest.json").read_text())
    manifest["assurance_profile"] = {"nested": "trick"}
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest))
    verdict = BundleVerifier().verify(bundle_dir)
    assert verdict.state is VerdictState.REJECT
    assert "malformed_manifest" in _reason_codes(verdict)


# --- grading coverage --------------------------------------------------------


def test_wired_grader_lifts_the_label_to_ok_with_disclosure(tmp_path):
    bundle = _write_bundle(tmp_path, assurance_profile="regulated-high-assurance")
    grader = _StubGrader("regulated-high-assurance", "any-fingerprint")
    verdict = BundleVerifier(plugins=[grader]).verify(bundle)
    assert verdict.state is VerdictState.OK
    assert any(
        "assurance_profile" in d and "graded" in d
        for d in verdict.completeness.disclosures
    )
    # No floor configured → the verdict face says so.
    assert any("no verifier-held floor" in d for d in verdict.completeness.disclosures)


def test_grader_for_a_different_profile_does_not_cover(tmp_path):
    bundle = _write_bundle(tmp_path, assurance_profile="regulated-high-assurance")
    grader = _StubGrader("production-standard", "any-fingerprint")
    verdict = BundleVerifier(plugins=[grader]).verify(bundle)
    assert verdict.state is VerdictState.ERROR
    assert PROFILE_DECLARED_BUT_UNGRADED in _details(verdict)


# --- verifier-held floor ------------------------------------------------------


def test_below_floor_declaration_rejects(tmp_path):
    bundle = _write_bundle(tmp_path, assurance_profile="offline-auditor-minimal")
    verdict = BundleVerifier(profile_floor="regulated-high-assurance").verify(bundle)
    assert verdict.state is VerdictState.REJECT
    assert PROFILE_DECLARED_BELOW_PINNED_FLOOR in _reason_codes(verdict)


def test_unknown_floor_fails_at_construction():
    with pytest.raises(ValueError, match="profile_floor"):
        BundleVerifier(profile_floor="not-a-profile")


# --- verifier-held completeness policy -----------------------------------------


def _policy_requiring_layer_a(*, obligations: bool) -> CompletenessPolicy:
    """Three-profile lattice where regulated-high-assurance requires
    causal_chain + layer_a (optionally with a non-empty obligation)."""
    required = frozenset({"causal_chain", "layer_a"})
    ob = {
        "causal_chain": ObligationLattice(),
        "layer_a": (
            ObligationLattice(required_checks=frozenset({"event_ids_unique"}))
            if obligations
            else ObligationLattice()
        ),
    }
    return CompletenessPolicy(
        profiles={
            "offline-auditor-minimal": Profile("offline-auditor-minimal"),
            "production-standard": Profile("production-standard"),
            "regulated-high-assurance": Profile(
                "regulated-high-assurance",
                required_structures=required,
                obligations=ob,
            ),
        },
        order_edges=frozenset(
            {
                ("regulated-high-assurance", "production-standard"),
                ("production-standard", "offline-auditor-minimal"),
            }
        ),
        policy_epoch=1,
    )


def test_required_structure_absent_rejects(tmp_path):
    policy = _policy_requiring_layer_a(obligations=False)
    bundle = _write_bundle(tmp_path, assurance_profile="regulated-high-assurance")
    verdict = BundleVerifier(
        completeness_policy=policy, profile_floor="regulated-high-assurance"
    ).verify(bundle)
    assert verdict.state is VerdictState.REJECT
    assert PROFILE_REQUIRED_STRUCTURE_ABSENT in _reason_codes(verdict)


def test_structures_present_empty_obligations_core_grades_green(tmp_path):
    """Admission + presence are CORE grading; with all-empty obligations no
    plugin is owed and the verdict is OK with the policy fingerprint on the
    face."""
    policy = _policy_requiring_layer_a(obligations=False)
    bundle = _write_bundle(
        tmp_path,
        assurance_profile="regulated-high-assurance",
        layer_a_profile="regulated-high-assurance",
    )
    verdict = BundleVerifier(
        completeness_policy=policy,
        profile_floor="regulated-high-assurance",
        plugins=[_CausalChainCoverageStub()],
    ).verify(bundle)
    assert verdict.state is VerdictState.OK
    fp = policy_fingerprint(policy)
    assert any(fp[:12] in d for d in verdict.completeness.disclosures)


def test_nonempty_obligations_require_a_fingerprint_matched_grader(tmp_path):
    policy = _policy_requiring_layer_a(obligations=True)
    bundle = _write_bundle(
        tmp_path,
        assurance_profile="regulated-high-assurance",
        layer_a_profile="regulated-high-assurance",
    )
    base_kwargs = dict(
        completeness_policy=policy, profile_floor="regulated-high-assurance"
    )
    # No grader → could-not-conclude.
    verdict = BundleVerifier(**base_kwargs).verify(bundle)
    assert verdict.state is VerdictState.ERROR
    assert PROFILE_DECLARED_BUT_UNGRADED in _details(verdict)
    # Grader against a DIFFERENT policy → still could-not-conclude
    # (a permissive grader cannot satisfy a strict relying-party config).
    wrong = _StubGrader("regulated-high-assurance", "0" * 64)
    verdict = BundleVerifier(plugins=[wrong], **base_kwargs).verify(bundle)
    assert verdict.state is VerdictState.ERROR
    assert PROFILE_DECLARED_BUT_UNGRADED in _details(verdict)
    # Grader against THE policy → OK (with the layer_a structure's coverage
    # discharged by the coverage stub, as a real high-assurance bundle would).
    right = _StubGrader("regulated-high-assurance", policy_fingerprint(policy))
    verdict = BundleVerifier(
        plugins=[right, _CausalChainCoverageStub()], **base_kwargs
    ).verify(bundle)
    assert verdict.state is VerdictState.OK


def test_policy_requiring_unmapped_structure_fails_at_construction():
    policy = CompletenessPolicy(
        profiles={
            "offline-auditor-minimal": Profile("offline-auditor-minimal"),
            "production-standard": Profile("production-standard"),
            "regulated-high-assurance": Profile(
                "regulated-high-assurance",
                required_structures=frozenset({"no_such_structure"}),
                obligations={"no_such_structure": ObligationLattice()},
            ),
        },
        order_edges=frozenset(
            {
                ("regulated-high-assurance", "production-standard"),
                ("production-standard", "offline-auditor-minimal"),
            }
        ),
    )
    with pytest.raises(ValueError, match="no canonical manifest path"):
        BundleVerifier(completeness_policy=policy)


# --- canonical reader unit coverage -------------------------------------------


def test_effective_declared_profile_reader():
    class _M:
        assurance_profile = None
        causal_chain = None

    m = _M()
    assert effective_declared_profile(m) == (None, None)
    m.assurance_profile = "production-standard"
    assert effective_declared_profile(m) == ("production-standard", None)
    m.causal_chain = {"layer_a": {"assurance_profile": "production-standard"}}
    assert effective_declared_profile(m) == ("production-standard", None)
    m.causal_chain = {"layer_a": {"assurance_profile": "offline-auditor-minimal"}}
    declared, conflict = effective_declared_profile(m)
    assert declared is None and conflict is not None
    m.assurance_profile = 7
    declared, conflict = effective_declared_profile(m)
    assert declared is None and conflict is not None


def test_builtin_lattice_is_shape_only():
    """Core's builtin lattice must never carry policy content: empty R(P)
    everywhere (what a label REQUIRES is relying-party config)."""
    lattice = builtin_profile_lattice()
    assert set(lattice.profiles) == {
        "offline-auditor-minimal",
        "production-standard",
        "regulated-high-assurance",
    }
    for profile in lattice.profiles.values():
        assert profile.required_structures == frozenset()
