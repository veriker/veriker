"""Sub-key coverage-disposition ratchet — every open-namespace manifest field
has a LIVE ``present − verified == ∅`` coverage guard on the verdict path
(2026-06-23).

This is ``test_manifest_field_disposition_ratchet`` pushed one level down. That
ratchet closes the orphan class at TOP-LEVEL field granularity: a new
``BundleManifest`` field cannot ship without naming the step that enforces it.
But several of those fields are OPEN-NAMESPACE dicts whose *sub-keys* carry the
claims — ``causal_chain`` (S19 sub-streams + pilot-custom chains),
``dispatch_records``/``aggregate_stamp`` (stamp claims), ``fragment_anchors``.
For those, "a step runs" is NOT the guarantee; the guarantee is the UNIVERSAL
coverage identity ``present_subkeys − verified_subkeys == ∅`` (else
could-not-conclude), so a sub-key nobody verified fails closed instead of
riding green.

That coverage discipline already exists per-namespace and is behaviorally
tested in isolation (test_causal_chain_coverage / test_cross_host_edge_coverage
/ test_layer_a_event_obligation_coverage / test_fragment_anchor_coverage /
test_stamp_claims_coverage_guard). What did NOT exist is the META property —
the ``assurance_profile`` failure mode one level out: nothing enumerated the
coverage namespaces in ONE place and proved each guard is actually wired into
the verdict path, and nothing forced a NEW verdict-path step to declare whether
it is a sub-key coverage guard. A coverage guard silently dropped from
``_verify_in_dir``, or a new open-namespace field shipped with only a
shape-validation step, would not be caught by any single test.

Three assertions close that:

  1. LIVENESS — every guard named in ``_COVERAGE_NAMESPACE_GUARDS`` exists on
     ``BundleVerifier`` AND is invoked in ``_verify_in_dir`` source. A coverage
     guard the verdict path never calls is an orphan, not a guarantee.
  2. KIND TEETH — each named guard's source carries the universal-coverage
     signature (``present`` / ``verified`` / ``uncovered`` / the
     ``VERIFIER_INCOMPLETE`` could-not-conclude leg). A field cannot be
     registered as sub-key-covered by pointing at a shape-only or floor step.
  3. PARTITION CLOSURE — the set of ``_step_*`` methods invoked in
     ``_verify_in_dir`` is EXACTLY the registry's guards ∪ the explicit
     non-coverage exclusion set. A new verdict-path step (or a renamed one)
     fails until it is classified here, in this diff — the same diff-is-the-
     disclosure forcing function the top-level disposition ratchet uses.
"""

from __future__ import annotations

import inspect
import re

from audit_bundle.verifier import BundleVerifier

# --- the coverage-namespace registry -----------------------------------------
#
# manifest open-namespace (or nested namespace) -> the verdict-path step that
# enforces ``present_subkeys − verified_subkeys == ∅`` over it. These are the
# guards whose absence would let an unguarded sub-key ride a green verdict.
_COVERAGE_NAMESPACE_GUARDS: dict[str, str] = {
    "causal_chain (whole open namespace)": "_step_causal_chain_coverage_guard",
    "causal_chain.cross_host_authenticators (edge-level)": "_step_cross_host_guard",
    "causal_chain.layer_a events (per-event obligations)": "_step_layer_a_event_obligation_guard",
    "fragment_anchors (fragments.attestable)": "_step_fragment_anchor_guard",
    "dispatch_records + aggregate_stamp (stamp claims)": "_step_stamp_claims_guard",
}

# Verdict-path ``_step_*`` methods that are NOT sub-key coverage guards. Listed
# explicitly so the partition is CLOSED: a new step forces an entry here or in
# the registry above (diff-is-the-disclosure). One-line rationale each.
_NON_SUBKEY_COVERAGE_STEPS: dict[str, str] = {
    "_step_file_integrity": "per-FILE byte-equality (file space, not a sub-key namespace)",
    "_step_spec_sha_pinning": "spec/ hash pinning (file space)",
    "_step_cross_refs": "cross-ref shape/resolution, not present−verified coverage",
    "_step_typed_check_plugins": "runs + reconciles plugins; not a namespace coverage fold",
    "_step_deep_manifest_validation": "structural shape validation of nested fields",
    "_step_spec_pinned_dispatch": "re-derivation from anchored spec (output space)",
    "_step_rederivation_pack_guard": "present−verified but over re_derive/*_pack FILES, not manifest sub-keys",
    "_step_extension_receipts": "receipt-verifier dispatch by kind, not a sub-key fold",
    "_step_assurance_profile_guard": "assurance FLOOR (downgrade gate), not sub-key coverage",
}

# Tokens that together mark a ``present − verified == ∅`` universal-coverage
# guard (verified live across all five guards 2026-06-23). A shape-only or floor
# step does not carry this full signature.
_COVERAGE_SIGNATURE = ("present", "verified", "uncovered", "VERIFIER_INCOMPLETE")

_VERIFY_IN_DIR_SRC = inspect.getsource(BundleVerifier._verify_in_dir)


def _verdict_path_step_calls() -> set[str]:
    """Every ``self._step_<name>(`` invoked in ``_verify_in_dir`` source."""
    return set(re.findall(r"self\.(_step_[a-z_]+)\(", _VERIFY_IN_DIR_SRC))


def test_coverage_guards_exist_and_are_live_on_the_verdict_path():
    for namespace, symbol in sorted(_COVERAGE_NAMESPACE_GUARDS.items()):
        assert hasattr(BundleVerifier, symbol), (
            f"{namespace}: coverage guard {symbol!r} does not exist on BundleVerifier"
        )
        assert symbol in _VERIFY_IN_DIR_SRC, (
            f"{namespace}: coverage guard {symbol!r} exists but is NOT invoked "
            "in _verify_in_dir — a coverage guard the verdict path never calls "
            "is an orphan, not a guarantee (the assurance_profile failure mode)."
        )


def test_registered_guards_are_universal_coverage_kind():
    """A guard registered as sub-key coverage must actually fold
    present−verified, not merely shape-check the namespace."""
    for namespace, symbol in sorted(_COVERAGE_NAMESPACE_GUARDS.items()):
        src = inspect.getsource(getattr(BundleVerifier, symbol))
        missing = [tok for tok in _COVERAGE_SIGNATURE if tok not in src]
        assert not missing, (
            f"{namespace}: {symbol!r} is registered as a sub-key coverage guard "
            f"but its source lacks the universal-coverage signature {missing} — "
            "a coverage namespace cannot be discharged by a shape-only / floor "
            "step (else a forged sub-key rides green, the orphan-key class)."
        )


def test_verdict_path_step_partition_is_closed():
    """Every verdict-path step is classified: a sub-key coverage guard, or an
    explicit non-coverage exclusion. A new/renamed step fails until placed."""
    invoked = _verdict_path_step_calls()
    classified = set(_COVERAGE_NAMESPACE_GUARDS.values()) | set(
        _NON_SUBKEY_COVERAGE_STEPS
    )

    unclassified = invoked - classified
    assert not unclassified, (
        f"verdict-path step(s) not classified: {sorted(unclassified)}. Add each "
        "to _COVERAGE_NAMESPACE_GUARDS (if it folds present−verified over an "
        "open sub-key namespace) or to _NON_SUBKEY_COVERAGE_STEPS with a "
        "one-line rationale — in THIS diff, so the classification is disclosed."
    )

    stale = classified - invoked
    assert not stale, (
        f"classified step(s) no longer invoked in _verify_in_dir: "
        f"{sorted(stale)}. Remove the stale entry — a registry/exclusion that "
        "names a dead step hides whether the verdict path still enforces it."
    )

    overlap = set(_COVERAGE_NAMESPACE_GUARDS.values()) & set(_NON_SUBKEY_COVERAGE_STEPS)
    assert not overlap, (
        f"step(s) both registered as coverage AND excluded: {sorted(overlap)} — "
        "the partition must be disjoint."
    )


def test_non_coverage_exclusions_are_real_methods():
    """No stale exclusion entry: every excluded name is a real BundleVerifier
    step (mirrors the top-level ratchet's stale-entry check)."""
    for symbol in sorted(_NON_SUBKEY_COVERAGE_STEPS):
        assert hasattr(BundleVerifier, symbol), (
            f"_NON_SUBKEY_COVERAGE_STEPS names {symbol!r} which is not a "
            "BundleVerifier method — remove the stale entry."
        )
