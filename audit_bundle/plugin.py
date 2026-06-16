"""audit_bundle/plugin.py — PEP 544 Protocol contract for typed-check plugins.

Implements the audit-bundle contract's typed-check plugin component.
Protocol only — no ABC — using field mirroring, not import coupling.

Plugin tracking is two-surface:
  - bundle_manifest._TYPED_CHECK_REGISTRY  — set of plugin names; plugins
    self-register via register_typed_check() at import; consulted by
    validate_manifest() §5.
  - BundleVerifier._plugins                — explicit list of plugin
    instances passed to the verifier constructor; consulted by verify().
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# PluginResult
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PluginResult:
    ok: bool
    reason_code: str  # PASS or named failure (e.g. SPEC_SHA_MISMATCH)
    detail: str
    files_audited: tuple[str, ...]
    # Clean-ERROR contract (BundleVerifier.verify() reads this via getattr):
    # incomplete=True means the plugin ran cleanly but COULD NOT CONCLUDE — a
    # present-but-unverified claim (e.g. a re-derivation pack present but not
    # executed in safe mode). It is NEITHER a REJECT (artifact not shown bad)
    # NOR a crash. verify() records it as a clean-ERROR leg (could-not-conclude,
    # exit 2), so a library consumer does not read OK over an unverified claim.
    # Checked BEFORE .ok, so an incomplete result's ok value is not consulted.
    incomplete: bool = False
    # Per-edge cross-host coverage (verdict-divergence follow-up, ratified
    # 2026-06-10): the set of cross_host_authenticators edge keys
    # (audit_bundle.cross_host_identity.cross_host_edge_key) this plugin actually
    # verified. BundleVerifier accumulates the union across plugins and asserts
    # present_edge_keys − verified == ∅; a non-empty difference fails closed
    # (could-not-conclude). Empty for plugins that do not verify cross-host edges.
    # frozenset is immutable, so it is a safe dataclass default. SUPERSEDES the
    # coarse boolean `verifies_cross_host_authenticators` marker (which proved
    # presence-of-a-verifier, not coverage-of-these-edges).
    verified_cross_host_edges: frozenset[str] = frozenset()
    # Per-anchor fragment-attestation coverage (RES-06 follow-up, 2026-06-11 —
    # same discipline as verified_cross_host_edges): the set of fragment-anchor
    # content keys (audit_bundle.fragments.attestable.fragment_anchor_key) this
    # plugin actually re-derived and matched against the frozen snapshot.
    # BundleVerifier accumulates the union and asserts present ATTESTABLE
    # anchor keys − verified == ∅; a non-empty difference is could-not-conclude
    # (clean-ERROR). Closes the plugin-less laundering hole: a library consumer
    # running BundleVerifier() with no plugins no longer reads OK over a bundle
    # whose quote claims (content_selector.exact) were never re-derived.
    # Pure-locator anchors are not attestable and impose no obligation.
    verified_fragment_anchors: frozenset[str] = frozenset()
    # Per-record dispatch-record coverage (stamp-claims follow-up, 2026-06-12 —
    # same discipline as the two channels above, 5th instance of the orphaned-
    # enforcement class): the set of dispatch_records content keys
    # (audit_bundle.stamp_claims.dispatch_record_key) this plugin actually
    # audited under the C15 well-formedness contract. BundleVerifier
    # accumulates the union and asserts present record keys − verified == ∅;
    # a non-empty difference is could-not-conclude (clean-ERROR). Distinct
    # from verified_stamp_claims below — coverage is PER-CONTRACT, so wiring
    # only the C14 plugin cannot launder the C15 obligation or vice versa
    # (tribunal 2026-06-12, Q1 unanimous).
    verified_dispatch_records: frozenset[str] = frozenset()
    # Whole-claim C14 lattice coverage (same follow-up): the singleton set of
    # stamp-claim keys (audit_bundle.stamp_claims.stamp_claim_key — binds the
    # aggregate_stamp value AND the full dispatch_records array) this plugin
    # evaluated under the C14 stamp-lattice contract. The guard asserts the
    # present bundle's claim key is in the union; absence is could-not-conclude.
    # Closes the plugin-less laundering hole: BundleVerifier() with no plugins
    # no longer reads OK over a forged "Verifier-set, never dispatcher-trusted"
    # aggregate_stamp nothing checked.
    verified_stamp_claims: frozenset[str] = frozenset()
    # Honest residuals (assurance-labeling follow-up, 2026-06-10): disclosure
    # strings a PASSING check must still surface machine-readably — guarantees
    # the green result does NOT include (e.g. C19's v0.3 reference-implementation
    # limitation; shape-checked-only edge timestamps). BundleVerifier.verify()
    # accumulates these (getattr, default ()) into Completeness.disclosures —
    # the verdict-face channel the conservation gate and append-only floor
    # already use — so the residual reaches LIBRARY consumers, not just the CLI
    # detail printout. Surfacing only: contributes to no pass/fail decision.
    # Prefix idiom: "<check_name>: <residual>".
    disclosures: tuple[str, ...] = ()
    # Assurance-profile grading coverage (label-downgrade fix, 2026-06-12 —
    # the cross-host/fragment-anchor discipline applied to the CC-2b D1
    # label): the set of (profile_id, policy_fingerprint) pairs this plugin
    # actually GRADED — floor admission + required-structure walk + O(S)
    # obligations against the named policy (fingerprint =
    # profile_completeness_policy.policy_fingerprint). BundleVerifier
    # accumulates the union and _step_assurance_profile_guard asserts the
    # DECLARED profile is in it (fingerprint-matched when the verifier holds
    # its own policy); a declared-but-ungraded label is could-not-conclude
    # (clean-ERROR), never a silent OK. The pair (not a bare ID) is the
    # binding: a permissive grader cannot satisfy a strict relying-party
    # config. Empty for plugins that do not grade profiles.
    graded_assurance_profiles: frozenset[tuple[str, str]] = frozenset()
    # Per-sub-key causal_chain coverage (BLOCK-02 follow-up, 2026-06-12 — the
    # cross-host/fragment-anchor/stamp discipline applied to the causal_chain
    # discriminated union): the set of sub-key content keys
    # (audit_bundle.causal_chain_coverage.causal_chain_subkey_key) this plugin
    # actually verified — e.g. a layer_a SCITT-counter re-derivation reports
    # {causal_chain_subkey_key("layer_a", layer_a)}, a layer_b_anchors
    # trusted-time re-derivation reports {causal_chain_subkey_key(
    # "layer_b_anchors", anchors)}. BundleVerifier accumulates the union and
    # _step_causal_chain_coverage_guard asserts present accountable sub-key keys
    # − verified == ∅; a non-empty difference is could-not-conclude (clean-
    # ERROR). Closes the plugin-less laundering hole: a fabricated layer_a /
    # layer_b_anchors audit DAG no longer rides a GREEN verdict that nothing
    # shape-checked or cryptographically verified. cross_host_authenticators is
    # NOT reported here (verified edge-level via verified_cross_host_edges).
    verified_causal_chain_subkeys: frozenset[str] = frozenset()
    # Per-event obligation coverage WITHIN layer_a (GPT redteam BLOCK-01,
    # 2026-06-12 — the cross-host/fragment-anchor/stamp discipline applied one
    # level FINER than verified_causal_chain_subkeys: at event-FIELD, not
    # sub-key, granularity): the set of obligation keys
    # (audit_bundle.causal_chain_coverage.event_obligation_key) this plugin
    # actually discharged. A layer_a event carrying event_kind=="key_rotation",
    # a timestamp_evidence field, or a cross_host_edge field asserts an
    # obligation the GENERIC verify_bundle_layer_a pipeline (SCITT/chain/Merkle/
    # HMAC) does NOT evaluate — admitted by validate_event_keys_str yet never
    # recomputed. A dedicated verifier (e.g. the eidas S19d rotation check)
    # reports {event_obligation_key(ev, "key_rotation")} per rotation event it
    # verifies. BundleVerifier accumulates the union and
    # _step_layer_a_event_obligation_guard asserts present obligation keys −
    # verified == ∅; a non-empty difference is could-not-conclude (clean-ERROR).
    # Closes the coarse-coverage laundering hole: the single
    # subkey_coverage("layer_a") key no longer papers over an unauthorized key
    # transition / forged trusted-time / unbound cross-host edge inside layer_a.
    # Empty for the generic counter plugin (it verifies none of these).
    verified_layer_a_event_obligations: frozenset[str] = frozenset()


# ---------------------------------------------------------------------------
# TypedCheck Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class TypedCheck(Protocol):
    name: str  # plugin class attribute
    applies_to_files: frozenset[str]  # paths inside bundle this plugin owns

    def check(self, bundle_dir: Path, manifest) -> PluginResult: ...


# ---------------------------------------------------------------------------
# ReDerivationPrimitive — Axis-2 recompute/compare split (SPEC_PINNED_DISPATCH
# §3.3). ADDITIVE to TypedCheck.check()->PluginResult, NOT a replacement.
#
# A TypedCheck fuses recompute + compare and returns a boolean PluginResult.
# A ReDerivationPrimitive does ONLY the recompute and returns the recomputed
# VALUE; a separate comparator (audit_bundle/rederivation/comparators.py)
# decides agreement against the producer's claimed value. The two halves of a
# resolved binding both run verifier-side and both resolve from the SHA-pinned,
# auditor-anchored spec — so the split costs zero trust (Axis-2 re-derivation).
#
# Primitives are verifier-DISTRIBUTION code, registry-resident, populated at
# import (audit_bundle/rederivation/registry.py). They are NEVER bundle-supplied
# (§C5/§C6, V8 [0010]). The in-bundle re-derivation pack is the DATA the
# primitive reads (inputs + SHA-pinned config), consistent with [0010]'s
# "the pack is data, not code."
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RecomputedValue:
    """The value a ReDerivationPrimitive recomputed for one claimed output.

    `value` is a plain JSON-comparable Python object (scalar / str / list /
    dict) — whatever shape the bound comparator-kind expects. The primitive
    does NOT compare; it only recomputes. `detail` is a human-readable note
    surfaced in failure messages.
    """

    value: object
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ParsedInputs:
    """Read-only handle a primitive uses to read bundle DATA during recompute.

    Carries the unpacked bundle directory only. A primitive reads its inputs/
    and SHA-pinned spec/ config from here — it executes no bundle-supplied
    code (the bundle carries data, not code; [0010]).
    """

    bundle_dir: Path


@runtime_checkable
class ReDerivationPrimitive(Protocol):
    primitive_id: str  # registry key; matches spec binding

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        """Recompute the claimed output's value from bundle DATA.

        `pack_section` carries the per-output dispatch context:
            {"output_id": str, "type": str, "params": dict, "claimed": object}
        where `params` is the comparator params from the pinned spec and
        `claimed` is the producer's stated value (read by the verifier from
        outputs/<output_id>.json). The primitive returns the RE-derived value;
        the verifier's comparator decides agreement. Pure recompute, no compare.
        """
        ...
