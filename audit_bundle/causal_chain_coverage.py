"""audit_bundle/causal_chain_coverage.py — universal coverage identity for the
``causal_chain`` field.

``manifest.causal_chain`` is an OPEN namespace dict. Most sub-keys are owned by
an S19 substrate sub-stream and carry a verifier-checkable crypto claim:

  * ``layer_a``                  — S19a SCITT-bound monotonic counter / event DAG
  * ``layer_b_anchors``          — S19c selective trusted-time anchors (TSA/Roughtime/BLS)
  * ``counter_chain``            — S19 counter sub-chain (reserved)
  * ``cross_host_edges``         — S19 cross-host edge set (reserved)
  * ``cross_host_authenticators``— S19b cross-host receipts (verified EDGE-LEVEL by
                                   BundleVerifier._step_cross_host_guard)

…but a pilot may also place its OWN custom chain here (e.g. bell_residency emits
``{bundle_id, events, note}`` — a synthetic HMAC event chain its own re-derivation
check verifies). The field is therefore not a closed discriminated union, so the
coverage invariant is UNIVERSAL rather than allowlist-based:

  every PRESENT sub-key must be reported VERIFIED by some wired plugin, or the
  verdict is could-not-conclude (clean-ERROR) — present − verified == ∅.

This is the same "present − verified == ∅" discipline already in force for
cross-host edges (``cross_host_identity``), fragment anchors
(``fragments.attestable``), and stamp claims (``stamp_claims``), generalized from
ONE causal_chain sub-key (cross_host_authenticators) to the WHOLE field — so the
class cannot regrow on the next sub-key nobody guarded. A forged ``layer_a`` /
``layer_b_anchors`` / an unknown future sub-key with no verifier all fail closed
identically; coverage is the ratchet, not a per-name allowlist.

``cross_host_authenticators`` is EXCLUDED from this module's name-level coverage:
it is verified at the finer EDGE level by the dedicated cross-host guard, which
keys per authenticator edge. Requiring a second coarser name-level proof would be
double jeopardy that breaks bundles already covered edge-level. Its key is the
ONLY name this module ever skips.

Stdlib only (keeps the core verify() path import-light).
"""

from __future__ import annotations

import hashlib
import json

# Sub-keys whose coverage obligation is discharged by a finer-grained dedicated
# guard, NOT by this module's name-level accounting.
EDGE_LEVEL_SUBKEYS: frozenset[str] = frozenset({"cross_host_authenticators"})

# The substrate (S19) sub-keys this codebase ships a verifier path for. NOT used
# to gate the runtime guard (coverage is universal) — kept as the documented
# substrate registry and pinned by test_causal_chain_coverage against
# profile_completeness_policy.STRUCTURE_PATHS so a new substrate sub-key cannot be
# registered for assurance-profile completeness without also being a sub-key the
# coverage discipline reasons about.
KNOWN_SUBSTRATE_SUBKEYS: frozenset[str] = frozenset(
    {
        "layer_a",
        "layer_b_anchors",
        "counter_chain",
        "cross_host_edges",
        "cross_host_authenticators",
    }
)


def _is_present(value: object) -> bool:
    """A sub-key asserts a claim only when it carries non-empty content.

    None (absent) and an empty dict/list/str (declared-but-says-nothing) are
    inert — mirrors the cross-host guard's empty-edge-list early return, so this
    guard rejects nothing a legacy/no-claim bundle legitimately carries.
    """
    if value is None:
        return False
    if isinstance(value, (dict, list, str)) and len(value) == 0:
        return False
    return True


def _canonical(value: object) -> str | None:
    """Canonical JSON for a parsed-manifest value, or None when not
    JSON-serializable (directly-constructed manifest carrying a non-JSON object —
    uncoverable, fails closed at the guard)."""
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
    except (TypeError, ValueError):
        return None


def causal_chain_subkey_key(name: str, value: object) -> str | None:
    """Canonical content key for one present causal_chain sub-key.

    ``"cc:" + name + ":" + sha256(name ‖ canonical JSON of value)``. The name is
    bound into the hash so coverage of ``layer_a`` can never be satisfied by a
    plugin that verified ``layer_b_anchors``. None when the value is not
    canonically serializable (uncoverable → fails closed)."""
    canonical = _canonical(value)
    if canonical is None:
        return None
    digest = hashlib.sha256(f"{name}\x00{canonical}".encode("utf-8")).hexdigest()
    return f"cc:{name}:{digest}"


def subkey_coverage(name: str, value: object) -> frozenset[str]:
    """Coverage key set a plugin reports for ONE sub-key it verified.

    Empty when the sub-key is absent / empty (no claim to cover) or unkeyable.
    Plugin-side convenience mirroring the guard-side ``accountable_causal_chain_keys``
    so a verifying plugin reports EXACTLY the key the guard accounts for."""
    if not _is_present(value):
        return frozenset()
    key = causal_chain_subkey_key(name, value)
    return frozenset({key}) if key is not None else frozenset()


def accountable_causal_chain_keys(
    causal_chain: object,
) -> tuple[frozenset[str], int]:
    """Coverage keys for EVERY present sub-key this module accounts for, plus a
    count of present-but-unkeyable ones.

    Returns ``(present_keys, n_unkeyable)``. ``cross_host_authenticators`` is the
    only excluded name (discharged edge-level). A present sub-key whose value is
    not canonically serializable contributes to ``n_unkeyable`` (uncoverable → the
    guard fails closed) rather than to ``present_keys``.
    """
    if not isinstance(causal_chain, dict):
        return frozenset(), 0
    keys: set[str] = set()
    n_unkeyable = 0
    for name, value in causal_chain.items():
        if name in EDGE_LEVEL_SUBKEYS:
            continue
        if not _is_present(value):
            continue
        key = causal_chain_subkey_key(name, value)
        if key is None:
            n_unkeyable += 1
        else:
            keys.add(key)
    return frozenset(keys), n_unkeyable


# ---------------------------------------------------------------------------
# Per-event obligation coverage WITHIN layer_a (event-field granularity).
#
# The coverage discipline above closes ``causal_chain`` at SUB-KEY granularity:
# a present ``layer_a`` is covered if some plugin reports ``subkey_coverage(
# "layer_a")``. But ``layer_a.events[*]`` carry SEMANTIC OBLIGATION fields whose
# verification the generic SCITT-receipt / hash-chain / Merkle / HMAC-signature
# pipeline (``verify_bundle_layer_a``) does NOT perform — admitted by the
# str-key gate (``validate_event_keys_str``) yet never recomputed:
#
#   * ``event_kind == "key_rotation"`` → rotation authorization (old/new
#     co-signatures, pre-commit window, emergency offline-root, validity windows)
#   * ``"timestamp_evidence"`` present → per-event TSA/Roughtime trusted-time proof
#   * ``"cross_host_edge"``    present → per-event cross-host binding
#
# The single coarse ``subkey_coverage("layer_a")`` key papered over ALL THREE
# (GPT redteam BLOCK-01, 2026-06-12 — found via ``key_rotation``; the
# ``timestamp_evidence`` and ``cross_host_edge`` siblings surfaced in the
# systemic sweep). This is the SAME ``present − verified == ∅`` discipline
# pushed one level finer: each present obligation is content-keyed; a dedicated
# verifier reports the keys it discharged in
# ``PluginResult.verified_layer_a_event_obligations``; the verify() guard
# asserts ``present − verified == ∅`` or clean-ERROR. The generic pipeline
# reports NONE of these (it does not verify them), so a bare-library consumer
# fails closed exactly as intended.
#
# The obligation registry is the forcing function the bare docstring deferral
# lacked: a new admitted event field that carries a dedicated-verifier
# obligation must be registered here (pinned by
# ``test_layer_a_event_obligation_coverage_ratchet``) or the admitted-keys vs
# obligation-accounting sets diverge and the test fails.
# ---------------------------------------------------------------------------

# Obligation tags = event surfaces a dedicated verifier (NOT the generic
# pipeline) must discharge. BOTH the guard (PRESENT) and a discharging plugin
# (VERIFIED) derive their keys from this same set keyed on the same tag, so the
# two sides can never name different keys for one obligation.
LAYER_A_EVENT_OBLIGATION_TAGS: frozenset[str] = frozenset(
    {"key_rotation", "timestamp_evidence", "cross_host_edge"}
)


def event_obligation_tags(event: object) -> frozenset[str]:
    """The obligation tags ONE str-keyed (live JSON-decoded) event carries.

    Subset of ``LAYER_A_EVENT_OBLIGATION_TAGS``; empty for a generic event with
    no obligation field. ``key_rotation`` keys off ``event_kind``; the other two
    key off the PRESENCE (non-empty) of their like-named field, on ANY event
    kind — a generic event can smuggle an unverified trusted-time or cross-host
    claim, so the obligation attaches wherever the field appears, not only to
    rotation events."""
    if not isinstance(event, dict):
        return frozenset()
    tags: set[str] = set()
    if event.get("event_kind") == "key_rotation":
        tags.add("key_rotation")
    if _is_present(event.get("timestamp_evidence")):
        tags.add("timestamp_evidence")
    if _is_present(event.get("cross_host_edge")):
        tags.add("cross_host_edge")
    return frozenset(tags)


def event_obligation_key(event: object, tag: str) -> str | None:
    """Canonical content key for ONE (event, obligation-tag).

    ``"la-ob:" + tag + ":" + sha256(tag ‖ canonical JSON of event)``. The tag is
    bound into the hash so discharging the rotation obligation can never satisfy
    the trusted-time obligation on the SAME event bytes. None when the event is
    not canonically serializable (uncoverable → the guard counts it as unkeyable
    and fails closed)."""
    canonical = _canonical(event)
    if canonical is None:
        return None
    digest = hashlib.sha256(f"{tag}\x00{canonical}".encode("utf-8")).hexdigest()
    return f"la-ob:{tag}:{digest}"


def event_obligation_coverage(event: object, tag: str) -> frozenset[str]:
    """Plugin-side convenience: the key a verifier reports for the ONE (event,
    tag) obligation it discharged. Empty when the event does not actually carry
    ``tag`` (a plugin cannot report coverage for an obligation not present) or is
    unkeyable — mirrors ``subkey_coverage`` for the sub-key path."""
    if tag not in event_obligation_tags(event):
        return frozenset()
    key = event_obligation_key(event, tag)
    return frozenset({key}) if key is not None else frozenset()


def layer_a_event_obligation_keys(layer_a: object) -> tuple[frozenset[str], int]:
    """Every PRESENT per-event obligation key under ``layer_a``, plus a count of
    present-but-unkeyable ones (guard side).

    Returns ``(present_keys, n_unkeyable)``. A non-dict ``layer_a`` or non-list
    ``events`` asserts no obligation (the structural shape validator already
    rejects malformed layer_a upstream; this is defense-in-depth and a genuine
    no-events bundle stays inert)."""
    if not isinstance(layer_a, dict):
        return frozenset(), 0
    events = layer_a.get("events")
    if not isinstance(events, list):
        return frozenset(), 0
    keys: set[str] = set()
    n_unkeyable = 0
    for ev in events:
        for tag in event_obligation_tags(ev):
            key = event_obligation_key(ev, tag)
            if key is None:
                n_unkeyable += 1
            else:
                keys.add(key)
    return frozenset(keys), n_unkeyable
