"""Tests for the per-event layer_a obligation guard (GPT redteam BLOCK-01).

The causal_chain coverage guard (BLOCK-02) closes ``causal_chain`` at SUB-KEY
granularity: a present ``layer_a`` is covered when some plugin reports
``subkey_coverage("layer_a")``. But a ``layer_a`` event can carry a SEMANTIC
obligation the generic ``verify_bundle_layer_a`` pipeline (SCITT / chain /
Merkle / HMAC) does NOT verify, yet which ``validate_event_keys_str`` ADMITS:

  * ``event_kind == "key_rotation"`` — rotation authorization (co-signatures,
    pre-commit window, emergency offline-root, validity windows)
  * ``timestamp_evidence`` present — a per-event TSA/Roughtime trusted-time claim
  * ``cross_host_edge``  present — a per-event cross-host binding

The single coarse ``subkey_coverage("layer_a")`` key papered over all three
(found via key_rotation; the other two surfaced in the systemic sweep). These
tests pin:

  1. the laundering regression — an obligation-carrying event fails closed even
     when the coarse layer_a sub-key coverage IS satisfied (the exact bug: the
     generic counter plugin reports whole-subtree coverage but verifies none of
     the per-event obligations);
  2. the coverage contract — a plugin reporting the per-event obligation key
     keeps it green; a near-miss (wrong bytes / wrong tag) does not;
  3. inert cases — generic events with no obligation field, and empty/absent
     layer_a, stay green;
  4. the divergence ratchet — every admitted optional/rotation event key is
     classified generic-or-obligation, and every obligation classification maps
     to a registered tag, so a new admitted semantic field cannot silently
     bypass the guard.
"""

from __future__ import annotations

import json
from pathlib import Path

from audit_bundle.causal_chain_coverage import (
    LAYER_A_EVENT_OBLIGATION_TAGS,
    event_obligation_coverage,
    event_obligation_key,
    subkey_coverage,
)
from audit_bundle.extensions.c19.layer_a_counter import (
    _EVENT_OPTIONAL_KEYS_STR,
    _ROTATION_EVENT_EXTRA_KEYS_STR,
)
from audit_bundle.plugin import PluginResult
from audit_bundle.verdict import VerdictState
from audit_bundle.verifier import BundleVerifier

_BASE = {
    "schema_version": "legacy",
    "bundle_id": "b",
    "created_at": "2026-06-12T00:00:00Z",
    "files": {},
    "spec_files": {},
    "cross_refs": {},
}


def _layer_a(event: dict) -> dict:
    """A minimal layer_a carrying exactly one event."""
    return {"event_dag_merkle_root": "a" * 64, "events": [event]}


def _verify(tmp_path: Path, causal_chain, *, plugins=()):
    manifest = dict(_BASE)
    if causal_chain is not None:
        manifest["causal_chain"] = causal_chain
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    return BundleVerifier(plugins=plugins).verify(tmp_path)


class _SubkeyOnlyStub:
    """Reports coarse subkey_coverage("layer_a") and NOTHING finer — stands in
    for the generic LayerACounterPlugin, which runs SCITT/chain/Merkle/HMAC and
    claims whole-subtree coverage but verifies no per-event obligation. This is
    the laundering surface: the coarse claim is satisfied, the obligation is not.
    """

    name = "test_subkey_only_stub"
    applies_to_files: frozenset[str] = frozenset()

    def check(self, bundle_dir, manifest) -> PluginResult:
        cc = getattr(manifest, "causal_chain", None) or {}
        layer_a = cc.get("layer_a")
        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail="stub: coarse layer_a coverage only",
            files_audited=(),
            verified_causal_chain_subkeys=subkey_coverage("layer_a", layer_a),
        )


class _ObligationStub:
    """Reports coarse subkey coverage AND the per-event obligation for the given
    tag — stands in for a dedicated verifier (e.g. eidas S19d) that actually
    re-derived the obligation."""

    name = "test_obligation_stub"
    applies_to_files: frozenset[str] = frozenset()

    def __init__(self, tag: str):
        self.tag = tag

    def check(self, bundle_dir, manifest) -> PluginResult:
        cc = getattr(manifest, "causal_chain", None) or {}
        layer_a = cc.get("layer_a") or {}
        discharged: set[str] = set()
        for ev in layer_a.get("events", []):
            discharged |= event_obligation_coverage(ev, self.tag)
        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail="stub: obligation discharged",
            files_audited=(),
            verified_causal_chain_subkeys=subkey_coverage("layer_a", layer_a),
            verified_layer_a_event_obligations=frozenset(discharged),
        )


# Representative obligation-carrying events, one per tag.
_ROTATION_EVENT = {
    "event_kind": "key_rotation",
    "old_key_id": "k_old",
    "new_key_id": "k_new",
    "rotation_reason": "scheduled",
    "co_signed_old_key": "00",
    "co_signed_new_key": "11",
}
_TIMESTAMP_EVENT = {
    "event_kind": "retrieval",
    "timestamp_evidence": {"kind": "tsa", "receipt": "deadbeef"},
}
_CROSS_HOST_EVENT = {
    "event_kind": "host_message_send",
    "cross_host_edge": {"peer": "host-b", "receipt": "cafe"},
}
_OBLIGATION_EVENTS = {
    "key_rotation": _ROTATION_EVENT,
    "timestamp_evidence": _TIMESTAMP_EVENT,
    "cross_host_edge": _CROSS_HOST_EVENT,
}


# --------------------------------------------------------------------------
# 1. Laundering regression — coarse coverage satisfied, obligation NOT
# --------------------------------------------------------------------------


def test_obligation_event_fails_closed_even_with_coarse_coverage(tmp_path):
    """The exact reported bug: a generic plugin claims whole-layer_a coverage,
    so the sub-key guard is satisfied — but the per-event obligation was never
    verified, and THIS guard must still fail closed."""
    for tag, event in _OBLIGATION_EVENTS.items():
        v = _verify(tmp_path, {"layer_a": _layer_a(event)}, plugins=[_SubkeyOnlyStub()])
        assert v.state is VerdictState.ERROR, (
            f"{tag}: laundered to {v.state} despite coarse-only coverage"
        )
        assert any(r.check_name == "layer_a_event_obligations" for r in v.reasons), (
            f"{tag}: expected a layer_a_event_obligations leg, got "
            f"{[r.check_name for r in v.reasons]}"
        )
        # And the coarse sub-key guard must NOT be the thing that fired —
        # proving this is a genuinely finer obligation the coarse claim hid.
        assert not any(r.check_name == "causal_chain" for r in v.reasons), (
            f"{tag}: coarse causal_chain guard fired — coverage was not actually "
            "satisfied, so the test does not isolate the obligation guard"
        )


def test_bare_library_consumer_fails_closed(tmp_path):
    """No plugins at all (BundleVerifier()): both the coarse and the obligation
    guard fire — a library consumer never reads OK over an admitted obligation."""
    v = _verify(tmp_path, {"layer_a": _layer_a(_ROTATION_EVENT)})
    assert v.state is VerdictState.ERROR
    assert any(r.check_name == "layer_a_event_obligations" for r in v.reasons)


# --------------------------------------------------------------------------
# 2. Coverage contract — a discharging plugin keeps it green; near-miss does not
# --------------------------------------------------------------------------


def test_reported_obligation_keeps_event_green(tmp_path):
    for tag, event in _OBLIGATION_EVENTS.items():
        v = _verify(
            tmp_path, {"layer_a": _layer_a(event)}, plugins=[_ObligationStub(tag)]
        )
        assert v.state is VerdictState.OK, (
            f"{tag}: discharged obligation not green ({v.state})"
        )


def test_wrong_tag_does_not_satisfy(tmp_path):
    """Discharging the cross_host_edge obligation cannot satisfy the
    key_rotation obligation on the same event bytes (tag bound into the key)."""
    v = _verify(
        tmp_path,
        {"layer_a": _layer_a(_ROTATION_EVENT)},
        plugins=[_ObligationStub("cross_host_edge")],  # wrong tag for this event
    )
    assert v.state is VerdictState.ERROR
    assert any(r.check_name == "layer_a_event_obligations" for r in v.reasons)


def test_coverage_of_other_event_bytes_does_not_satisfy(tmp_path):
    """Content keys bind to bytes: verifying SOME OTHER rotation event cannot
    launder THIS one."""

    class _WrongBytesStub:
        name = "wrong_bytes"
        applies_to_files: frozenset[str] = frozenset()

        def check(self, bundle_dir, manifest) -> PluginResult:
            cc = getattr(manifest, "causal_chain", None) or {}
            layer_a = cc.get("layer_a") or {}
            other = dict(_ROTATION_EVENT, old_key_id="DIFFERENT")
            return PluginResult(
                ok=True,
                reason_code="PASS",
                detail="",
                files_audited=(),
                verified_causal_chain_subkeys=subkey_coverage("layer_a", layer_a),
                verified_layer_a_event_obligations=frozenset(
                    {event_obligation_key(other, "key_rotation")}
                ),
            )

    v = _verify(
        tmp_path, {"layer_a": _layer_a(_ROTATION_EVENT)}, plugins=[_WrongBytesStub()]
    )
    assert v.state is VerdictState.ERROR


def test_tag_is_bound_into_the_key():
    assert event_obligation_key(
        _ROTATION_EVENT, "key_rotation"
    ) != event_obligation_key(_ROTATION_EVENT, "timestamp_evidence")


# --------------------------------------------------------------------------
# 3. Inert cases — no obligation present stays green
# --------------------------------------------------------------------------


def test_generic_event_with_no_obligation_field_stays_green(tmp_path):
    generic = {"event_kind": "retrieval", "payload_hash": "00" * 32}
    v = _verify(tmp_path, {"layer_a": _layer_a(generic)}, plugins=[_SubkeyOnlyStub()])
    assert v.state is VerdictState.OK


def test_empty_or_eventless_layer_a_imposes_no_obligation(tmp_path):
    for cc in (None, {}, {"layer_a": {}}, {"layer_a": {"events": []}}):
        v = _verify(tmp_path, cc, plugins=[_SubkeyOnlyStub()])
        assert v.state is VerdictState.OK, (
            f"{cc!r} should impose no obligation, got {v.state}"
        )


# --------------------------------------------------------------------------
# 4. Divergence ratchet — admitted-keys vs obligation classification can't drift
# --------------------------------------------------------------------------

# Every admitted OPTIONAL or ROTATION-EXTRA event key is classified here as
# either "generic" (discharged by the generic per-event pipeline, or a purely
# structural/advisory field that elevates no trust) or "obligation:<tag>" (a
# dedicated-verifier obligation the generic pipeline does NOT evaluate). The
# comparison against the live admitted-key sets is EXACT in both directions, so
# adding a new admitted key without classifying it — or removing one — fails the
# test. This is the forcing function the bare docstring deferral lacked: a new
# admitted semantic field can no longer ride the coarse layer_a coverage claim.
_KEY_DISPOSITION: dict[str, str] = {
    # --- _EVENT_OPTIONAL_KEYS_STR ---
    # advisory DAG ordering; the prev_event_hash chain is the authoritative
    # integrity spine and is generically verified — causal_dependencies elevates
    # no trust on its own (shape-validated only).
    "causal_dependencies": "generic",
    # selects the per-event issuer key in stage 6 (generically verified there).
    "host_id": "generic",
    # the COSE receipt bytes alias; verified in SCITT stages 1.5–2.
    "scitt_inclusion_proof_bytes": "generic",
    # per-event TSA/Roughtime trusted-time — NOT re-derived by the generic path.
    "timestamp_evidence": "obligation:timestamp_evidence",
    # per-event cross-host binding — the top-level cross_host_authenticators
    # guard keys on the authenticator set, not this event field.
    "cross_host_edge": "obligation:cross_host_edge",
    # --- _ROTATION_EVENT_EXTRA_KEYS_STR (all part of the one rotation obligation) ---
    "old_key_id": "obligation:key_rotation",
    "new_key_id": "obligation:key_rotation",
    "rotation_reason": "obligation:key_rotation",
    "new_key_pre_commitment_scitt_id": "obligation:key_rotation",
    "new_key_pre_commitment_scitt_receipt": "obligation:key_rotation",
    "pre_commit_issuance_iso8601": "obligation:key_rotation",
    "issuance_at": "obligation:key_rotation",
    "rotation_at": "obligation:key_rotation",
    "valid_not_before": "obligation:key_rotation",
    "valid_not_after": "obligation:key_rotation",
    "co_signed_old_key": "obligation:key_rotation",
    "co_signed_new_key": "obligation:key_rotation",
    "emergency_offline_root_signature": "obligation:key_rotation",
    "offline_root_key_id": "obligation:key_rotation",
}


def test_every_admitted_optional_or_rotation_key_is_classified():
    admitted = set(_EVENT_OPTIONAL_KEYS_STR) | set(_ROTATION_EVENT_EXTRA_KEYS_STR)
    classified = set(_KEY_DISPOSITION)
    unclassified = admitted - classified
    stale = classified - admitted
    assert not unclassified, (
        f"admitted event key(s) {sorted(unclassified)} are not classified in "
        "_KEY_DISPOSITION — classify each as 'generic' (verified by the generic "
        "pipeline / purely structural) or 'obligation:<tag>' (needs a dedicated "
        "verifier, and register <tag> in LAYER_A_EVENT_OBLIGATION_TAGS)"
    )
    assert not stale, (
        f"_KEY_DISPOSITION classifies key(s) {sorted(stale)} no longer admitted by "
        "the event key gate — drop them so the ratchet only shrinks truthfully"
    )


def test_every_obligation_classification_maps_to_a_registered_tag():
    obligation_tags = {
        d.split(":", 1)[1]
        for d in _KEY_DISPOSITION.values()
        if d.startswith("obligation:")
    }
    assert obligation_tags == set(LAYER_A_EVENT_OBLIGATION_TAGS), (
        "the obligation tags referenced by _KEY_DISPOSITION "
        f"{sorted(obligation_tags)} must equal LAYER_A_EVENT_OBLIGATION_TAGS "
        f"{sorted(LAYER_A_EVENT_OBLIGATION_TAGS)} — a new obligation field must "
        "register its tag (and the guard helper must realize it), and a retired "
        "tag must drop from both"
    )


def test_each_registered_tag_is_realized_by_a_representative_event():
    """Every registered tag must actually fire on some event shape — a tag in the
    registry that no event predicate produces would be dead (an obligation the
    guard can never see as present)."""
    from audit_bundle.causal_chain_coverage import event_obligation_tags

    for tag in LAYER_A_EVENT_OBLIGATION_TAGS:
        assert tag in _OBLIGATION_EVENTS, (
            f"registered obligation tag {tag!r} has no representative event in "
            "this test — add one so the realization is exercised"
        )
        assert tag in event_obligation_tags(_OBLIGATION_EVENTS[tag]), (
            f"tag {tag!r} is registered but event_obligation_tags does not "
            "produce it for its representative event — the helper does not "
            "realize the tag (dead obligation)"
        )
