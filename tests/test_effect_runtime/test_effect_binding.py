"""Unit tests for audit_bundle.effect_runtime.effect_binding —
translate dispatch_record.effect to a Wasmtime Linker import allowlist."""

from __future__ import annotations

import pytest

from audit_bundle.effect_runtime.effect_binding import (
    EFFECT_LABEL_TO_IMPORTS,
    IMPORT_TO_EFFECT_LABEL,
    LOCKED_LABELS,
    RESERVED_LABELS,
    EffectBindingError,
    label_admits_import,
    reverse_map_import,
    translate_effects_to_allowlist,
)


# ---------------------------------------------------------------------------
# Vocabulary invariants — these tests pin the v0.2 substrate
# ---------------------------------------------------------------------------


def test_locked_labels_match_effect_calculus_v0_1():
    """The locked set MUST be exactly the six labels EFFECT_CALCULUS.md
    locks at v0.1. Any drift requires a curator-review pass per the
    additive-only invariant."""
    assert LOCKED_LABELS == frozenset({
        "net", "fs", "model", "llm_spend_usd",
        "time_bound_ms", "locale_bound",
    })


def test_reserved_labels_match_effect_calculus_v0_1():
    """Reserved-forward set MUST be exactly the five labels
    EFFECT_CALCULUS.md reserves (db / subprocess / random / clock / notify)."""
    assert RESERVED_LABELS == frozenset({
        "db", "subprocess", "random", "clock", "notify",
    })


def test_locked_and_reserved_disjoint():
    """A label cannot be both locked AND reserved."""
    assert LOCKED_LABELS.isdisjoint(RESERVED_LABELS)


def test_every_locked_label_has_a_translation():
    """Translation function totality — every locked label must appear
    as a key in EFFECT_LABEL_TO_IMPORTS (even if its tuple is empty,
    indicating host-side enforcement without a guest-visible import)."""
    for label in LOCKED_LABELS:
        assert label in EFFECT_LABEL_TO_IMPORTS


def test_no_reserved_label_has_a_translation():
    """Reserved labels are explicitly NOT in EFFECT_LABEL_TO_IMPORTS —
    the absence is the v0.2 'no enforcement story' invariant."""
    for label in RESERVED_LABELS:
        assert label not in EFFECT_LABEL_TO_IMPORTS


def test_imports_are_unique_across_labels():
    """No import name belongs to two different labels; the reverse map
    would otherwise have a collision and a trace line couldn't be
    unambiguously tagged."""
    seen: dict[str, str] = {}
    for label, imports in EFFECT_LABEL_TO_IMPORTS.items():
        for imp in imports:
            assert imp not in seen, (
                f"import {imp!r} claimed by both {seen[imp]!r} and {label!r}"
            )
            seen[imp] = label


def test_reverse_map_round_trips_on_locked_imports():
    """For every (label, import) pair in the forward map, the reverse
    map must return that label."""
    for label, imports in EFFECT_LABEL_TO_IMPORTS.items():
        for imp in imports:
            assert reverse_map_import(imp) == label


# ---------------------------------------------------------------------------
# Translation — happy path
# ---------------------------------------------------------------------------


def test_empty_effect_translates_to_empty_allowlist():
    """A declared-pure dispatch has effect={} → allowlist is empty."""
    assert translate_effects_to_allowlist({}, mode="wasm") == frozenset()


def test_net_only_admits_socket_imports():
    """effect={'net': [...]} → allowlist contains TCP/UDP/DNS imports
    and nothing else."""
    allow = translate_effects_to_allowlist({"net": []}, mode="wasm")
    assert allow == frozenset({
        "wasi:sockets/tcp",
        "wasi:sockets/udp",
        "wasi:sockets/ip-name-lookup",
    })


def test_fs_only_admits_filesystem_imports():
    allow = translate_effects_to_allowlist({"fs": []}, mode="wasm")
    assert "wasi:filesystem/preopens" in allow
    assert "wasi:filesystem/types" in allow
    # Negative — net imports MUST NOT be in the fs-only allowlist.
    assert "wasi:sockets/tcp" not in allow


def test_multi_label_unions_imports():
    """Union-of-labels semantics: f(L1 ∪ L2) = f(L1) ∪ f(L2)."""
    a = translate_effects_to_allowlist({"net": []}, mode="wasm")
    b = translate_effects_to_allowlist({"fs": []}, mode="wasm")
    a_b = translate_effects_to_allowlist(
        {"net": [], "fs": []}, mode="wasm"
    )
    assert a_b == a | b


def test_host_enforced_label_admits_no_guest_import():
    """time_bound_ms is host-enforced (Wasmtime fuel/epoch) — declaring
    it does NOT add any guest-visible import."""
    assert translate_effects_to_allowlist(
        {"time_bound_ms": 5000}, mode="wasm"
    ) == frozenset()


def test_locale_bound_admits_no_guest_import():
    """locale_bound is host-enforced — same as time_bound_ms."""
    assert translate_effects_to_allowlist(
        {"locale_bound": ["en-US"]}, mode="wasm"
    ) == frozenset()


# ---------------------------------------------------------------------------
# Translation — rejection paths
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("reserved", sorted(RESERVED_LABELS))
def test_reserved_label_rejected_under_wasm_mode(reserved):
    with pytest.raises(EffectBindingError, match="reserved"):
        translate_effects_to_allowlist({reserved: []}, mode="wasm")


@pytest.mark.parametrize("reserved", sorted(RESERVED_LABELS))
def test_reserved_label_accepted_under_advisory_mode(reserved):
    """In mode='advisory' (v0.1 posture), reserved labels translate to
    empty imports (silent accept). This is the symmetry guarantee with
    the v0.1 plugin path."""
    allow = translate_effects_to_allowlist({reserved: []}, mode="advisory")
    assert allow == frozenset()


def test_unknown_label_always_rejected():
    """A label outside locked ∪ reserved is rejected in BOTH modes —
    well-formedness is C15's domain; an unknown label arriving here
    indicates the upstream plugin failed."""
    for mode in ("wasm", "advisory"):
        with pytest.raises(EffectBindingError, match="not in the locked"):
            translate_effects_to_allowlist({"made_up_label": []}, mode=mode)


def test_non_dict_effect_rejected():
    with pytest.raises(EffectBindingError, match="dict"):
        translate_effects_to_allowlist(["net"], mode="wasm")
    with pytest.raises(EffectBindingError, match="dict"):
        translate_effects_to_allowlist("net", mode="wasm")
    with pytest.raises(EffectBindingError, match="dict"):
        translate_effects_to_allowlist(None, mode="wasm")


def test_non_string_label_rejected():
    """A dict like {42: []} — well-formedness should have caught this
    upstream, but we defend in depth."""
    with pytest.raises(EffectBindingError, match="must be str"):
        translate_effects_to_allowlist({42: []}, mode="wasm")


def test_invalid_mode_rejected():
    with pytest.raises(EffectBindingError, match="mode"):
        translate_effects_to_allowlist({}, mode="enforced")
    with pytest.raises(EffectBindingError, match="mode"):
        translate_effects_to_allowlist({}, mode="")


# ---------------------------------------------------------------------------
# Reverse-map + label_admits_import — used by trace-divergence detection
# ---------------------------------------------------------------------------


def test_reverse_map_unknown_import_returns_none():
    assert reverse_map_import("wasi:cli/exit") is None
    assert reverse_map_import("attacker:malware/run") is None


def test_reverse_map_non_string_returns_none():
    assert reverse_map_import(None) is None
    assert reverse_map_import(42) is None
    assert reverse_map_import(["wasi:sockets/tcp"]) is None


def test_label_admits_import_positive():
    assert label_admits_import("net", "wasi:sockets/tcp")
    assert label_admits_import("fs", "wasi:filesystem/preopens")
    assert label_admits_import("model", "nexi:dispatch/model")


def test_label_admits_import_negative_cross_label():
    """A net-imported syscall is NOT admitted by the fs label."""
    assert not label_admits_import("fs", "wasi:sockets/tcp")
    assert not label_admits_import("net", "wasi:filesystem/preopens")


def test_label_admits_import_negative_unknown_label():
    """Unknown label name → never admits anything (defense in depth)."""
    assert not label_admits_import("made_up", "wasi:sockets/tcp")


def test_label_admits_import_host_enforced_admits_nothing():
    """time_bound_ms / locale_bound have empty import tuples — they
    admit no guest imports, full stop."""
    assert not label_admits_import("time_bound_ms", "wasi:clocks/wall-clock")
    assert not label_admits_import("locale_bound", "wasi:cli/environment")


# ---------------------------------------------------------------------------
# Reverse-map covers exactly the union of imports
# ---------------------------------------------------------------------------


def test_reverse_map_size_matches_total_imports():
    """The reverse map's size equals the count of (label, import) pairs
    in the forward map — confirms uniqueness invariant from above."""
    forward_count = sum(len(v) for v in EFFECT_LABEL_TO_IMPORTS.values())
    assert len(IMPORT_TO_EFFECT_LABEL) == forward_count
