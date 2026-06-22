"""tests/test_integrity_ownership.py — unit tests for the integrity-ownership map.

One test per owner class, plus the precedence/collision cases and the
mirrored as-built quirks. The map is pure and unconsumed (no call sites), so
these tests pin its SEMANTICS; agreement with the live walks over the real
corpus is the parity harness's job (tests/test_integrity_ownership_parity.py).
"""

from __future__ import annotations

import dataclasses
from types import SimpleNamespace

from audit_bundle.bundle_manifest import BundleManifest
from audit_bundle.integrity_ownership import (
    ENVELOPE_PATHS,
    SCAFFOLD_BASENAMES,
    Authority,
    Guarantee,
    Owner,
    OwnerKind,
    append_only_declared_paths,
    classify_path,
)

NO_PLUGINS: frozenset[str] = frozenset()


def _stub(
    *,
    files: dict | None = None,
    spec_files: dict | None = None,
    snapshots: dict | None = None,
    typed_checks: list | None = None,
    append_only_files: tuple = (),
) -> SimpleNamespace:
    """Duck-typed manifest stand-in (mirrors the minimal stubs other tests use)."""
    return SimpleNamespace(
        files=files or {},
        spec_files=spec_files or {},
        snapshots=snapshots or {},
        typed_checks=typed_checks or [],
        append_only_files=append_only_files,
    )


SHA = "0" * 64


# ---------------------------------------------------------------------------
# One test per owner class
# ---------------------------------------------------------------------------


def test_envelope_both_names_top_level_only():
    m = _stub()
    for name in ("manifest.json", "bundle.dsse.json"):
        owner = classify_path(name, m, NO_PLUGINS)
        assert owner == Owner(
            OwnerKind.ENVELOPE,
            Guarantee.DSSE_BINDING_SET_CLOSURE,
            Authority.VERIFIER_STATIC,
        )
    # Nested copies are NOT envelope (mirrors the Pass-3 full-rel_path match).
    assert classify_path("sub/manifest.json", m, NO_PLUGINS).kind is OwnerKind.UNOWNED
    assert ENVELOPE_PATHS == frozenset({"manifest.json", "bundle.dsse.json"})


def test_strict_sha_for_declared_file():
    m = _stub(files={"payload/release.json": SHA})
    owner = classify_path("payload/release.json", m, NO_PLUGINS)
    assert owner == Owner(
        OwnerKind.STRICT_SHA, Guarantee.BYTE_EQUALITY, Authority.PRODUCER_DECLARED
    )


def test_spec_tree_declared_basename_vs_undeclared():
    # spec_files KEYS are spec-doc paths; the walk pins spec/<basename(key)>.
    m = _stub(spec_files={"docs/specs/span_v2.md": SHA})
    pinned = classify_path("spec/span_v2.md", m, NO_PLUGINS)
    assert pinned == Owner(
        OwnerKind.SPEC, Guarantee.PINNED_BLOB_HASH, Authority.PRODUCER_DECLARED
    )
    # Same tree, undeclared basename: skipped unchecked as-built.
    surplus = classify_path("spec/extra.md", m, NO_PLUGINS)
    assert surplus == Owner(OwnerKind.SPEC, Guarantee.NONE, Authority.VERIFIER_STATIC)
    # The pinning walk is FLAT (spec/<basename> only): a deeper path is never
    # pinned even when its basename matches a declared key.
    deeper = classify_path("spec/sub/span_v2.md", m, NO_PLUGINS)
    assert deeper.kind is OwnerKind.SPEC
    assert deeper.guarantee is Guarantee.NONE


def test_snapshot_declared_value_vs_tree_only():
    cas_path = "snapshots/sha256/00/00aa"
    m = _stub(snapshots={"sha256:00aa": cas_path})
    declared = classify_path(cas_path, m, NO_PLUGINS)
    assert declared == Owner(
        OwnerKind.SNAPSHOT, Guarantee.CID_RECOMPUTE, Authority.PRODUCER_DECLARED
    )
    # In-tree but undeclared: skipped unchecked as-built.
    stray = classify_path("snapshots/stray.bin", m, NO_PLUGINS)
    assert stray == Owner(OwnerKind.SNAPSHOT, Guarantee.NONE, Authority.VERIFIER_STATIC)
    # A declared snapshot value is CID-recomputed WHEREVER it lives — the
    # deep validator walks snapshots.values(), not the snapshots/ tree.
    m2 = _stub(snapshots={"sha256:00bb": "evidence/frozen.txt"})
    outside = classify_path("evidence/frozen.txt", m2, NO_PLUGINS)
    assert outside.kind is OwnerKind.SNAPSHOT
    assert outside.guarantee is Guarantee.CID_RECOMPUTE


def test_append_only_declared_path():
    m = _stub(
        append_only_files=(
            {
                "path": "retrieval_trace_log.jsonl",
                "attribution_key": "trace_id",
                "attribution_plugin": "three_set_sum_invariant",
                "verification_mode": "first_match",
            },
        )
    )
    owner = classify_path("retrieval_trace_log.jsonl", m, NO_PLUGINS)
    assert owner == Owner(
        OwnerKind.APPEND_ONLY,
        Guarantee.ATTRIBUTION_KEY_COVERAGE,
        Authority.PRODUCER_DECLARED,
    )


def test_plugin_via_applies_to_files_exact_path():
    m = _stub(files={"energy_score.json": SHA})
    owner = classify_path(
        "energy_score.json", m, frozenset({"energy_score.json", "raw_traces/"})
    )
    assert owner == Owner(OwnerKind.PLUGIN, Guarantee.NONE, Authority.AUDITOR_SUPPLIED)


def test_scaffold_top_level_only():
    # D4 (ratified as amended): the scaffold allowance is TOP-LEVEL only. A
    # top-level pilot.json/README.md is SCAFFOLD; a nested copy is UNOWNED
    # (and therefore Pass-3-flagged), congruent with the sealed set-closure
    # walk which never had the allowance.
    m = _stub()
    assert SCAFFOLD_BASENAMES == frozenset({"pilot.json", "README.md"})
    for rel in ("pilot.json", "README.md"):
        owner = classify_path(rel, m, NO_PLUGINS)
        assert owner == Owner(
            OwnerKind.SCAFFOLD, Guarantee.NONE, Authority.VERIFIER_STATIC
        ), rel
    for rel in ("payload/README.md", "a/b/pilot.json"):
        owner = classify_path(rel, m, NO_PLUGINS)
        assert owner == Owner(
            OwnerKind.UNOWNED, Guarantee.NONE, Authority.VERIFIER_STATIC
        ), rel


def test_unowned_default():
    m = _stub(files={"data/x.txt": SHA})
    owner = classify_path("data/stray.bin", m, NO_PLUGINS)
    assert owner == Owner(OwnerKind.UNOWNED, Guarantee.NONE, Authority.VERIFIER_STATIC)


# ---------------------------------------------------------------------------
# Precedence / collision cases
# ---------------------------------------------------------------------------


def test_collision_snapshot_value_also_in_files_is_strict_sha():
    # The brief's named collision: declaration in files wins (the strict-SHA
    # walk checks it as-built; the CID recompute additionally runs — the map
    # records the files declaration as the primary owner).
    p = "snapshots/sha256/aa/aabb"
    m = _stub(files={p: SHA}, snapshots={"sha256:aabb": p})
    assert classify_path(p, m, NO_PLUGINS).kind is OwnerKind.STRICT_SHA


def test_collision_append_only_beats_files_membership():
    # Loader rejects this overlap at parse time; for directly constructed
    # manifests the map mirrors the strict-SHA walk, which SKIPS the path
    # even when it is also in files.
    p = "trace.jsonl"
    m = _stub(
        files={p: SHA},
        append_only_files=({"path": p, "attribution_key": "trace_id"},),
    )
    assert classify_path(p, m, NO_PLUGINS).kind is OwnerKind.APPEND_ONLY


def test_collision_envelope_beats_files_membership():
    # Structurally self-contradictory bundle (manifest.json cannot contain
    # its own hash); the map classifies ENVELOPE first, documented.
    m = _stub(files={"manifest.json": SHA})
    assert classify_path("manifest.json", m, NO_PLUGINS).kind is OwnerKind.ENVELOPE


def test_collision_declared_scaffold_basename_is_strict_sha():
    # Live in the corpus (partner-pilot manifests declare README.md in files):
    # declared copies are byte-equality-checked; only undeclared scaffold
    # files ride the basename allowance.
    m = _stub(files={"README.md": SHA})
    assert classify_path("README.md", m, NO_PLUGINS).kind is OwnerKind.STRICT_SHA


def test_collision_spec_tree_path_in_files_is_strict_sha():
    m = _stub(files={"spec/inline.md": SHA})
    assert classify_path("spec/inline.md", m, NO_PLUGINS).kind is OwnerKind.STRICT_SHA


def test_plugin_via_applies_to_files_authority_is_auditor():
    # D3 dropped the typed_checks-as-paths PLUGIN leg; the only surviving
    # PLUGIN leg is an exact-path applies_to_files entry (auditor-supplied).
    # A lingering typed_checks claim is now ignored.
    p = "covered.json"
    m = _stub(files={p: SHA}, typed_checks=[p])
    owner = classify_path(p, m, frozenset({p}))
    assert owner.kind is OwnerKind.PLUGIN
    assert owner.authority is Authority.AUDITOR_SUPPLIED


def test_partition_exactly_one_kind_per_path_and_deterministic():
    # Maximal-overlap stub: every rule has a candidate; classify_path must
    # return exactly one Owner per path, stably.
    m = _stub(
        files={
            "manifest.json": SHA,
            "README.md": SHA,
            "spec/inline.md": SHA,
            "snapshots/cas": SHA,
            "covered.json": SHA,
            "plain.txt": SHA,
        },
        spec_files={"docs/pinned.md": SHA},
        snapshots={"sha256:x": "snapshots/cas", "sha256:y": "elsewhere/frozen.txt"},
        typed_checks=["covered.json", "file_integrity_many_small"],
        append_only_files=({"path": "trace.jsonl", "attribution_key": "trace_id"},),
    )
    plugin_files = frozenset({"covered.json", "spec/"})
    paths = [
        "manifest.json",
        "bundle.dsse.json",
        "trace.jsonl",
        "covered.json",
        "plain.txt",
        "README.md",
        "sub/README.md",
        "pilot.json",
        "spec/inline.md",
        "spec/pinned.md",
        "spec/extra.md",
        "snapshots/cas",
        "snapshots/stray",
        "elsewhere/frozen.txt",
        "file_integrity_many_small",
        "stray.bin",
        "",
    ]
    for rel in paths:
        first = classify_path(rel, m, plugin_files)
        second = classify_path(rel, m, plugin_files)
        assert first == second, rel
        assert isinstance(first.kind, OwnerKind), rel


# ---------------------------------------------------------------------------
# Mirrored as-built quirks
# ---------------------------------------------------------------------------


def test_typed_check_name_matching_a_file_path_is_now_strict_sha():
    # D3 (ratified): the dead typed_checks-as-paths leg is gone. A file in
    # manifest.files literally named like a registered plugin is no longer
    # exempt — it is STRICT_SHA (byte-equality). The map no longer reads
    # typed_checks at all.
    p = "file_integrity_many_small"
    m = _stub(files={p: SHA}, typed_checks=[p])
    owner = classify_path(p, m, NO_PLUGINS)
    assert owner.kind is OwnerKind.STRICT_SHA
    assert owner.authority is Authority.PRODUCER_DECLARED


def test_quirk_trailing_slash_prefix_entries_are_inert():
    # applies_to_files dir-prefixes ("corpus/") are consumed by EXACT match
    # as-built, so they exempt nothing; the map does no prefix matching.
    m = _stub(files={"corpus/corpus.jsonl": SHA})
    owner = classify_path(
        "corpus/corpus.jsonl", m, frozenset({"corpus/", "previous_corpus/"})
    )
    assert owner.kind is OwnerKind.STRICT_SHA


def test_quirk_plugin_coverage_without_files_membership_is_unowned():
    # An on-disk path covered by applies_to_files but absent from files is
    # surplus to the Pass-3 sweep as-built (it has no plugin skip), so the
    # map calls it UNOWNED rather than PLUGIN.
    m = _stub(files={})
    owner = classify_path("energy_score.json", m, frozenset({"energy_score.json"}))
    assert owner.kind is OwnerKind.UNOWNED


def test_quirk_pathless_append_only_spec_admits_empty_string():
    # Mirrors the .get("path", "") extraction at both walk sites. Reachable
    # only via directly constructed manifests (the validator rejects the
    # shape at load), but the map must not diverge from the walks on it.
    m = _stub(append_only_files=({"attribution_key": "trace_id"},))
    assert "" in append_only_declared_paths(m)
    assert classify_path("", m, NO_PLUGINS).kind is OwnerKind.APPEND_ONLY
    # Non-dict entries are filtered, as at both walk sites.
    m2 = _stub(append_only_files=("not-a-dict",))
    assert append_only_declared_paths(m2) == frozenset()


def test_quirk_stub_without_append_only_attr_uses_getattr_default():
    # Pre-v0.4 stubs lack the field; the Pass-3 sweep getattr-defaults it.
    legacy_stub = SimpleNamespace(
        files={"a.txt": SHA}, spec_files={}, snapshots={}, typed_checks=[]
    )
    assert append_only_declared_paths(legacy_stub) == frozenset()
    assert classify_path("a.txt", legacy_stub, NO_PLUGINS).kind is OwnerKind.STRICT_SHA


def test_real_bundle_manifest_classifies():
    # The map consumes a real BundleManifest identically to a stub.
    m = BundleManifest(
        schema_version="legacy",
        bundle_id="iomap-unit",
        created_at="2026-06-10T00:00:00Z",
        files={"data/x.txt": SHA},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
    )
    assert classify_path("data/x.txt", m, NO_PLUGINS).kind is OwnerKind.STRICT_SHA
    m2 = dataclasses.replace(
        m, append_only_files=({"path": "log.jsonl", "attribution_key": "trace_id"},)
    )
    assert classify_path("log.jsonl", m2, NO_PLUGINS).kind is OwnerKind.APPEND_ONLY
