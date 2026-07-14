"""Ratchet: no NEW mutable-container fields on frozen dataclasses.

Why this exists
---------------
``@dataclass(frozen=True)`` freezes only the top-level attribute bindings; a
``dict``/``list`` field stays mutable in place. Two redteam passes found the
same shape independently (BundleManifest nested fields, 2026-06-10 manifest
deep-immutability lock; then RevocationList.entries — the decision map
``is_revoked`` reads while the verdict records the raw-bytes hash). Rather than
patching instances one finding at a time, this test enumerates the whole class
by AST sweep and pins it:

* a NEW mutable-container field on a frozen dataclass fails here with a pointer
  to ``audit_bundle._freeze.deep_freeze`` (freeze it at the parse/construction
  boundary, or consciously allowlist it);
* a field that disappears (fixed to an immutable type, or removed) must also be
  removed from the allowlist — the ratchet only turns one way.

Tier semantics
--------------
RUNTIME_FROZEN  — annotation still says dict/list, but the VALUE is deep-frozen
                  at its parse/construction boundary (verified by a runtime test
                  here or in test_manifest_deep_immutability.py).
LEGACY_MUTABLE  — known-unprotected burn-down list (triaged NOT-a-vuln: every
                  holder is verifier-shipped TCB code; bundle-supplied execution
                  is subprocess-isolated). Burn down trust-decision carriers
                  first (SpecAnchor.allowed, AnchoredSpecSet.by_type, the
                  CrossOrgKeyPolicy / OfflineRootPolicy pins). When you protect
                  one, MOVE its key to RUNTIME_FROZEN (and add a runtime test)
                  or make the annotation immutable and DELETE the key.

Stdlib only.
"""

from __future__ import annotations

import ast
from pathlib import Path

import audit_bundle
from audit_bundle.revocation import RevocationList

PACKAGE_ROOT = Path(audit_bundle.__file__).resolve().parent

# Outermost annotation names treated as mutable containers.
_MUTABLE_TYPE_NAMES = frozenset(
    {
        "dict",
        "list",
        "set",
        "Dict",
        "List",
        "Set",
        "MutableMapping",
        "MutableSequence",
        "MutableSet",
        "defaultdict",
        "OrderedDict",
        "Counter",
        "deque",
        "bytearray",
    }
)

# --- Tier 1: annotation is mutable, value is deep-frozen at the boundary. ---
RUNTIME_FROZEN: frozenset[str] = frozenset(
    {
        # BundleManifest: deep-frozen by _load_manifest (verifier.py); runtime
        # behavior locked by tests/test_manifest_deep_immutability.py.
        "bundle_manifest.py::BundleManifest.files",
        "bundle_manifest.py::BundleManifest.spec_files",
        "bundle_manifest.py::BundleManifest.cross_refs",
        "bundle_manifest.py::BundleManifest.payload",
        "bundle_manifest.py::BundleManifest.typed_checks",
        "bundle_manifest.py::BundleManifest.snapshots",
        "bundle_manifest.py::BundleManifest.snapshot_policy",
        "bundle_manifest.py::BundleManifest.fragment_anchors",
        "bundle_manifest.py::BundleManifest.source_attributes",
        "bundle_manifest.py::BundleManifest.output_mode_signal",
        "bundle_manifest.py::BundleManifest.rigor_profile",
        "bundle_manifest.py::BundleManifest.attested_serving",
        "bundle_manifest.py::BundleManifest.verifier_identity",
        "bundle_manifest.py::BundleManifest.causal_chain",
        "bundle_manifest.py::BundleManifest.semantic_fidelity",
        "bundle_manifest.py::BundleManifest.extension_receipts",
        # RevocationList: deep-frozen in __post_init__ (every construction
        # site); runtime behavior locked by the tests at the bottom of this
        # file.
        "revocation.py::RevocationList.entries",
    }
)

# --- Tier 2: known-unprotected burn-down list (do NOT add to this set). ---
LEGACY_MUTABLE: frozenset[str] = frozenset(
    {
        "coverage/protocol.py::CoverageRow.withheld_reason_breakdown",
        "emitter/hooks.py::TimestampResult.extra_manifest_fields",
        "emitter/hooks.py::CausalChainResult.extra_manifest_fields",
        "emitter/hooks.py::AttestationResult.extra_manifest_fields",
        "event_stream.py::StatusEvent.metadata",
        "extensions/c19/cross_host_peerreview.py::CrossOrgKeyPolicy.pinned_cose_keys",
        "extensions/c19/cross_host_peerreview.py::CrossOrgKeyPolicy.pinned_hmac_ikm",
        "extensions/c19/cross_host_peerreview.py::CrossOrgKeyPolicy.pinned_cose_key_hosts",
        "extensions/c19/offline_root.py::OfflineRootPolicy.pinned_offline_root_verifying_keys",
        "extensions/c19/profile_completeness_policy.py::Profile.obligations",
        "extensions/c19/profile_completeness_policy.py::CompletenessPolicy.profiles",
        "extensions/c19/profile_completeness_policy.py::CompletenessPolicy._reachable",
        "fragments/fragment_id.py::OpaqueFragment.locator",
        "manifest_three_set.py::PerOutputManifest.three_set",
        "rederivation/spec_binding.py::Binding.comparator_params",
        "rederivation/spec_binding.py::SpecAnchor.allowed",
        "rederivation/spec_binding.py::AnchoredSpecSet.by_type",
        "snapshots/ingest_record.py::SnapshotIngestRecord.ingestion_metadata",
        "source_registry/decision_provenance.py::DecisionProvenance.evidence",
        # SourceProperties.external_status_flags burned down 2026-06-11
        # (Codex RES-10, instance #3 of this class): annotation is now
        # tuple[str, ...] with list-coercion in __post_init__ — the field
        # left the mutable inventory outright rather than moving tiers.
    }
)


def _is_frozen_dataclass_decorator(dec: ast.expr) -> bool:
    if not isinstance(dec, ast.Call):
        return False
    func = dec.func
    name = getattr(func, "id", None) or getattr(func, "attr", None)
    if name != "dataclass":
        return False
    return any(
        kw.arg == "frozen"
        and isinstance(kw.value, ast.Constant)
        and kw.value.value is True
        for kw in dec.keywords
    )


def _mutable_base(ann: ast.expr) -> str | None:
    """Outermost mutable-container name in an annotation, or None."""
    if isinstance(ann, ast.Subscript):
        return _mutable_base(ann.value)
    if isinstance(ann, ast.Name) and ann.id in _MUTABLE_TYPE_NAMES:
        return ann.id
    if isinstance(ann, ast.Attribute) and ann.attr in _MUTABLE_TYPE_NAMES:
        return ann.attr
    if isinstance(ann, ast.BinOp):  # unions like `dict | None`
        return _mutable_base(ann.left) or _mutable_base(ann.right)
    # String annotations ("RevocationList | None" style) — parse and recurse.
    if isinstance(ann, ast.Constant) and isinstance(ann.value, str):
        try:
            return _mutable_base(ast.parse(ann.value, mode="eval").body)
        except SyntaxError:
            return None
    return None


def _sweep() -> set[str]:
    """Every '<relpath>::<Class>.<field>' where a frozen dataclass declares a
    mutable-container field, across the whole audit_bundle package."""
    found: set[str] = set()
    for py in sorted(PACKAGE_ROOT.rglob("*.py")):
        rel = py.relative_to(PACKAGE_ROOT).as_posix()
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.ClassDef)
                and any(_is_frozen_dataclass_decorator(d) for d in node.decorator_list)
            ):
                continue
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(
                    stmt.target, ast.Name
                ):
                    if _mutable_base(stmt.annotation) is not None:
                        found.add(f"{rel}::{node.name}.{stmt.target.id}")
    return found


# ---------------------------------------------------------------------------
# The ratchet
# ---------------------------------------------------------------------------


def test_allowlist_tiers_are_disjoint():
    overlap = RUNTIME_FROZEN & LEGACY_MUTABLE
    assert not overlap, f"a field cannot be in both tiers: {sorted(overlap)}"


def test_no_new_mutable_fields_on_frozen_dataclasses():
    found = _sweep()
    allowed = RUNTIME_FROZEN | LEGACY_MUTABLE
    new = found - allowed
    assert not new, (
        "NEW mutable-container field(s) on frozen dataclass(es):\n  "
        + "\n  ".join(sorted(new))
        + "\nfrozen=True locks only the top-level bindings — the container is "
        "still mutable in place, and two redteam passes have flagged exactly "
        "this shape. Either deep-freeze the value at its parse/construction "
        "boundary (audit_bundle._freeze.deep_freeze; see "
        "RevocationList.__post_init__ for the pattern) and add the key to "
        "RUNTIME_FROZEN with a runtime test, or use an immutable type "
        "(tuple / frozenset / frozen dataclass). Do NOT extend LEGACY_MUTABLE."
    )


def test_ratchet_only_turns_one_way():
    found = _sweep()
    # Only judge entries whose FILE is present: the OSS export drops boundary
    # paths (orchestrator_turn/, emitter_premium/, gate/) wholesale, and this
    # test must stay green in that standalone tree. In the full internal tree
    # every allowlisted file exists, so the ratchet runs at full strength; a
    # field fixed-or-removed while its file survives is still flagged.
    judged = {
        key
        for key in RUNTIME_FROZEN | LEGACY_MUTABLE
        if (PACKAGE_ROOT / key.split("::", 1)[0]).is_file()
    }
    stale = judged - found
    assert not stale, (
        "allowlisted field(s) no longer exist — remove them so the ratchet "
        "stays tight:\n  " + "\n  ".join(sorted(stale))
    )


# ---------------------------------------------------------------------------
# Runtime proof for the RevocationList tier-1 claim
# ---------------------------------------------------------------------------


def _make_list() -> RevocationList:
    return RevocationList(
        entries={"kid-a": 1000, "kid-b": 2000},
        issued_at=500,
        expires=9000,
        revocation_list_hash="ab" * 32,
    )


def test_revocation_entries_frozen_on_direct_construction():
    rl = _make_list()
    import pytest

    with pytest.raises(TypeError):
        rl.entries["kid-evil"] = 0  # add a revocation
    with pytest.raises(TypeError):
        del rl.entries["kid-a"]  # un-revoke
    with pytest.raises(TypeError):
        rl.entries.clear()
    with pytest.raises(TypeError):
        rl.entries.update({"kid-a": 10**12})  # push not_after into the future
    # Read API intact — is_revoked()'s .get() path.
    assert rl.entries.get("kid-a") == 1000
    assert rl.entries.get("missing") is None


def test_revocation_decision_unchanged_by_freeze():
    from audit_bundle.revocation import DSSE_KEY_REVOKED, is_revoked

    rl = _make_list()
    revoked = is_revoked(rl, "kid-a", verifier_now=1000)
    assert revoked.revoked is True
    assert revoked.reason_code == DSSE_KEY_REVOKED
    valid = is_revoked(rl, "kid-b", verifier_now=1000)
    assert valid.revoked is False
    unknown = is_revoked(rl, "kid-unknown", verifier_now=1000)
    assert unknown.revoked is False


def test_empty_entries_construction_still_works():
    # emitter/pipeline.py constructs RevocationList(entries={}, ...) directly;
    # __post_init__ must not break that site.
    rl = RevocationList(
        entries={}, issued_at=0, expires=10, revocation_list_hash="00" * 32
    )
    assert rl.entries == {}
