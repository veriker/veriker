"""tests/test_append_only_floor.py — the §C9.2 reclassification floor.

``append_only_files`` is a producer-authored downgrade from byte-equality
(rank 2) to attribution-key coverage (rank 1). The floor
(audit_bundle/append_only_floor.py, wired into ``BundleVerifier.verify()`` as
a HARD PRE-CHECK) makes that downgrade authorization-gated:

  * default minimum class is STRICT_SHA for every path;
  * the closed static allowlist authorizes exactly the two live shapes,
    keyed by (path, attribution_key) — a key swap on an allowlisted path
    REJECTS;
  * an unauthorized APPEND_ONLY declaration REJECTS with
    APPEND_ONLY_FLOOR_VIOLATION regardless of content (no salvage lane);
  * an honored declaration's on-disk object must be a REGULAR file;
  * the auditor min-class policy (construction-time, anchored patterns,
    never manifest-sourced, never envelope-adjustable) is the only other
    floor-lowering authority; authorities compose by stronger_of, never
    override — a stricter auditor entry on an allowlisted path raises the
    floor back;
  * the two live mesh-pilot declarations keep verifying identically
    (the D2-empty corpus invariant).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from audit_bundle.append_only_floor import (
    APPEND_ONLY_FLOOR_VIOLATION,
    GUARANTEE_RANK,
    STATIC_APPEND_ONLY_ALLOWLIST,
    check_append_only_floor,
    stronger_of,
    validate_min_class_policy,
)
from audit_bundle.integrity_ownership import Guarantee
from audit_bundle.verifier import BundleVerifier, _load_manifest

REPO_ROOT = Path(__file__).resolve().parents[1]
MESH_PILOT_ROOT = REPO_ROOT / "examples" / "mesh_pilot_v2"

ALLOWED_TRACE = {
    "path": "retrieval_trace_log.jsonl",
    "attribution_key": "trace_id",
    "attribution_plugin": "three_set_sum_invariant",
    "verification_mode": "first_match",
}
THIRD_PATH = {
    "path": "status_events.jsonl",
    "attribution_key": "trace_id",
    "attribution_plugin": "three_set_sum_invariant",
    "verification_mode": "first_match",
}


def _write_bundle(bundle_dir: Path, append_only: list[dict]) -> None:
    """Minimal unsealed bundle whose only on-disk files are the append-only
    declarations themselves (each with one well-formed keyed record)."""
    bundle_dir.mkdir(parents=True, exist_ok=True)
    for spec in append_only:
        target = bundle_dir / spec["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps({spec["attribution_key"]: "rec-1"}) + "\n",
            encoding="utf-8",
        )
    (bundle_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "vcp-v1.1-canary4",
                "bundle_id": "floor-test",
                "created_at": "2026-06-10T00:00:00Z",
                "files": {},
                "spec_files": {},
                "cross_refs": {},
                "append_only_files": append_only,
            }
        ),
        encoding="utf-8",
    )


def _floor_failures(verdict):
    return [f for f in verdict.failures if f.check_name == "append_only_floor"]


# ---------------------------------------------------------------------------
# The guarantee lattice
# ---------------------------------------------------------------------------


def test_lattice_ranks_match_contract():
    assert GUARANTEE_RANK[Guarantee.DSSE_BINDING_SET_CLOSURE] == 3
    assert GUARANTEE_RANK[Guarantee.BYTE_EQUALITY] == 2
    assert GUARANTEE_RANK[Guarantee.PINNED_BLOB_HASH] == 2
    assert GUARANTEE_RANK[Guarantee.CID_RECOMPUTE] == 2
    assert GUARANTEE_RANK[Guarantee.ATTRIBUTION_KEY_COVERAGE] == 1
    assert GUARANTEE_RANK[Guarantee.NONE] == 0


def test_stronger_of_picks_higher_rank_and_ties_keep_first():
    assert (
        stronger_of(Guarantee.ATTRIBUTION_KEY_COVERAGE, Guarantee.BYTE_EQUALITY)
        is Guarantee.BYTE_EQUALITY
    )
    assert (
        stronger_of(Guarantee.BYTE_EQUALITY, Guarantee.ATTRIBUTION_KEY_COVERAGE)
        is Guarantee.BYTE_EQUALITY
    )
    # Rank-2 ties keep the manifest's declared mechanism (the first operand).
    assert (
        stronger_of(Guarantee.CID_RECOMPUTE, Guarantee.BYTE_EQUALITY)
        is Guarantee.CID_RECOMPUTE
    )


def test_static_allowlist_is_exactly_the_two_live_shapes():
    assert STATIC_APPEND_ONLY_ALLOWLIST == frozenset(
        {
            ("retrieval_trace_log.jsonl", "trace_id"),
            ("source_attributes/source_properties.jsonl", "source_cid"),
        }
    )


# ---------------------------------------------------------------------------
# D2-empty corpus invariant — the live mesh-pilot declarations keep working
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not MESH_PILOT_ROOT.is_dir(),
    reason="mesh-pilot corpus not present (excluded from the open drop)",
)
def test_mesh_pilot_live_declarations_pass_the_floor():
    """The two live declarations ARE the allowlist: the floor finds nothing,
    on the mesh root and on a child bundle alike."""
    for bundle_dir in (
        MESH_PILOT_ROOT,
        MESH_PILOT_ROOT / "bundles" / "es_sleep_stages",
    ):
        manifest = _load_manifest(bundle_dir)
        result = check_append_only_floor(bundle_dir, manifest, {})
        assert result.failures == (), (bundle_dir, result.failures)
        assert result.policy_lowered == ()


def test_allowlisted_declaration_verifies_green_end_to_end(tmp_path):
    bundle_dir = tmp_path / "b"
    _write_bundle(bundle_dir, [ALLOWED_TRACE])

    verdict = BundleVerifier(plugins=()).verify(bundle_dir)

    assert verdict.ok, [(f.reason_code, f.detail) for f in verdict.failures]


# ---------------------------------------------------------------------------
# Hard pre-check: unauthorized downgrade rejects regardless of content
# ---------------------------------------------------------------------------


def test_third_undeclared_append_only_path_rejects(tmp_path):
    bundle_dir = tmp_path / "b"
    _write_bundle(bundle_dir, [ALLOWED_TRACE, THIRD_PATH])

    verdict = BundleVerifier(plugins=()).verify(bundle_dir)

    assert not verdict.ok
    hits = _floor_failures(verdict)
    assert len(hits) == 1
    assert hits[0].reason_code == APPEND_ONLY_FLOOR_VIOLATION
    assert "'status_events.jsonl'" in hits[0].detail
    # The allowlisted declaration is unaffected (per-declaration gating).
    assert "'retrieval_trace_log.jsonl'" not in hits[0].detail


def test_unauthorized_rejects_even_with_perfect_content(tmp_path):
    """No salvage lane: the file carries a perfectly well-formed keyed record
    and the floor still rejects — authorization is independent of content."""
    bundle_dir = tmp_path / "b"
    _write_bundle(bundle_dir, [THIRD_PATH])
    target = bundle_dir / "status_events.jsonl"
    assert json.loads(target.read_text().splitlines()[0])["trace_id"] == "rec-1"

    verdict = BundleVerifier(plugins=()).verify(bundle_dir)

    assert not verdict.ok
    assert _floor_failures(verdict)[0].reason_code == APPEND_ONLY_FLOOR_VIOLATION


def test_key_swap_on_allowlisted_path_rejects(tmp_path):
    """Authorization is per (path, attribution_key): riding the path's
    authorization with the OTHER closed-set key rejects."""
    bundle_dir = tmp_path / "b"
    swapped = dict(
        ALLOWED_TRACE,
        attribution_key="source_cid",
        attribution_plugin="source_attributes_consistency",
    )
    _write_bundle(bundle_dir, [swapped])

    verdict = BundleVerifier(plugins=()).verify(bundle_dir)

    assert not verdict.ok
    hits = _floor_failures(verdict)
    assert hits and hits[0].reason_code == APPEND_ONLY_FLOOR_VIOLATION
    assert "attribution_key" in hits[0].detail


@pytest.mark.skipif(sys.platform != "linux", reason="symlink semantics")
def test_non_regular_object_at_allowlisted_path_rejects(tmp_path):
    """An honored declaration requires a REGULAR on-disk file: a symlink at
    the allowlisted path fails the floor (lstat, never followed)."""
    bundle_dir = tmp_path / "b"
    _write_bundle(bundle_dir, [ALLOWED_TRACE])
    target = bundle_dir / "retrieval_trace_log.jsonl"
    real = bundle_dir / "real.jsonl"
    target.rename(real)
    target.symlink_to(real)
    # keep conservation quiet about the relocated real file
    manifest = json.loads((bundle_dir / "manifest.json").read_text())
    import hashlib

    manifest["files"] = {"real.jsonl": hashlib.sha256(real.read_bytes()).hexdigest()}
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest))

    verdict = BundleVerifier(plugins=()).verify(bundle_dir)

    assert not verdict.ok
    hits = _floor_failures(verdict)
    assert hits and hits[0].reason_code == APPEND_ONLY_FLOOR_VIOLATION
    assert "not a regular file" in hits[0].detail


def test_absent_declared_path_is_not_the_floors_finding(tmp_path):
    """Absence belongs to the §C9.1 attribution check, not the floor: an
    allowlisted declaration whose file is missing passes the FLOOR."""
    bundle_dir = tmp_path / "b"
    _write_bundle(bundle_dir, [ALLOWED_TRACE])
    (bundle_dir / "retrieval_trace_log.jsonl").unlink()

    manifest = _load_manifest(bundle_dir)
    result = check_append_only_floor(bundle_dir, manifest, {})
    assert result.failures == ()


def test_traversal_path_fails_closed_without_lstat_oracle(tmp_path):
    """A directly-constructed manifest with a traversal path fails the
    lexical guard before any authority consult or lstat."""
    from types import SimpleNamespace

    bundle_dir = tmp_path / "b"
    bundle_dir.mkdir()
    manifest = SimpleNamespace(
        append_only_files=({"path": "../../etc/passwd", "attribution_key": "trace_id"},)
    )
    result = check_append_only_floor(bundle_dir, manifest, {})
    assert result.failures
    assert result.failures[0][0] == APPEND_ONLY_FLOOR_VIOLATION
    assert "bundle-relative" in result.failures[0][1]


# ---------------------------------------------------------------------------
# Auditor min-class policy — the only other floor-lowering authority
# ---------------------------------------------------------------------------


def test_policy_authorizes_third_path_with_verbose_disclosure(tmp_path):
    bundle_dir = tmp_path / "b"
    _write_bundle(bundle_dir, [ALLOWED_TRACE, THIRD_PATH])

    verdict = BundleVerifier(
        plugins=(), min_class_policy={"status_events.jsonl": "append_only"}
    ).verify(bundle_dir)

    assert verdict.ok, [(f.reason_code, f.detail) for f in verdict.failures]
    assert any(
        "'status_events.jsonl'" in d and "min-class policy" in d
        for d in verdict.completeness.disclosures
    )
    # The static-allowlisted path is NOT reported as policy-lowered.
    assert not any(
        "'retrieval_trace_log.jsonl'" in d
        for d in verdict.completeness.disclosures
        if "append_only_floor" in d
    )


def test_policy_strict_sha_on_allowlisted_path_raises_floor_back(tmp_path):
    """Compose by stronger_of, never override: a stricter auditor entry on
    an allowlisted path raises the floor back to rank 2 → the declaration
    rejects."""
    bundle_dir = tmp_path / "b"
    _write_bundle(bundle_dir, [ALLOWED_TRACE])

    verdict = BundleVerifier(
        plugins=(),
        min_class_policy={"retrieval_trace_log.jsonl": "strict_sha"},
    ).verify(bundle_dir)

    assert not verdict.ok
    hits = _floor_failures(verdict)
    assert hits and hits[0].reason_code == APPEND_ONLY_FLOOR_VIOLATION


def test_policy_is_a_minimum_never_a_cap(tmp_path):
    """A rank-1 policy floor does not downgrade anything by itself: ordinary
    manifest.files entries keep byte-equality (the producer asked for the
    stronger guarantee; the floor is a MINIMUM)."""
    import hashlib

    bundle_dir = tmp_path / "b"
    bundle_dir.mkdir()
    data = b"strict bytes"
    (bundle_dir / "data.txt").write_bytes(data)
    (bundle_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "vcp-v1.1-canary4",
                "bundle_id": "floor-min",
                "created_at": "2026-06-10T00:00:00Z",
                "files": {"data.txt": hashlib.sha256(data).hexdigest()},
                "spec_files": {},
                "cross_refs": {},
            }
        )
    )
    policy = {"data.txt": "append_only"}
    assert BundleVerifier(plugins=(), min_class_policy=policy).verify(bundle_dir).ok

    # …and a tampered byte still rejects: the policy floor never weakened
    # the strict-SHA check the producer requested.
    (bundle_dir / "data.txt").write_bytes(b"tampered bytes")
    verdict = BundleVerifier(plugins=(), min_class_policy=policy).verify(bundle_dir)
    assert not verdict.ok
    assert any(f.reason_code == "bad_file_sha" for f in verdict.failures)


def test_policy_anchored_glob_matches(tmp_path):
    bundle_dir = tmp_path / "b"
    deep_third = dict(THIRD_PATH, path="logs/events.jsonl")
    _write_bundle(bundle_dir, [deep_third])

    verdict = BundleVerifier(
        plugins=(), min_class_policy={"logs/*.jsonl": "append_only"}
    ).verify(bundle_dir)

    assert verdict.ok, [(f.reason_code, f.detail) for f in verdict.failures]


@pytest.mark.parametrize(
    "bad_policy",
    [
        {"*.jsonl": "append_only"},  # unanchored wildcard
        {"**/x.jsonl": "append_only"},  # recursive glob
        {"a/../b.jsonl": "append_only"},  # traversal
        {"manifest.json": "append_only"},  # envelope is never policy-adjustable
        {"x.jsonl": "scaffold"},  # not a floorable class
        {"x.jsonl": "unowned"},  # not a floorable class
    ],
)
def test_invalid_policy_rejected_at_construction(bad_policy):
    with pytest.raises(ValueError):
        BundleVerifier(min_class_policy=bad_policy)


def test_policy_never_sourced_from_manifest(tmp_path):
    """A manifest field named min_class_policy is meaningless: the downgrade
    authority lives at construction, outside the producer's control."""
    bundle_dir = tmp_path / "b"
    _write_bundle(bundle_dir, [THIRD_PATH])
    manifest = json.loads((bundle_dir / "manifest.json").read_text())
    manifest["min_class_policy"] = {"status_events.jsonl": "append_only"}
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest))

    verdict = BundleVerifier(plugins=()).verify(bundle_dir)

    assert not verdict.ok
    assert _floor_failures(verdict)[0].reason_code == APPEND_ONLY_FLOOR_VIOLATION


def test_validate_min_class_policy_normalizes_values():
    validated = validate_min_class_policy(
        {"logs/*.jsonl": "append_only", "x.jsonl": "strict_sha"}
    )
    assert {k: v.value for k, v in validated.items()} == {
        "logs/*.jsonl": "append_only",
        "x.jsonl": "strict_sha",
    }
    assert validate_min_class_policy(None) == {}
