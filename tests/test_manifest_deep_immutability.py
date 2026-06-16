"""Structural test: a parsed BundleManifest is DEEPLY immutable.

`@dataclass(frozen=True, slots=True)` freezes only the top-level bindings on
BundleManifest — the nested dict/list values parsed from manifest.json stay
mutable. `audit_bundle.verifier._load_manifest` threads ONE manifest object
through ~10 sequential pipeline steps (conservation gate, append-only floor,
the 4-step walk, typed-check plugins, spec-pinned dispatch, extension-receipt /
cross-host / deep validators), and several LATE steps re-read fields the early
integrity steps already consumed. Verdict correctness therefore rests on an
unenforced convention: "no in-process step mutates a nested field a later step
re-reads."

This file LOCKS that convention into a mechanically-enforced invariant. It is
NOT a regression test for a live exploit — no attacker-controlled code holds a
live reference to the manifest object (every bundle-supplied executable runs in
a subprocess with separate memory; the only in-process holders are
verifier-shipped TCB code). It defends against the reachable failure mode: a
future maintainer who adds an in-process step that mutates a manifest collection
in place (sort / dedup / normalize), which would otherwise silently launder a
later verdict. With the freeze in place that mutation raises TypeError at the
offending line instead.

Two properties are asserted together because they are in tension:
  (1) IMMUTABILITY — the normal mutation API on every nested collection raises.
  (2) COMPATIBILITY — the frozen containers are still `isinstance(_, dict/list)`
      and serialize byte-identically to plain dict/list, so the OF1
      manifest-header leaf and the snapshot-policy SHA (both of which
      `json.dumps` manifest fields) are unchanged. A regression on (2) would
      silently shift every canonical leaf, so it is guarded explicitly.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from audit_bundle.bundle_manifest import (
    _FrozenDict,
    _FrozenList,
    deep_freeze,
)
from audit_bundle.verifier import _load_manifest


# ---------------------------------------------------------------------------
# Minimal manifest builder (mirrors test_load_manifest_v0_3_propagation).
# ---------------------------------------------------------------------------

_MINIMAL_BASE_FIELDS: dict = {
    "schema_version": "vcp-v1.1",
    "bundle_id": "00000000-0000-4000-8000-000000000000",
    "created_at": "2026-05-20T00:00:00Z",
    "files": {},
    "spec_files": {},
    "cross_refs": {},
    "payload": {},
    "typed_checks": [],
}


def _write_manifest(bundle_dir: Path, **extra) -> Path:
    bundle_dir.mkdir(parents=True, exist_ok=True)
    manifest = {**_MINIMAL_BASE_FIELDS, **extra}
    manifest_path = bundle_dir / "manifest.json"
    manifest_path.write_bytes(json.dumps(manifest).encode("utf-8"))
    return manifest_path


# ---------------------------------------------------------------------------
# deep_freeze unit behavior
# ---------------------------------------------------------------------------


def test_deep_freeze_dict_blocks_mutation_api():
    frozen = deep_freeze({"a": 1, "b": 2})
    assert isinstance(frozen, dict)
    assert frozen == {"a": 1, "b": 2}
    with pytest.raises(TypeError):
        frozen["c"] = 3
    with pytest.raises(TypeError):
        del frozen["a"]
    with pytest.raises(TypeError):
        frozen.update({"x": 9})
    with pytest.raises(TypeError):
        frozen.pop("a")
    with pytest.raises(TypeError):
        frozen.setdefault("z", 0)
    with pytest.raises(TypeError):
        frozen.clear()
    with pytest.raises(TypeError):
        frozen |= {"q": 1}


def test_deep_freeze_list_blocks_mutation_api():
    frozen = deep_freeze([1, 2, 3])
    assert isinstance(frozen, list)
    assert frozen == [1, 2, 3]
    with pytest.raises(TypeError):
        frozen.append(4)
    with pytest.raises(TypeError):
        frozen[0] = 9
    with pytest.raises(TypeError):
        frozen.extend([5])
    with pytest.raises(TypeError):
        frozen.pop()
    with pytest.raises(TypeError):
        frozen.sort()
    with pytest.raises(TypeError):
        frozen.insert(0, 0)
    with pytest.raises(TypeError):
        frozen += [7]


def test_deep_freeze_recurses_through_nesting():
    frozen = deep_freeze(
        {"outer": {"inner": [{"leaf": 1}]}, "arr": [[1, 2], {"k": "v"}]}
    )
    inner_dict = frozen["outer"]["inner"][0]
    nested_list = frozen["arr"][0]
    nested_in_list = frozen["arr"][1]
    assert isinstance(inner_dict, _FrozenDict)
    assert isinstance(nested_list, _FrozenList)
    assert isinstance(nested_in_list, _FrozenDict)
    with pytest.raises(TypeError):
        inner_dict["leaf"] = 2
    with pytest.raises(TypeError):
        nested_list.append(3)
    with pytest.raises(TypeError):
        nested_in_list["k"] = "x"


def test_deep_freeze_tuple_stays_immutable_and_freezes_elements():
    frozen = deep_freeze(({"a": 1}, [2, 3]))
    assert isinstance(frozen, tuple)
    assert isinstance(frozen[0], _FrozenDict)
    assert isinstance(frozen[1], _FrozenList)
    with pytest.raises(TypeError):
        frozen[0]["a"] = 9
    with pytest.raises(TypeError):
        frozen[1].append(4)


def test_deep_freeze_passes_scalars_through():
    assert deep_freeze("s") == "s"
    assert deep_freeze(7) == 7
    assert deep_freeze(3.5) == 3.5
    assert deep_freeze(True) is True
    assert deep_freeze(None) is None


# ---------------------------------------------------------------------------
# Compatibility: frozen containers serialize byte-identically to plain ones.
# A regression here would silently shift every canonical manifest-header leaf.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        {"b": 2, "a": 1, "nested": {"y": [1, 2, 3], "x": "v"}},
        {"policy": {"mode": "strict", "windows": [{"id": 1}, {"id": 2}]}},
        [{"k": "v"}, [1, 2], "s", 3, None, True],
    ],
)
def test_frozen_serializes_byte_identically(value):
    plain_sorted = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    frozen_sorted = json.dumps(
        deep_freeze(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    assert frozen_sorted == plain_sorted


# ---------------------------------------------------------------------------
# End-to-end: the parsed manifest from _load_manifest is deeply immutable.
# ---------------------------------------------------------------------------


def test_loaded_manifest_top_level_collections_frozen(tmp_path):
    _write_manifest(
        tmp_path,
        files={"a.txt": "ab" * 32},
        cross_refs={"ref": "a.txt"},
        typed_checks=["x"],
    )
    m = _load_manifest(tmp_path)
    assert isinstance(m.files, dict)
    assert isinstance(m.typed_checks, list)
    with pytest.raises(TypeError):
        m.files["evil.txt"] = "00" * 32
    with pytest.raises(TypeError):
        m.files.clear()
    with pytest.raises(TypeError):
        m.cross_refs["ref"] = "other.txt"
    with pytest.raises(TypeError):
        m.typed_checks.append("y")


def test_loaded_manifest_nested_collections_frozen(tmp_path):
    """A late pipeline step mutating a NESTED manifest value must raise — the
    verdict-laundering window the freeze closes."""
    causal_chain = {
        "layer_a": {
            "event_dag_merkle_root": "ab" * 32,
            "chain_height": 0,
            "scitt_log_id": "test-log",
            "assurance_profile": "offline-auditor-minimal",
            "protocol_version": "v0.3",
            "events": [],
        }
    }
    _write_manifest(tmp_path, causal_chain=causal_chain)
    m = _load_manifest(tmp_path)
    layer_a = m.causal_chain["layer_a"]
    assert isinstance(layer_a, dict)
    # Attempt to launder: blank the merkle root in place after the load.
    with pytest.raises(TypeError):
        layer_a["event_dag_merkle_root"] = "00" * 32
    with pytest.raises(TypeError):
        layer_a["events"].append({"forged": True})
    # Value is unchanged after the blocked mutation.
    assert m.causal_chain["layer_a"]["event_dag_merkle_root"] == "ab" * 32


def test_loaded_manifest_outputs_tuple_elements_frozen(tmp_path):
    _write_manifest(
        tmp_path,
        outputs=[{"output_id": "o1", "type": "t", "conforms_to": "s"}],
    )
    m = _load_manifest(tmp_path)
    assert isinstance(m.outputs, tuple)
    entry = m.outputs[0]
    assert isinstance(entry, dict)
    with pytest.raises(TypeError):
        entry["type"] = "weaker"


def test_loaded_manifest_reads_still_work(tmp_path):
    """Immutability must not break the read API every plugin relies on."""
    _write_manifest(
        tmp_path,
        files={"a.txt": "ab" * 32, "b.txt": "cd" * 32},
        snapshots={"cid1": "snap/a"},
    )
    m = _load_manifest(tmp_path)
    # Reads used across plugins: items(), get(), membership, set(), len, iter.
    assert dict(m.files.items()) == {"a.txt": "ab" * 32, "b.txt": "cd" * 32}
    assert m.files.get("a.txt") == "ab" * 32
    assert "b.txt" in m.files
    assert set(m.files) == {"a.txt", "b.txt"}
    assert len(m.files) == 2
    assert sorted(m.files) == ["a.txt", "b.txt"]
    assert set(m.snapshots) == {"cid1"}
