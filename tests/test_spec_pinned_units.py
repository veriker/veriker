"""tests/test_spec_pinned_units.py — unit tests for the spec-pinned dispatch
substrate (comparator registry §3.4/§4a.6, spec parsing + anchoring §3.1/§4a.2).
Stdlib-only; no bundle build required.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from audit_bundle.rederivation import comparators as C
from audit_bundle.rederivation.spec_binding import (
    AmbiguousTypeBinding,
    MalformedSpec,
    SpecAnchor,
    build_anchored_spec_set,
    parse_spec,
)


# --- comparator registry ----------------------------------------------------


def test_comparator_kinds_are_the_five_generic():
    assert C.comparator_kinds() == {
        "scalar_epsilon",
        "exact",
        "text_normalized",
        "set",
        "structured",
    }


def test_unknown_comparator_kind_fails_closed():
    with pytest.raises(C.UnknownComparatorKind):
        C.resolve_comparator("always_true")


def test_scalar_epsilon_within_and_outside():
    cmp = C.resolve_comparator("scalar_epsilon")
    ok, _ = cmp(1.0, 1.0 + 5e-7, {"epsilon": 1e-6})
    assert ok
    ok, _ = cmp(1.0, 1.0 + 5e-3, {"epsilon": 1e-6})
    assert not ok


def test_exact_and_set():
    assert C.resolve_comparator("exact")(3, 3, {})[0]
    assert not C.resolve_comparator("exact")(3, 4, {})[0]
    assert C.resolve_comparator("set")([1, 2, 3], [3, 2, 1], {})[0]
    assert not C.resolve_comparator("set")([1, 2], [1, 2, 3], {})[0]


def test_set_comparator_is_multiset_sensitive():
    """Order-independent but multiplicity-sensitive: a producer cannot claim a
    different multiset than was recomputed. (M3 regression — pure-set semantics
    was multiset-blind and treated ['A','A','B'] == ['A','B','B'].)"""
    cmp = C.resolve_comparator("set")
    # Same multiset, different order -> equal.
    assert cmp(["A", "A", "B"], ["B", "A", "A"], {})[0]
    # Same DISTINCT elements, different multiplicities -> NOT equal.
    ok, detail = cmp(["A", "A", "B"], ["A", "B", "B"], {})
    assert not ok
    assert "mismatch" in detail
    # Differing count of one element -> NOT equal.
    assert not cmp(["A", "A"], ["A"], {})[0]


def test_set_comparator_dict_key_order_independent():
    """_freeze must canonicalize dicts order-independently, so two records with
    the same keys/values in different insertion order compare EQUAL as set
    elements (M3: the old insertion-order freeze caused spurious REJECTs)."""
    cmp = C.resolve_comparator("set")
    a = [{"x": 1, "y": 2}]
    b = [{"y": 2, "x": 1}]
    assert cmp(a, b, {})[0]
    # Genuinely different dict values still mismatch.
    assert not cmp([{"x": 1, "y": 2}], [{"x": 1, "y": 3}], {})[0]


def test_text_normalized_unknown_profile_fails_closed_at_compare():
    cmp = C.resolve_comparator("text_normalized")
    ok, detail = cmp("a", "a", {"profile": "no_such_profile"})
    assert not ok and "unknown normalization profile" in detail


def test_validate_params_closed_world_rejects_arbitrary_profile_and_schema():
    # §4a.6: arbitrary per-bundle profile/schema is "code in disguise" — rejected.
    with pytest.raises(C.UnknownComparatorParam):
        C.validate_comparator_params("text_normalized", {"profile": "evil_v9"})
    with pytest.raises(C.UnknownComparatorParam):
        C.validate_comparator_params("structured", {"schema": "evil_schema"})
    # known ones validate fine
    C.validate_comparator_params("text_normalized", {"profile": "spectra_v1"})
    C.validate_comparator_params("scalar_epsilon", {"epsilon": 1e-6})


def test_validate_params_rejects_bad_epsilon():
    with pytest.raises(ValueError):
        C.validate_comparator_params("scalar_epsilon", {"epsilon": -1})
    with pytest.raises(ValueError):
        C.validate_comparator_params("scalar_epsilon", {})


# --- spec parsing -----------------------------------------------------------


def test_parse_spec_happy():
    raw = {
        "spec_id": "x.v1",
        "types": {
            "t": {
                "primitive_id": "p",
                "comparator": {"kind": "exact", "params": {}},
            }
        },
    }
    spec_id, bindings = parse_spec(raw, "x.spec.json")
    assert spec_id == "x.v1"
    assert bindings["t"].primitive_id == "p"
    assert bindings["t"].comparator_kind == "exact"


def test_parse_spec_rejects_unknown_comparator_param_at_load():
    raw = {
        "spec_id": "x.v1",
        "types": {
            "t": {
                "primitive_id": "p",
                "comparator": {
                    "kind": "text_normalized",
                    "params": {"profile": "evil"},
                },
            }
        },
    }
    with pytest.raises(MalformedSpec):
        parse_spec(raw, "x.spec.json")


@pytest.mark.parametrize(
    "raw",
    [
        {"types": {}},  # no spec_id
        {"spec_id": "x", "types": {}},  # empty types
        {
            "spec_id": "x",
            "types": {"t": {"comparator": {"kind": "exact"}}},
        },  # no primitive_id
        {"spec_id": "x", "types": {"t": {"primitive_id": "p"}}},  # no comparator
    ],
)
def test_parse_spec_rejects_malformed(raw):
    with pytest.raises(MalformedSpec):
        parse_spec(raw, "bad.spec.json")


# --- anchoring + ambiguity across specs -------------------------------------


def _write_spec(spec_dir: Path, basename: str, doc: dict) -> str:
    spec_dir.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(doc).encode("utf-8")
    (spec_dir / basename).write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


class _M:
    """Minimal manifest stand-in carrying spec_files."""

    def __init__(self, spec_files):
        self.spec_files = spec_files


def test_ambiguous_type_across_two_anchored_specs(tmp_path):
    # Two authoritative specs define the SAME type key -> fail-closed (§4a.2).
    sha_a = _write_spec(
        tmp_path / "spec",
        "a.spec.json",
        {
            "spec_id": "a.v1",
            "types": {
                "t": {
                    "primitive_id": "p1",
                    "comparator": {"kind": "exact", "params": {}},
                }
            },
        },
    )
    sha_b = _write_spec(
        tmp_path / "spec",
        "b.spec.json",
        {
            "spec_id": "b.v1",
            "types": {
                "t": {
                    "primitive_id": "p2",
                    "comparator": {"kind": "exact", "params": {}},
                }
            },
        },
    )
    manifest = _M({"a.spec.json": sha_a, "b.spec.json": sha_b})
    anchor = SpecAnchor(allowed={"a.v1": sha_a, "b.v1": sha_b})
    with pytest.raises(AmbiguousTypeBinding):
        build_anchored_spec_set(tmp_path, manifest, anchor)


def test_unanchored_spec_is_not_authoritative(tmp_path):
    # A spec present + SHA-valid in the manifest but absent from the anchor is
    # NOT authoritative; with no authoritative spec the set fails closed.
    sha = _write_spec(
        tmp_path / "spec",
        "a.spec.json",
        {
            "spec_id": "a.v1",
            "types": {
                "t": {
                    "primitive_id": "p",
                    "comparator": {"kind": "exact", "params": {}},
                }
            },
        },
    )
    manifest = _M({"a.spec.json": sha})
    empty_anchor = SpecAnchor(allowed={})  # auditor anchored nothing
    from audit_bundle.rederivation.spec_binding import AnchorViolation

    with pytest.raises(AnchorViolation):
        build_anchored_spec_set(tmp_path, manifest, empty_anchor)


def test_anchored_resolves_and_search_is_global(tmp_path):
    sha = _write_spec(
        tmp_path / "spec",
        "a.spec.json",
        {
            "spec_id": "a.v1",
            "types": {
                "t": {
                    "primitive_id": "p",
                    "comparator": {"kind": "exact", "params": {}},
                }
            },
        },
    )
    manifest = _M({"a.spec.json": sha})
    anchor = SpecAnchor(allowed={"a.v1": sha})
    anchored = build_anchored_spec_set(tmp_path, manifest, anchor)
    assert anchored.resolve("t").primitive_id == "p"
    assert anchored.authoritative_spec_ids == ("a.v1",)
