"""tests/test_admit_json_file.py — the shared bundle-file admission loader.

Redteam (ChatGPT, redteam mirror): admission bounds (size/depth/cardinality) were
applied to the raw manifest only; primitives/plugins read other bundle JSON via raw
json.loads(path.read_bytes()) with no bound. The strong form (a crash / fail-closed
violation) does NOT reproduce — RecursionError/MemoryError subclass Exception and are
caught by the dispatch and plugin boundaries (see test_verdict_contract.py). The real
residual is an asymmetry: the manifest gets a cheap PRE-PARSE reject; other reads pay an
expensive caught-exception. admit_json_file lifts the manifest's discipline to a shared
loader so a hostile input file is a cheap, localized REJECT.

Asserted here:
  * size  — a file over max_bytes is rejected by the stat pre-check (no read needed);
  * depth — a depth-bomb file is rejected by admit_bytes BEFORE json.loads can recurse;
  * cardinality — an over-wide collection is rejected by admit_obj after parse;
  * malformed/absent — raise InputInadmissible (typed, fail-closed), never a bare crash;
  * happy path — a normal file parses and returns the object;
  * end-to-end — the climate primitive on a depth-bomb input yields a clean dispatch
    failure, not an uncaught RecursionError.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from audit_bundle.admission import (
    AdmissionLimits,
    InputInadmissible,
    admit_json_file,
)


def _write(path: Path, raw: bytes) -> Path:
    path.write_bytes(raw)
    return path


def test_size_rejected_at_stat_precheck(tmp_path: Path):
    p = _write(tmp_path / "big.json", b'"' + b"x" * 5000 + b'"')
    with pytest.raises(InputInadmissible) as ei:
        admit_json_file(p, AdmissionLimits(max_bytes=100))
    assert ei.value.verdict.reason == "INPUT_SIZE_EXCEEDED"


def test_depth_bomb_rejected_before_parse(tmp_path: Path):
    # Deep enough that a raw json.loads would RecursionError; admit_bytes must
    # reject it first via the cheap pre-parse byte scan.
    depth = 5000
    p = _write(tmp_path / "deep.json", b"[" * depth + b"]" * depth)
    with pytest.raises(InputInadmissible) as ei:
        admit_json_file(p, AdmissionLimits(max_depth=64))
    assert ei.value.verdict.reason == "INPUT_DEPTH_EXCEEDED"


def test_cardinality_rejected_after_parse(tmp_path: Path):
    p = _write(tmp_path / "wide.json", json.dumps(list(range(500))).encode())
    with pytest.raises(InputInadmissible) as ei:
        admit_json_file(p, AdmissionLimits(max_collection=100))
    assert ei.value.verdict.reason == "INPUT_CARDINALITY_EXCEEDED"


def test_malformed_json_raises_inadmissible(tmp_path: Path):
    p = _write(tmp_path / "bad.json", b"{not valid")
    with pytest.raises(InputInadmissible):
        admit_json_file(p)


def test_absent_file_raises_inadmissible(tmp_path: Path):
    with pytest.raises(InputInadmissible):
        admit_json_file(tmp_path / "nope.json")


def test_happy_path_returns_object(tmp_path: Path):
    obj = {"a": [1, 2, 3], "b": {"c": 4}}
    p = _write(tmp_path / "ok.json", json.dumps(obj).encode())
    assert admit_json_file(p) == obj


def test_inadmissible_is_valueerror_subclass():
    # A primitive that simply lets it propagate is recorded fail-closed by the
    # dispatch boundary's malformed-input handling exactly like any ValueError.
    assert issubclass(InputInadmissible, ValueError)


def test_climate_primitive_depth_bomb_is_clean_dispatch_failure(tmp_path: Path):
    """End-to-end: a depth-bomb supplier_chain.json drives the climate primitive
    to a fail-closed RECOMPUTE_ERROR (via the cheap pre-parse reject), never an
    uncaught RecursionError."""
    from audit_bundle.plugin import ParsedInputs
    from audit_bundle.rederivation.primitives.climate_emission import (
        ClimateEmissionRecompute,
    )

    inputs_dir = tmp_path / "inputs"
    inputs_dir.mkdir()
    depth = 5000
    (inputs_dir / "supplier_chain.json").write_bytes(b"[" * depth + b"]" * depth)

    prim = ClimateEmissionRecompute()
    # The primitive raises InputInadmissible (a ValueError); the dispatch boundary
    # is what records RECOMPUTE_ERROR. Here we assert the raise is the typed,
    # bounded one — not a RecursionError from an unbounded parse.
    with pytest.raises(InputInadmissible) as ei:
        prim.recompute(ParsedInputs(bundle_dir=tmp_path), {})
    assert ei.value.verdict.reason == "INPUT_DEPTH_EXCEEDED"
