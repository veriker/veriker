"""tests/test_plugin_fail_closed_sweep.py — fail-closed wrapping sibling sweep (Pattern 1b).

Follow-up to the M4 fix (fail-closed comparator boundary): per-item evaluation
calls in the default plugins could RAISE on hostile bundle data without being
wrapped, so the exception escaped the plugin and the verify run degraded to a
could-not-conclude crash (the plugin loop maps any check() exception to
VerifierError → exit 2) instead of the correct fail-closed REJECT (exit 1).

Every test here feeds a hostile input and asserts the plugin returns
ok=False with the expected reason_code — and does NOT raise.

Sites covered:
  * dispatch_record_wellformed / stamp_lattice / refinement_discharge —
    non-dict dispatch_records element (shared root cause)
  * three_set_sum_invariant   — non-dict three_set, non-list set field,
    unhashable / mutually-unorderable elements
  * source_attributes_consistency — non-dict source_attributes value;
    unreadable / malformed decision_provenance_log
  * monotone_growth           — unreadable / malformed corpus.jsonl
  * falsification_negative_test — valid-JSON-but-not-object rule file;
    invalid-UTF-8 rule file
  * file_integrity_many_small — file exists but read raises OSError
  * spec_sha_pin              — spec file exists but read raises OSError
  * refinement_discharge      — obligation file exists but read raises OSError
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from audit_bundle.plugins.dispatch_record_wellformed import (
    DispatchRecordWellformedCheck,
)
from audit_bundle.plugins.falsification_negative_test import (
    FalsificationNegativeTestCheck,
)
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall
from audit_bundle.plugins.monotone_growth import MonotoneGrowthCheck
from audit_bundle.plugins.refinement_discharge import RefinementDischargeCheck
from audit_bundle.plugins.source_attributes_consistency import (
    SourceAttributesConsistencyCheck,
)
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck
from audit_bundle.plugins.three_set_sum_invariant import ThreeSetSumInvariantCheck


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


class _Manifest:
    """Minimal manifest stub; only carries fields plugins actually read."""

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


# Hostile non-dict dispatch_records elements. None is excluded — all three
# plugins deliberately skip None (legacy placeholder), and that behaviour is
# unchanged by the sweep.
HOSTILE_RECORDS = ["foo", 123, ["nested"], 1.5]


# ---------------------------------------------------------------------------
# Shared root cause — non-dict dispatch_records element (3 default plugins)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("record", HOSTILE_RECORDS)
def test_dispatch_record_wellformed_non_dict_record_rejects(tmp_path: Path, record):
    res = DispatchRecordWellformedCheck().check(
        tmp_path, _Manifest(dispatch_records=(record,))
    )
    assert res.ok is False
    assert res.reason_code == "DISPATCH_RECORD_MALFORMED"


@pytest.mark.parametrize("record", HOSTILE_RECORDS)
def test_stamp_lattice_non_dict_record_rejects(tmp_path: Path, record):
    res = StampLatticeCheck().check(tmp_path, _Manifest(dispatch_records=(record,)))
    assert res.ok is False
    assert res.reason_code == "DISPATCH_RECORD_MALFORMED"


@pytest.mark.parametrize("record", HOSTILE_RECORDS)
def test_refinement_discharge_non_dict_record_rejects(tmp_path: Path, record):
    res = RefinementDischargeCheck().check(
        tmp_path, _Manifest(dispatch_records=(record,))
    )
    assert res.ok is False
    assert res.reason_code == "DISPATCH_RECORD_MALFORMED"


def test_non_dict_record_does_not_break_none_skip(tmp_path: Path):
    """A None element is still skipped (legacy placeholder), and a bundle of
    only-None records still passes all three plugins."""
    manifest = _Manifest(dispatch_records=(None, None))
    for plugin in (
        DispatchRecordWellformedCheck(),
        StampLatticeCheck(),
        RefinementDischargeCheck(),
    ):
        res = plugin.check(tmp_path, manifest)
        assert res.ok is True, plugin.name


# ---------------------------------------------------------------------------
# three_set_sum_invariant — malformed three_set shapes
# ---------------------------------------------------------------------------


def _three_set_manifest(entry):
    return _Manifest(
        per_output_manifests=(entry,),
        snapshots={"cid1": "sha"},
        source_attributes={},
    )


@pytest.mark.parametrize("three_set", ["evil", 123, ["a"]])
def test_three_set_non_dict_rejects(tmp_path: Path, three_set):
    res = ThreeSetSumInvariantCheck().check(
        tmp_path, _three_set_manifest({"output_id": "o1", "three_set": three_set})
    )
    assert res.ok is False
    assert res.reason_code == "THREE_SET_MALFORMED"


@pytest.mark.parametrize("val", ["abc", 123, {"a": 1}])
def test_three_set_non_list_field_rejects(tmp_path: Path, val):
    res = ThreeSetSumInvariantCheck().check(
        tmp_path,
        _three_set_manifest({"output_id": "o1", "three_set": {"retrieved": val}}),
    )
    assert res.ok is False
    assert res.reason_code == "THREE_SET_MALFORMED"


def test_three_set_unhashable_elements_reject(tmp_path: Path):
    res = ThreeSetSumInvariantCheck().check(
        tmp_path,
        _three_set_manifest({"output_id": "o1", "three_set": {"retrieved": [["x"]]}}),
    )
    assert res.ok is False
    assert res.reason_code == "THREE_SET_MALFORMED"


def test_three_set_unorderable_elements_reject(tmp_path: Path):
    res = ThreeSetSumInvariantCheck().check(
        tmp_path,
        _three_set_manifest({"output_id": "o1", "three_set": {"retrieved": [1, "a"]}}),
    )
    assert res.ok is False
    assert res.reason_code == "THREE_SET_MALFORMED"


def test_three_set_wellformed_still_passes(tmp_path: Path):
    entry = {
        "output_id": "o1",
        "three_set": {
            "retrieved": ["cid1"],
            "context_injected": ["cid1"],
            "quote_supporting": [],
        },
    }
    res = ThreeSetSumInvariantCheck().check(tmp_path, _three_set_manifest(entry))
    assert res.ok is True


# ---------------------------------------------------------------------------
# source_attributes_consistency — non-dict props + hostile provenance log
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("props", ["evil", 123, ["a"]])
def test_source_attributes_non_dict_props_rejects(tmp_path: Path, props):
    m = _Manifest(
        source_attributes={"cid1": props},
        snapshots={"cid1": "sha"},
        decision_provenance_log=None,
    )
    res = SourceAttributesConsistencyCheck().check(tmp_path, m)
    assert res.ok is False
    assert res.reason_code == "SOURCE_ATTRIBUTES_MALFORMED"


@pytest.mark.parametrize(
    "content",
    [
        b"not json\n",  # invalid JSON -> JSONDecodeError
        b"123\n",  # valid JSON non-object -> TypeError on obj["source_cid"]
        b'{"a": 1}\n',  # object missing required fields -> KeyError
        b"\xff\xfe\n",  # invalid UTF-8 -> decode/parse error
    ],
)
def test_provenance_log_malformed_rejects(tmp_path: Path, content):
    (tmp_path / "prov.jsonl").write_bytes(content)
    m = _Manifest(
        source_attributes={},
        snapshots={},
        decision_provenance_log="prov.jsonl",
    )
    res = SourceAttributesConsistencyCheck().check(tmp_path, m)
    assert res.ok is False
    assert res.reason_code == "PROVENANCE_LOG_UNREADABLE"


def test_provenance_log_absent_file_rejects(tmp_path: Path):
    # This plugin runs BEFORE the deep-validation existence check, so an
    # absent log file must be a recorded REJECT, not a FileNotFoundError.
    m = _Manifest(
        source_attributes={},
        snapshots={},
        decision_provenance_log="missing.jsonl",
    )
    res = SourceAttributesConsistencyCheck().check(tmp_path, m)
    assert res.ok is False
    assert res.reason_code == "PROVENANCE_LOG_UNREADABLE"


@pytest.mark.parametrize(
    "evil_path",
    [
        "../../../etc/passwd",  # .. traversal escaping the bundle
        "/etc/passwd",  # absolute path (pathlib `/` absolutizes the join)
        "sub/../../outside.jsonl",  # normalizes outside bundle_dir
    ],
)
def test_provenance_log_path_escape_rejects(tmp_path: Path, evil_path):
    """A bundle-controlled decision_provenance_log that resolves OUTSIDE
    bundle_dir must fail closed at the read site (PROVENANCE_LOG_UNSAFE_PATH),
    never steer an out-of-bundle read. This plugin runs BEFORE the deep
    manifest-validation containment check, and verify() aggregates rather than
    short-circuits, so the containment guard must live here. (Redteam: ChatGPT
    path-containment finding — the read site lacked _safe_bundle_path that its
    sibling plugins already use.)"""
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    # Plant a readable file at the escape target to prove the guard rejects on
    # PATH SHAPE, before any read — not merely because the target is absent.
    (tmp_path / "outside.jsonl").write_text("SECRET\n", encoding="utf-8")
    m = _Manifest(
        source_attributes={"cid1": {"publication_class": "peer_reviewed"}},
        snapshots={"cid1": "sha"},
        decision_provenance_log=evil_path,
    )
    res = SourceAttributesConsistencyCheck().check(bundle, m)
    assert res.ok is False
    assert res.reason_code == "PROVENANCE_LOG_UNSAFE_PATH", res.reason_code
    # The out-of-bundle file content must not appear in the failure detail.
    assert "SECRET" not in res.detail


def test_provenance_log_directory_target_rejects(tmp_path: Path):
    """A decision_provenance_log pointing at a directory fails closed at the
    guard (would otherwise raise IsADirectoryError on read)."""
    (tmp_path / "adir").mkdir()
    m = _Manifest(
        source_attributes={},
        snapshots={},
        decision_provenance_log="adir",
    )
    res = SourceAttributesConsistencyCheck().check(tmp_path, m)
    assert res.ok is False
    assert res.reason_code == "PROVENANCE_LOG_UNSAFE_PATH", res.reason_code


def test_provenance_log_wellformed_still_passes(tmp_path: Path):
    row = {
        "source_cid": "cid1",
        "property_name": "publication_class",
        "decided_by": "human:max@nexi",
        "decided_at": "2026-06-09T00:00:00Z",
        "policy_version": "props_v0.1+iv_v0.1",
        "new_value": "peer_reviewed",
    }
    (tmp_path / "prov.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
    m = _Manifest(
        source_attributes={},
        snapshots={},
        decision_provenance_log="prov.jsonl",
    )
    res = SourceAttributesConsistencyCheck().check(tmp_path, m)
    assert res.ok is True


# ---------------------------------------------------------------------------
# monotone_growth — unreadable / malformed corpus.jsonl
# ---------------------------------------------------------------------------


def _corpus_bundle(tmp_path: Path, current: bytes, prior: bytes) -> None:
    (tmp_path / "corpus").mkdir()
    (tmp_path / "previous_corpus").mkdir()
    (tmp_path / "corpus" / "v2").write_bytes(current)
    (tmp_path / "previous_corpus" / "v1").write_bytes(prior)


@pytest.mark.parametrize(
    "hostile",
    [
        b"not json\n",  # invalid JSON
        b"[1, 2]\n",  # valid JSON non-object
        b'"foo"\n',  # valid JSON non-object
        b"\xff\xfe\n",  # invalid UTF-8
    ],
)
def test_monotone_growth_malformed_corpus_rejects(tmp_path: Path, hostile):
    _corpus_bundle(tmp_path, hostile, b'{"id": "a"}\n')
    res = MonotoneGrowthCheck("v2", "v1").check(tmp_path, _Manifest())
    assert res.ok is False
    assert res.reason_code == "ADVERSARIAL_CORPUS_UNREADABLE"


def test_monotone_growth_malformed_prior_corpus_rejects(tmp_path: Path):
    _corpus_bundle(tmp_path, b'{"id": "a"}\n', b"[]\n")
    res = MonotoneGrowthCheck("v2", "v1").check(tmp_path, _Manifest())
    assert res.ok is False
    assert res.reason_code == "ADVERSARIAL_CORPUS_UNREADABLE"


def test_monotone_growth_wellformed_still_passes(tmp_path: Path):
    _corpus_bundle(tmp_path, b'{"id": "a"}\n{"id": "b"}\n', b'{"id": "a"}\n')
    res = MonotoneGrowthCheck("v2", "v1").check(tmp_path, _Manifest())
    assert res.ok is True


# ---------------------------------------------------------------------------
# falsification_negative_test — non-object rule file + invalid UTF-8
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content,expected",
    [
        (b"[]", "FALSIFICATION_RULE_SCHEMA_ERROR"),
        (b'"foo"', "FALSIFICATION_RULE_SCHEMA_ERROR"),
        (b"123", "FALSIFICATION_RULE_SCHEMA_ERROR"),
        (b"\xff\xfe", "FALSIFICATION_RULE_PARSE_ERROR"),  # UnicodeDecodeError leg
    ],
)
def test_falsification_hostile_rule_file_rejects(tmp_path: Path, content, expected):
    rules = tmp_path / "falsification_rules"
    rules.mkdir()
    (rules / "rule_x.json").write_bytes(content)
    res = FalsificationNegativeTestCheck().check(tmp_path, _Manifest())
    assert res.ok is False
    assert res.reason_code == expected


# ---------------------------------------------------------------------------
# Unreadable-bytes residual (special file / read error) — file_integrity,
# spec_sha_pin, refinement_discharge obligation read. Simulated by patching
# Path.read_bytes (a FIFO would block the test; a socket path can exceed the
# AF_UNIX limit under pytest tmp dirs).
# ---------------------------------------------------------------------------


def _raise_oserror(self):
    raise OSError("simulated unreadable special file (FIFO/socket)")


def test_file_integrity_unreadable_file_rejects(tmp_path: Path, monkeypatch):
    (tmp_path / "data.bin").write_bytes(b"payload")
    m = _Manifest(files={"data.bin": hashlib.sha256(b"payload").hexdigest()})
    monkeypatch.setattr(Path, "read_bytes", _raise_oserror)
    res = FileIntegrityManySmall().check(tmp_path, m)
    assert res.ok is False
    assert res.reason_code == "BAD_FILE_SHA"
    assert "could not be read" in res.detail


def test_spec_sha_pin_unreadable_spec_rejects(tmp_path: Path, monkeypatch):
    (tmp_path / "spec").mkdir()
    (tmp_path / "spec" / "s.md").write_bytes(b"spec")
    m = _Manifest(
        files={},
        spec_files={"s.md": hashlib.sha256(b"spec").hexdigest()},
        typed_checks=[],
    )
    monkeypatch.setattr(Path, "read_bytes", _raise_oserror)
    res = SpecShaPinCheck().check(tmp_path, m)
    assert res.ok is False
    assert res.reason_code == "SPEC_SHA_MISMATCH"
    assert "could not be read" in res.detail


def test_refinement_discharge_unreadable_obligation_rejects(
    tmp_path: Path, monkeypatch
):
    (tmp_path / "obl.smt2").write_bytes(b"(assert true)")
    record = {
        "proof": {
            "kind": "smt-z3",
            "obligation_uri": "obl.smt2",
            "obligation_sha": hashlib.sha256(b"(assert true)").hexdigest(),
            "discharge_status": "not-attempted",
        }
    }
    m = _Manifest(dispatch_records=(record,), bundle_id="b1")
    monkeypatch.setattr(Path, "read_bytes", _raise_oserror)
    res = RefinementDischargeCheck().check(tmp_path, m)
    assert res.ok is False
    assert res.reason_code == "PROOF_OBLIGATION_MISSING"
    assert "could not be read" in res.detail
