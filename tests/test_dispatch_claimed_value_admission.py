"""tests/test_dispatch_claimed_value_admission.py — RES-02: the producer-claimed
value clears the shared admission gate.

Redteam finding (ChatGPT, redteam mirror): outputs/<output_id>.json — the
producer's claimed value, the most bundle-controlled read on the dispatch
path — was parsed with raw json.loads(claimed_path.read_bytes()) instead of
admission.admit_json_file. RecursionError was already caught (fail-closed,
no crash), but the memory allocation and the parser recursion happened BEFORE
rejection: a multi-GiB or deeply-nested claimed value did its damage first
and got rejected second. The same gap held for the in-bundle spec copy
(spec_binding.py), which was parsed BEFORE the anchor-authority check.

Boundaries asserted here:
  * a depth-bomb claimed value -> CLAIMED_VALUE_MALFORMED, rejected by the
    pre-parse depth scan (cheap structural check, parser never recurses);
  * an oversize claimed value -> CLAIMED_VALUE_MALFORMED, rejected by stat()
    BEFORE read_bytes() (no allocation);
  * a valid claimed value still passes (no over-reject);
  * a depth-bomb spec copy -> MalformedSpec (clean), even when the spec is
    NOT in the anchor (parse used to run before authority was established);
  * the C9.1 line scans tolerate a depth-bomb line the way they tolerate a
    malformed one (pre-fix: a 100k-deep line drove json.loads to
    RecursionError, which ESCAPED their (JSONDecodeError, ValueError)
    tolerance and crashed the verifier — verified against the pre-fix code);
  * iter_admitted_jsonl_tolerant skips bad lines, yields good rows, and fails
    CLOSED on an oversize file.

Self-contained (mirrors test_dispatch_nonfinite_value_fail_closed's minimal
anchored bundle) so it ships and runs inside the open-tier export.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from audit_bundle.admission import InputInadmissible, iter_admitted_jsonl_tolerant
from audit_bundle.extensions.c9_1_append_only_files import (
    _check_all_attributed,
    _check_first_match,
)
from audit_bundle.plugin import RecomputedValue
from audit_bundle.rederivation import dispatch as D
from audit_bundle.rederivation.dispatch import run_spec_pinned_dispatch
from audit_bundle.rederivation.spec_binding import (
    MalformedSpec,
    SpecAnchor,
    build_anchored_spec_set,
)

_SPEC_BASENAME = "res02_admission.spec.json"
_SPEC_ID = "res02-claimed-value-admission"
_TYPE_KEY = "t1"

# Deep enough to breach AdmissionLimits.max_depth (64) by an order of
# magnitude, far below CPython's recursion limit — the point is that the
# STRUCTURAL scan rejects it, the parser never sees it.
_DEPTH_BOMB = b'{"value": ' + b"[" * 600 + b"1" + b"]" * 600 + b"}"


class _Manifest:
    def __init__(self, spec_files, outputs):
        self.spec_files = spec_files
        self.outputs = outputs


def _anchored_bundle(tmp_path: Path, outputs):
    bundle = tmp_path / "bundle"
    (bundle / "spec").mkdir(parents=True, exist_ok=True)
    spec = {
        "spec_id": _SPEC_ID,
        "types": {
            _TYPE_KEY: {
                "primitive_id": "noop-res02",
                "comparator": {"kind": "exact", "params": {}},
            }
        },
    }
    raw = json.dumps(spec).encode("utf-8")
    (bundle / "spec" / _SPEC_BASENAME).write_bytes(raw)
    anchor = SpecAnchor(allowed={_SPEC_ID: hashlib.sha256(raw).hexdigest()})
    manifest = _Manifest(spec_files=[_SPEC_BASENAME], outputs=outputs)
    return bundle, manifest, anchor


def _stub_primitive(value):
    class _P:
        primitive_id = "noop-res02"

        def recompute(self, inputs, pack_section):
            return RecomputedValue(value=value, detail="stub")

    return _P()


def _run(tmp_path, claimed_raw, monkeypatch, *, sparse_bytes: int | None = None):
    output_id = "v1"
    bundle, manifest, anchor = _anchored_bundle(
        tmp_path, [{"output_id": output_id, "type": _TYPE_KEY}]
    )
    out_dir = bundle / "outputs"
    out_dir.mkdir(parents=True, exist_ok=True)
    claimed = out_dir / f"{output_id}.json"
    if sparse_bytes is not None:
        # A sparse file: stat() reports the size with no disk/alloc cost,
        # which is exactly the boundary under test (size-reject BEFORE read).
        with claimed.open("wb") as fh:
            fh.truncate(sparse_bytes)
    else:
        claimed.write_bytes(claimed_raw)
    monkeypatch.setattr(D, "resolve_primitive", lambda _pid: _stub_primitive(1))
    return run_spec_pinned_dispatch(bundle, manifest, anchor)


def test_depth_bomb_claimed_value_rejected_clean(tmp_path, monkeypatch):
    failures = _run(tmp_path, _DEPTH_BOMB, monkeypatch)
    codes = {f.reason_code for f in failures}
    assert "CLAIMED_VALUE_MALFORMED" in codes, codes
    [failure] = [f for f in failures if f.reason_code == "CLAIMED_VALUE_MALFORMED"]
    assert "depth" in failure.detail, failure.detail


def test_oversize_claimed_value_rejected_before_allocation(tmp_path, monkeypatch):
    failures = _run(
        tmp_path, b"", monkeypatch, sparse_bytes=17 * 1024 * 1024
    )  # > 16 MiB default
    codes = {f.reason_code for f in failures}
    assert "CLAIMED_VALUE_MALFORMED" in codes, codes
    [failure] = [f for f in failures if f.reason_code == "CLAIMED_VALUE_MALFORMED"]
    assert "exceeds max" in failure.detail, failure.detail


def test_valid_claimed_value_still_passes(tmp_path, monkeypatch):
    failures = _run(tmp_path, b'{"value": 1}', monkeypatch)
    assert failures == [], [f.reason_code for f in failures]


def test_depth_bomb_spec_copy_is_malformed_spec_not_crash(tmp_path):
    """The in-bundle spec copy is parsed BEFORE the anchor-authority check, so
    a hostile NON-anchored spec must still hit a bounded parse."""
    bundle = tmp_path / "bundle"
    (bundle / "spec").mkdir(parents=True)
    (bundle / "spec" / "bomb.spec.json").write_bytes(b"[" * 600 + b"{}" + b"]" * 600)
    manifest = _Manifest(spec_files=["bomb.spec.json"], outputs=[])
    anchor = SpecAnchor(allowed={"unrelated": "0" * 64})
    with pytest.raises(MalformedSpec):
        build_anchored_spec_set(bundle, manifest, anchor)


def _bomb_line() -> bytes:
    # 100k nesting GENUINELY crashes the pre-fix scanners (verified on master:
    # RecursionError escapes _check_first_match's except tuple); the 600-deep
    # bomb elsewhere in this file is below CPython's parser tolerance and
    # exists to show the 64-depth admission bound rejects long before the
    # parser is ever at risk.
    n = 100_000
    return b"[" * n + b"1" + b"]" * n


def test_c9_1_first_match_tolerates_depth_bomb_line(tmp_path):
    """Pre-fix this CRASHED: RecursionError out of json.loads escaped the
    (JSONDecodeError, ValueError) tolerance. A depth-bomb line must be skipped
    like a malformed one, and a later honest match still found."""
    log = tmp_path / "events.jsonl"
    log.write_bytes(_bomb_line() + b"\n" + b'{"who": "writer-1"}\n')
    assert _check_first_match(log, "events.jsonl", "who", "test_plugin") is None


def test_c9_1_all_attributed_counts_depth_bomb_as_missing(tmp_path):
    log = tmp_path / "events.jsonl"
    log.write_bytes(b'{"who": "writer-1"}\n' + _bomb_line() + b"\n")
    failure = _check_all_attributed(log, "events.jsonl", "who", "test_plugin")
    assert failure is not None  # cannot certify the bombed record
    assert "1" in failure.detail


def test_tolerant_iterator_skips_bad_lines_and_rejects_oversize(tmp_path):
    good = tmp_path / "rows.jsonl"
    good.write_bytes(
        b'{"a": 1}\n' + _bomb_line() + b"\n" + b"not json\n" + b'{"b": 2}\n'
    )
    assert list(iter_admitted_jsonl_tolerant(good)) == [{"a": 1}, {"b": 2}]

    big = tmp_path / "big.jsonl"
    with big.open("wb") as fh:
        fh.truncate(17 * 1024 * 1024)
    with pytest.raises(InputInadmissible):
        list(iter_admitted_jsonl_tolerant(big))
