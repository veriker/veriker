"""tests/test_dispatch_comparator_fail_closed.py — comparator/claimed-value
fail-closed boundary (M4 regression).

Redteam finding: the recompute call in run_spec_pinned_dispatch was wrapped
(-> RECOMPUTE_ERROR), but the comparator call was NOT. A deeply-nested claimed
value read from outputs/<id>.json drives _freeze/_cmp_* into RecursionError,
which escaped the per-output loop and propagated to the fail-closed boundary as
a crash (could-not-conclude / exit 2) instead of the correct fail-closed REJECT
(exit 1) — a denial-of-correct-verdict, and a contradiction of the module's own
"every per-output evaluation is wrapped" contract.

Two boundaries are asserted:
  * a deeply-nested claimed JSON file fails closed at the claimed-value parse
    (CLAIMED_VALUE_MALFORMED), never an uncaught RecursionError crash;
  * a comparator that raises is recorded as COMPARATOR_ERROR (fail-closed),
    never propagated — proving the comparator call is wrapped like recompute.

Self-contained (mirrors test_dispatch_output_id_safety's minimal anchored bundle)
so it ships and runs inside the open-tier export.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from audit_bundle.rederivation import dispatch as D
from audit_bundle.rederivation.dispatch import run_spec_pinned_dispatch
from audit_bundle.rederivation.spec_binding import SpecAnchor

_SPEC_BASENAME = "redteam.spec.json"
_SPEC_ID = "redteam-comparator-fail-closed"
_TYPE_KEY = "t1"


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
                "primitive_id": "noop-unregistered",
                "comparator": {"kind": "set", "params": {}},
            }
        },
    }
    raw = json.dumps(spec).encode("utf-8")
    (bundle / "spec" / _SPEC_BASENAME).write_bytes(raw)
    anchor = SpecAnchor(allowed={_SPEC_ID: hashlib.sha256(raw).hexdigest()})
    manifest = _Manifest(spec_files=[_SPEC_BASENAME], outputs=outputs)
    return bundle, manifest, anchor


def _write_claimed(bundle: Path, output_id: str, raw: bytes) -> None:
    out_dir = bundle / "outputs"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{output_id}.json").write_bytes(raw)


def test_very_deeply_nested_claimed_json_fails_closed_at_parse(tmp_path):
    """A claimed-value file nested deeply enough that json.loads itself raises
    RecursionError must be a recorded fail-closed CLAIMED_VALUE_MALFORMED, never
    an uncaught crash (json's C scanner tolerates ~thousands of levels, so this
    uses a depth past that)."""
    output_id = "deep_value"
    bundle, manifest, anchor = _anchored_bundle(
        tmp_path, [{"output_id": output_id, "type": _TYPE_KEY}]
    )
    depth = 50_000
    raw = b'{"value":' + b"[" * depth + b"]" * depth + b"}"
    _write_claimed(bundle, output_id, raw)

    # Must NOT raise — the call returns a recorded failure list.
    failures = run_spec_pinned_dispatch(bundle, manifest, anchor)
    codes = {f.reason_code for f in failures}
    assert "CLAIMED_VALUE_MALFORMED" in codes, codes


def test_comparator_that_raises_is_recorded_not_propagated(tmp_path, monkeypatch):
    """The PRIMARY M4 path, made deterministic: a comparator that raises
    RecursionError (as the real `set`/`_freeze` does on a moderately-nested
    claimed value — too shallow for json.loads to reject but past the Python
    recursion limit) must be recorded as a fail-closed COMPARATOR_ERROR, never
    propagated to a could-not-conclude crash. (A depth-based end-to-end test is
    intentionally avoided — the json-vs-_freeze threshold gap depends on ambient
    stack depth and is flaky across run contexts.)"""
    output_id = "v1"
    bundle, manifest, anchor = _anchored_bundle(
        tmp_path, [{"output_id": output_id, "type": _TYPE_KEY}]
    )
    _write_claimed(bundle, output_id, json.dumps({"value": [1, 2, 3]}).encode())

    class _FakePrimitive:
        primitive_id = "noop-unregistered"

        def recompute(self, inputs, pack_section):
            from audit_bundle.plugin import RecomputedValue

            return RecomputedValue(value=[1, 2, 3], detail="")

    def _raising_comparator(_re, _claimed, _params):
        raise RecursionError("maximum recursion depth exceeded")

    # Reach the comparator: stub primitive resolution + comparator resolution.
    monkeypatch.setattr(D, "resolve_primitive", lambda _pid: _FakePrimitive())
    monkeypatch.setattr(D, "resolve_comparator", lambda _kind: _raising_comparator)

    failures = run_spec_pinned_dispatch(bundle, manifest, anchor)
    codes = {f.reason_code for f in failures}
    assert "COMPARATOR_ERROR" in codes, codes
    # One result per declared output — the wrapped failure satisfies the
    # cardinality guard (no CARDINALITY_VIOLATION from a dropped output).
    assert "CARDINALITY_VIOLATION" not in codes, codes
