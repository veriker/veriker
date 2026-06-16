"""tests/test_dispatch_nonfinite_value_fail_closed.py — the non-finite boundary
(THREAT_MODEL attack #13 / VERIFIER_CONTRACT C-9).

Redteam finding (ChatGPT, redteam mirror): re-derivation primitives recompute in
native binary64 and the producer's claimed value is read from outputs/<id>.json
with stdlib `json`, which round-trips the non-standard `Infinity`/`NaN` tokens.
A producer can therefore commit an input that OVERFLOWS the (faithfully mirrored)
arithmetic to `inf` and CLAIM `Infinity`; `exact` (`inf == inf` is True), and
likewise `structured`/`set` over a non-finite field, would bless it GREEN —
"emissions = infinity" certified.

The fix lives at the dispatch chokepoint, not in one comparator: before any
comparator runs, dispatch walks BOTH the recomputed value and the claimed value
(through nested lists/dicts) and a non-finite float on either side is a
fail-closed REJECT (`NON_FINITE_VALUE`). This lifts the per-operand guard that
`scalar_epsilon` already had to a boundary that holds for every comparator kind.

Two boundaries asserted here, plus a no-regression check:
  * a non-finite CLAIMED scalar under an `exact` comparator -> NON_FINITE_VALUE
    (not a GREEN `inf == inf`);
  * a non-finite field nested inside a CLAIMED structured/list value -> rejected
    (the laundering is not comparator-specific);
  * a finite claimed value still PASSES (the boundary does not over-reject).

Self-contained (mirrors test_dispatch_comparator_fail_closed's minimal anchored
bundle) so it ships and runs inside the open-tier export.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from audit_bundle.plugin import RecomputedValue
from audit_bundle.rederivation import dispatch as D
from audit_bundle.rederivation.dispatch import run_spec_pinned_dispatch
from audit_bundle.rederivation.spec_binding import SpecAnchor

_SPEC_BASENAME = "redteam_nonfinite.spec.json"
_SPEC_ID = "redteam-nonfinite-boundary"
_TYPE_KEY = "t1"


class _Manifest:
    def __init__(self, spec_files, outputs):
        self.spec_files = spec_files
        self.outputs = outputs


def _anchored_bundle(tmp_path: Path, comparator: dict, outputs):
    bundle = tmp_path / "bundle"
    (bundle / "spec").mkdir(parents=True, exist_ok=True)
    spec = {
        "spec_id": _SPEC_ID,
        "types": {
            _TYPE_KEY: {
                "primitive_id": "noop-nonfinite",
                "comparator": comparator,
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


def _stub_primitive(value):
    class _P:
        primitive_id = "noop-nonfinite"

        def recompute(self, inputs, pack_section):
            return RecomputedValue(value=value, detail="stub")

    return _P()


def _run(tmp_path, comparator, recomputed, claimed_raw, monkeypatch):
    output_id = "v1"
    bundle, manifest, anchor = _anchored_bundle(
        tmp_path, comparator, [{"output_id": output_id, "type": _TYPE_KEY}]
    )
    _write_claimed(bundle, output_id, claimed_raw)
    monkeypatch.setattr(
        D, "resolve_primitive", lambda _pid: _stub_primitive(recomputed)
    )
    failures = run_spec_pinned_dispatch(bundle, manifest, anchor)
    return {f.reason_code for f in failures}


def test_claimed_infinity_scalar_exact_is_rejected_not_blessed(tmp_path, monkeypatch):
    """recompute=inf, claim=Infinity, exact comparator. `inf == inf` would be
    True; the non-finite boundary must REJECT before the comparator runs."""
    codes = _run(
        tmp_path,
        {"kind": "exact", "params": {}},
        recomputed=float("inf"),
        claimed_raw=b'{"value": Infinity}',
        monkeypatch=monkeypatch,
    )
    assert "NON_FINITE_VALUE" in codes, codes
    assert "REDERIVATION_MISMATCH" not in codes, codes


def test_claimed_nan_scalar_is_rejected(tmp_path, monkeypatch):
    codes = _run(
        tmp_path,
        {"kind": "exact", "params": {}},
        recomputed=1.0,
        claimed_raw=b'{"value": NaN}',
        monkeypatch=monkeypatch,
    )
    assert "NON_FINITE_VALUE" in codes, codes


def test_nonfinite_recomputed_side_is_rejected(tmp_path, monkeypatch):
    """The overflow can live on the verifier's own recompute (faithfully mirrored
    arithmetic that overflowed). A finite claim must not let it through."""
    codes = _run(
        tmp_path,
        {"kind": "scalar_epsilon", "params": {"epsilon": 1e-6}},
        recomputed=float("-inf"),
        claimed_raw=b'{"value": 0.0}',
        monkeypatch=monkeypatch,
    )
    assert "NON_FINITE_VALUE" in codes, codes


def test_nonfinite_nested_in_structured_claim_is_rejected(tmp_path, monkeypatch):
    """Laundering is not comparator-specific: a non-finite float nested inside a
    list/record claimed value is caught by the structure-walking boundary, even
    though the comparator (set, here) does value-equality that would match
    inf==inf field-wise."""
    codes = _run(
        tmp_path,
        {"kind": "set", "params": {}},
        recomputed=[1.0, float("inf"), 3.0],
        claimed_raw=b'{"value": [1.0, Infinity, 3.0]}',
        monkeypatch=monkeypatch,
    )
    assert "NON_FINITE_VALUE" in codes, codes


def test_finite_value_still_passes(tmp_path, monkeypatch):
    """No over-rejection: a finite recompute equal to a finite claim PASSES."""
    codes = _run(
        tmp_path,
        {"kind": "exact", "params": {}},
        recomputed=42.5,
        claimed_raw=b'{"value": 42.5}',
        monkeypatch=monkeypatch,
    )
    assert codes == set(), codes
