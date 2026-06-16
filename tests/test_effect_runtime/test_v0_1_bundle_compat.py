"""V15 — v0.1 backward-compatibility tests.

s15-011 deliverable: confirm that pre-V15 bundles (no
`effect_enforcement_mode` field, no `execution_trace`) verify exactly
as v0.1. The V15 branch is opt-in; a bundle that does not opt in
must see no behavior change.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from audit_bundle.discharge.verifier_signing import VerifierSigningKey
from audit_bundle.plugins.dispatch_record_wellformed import (
    DispatchRecordWellformedCheck,
)


_KEY = VerifierSigningKey(
    verifier_id="v-kernel-test",
    secret=b"v15-compat-secret-32bytes-pad!!!",
)


class _Manifest:
    def __init__(self, dispatch_records=()):
        self.dispatch_records = dispatch_records
        self.bundle_id = "bundle-v0-1-compat"
        self.created_at = "2026-05-03T12:00:00Z"
        self.per_output_manifests = ()
        self.schema_version = "vcp-v1.1-canary4"


def _legacy_record(*, effect=None) -> dict:
    """A v0.1-shaped dispatch_record — no effect_enforcement_mode,
    no execution_trace, no V15-era fields."""
    return {
        "schema_version": "0.1",
        "op": {"kind": "COMPUTE", "name": "score"},
        "inputs": [],
        "outputs": [
            {"name": "r", "type": {"base": "Int", "refine": "(>= r 0)"}},
        ],
        "effect": effect if effect is not None else {},
        "locale": "en-US",
        "predicates": [],
        "stamp_declared": "INTERNAL_BENCHMARK",
        "stamp_observed": "INTERNAL_BENCHMARK",
    }


# ---------------------------------------------------------------------------
# v0.1 bundles — no V15 fields, plugin without recheck_key
# ---------------------------------------------------------------------------


def test_v0_1_pure_compute_passes_no_key(tmp_path):
    rec = _legacy_record(effect={})
    plugin = DispatchRecordWellformedCheck()  # no key
    res = plugin.check(tmp_path, _Manifest(dispatch_records=(rec,)))
    assert res.ok is True


def test_v0_1_with_locked_effect_passes_no_key(tmp_path):
    rec = _legacy_record(effect={"net": [], "fs": []})
    plugin = DispatchRecordWellformedCheck()
    res = plugin.check(tmp_path, _Manifest(dispatch_records=(rec,)))
    assert res.ok is True


def test_v0_1_with_reserved_advisory_passes_no_key(tmp_path):
    """Reserved labels are advisory at v0.1 — they DON'T fail the
    plugin even though they have no v0.2 enforcement story. The
    rejection only applies under mode='wasm', which legacy bundles
    don't claim."""
    rec = _legacy_record(effect={"db": [], "subprocess": []})
    plugin = DispatchRecordWellformedCheck()
    res = plugin.check(tmp_path, _Manifest(dispatch_records=(rec,)))
    assert res.ok is True
    # Detail string mentions the advisory count.
    assert "advisor" in res.detail.lower() or "reserved" in res.detail.lower()


def test_v0_1_with_unknown_effect_still_rejects(tmp_path):
    """Backward-compat doesn't extend to unknown labels — those are
    well-formedness violations and continue to reject as v0.1 did."""
    rec = _legacy_record(effect={"made_up_label": []})
    plugin = DispatchRecordWellformedCheck()
    res = plugin.check(tmp_path, _Manifest(dispatch_records=(rec,)))
    assert res.ok is False
    assert res.reason_code == "EFFECT_LABEL_UNKNOWN"


def test_v0_1_with_recheck_key_still_passes(tmp_path):
    """Wiring a key on the plugin does NOT change behavior on a v0.1
    bundle (no mode field → no V15 branch). Important so production
    deployments can pre-wire the key without breaking legacy bundles."""
    rec = _legacy_record(effect={"net": []})
    plugin = DispatchRecordWellformedCheck(recheck_key=_KEY)
    res = plugin.check(tmp_path, _Manifest(dispatch_records=(rec,)))
    assert res.ok is True


# ---------------------------------------------------------------------------
# Mixed bundles — v0.1 records alongside V15 mode='advisory' records
# ---------------------------------------------------------------------------


def test_mixed_v0_1_and_advisory_passes(tmp_path):
    rec_legacy = _legacy_record(effect={"net": []})
    rec_advisory = _legacy_record(effect={"fs": []})
    rec_advisory["effect_enforcement_mode"] = "advisory"
    plugin = DispatchRecordWellformedCheck()
    res = plugin.check(
        tmp_path,
        _Manifest(dispatch_records=(rec_legacy, rec_advisory)),
    )
    assert res.ok is True


# ---------------------------------------------------------------------------
# Empty bundle — no dispatch_records at all (pre-Phase-0 / W3-baseline)
# ---------------------------------------------------------------------------


def test_no_dispatch_records_passes(tmp_path):
    """Empty dispatch_records is the W3-baseline / pre-Phase-0 case."""
    plugin = DispatchRecordWellformedCheck(recheck_key=_KEY)
    res = plugin.check(tmp_path, _Manifest(dispatch_records=()))
    assert res.ok is True
