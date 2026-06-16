"""tests/test_stamp_claims_coverage_guard.py — the §C14/§C15 stamp-claims
coverage guard (5th instance of the orphaned-enforcement class, 2026-06-12).

Before this guard, `dispatch_records` (C15 well-formedness) and
`aggregate_stamp` (C14 lattice: "Verifier-set, never dispatcher-trusted") were
parsed by core but enforced only by caller-supplied plugins. The CLI wires
both by default; plugin-less library ``BundleVerifier().verify()`` read OK
over a forged aggregate_stamp=CONFIRMED_EXTERNAL above a per-row min of
UNVERIFIED, and over garbage records nothing had checked (reproduced on
master 588b0167e).

Locked here (tribunal 2026-06-12, Q1/Q2/Q3):
  1. Plugin-less verify() over a forged aggregate → clean-ERROR (could not
     conclude), never OK. Same for rows-only and garbage-rows bundles.
  2. Legacy bundle carrying NEITHER field → OK unchanged (no claim, no
     obligation).
  3. Both plugins wired: honest bundle → OK; forged aggregate → REJECT
     (STAMP_AGGREGATE_ROUNDUP_DETECTED, pre-existing C14 semantics).
  4. Coverage is PER-CONTRACT (Q1: two channels): wiring only the C15 plugin
     leaves the C14 claim uncovered (ERROR) and vice versa — no
     cross-laundering.
  5. Coverage is PROOF, not promise (Q2: content keys, full-array binding):
     a plugin reporting keys for DIFFERENT content does not cover the
     present claim.
  6. Vacuous-pass closed (Q3: plugin tightening): non-None aggregate over
     ZERO rows now REJECTS under the wired C14 plugin (previously passed
     vacuously), and an out-of-enum aggregate rejects independent of row
     count.

Stdlib + pytest only.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit_bundle.plugin import PluginResult
from audit_bundle.plugins.dispatch_record_wellformed import (
    DispatchRecordWellformedCheck,
)
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck
from audit_bundle.stamp_claims import dispatch_record_keys, stamp_claim_key
from audit_bundle.verdict import VerdictState
from audit_bundle.verifier import BundleVerifier

_ROWS = (
    {"schema_version": "0.1", "op": {"kind": "TOOL"}, "stamp_observed": "UNVERIFIED"},
    {"schema_version": "0.1", "op": {"kind": "TOOL"}, "stamp_observed": "TARGET"},
)


def _write_bundle(tmp_path: Path, **extra) -> Path:
    """Minimal integrity-clean bundle (same shape as the verdict-out fixture)."""
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    corpus_dir = bundle_dir / "corpus"
    corpus_dir.mkdir()
    content = b"stamp-claims coverage guard corpus"
    (corpus_dir / "entry0.txt").write_bytes(content)
    manifest = {
        "schema_version": "legacy",
        "bundle_id": "stamp-claims-guard-test",
        "created_at": "2026-01-01T00:00:00Z",
        "files": {"corpus/entry0.txt": hashlib.sha256(content).hexdigest()},
        "spec_files": {},
        "cross_refs": {},
        "payload": {},
        "typed_checks": [],
        "per_output_manifests": [],
        **extra,
    }
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return bundle_dir


def _codes(verdict):
    return [(r.code, r.check_name) for r in verdict.reasons]


def _incomplete_checks(verdict):
    return {r.check_name for r in verdict.reasons if r.code == "VERIFIER_INCOMPLETE"}


# ---------------------------------------------------------------------------
# 1. Plugin-less laundering closed
# ---------------------------------------------------------------------------


def test_pluginless_forged_aggregate_is_error_not_ok(tmp_path):
    bundle = _write_bundle(
        tmp_path,
        dispatch_records=list(_ROWS),
        aggregate_stamp="CONFIRMED_EXTERNAL",  # forged: per-row min is UNVERIFIED
    )
    verdict = BundleVerifier().verify(bundle)
    assert verdict.state is VerdictState.ERROR, _codes(verdict)
    assert verdict.ok is False
    assert _incomplete_checks(verdict) == {"dispatch_records", "aggregate_stamp"}


def test_pluginless_rows_only_is_error(tmp_path):
    """Rows without an aggregate still carry C15 + C14 row-stamp obligations."""
    bundle = _write_bundle(tmp_path, dispatch_records=list(_ROWS))
    verdict = BundleVerifier().verify(bundle)
    assert verdict.state is VerdictState.ERROR, _codes(verdict)
    assert _incomplete_checks(verdict) == {"dispatch_records", "aggregate_stamp"}


def test_pluginless_garbage_rows_is_error(tmp_path):
    """The original repro's garbage rows (bogus stamp enum, missing record
    schema_version, non-dict element) no longer verify OK plugin-less."""
    bundle = _write_bundle(
        tmp_path,
        dispatch_records=[
            {"stamp_observed": "TOTALLY_BOGUS_STAMP"},
            {"op_kind": "??", "whatever": 1},
            "not-even-a-dict",
        ],
    )
    verdict = BundleVerifier().verify(bundle)
    assert verdict.state is VerdictState.ERROR, _codes(verdict)
    assert "dispatch_records" in _incomplete_checks(verdict)


def test_pluginless_aggregate_over_zero_rows_is_error(tmp_path):
    bundle = _write_bundle(tmp_path, aggregate_stamp="TARGET")
    verdict = BundleVerifier().verify(bundle)
    assert verdict.state is VerdictState.ERROR, _codes(verdict)
    assert _incomplete_checks(verdict) == {"aggregate_stamp"}


# ---------------------------------------------------------------------------
# 2. Back-compat: no claim, no obligation
# ---------------------------------------------------------------------------


def test_legacy_bundle_with_neither_field_stays_ok(tmp_path):
    bundle = _write_bundle(tmp_path)
    verdict = BundleVerifier().verify(bundle)
    assert verdict.state is VerdictState.OK, _codes(verdict)


def test_explicit_null_dispatch_records_stays_ok(tmp_path):
    """dispatch_records: null parses to () — the legacy no-claim marker."""
    bundle = _write_bundle(tmp_path, dispatch_records=None)
    verdict = BundleVerifier().verify(bundle)
    assert verdict.state is VerdictState.OK, _codes(verdict)


# ---------------------------------------------------------------------------
# 3. Wired pair: honest OK, forged REJECT
# ---------------------------------------------------------------------------


def _both():
    return [DispatchRecordWellformedCheck(), StampLatticeCheck()]


def test_wired_honest_bundle_is_ok(tmp_path):
    bundle = _write_bundle(
        tmp_path, dispatch_records=list(_ROWS), aggregate_stamp="UNVERIFIED"
    )
    verdict = BundleVerifier(_both()).verify(bundle)
    assert verdict.state is VerdictState.OK, _codes(verdict)


def test_wired_forged_aggregate_rejects(tmp_path):
    bundle = _write_bundle(
        tmp_path, dispatch_records=list(_ROWS), aggregate_stamp="CONFIRMED_EXTERNAL"
    )
    verdict = BundleVerifier(_both()).verify(bundle)
    assert verdict.state is VerdictState.REJECT, _codes(verdict)
    assert any(
        r.check_name == "typed_check_plugins:stamp_lattice"
        and "exceeds per-row min" in r.detail
        for r in verdict.reasons
    )


# ---------------------------------------------------------------------------
# 4. Per-contract channels — no cross-laundering (tribunal Q1)
# ---------------------------------------------------------------------------


def test_c15_only_leaves_c14_claim_uncovered(tmp_path):
    bundle = _write_bundle(
        tmp_path, dispatch_records=list(_ROWS), aggregate_stamp="UNVERIFIED"
    )
    verdict = BundleVerifier([DispatchRecordWellformedCheck()]).verify(bundle)
    assert verdict.state is VerdictState.ERROR, _codes(verdict)
    assert _incomplete_checks(verdict) == {"aggregate_stamp"}


def test_c14_only_leaves_c15_records_uncovered(tmp_path):
    bundle = _write_bundle(
        tmp_path, dispatch_records=list(_ROWS), aggregate_stamp="UNVERIFIED"
    )
    verdict = BundleVerifier([StampLatticeCheck()]).verify(bundle)
    assert verdict.state is VerdictState.ERROR, _codes(verdict)
    assert _incomplete_checks(verdict) == {"dispatch_records"}


# ---------------------------------------------------------------------------
# 5. Coverage is proof, not promise (tribunal Q2)
# ---------------------------------------------------------------------------


class _LazyPlugin:
    """Hostile/lazy plugin claiming coverage of content that is NOT present."""

    name = "lazy_claimer"
    applies_to_files: frozenset[str] = frozenset()

    def check(self, bundle_dir, manifest):
        other_rows = [{"schema_version": "0.1", "stamp_observed": "CONFIRMED_EXTERNAL"}]
        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail="claims coverage of different bytes",
            files_audited=(),
            verified_dispatch_records=dispatch_record_keys(other_rows),
            verified_stamp_claims=frozenset(
                {stamp_claim_key("CONFIRMED_EXTERNAL", other_rows)}
            ),
        )


def test_lazy_plugin_claiming_other_content_does_not_cover(tmp_path):
    bundle = _write_bundle(
        tmp_path, dispatch_records=list(_ROWS), aggregate_stamp="UNVERIFIED"
    )
    verdict = BundleVerifier([_LazyPlugin()]).verify(bundle)
    assert verdict.state is VerdictState.ERROR, _codes(verdict)
    assert _incomplete_checks(verdict) == {"dispatch_records", "aggregate_stamp"}


def test_c14_key_binds_full_records_array(tmp_path):
    """Full-array binding: the same aggregate over different rows is a
    DIFFERENT claim — a key computed over other rows cannot cover it."""
    assert stamp_claim_key("UNVERIFIED", list(_ROWS)) != stamp_claim_key(
        "UNVERIFIED", list(_ROWS)[:1]
    )
    assert stamp_claim_key("UNVERIFIED", list(_ROWS)) != stamp_claim_key(
        "TARGET", list(_ROWS)
    )


# ---------------------------------------------------------------------------
# 6. Wired vacuous-pass closed (tribunal Q3 — plugin tightening)
# ---------------------------------------------------------------------------


def test_wired_aggregate_over_zero_rows_rejects(tmp_path):
    bundle = _write_bundle(tmp_path, aggregate_stamp="TARGET")
    verdict = BundleVerifier(_both()).verify(bundle)
    assert verdict.state is VerdictState.REJECT, _codes(verdict)
    assert any(
        "aggregate claim over zero rows is unsupportable" in r.detail
        for r in verdict.reasons
    )


def test_wired_out_of_enum_aggregate_rejects_independent_of_rows(tmp_path):
    bundle = _write_bundle(tmp_path, aggregate_stamp="BOGUS_STAMP")
    verdict = BundleVerifier(_both()).verify(bundle)
    assert verdict.state is VerdictState.REJECT, _codes(verdict)
    assert any("not in the C14" in r.detail for r in verdict.reasons)
