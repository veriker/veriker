"""tests/test_integration_c14_c15_c16.py — Integration: C14/C15/C16 through BundleVerifier.

Exercises BundleVerifier with default_post_w3_plugin_set() against synthesized bundles.
Proves the three plugins compose cleanly through verifier.py and that each named
reason code is reachable end-to-end.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from audit_bundle.verifier import BundleVerifier, VerifyResult
from audit_bundle.plugins import default_post_w3_plugin_set

# ---------------------------------------------------------------------------
# Module-level verifier — C15 → C14 → C16 plugin order
# ---------------------------------------------------------------------------

_VERIFIER = BundleVerifier(plugins=default_post_w3_plugin_set())


# ---------------------------------------------------------------------------
# Bundle builder helper
# ---------------------------------------------------------------------------


def _build_bundle(
    tmp_path: Path,
    dispatch_records,
    aggregate_stamp: str | None,
    output_mode_signal: dict | None = None,
    per_output_manifests: tuple = (),
) -> Path:
    """Write a minimal bundle dir with manifest.json. Returns bundle_dir Path."""
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    manifest: dict = {
        "schema_version": "legacy",
        "bundle_id": "test-bundle",
        "created_at": "2026-05-01T00:00:00Z",
        "files": {},
        "spec_files": {},
        "cross_refs": {},
        "payload": {},
        "typed_checks": [],
        "per_output_manifests": list(per_output_manifests),
        "dispatch_records": dispatch_records,
        "aggregate_stamp": aggregate_stamp,
    }
    if output_mode_signal is not None:
        manifest["output_mode_signal"] = output_mode_signal
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return bundle_dir


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _stamp(s: str) -> str:
    """Shorthand: stamp strings are plain strings in this implementation."""
    return s


def _good_record(
    op_kind: str = "COMPUTE",
    effect: dict | None = None,
    outputs: list | None = None,
    stamp_observed: str | None = "UNVERIFIED",
) -> dict:
    return {
        "schema_version": "0.1",
        "op": {"kind": op_kind},
        "effect": {} if effect is None else effect,
        "outputs": [] if outputs is None else outputs,
        "stamp_observed": stamp_observed,
    }


def _plugin_detail(result: VerifyResult, plugin_name: str) -> str:
    """Return the failure detail from the named plugin, or '' if no failure."""
    for f in result.failures:
        if f.check_name == f"typed_check_plugins:{plugin_name}":
            return f.detail
    return ""


def _assert_plugin_failed(
    result: VerifyResult, plugin_name: str, substr: str = ""
) -> None:
    assert result.ok is False
    detail = _plugin_detail(result, plugin_name)
    assert detail, f"Expected plugin {plugin_name!r} to have failed, but it did not"
    if substr:
        assert substr in detail, f"Expected {substr!r} in detail: {detail!r}"


# ============================================================================
# HAPPY PATH
# ============================================================================


def test_w3_baseline_bundle_passes(tmp_path):
    """No dispatch_records + no aggregate_stamp: all three plugins are no-op."""
    bundle_dir = _build_bundle(tmp_path, [], None)
    result = _VERIFIER.verify(bundle_dir)
    assert result.ok is True
    assert result.failures == []


def test_one_dispatch_record_minimum(tmp_path):
    """Single minimal COMPUTE record passes all three plugins."""
    record = _good_record(stamp_observed=_stamp("UNVERIFIED"))
    bundle_dir = _build_bundle(tmp_path, [record], _stamp("UNVERIFIED"))
    result = _VERIFIER.verify(bundle_dir)
    assert result.ok is True


def test_three_records_full_shape(tmp_path):
    """Three records with mixed op.kinds, full effect set, and valid refine formula all pass."""
    tool_rec = _good_record(op_kind="TOOL", stamp_observed=_stamp("INTERNAL_BENCHMARK"))
    model_rec = _good_record(
        op_kind="MODEL_CALL",
        effect={
            "net": True,
            "fs": False,
            "model": "gpt-stub",
            "llm_spend_usd": 0.01,
            "time_bound_ms": 5000,
            "locale_bound": "en-US",
        },
        stamp_observed=_stamp("INTERNAL_BENCHMARK"),
    )
    compute_rec = _good_record(
        op_kind="COMPUTE",
        outputs=[
            {
                "type": {
                    "name": "Float",
                    "refine": "(= edge_attribution_sum total_impact)",
                }
            }
        ],
        stamp_observed=_stamp("INTERNAL_BENCHMARK"),
    )
    bundle_dir = _build_bundle(
        tmp_path, [tool_rec, model_rec, compute_rec], _stamp("INTERNAL_BENCHMARK")
    )
    result = _VERIFIER.verify(bundle_dir)
    assert result.ok is True


def test_record_with_proof_not_attempted(tmp_path):
    """Proof field with discharge_status='not-attempted' and matching file passes C16."""
    proof_content = b"theorem main : 1 + 1 = 2 := rfl"
    proof_sha = hashlib.sha256(proof_content).hexdigest()
    record = {
        "schema_version": "0.1",
        "op": {"kind": "COMPUTE"},
        "effect": {},
        "outputs": [],
        "stamp_observed": "UNVERIFIED",
        "proof": {
            "kind": "lean-4",
            "obligation_uri": "proofs/main.lean",
            "obligation_sha": proof_sha,
            "discharge_status": "not-attempted",
        },
    }
    bundle_dir = _build_bundle(tmp_path, [record], None)
    (bundle_dir / "proofs").mkdir()
    (bundle_dir / "proofs" / "main.lean").write_bytes(proof_content)
    # The proof file must be DECLARED like any other bundle member — the core
    # conservation gate (and the Pass-3 sweep before it) rejects undeclared
    # on-disk files; the C16 obligation_sha pin composes with, not replaces,
    # files{} ownership.
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["proofs/main.lean"] = proof_sha
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = _VERIFIER.verify(bundle_dir)
    assert result.ok is True


# ============================================================================
# REASON-CODE COVERAGE
# ============================================================================


def test_dispatch_record_field_absent(tmp_path, monkeypatch):
    """C15: DISPATCH_RECORD_FIELD_ABSENT — per_output_manifests present but dispatch_records empty.

    Cardinality enforcement gates on Phase-0-cutover schema versions; v0.1 ships
    with an empty cutover set so legacy bundles pass cleanly. Inject 'legacy' so
    the negative-test path is exercised.
    """
    from audit_bundle.plugins import dispatch_record_wellformed as _drw_mod

    monkeypatch.setattr(
        _drw_mod,
        "_PHASE_0_CUTOVER_SCHEMA_VERSIONS",
        frozenset({"legacy"}),
    )
    bundle_dir = _build_bundle(
        tmp_path, [], None, per_output_manifests=({"output_id": "o1"},)
    )
    result = _VERIFIER.verify(bundle_dir)
    _assert_plugin_failed(
        result, "dispatch_record_wellformed", "dispatch_records is empty"
    )


def test_schema_version_unrecognized(tmp_path):
    """C15: SCHEMA_VERSION_UNRECOGNIZED — record carries schema_version='0.2'."""
    record = {**_good_record(), "schema_version": "0.2"}
    bundle_dir = _build_bundle(tmp_path, [record], None)
    result = _VERIFIER.verify(bundle_dir)
    _assert_plugin_failed(result, "dispatch_record_wellformed", "not recognized")


def test_op_kind_out_of_enum(tmp_path):
    """C15: OP_KIND_OUT_OF_ENUM — record.op.kind is not in the recognized enum."""
    record = _good_record(op_kind="UNKNOWN_OP")
    bundle_dir = _build_bundle(tmp_path, [record], None)
    result = _VERIFIER.verify(bundle_dir)
    _assert_plugin_failed(
        result, "dispatch_record_wellformed", "not in the recognized enum"
    )


def test_effect_label_unknown(tmp_path):
    """C15: EFFECT_LABEL_UNKNOWN — record.effect uses a label outside the v0.1 vocabulary."""
    record = _good_record(effect={"mystery_label": []})
    bundle_dir = _build_bundle(tmp_path, [record], None)
    result = _VERIFIER.verify(bundle_dir)
    _assert_plugin_failed(
        result, "dispatch_record_wellformed", "not in the v0.1 locked vocabulary"
    )


def test_reserved_effect_label_forward(tmp_path):
    """C15: reserved effect label 'db' is advisory — verification passes with ok=True."""
    record = _good_record(effect={"db": [{"action": "write"}]})
    bundle_dir = _build_bundle(tmp_path, [record], None)
    result = _VERIFIER.verify(bundle_dir)
    # Reserved label is an advisory, not a hard failure
    assert result.ok is True
    assert not result.failures


def test_refinement_fragment_out_of_scope(tmp_path):
    """C15: out-of-fragment 'forall' formula is advisory — verification passes with ok=True."""
    record = _good_record(
        outputs=[{"type": {"name": "Bool", "refine": "(forall ((x Int)) (> x 0))"}}]
    )
    bundle_dir = _build_bundle(tmp_path, [record], None)
    result = _VERIFIER.verify(bundle_dir)
    # Out-of-fragment refinement is advisory at v0.1
    assert result.ok is True
    assert not result.failures


def test_refinement_parse_error(tmp_path):
    """C15: REFINEMENT_PARSE_ERROR — unbalanced parentheses in refine formula."""
    record = _good_record(
        outputs=[{"type": {"name": "Bool", "refine": "( unbalanced"}}]
    )
    bundle_dir = _build_bundle(tmp_path, [record], None)
    result = _VERIFIER.verify(bundle_dir)
    _assert_plugin_failed(
        result, "dispatch_record_wellformed", "unbalanced parentheses"
    )


def test_stamp_observed_out_of_enum(tmp_path):
    """C14: STAMP_OBSERVED_OUT_OF_ENUM — stamp_observed='FOO' is not in the lattice."""
    record = _good_record(stamp_observed="FOO")
    bundle_dir = _build_bundle(tmp_path, [record], None)
    result = _VERIFIER.verify(bundle_dir)
    _assert_plugin_failed(result, "stamp_lattice", "not in the recognized lattice")


def test_stamp_aggregate_roundup_detected(tmp_path):
    """C14: STAMP_AGGREGATE_ROUNDUP_DETECTED — aggregate claims stronger tier than per-row min."""
    records = [
        _good_record(stamp_observed=_stamp("TARGET")),
        _good_record(stamp_observed=_stamp("TARGET")),
        _good_record(stamp_observed=_stamp("TARGET")),
    ]
    bundle_dir = _build_bundle(tmp_path, records, _stamp("CONFIRMED_EXTERNAL"))
    result = _VERIFIER.verify(bundle_dir)
    _assert_plugin_failed(result, "stamp_lattice", "exceeds per-row min")


def test_stamp_aggregation_rule_rejected(tmp_path):
    """C14: STAMP_AGGREGATION_RULE_REJECTED — non-min sentinel field injected into manifest.json."""
    record = _good_record(stamp_observed=_stamp("INTERNAL_BENCHMARK"))
    bundle_dir = _build_bundle(tmp_path, [record], _stamp("INTERNAL_BENCHMARK"))
    # Inject a non-min aggregation sentinel field into the raw JSON
    manifest_path = bundle_dir / "manifest.json"
    raw = json.loads(manifest_path.read_text("utf-8"))
    raw["aggregate_stamp_avg"] = "INTERNAL_BENCHMARK"
    manifest_path.write_text(json.dumps(raw), encoding="utf-8")
    result = _VERIFIER.verify(bundle_dir)
    # Detail wording was tightened by BUG 6 (2026-05-03 panel): the
    # allowlist of named "sentinel fields" became a prefix denylist over
    # `aggregate_stamp_*`, so the message now reads "non-min aggregation
    # field" without the "sentinel" qualifier.
    _assert_plugin_failed(result, "stamp_lattice", "non-min aggregation field")


def test_proof_field_malformed(tmp_path):
    """C16: PROOF_FIELD_MALFORMED — proof.kind='F*' is not a recognized verifier kind."""
    record = {
        **_good_record(),
        "proof": {
            "kind": "F*",
            "obligation_uri": "proofs/main.lean",
            "obligation_sha": "a" * 64,
            "discharge_status": "not-attempted",
        },
    }
    bundle_dir = _build_bundle(tmp_path, [record], None)
    result = _VERIFIER.verify(bundle_dir)
    _assert_plugin_failed(
        result, "refinement_discharge", "not in the recognized verifier set"
    )


def test_discharge_status_forged(tmp_path):
    """C16 NEGATIVE TEST: DISCHARGE_STATUS_FORGED — dispatcher emits 'discharged' without verifier backing."""
    proof_content = b"-- stub proof"
    proof_sha = hashlib.sha256(proof_content).hexdigest()
    record = {
        **_good_record(),
        "proof": {
            "kind": "lean-4",
            "obligation_uri": "proofs/main.lean",
            "obligation_sha": proof_sha,
            "discharge_status": "discharged",  # forged: verifier did not discharge
        },
    }
    bundle_dir = _build_bundle(tmp_path, [record], None)
    (bundle_dir / "proofs").mkdir()
    (bundle_dir / "proofs" / "main.lean").write_bytes(proof_content)
    result = _VERIFIER.verify(bundle_dir)
    # v0.2 detail wording is "verifier_signature is missing or malformed"
    # (more precise than v0.1's "dispatcher-forged claim"); both surface the
    # same DISCHARGE_STATUS_FORGED reason code.
    _assert_plugin_failed(result, "refinement_discharge", "verifier_signature")


def test_proof_obligation_missing(tmp_path):
    """C16: PROOF_OBLIGATION_MISSING — obligation_uri points to a non-existent file."""
    record = {
        **_good_record(),
        "proof": {
            "kind": "dafny",
            "obligation_uri": "proofs/nonexistent.dfy",
            "obligation_sha": "b" * 64,
            "discharge_status": "not-attempted",
        },
    }
    bundle_dir = _build_bundle(tmp_path, [record], None)
    result = _VERIFIER.verify(bundle_dir)
    _assert_plugin_failed(
        result, "refinement_discharge", "does not exist in bundle_dir"
    )


def test_proof_obligation_sha_mismatch(tmp_path):
    """C16: PROOF_OBLIGATION_SHA_MISMATCH — obligation_sha does not match file content."""
    proof_content = b"-- real proof content"
    wrong_sha = "c" * 64  # does not match SHA-256 of proof_content
    record = {
        **_good_record(),
        "proof": {
            "kind": "lean-4",
            "obligation_uri": "proofs/main.lean",
            "obligation_sha": wrong_sha,
            "discharge_status": "not-attempted",
        },
    }
    bundle_dir = _build_bundle(tmp_path, [record], None)
    (bundle_dir / "proofs").mkdir()
    (bundle_dir / "proofs" / "main.lean").write_bytes(proof_content)
    result = _VERIFIER.verify(bundle_dir)
    _assert_plugin_failed(result, "refinement_discharge", "obligation SHA mismatch")


# ============================================================================
# CROSS-CONTRACT COMPOSITION
# ============================================================================


def test_c15_failure_does_not_mask_c14_failure(tmp_path):
    """C15 and C14 both fire independently; C15 appears first confirming plugin order."""
    # op.kind=UNKNOWN_OP violates C15; stamp roundup violates C14
    record = {
        "schema_version": "0.1",
        "op": {"kind": "UNKNOWN_OP"},
        "effect": {},
        "outputs": [],
        "stamp_observed": _stamp("TARGET"),
    }
    bundle_dir = _build_bundle(tmp_path, [record], _stamp("CONFIRMED_EXTERNAL"))
    result = _VERIFIER.verify(bundle_dir)
    assert result.ok is False
    # Both plugins fail — verifier does not short-circuit after first plugin
    # failure. (Failing plugins report no coverage, so the stamp-claims guard
    # also records its could-not-conclude legs — filter to the plugin
    # failures this test is about.)
    plugin_failures = [
        r for r in result.failures if r.check_name.startswith("typed_check_plugins:")
    ]
    assert len(plugin_failures) == 2
    # C15 fires first (plugin order: C15 → C14 → C16)
    assert (
        plugin_failures[0].check_name
        == "typed_check_plugins:dispatch_record_wellformed"
    )
    assert plugin_failures[1].check_name == "typed_check_plugins:stamp_lattice"
    assert "not in the recognized enum" in plugin_failures[0].detail
    assert "exceeds per-row min" in plugin_failures[1].detail


def test_well_formed_record_with_invalid_lattice(tmp_path):
    """C15 passes (well-formed) but C14 still fires when aggregate exceeds per-row min."""
    record = _good_record(stamp_observed=_stamp("TARGET"))
    bundle_dir = _build_bundle(tmp_path, [record], _stamp("CONFIRMED_EXTERNAL"))
    result = _VERIFIER.verify(bundle_dir)
    assert result.ok is False
    # C15 must not appear in failures
    assert _plugin_detail(result, "dispatch_record_wellformed") == ""
    _assert_plugin_failed(result, "stamp_lattice", "exceeds per-row min")


def test_legacy_bundle_with_explicit_null_dispatch_records(tmp_path):
    """dispatch_records: null in JSON is treated identically to [] (explicit-null legacy marker)."""
    bundle_dir = _build_bundle(tmp_path, None, None)  # None serialises as JSON null
    result = _VERIFIER.verify(bundle_dir)
    assert result.ok is True
    assert result.failures == []
