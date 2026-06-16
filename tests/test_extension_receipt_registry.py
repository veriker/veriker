"""Generic extension-receipt registry — dispatch, NOT-EVALUATED contract, and
per-run registry-snapshot / single-execution discipline.

Base-tier test (no extension-specific deps): guards the pluggable
receipt-verifier behaviour the verifier relies on. A registered handler's
PASS/FAIL verdict is folded into the result; an unhandled receipt kind is
reported NOT EVALUATED (present but unverified) — never silently passed and
never used to fail an otherwise-valid bundle; a non-dict assembly or a handler
that raises is a fail-closed reject. This contract must hold independently of
whichever handlers a given build happens to register.

Registry-snapshot discipline (Codex registry-mutability finding, 2026-06-11 —
the RES-04 single-acquisition class applied to verifier CONFIGURATION):

  1. verify() evaluates every receipt kind in one run against ONE
     registered_receipt_verifiers() snapshot, so a (TCB-only) mutation of the
     module-global registry mid-run can never make two kinds in the same
     verdict see different registry states.
  2. Each handler executes exactly ONCE per CLI invocation: the CLI presents
     the dispositions verify() recorded on the verdict face instead of
     re-executing handlers, so --verdict-out can never mix two handler runs.
  3. A receipt kind present in the manifest but with NO recorded disposition
     (receipt step never reached, e.g. upstream crash-ERROR) is UNACCOUNTED —
     fail-closed could-not-conclude, never a silent pass.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

from audit_bundle.bundle_manifest import (
    evaluate_extension_receipt,
    register_receipt_verifier,
)
from audit_bundle.verdict import VERIFIER_INCOMPLETE, Completeness, Verdict
from audit_bundle.verifier import BundleVerifier
from veriker.cli.verify import _extension_receipt_disposition


# ---------------------------------------------------------------------------
# Evaluator contract (status/reason/detail semantics)
# ---------------------------------------------------------------------------


def test_unhandled_kind_is_not_evaluated():
    status, reason, detail = evaluate_extension_receipt("no_such_kind_xyz", {"a": 1})
    assert status == "NOT_EVALUATED"
    assert reason is None
    assert "UNVERIFIED" in detail


def test_registered_handler_pass_is_folded_in():
    register_receipt_verifier("test_kind_pass", lambda a: (True, None, "ok"))
    status, reason, detail = evaluate_extension_receipt("test_kind_pass", {"x": 1})
    assert status == "PASS" and reason is None and detail == "ok"


def test_registered_handler_fail_is_folded_in():
    register_receipt_verifier("test_kind_fail", lambda a: (False, "NOPE", "rejected"))
    status, reason, _ = evaluate_extension_receipt("test_kind_fail", {"x": 1})
    assert status == "FAIL" and reason == "NOPE"


def test_handler_raising_is_fail_closed():
    def _boom(_assembly):
        raise ValueError("bad")

    register_receipt_verifier("test_kind_boom", _boom)
    status, reason, _ = evaluate_extension_receipt("test_kind_boom", {"x": 1})
    assert status == "FAIL" and reason == "RECEIPT_ASSEMBLY_MALFORMED"


def test_non_dict_assembly_is_malformed():
    register_receipt_verifier("test_kind_nd", lambda a: (True, None, "ok"))
    status, reason, _ = evaluate_extension_receipt("test_kind_nd", ["not", "a", "dict"])
    assert status == "FAIL" and reason == "RECEIPT_MALFORMED"


def test_explicit_registry_snapshot_beats_live_global():
    # An explicit `registry` snapshot is authoritative: a later mutation of the
    # module-global registry must not leak into an evaluation made against the
    # snapshot (the per-run coherence primitive verify() builds on).
    register_receipt_verifier("test_kind_snap", lambda a: (True, None, "from-snap"))
    from audit_bundle.bundle_manifest import registered_receipt_verifiers

    snapshot = registered_receipt_verifiers()
    register_receipt_verifier(
        "test_kind_snap", lambda a: (False, "MUTATED", "from-live")
    )
    status, reason, detail = evaluate_extension_receipt(
        "test_kind_snap", {"x": 1}, registry=snapshot
    )
    assert (status, reason, detail) == ("PASS", None, "from-snap")
    # And the live-global fallback (registry=None) sees the mutation.
    status, reason, _ = evaluate_extension_receipt("test_kind_snap", {"x": 1})
    assert (status, reason) == ("FAIL", "MUTATED")


# ---------------------------------------------------------------------------
# verify() step — one snapshot per run, PASS recorded on the verdict face
# ---------------------------------------------------------------------------


def _run_step(receipts: dict):
    verifier = BundleVerifier(plugins=[])
    manifest = SimpleNamespace(extension_receipts=receipts)
    failures: list = []
    incompletes: list = []
    disclosures: list[str] = []
    verifier._step_extension_receipts(manifest, failures, incompletes, disclosures)
    return failures, incompletes, disclosures


def test_step_takes_one_registry_snapshot_per_run():
    # Handler for the FIRST kind (sorted order) maliciously/buggily re-registers
    # the SECOND kind's handler to a failing one mid-run. With per-run snapshot
    # discipline the second kind must still be evaluated against the registry
    # state observed at step start — both PASS, zero failures. Without the
    # snapshot this test fails with a MUTATED_MID_RUN reject (live read).
    register_receipt_verifier("aaa_mutator_kind", lambda a: _mutate_and_pass())
    register_receipt_verifier("zzz_victim_kind", lambda a: (True, None, "victim ok"))

    def _mutate_and_pass():
        register_receipt_verifier(
            "zzz_victim_kind",
            lambda a: (False, "MUTATED_MID_RUN", "registry changed mid-run"),
        )
        return (True, None, "mutator ok")

    failures, incompletes, disclosures = _run_step(
        {"aaa_mutator_kind": {}, "zzz_victim_kind": {}}
    )
    assert failures == [] and incompletes == []
    assert "extension_receipt:zzz_victim_kind: PASS — victim ok" in disclosures


def test_step_records_pass_as_prefixed_disclosure():
    register_receipt_verifier("test_kind_disc", lambda a: (True, None, "all good"))
    failures, incompletes, disclosures = _run_step({"test_kind_disc": {"x": 1}})
    assert failures == [] and incompletes == []
    assert disclosures == ["extension_receipt:test_kind_disc: PASS — all good"]


# ---------------------------------------------------------------------------
# CLI presentation reads the verdict — never a second handler execution
# ---------------------------------------------------------------------------


def _result_with(reasons=(), disclosures=()):
    completeness = Completeness(
        layers=("shallow_walk",), deep_validation=True, disclosures=tuple(disclosures)
    )
    base = Verdict.from_failures([], completeness=completeness)
    if not reasons:
        return base
    from dataclasses import replace

    return replace(base, reasons=tuple(reasons))


def test_disposition_reconstructs_fail_from_reason_leg():
    leg = SimpleNamespace(
        code="RECEIPT_REJECT", check_name="extension_receipt:k1", detail="bad receipt"
    )
    status, reason, detail = _extension_receipt_disposition(
        "k1", _result_with(reasons=[leg])
    )
    assert (status, reason, detail) == ("FAIL", "RECEIPT_REJECT", "bad receipt")


def test_disposition_reconstructs_not_evaluated_from_incomplete_leg():
    leg = SimpleNamespace(
        code=VERIFIER_INCOMPLETE,
        check_name="extension_receipt:k2",
        detail="present but UNVERIFIED",
    )
    status, reason, detail = _extension_receipt_disposition(
        "k2", _result_with(reasons=[leg])
    )
    assert status == "NOT_EVALUATED" and reason is None
    assert "UNVERIFIED" in detail


def test_disposition_reconstructs_pass_from_disclosure():
    status, reason, detail = _extension_receipt_disposition(
        "k3", _result_with(disclosures=["extension_receipt:k3: PASS — fine"])
    )
    assert (status, reason, detail) == ("PASS", None, "fine")


def test_disposition_unaccounted_kind_fails_closed():
    # Present in the manifest, but verify() recorded neither a leg nor a PASS
    # disclosure (receipt step never reached): could-not-conclude, never PASS.
    status, reason, _ = _extension_receipt_disposition("ghost_kind", _result_with())
    assert status == "UNACCOUNTED"
    assert reason == "EXTENSION_RECEIPT_UNACCOUNTED"


def _write_bundle(tmp_path: Path, *, extension_receipts: dict) -> Path:
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    corpus_dir = bundle_dir / "corpus"
    corpus_dir.mkdir()
    content = b"synthetic corpus entry for single-execution test"
    (corpus_dir / "entry0.txt").write_bytes(content)
    manifest = {
        "schema_version": "legacy",
        "bundle_id": "receipt-single-execution-test",
        "created_at": "2026-01-01T00:00:00Z",
        "files": {"corpus/entry0.txt": hashlib.sha256(content).hexdigest()},
        "spec_files": {},
        "cross_refs": {},
        "payload": {},
        "typed_checks": [],
        "per_output_manifests": [],
        "extension_receipts": extension_receipts,
    }
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return bundle_dir


def test_cli_executes_each_handler_exactly_once(tmp_path, monkeypatch, capsys):
    # THE load-bearing regression: pre-2026-06-11 the CLI executed every
    # handler twice (once in verify() core, once in its presentation loop) and
    # --verdict-out mixed the two runs. The CLI must now present from the
    # verdict; the handler body runs exactly once per invocation.
    calls = {"n": 0}

    def _counting(_assembly):
        calls["n"] += 1
        return (True, None, "counted ok")

    register_receipt_verifier("test_kind_count", _counting)
    bundle_dir = _write_bundle(
        tmp_path, extension_receipts={"test_kind_count": {"x": 1}}
    )
    import veriker.cli.verify as cli_verify

    monkeypatch.setattr(sys, "argv", ["verify", "--bundle-dir", str(bundle_dir)])
    rc = cli_verify.main()
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "PASS  extension_receipt:test_kind_count  counted ok" in out
    assert calls["n"] == 1, f"handler executed {calls['n']} times; must be exactly 1"
