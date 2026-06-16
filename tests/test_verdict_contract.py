"""tests/test_verdict_contract.py — the contract-fuzz harness (ADR D3 / BI-5 step i).

A STANDING substrate invariant, the executable definition of the canonical verdict
contract (the internal design notes). Same posture as the OSS-boundary guard:
every verdict-bearing entry point on the offline core is registered here and must prove

  1. NO-ESCAPE      — for arbitrary/adversarial input it RETURNS a Verdict; it raises
                      nothing except SystemExit / KeyboardInterrupt (BI-2).
  2. NO-FALSE-GREEN — an unexpected exception inside a leg/plugin yields state == ERROR,
                      never OK (BI-4). A silently-skipped broken check (= false green) is
                      the worst outcome and is what this asserts against.
  3. TAXONOMY       — admission rejects carry INPUT_* (REJECT); the boundary's
                      catch-all carries VERIFIER_* (ERROR) (BI-3).

A NEW verdict-bearing entry point on the offline core MUST be added to
REGISTERED_ENTRY_POINTS and prove no-escape, or this guard fails — exactly like adding
a premium pilot path to the OSS-boundary guard. See the ADR §6 cascade for the
not-yet-migrated leaves (premium / c19 / orchestrator_turn composites) deferred on
purpose.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from audit_bundle.admission import AdmissionLimits, admit_bytes, admit_obj

# o5 is the closed cross-pillar receipt tier — absent from the open-tier drop.
# Guard the import so this open-tier verdict-contract test stays clean for the
# redteam mirror (the leak verify rejects an UNGUARDED excluded import); the
# o5-specific cases below skip when o5 is not present.
try:
    from audit_bundle.o5.verify import verify_bundle, verify_node_stamp

    _O5_AVAILABLE = True
except ImportError:
    verify_bundle = verify_node_stamp = None  # type: ignore[assignment]
    _O5_AVAILABLE = False

from audit_bundle.verdict import (
    INPUT_PREFIX,
    VERIFIER_PREFIX,
    ErrorKind,
    Verdict,
    VerdictState,
    compose,
    fail_closed,
)
from audit_bundle.verifier import BundleVerifier

# ---------------------------------------------------------------------------
# Registry of offline-core verdict-bearing entry points (ADR §4.1 subset that the
# build pass migrated). Each entry is (label, is-fail_closed-wrapped-callable).
# ---------------------------------------------------------------------------
REGISTERED_ENTRY_POINTS = {
    "BundleVerifier.verify": BundleVerifier.verify,
}
if _O5_AVAILABLE:  # closed-tier entry points — only when o5 is present.
    REGISTERED_ENTRY_POINTS["o5.verify_node_stamp"] = verify_node_stamp
    REGISTERED_ENTRY_POINTS["o5.verify_bundle"] = verify_bundle


def _is_boundary_wrapped(fn) -> bool:
    """fail_closed uses functools.wraps, which sets __wrapped__ on the wrapper."""
    return hasattr(fn, "__wrapped__")


def test_registered_entry_points_are_boundary_wrapped():
    """Every registered entry point sits behind the differentiated boundary."""
    for label, fn in REGISTERED_ENTRY_POINTS.items():
        assert _is_boundary_wrapped(fn), f"{label} is not fail_closed-wrapped"


# ---------------------------------------------------------------------------
# Adversarial manifest corpus for BundleVerifier.verify
# ---------------------------------------------------------------------------
_DEEP = ("[" * 400 + "]" * 400).encode()

# (raw manifest.json bytes, must_be_non_ok)
ADVERSARIAL_MANIFESTS = [
    (b"123", True),
    (b'"just a string"', True),
    (b"[1, 2, 3]", True),
    (b"null", True),
    (b"", True),
    (b"{ not valid json", True),
    (b'{"outputs": 123}', True),  # the verifier.py:~204 TypeError escape
    (b'{"per_output_manifests": 7}', True),
    (b'{"dispatch_records": 9}', True),
    (b'{"files": 123}', True),
    (b'{"spec_files": [1, 2]}', True),
    (b'{"cross_refs": 5}', True),
    (b'{"typed_checks": {"x": 1}}', True),
    (b'{"schema_version": {"unhashable": 1}}', True),
    (b'{"append_only_files": 12}', True),
    (_DEEP, True),  # the RecursionError-DoS escape
    # benign — must NOT be forced non-ok by the harness:
    (
        b'{"schema_version": "legacy", "files": {}, "spec_files": {}, "cross_refs": {}}',
        False,
    ),
]


def _write_bundle(tmp_path: Path, raw: bytes) -> Path:
    bundle = tmp_path / "b"
    bundle.mkdir()
    (bundle / "manifest.json").write_bytes(raw)
    return bundle


@pytest.mark.parametrize("raw,must_be_non_ok", ADVERSARIAL_MANIFESTS)
def test_verify_never_escapes(tmp_path, raw, must_be_non_ok):
    """NO-ESCAPE: verify() returns a Verdict for any input; never raises."""
    bundle = _write_bundle(tmp_path, raw)
    verifier = BundleVerifier()
    result = verifier.verify(bundle)  # must not raise
    assert isinstance(result, Verdict)
    assert result.state in (VerdictState.OK, VerdictState.REJECT, VerdictState.ERROR)
    if must_be_non_ok:
        assert not result.ok, f"adversarial input verified OK: {raw!r}"


def test_verify_deep_nesting_is_admission_reject(tmp_path):
    """The RecursionError-DoS shape becomes a clean INPUT_DEPTH_EXCEEDED REJECT."""
    bundle = _write_bundle(tmp_path, _DEEP)
    result = BundleVerifier().verify(bundle)
    assert result.state is VerdictState.REJECT
    assert result.reasons[0].code == "INPUT_DEPTH_EXCEEDED"


# ---------------------------------------------------------------------------
# NO-FALSE-GREEN: an unexpected plugin exception -> ERROR, never OK (BI-4)
# ---------------------------------------------------------------------------
_VALID_MANIFEST = (
    b'{"schema_version": "legacy", "files": {}, "spec_files": {}, "cross_refs": {}}'
)


class _RaisingPlugin:
    name = "raising_plugin"
    applies_to_files: frozenset = frozenset()

    def check(self, bundle_dir, manifest):
        raise ValueError("simulated plugin bug")


class _NonConformingPlugin:
    name = "nonconforming_plugin"
    applies_to_files: frozenset = frozenset()

    def check(self, bundle_dir, manifest):
        return object()  # no .ok attribute


def test_plugin_unexpected_exception_is_error_not_green(tmp_path):
    bundle = _write_bundle(tmp_path, _VALID_MANIFEST)
    result = BundleVerifier(plugins=[_RaisingPlugin()]).verify(bundle)
    assert result.state is VerdictState.ERROR, "unexpected plugin raise must be ERROR"
    assert not result.ok
    assert result.reasons[0].code == "VERIFIER_UNEXPECTED_PLUGIN_EXCEPTION"


def test_plugin_nonconforming_result_is_error_not_green(tmp_path):
    bundle = _write_bundle(tmp_path, _VALID_MANIFEST)
    result = BundleVerifier(plugins=[_NonConformingPlugin()]).verify(bundle)
    assert result.state is VerdictState.ERROR
    assert not result.ok


def test_empty_bundle_is_ok(tmp_path):
    """Sanity: a well-formed empty manifest with no plugins verifies OK (so the
    harness is proving fail-closed on REAL bad input, not just rejecting everything)."""
    bundle = _write_bundle(tmp_path, _VALID_MANIFEST)
    assert BundleVerifier().verify(bundle).state is VerdictState.OK


# ---------------------------------------------------------------------------
# o5 entry points — attacker-shaped inputs never escape (file had ZERO try/except)
# ---------------------------------------------------------------------------
O5_NODE_STAMP_JUNK = [123, "str", None, [1, 2], {"only": "keys"}]
O5_BUNDLE_JUNK = [
    123,
    "str",
    None,
    {"bogus": True},
    {"bundle_body": 1, "nodes": []},
    {"bundle_body": {}, "nodes": [123]},  # node not a dict -> deep escape
    {"bundle_body": {}, "nodes": "notalist"},
]


@pytest.mark.skipif(
    not _O5_AVAILABLE, reason="o5 is the closed tier, absent from the open drop"
)
@pytest.mark.parametrize("junk", O5_NODE_STAMP_JUNK)
def test_o5_verify_node_stamp_never_escapes(junk):
    result = verify_node_stamp(
        junk,
        claimed_cid="x",
        objective_row_body={},
        registry_snapshot={},
        grounds=None,
    )
    assert isinstance(result, Verdict)
    assert not result.ok


@pytest.mark.skipif(
    not _O5_AVAILABLE, reason="o5 is the closed tier, absent from the open drop"
)
@pytest.mark.parametrize("junk", O5_BUNDLE_JUNK)
def test_o5_verify_bundle_never_escapes(junk):
    result = verify_bundle(junk)
    assert isinstance(result, Verdict)
    assert not result.ok


@pytest.mark.skipif(
    not _O5_AVAILABLE, reason="o5 is the closed tier, absent from the open drop"
)
def test_o5_nondict_assembly_is_input_reject():
    # intentionally passing a non-dict to a dict-typed param (the whole point of the
    # admission guard) — silence the static type-checker, not the runtime contract.
    assert verify_bundle(123).reasons[0].code == "INPUT_MALFORMED_ASSEMBLY"  # type: ignore[arg-type]
    assert (
        verify_node_stamp(
            123,  # type: ignore[arg-type]
            claimed_cid="x",
            objective_row_body={},
            registry_snapshot={},
            grounds=None,
        )
        .reasons[0]
        .code
        == "INPUT_MALFORMED_ASSEMBLY"
    )


# ---------------------------------------------------------------------------
# Taxonomy (BI-3): admission -> INPUT_*, boundary catch-all -> VERIFIER_*
# ---------------------------------------------------------------------------
def test_admission_reasons_are_input_namespaced():
    for verdict in (
        admit_bytes(b"x" * 50, AdmissionLimits(max_bytes=10)),
        admit_bytes(
            ("[" * 100).encode() + ("]" * 100).encode(), AdmissionLimits(max_depth=8)
        ),
        admit_obj({"a": list(range(20))}, AdmissionLimits(max_collection=3)),
    ):
        assert verdict is not None
        assert verdict.state is VerdictState.REJECT
        assert verdict.reasons[0].code.startswith(INPUT_PREFIX)


def test_boundary_catchall_is_verifier_namespaced():
    @fail_closed("probe")
    def boom():
        raise RuntimeError("x")

    v = boom()
    assert v.state is VerdictState.ERROR
    assert v.reasons[0].code.startswith(VERIFIER_PREFIX)


def test_boundary_propagates_systemexit_and_keyboardinterrupt():
    @fail_closed("probe")
    def se():
        raise SystemExit(2)

    @fail_closed("probe")
    def kb():
        raise KeyboardInterrupt()

    with pytest.raises(SystemExit):
        se()
    with pytest.raises(KeyboardInterrupt):
        kb()


def test_admission_admits_real_manifest():
    """A normal manifest passes admission (no false-reject of legitimate bundles)."""
    raw = json.dumps(
        {"schema_version": "s0.v0.3", "files": {f"f{i}": "ab" * 32 for i in range(50)}}
    ).encode()
    assert admit_bytes(raw) is None
    assert admit_obj(json.loads(raw)) is None


# ---------------------------------------------------------------------------
# compose() — the ratified Q2 two-class ERROR algebra (ADR §5.2 RULING):
#   crash-ERROR > REJECT > clean-ERROR > OK   (crash short-circuits; advisory non-gating)
# This is a STANDING invariant: a change to compose() that breaks the dominance order
# turns this RED, exactly like the no-escape registry above.
# ---------------------------------------------------------------------------
_OK = Verdict.passed()
_REJECT = Verdict.reject("INPUT_X", "artifact bad")
_CRASH = Verdict.error("VERIFIER_INTERNAL_ERROR", "boom")  # crash-class ERROR
_INCOMPLETE = Verdict.incomplete(
    "VERIFIER_INCOMPLETE", "cannot conclude"
)  # clean-ERROR


def test_compose_a_crash_plus_reject_is_crash():
    """(a) crash-ERROR + sibling REJECT → composite crash-ERROR (crash dominates)."""
    v = compose([_CRASH, _REJECT])
    assert v.state is VerdictState.ERROR
    assert v.is_crash and v.error_kind is ErrorKind.CRASH
    assert not v.ok
    # crash short-circuits: the crash reason heads the composite.
    assert v.reasons[0].code == "VERIFIER_INTERNAL_ERROR"


def test_compose_b_clean_error_plus_reject_is_reject():
    """(b) clean-ERROR + sibling REJECT → composite REJECT (REJECT-dominant)."""
    v = compose([_INCOMPLETE, _REJECT])
    assert v.state is VerdictState.REJECT
    assert not v.ok
    assert v.reasons[0].code == "INPUT_X"


def test_compose_c_clean_error_alone_is_incomplete():
    """(c) clean-ERROR alone → composite clean-ERROR (INCOMPLETE)."""
    v = compose([_INCOMPLETE])
    assert v.state is VerdictState.ERROR
    assert v.is_incomplete and v.error_kind is ErrorKind.INCOMPLETE
    assert not v.ok
    assert v.reasons[0].code == "VERIFIER_INCOMPLETE"


@pytest.mark.parametrize("advisory", [_OK, _REJECT, _CRASH, _INCOMPLETE])
def test_compose_d_advisory_leg_never_changes_state(advisory):
    """(d) an ADVISORY leg of ANY state never changes the gating composite, but is
    still recorded in `legs` (D6/D7)."""
    # gating leg is a single OK; the advisory leg of any state must not move it off OK.
    v = compose([_OK, advisory], gating=[True, False])
    assert v.state is VerdictState.OK
    assert advisory in v.legs  # recorded, just non-gating
    # and a gating REJECT is not laundered by an advisory OK either.
    v2 = compose([_REJECT, _OK], gating=[True, False])
    assert v2.state is VerdictState.REJECT


def test_compose_ok_when_all_ok():
    assert compose([_OK, _OK]).state is VerdictState.OK
    assert compose([]).state is VerdictState.OK


def test_compose_single_fault_surfaces_its_reason():
    """The property the o5 single-fault tests rely on."""
    assert compose([_OK, _REJECT, _OK]).reason == "INPUT_X"
    assert compose([_OK, _INCOMPLETE]).reason == "VERIFIER_INCOMPLETE"


def test_compose_all_legs_preserved():
    legs = compose([_OK, _REJECT, _INCOMPLETE]).legs
    assert len(legs) == 3  # gating + advisory all stored


# ---------------------------------------------------------------------------
# (e) the boundary catches RecursionError AND MemoryError as crash-ERROR.
# Both are Exceptions (NOT BaseException) → ERROR, never green, crash-class.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("exc_cls", [RecursionError, MemoryError, RuntimeError])
def test_boundary_catches_resource_exhaustion_as_crash_error(exc_cls):
    @fail_closed("probe")
    def boom():
        raise exc_cls("simulated")

    v = boom()
    assert v.state is VerdictState.ERROR
    assert v.is_crash and v.error_kind is ErrorKind.CRASH
    assert not v.ok
    assert v.reasons[0].code.startswith(VERIFIER_PREFIX)


# ---------------------------------------------------------------------------
# Plugin clean-ERROR contract (precondition 1): a plugin that returns incomplete=True
# yields a clean-ERROR composite, NOT a REJECT and NOT a crash. A real REJECT alongside
# it still dominates (REJECT-dominant over clean-ERROR).
# ---------------------------------------------------------------------------
class _IncompletePlugin:
    name = "incomplete_plugin"
    applies_to_files: frozenset = frozenset()

    def check(self, bundle_dir, manifest):
        class _R:
            ok = False
            incomplete = True
            detail = "external attestation absent — cannot conclude"

        return _R()


class _FailingPlugin:
    name = "failing_plugin"
    applies_to_files: frozenset = frozenset()

    def check(self, bundle_dir, manifest):
        class _R:
            ok = False
            incomplete = False
            detail = "artifact bad"

        return _R()


def test_plugin_incomplete_is_clean_error_not_reject(tmp_path):
    bundle = _write_bundle(tmp_path, _VALID_MANIFEST)
    result = BundleVerifier(plugins=[_IncompletePlugin()]).verify(bundle)
    assert result.state is VerdictState.ERROR, "incomplete plugin must be ERROR"
    assert result.is_incomplete, "must be the clean-ERROR class, not crash"
    assert not result.ok
    assert result.reasons[0].code.startswith(VERIFIER_PREFIX)


def test_plugin_reject_dominates_incomplete(tmp_path):
    """A genuine plugin REJECT alongside a could-not-conclude plugin → composite REJECT
    (REJECT-dominant over clean-ERROR), never softened to indeterminate."""
    bundle = _write_bundle(tmp_path, _VALID_MANIFEST)
    result = BundleVerifier(plugins=[_IncompletePlugin(), _FailingPlugin()]).verify(
        bundle
    )
    assert result.state is VerdictState.REJECT
    assert not result.ok


# ---------------------------------------------------------------------------
# D5: verify() is complete-by-construction. A LIBRARY consumer of verify() (not just
# the CLI fast-path) now gets the DEEP manifest validators, and every verdict declares
# on its face which layers ran. A regression that drops the deep step turns this RED.
# ---------------------------------------------------------------------------
# snapshots non-empty but snapshot_policy is None -> deep validator step 6 (the first
# deep check the shallow 4-step walk does NOT cover) -> REJECT.
_DEEP_FAIL_MANIFEST = (
    b'{"schema_version": "legacy", "files": {}, "spec_files": {}, '
    b'"cross_refs": {}, "snapshots": {"deadbeef": "snap.txt"}}'
)


def test_verify_runs_deep_validation_for_library_consumers(tmp_path):
    result = BundleVerifier().verify(_write_bundle(tmp_path, _DEEP_FAIL_MANIFEST))
    assert result.state is VerdictState.REJECT, (
        "deep validation must reject via verify()"
    )
    assert result.reasons[0].code == "SnapshotPolicyMissing"
    assert result.reasons[0].check_name == "deep_manifest_validation"


def test_verify_declares_completeness(tmp_path):
    """Every verify() verdict declares deep_validation=True (D5) — OK and REJECT alike."""
    a = tmp_path / "a"
    a.mkdir()
    b = tmp_path / "b"
    b.mkdir()
    ok = BundleVerifier().verify(_write_bundle(a, _VALID_MANIFEST))
    assert ok.state is VerdictState.OK
    assert ok.completeness is not None and ok.completeness.deep_validation is True
    bad = BundleVerifier().verify(_write_bundle(b, _DEEP_FAIL_MANIFEST))
    assert bad.completeness is not None and bad.completeness.deep_validation is True
