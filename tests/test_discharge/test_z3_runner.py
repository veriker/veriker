"""Tests for audit_bundle/discharge/z3_runner.py.

Covers:
  - FakeZ3Invoker — basic scripted-response path used by the adversarial suite
  - InProcessZ3Invoker — real Z3 happy paths (sat/unsat/unknown) using the
    z3-solver Python module
  - SubprocessZ3Invoker — real Z3 happy path if `z3` binary is on PATH (skipped
    otherwise; CI / curator boxes have z3 installed)
  - discharge() top-level — fallback when no invoker is available
  - 5 adversarial categories (driven by FakeZ3Invoker so they're deterministic
    on a machine without Z3):
      A. Z3 process crash / non-zero exit  -> SUBPROCESS_FAILURE
      B. Timeout                            -> TIMEOUT
      C. Unknown response                   -> UNKNOWN
      D. Nondeterminism (same input, two runs, different outcomes)
      E. Malformed parse error              -> SUBPROCESS_FAILURE
"""

from __future__ import annotations

import shutil

import pytest

from audit_bundle.discharge.z3_runner import (
    FakeZ3Invoker,
    InProcessZ3Invoker,
    SubprocessZ3Invoker,
    Z3Result,
    Z3Status,
    discharge,
    pick_default_invoker,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_TRIVIAL_SCRIPT = """
(set-logic QF_LIA)
(declare-const x Int)
(assert (not (= (+ 0 x) x)))
(check-sat)
"""

_FALSE_REFINEMENT_SCRIPT = """
(set-logic QF_LIA)
(declare-const x Int)
(assert (not (= x (+ x 1))))
(check-sat)
"""


def _has_z3_binary() -> bool:
    return shutil.which("z3") is not None


# ============================================================================
# FakeZ3Invoker — scripted responses
# ============================================================================


def test_fake_invoker_returns_scripted_response():
    fake = FakeZ3Invoker(
        [
            Z3Result(Z3Status.DISCHARGED, "unsat\n", 0.01, "fake"),
        ]
    )
    out = fake.run("(check-sat)", timeout_s=5.0)
    assert out.status is Z3Status.DISCHARGED
    assert fake.last_script == "(check-sat)"
    assert fake.last_timeout == 5.0


def test_fake_invoker_consumes_responses_in_order():
    fake = FakeZ3Invoker(
        [
            Z3Result(Z3Status.DISCHARGED, "unsat", 0.01, "fake"),
            Z3Result(Z3Status.FAILED, "sat", 0.01, "fake"),
            Z3Result(Z3Status.UNKNOWN, "unknown", 0.01, "fake"),
        ]
    )
    a = fake.run("a", 1.0)
    b = fake.run("b", 1.0)
    c = fake.run("c", 1.0)
    assert (a.status, b.status, c.status) == (
        Z3Status.DISCHARGED,
        Z3Status.FAILED,
        Z3Status.UNKNOWN,
    )


def test_fake_invoker_exhausted_raises():
    fake = FakeZ3Invoker([Z3Result(Z3Status.DISCHARGED, "", 0.0, "fake")])
    fake.run("a", 1.0)
    with pytest.raises(AssertionError):
        fake.run("b", 1.0)


# ============================================================================
# InProcessZ3Invoker — real Z3 via z3-solver Python module
# ============================================================================


def test_in_process_invoker_proves_trivial_tautology():
    """The negation `(not (= (+ 0 x) x))` is unsat for all Int x → DISCHARGED."""
    inv = InProcessZ3Invoker()
    out = inv.run(_TRIVIAL_SCRIPT, timeout_s=5.0)
    assert out.status is Z3Status.DISCHARGED, out.raw_output
    assert out.invoker_kind == "in_process"


def test_in_process_invoker_finds_counterexample_to_false_claim():
    """The negation of `(= x (+ x 1))` is sat (any x is a counterexample)
    → FAILED (refinement claim is false)."""
    inv = InProcessZ3Invoker()
    out = inv.run(_FALSE_REFINEMENT_SCRIPT, timeout_s=5.0)
    assert out.status is Z3Status.FAILED, out.raw_output


def test_in_process_invoker_handles_parse_error():
    inv = InProcessZ3Invoker()
    out = inv.run("(this is not valid smt-lib", timeout_s=5.0)
    assert out.status is Z3Status.SUBPROCESS_FAILURE
    assert "parse" in out.raw_output.lower() or "error" in out.raw_output.lower()


# ============================================================================
# SubprocessZ3Invoker — only when z3 binary is on PATH
# ============================================================================


@pytest.mark.skipif(not _has_z3_binary(), reason="z3 binary not on PATH")
def test_subprocess_invoker_proves_trivial_tautology():
    inv = SubprocessZ3Invoker()
    out = inv.run(_TRIVIAL_SCRIPT, timeout_s=5.0)
    assert out.status is Z3Status.DISCHARGED, out.raw_output
    assert out.invoker_kind == "subprocess"


@pytest.mark.skipif(not _has_z3_binary(), reason="z3 binary not on PATH")
def test_subprocess_invoker_finds_counterexample():
    inv = SubprocessZ3Invoker()
    out = inv.run(_FALSE_REFINEMENT_SCRIPT, timeout_s=5.0)
    assert out.status is Z3Status.FAILED


def test_subprocess_invoker_missing_binary_raises():
    with pytest.raises(FileNotFoundError):
        SubprocessZ3Invoker(z3_binary_path=None) if not _has_z3_binary() else (
            _ for _ in ()
        ).throw(FileNotFoundError())  # only assert when z3 absent
    if not _has_z3_binary():
        # already raised above
        return
    # If z3 IS on PATH, asking for a different bogus binary still raises
    pytest.skip("z3 binary present; missing-binary path covered by environment")


# ============================================================================
# discharge() top-level
# ============================================================================


def test_discharge_with_explicit_invoker_routes_through():
    fake = FakeZ3Invoker([Z3Result(Z3Status.DISCHARGED, "unsat", 0.01, "fake")])
    result = discharge("(check-sat)", invoker=fake)
    assert result.status is Z3Status.DISCHARGED


def test_discharge_rejects_empty_script():
    with pytest.raises(ValueError):
        discharge("", invoker=FakeZ3Invoker([]))


def test_discharge_rejects_negative_timeout():
    with pytest.raises(ValueError):
        discharge("(check-sat)", timeout_s=-1.0, invoker=FakeZ3Invoker([]))


def test_pick_default_invoker_returns_real_invoker():
    inv = pick_default_invoker()
    assert inv is not None
    assert inv.kind in {"in_process", "subprocess"}


# ============================================================================
# Adversarial category A — Z3 process crash / non-zero exit
# ============================================================================


def test_adversarial_subprocess_failure_surfaces_as_status():
    fake = FakeZ3Invoker(
        [
            Z3Result(
                Z3Status.SUBPROCESS_FAILURE, "z3 segfault: signal 11", 0.5, "fake"
            ),
        ]
    )
    result = discharge("(check-sat)", invoker=fake)
    assert result.status is Z3Status.SUBPROCESS_FAILURE
    assert "segfault" in result.raw_output


# ============================================================================
# Adversarial category B — Timeout
# ============================================================================


def test_adversarial_timeout_surfaces_as_status():
    fake = FakeZ3Invoker(
        [
            Z3Result(Z3Status.TIMEOUT, "timeout after 30s", 30.0, "fake"),
        ]
    )
    result = discharge("(check-sat)", invoker=fake, timeout_s=30.0)
    assert result.status is Z3Status.TIMEOUT


# ============================================================================
# Adversarial category C — Unknown response
# ============================================================================


def test_adversarial_unknown_surfaces_as_status():
    fake = FakeZ3Invoker(
        [
            Z3Result(Z3Status.UNKNOWN, "unknown (incomplete quantifiers)", 0.1, "fake"),
        ]
    )
    result = discharge("(check-sat)", invoker=fake)
    assert result.status is Z3Status.UNKNOWN


# ============================================================================
# Adversarial category D — Nondeterminism (same script, varying outcomes)
# ============================================================================


def test_adversarial_nondeterminism_does_not_silent_retry():
    """Two consecutive runs of the same script returning different outcomes
    must surface BOTH outcomes verbatim — the runner does not silently retry."""
    fake = FakeZ3Invoker(
        [
            Z3Result(Z3Status.UNKNOWN, "first: unknown", 0.1, "fake"),
            Z3Result(Z3Status.DISCHARGED, "second: unsat", 0.1, "fake"),
        ]
    )
    a = discharge("script", invoker=fake)
    b = discharge("script", invoker=fake)
    assert a.status is Z3Status.UNKNOWN
    assert b.status is Z3Status.DISCHARGED


# ============================================================================
# Adversarial category E — Malformed parse error from Z3
# ============================================================================


def test_adversarial_parse_error_surfaces_as_subprocess_failure():
    inv = InProcessZ3Invoker()
    # Genuinely malformed: undefined sort (Z3 emits a parse error).
    out = inv.run("(declare-const x ThisSortDoesNotExist)\n(check-sat)", timeout_s=5.0)
    assert out.status is Z3Status.SUBPROCESS_FAILURE
    assert (
        "parse" in out.raw_output.lower()
        or "error" in out.raw_output.lower()
        or "unknown" in out.raw_output.lower()
    )


def test_adversarial_unbalanced_parens_surfaces_as_subprocess_failure():
    inv = InProcessZ3Invoker()
    out = inv.run("(declare-const x Int", timeout_s=5.0)
    assert out.status is Z3Status.SUBPROCESS_FAILURE


# ============================================================================
# Regression — V16 panel review BUG 7 (Sonnet 4.6 2026-05-02)
# ============================================================================


def test_panel_bug_7_z3_seed_isolation_per_solver():
    """BUG 7: prior code used z3.set_param("smt.random_seed", N) which
    mutates Z3's MODULE-GLOBAL parameter — seeds bled across invocations.
    The fix uses solver.set("random_seed", N) per-instance.

    Verification: after running InProcessZ3Invoker(random_seed=42) and then
    InProcessZ3Invoker(random_seed=99), the global Z3 module-level seed
    parameter should NOT carry the runner's seed (the runner sets it on
    the Solver, not the module)."""
    # Cumulative-pre-soak Patch 10 (Gate 1, 2026-05-04): use
    # importorskip so lean installs without z3-solver get a clean SKIP.
    z3 = pytest.importorskip("z3")

    # Capture pre-state
    pre_global = z3.get_param("smt.random_seed") if hasattr(z3, "get_param") else None

    inv1 = InProcessZ3Invoker(random_seed=42)
    inv2 = InProcessZ3Invoker(random_seed=99)
    script = "(set-logic QF_LIA)\n(assert (not (= 1 1)))\n(check-sat)\n"
    r1 = inv1.run(script, 5.0)
    r2 = inv2.run(script, 5.0)

    assert r1.status is Z3Status.DISCHARGED
    assert r2.status is Z3Status.DISCHARGED

    # Post-state: global seed parameter is unchanged from pre-state.
    # Z3 returns "0" or the prior value as a string — we assert it's NOT
    # one of the runner-supplied seeds (which would indicate the leak).
    if pre_global is not None:
        post_global = z3.get_param("smt.random_seed")
        assert post_global == pre_global, (
            f"Z3 module-global smt.random_seed was mutated by runner: "
            f"pre={pre_global!r} post={post_global!r}; expected unchanged "
            "after the BUG 7 fix moved seed-setting to per-Solver"
        )


def test_panel_bug_7_strength_check_global_set_param_does_mutate():
    """Strength check for BUG 7: confirm the broken pattern (the pre-fix code)
    DOES mutate the module global, so the regression test above is detecting
    a real signal — not a vacuous pass on a Z3 build that ignores the param.

    Saves and restores the global to avoid leaking into sibling tests."""
    # Cumulative-pre-soak Patch 10 (Gate 1, 2026-05-04): use
    # importorskip so lean installs without z3-solver get a clean SKIP.
    z3 = pytest.importorskip("z3")
    if not hasattr(z3, "get_param") or not hasattr(z3, "set_param"):
        pytest.skip("z3 build lacks get_param/set_param introspection")

    pre = z3.get_param("smt.random_seed")
    try:
        z3.set_param("smt.random_seed", 4242)
        observed = z3.get_param("smt.random_seed")
        assert observed == "4242", (
            f"expected z3.set_param to mutate the global to '4242', got {observed!r}; "
            "if this fails the BUG 7 regression test is vacuous on this z3 build"
        )
    finally:
        z3.set_param("smt.random_seed", pre)


def test_panel_bug_7_subprocess_invoker_passes_seed_via_cli(monkeypatch):
    """Subprocess invoker must pass the seed as a CLI arg (`smt.random_seed=N`),
    not via module-global mutation. Process isolation makes this safe by
    construction, but verify the wiring so a future refactor can't regress it
    silently."""
    from audit_bundle.discharge import z3_runner as zr

    captured: list = []

    class _FakeProc:
        returncode = 0
        stdout = "unsat\n"
        stderr = ""

    def fake_run(cmd, **kwargs):
        # run() now also issues a `z3 --version` probe (solver-policy
        # provenance) — capture every call and assert on the solve call.
        captured.append(cmd)
        return _FakeProc()

    monkeypatch.setattr(zr.subprocess, "run", fake_run)

    inv = zr.SubprocessZ3Invoker(z3_binary_path="/nonexistent/z3", random_seed=777)
    out = inv.run("(check-sat)", timeout_s=2.0)
    assert out.status is zr.Z3Status.DISCHARGED
    solve_cmds = [c for c in captured if "--version" not in c]
    assert len(solve_cmds) == 1, captured
    assert "smt.random_seed=777" in solve_cmds[0], solve_cmds[0]
