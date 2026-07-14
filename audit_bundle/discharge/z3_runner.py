"""audit_bundle/discharge/z3_runner.py — Z3 invocation with deterministic budget + outcome map.

Two real invokers + one fake invoker:

  - InProcessZ3Invoker  — uses the bundled z3-solver Python module. Default,
                          works wherever z3-solver is installed (no z3.exe on
                          PATH required).
  - SubprocessZ3Invoker — invokes the z3 binary on PATH. Preferred when
                          available because OS-level isolation survives Z3
                          crashes (sigsegv, OOM).
  - FakeZ3Invoker       — test seam. Yields scripted Z3Result responses. Used
                          by the adversarial suite to drive crash / timeout /
                          unknown / divergence paths deterministically without
                          requiring Z3 on the test machine.

`pick_default_invoker()` returns SubprocessZ3Invoker if z3 binary is on PATH,
else InProcessZ3Invoker if the python module is importable, else None.

Outcome map (negation pattern — we assert NOT(refinement) inside the script):
    Z3 ``unsat``    → Z3Status.DISCHARGED        (refinement proved)
    Z3 ``sat``      → Z3Status.FAILED            (counterexample exists)
    Z3 ``unknown``  → Z3Status.UNKNOWN           (decidability boundary)
    budget-exhausted ``unknown`` → Z3Status.TIMEOUT
    Z3 process crash / non-zero exit / parse error → Z3Status.SUBPROCESS_FAILURE

Determinism doctrine (tribunal-ratified 2026-06-10, replaces the wall-clock
posture this module shipped with):

  * The verdict-bearing budget is Z3's ``rlimit`` — an abstract resource
    counter that is machine-speed-independent: same Z3 version + same input
    + same rlimit → same outcome on any machine. When an invoker carries an
    rlimit, wall-clock plays NO classification role; it survives only as an
    OS-level crash guard on the subprocess invoker, and a crash-guard firing
    is SUBPROCESS_FAILURE (infrastructure error), never TIMEOUT.
  * Without an rlimit (legacy mode) the wall-clock ``timeout`` budget still
    applies, and outcomes near the budget boundary are machine-dependent.
    The C16 plugin treats such replays as NON-AUTHORITATIVE.
  * The TIMEOUT/UNKNOWN split is display-only. Verdict weight rides the
    coarse lattice {discharged, failed, not_proved} in the C16 plugin —
    reason strings are free-form English that drifts across Z3 versions and
    must never bear verdict weight.
  * Seed: Z3's default random seed is fixed (0) per version — leaving it
    unset is deterministic on one build, but invokers default to an explicit
    0 so the configuration is visible in `solver_policy()` and pinnable in
    proof records. The C16 caller policy on ``unknown`` is to record it,
    never to silently retry with another seed.

`Z3Invoker.solver_policy()` returns the dict {invoker_kind, random_seed,
rlimit, z3_version} that minting writes into `recheck_context["__solver_policy__"]`
(HMAC-bound via context_canonical_sha256) and the C16 plugin replays under.
"""

from __future__ import annotations

import enum
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Iterable


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


class Z3Status(str, enum.Enum):
    DISCHARGED = "discharged"
    FAILED = "failed"
    UNKNOWN = "unknown"
    TIMEOUT = "timeout"
    SUBPROCESS_FAILURE = "subprocess_failure"


@dataclass(frozen=True)
class Z3Result:
    status: Z3Status
    raw_output: str
    elapsed_seconds: float
    invoker_kind: str  # 'in_process' | 'subprocess' | 'fake'
    # Solver-policy provenance (determinism doctrine 2026-06-10). Defaults keep
    # pre-existing construction sites (FakeZ3Invoker test scripts) valid.
    # elapsed_seconds stays diagnostic-only: it never classifies an outcome.
    z3_version: str | None = None
    rlimit: int | None = None
    random_seed: int | None = None


# Keys of the pinned solver policy a minting verifier writes into
# recheck_context["__solver_policy__"]. Living inside recheck_context means the
# policy is HMAC-bound via the existing context_canonical_sha256 payload field —
# tampering with a pinned policy breaks the V16 signature, no wire-format change.
SOLVER_POLICY_KEYS: tuple[str, ...] = (
    "invoker_kind",
    "random_seed",
    "rlimit",
    "z3_version",
)

# Default deterministic recheck budget (Z3 abstract resource units) used by
# pick_default_invoker(). Empirical basis (z3 4.16.0, 2026-06-10): a trivial
# QF_LIA discharge consumes ~14 units; 200M units is several wall-seconds of
# work on 2026 hardware — comparable to the old 5s wall budget, but identical
# on every machine for a given Z3 version.
DEFAULT_RECHECK_RLIMIT: int = 200_000_000


def normalize_z3_version(raw: str | None) -> str | None:
    """Reduce a Z3 version self-report to its bare dotted version.

    'Z3 version 4.16.0 - 64 bit' (CLI) and '4.16.0' (python module) both
    normalize to '4.16.0' so the two invoker kinds agree on identity."""
    if not raw:
        return None
    m = re.search(r"\d+\.\d+\.\d+(?:\.\d+)?", raw)
    return m.group(0) if m else raw.strip() or None


# ---------------------------------------------------------------------------
# Invoker base + fakes
# ---------------------------------------------------------------------------


class Z3Invoker:
    """Abstract invoker. Concrete subclasses implement run(script, timeout_s)."""

    kind: str = "abstract"
    random_seed: int | None = None
    rlimit: int | None = None

    def run(self, script: str, timeout_s: float) -> Z3Result:  # pragma: no cover
        raise NotImplementedError

    @property
    def z3_version(self) -> str | None:  # pragma: no cover - overridden
        return None

    def solver_policy(self) -> dict:
        """The pinnable solver policy of this invoker (SOLVER_POLICY_KEYS shape).

        Minting writes this into recheck_context['__solver_policy__'] so the
        budget/seed/version the claim was minted under travels with the record
        inside the HMAC-bound context."""
        return {
            "invoker_kind": self.kind,
            "random_seed": self.random_seed,
            "rlimit": self.rlimit,
            "z3_version": normalize_z3_version(self.z3_version),
        }


class FakeZ3Invoker(Z3Invoker):
    """Scripted invoker for adversarial tests.

    `responses` is consumed in order; each call to `run()` yields the next.
    Used to drive crash / timeout / unknown / divergence paths deterministically.
    """

    kind = "fake"

    def __init__(
        self,
        responses: Iterable[Z3Result],
        *,
        z3_version: str | None = None,
        random_seed: int | None = None,
        rlimit: int | None = None,
    ):
        self._responses = list(responses)
        self._index = 0
        self.last_script: str | None = None
        self.last_timeout: float | None = None
        # Declared identity for solver_policy()/authority tests — lets the
        # adversarial suite script version-skew and budget scenarios.
        self._z3_version = z3_version
        self.random_seed = random_seed
        self.rlimit = rlimit

    @property
    def z3_version(self) -> str | None:
        return self._z3_version

    def run(self, script: str, timeout_s: float) -> Z3Result:
        self.last_script = script
        self.last_timeout = timeout_s
        if self._index >= len(self._responses):
            raise AssertionError(
                f"FakeZ3Invoker exhausted: expected at most {len(self._responses)} call(s)"
            )
        r = self._responses[self._index]
        self._index += 1
        return r


# ---------------------------------------------------------------------------
# In-process invoker (z3-solver python module)
# ---------------------------------------------------------------------------


class InProcessZ3Invoker(Z3Invoker):
    """Uses the bundled z3-solver Python module. No external binary required.

    With `rlimit` set (the default), the budget is Z3's deterministic abstract
    resource counter and NO wall-clock timeout is installed — rlimit bounds the
    work and guarantees termination, and installing a wall budget alongside it
    would let a slow machine's clock fire before the resource budget, flipping
    a would-be DISCHARGED into not-proved (the exact nondeterminism this
    posture removes). `rlimit=None` is legacy wall-clock mode."""

    kind = "in_process"

    def __init__(
        self,
        *,
        random_seed: int | None = 0,
        rlimit: int | None = DEFAULT_RECHECK_RLIMIT,
    ):
        self.random_seed = random_seed
        self.rlimit = rlimit

    @property
    def z3_version(self) -> str | None:
        try:
            import z3
        except ImportError:
            return None
        return normalize_z3_version(z3.get_version_string())

    def run(self, script: str, timeout_s: float) -> Z3Result:
        try:
            import z3  # imported lazily so the module is import-clean without z3-solver
        except ImportError as exc:
            return Z3Result(
                status=Z3Status.SUBPROCESS_FAILURE,
                raw_output=f"z3-solver python module not importable: {exc}",
                elapsed_seconds=0.0,
                invoker_kind=self.kind,
            )

        start = time.monotonic()
        try:
            solver = z3.Solver()
            if self.rlimit is not None:
                solver.set("rlimit", self.rlimit)
            else:
                # Legacy wall-clock budget — outcomes near the boundary are
                # machine-dependent; the C16 plugin treats this replay mode
                # as non-authoritative on mismatch.
                solver.set("timeout", max(1, int(round(timeout_s * 1000))))
            if self.random_seed is not None:
                # BUG 7 (panel review 2026-05-02): the prior code called
                # z3.set_param("smt.random_seed", N) which mutates Z3's
                # MODULE-GLOBAL parameter, leaking across invocations and
                # racing under threading. Set per-solver via Solver.set().
                solver.set("random_seed", self.random_seed)
            try:
                # parse_smt2_string returns a vector of asserted formulas; we add them all
                asserts = z3.parse_smt2_string(script)
            except z3.Z3Exception as exc:
                elapsed = time.monotonic() - start
                return Z3Result(
                    status=Z3Status.SUBPROCESS_FAILURE,
                    raw_output=f"z3 parse error: {exc}",
                    elapsed_seconds=elapsed,
                    invoker_kind=self.kind,
                )
            solver.add(asserts)
            outcome = solver.check()
            elapsed = time.monotonic() - start
            outcome_str = repr(outcome)
            if str(outcome) == "unsat":
                status = Z3Status.DISCHARGED
            elif str(outcome) == "sat":
                status = Z3Status.FAILED
            elif str(outcome) == "unknown":
                # Budget-exhausted vs decidability-boundary unknown, from the
                # solver's own reason string ONLY — the former elapsed-time
                # heuristic (`elapsed >= timeout_s * 0.95`) classified on an
                # unrecorded wall clock and is gone. This split is display-only:
                # verdict weight rides the coarse lattice in the C16 plugin,
                # where both map to not_proved.
                reason = (solver.reason_unknown() or "").lower()
                if (
                    "timeout" in reason
                    or "canceled" in reason
                    or "resource limit" in reason
                ):
                    status = Z3Status.TIMEOUT
                else:
                    status = Z3Status.UNKNOWN
                outcome_str = f"unknown (reason: {reason})"
            else:
                status = Z3Status.SUBPROCESS_FAILURE
                outcome_str = f"unrecognised z3 outcome: {outcome!r}"
            return Z3Result(
                status=status,
                raw_output=outcome_str,
                elapsed_seconds=elapsed,
                invoker_kind=self.kind,
                z3_version=normalize_z3_version(z3.get_version_string()),
                rlimit=self.rlimit,
                random_seed=self.random_seed,
            )
        except Exception as exc:
            elapsed = time.monotonic() - start
            return Z3Result(
                status=Z3Status.SUBPROCESS_FAILURE,
                raw_output=f"z3 in-process exception: {type(exc).__name__}: {exc}",
                elapsed_seconds=elapsed,
                invoker_kind=self.kind,
            )


# ---------------------------------------------------------------------------
# Subprocess invoker
# ---------------------------------------------------------------------------


class SubprocessZ3Invoker(Z3Invoker):
    """Invokes a z3 binary on PATH (or explicit path). Survives Z3 crashes via
    OS-level process isolation."""

    kind = "subprocess"

    def __init__(
        self,
        z3_binary_path: str | None = None,
        *,
        random_seed: int | None = 0,
        rlimit: int | None = DEFAULT_RECHECK_RLIMIT,
        memory_cap_mb: int = 512,
    ):
        if z3_binary_path is None:
            z3_binary_path = shutil.which("z3")
        if not z3_binary_path:
            raise FileNotFoundError(
                "z3 binary not found on PATH; install z3 or use InProcessZ3Invoker"
            )
        self.z3_binary_path = z3_binary_path
        self.random_seed = random_seed
        self.rlimit = rlimit
        self.memory_cap_mb = memory_cap_mb
        self._z3_version_cache: str | None | bool = False  # False = unprobed

    @property
    def z3_version(self) -> str | None:
        if self._z3_version_cache is False:
            try:
                proc = subprocess.run(
                    [self.z3_binary_path, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10.0,
                )
                self._z3_version_cache = normalize_z3_version(proc.stdout)
            except (OSError, subprocess.TimeoutExpired):
                self._z3_version_cache = None
        return self._z3_version_cache

    def run(self, script: str, timeout_s: float) -> Z3Result:
        cmd = [self.z3_binary_path, "-in", "-smt2"]
        if self.rlimit is not None:
            # Deterministic budget. No -T: wall flag alongside it — a wall
            # budget that can fire before the resource budget reintroduces
            # machine-speed-dependent outcomes.
            cmd.append(f"rlimit={self.rlimit}")
        else:
            cmd.append(f"-T:{int(round(timeout_s))}")
        if self.memory_cap_mb:
            cmd.append(f"-memory:{self.memory_cap_mb}")
        if self.random_seed is not None:
            cmd.append(f"smt.random_seed={self.random_seed}")

        # OS-level crash guard. In rlimit mode it is generous (rlimit is the
        # budget; this only catches a hung/defective z3) and firing is an
        # INFRASTRUCTURE error, never a verdict-classifying TIMEOUT.
        crash_guard_s = (
            (timeout_s * 10.0 + 30.0) if self.rlimit is not None else (timeout_s + 2.0)
        )
        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                input=script,
                capture_output=True,
                text=True,
                timeout=crash_guard_s,
            )
        except subprocess.TimeoutExpired:
            elapsed = time.monotonic() - start
            if self.rlimit is not None:
                return Z3Result(
                    status=Z3Status.SUBPROCESS_FAILURE,
                    raw_output=(
                        f"crash guard fired after {elapsed:.2f}s with "
                        f"rlimit={self.rlimit} set — z3 hang/defect, not a "
                        "verdict outcome"
                    ),
                    elapsed_seconds=elapsed,
                    invoker_kind=self.kind,
                )
            return Z3Result(
                status=Z3Status.TIMEOUT,
                raw_output=f"subprocess timeout after {elapsed:.2f}s",
                elapsed_seconds=elapsed,
                invoker_kind=self.kind,
            )
        except (OSError, FileNotFoundError) as exc:
            elapsed = time.monotonic() - start
            return Z3Result(
                status=Z3Status.SUBPROCESS_FAILURE,
                raw_output=f"subprocess failed: {type(exc).__name__}: {exc}",
                elapsed_seconds=elapsed,
                invoker_kind=self.kind,
            )

        elapsed = time.monotonic() - start
        out = (proc.stdout or "") + (proc.stderr or "")
        first_line = out.strip().splitlines()[0] if out.strip() else ""

        if proc.returncode != 0 and "unsat" not in out and "sat" not in out:
            return Z3Result(
                status=Z3Status.SUBPROCESS_FAILURE,
                raw_output=f"z3 exit {proc.returncode}: {out[:500]}",
                elapsed_seconds=elapsed,
                invoker_kind=self.kind,
            )

        def _result(status: Z3Status) -> Z3Result:
            return Z3Result(
                status=status,
                raw_output=out,
                elapsed_seconds=elapsed,
                invoker_kind=self.kind,
                z3_version=self.z3_version,
                rlimit=self.rlimit,
                random_seed=self.random_seed,
            )

        if first_line == "unsat":
            return _result(Z3Status.DISCHARGED)
        if first_line == "sat":
            return _result(Z3Status.FAILED)
        if first_line == "unknown":
            # Budget-exhausted vs other unknown — display-only split; verdict
            # weight rides the coarse lattice in the C16 plugin.
            if "timeout" in out.lower() or "resource" in out.lower():
                status = Z3Status.TIMEOUT
            else:
                status = Z3Status.UNKNOWN
            return _result(status)
        if "timeout" in out.lower() or "canceled" in out.lower():
            return Z3Result(Z3Status.TIMEOUT, out, elapsed, self.kind)
        return Z3Result(
            status=Z3Status.SUBPROCESS_FAILURE,
            raw_output=f"unrecognised z3 output: {out[:500]}",
            elapsed_seconds=elapsed,
            invoker_kind=self.kind,
        )


# ---------------------------------------------------------------------------
# Default invoker selection
# ---------------------------------------------------------------------------


def pick_default_invoker() -> Z3Invoker | None:
    """Return the first available real invoker:
    1. SubprocessZ3Invoker if `z3` binary is on PATH (preferred — OS isolation).
    2. InProcessZ3Invoker if the z3-solver python module is importable.
    3. None if neither.

    Both come configured with the explicit-seed + DEFAULT_RECHECK_RLIMIT
    deterministic policy, so even legacy records (no pinned policy) are
    rechecked under a budget that replays identically across machines for a
    given Z3 version.
    """
    if shutil.which("z3"):
        try:
            return SubprocessZ3Invoker()
        except FileNotFoundError:
            pass
    try:
        import z3  # noqa: F401

        return InProcessZ3Invoker()
    except ImportError:
        return None


def invoker_from_policy(
    policy: dict, base_invoker: Z3Invoker | None = None
) -> Z3Invoker | None:
    """Build an invoker matching a pinned __solver_policy__ as closely as the
    host allows.

    Preference order: an invoker of the PINNED kind (constructed fresh with the
    pinned seed/rlimit), else the base invoker's kind re-configured with the
    pinned seed/rlimit, else the base invoker as-is. Returns None only when no
    real invoker is constructible and no base was given. The caller decides
    authority separately by comparing the USED invoker's solver_policy() to
    the pin — this helper never silently widens authority."""
    seed = policy.get("random_seed")
    rlim = policy.get("rlimit")
    kind = policy.get("invoker_kind")
    seed = seed if isinstance(seed, int) and not isinstance(seed, bool) else None
    rlim = rlim if isinstance(rlim, int) and not isinstance(rlim, bool) else None

    if kind == "subprocess":
        try:
            return SubprocessZ3Invoker(random_seed=seed, rlimit=rlim)
        except FileNotFoundError:
            pass
    if kind == "in_process":
        try:
            import z3  # noqa: F401

            return InProcessZ3Invoker(random_seed=seed, rlimit=rlim)
        except ImportError:
            pass

    if isinstance(base_invoker, SubprocessZ3Invoker):
        return SubprocessZ3Invoker(
            base_invoker.z3_binary_path,
            random_seed=seed,
            rlimit=rlim,
            memory_cap_mb=base_invoker.memory_cap_mb,
        )
    if isinstance(base_invoker, InProcessZ3Invoker):
        return InProcessZ3Invoker(random_seed=seed, rlimit=rlim)
    return base_invoker


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------


def discharge(
    script: str, *, timeout_s: float = 5.0, invoker: Z3Invoker | None = None
) -> Z3Result:
    """Discharge an SMT-LIB script and return the verifier-side outcome."""
    if not isinstance(script, str) or not script.strip():
        raise ValueError("discharge requires a non-empty SMT-LIB script string")
    if timeout_s <= 0:
        raise ValueError(f"timeout_s must be positive, got {timeout_s!r}")

    if invoker is None:
        invoker = pick_default_invoker()
        if invoker is None:
            return Z3Result(
                status=Z3Status.SUBPROCESS_FAILURE,
                raw_output=(
                    "no Z3 invoker available: install z3-solver Python package "
                    "or put the z3 binary on PATH"
                ),
                elapsed_seconds=0.0,
                invoker_kind="none",
            )

    return invoker.run(script, timeout_s)
