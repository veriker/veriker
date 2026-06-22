"""audit_bundle/verdict.py — the canonical V-pillar verdict contract (tri-state).

Keel module for the verdict contract. stdlib-only (importable on the
offline core; no `cryptography`, no network). Defines:

  * VerdictState  — OK | REJECT | ERROR  (BI-1: the tri-state)
  * VerdictReason — one machine-stable reason (INPUT_* / VERIFIER_* per §7 taxonomy)
  * Verdict       — the canonical verdict every verdict-bearing entry point returns,
                    with back-compat faces (.ok / .failures / .reason / .detail) so the
                    existing VerifyResult consumers keep working during migration.
  * VerifierError — internal signal: "the verifier could not conclude" → mapped to an
                    ERROR verdict by `fail_closed` (lets a deep step ABORT to ERROR with
                    a precise code, e.g. the BI-4 unexpected-plugin-exception).
  * fail_closed   — the differentiated outer boundary (BI-2): wraps a verdict-bearing
                    entry point so NO stdlib exception escapes — it becomes an ERROR
                    verdict (traceback logged at CRITICAL). SystemExit/KeyboardInterrupt
                    propagate (NOT BaseException). RecursionError/MemoryError ARE
                    Exceptions → ERROR (correct).

The state distinction is load-bearing (BI-1): REJECT = "I ran my full logic; the
ARTIFACT is bad"; ERROR = "I could not conclude" (about the VERIFIER). Conflating them
is alert-laundering — an attacker who crafts a verifier-crashing input must NOT produce
a reject indistinguishable from a real one.
"""

from __future__ import annotations

import functools
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable

logger = logging.getLogger("audit_bundle.verdict")


class VerdictState(str, Enum):
    """The three verdict states (BI-1). `str` mixin so a state compares/serializes
    as its name for back-compat logging and JSON."""

    OK = "OK"  # ran full logic; artifact verified good on this dimension
    REJECT = "REJECT"  # ran full logic; artifact is bad (INPUT_* reason)
    ERROR = "ERROR"  # could NOT conclude; verifier-side (VERIFIER_* reason)


class ErrorKind(str, Enum):
    """Sub-kind of an ERROR verdict (Q2 two-class ERROR model, ADR §5.2 RULING).

    BI-1 keeps exactly THREE top-level states; this discriminator lives BELOW
    `state == ERROR` and is consulted only by composition + telemetry — it is NOT a
    fourth top-level state (precondition-3: both REJECT and ERROR hard-block downstream,
    so safety never needs to distinguish the two ERROR kinds).

      * CRASH       — an unexpected exception / OOM / stack-exhaustion / verifier-state
                      corruption. Process integrity is in doubt, so sibling-leg results
                      cannot be trusted: this is the BI-4 plugin-abort. GLOBAL + dominant
                      + short-circuits the run (`crash-ERROR > REJECT > clean-ERROR > OK`).
      * INCOMPLETE  — a leg CLEANLY returned "cannot conclude" (e.g. key material absent,
                      INSUFFICIENT_GROUNDS, LEG_INDETERMINATE). A LOCAL unknown — a sibling
                      REJECT still stands (REJECT-dominant over a clean-ERROR).
    """

    CRASH = "CRASH"
    INCOMPLETE = "INCOMPLETE"


# ---------------------------------------------------------------------------
# Reason-code taxonomy (§7). INPUT_* accompanies REJECT, VERIFIER_* accompanies
# ERROR. NOTE: legacy domain codes (CID_MISMATCH, bad_file_sha, …) are NOT yet
# re-prefixed — that is the D8 public-schema-bump migration. The harness enforces
# the STATE-level invariant + that boundary/admission codes are correctly
# namespaced; it does not force-prefix every legacy domain reject code.
# ---------------------------------------------------------------------------

# INPUT_* — REJECT (about the artifact/input)
INPUT_MALFORMED_MANIFEST = "INPUT_MALFORMED_MANIFEST"
INPUT_MALFORMED_JSON = "INPUT_MALFORMED_JSON"
INPUT_FIELD_TYPE_MISMATCH = "INPUT_FIELD_TYPE_MISMATCH"
INPUT_DEPTH_EXCEEDED = "INPUT_DEPTH_EXCEEDED"
INPUT_SIZE_EXCEEDED = "INPUT_SIZE_EXCEEDED"
INPUT_CARDINALITY_EXCEEDED = "INPUT_CARDINALITY_EXCEEDED"
INPUT_MALFORMED_ASSEMBLY = "INPUT_MALFORMED_ASSEMBLY"

# VERIFIER_* — ERROR (about the verifier)
VERIFIER_INTERNAL_ERROR = (
    "VERIFIER_INTERNAL_ERROR"  # crash-class (outer-boundary catch)
)
VERIFIER_UNEXPECTED_PLUGIN_EXCEPTION = (
    "VERIFIER_UNEXPECTED_PLUGIN_EXCEPTION"  # crash-class
)
VERIFIER_INCOMPLETE = "VERIFIER_INCOMPLETE"  # clean-ERROR: a leg could not conclude

INPUT_PREFIX = "INPUT_"
VERIFIER_PREFIX = "VERIFIER_"


@dataclass(frozen=True, slots=True)
class VerdictReason:
    """One reason. `code` is the machine-stable string; `check_name` names the step/leg
    that produced it; `detail` is human text. `.reason_code` is a back-compat alias for
    the legacy `VerifyFailure.reason_code` field name."""

    code: str
    check_name: str = ""
    detail: str = ""

    @property
    def reason_code(self) -> str:  # back-compat: VerifyFailure.reason_code
        return self.code


@dataclass(frozen=True, slots=True)
class Completeness:
    """Which validation layers actually ran (D5/Q3). Surfaced on the verdict face so a
    consumer can never mistake a shallow pass for a complete one. `layers` is the set of
    layer names that ran; `deep_validation` records whether the deep validate_manifest
    checks were executed for this bundle.

    `disclosures` carries honest residuals a GREEN verdict must still surface
    (e.g. the conservation gate's unsealed-lane note that manifest.json is
    parse-validated but byte-integrity-owned by nobody, or auditor fs_ignore
    tolerances). Disclosed-not-silently-passed: a consumer that ignores this
    field gets the same verdict as before; one that reads it sees exactly
    which guarantees the green verdict does NOT include."""

    layers: tuple[str, ...] = ()
    deep_validation: bool = False
    disclosures: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Verdict:
    """The canonical V-pillar verdict (ADR D1). `state` is authoritative; `.ok` is a
    derived back-compat face (ERROR → ok=False, fail-closed for legacy `if r.ok:`).

    `legs` carries the per-dimension breakdown for composites (D6); `completeness`
    declares which validation layers ran (D5). `error_kind` is the Q2 two-class ERROR
    discriminator (ADR §5.2): set ONLY when `state is ERROR`, distinguishing a global
    CRASH from a local INCOMPLETE. It never adds a fourth top-level state (BI-1).
    """

    state: VerdictState
    reasons: tuple[VerdictReason, ...] = ()
    legs: tuple["Verdict", ...] = ()
    completeness: Completeness | None = None
    error_kind: ErrorKind | None = None

    def __post_init__(self) -> None:
        # Invariant: error_kind is meaningful ONLY on an ERROR verdict. An ERROR built
        # without an explicit kind defaults to CRASH (the fail-closed dominant class — an
        # unclassified error is treated as the worst case). A non-ERROR verdict never
        # carries a kind. frozen dataclass → mutate via object.__setattr__.
        if self.state is VerdictState.ERROR:
            if self.error_kind is None:
                object.__setattr__(self, "error_kind", ErrorKind.CRASH)
        elif self.error_kind is not None:
            object.__setattr__(self, "error_kind", None)

    # -- constructors -------------------------------------------------------
    @classmethod
    def passed(cls, *, completeness: Completeness | None = None) -> "Verdict":
        return cls(VerdictState.OK, (), (), completeness)

    # alias kept for symmetry with future call sites
    ok_ = passed

    @classmethod
    def reject(cls, reason: str, detail: str = "", check_name: str = "") -> "Verdict":
        return cls(VerdictState.REJECT, (VerdictReason(reason, check_name, detail),))

    @classmethod
    def error(
        cls,
        reason: str = VERIFIER_INTERNAL_ERROR,
        detail: str = "",
        check_name: str = "",
    ) -> "Verdict":
        """A crash-class ERROR (INDETERMINATE): an unexpected exception / verifier-state
        corruption. GLOBAL + dominant + short-circuits composition (the BI-4 abort)."""
        return cls(
            VerdictState.ERROR,
            (VerdictReason(reason, check_name, detail),),
            error_kind=ErrorKind.CRASH,
        )

    @classmethod
    def incomplete(
        cls,
        reason: str = VERIFIER_INCOMPLETE,
        detail: str = "",
        check_name: str = "",
    ) -> "Verdict":
        """A clean-ERROR (INCOMPLETE): a leg cleanly returned "cannot conclude" (e.g.
        INSUFFICIENT_GROUNDS, LEG_INDETERMINATE). A LOCAL unknown — REJECT-dominant under
        composition (a sibling REJECT stands). `.ok` is False (not-passing, fail-closed)."""
        return cls(
            VerdictState.ERROR,
            (VerdictReason(reason, check_name, detail),),
            error_kind=ErrorKind.INCOMPLETE,
        )

    @classmethod
    def from_failures(
        cls, failures: Any, *, completeness: Completeness | None = None
    ) -> "Verdict":
        """Build a REJECT/OK verdict from a list of failures (VerifyFailure-like objects
        with .reason_code/.check_name/.detail, or VerdictReason). Empty → OK."""
        reasons = tuple(
            r
            if isinstance(r, VerdictReason)
            else VerdictReason(
                getattr(r, "reason_code", getattr(r, "code", "")),
                getattr(r, "check_name", ""),
                getattr(r, "detail", ""),
            )
            for r in failures
        )
        state = VerdictState.OK if not reasons else VerdictState.REJECT
        return cls(state, reasons, (), completeness)

    # -- back-compat faces --------------------------------------------------
    @property
    def ok(self) -> bool:
        return self.state is VerdictState.OK

    @property
    def failures(self) -> list[VerdictReason]:
        """Back-compat for verifier.VerifyResult.failures consumers."""
        return list(self.reasons)

    @property
    def reason(self) -> str | None:
        """Back-compat for o5.VerifyResult.reason (first reason code, None on pass)."""
        return self.reasons[0].code if self.reasons else None

    @property
    def detail(self) -> str:
        """Back-compat for o5.VerifyResult.detail (first reason detail)."""
        return self.reasons[0].detail if self.reasons else ""

    # -- Q2 ERROR-class discriminators (ADR §5.2) ---------------------------
    @property
    def is_crash(self) -> bool:
        """An ERROR of the global, dominant CRASH class (verifier-state in doubt)."""
        return self.state is VerdictState.ERROR and self.error_kind is ErrorKind.CRASH

    @property
    def is_incomplete(self) -> bool:
        """An ERROR of the local, REJECT-dominated INCOMPLETE class (cannot conclude)."""
        return (
            self.state is VerdictState.ERROR and self.error_kind is ErrorKind.INCOMPLETE
        )


class VerifierError(Exception):
    """Internal signal that the VERIFIER could not conclude (→ ERROR verdict, NOT a
    reject). Raise this from a deep step to ABORT to a precise ERROR code with the
    differentiated boundary mapping it (BI-4: an unexpected plugin exception poisons the
    whole verdict to INDETERMINATE and aborts, carrying plugin_id + detail)."""

    def __init__(self, code: str = VERIFIER_INTERNAL_ERROR, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def fail_closed(check_name: str = "verify") -> Callable:
    """Differentiated outer boundary (BI-2). Decorate a verdict-bearing entry point so
    NO stdlib exception escapes:

      * SystemExit / KeyboardInterrupt  → propagate (NOT BaseException).
      * VerifierError                   → ERROR verdict carrying its precise code.
      * any other Exception (incl. RecursionError / MemoryError) → ERROR verdict
        (VERIFIER_INTERNAL_ERROR), full traceback logged at CRITICAL.

    The wrapped function's normal return (an OK/REJECT Verdict) is passed through
    untouched, so the boundary only ever ADDS the ERROR path — it never turns a real
    REJECT into something else, and (crucially) never turns an exception into OK."""

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Verdict:
            try:
                return fn(*args, **kwargs)
            except (SystemExit, KeyboardInterrupt):
                raise
            except VerifierError as exc:
                logger.critical(
                    "verifier ERROR in %s: %s", check_name, exc, exc_info=True
                )
                return Verdict.error(exc.code, exc.detail, check_name)
            except Exception as exc:  # noqa: BLE001 — fail-closed contract: never escape
                logger.critical(
                    "verifier ERROR in %s: %s: %s",
                    check_name,
                    type(exc).__name__,
                    exc,
                    exc_info=True,
                )
                return Verdict.error(
                    VERIFIER_INTERNAL_ERROR,
                    f"{type(exc).__name__}: {exc}",
                    check_name,
                )

        return wrapper

    return decorator


def compose(
    legs: "list[Verdict] | tuple[Verdict, ...]",
    *,
    gating: "list[bool] | tuple[bool, ...] | None" = None,
) -> Verdict:
    """Compose per-leg verdicts into one composite (ADR D6/D7 + Q2 RULING §5.2).

    The ratified composition algebra is the MEET over the total dominance order

        crash-ERROR  >  REJECT  >  clean-ERROR  >  OK

    (a crash short-circuits — process integrity is in doubt, so sibling results cannot
    be trusted; this IS the BI-4 plugin-abort as the composition rule for the crash
    class). Concretely, over the GATING legs:

      * any gating leg is crash-ERROR  → composite crash-ERROR (its reasons first);
      * else any gating leg is REJECT  → composite REJECT (REJECT reasons first);
      * else any gating leg is clean-ERROR (INCOMPLETE) → composite clean-ERROR;
      * else                            → OK.

    `gating` is an optional boolean mask the SAME length as `legs` (True = a gating leg
    that participates in the top-level state; False = ADVISORY). Default (None) = every
    leg is gating. ADVISORY legs are STILL recorded in the returned `Verdict.legs` but
    NEVER affect the composite `state` (D6/D7, the native-Fulcio advisory-leg precedent).

    The dominant class's reasons are ordered FIRST in the composite `reasons` (so a
    single-fault composite surfaces that fault's code as `.reason` — the property the o5
    single-fault tests rely on), followed by the remaining gating legs' reasons. ALL legs
    (gating + advisory) are preserved in `legs` so a per-leg ERROR is never swallowed.
    """
    legs = tuple(legs)
    if gating is None:
        mask = (True,) * len(legs)
    else:
        mask = tuple(gating)
        if len(mask) != len(legs):
            raise VerifierError(
                VERIFIER_INTERNAL_ERROR,
                f"compose(): gating mask len {len(mask)} != legs len {len(legs)}",
            )
    gating_legs = tuple(leg for leg, g in zip(legs, mask) if g)

    def _ordered(dominant: "tuple[Verdict, ...]") -> tuple[VerdictReason, ...]:
        dom_ids = {id(d) for d in dominant}
        first = tuple(r for d in dominant for r in d.reasons)
        rest = tuple(
            r for leg in gating_legs if id(leg) not in dom_ids for r in leg.reasons
        )
        return first + rest

    crash = tuple(leg for leg in gating_legs if leg.is_crash)
    if crash:
        return Verdict(
            VerdictState.ERROR, _ordered(crash), legs, error_kind=ErrorKind.CRASH
        )
    rejects = tuple(leg for leg in gating_legs if leg.state is VerdictState.REJECT)
    if rejects:
        return Verdict(VerdictState.REJECT, _ordered(rejects), legs)
    incompletes = tuple(leg for leg in gating_legs if leg.is_incomplete)
    if incompletes:
        return Verdict(
            VerdictState.ERROR,
            _ordered(incompletes),
            legs,
            error_kind=ErrorKind.INCOMPLETE,
        )
    return Verdict(VerdictState.OK, (), legs)
