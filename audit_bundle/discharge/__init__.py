"""audit_bundle.discharge — V-Kernel v0.2 SMT discharge runner (C16 hardening).

Implements the audit-bundle contract §C16 (refinement fragment discharge).

Public surface:
  - smtlib_parser.parse_refinement(text)        -> ParsedRefinement | raise FragmentOutOfScope
  - context_substitution.substitute(parsed, ctx) -> SmtScript
  - z3_runner.discharge(script, *, timeout_s)    -> Z3Result
  - verifier_signing.sign_and_write(record, ...) -> dict (the only path that writes
                                                    proof.discharge_status post-v0.1)

Verifier-set discipline (load-bearing for V14 + the C16 contract):
  Only `verifier_signing.sign_and_write` is allowed to set proof.discharge_status to
  any value other than 'not-attempted'. The C16 plugin enforces this by rejecting
  unsigned non-trivial statuses as DISCHARGE_STATUS_FORGED.

v0.2 fragment locked: QF_LIA + QF_BV + QF_LRA + QF_UF.
v0.3 deferred: QF_AX (arrays), QF_S (strings), quantifiers, recursive datatypes,
               Lean-4 / Dafny backends.
"""

from __future__ import annotations

from .smtlib_parser import (
    FragmentOutOfScope,
    ParsedRefinement,
    SmtLibParseError,
    parse_refinement,
)
from .context_substitution import (
    ContextSubstitutionError,
    SmtScript,
    substitute,
)
from .z3_runner import (
    FakeZ3Invoker,
    InProcessZ3Invoker,
    SubprocessZ3Invoker,
    Z3Invoker,
    Z3Result,
    Z3Status,
    discharge,
    pick_default_invoker,
)
from .verifier_signing import (
    SIGNED_DISCHARGE_STATUS_VALUES,
    STAMP_UPGRADE_REASONS,
    SigningError,
    VerifierSigningKey,
    sign_and_write,
    sign_stamp_upgrade,
    verify_signature,
    verify_stamp_upgrade_signature,
)

__all__ = [
    "ContextSubstitutionError",
    "FakeZ3Invoker",
    "FragmentOutOfScope",
    "InProcessZ3Invoker",
    "ParsedRefinement",
    "SIGNED_DISCHARGE_STATUS_VALUES",
    "STAMP_UPGRADE_REASONS",
    "SigningError",
    "SmtLibParseError",
    "SmtScript",
    "SubprocessZ3Invoker",
    "VerifierSigningKey",
    "Z3Invoker",
    "Z3Result",
    "Z3Status",
    "discharge",
    "parse_refinement",
    "pick_default_invoker",
    "sign_and_write",
    "sign_stamp_upgrade",
    "substitute",
    "verify_signature",
    "verify_stamp_upgrade_signature",
]
