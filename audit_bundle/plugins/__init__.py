"""Audit bundle plugins."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from audit_bundle.plugin import TypedCheck
from .dispatch_record_wellformed import DispatchRecordWellformedCheck
from .stamp_lattice import StampLatticeCheck
from .refinement_discharge import RefinementDischargeCheck
from .verifier_identity_tripwire import VerifierIdentityTripwireCheck


# Optional file fallback for the verifier recheck secret. Operators opt in by
# pointing VKERNEL_VERIFIER_HMAC_KEY_FILE at an ABSOLUTE path to a dotenv-style
# file containing a VKERNEL_VERIFIER_HMAC_KEY=... line. A relative path is
# REFUSED so the secret source can never be influenced by the process working
# directory. There is deliberately NO hardcoded default path: a Windows-style
# "<drive>:/..." literal is not absolute on POSIX — it is parsed as a directory
# named "<drive>:" under the cwd, which would let an attacker-planted file below
# the working directory supply the verifier signing/recheck key.
_KEY_FILE_ENV = "VKERNEL_VERIFIER_HMAC_KEY_FILE"


def _read_key_from_dotenv(path: Path) -> str | None:
    """Line-scan a dotenv-style file for VKERNEL_VERIFIER_HMAC_KEY=..."""
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            if k.strip() == "VKERNEL_VERIFIER_HMAC_KEY":
                return v.strip().strip('"').strip("'")
    except OSError:
        return None
    return None


def _load_verifier_recheck_key():
    """Resolve VKERNEL_VERIFIER_HMAC_KEY → VerifierSigningKey or None.

    Source order: process env first; then — only when VKERNEL_VERIFIER_HMAC_KEY_FILE
    names an ABSOLUTE path to an existing file — a dotenv line-scan of that file.
    A relative key-file path is refused (the secret source must never depend on
    the working directory). Returns None when the secret is absent, preserving
    the FAIL-CLOSED posture for deployments that did not wire the verifier secret
    (mirrors the v0.1 strict-mode default).
    """
    secret = os.environ.get("VKERNEL_VERIFIER_HMAC_KEY")
    if not secret:
        key_file = os.environ.get(_KEY_FILE_ENV)
        if key_file:
            p = Path(key_file)
            if not p.is_absolute():
                # Refuse cwd-relative key files — surface the misconfiguration
                # rather than silently reading a working-directory-relative path.
                print(
                    f"[v-kernel] ignoring {_KEY_FILE_ENV}={key_file!r}: a verifier "
                    "key file must be an ABSOLUTE path (cwd-relative key sources "
                    "are refused).",
                    file=sys.stderr,
                )
            elif p.is_file():
                secret = _read_key_from_dotenv(p)
    if not secret:
        return None
    from audit_bundle.discharge.verifier_signing import VerifierSigningKey

    return VerifierSigningKey.from_secret_bytes(secret.encode("utf-8"))


def default_post_w3_plugin_set() -> tuple[TypedCheck, ...]:
    """Returns the C14+C15+C16 plugin set in the recommended invocation order.

    Order: C15 (well-formedness) before C14 (lattice) before C16 (refinement).
    Rationale: C14 reads stamp_observed and aggregate_stamp shape;
    well-formedness must pass first or downstream reasoning operates on
    malformed input. C16 reads proof fields whose shape is asserted by C15.

    Phase-0 cutover (2026-05-04): wires VKERNEL_VERIFIER_HMAC_KEY (process env,
    or an absolute dotenv file named by VKERNEL_VERIFIER_HMAC_KEY_FILE) as
    recheck_key. Without this, every
    stamp_upgrade / execution_trace / discharge-status check trips at
    FAIL-CLOSED — the v0.2 reason codes (STAMP_UPGRADE_OUT_OF_ORDER,
    STAMP_UPGRADE_DISCHARGE_LINK_BROKEN, WASM_TRACE_SIGNATURE_INVALID,
    DISCHARGE_STATUS_VERIFIER_DIVERGENCE, ...) would be unreachable in
    production. Falls back to None when the secret is absent.

    Also wires a Z3 invoker via pick_default_invoker() so the C16
    re-discharge path is reachable (DISCHARGE_STATUS_VERIFIER_DIVERGENCE,
    Z3_SUBPROCESS_FAILURE). Falls back to None when no Z3 backend is
    available — signature checks still run, and any verifier-signed smt-z3
    record then surfaces as Z3_RECHECK_NOT_AVAILABLE (incomplete=True,
    clean-ERROR) rather than a silent recheck skip (availability
    discipline, RES-01 hardening 2026-06-11).
    """
    key = _load_verifier_recheck_key()
    invoker = None
    try:
        from audit_bundle.discharge.z3_runner import pick_default_invoker

        invoker = pick_default_invoker()
    except Exception:
        invoker = None
    return (
        DispatchRecordWellformedCheck(recheck_key=key),
        StampLatticeCheck(recheck_key=key),
        RefinementDischargeCheck(recheck_key=key, recheck_invoker=invoker),
    )


def default_post_w3_plus_c18_plugin_set() -> tuple[TypedCheck, ...]:
    """Post-W3 plugin set EXTENDED with the C18 verifier_identity tripwire.

    This helper PRESERVES the existing default_post_w3_plugin_set() shape
    (C14/C15/C16 plugins) and APPENDS VerifierIdentityTripwireCheck. A
    separate helper name keeps legacy callers on the unextended set; C18-aware
    substrate verifiers use this helper.

    Invocation order: W3 plugins first (their results constrain the
    structural shape of the rest of the bundle), then C18 tripwire (its
    logging-only signal is surfaced on the verdict face via
    PluginResult.disclosures after the W3 plugins have validated
    structural integrity — verify() never writes inside bundle_dir).
    """
    return (*default_post_w3_plugin_set(), VerifierIdentityTripwireCheck())


__all__ = [
    "TypedCheck",
    "DispatchRecordWellformedCheck",
    "StampLatticeCheck",
    "RefinementDischargeCheck",
    "VerifierIdentityTripwireCheck",
    "default_post_w3_plugin_set",
    "default_post_w3_plus_c18_plugin_set",
]
