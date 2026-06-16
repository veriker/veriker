"""Verifier-set discharge discipline — C16 proof-field integrity per the audit-bundle contract §C16.

Layered shipped-vs-deferred disclosure (the "tabs statement"):
  Contract    — audit-bundle contract §C16.
  Plugin code — this file + audit_bundle/discharge/. Wired into veriker/cli/verify.py
                default plugin set.
  Enforcement scope:
    v0.1 — verifier-set discipline only: any discharge_status other than
           'not-attempted' was rejected as DISCHARGE_STATUS_FORGED. No
           semantic discharge pipeline (no Z3 calls).
    v0.2 — Z3-backed semantic discharge for the QF_LIA + QF_BV + QF_LRA + QF_UF
           fragment (this file). 'smt-z3' added to the proof.kind enum.
           Verifier-signed statuses ('discharged', 'failed', 'timeout',
           'unknown') admitted iff their HMAC signature re-verifies.
           Unsigned non-trivial statuses still fail as DISCHARGE_STATUS_FORGED.
    v0.3 — Lean-4 + Dafny backends. Schema reservation already in place; only
           backend implementation deferred.

Sub-invariants enforced (extends v0.1):
  1. Proof shape well-formed (kind, obligation_uri, obligation_sha,
     discharge_status). v0.2 adds the verifier_signature sub-field shape.
  2. Verifier-set discipline:
       - 'not-attempted' is always admissible (legitimate dispatcher default).
       - 'discharged' / 'failed' / 'timeout' / 'unknown' are admissible iff
         the record carries a valid HMAC signature from
         audit_bundle.discharge.verifier_signing (see V14 + V16 cross-file
         invariant). Unsigned status = DISCHARGE_STATUS_FORGED.
  3. Proof obligation file present and SHA-matched.
  4. NEW v0.2: For 'smt-z3' kind records, when a Z3Invoker is supplied, the
     plugin re-runs the discharge (parser → context substitution → Z3) and
     compares the runner outcome to the claimed (signed) discharge_status.
     Divergence → DISCHARGE_STATUS_VERIFIER_DIVERGENCE.
  5. NEW v0.2: refinement formulas in dispatch_record.outputs[].type.refine
     must lie in the v0.1 fragment per smtlib_parser.parse_refinement.
     Out-of-fragment → DISCHARGE_FRAGMENT_OUT_OF_SCOPE.

Reason codes added at v0.2:
  - DISCHARGE_FRAGMENT_OUT_OF_SCOPE       (parser rejected formula)
  - DISCHARGE_TIMEOUT                     (runner reported timeout)
  - DISCHARGE_UNKNOWN                     (runner reported unknown — non-fatal
                                           when claimed status is also 'unknown')
  - DISCHARGE_STATUS_VERIFIER_DIVERGENCE  (claimed contradicts AUTHORITATIVE replay)
  - Z3_SUBPROCESS_FAILURE                 (runner crash / parse error — clean-ERROR,
                                           incomplete=True: infrastructure, not artifact)

Determinism doctrine (tribunal-ratified 2026-06-10) — the recheck comparison:

  * Claimed and replayed statuses are compared on the COARSE lattice
    {discharged, failed, not_proved} where both 'timeout' and 'unknown'
    collapse to not_proved. The fine TIMEOUT/UNKNOWN split rides free-form
    Z3 reason strings that drift across versions and must never bear
    verdict weight; collapsing it also removes the claimed-'timeout'-vs-
    replayed-'unknown' false-divergence class outright.
  * The divergence matrix has THREE cells, not two:
      claim == replay (coarse)                      → confirmed
      claim != replay, replay AUTHORITATIVE          → DISCHARGE_STATUS_VERIFIER_DIVERGENCE (REJECT)
      claim != replay, replay NON-AUTHORITATIVE      → DISCHARGE_STATUS_NOT_CONFIRMED (clean-ERROR, exit 2)
    EXCEPTION: discharged↔failed (conclusive↔conclusive) is a sat/unsat
    contradiction no budget, seed, or version skew can explain — that is
    ALWAYS a divergence REJECT, authority irrelevant.
  * A replay is AUTHORITATIVE iff the record carries a pinned
    recheck_context['__solver_policy__'] (HMAC-bound via
    context_canonical_sha256 — tampering breaks the V16 signature) and the
    invoker actually used matches it on invoker_kind, random_seed, rlimit,
    and z3_version (or both versions are in accepted_z3_versions).
  * Producer-steered under-resourcing floor: a pinned rlimit below
    min_pinned_rlimit with a not_proved-class claim is
    DISCHARGE_UNDER_RESOURCED (clean-ERROR) even when the replay matches —
    a tiny budget makes 'unknown' trivially true for every obligation and
    would pass C16 with zero proof content. Conclusive claims (discharged /
    failed) are budget-independent (unsat is unsat at any budget) and skip
    the floor.

Reason codes added by the determinism doctrine:
  - DISCHARGE_STATUS_NOT_CONFIRMED        (mismatch under non-authoritative replay —
                                           present-but-unverified, never 'forged')
  - DISCHARGE_UNDER_RESOURCED             (pinned rlimit below verifier floor on a
                                           not_proved-class claim)

Availability discipline (RES-01 hardening, 2026-06-11) — the recheck capability:

  * A verifier-signed smt-z3 discharge claim that THIS verifier cannot
    semantically replay must never contribute to a silent GREEN. When the
    plugin holds no Z3Invoker (host lacks both the z3 binary and the
    z3-solver module; pick_default_invoker() returned None) and the manifest
    carries any non-'not-attempted' smt-z3 record, the result is
    Z3_RECHECK_NOT_AVAILABLE (incomplete=True, clean-ERROR, exit 2) — the
    same epistemic state as Z3_SUBPROCESS_FAILURE's missing-solver case,
    discovered at construction instead of mid-run. Signature validation
    still runs first, and a REJECT-class defect anywhere in the manifest
    (forged signature, divergence, shape) outranks the availability ERROR.
  * 'not-attempted' records carry no semantic claim and pass without a
    backend, so W3-baseline and dispatch-only bundles verify identically
    on every host — the verdict stays a function of bundle bytes + verifier
    config, with environment gaps surfacing loud instead of silently
    weakening the verdict.

Reason codes added by the availability discipline:
  - Z3_RECHECK_NOT_AVAILABLE              (signed smt-z3 claims present but no Z3
                                           backend on this host — clean-ERROR)


"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from audit_bundle.bundle_manifest import (
    UnsafeBundlePath,
    _safe_bundle_path,
    register_typed_check,
)
from audit_bundle.plugin import PluginResult

from audit_bundle.discharge.smtlib_parser import (
    FragmentOutOfScope,
    SmtLibParseError,
    parse_refinement,
)
from audit_bundle.discharge.context_substitution import (
    ContextSubstitutionError,
    substitute,
)
from audit_bundle.discharge.z3_runner import (
    SOLVER_POLICY_KEYS,
    Z3Invoker,
    Z3Status,
    discharge as run_z3,
    invoker_from_policy,
    normalize_z3_version,
)
from audit_bundle.discharge.verifier_signing import (
    DIVERGENCE_KIND_CONTEXT_SUBSTITUTION,
    DIVERGENCE_KIND_RUNNER_MISMATCH,
    SIGNED_DISCHARGE_STATUS_VALUES,
    VerifierSigningKey,
    extract_refine_text,
    sign_divergence_record,
    verify_signature,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


VALID_DISCHARGE_STATUS: frozenset[str] = frozenset(
    {
        "discharged",
        "failed",
        "timeout",
        "unknown",
        "not-attempted",
    }
)

_VALID_KIND: frozenset[str] = frozenset({"lean-4", "dafny", "smt-z3"})

_SHA256_RE: re.Pattern = re.compile(r"^[0-9a-fA-F]{64}$")

_REQUIRED_PROOF_KEYS: frozenset[str] = frozenset(
    {"kind", "obligation_uri", "obligation_sha", "discharge_status"}
)


# ---------------------------------------------------------------------------
# Mapping z3 outcome -> claimed discharge_status (for the divergence check)
# ---------------------------------------------------------------------------


_Z3_TO_DISCHARGE: dict[Z3Status, str] = {
    Z3Status.DISCHARGED: "discharged",
    Z3Status.FAILED: "failed",
    Z3Status.UNKNOWN: "unknown",
    Z3Status.TIMEOUT: "timeout",
    # SUBPROCESS_FAILURE intentionally absent — caller logic handles separately
}

# Coarse verdict lattice (determinism doctrine 2026-06-10). 'timeout' and
# 'unknown' carry the same verdict weight: the obligation was attempted and
# not proved either way, and the split between them rides Z3 reason strings /
# budget mechanics that are not stable enough to bear verdict weight.
_COARSE_STATUS: dict[str, str] = {
    "discharged": "discharged",
    "failed": "failed",
    "timeout": "not_proved",
    "unknown": "not_proved",
}

# Verifier-side floor on pinned rlimit for not_proved-class claims (abstract
# Z3 resource units — see DEFAULT_RECHECK_RLIMIT for the unit's empirical
# scale: a trivial QF_LIA discharge is ~14 units, so 1M units is a genuine
# tens-of-milliseconds attempt, far above gaming territory and far below the
# default 200M recheck budget). Verifier config, so replay determinism holds.
DEFAULT_MIN_PINNED_RLIMIT: int = 1_000_000


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _RecheckPolicy:
    """Optional Z3 re-check configuration. When `key` is None and `invoker` is
    None, the plugin enforces shape + signature only (no Z3 invocation).
    When both are supplied, signed records of kind='smt-z3' are re-discharged
    and the runner outcome is compared against the claimed status."""

    key: VerifierSigningKey | None = None
    invoker: Z3Invoker | None = None
    timeout_s: float = 5.0
    # Determinism doctrine (2026-06-10):
    # Floor on pinned rlimit for not_proved-class claims — see
    # DEFAULT_MIN_PINNED_RLIMIT for the empirical basis.
    min_pinned_rlimit: int = DEFAULT_MIN_PINNED_RLIMIT
    # Z3 versions treated as replay-equivalent for authority. None = the
    # pinned and used versions must be EXACTLY equal (default posture);
    # operators who accept cross-version replay equivalence widen this
    # explicitly and own the trust consequence.
    accepted_z3_versions: frozenset[str] | None = None


class RefinementDischargeCheck:
    """TypedCheck plugin enforcing the audit-bundle contract §C16 verifier-set discipline.

    v0.2 hardening: accepts verifier-signed discharge_status values when the
    HMAC signature re-verifies. Optionally re-runs Z3 to detect verifier-vs-
    claim divergence when constructed with a recheck policy."""

    name: str = "refinement_discharge"
    applies_to_files: frozenset[str] = frozenset()

    # Deterministic timestamp sentinel for retained divergence records.
    # verify() is a pure function of bundle bytes + verifier config (SECURITY.md
    # replay map, row 1): stamping the retained record with wall time would make
    # back-to-back runs mint byte-different verdict disclosures. Callers that
    # want a real observation time inject divergence_timestamp_utc.
    DIVERGENCE_TS_UNRECORDED = "unrecorded"

    def __init__(
        self,
        *,
        recheck_key: VerifierSigningKey | None = None,
        recheck_invoker: Z3Invoker | None = None,
        recheck_timeout_s: float = 5.0,
        recheck_context_resolver=None,
        divergence_timestamp_utc: str | None = None,
        min_pinned_rlimit: int = DEFAULT_MIN_PINNED_RLIMIT,
        accepted_z3_versions: frozenset[str] | None = None,
    ):
        """`recheck_key` enables verifier-signature checking.

        When `recheck_key` is None, the plugin FAILS CLOSED on non-trivial
        discharge_status — every record that claims
        `discharged`/`failed`/`timeout`/`unknown` is rejected as
        DISCHARGE_STATUS_FORGED, preserving the v0.1 strict behaviour.
        Accepting any structurally-valid `verifier_signature` dict as
        sufficient proof when no key is wired would allow trivial forgery, so
        production deployments MUST supply the key.

        `recheck_invoker` enables Z3 re-discharge. When present, smt-z3 records
        with valid signatures are re-run end-to-end and the runner outcome is
        compared to the claimed (signed) discharge_status; divergence raises
        DISCHARGE_STATUS_VERIFIER_DIVERGENCE. When ABSENT and the manifest
        carries verifier-signed smt-z3 records, the plugin returns
        Z3_RECHECK_NOT_AVAILABLE (incomplete=True, clean-ERROR) — availability
        discipline: a signed semantic claim this host cannot replay never
        passes silently. 'not-attempted' records carry no semantic claim and
        pass without a backend.

        `recheck_context_resolver(record) -> dict` returns the dispatch
        substitution context for a record (so the plugin can rebuild the SMT
        script). When absent, the plugin reads the record's
        `proof.recheck_context` field. A resolver returning a non-dict yields
        DISCHARGE_STATUS_NOT_CONFIRMED (incomplete=True), never a silent pass.

        `divergence_timestamp_utc` stamps retained Fork A divergence records.
        Default None → the deterministic DIVERGENCE_TS_UNRECORDED sentinel,
        keeping verify() replayable (same bundle bytes → byte-identical
        verdict, disclosures included). An ops harness that wants a real
        observation time injects its own ISO-8601 string here — never a
        wall-clock read inside the verify path.

        `min_pinned_rlimit` / `accepted_z3_versions` configure the determinism
        doctrine (module docstring): the under-resourcing floor and the
        cross-version replay-equivalence set. Both are verifier config, so
        the verdict stays a pure function of bundle bytes + verifier config."""
        self.recheck_policy = _RecheckPolicy(
            key=recheck_key,
            invoker=recheck_invoker,
            timeout_s=recheck_timeout_s,
            min_pinned_rlimit=min_pinned_rlimit,
            accepted_z3_versions=accepted_z3_versions,
        )
        self.recheck_context_resolver = recheck_context_resolver
        self.divergence_timestamp_utc = (
            divergence_timestamp_utc
            if divergence_timestamp_utc is not None
            else self.DIVERGENCE_TS_UNRECORDED
        )

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        records = getattr(manifest, "dispatch_records", ()) or ()

        if not records:
            return PluginResult(
                ok=True,
                reason_code="PASS",
                detail="no dispatch_records present (W3-baseline / pre-Phase-0 bundle)",
                files_audited=(),
            )

        # Authoritative bundle_id (from manifest, NOT from the signature dict).
        # Used as ground truth in verify_signature so a sig from bundle A is
        # rejected when carried into bundle B.
        bundle_id = getattr(manifest, "bundle_id", None)

        rechecked = 0
        signed_admitted = 0
        not_attempted = 0
        not_replayable: list[int] = []
        disclosures: list[str] = []

        for idx, record in enumerate(records):
            if record is None:
                continue
            if not isinstance(record, dict):
                # Fail-closed type guard: a hostile non-dict dispatch_records
                # element would otherwise raise AttributeError out of the
                # plugin (record.get) and degrade the run to a
                # VERIFIER_INTERNAL_ERROR crash instead of a recorded REJECT.
                return PluginResult(
                    ok=False,
                    reason_code="DISPATCH_RECORD_MALFORMED",
                    detail=(
                        f"record[{idx}]: dispatch_records element must be a "
                        f"JSON object, got {type(record).__name__!r}"
                    ),
                    files_audited=(),
                )

            proof = record.get("proof")
            if proof is None:
                # Legacy/W3-baseline record with no proof field — skip silently.
                continue

            shape_failure = self._check_proof_shape(idx, proof, bundle_dir)
            if shape_failure is not None:
                return shape_failure

            discharge_status = proof["discharge_status"]

            if discharge_status == "not-attempted":
                not_attempted += 1
                continue

            # discharge_status != 'not-attempted' — must be verifier-signed.
            sig_failure = self._check_signature(
                idx,
                record,
                discharge_status,
                bundle_id=bundle_id,
            )
            if sig_failure is not None:
                return sig_failure
            signed_admitted += 1

            # 5. Refinement-fragment check on every output.type.refine,
            #    regardless of proof.kind. Out-of-fragment formulas are not
            #    eligible for stamp upgrade.
            frag_failure = self._check_refinement_fragment(idx, record)
            if frag_failure is not None:
                return frag_failure

            # 4. Z3 re-discharge for smt-z3 records. Availability discipline
            #    (module docstring): with no invoker on this host, the signed
            #    semantic claim cannot be replayed — collect the record and
            #    keep walking, so a REJECT-class defect on a LATER record
            #    (e.g. a forged signature) still surfaces as its REJECT
            #    instead of being masked by the availability clean-ERROR.
            if proof["kind"] == "smt-z3":
                if self.recheck_policy.invoker is None:
                    not_replayable.append(idx)
                    continue
                recheck_failure = self._recheck_smt_z3(
                    idx,
                    record,
                    discharge_status,
                    bundle_dir=bundle_dir,
                    bundle_id=bundle_id,
                    disclosures_out=disclosures,
                )
                if recheck_failure is not None:
                    return recheck_failure
                rechecked += 1

        if not_replayable:
            # Same epistemic state as Z3_SUBPROCESS_FAILURE's missing-solver
            # case, discovered at construction time instead of mid-run: the
            # artifact was not shown bad and was not confirmed either —
            # could-not-conclude (clean-ERROR), never a silent GREEN with
            # rechecked=0 buried in detail prose.
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="Z3_RECHECK_NOT_AVAILABLE",
                detail=(
                    f"{len(not_replayable)} verifier-signed smt-z3 record(s) "
                    f"at indices {not_replayable} carry semantic discharge "
                    "claims, but no Z3 backend is available on this host "
                    "(RefinementDischargeCheck was constructed without a "
                    "recheck_invoker). Signatures verified, but the claims "
                    "could not be semantically re-discharged. Install z3 or "
                    "the z3-solver module, or wire a recheck_invoker."
                ),
                files_audited=(),
            )

        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail=(
                f"refinement discharge discipline satisfied; "
                f"{len(records)} records audited; "
                f"{not_attempted} not-attempted, "
                f"{signed_admitted} verifier-signed, "
                f"{rechecked} re-discharged"
            ),
            files_audited=(),
            disclosures=tuple(disclosures),
        )

    # ------------------------------------------------------------------
    # Sub-checks
    # ------------------------------------------------------------------

    def _check_proof_shape(
        self, idx: int, proof, bundle_dir: Path
    ) -> PluginResult | None:
        if not isinstance(proof, dict):
            return PluginResult(
                ok=False,
                reason_code="PROOF_FIELD_MALFORMED",
                detail=(
                    f"record[{idx}]: proof must be a dict, got {type(proof).__name__!r}"
                ),
                files_audited=(),
            )

        missing = _REQUIRED_PROOF_KEYS - proof.keys()
        if missing:
            return PluginResult(
                ok=False,
                reason_code="PROOF_FIELD_MALFORMED",
                detail=f"record[{idx}]: proof is missing required keys: {sorted(missing)}",
                files_audited=(),
            )

        kind = proof["kind"]
        if kind not in _VALID_KIND:
            return PluginResult(
                ok=False,
                reason_code="PROOF_FIELD_MALFORMED",
                detail=(
                    f"record[{idx}]: proof.kind={kind!r} is not in the "
                    f"recognized verifier set {sorted(_VALID_KIND)}"
                ),
                files_audited=(),
            )

        obligation_uri = proof["obligation_uri"]
        if not isinstance(obligation_uri, str) or not obligation_uri:
            return PluginResult(
                ok=False,
                reason_code="PROOF_FIELD_MALFORMED",
                detail=f"record[{idx}]: proof.obligation_uri must be a non-empty string",
                files_audited=(),
            )

        obligation_sha = proof["obligation_sha"]
        if not isinstance(obligation_sha, str) or not _SHA256_RE.match(obligation_sha):
            return PluginResult(
                ok=False,
                reason_code="PROOF_FIELD_MALFORMED",
                detail=(
                    f"record[{idx}]: proof.obligation_sha must be a "
                    f"64-character hex string, got {obligation_sha!r}"
                ),
                files_audited=(),
            )

        discharge_status = proof["discharge_status"]
        if discharge_status not in VALID_DISCHARGE_STATUS:
            return PluginResult(
                ok=False,
                reason_code="PROOF_FIELD_MALFORMED",
                detail=(
                    f"record[{idx}]: proof.discharge_status={discharge_status!r} "
                    f"is not in the valid enum {sorted(VALID_DISCHARGE_STATUS)}"
                ),
                files_audited=(),
            )

        # Sub-invariant 3 — obligation file present and SHA-matched.
        # _safe_bundle_path fail-closes on path-escape (absolute paths,
        # .. traversal, symlinks leaving the tree) and directory targets
        # (a directory obligation_uri would otherwise raise IsADirectoryError
        # on read). Surface as a structured PluginResult failure rather
        # than letting UnsafeBundlePath propagate to the verifier.
        try:
            obligation_path = _safe_bundle_path(bundle_dir, obligation_uri)
        except UnsafeBundlePath as exc:
            return PluginResult(
                ok=False,
                reason_code="PROOF_OBLIGATION_PATH_UNSAFE",
                detail=(
                    f"record[{idx}]: refinement_discharge rejected unsafe "
                    f"obligation_uri={obligation_uri!r}: {exc}"
                ),
                files_audited=(),
            )
        if not obligation_path.exists():
            return PluginResult(
                ok=False,
                reason_code="PROOF_OBLIGATION_MISSING",
                detail=(
                    f"record[{idx}]: obligation file {obligation_uri!r} "
                    "does not exist in bundle_dir"
                ),
                files_audited=(),
            )

        # Sibling of the file_integrity_many_small residual: a special file
        # (FIFO / socket) passes the containment + exists() checks but
        # read_bytes() raises OSError — fail closed as a REJECT, never an
        # escaping exception.
        try:
            obligation_bytes = obligation_path.read_bytes()
        except OSError as exc:
            return PluginResult(
                ok=False,
                reason_code="PROOF_OBLIGATION_MISSING",
                detail=(
                    f"record[{idx}]: obligation file {obligation_uri!r} "
                    f"exists but could not be read: {exc}"
                ),
                files_audited=(),
            )
        computed_sha = hashlib.sha256(obligation_bytes).hexdigest()
        if computed_sha.lower() != obligation_sha.lower():
            return PluginResult(
                ok=False,
                reason_code="PROOF_OBLIGATION_SHA_MISMATCH",
                detail=(
                    f"record[{idx}]: obligation SHA mismatch for {obligation_uri!r}; "
                    f"manifest={obligation_sha!r} computed={computed_sha!r}"
                ),
                files_audited=(),
            )

        return None

    def _check_signature(
        self, idx: int, record: dict, discharge_status: str, *, bundle_id: str | None
    ) -> PluginResult | None:
        """Verifier-set discipline (the core C16 contract).

        At v0.2, statuses other than 'not-attempted' are admissible only when
        accompanied by a valid HMAC signature from
        audit_bundle.discharge.verifier_signing. Unsigned non-trivial statuses
        are forged.

        When `recheck_key` is None, FAIL CLOSED — every non-trivial
        discharge_status is rejected as DISCHARGE_STATUS_FORGED. Accepting a
        structurally-valid signature dict without HMAC verification would allow
        trivial forgery whenever the plugin was constructed without a key.

        Pass authoritative ground-truth bindings (bundle_id from the manifest,
        refine_text from the record's outputs[*].type.refine, recheck_context
        from proof.recheck_context) to verify_signature. The signature must
        bind to the same bundle / formula / context the verifier sees on
        disk — a sig copied from another bundle or another record fails to
        verify.
        """
        if discharge_status not in SIGNED_DISCHARGE_STATUS_VALUES:
            # discharge_status is 'not-attempted' — caller already filtered;
            # this branch is defensive.
            return None

        proof = record["proof"]
        sig = proof.get("verifier_signature")
        if not isinstance(sig, dict):
            return PluginResult(
                ok=False,
                reason_code="DISCHARGE_STATUS_FORGED",
                detail=(
                    f"record[{idx}]: proof.discharge_status={discharge_status!r} "
                    "is non-trivial but proof.verifier_signature is missing or malformed; "
                    "verifier-set discipline requires every signed status to carry an "
                    "HMAC signature from audit_bundle.discharge.verifier_signing.sign_and_write"
                ),
                files_audited=(),
            )

        # Fail closed when no key is wired.
        if self.recheck_policy.key is None:
            return PluginResult(
                ok=False,
                reason_code="DISCHARGE_STATUS_FORGED",
                detail=(
                    f"record[{idx}]: proof.discharge_status={discharge_status!r} "
                    "is non-trivial but RefinementDischargeCheck was constructed "
                    "without a recheck_key. Production deployments MUST wire a "
                    "VerifierSigningKey; without it the plugin cannot verify the "
                    "HMAC and falls back to v0.1 strict mode (only "
                    "'not-attempted' admissible)."
                ),
                files_audited=(),
            )

        # Resolve the authoritative bindings before calling verify_signature.
        # Use the shared canonical helper so V14/V16/C14 stay unified on the
        # "first output's refine" convention.
        refine_text = extract_refine_text(record)
        recheck_context = (
            proof.get("recheck_context")
            if isinstance(proof.get("recheck_context"), dict)
            else None
        )

        if not verify_signature(
            record,
            key=self.recheck_policy.key,
            bundle_id=bundle_id,
            refine_text=refine_text,
            recheck_context=recheck_context,
            record_idx=idx,
        ):
            return PluginResult(
                ok=False,
                reason_code="DISCHARGE_STATUS_FORGED",
                detail=(
                    f"record[{idx}]: proof.verifier_signature failed HMAC "
                    f"verification under verifier_id={self.recheck_policy.key.verifier_id!r}; "
                    "signature is forged, replayed across bundles/records/contexts, "
                    "signed under a different key, or the record was tampered "
                    "after signing"
                ),
                files_audited=(),
            )

        return None

    def _check_refinement_fragment(self, idx: int, record: dict) -> PluginResult | None:
        """Verify every refinement formula in record.outputs[].type.refine
        lies in the v0.1 fragment. Returns the failure PluginResult or None
        on success.

        This returns only a failure PluginResult or None: out-of-fragment
        formulas raise here (they are not silently skipped), so there is no
        "skipped" count for the caller's summary line to reference."""
        outputs = record.get("outputs", []) or []
        if not isinstance(outputs, list):
            return None
        for out_idx, output in enumerate(outputs):
            if not isinstance(output, dict):
                continue
            out_type = output.get("type")
            if not isinstance(out_type, dict):
                continue
            refine = out_type.get("refine")
            if refine is None:
                continue
            try:
                parse_refinement(refine)
            except FragmentOutOfScope as exc:
                return PluginResult(
                    ok=False,
                    reason_code="DISCHARGE_FRAGMENT_OUT_OF_SCOPE",
                    detail=(
                        f"record[{idx}] output[{out_idx}]: refinement "
                        f"{refine!r} is outside the v0.1 fragment; "
                        f"offending token={exc.offending_token!r}"
                    ),
                    files_audited=(),
                )
            except SmtLibParseError as exc:
                return PluginResult(
                    ok=False,
                    reason_code="DISCHARGE_FRAGMENT_OUT_OF_SCOPE",
                    detail=(
                        f"record[{idx}] output[{out_idx}]: refinement "
                        f"{refine!r} failed to parse: {exc}"
                    ),
                    files_audited=(),
                )
        return None

    def _recheck_smt_z3(
        self,
        idx: int,
        record: dict,
        claimed_status: str,
        *,
        bundle_dir: Path,
        bundle_id: str | None,
        disclosures_out: list[str],
    ) -> PluginResult | None:
        """Re-run discharge for an smt-z3 record and confirm the runner outcome
        agrees with the verifier-signed claimed_status on the COARSE lattice
        (module docstring: determinism doctrine).

        On divergence under an AUTHORITATIVE replay (or any conclusive↔
        conclusive contradiction) a verifier-signed divergence record is
        retained to the bundle event log (C16 Fork A, retain-and-still-reject)
        BEFORE the ok=False verdict is returned. Mismatch under a
        NON-AUTHORITATIVE replay is DISCHARGE_STATUS_NOT_CONFIRMED
        (incomplete=True, clean-ERROR) — present-but-unverified, never
        labelled forgery. `disclosures_out` collects honest residuals for
        records that pass (e.g. confirmation under a non-authoritative
        environment)."""
        invoker = self.recheck_policy.invoker
        # Use the shared extract_refine_text helper rather than hand-rolling the
        # "first outputs[*].type.refine" extraction. A separate hand-rolled copy
        # is byte-identical today but is a drift surface: if extract_refine_text
        # is ever extended (e.g. output_idx-aware in v0.3), a hand-rolled copy
        # would silently diverge. The shared helper keeps the
        # single-source-of-truth invariant intact.
        formula = extract_refine_text(record)
        if formula is None:
            # No refinement formula to re-check; signature was sufficient.
            return None

        if self.recheck_context_resolver is not None:
            context = self.recheck_context_resolver(record)
        else:
            context = (record.get("proof") or {}).get("recheck_context")
        if not isinstance(context, dict):
            # No replay terms. Unreachable on the default path for a signed
            # record — verify_signature fails closed unless
            # proof.recheck_context is a dict — so this fires only when a
            # custom recheck_context_resolver returns a non-dict. Same
            # availability discipline as the missing-invoker case:
            # present-but-unverified is a clean-ERROR, never a silent pass.
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="DISCHARGE_STATUS_NOT_CONFIRMED",
                detail=(
                    f"record[{idx}]: recheck_context_resolver returned a "
                    "non-dict, so no substitution context is available; the "
                    f"signed discharge_status={claimed_status!r} could not be "
                    "semantically re-discharged"
                ),
                files_audited=(),
            )

        try:
            parsed = parse_refinement(formula)
        except (FragmentOutOfScope, SmtLibParseError):
            # Already caught upstream; if we get here the upstream check
            # didn't run (no outputs were walked).
            return None

        # __logic__ comes from dispatcher-supplied recheck_context;
        # substitute() restricts _SUPPORTED_LOGICS to the v0.1 fragment, so a
        # hostile dispatcher claiming __logic__='ALL' or 'QF_NIA' gets a clean
        # ContextSubstitutionError below — surfaced as VERIFIER_DIVERGENCE.
        try:
            script = substitute(
                parsed, context, logic=context.get("__logic__", "QF_UFLIRA")
            )
        except ContextSubstitutionError as exc:
            retained = self._mint_divergence_disclosure(
                bundle_id=bundle_id,
                idx=idx,
                record=record,
                producer_claimed=claimed_status,
                verifier_computed="context_substitution_error",
                divergence_kind=DIVERGENCE_KIND_CONTEXT_SUBSTITUTION,
            )
            return PluginResult(
                ok=False,
                reason_code="DISCHARGE_STATUS_VERIFIER_DIVERGENCE",
                detail=(
                    f"record[{idx}]: re-substitution failed: {exc}; "
                    "the claimed signature was over a context that does not "
                    "satisfy the formula's free symbols (or requested an "
                    "out-of-fragment logic)"
                ),
                files_audited=(),
                disclosures=(retained,) if retained else (),
            )

        # --- Determinism doctrine: pinned policy, floor, replay ----------
        pinned, pin_defect = self._extract_solver_policy(context)
        if pin_defect is not None:
            # A malformed pin is signed material (context_canonical_sha256
            # binds it), so it is a minting defect: replay terms cannot be
            # established — could-not-conclude, not forgery.
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="DISCHARGE_STATUS_NOT_CONFIRMED",
                detail=(
                    f"record[{idx}]: {pin_defect}; replay terms cannot be "
                    "established for the pinned solver policy"
                ),
                files_audited=(),
            )

        coarse_claimed = _COARSE_STATUS[claimed_status]

        if (
            pinned is not None
            and coarse_claimed == "not_proved"
            and pinned["rlimit"] < self.recheck_policy.min_pinned_rlimit
        ):
            # Producer-steered under-resourcing: a tiny pinned budget makes
            # 'unknown' deterministically true for every obligation and would
            # pass C16 with zero proof content. Conclusive claims skip this
            # floor — unsat is unsat at any budget.
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="DISCHARGE_UNDER_RESOURCED",
                detail=(
                    f"record[{idx}]: claimed {claimed_status!r} was minted under "
                    f"pinned rlimit={pinned['rlimit']}, below the verifier floor "
                    f"min_pinned_rlimit={self.recheck_policy.min_pinned_rlimit}; "
                    "a not-proved claim at this budget carries no proof content"
                ),
                files_audited=(),
            )

        invoker = self.recheck_policy.invoker
        if pinned is not None and invoker is not None and invoker.kind != "fake":
            # Replay under the PINNED policy where the host allows. Fake
            # invokers are left untouched: the adversarial suite scripts
            # their outcomes and declares their identity explicitly.
            invoker = invoker_from_policy(pinned, invoker) or invoker

        result = run_z3(
            script.text, timeout_s=self.recheck_policy.timeout_s, invoker=invoker
        )
        if result.status == Z3Status.SUBPROCESS_FAILURE:
            # Infrastructure failure (crash guard, missing solver, z3 defect)
            # — the artifact was not shown bad and was not confirmed either:
            # clean-ERROR, never a verdict-classifying outcome.
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="Z3_SUBPROCESS_FAILURE",
                detail=(
                    f"record[{idx}]: Z3 invocation failed during re-discharge: "
                    f"{result.raw_output[:200]}"
                ),
                files_audited=(),
            )

        runner_status = _Z3_TO_DISCHARGE.get(result.status)
        if runner_status is None:
            return PluginResult(
                ok=False,
                incomplete=True,
                reason_code="Z3_SUBPROCESS_FAILURE",
                detail=f"record[{idx}]: unrecognised Z3 status {result.status!r}",
                files_audited=(),
            )

        coarse_runner = _COARSE_STATUS[runner_status]
        authoritative, authority_note = self._replay_authoritative(pinned, invoker)

        if coarse_runner == coarse_claimed:
            if not authoritative:
                disclosures_out.append(
                    f"refinement_discharge: record[{idx}] status "
                    f"{claimed_status!r} coarse-confirmed under a "
                    f"non-authoritative replay ({authority_note}); claim "
                    "accepted, forgery-detection not exercised at full strength"
                )
            return None

        # Coarse mismatch. discharged↔failed is a sat/unsat contradiction no
        # budget, seed, or version skew can explain — always a divergence.
        _CONCLUSIVE = ("discharged", "failed")
        hard_contradiction = (
            coarse_claimed in _CONCLUSIVE and coarse_runner in _CONCLUSIVE
        )
        if hard_contradiction or authoritative:
            retained = self._mint_divergence_disclosure(
                bundle_id=bundle_id,
                idx=idx,
                record=record,
                producer_claimed=claimed_status,
                verifier_computed=runner_status,
                divergence_kind=DIVERGENCE_KIND_RUNNER_MISMATCH,
            )
            return PluginResult(
                ok=False,
                reason_code="DISCHARGE_STATUS_VERIFIER_DIVERGENCE",
                detail=(
                    f"record[{idx}]: claimed discharge_status={claimed_status!r} "
                    f"but runner returned {runner_status!r} "
                    f"(raw={result.raw_output[:200]!r}); the verifier-signed "
                    "claim contradicts "
                    + (
                        "re-discharge under the record's own pinned solver policy"
                        if authoritative
                        else "independent re-discharge (conclusive↔conclusive "
                        "contradiction; authority irrelevant)"
                    )
                ),
                files_audited=(),
                disclosures=(retained,) if retained else (),
            )

        return PluginResult(
            ok=False,
            incomplete=True,
            reason_code="DISCHARGE_STATUS_NOT_CONFIRMED",
            detail=(
                f"record[{idx}]: claimed discharge_status={claimed_status!r} "
                f"but replay returned {runner_status!r} under non-authoritative "
                f"conditions ({authority_note}); present-but-unverified — this "
                "is NOT forgery evidence, the replay terms differ from the "
                "minting terms"
            ),
            files_audited=(),
        )

    def _extract_solver_policy(self, context: dict) -> tuple[dict | None, str | None]:
        """Pull and validate recheck_context['__solver_policy__'].

        Returns (policy, None) for a well-formed pin, (None, None) when absent
        (legacy record), (None, defect) when present but malformed. The pin
        lives inside the HMAC-bound context, so a malformed pin is a signed
        minting defect, not tampering."""
        raw = context.get("__solver_policy__")
        if raw is None:
            return None, None
        if not isinstance(raw, dict):
            return None, "__solver_policy__ is present but not a JSON object"
        missing = [k for k in SOLVER_POLICY_KEYS if k not in raw]
        if missing:
            return None, f"__solver_policy__ is missing keys {missing}"
        kind = raw["invoker_kind"]
        seed = raw["random_seed"]
        rlim = raw["rlimit"]
        ver = raw["z3_version"]
        if not isinstance(kind, str) or not kind:
            return None, "__solver_policy__.invoker_kind must be a non-empty string"
        if not isinstance(seed, int) or isinstance(seed, bool):
            return None, "__solver_policy__.random_seed must be an integer"
        if not isinstance(rlim, int) or isinstance(rlim, bool) or rlim <= 0:
            return None, "__solver_policy__.rlimit must be a positive integer"
        if not isinstance(ver, str) or not ver:
            return None, "__solver_policy__.z3_version must be a non-empty string"
        return {
            "invoker_kind": kind,
            "random_seed": seed,
            "rlimit": rlim,
            "z3_version": normalize_z3_version(ver),
        }, None

    def _replay_authoritative(
        self, pinned: dict | None, used_invoker: Z3Invoker
    ) -> tuple[bool, str]:
        """Decide whether this replay is authoritative for forgery semantics.

        Authoritative = the record pinned a solver policy AND the invoker
        actually used matches it on invoker_kind, random_seed, rlimit, and
        z3_version (or both versions sit in accepted_z3_versions). Anything
        less and a mismatch is explainable by environment, not forgery."""
        if pinned is None:
            return False, "record carries no pinned __solver_policy__ (legacy)"
        used = used_invoker.solver_policy()
        if used["invoker_kind"] != pinned["invoker_kind"]:
            return False, (
                f"invoker kind {used['invoker_kind']!r} != pinned "
                f"{pinned['invoker_kind']!r}"
            )
        if used["random_seed"] != pinned["random_seed"]:
            return False, (
                f"random_seed {used['random_seed']!r} != pinned "
                f"{pinned['random_seed']!r}"
            )
        if used["rlimit"] != pinned["rlimit"]:
            return False, (f"rlimit {used['rlimit']!r} != pinned {pinned['rlimit']!r}")
        used_ver = used["z3_version"]
        pinned_ver = pinned["z3_version"]
        if used_ver is None:
            return False, "verifier z3 version unresolvable"
        if used_ver == pinned_ver:
            return True, "pinned policy replayed exactly"
        accepted = self.recheck_policy.accepted_z3_versions
        if accepted is not None and used_ver in accepted and pinned_ver in accepted:
            return True, (
                f"z3 {pinned_ver} (pinned) and {used_ver} (used) are both in "
                "accepted_z3_versions"
            )
        return False, f"z3 version skew: pinned {pinned_ver!r}, used {used_ver!r}"

    def _mint_divergence_disclosure(
        self,
        *,
        bundle_id: str | None,
        idx: int,
        record: dict,
        producer_claimed: str,
        verifier_computed: str,
        divergence_kind: str,
    ) -> str | None:
        """C16 Fork A — retain the producer's claim alongside the verifier's
        independent computation as a verifier-signed artifact, delivered on
        the verdict face (``PluginResult.disclosures`` →
        ``Completeness.disclosures``). The divergence evidence is retained
        EVEN THOUGH the verdict is still a hard reject
        (retain-and-still-reject; contrast the C18 logging-only tripwire
        which continues ok=True).

        READ-ONLY INVARIANT (2026-06-10): an earlier revision appended the
        signed record to ``bundle_dir/events.jsonl``, justified by "Step-1
        walks only manifest.files". The conservation gate falsified that
        premise — its on-disk ∪ declared universe classifies a verifier-
        written ``events.jsonl`` as UNOWNED surplus, so the append changed
        the re-verification failure set (EXTRA_FILE_NOT_IN_MANIFEST joined
        the divergence reject), breaking reason-set reproducibility. The
        signed record now reaches the consumer in the verdict itself;
        persistence is caller-owned. The record dict is JSON-encoded inside
        the disclosure string and re-verifiable via
        ``verifier_signing.verify_divergence_record`` after ``json.loads``
        of the payload following the ``" — "`` separator."""
        key = self.recheck_policy.key
        if key is None or not bundle_id:
            # No signing key wired, or no authoritative bundle_id to bind the
            # replay defense to — cannot mint a sound signed record. The
            # verdict (ok=False) is unaffected; we simply skip retention.
            return None
        obligation_sha = (record.get("proof") or {}).get("obligation_sha", "")
        # obligation_sha was validated as 64-hex by _check_proof_shape upstream,
        # so sign_divergence_record will not raise on it under normal flow.
        signed = sign_divergence_record(
            key=key,
            bundle_id=bundle_id,
            record_idx=idx,
            obligation_sha=obligation_sha,
            producer_claimed=producer_claimed,
            verifier_computed=verifier_computed,
            divergence_kind=divergence_kind,
            # Deterministic by default (DIVERGENCE_TS_UNRECORDED): a wall-clock
            # stamp here would make re-runs mint byte-different disclosures on
            # the verdict face, breaking the replay-map row-1 promise.
            timestamp_utc=self.divergence_timestamp_utc,
        )
        return f"{self.name}: DISCHARGE_STATUS_VERIFIER_DIVERGENCE — " + json.dumps(
            signed, sort_keys=True
        )


register_typed_check("refinement_discharge")
