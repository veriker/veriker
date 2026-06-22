"""audit_bundle/discharge/verifier_signing.py — sole writer of proof.discharge_status.

LOAD-BEARING INVARIANT (held across V14 + V16 + the C16 contract):
  Only this module's `sign_and_write` function is allowed to set
  proof.discharge_status to any value other than 'not-attempted'. Every other
  code path that wants to write a non-trivial discharge_status MUST go through
  here. The C16 plugin enforces this by rejecting unsigned non-trivial statuses
  as DISCHARGE_STATUS_FORGED (mirrors C14 stamp_observed verifier-set
  discipline).

V14 imports `sign_and_write` to write `stamp_upgrade` events on refinement-
discharged rows (the V14 multi-row aggregation depends on this single-writer
invariant).

Signature scheme (v0.2):
  HMAC-SHA256 over the canonical-bytes JSON of:
    {"bundle_id": "<id>",
     "record_idx": <int>,
     "obligation_sha": "<hex>",
     "refine_text_sha256": "<hex>",
     "context_canonical_sha256": "<hex>",
     "discharge_status": "<status>",
     "z3_status": "<z3_status>",
     "verifier_id": "<id>",
     "timestamp_utc": "<iso8601>"}
  The three new fields (`bundle_id`, `refine_text_sha256`,
  `context_canonical_sha256`) bind the signature to a specific bundle,
  formula, and substitution context — closing the cross-record replay
  surfaced by Sonnet 4.6 in the V16 panel review (a signature for one
  record was previously valid for any other record sharing
  `obligation_sha`, regardless of formula or context). Signed under a
  verifier-secret key (from MASTER.env). Verifier-id is a short string
  identifying which verifier instance signed.

v1.0 will replace HMAC with Ed25519 detached signatures + a verifier-key trust
root. The HMAC layer at v0.2 is honest about its limit: a leaked
VKERNEL_VERIFIER_HMAC_KEY allows forgery. Production deployments rotate the
secret quarterly per SOC 2 controls; the contract's verifier-set discipline is
structurally honored even with HMAC because the dispatcher does not have the
secret.

Canonical-bytes format: JSON with sort_keys=True, separators=(',',':'),
ensure_ascii=False (mirrors the policy_dict_sha256 canonicalisation convention in
bundle_manifest.py).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone


# Shared SHA-256 hex regex (used by stamp_upgrade discharge_obligation_sha
# format check; mirrors plugins/refinement_discharge.py).
_SHA256_RE: re.Pattern = re.compile(r"^[0-9a-fA-F]{64}$")


# v0.1 admitted only 'not-attempted' as legitimate. v0.2 admits the verifier-
# signed values below — but ONLY when accompanied by a valid signature
# payload. Unsigned non-trivial statuses still fail as DISCHARGE_STATUS_FORGED.
SIGNED_DISCHARGE_STATUS_VALUES: frozenset[str] = frozenset(
    {
        "discharged",
        "failed",
        "timeout",
        "unknown",
    }
)


# V14 (post-W3 stamp-upgrade extension, 2026-05-03): the verifier may upgrade
# a row's stamp_observed by exactly one tier when the upgrade is grounded in
# a verifier-checked event. Two grounding kinds are admitted at v0.2:
#   - 'discharged'           — V16 successfully discharged the row's
#                               refinement obligation; the matching
#                               proof.verifier_signature must exist and its
#                               discharge_status must equal 'discharged'.
#   - 'predicate_satisfied'  — additional dispatch_record.predicates were
#                               satisfied post-bundle-build (rare; reserved
#                               for cross-bundle attestation flows).
STAMP_UPGRADE_REASONS: frozenset[str] = frozenset(
    {
        "discharged",
        "predicate_satisfied",
    }
)


# Map Z3Status enum values to discharge_status values for the consistency check.
# `failed` here means the refinement claim was contradicted (Z3 found a
# counterexample). `discharged` means proved.
_VALID_PAIRINGS: frozenset[tuple[str, str]] = frozenset(
    {
        ("discharged", "discharged"),
        ("failed", "failed"),
        ("timeout", "timeout"),
        ("unknown", "unknown"),
        (
            "subprocess_failure",
            "failed",
        ),  # treat infra failures as discharge-failed at v0.2
    }
)


class SigningError(Exception):
    """Raised when sign_and_write is called with an inconsistent / invalid input
    (e.g. asking to sign discharge_status='discharged' with z3_status='sat'),
    or when verify_signature fails the integrity check."""


@dataclass(frozen=True)
class VerifierSigningKey:
    """A verifier-secret key envelope. v0.2 uses HMAC-SHA256; v1.0 will swap to
    Ed25519. Treat the key bytes as opaque; do not rely on .secret length."""

    verifier_id: str
    secret: bytes  # HMAC key at v0.2

    @classmethod
    def from_env(
        cls,
        verifier_id: str = "v-kernel-default",
        *,
        env_var: str = "VKERNEL_VERIFIER_HMAC_KEY",
    ) -> "VerifierSigningKey":
        secret = os.environ.get(env_var)
        if not secret:
            raise SigningError(
                f"missing {env_var} in environment; "
                "verifier secret required for proof signing at v0.2"
            )
        return cls(verifier_id=verifier_id, secret=secret.encode("utf-8"))

    @classmethod
    def from_secret_bytes(
        cls, secret: bytes, verifier_id: str = "v-kernel-default"
    ) -> "VerifierSigningKey":
        if not isinstance(secret, (bytes, bytearray)):
            raise SigningError("secret must be bytes or bytearray")
        if len(secret) < 16:
            raise SigningError("secret must be at least 16 bytes")
        return cls(verifier_id=verifier_id, secret=bytes(secret))


# ---------------------------------------------------------------------------
# Canonical signing payload
# ---------------------------------------------------------------------------


# Documented key set of the V16 HMAC payload. Kept in lockstep with
# _build_payload by tests/test_discharge/test_verifier_signing.py
# (test_payload_keys_constant_matches_builder) — this constant drifted
# silently once when the P5 fix added `_kind`/`kind` to the builder only.
_PAYLOAD_KEYS: tuple[str, ...] = (
    "_kind",
    "bundle_id",
    "record_idx",
    "kind",
    "obligation_sha",
    "refine_text_sha256",
    "context_canonical_sha256",
    "discharge_status",
    "z3_status",
    "verifier_id",
    "timestamp_utc",
)


def _canonical_bytes(obj) -> bytes:
    """JSON canonical-bytes per the policy_dict_sha256 convention."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def canonical_context_sha256(context: dict) -> str:
    """Compute the canonical-bytes SHA256 of a recheck context dict.
    Used by both sign_and_write (at signing time) and the C16 plugin (at
    verify time) so both sides agree on the payload binding."""
    if not isinstance(context, dict):
        raise SigningError(f"context must be a dict, got {type(context).__name__}")
    # Strip __sorts__ / __logic__ markers? No — those are part of the context's
    # binding identity. A signature for context with __logic__='QF_LIA' must
    # not validate for context with __logic__='QF_UFLIRA'.
    return hashlib.sha256(_canonical_bytes(context)).hexdigest()


def refine_text_sha256(text: str) -> str:
    """SHA256 of the refinement formula text. Used to bind a signature to a
    specific formula — a signature for `(= (+ a b) total)` does not validate
    for `(= a 0)` even when other payload fields match."""
    if not isinstance(text, str):
        raise SigningError(f"refine text must be a string, got {type(text).__name__}")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def extract_refine_text(record: dict) -> str | None:
    """Canonical helper for resolving a record's refinement formula.

    Returns the FIRST `outputs[*].type.refine` string found on the record's
    outputs list, or None if none is present.

    BUG 5 fix (Gemini panel review 2026-05-03): this is the single source of
    truth for the "which output's refine text is canonical?" cross-plugin
    convention. V14 (sign_stamp_upgrade), V16 (refinement_discharge plugin),
    and C14 (stamp_lattice plugin) ALL must use this function — if one of
    them ever diverges from "first output," the cross-plugin discharge-link
    re-verification in C14 silently breaks for multi-output records. Because
    the convention is not in the wire format, it can only be enforced by
    sharing this helper.

    The contract is "first output," not "only output" — multi-output records
    are admissible at v0.2 but only the first refine formula is signed and
    re-verified. v0.3 will extend the V16 signature payload with an explicit
    `output_idx` so multiple per-output refinements can each be discharged
    and re-verified independently. Until then, callers that need to sign a
    non-first output must pass `refine_text` explicitly to sign_and_write /
    sign_stamp_upgrade rather than relying on the default.
    """
    if not isinstance(record, dict):
        return None
    outputs = record.get("outputs", []) or []
    if not isinstance(outputs, list):
        return None
    for output in outputs:
        if isinstance(output, dict):
            t = output.get("type", {})
            if isinstance(t, dict):
                r = t.get("refine")
                if isinstance(r, str):
                    return r
    return None


def _build_payload(
    bundle_id: str,
    record_idx: int,
    kind: str,
    obligation_sha: str,
    refine_text_sha256: str,
    context_canonical_sha256: str,
    discharge_status: str,
    z3_status: str,
    verifier_id: str,
    timestamp_utc: str,
) -> bytes:
    # Gate 3a frontier-pair P5 (Opus 4.7 §a2 + §a4, 2026-05-19):
    # `kind` was not in the V16 HMAC payload, which meant a V16 signature
    # minted for a `proof.kind='smt-z3'` proof re-verified cleanly after
    # the dispatcher rewrote proof.kind to 'lean-4' (or 'dafny'). The C16
    # plugin's optional Z3 re-discharge is gated by `proof['kind'] ==
    # 'smt-z3'`; rewriting the kind post-signing routes around the
    # re-discharge check without breaking the HMAC. Binding `kind` into
    # the payload closes the prover-kind laundering attack.
    #
    # `_kind="discharge_proof.v0.2"` is the domain-separation tag. V14
    # (`_build_stamp_upgrade_payload`) added `_kind="stamp_upgrade.v0.2"`
    # post-BUG-5, and V15 (`_build_trace_payload`) added
    # `_kind="execution_trace.v0.2"`. V16 was the unprotected anchor —
    # the OTHER two streams added `_kind` to defend AGAINST V16-shaped
    # payloads. Closing the asymmetry. Forward-compat: any v0.3 stream
    # adding a similar key set now canonical-bytes-differs from V16
    # regardless of HMAC key reuse.
    #
    # WIRE-FORMAT BREAK: V16 sigs minted under v0.2.0 will NOT verify
    # under v0.2.1. Acceptable because v0.2 was not customer-shipped at
    # the time of patch; see CHANGELOG.md v0.2.1 entry.
    payload = {
        "_kind": "discharge_proof.v0.2",
        "bundle_id": bundle_id,
        "record_idx": record_idx,
        "kind": kind,
        "obligation_sha": obligation_sha,
        "refine_text_sha256": refine_text_sha256,
        "context_canonical_sha256": context_canonical_sha256,
        "discharge_status": discharge_status,
        "z3_status": z3_status,
        "verifier_id": verifier_id,
        "timestamp_utc": timestamp_utc,
    }
    return _canonical_bytes(payload)


def _hmac_hex(key: VerifierSigningKey, payload: bytes) -> str:
    return hmac.new(key.secret, payload, hashlib.sha256).hexdigest()


def _now_iso8601_utc() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def sign_and_write(
    record: dict,
    *,
    key: VerifierSigningKey,
    discharge_status: str,
    z3_status: str,
    bundle_id: str,
    record_idx: int = 0,
    refine_text: str | None = None,
    recheck_context: dict | None = None,
    timestamp_utc: str | None = None,
) -> dict:
    """Apply a verifier signature to a dispatch record's `proof` field and
    return the modified record (deep-copy semantics; the input is not mutated).

    Required parameters (V16 panel review BUG 2 fix, 2026-05-02):
      - `bundle_id`: binds the signature to a specific bundle. A signature
        for bundle A does not validate when copied into bundle B.
      - `refine_text`: the refinement formula text. Defaults to the first
        `outputs[].type.refine` field on the record if not supplied; pass
        explicitly when the record has multiple refinements or when re-
        signing a record that has been transformed.
      - `recheck_context`: the dispatch context that was substituted into
        the formula. Defaults to `proof.recheck_context` if present.
        A signature over context X does not validate when verifier sees
        context Y — this closes the cross-record replay surfaced by the
        panel.

    Returned record has::

        record['proof']['discharge_status'] = discharge_status
        record['proof']['verifier_signature'] = {
            'algorithm': 'hmac-sha256',
            'verifier_id': key.verifier_id,
            'z3_status': z3_status,
            'timestamp_utc': timestamp_utc,
            'bundle_id': bundle_id,
            'record_idx': record_idx,
            'refine_text_sha256': '<hex>',
            'context_canonical_sha256': '<hex>',
            'mac': '<hex>',
        }

    Raises SigningError on invalid inputs (status out of enum, missing proof
    field, inconsistent (discharge_status, z3_status) pairing, missing
    refine_text or recheck_context).
    """
    if not isinstance(record, dict):
        raise SigningError(f"record must be a dict, got {type(record).__name__}")
    proof = record.get("proof")
    if not isinstance(proof, dict):
        raise SigningError("record has no 'proof' field; cannot sign")

    if discharge_status == "not-attempted":
        raise SigningError(
            "verifier-set discipline: 'not-attempted' is the dispatcher-default; "
            "verifier signs only the four statuses in SIGNED_DISCHARGE_STATUS_VALUES"
        )
    if discharge_status not in SIGNED_DISCHARGE_STATUS_VALUES:
        raise SigningError(
            f"discharge_status {discharge_status!r} is not in "
            f"{sorted(SIGNED_DISCHARGE_STATUS_VALUES)}"
        )
    if (z3_status, discharge_status) not in _VALID_PAIRINGS:
        raise SigningError(
            f"inconsistent pairing: z3_status={z3_status!r} cannot sign "
            f"discharge_status={discharge_status!r}; valid pairings: {sorted(_VALID_PAIRINGS)}"
        )

    if not isinstance(bundle_id, str) or not bundle_id:
        raise SigningError("bundle_id is required for signing (panel BUG 2 fix)")

    obligation_sha = proof.get("obligation_sha", "")
    if not isinstance(obligation_sha, str) or not obligation_sha:
        raise SigningError("proof.obligation_sha is required for signing")
    # Cumulative-pre-soak Patch 8 (Gate 1, 2026-05-04): enforce 64-hex
    # SHA-256 shape at signing time, mirroring the stricter check
    # already in sign_stamp_upgrade. Pre-fix, sign_and_write accepted
    # any non-empty string, so a hostile dispatcher could write
    # proof.obligation_sha = "x", get a valid V16 signature for it,
    # and the malformed string would later block a stamp upgrade at
    # V14 (deferred error instead of fail-fast at signing). The
    # discharge_obligation_sha = obligation_sha equality check in
    # sign_stamp_upgrade also relied on shape symmetry that was not
    # actually enforced upstream.
    if not _SHA256_RE.match(obligation_sha):
        raise SigningError(
            f"proof.obligation_sha={obligation_sha!r} is not a valid "
            "64-character hex SHA-256 (sign_and_write enforces shape "
            "for fail-fast symmetry with sign_stamp_upgrade)"
        )

    # Resolve refine_text from record outputs if not supplied. Use the
    # shared canonical helper so the V14/V16/C14 convention stays unified
    # (BUG 5 fix from 2026-05-03 panel review).
    if refine_text is None:
        refine_text = extract_refine_text(record)
    if refine_text is None:
        raise SigningError(
            "refine_text is required for signing — pass explicitly or ensure "
            "the record has a string refine field on outputs[*].type.refine"
        )

    if recheck_context is None:
        recheck_context = proof.get("recheck_context")
    if not isinstance(recheck_context, dict):
        raise SigningError(
            "recheck_context (the substitution context that was discharged) "
            "is required for signing — pass explicitly or ensure the record "
            "has a dict at proof.recheck_context"
        )

    refine_sha = refine_text_sha256(refine_text)
    context_sha = canonical_context_sha256(recheck_context)

    # Gate 3a frontier-pair P5: extract proof.kind to bind into the HMAC.
    # The V16 plugin's optional Z3 re-discharge routes by proof.kind, so
    # leaving it unsigned admitted a smt-z3 → lean-4 laundering attack.
    proof_kind = proof.get("kind")
    if not isinstance(proof_kind, str) or not proof_kind:
        raise SigningError(
            "proof.kind is required for signing (Gate 3a P5 binding); "
            "got proof without a string 'kind' field"
        )

    if timestamp_utc is None:
        timestamp_utc = _now_iso8601_utc()

    payload = _build_payload(
        bundle_id=bundle_id,
        record_idx=record_idx,
        kind=proof_kind,
        obligation_sha=obligation_sha,
        refine_text_sha256=refine_sha,
        context_canonical_sha256=context_sha,
        discharge_status=discharge_status,
        z3_status=z3_status,
        verifier_id=key.verifier_id,
        timestamp_utc=timestamp_utc,
    )
    mac = _hmac_hex(key, payload)

    new_record = json.loads(json.dumps(record))  # deep copy via JSON round-trip
    new_record["proof"]["discharge_status"] = discharge_status
    new_record["proof"]["verifier_signature"] = {
        "algorithm": "hmac-sha256",
        "verifier_id": key.verifier_id,
        "z3_status": z3_status,
        "timestamp_utc": timestamp_utc,
        "bundle_id": bundle_id,
        "record_idx": record_idx,
        "refine_text_sha256": refine_sha,
        "context_canonical_sha256": context_sha,
        "mac": mac,
    }
    return new_record


def verify_signature(
    record: dict,
    *,
    key: VerifierSigningKey,
    bundle_id: str,
    refine_text: str,
    recheck_context: dict,
    record_idx: int,
) -> bool:
    """Return True iff the record carries a verifier signature that re-verifies
    against `key` and the caller-supplied authoritative bindings.

    The four required parameters bind verification to
    authoritative ground truth — the verifier reads `bundle_id` from the
    manifest, `refine_text` from the record's `outputs[*].type.refine` via
    the canonical `extract_refine_text` helper, `recheck_context` from
    `proof.recheck_context`, and `record_idx` from the iteration index.
    NOT from the signature dict (which is attacker-controlled). This closes
    the cross-record replay surfaced by the panel: the signed payload must
    bind to the same bundle_id, formula text, substitution context, AND
    row position the verifier sees on disk.

    Cumulative-pre-soak Patch 6 (Gate 1, 2026-05-04): pre-fix
    `verify_signature` sourced `record_idx` from the attacker-controlled
    sig dict (`sig.get("record_idx", 0)`), so a signed proof copied from
    row 5 to row 7 would still verify when other bindings collided
    (e.g. two rows sharing bundle_id, refine_text, recheck_context,
    obligation_sha — possible for templated dispatches). Now `record_idx`
    is a required caller-supplied authoritative parameter and the sig's
    self-reported value must match. Mirrors the
    `verify_stamp_upgrade_signature` BUG 3 fix from 2026-05-03.

    False on any mismatch (missing field, wrong key, tampered fields).
    Never raises on invalid input AT THE RECORD LEVEL; returns False
    instead so adversarial-path callers (C14/C16 plugins) yield a clean
    rejection rather than a crash. (Caller-supplied binding TYPE errors
    at the parameter boundary still raise — the bindings are the caller's
    contract with the verifier, not data fields.)
    """
    if not isinstance(record, dict):
        return False
    proof = record.get("proof")
    if not isinstance(proof, dict):
        return False
    sig = proof.get("verifier_signature")
    if not isinstance(sig, dict):
        return False
    if sig.get("algorithm") != "hmac-sha256":
        return False
    if sig.get("verifier_id") != key.verifier_id:
        return False

    discharge_status = proof.get("discharge_status")
    z3_status = sig.get("z3_status")
    timestamp_utc = sig.get("timestamp_utc")
    obligation_sha = proof.get("obligation_sha", "")
    mac_claimed = sig.get("mac", "")

    # Authoritative bindings — caller MUST supply all four. Reject empty
    # or wrong-typed inputs (they would otherwise hash to a sentinel and
    # could collide with attacker payloads).
    if not isinstance(bundle_id, str) or not bundle_id:
        return False
    if not isinstance(refine_text, str):
        return False
    if not isinstance(recheck_context, dict):
        return False
    # BUG 8 lesson: isinstance(True, int) is True; exclude bool explicitly
    # so record_idx=True doesn't silently verify a sig minted for record_idx=1.
    if (
        isinstance(record_idx, bool)
        or not isinstance(record_idx, int)
        or record_idx < 0
    ):
        return False

    sig_bundle_id = sig.get("bundle_id")
    sig_refine_sha = sig.get("refine_text_sha256")
    sig_context_sha = sig.get("context_canonical_sha256")
    sig_record_idx = sig.get("record_idx")

    # If the sig dict carries self-reported bindings, they must agree with
    # the caller's authoritative values. (Older sigs without these fields
    # are rejected — every sig minted by sign_and_write since the BUG 2
    # fix carries them.)
    if not isinstance(sig_bundle_id, str) or sig_bundle_id != bundle_id:
        return False

    # Cumulative-pre-soak Patch 6: cross-check sig.record_idx against the
    # caller-authoritative value. Fail closed on missing / wrong-typed /
    # mismatched record_idx — closes the intra-bundle row-replay niche.
    if (
        isinstance(sig_record_idx, bool)
        or not isinstance(sig_record_idx, int)
        or sig_record_idx < 0
    ):
        return False
    if sig_record_idx != record_idx:
        return False

    try:
        refine_sha_for_verify = refine_text_sha256(refine_text)
    except SigningError:
        return False
    if not isinstance(sig_refine_sha, str) or sig_refine_sha != refine_sha_for_verify:
        return False

    try:
        context_sha_for_verify = canonical_context_sha256(recheck_context)
    except SigningError:
        return False
    if (
        not isinstance(sig_context_sha, str)
        or sig_context_sha != context_sha_for_verify
    ):
        return False

    bundle_id_for_verify = bundle_id

    if not isinstance(discharge_status, str) or not isinstance(z3_status, str):
        return False
    if not isinstance(timestamp_utc, str):
        return False
    if not isinstance(obligation_sha, str) or not obligation_sha:
        return False
    if not isinstance(mac_claimed, str):
        return False
    if (z3_status, discharge_status) not in _VALID_PAIRINGS:
        return False

    # Gate 3a frontier-pair P5: bind proof.kind into the HMAC payload so
    # smt-z3 → lean-4 rewrites post-signing break verification. Reject
    # missing / non-string / empty kind — without a kind the HMAC
    # payload would carry a sentinel that an adversary could collide.
    proof_kind = proof.get("kind")
    if not isinstance(proof_kind, str) or not proof_kind:
        return False

    payload = _build_payload(
        bundle_id=bundle_id_for_verify,
        record_idx=record_idx,
        kind=proof_kind,
        obligation_sha=obligation_sha,
        refine_text_sha256=refine_sha_for_verify,
        context_canonical_sha256=context_sha_for_verify,
        discharge_status=discharge_status,
        z3_status=z3_status,
        verifier_id=key.verifier_id,
        timestamp_utc=timestamp_utc,
    )
    mac_expected = _hmac_hex(key, payload)
    return hmac.compare_digest(mac_claimed, mac_expected)


# ===========================================================================
# V14 — stamp_upgrade signing (sole writer of dispatch_record['stamp_upgrade'])
# ===========================================================================
#
# The C14 stamp lattice (audit-bundle contract §C14) specifies that
# `stamp_observed` is verifier-set, never dispatcher-trusted. v0.2 extends
# that discipline to *upgrades*: when the verifier discharges a refinement
# (V16) or otherwise gains evidence the dispatcher could not have known at
# bundle-build time, it may write a `stamp_upgrade` record on the row.
# The C14 plugin then computes `effective_stamp_observed = upgrade.to_stamp`
# for that row, and the bundle's aggregate_stamp = min(effective_stamp_observed
# per row).
#
# LOAD-BEARING INVARIANT (held across V14 + V16 + the C14/C16 contracts):
#   Only this module's `sign_stamp_upgrade` function is allowed to set
#   record['stamp_upgrade']. Every other code path that wants to write an
#   upgrade MUST go through here. The C14 plugin enforces this by rejecting
#   unsigned upgrades as STAMP_UPGRADE_FORGED (mirrors the C16 plugin's
#   DISCHARGE_STATUS_FORGED discipline).
#
# Upgrade signature payload (binds to bundle + record + tier-transition +
# discharge link to defeat replay across bundles, records, or refinements):
#   {"bundle_id": "<id>",
#    "record_idx": <int>,
#    "from_stamp": "<stamp>",
#    "to_stamp":   "<stamp>",
#    "upgrade_reason": "<reason>",
#    "discharge_obligation_sha": "<hex or empty-string>",
#    "verifier_id": "<id>",
#    "timestamp_utc": "<iso8601>"}
#
# Tier-transition rule (one-tier-only): to_stamp must be from_stamp's
# C14 lattice rank + 1. Multi-tier jumps (e.g. INTERNAL_BENCHMARK →
# CONFIRMED_EXTERNAL in one upgrade) are rejected by the verifier because
# the C16 contract specifies "A successfully discharged refinement upgrades
# stamp_observed by one tier in the C14 lattice." Larger upgrades require
# additional grounding events stacked one tier at a time across multiple
# bundle revisions.
#
# Discharge-link rule: when upgrade_reason='discharged', the row must carry
# a proof field whose obligation_sha equals discharge_obligation_sha AND
# whose verifier_signature.discharge_status equals 'discharged' (V16 must
# have signed it as proved, not as failed/timeout/unknown). The plugin
# enforces the cross-link; this signing function only enforces the
# non-empty-when-claimed shape.


_STAMP_UPGRADE_PAYLOAD_KEYS: tuple[str, ...] = (
    "_kind",  # domain-separation tag (BUG 5 fix from 2026-05-03 panel review)
    "bundle_id",
    "record_idx",
    "from_stamp",
    "to_stamp",
    "upgrade_reason",
    "discharge_obligation_sha",
    "verifier_id",
    "timestamp_utc",
)

# Domain-separation tag (BUG 5 fix — Opus #6 panel review 2026-05-03):
# every stamp-upgrade HMAC payload carries a literal `_kind` field that
# tags it as a V14 stamp-upgrade payload. This makes cross-protocol forgery
# (signing a V16 discharge_status payload that happens to canonically-encode
# to the same bytes as a V14 stamp-upgrade payload) computationally
# infeasible regardless of how V16's payload schema evolves. The leading
# underscore keeps the field sorted before the existing payload keys
# under sort_keys=True.
_STAMP_UPGRADE_PAYLOAD_KIND: str = "stamp_upgrade.v0.2"


# C14 lattice rank — must mirror plugins/stamp_lattice.py STAMP_RANK.
# Duplicated here (not imported) to avoid a circular dep: the plugin imports
# from this module, not the other way around.
_C14_STAMP_ORDER: tuple[str, ...] = (
    "UNVERIFIED",
    "COMPOSED_HYPOTHESIS",
    "TARGET",
    "INTERNAL_BENCHMARK",
    "INTERNAL_SOURCE",
    "WEB_SOURCE",
    "CONFIRMED_EXTERNAL",
)
_C14_STAMP_RANK: dict[str, int] = {s: i for i, s in enumerate(_C14_STAMP_ORDER)}


def _build_stamp_upgrade_payload(
    *,
    bundle_id: str,
    record_idx: int,
    from_stamp: str,
    to_stamp: str,
    upgrade_reason: str,
    discharge_obligation_sha: str,
    verifier_id: str,
    timestamp_utc: str,
) -> bytes:
    payload = {
        "_kind": _STAMP_UPGRADE_PAYLOAD_KIND,
        "bundle_id": bundle_id,
        "record_idx": record_idx,
        "from_stamp": from_stamp,
        "to_stamp": to_stamp,
        "upgrade_reason": upgrade_reason,
        "discharge_obligation_sha": discharge_obligation_sha,
        "verifier_id": verifier_id,
        "timestamp_utc": timestamp_utc,
    }
    return _canonical_bytes(payload)


def sign_stamp_upgrade(
    record: dict,
    *,
    key: VerifierSigningKey,
    from_stamp: str,
    to_stamp: str,
    upgrade_reason: str,
    bundle_id: str,
    record_idx: int = 0,
    discharge_obligation_sha: str = "",
    timestamp_utc: str | None = None,
) -> dict:
    """V14 entry point — apply a verifier signature to a dispatch record's
    `stamp_upgrade` field and return the modified record (deep-copy
    semantics; the input is not mutated).

    Required parameters:
      - `bundle_id`: binds the signature to a specific bundle. A signature
        for bundle A does not validate when copied into bundle B.
      - `record_idx`: row position in manifest.dispatch_records. A
        signature for record[0] does not validate when copied into record[5].
      - `from_stamp` / `to_stamp`: the C14-tier transition. Must be exactly
        one tier apart and to_stamp must be strictly stronger than from_stamp.
      - `upgrade_reason`: in STAMP_UPGRADE_REASONS.
      - `discharge_obligation_sha`: required (non-empty hex) when
        upgrade_reason == 'discharged'; must equal the record's
        proof.obligation_sha. Empty-string permitted only for the
        'predicate_satisfied' reason.

    Returned record has::

        record['stamp_upgrade'] = {
            'from_stamp': from_stamp,
            'to_stamp':   to_stamp,
            'upgrade_reason': upgrade_reason,
            'discharge_obligation_sha': discharge_obligation_sha,
            'verifier_signature': {
                'algorithm': 'hmac-sha256',
                'verifier_id': key.verifier_id,
                'timestamp_utc': timestamp_utc,
                'bundle_id': bundle_id,
                'record_idx': record_idx,
                'from_stamp': from_stamp,
                'to_stamp':   to_stamp,
                'upgrade_reason': upgrade_reason,
                'discharge_obligation_sha': discharge_obligation_sha,
                'mac': '<hex>',
            },
        }

    Raises SigningError on shape / tier-rule / discharge-link violations.
    """
    if not isinstance(record, dict):
        raise SigningError(f"record must be a dict, got {type(record).__name__}")
    if not isinstance(bundle_id, str) or not bundle_id:
        raise SigningError("bundle_id is required for stamp-upgrade signing")
    # BUG 8 fix (panel review 2026-05-03): exclude bool subclass — isinstance(True, int)
    # is True in Python, but record_idx=True would silently produce a sig for
    # record_idx=1 (since True == 1) without the caller's awareness.
    if (
        isinstance(record_idx, bool)
        or not isinstance(record_idx, int)
        or record_idx < 0
    ):
        raise SigningError(
            f"record_idx must be a non-negative int (bool excluded), got "
            f"{record_idx!r} of type {type(record_idx).__name__}"
        )

    if from_stamp not in _C14_STAMP_RANK:
        raise SigningError(
            f"from_stamp={from_stamp!r} is not in the C14 lattice "
            f"{list(_C14_STAMP_ORDER)}"
        )
    if to_stamp not in _C14_STAMP_RANK:
        raise SigningError(
            f"to_stamp={to_stamp!r} is not in the C14 lattice {list(_C14_STAMP_ORDER)}"
        )
    if _C14_STAMP_RANK[to_stamp] != _C14_STAMP_RANK[from_stamp] + 1:
        raise SigningError(
            f"tier-transition rule: to_stamp must be exactly one tier stronger "
            f"than from_stamp. got from={from_stamp!r} (rank {_C14_STAMP_RANK[from_stamp]}) "
            f"to={to_stamp!r} (rank {_C14_STAMP_RANK[to_stamp]})"
        )

    if upgrade_reason not in STAMP_UPGRADE_REASONS:
        raise SigningError(
            f"upgrade_reason={upgrade_reason!r} is not in "
            f"{sorted(STAMP_UPGRADE_REASONS)}"
        )

    if upgrade_reason == "discharged":
        if (
            not isinstance(discharge_obligation_sha, str)
            or not discharge_obligation_sha
        ):
            raise SigningError(
                "upgrade_reason='discharged' requires a non-empty "
                "discharge_obligation_sha"
            )
        # BUG 6 fix (Opus O2 panel review 2026-05-03): enforce the SHA shape
        # at signing time so the obligation reference is structurally
        # verifiable. Without this, a hostile dispatcher controlling
        # proof.obligation_sha can pass arbitrary strings (e.g. "x") that
        # echo through the equality check below.
        if not _SHA256_RE.match(discharge_obligation_sha):
            raise SigningError(
                # Cumulative-pre-soak LOW (Gate 1, 2026-05-04): align
                # error text with regex — _SHA256_RE accepts both upper
                # and lower hex; do not claim "lowercase".
                f"discharge_obligation_sha={discharge_obligation_sha!r} is not a "
                "valid 64-character hex SHA-256"
            )
        proof = record.get("proof")
        if not isinstance(proof, dict):
            raise SigningError(
                "upgrade_reason='discharged' requires the record to carry a "
                "proof field; got record without proof"
            )
        proof_obl = proof.get("obligation_sha", "")
        if proof_obl != discharge_obligation_sha:
            raise SigningError(
                f"discharge_obligation_sha={discharge_obligation_sha!r} does not "
                f"match record.proof.obligation_sha={proof_obl!r}"
            )
        # BUG 7 fix (Sonnet #1a panel review 2026-05-03): the signer MUST
        # refuse to sign a 'discharged'-reason upgrade against a proof that
        # is not itself in the 'discharged' state. Defense-in-depth pairing
        # with the C14 plugin's _check_discharge_link — without this, the
        # signer's docstring promise that "upgrade_reason='discharged'
        # requires the row to carry a proof field" was weaker than it sounded
        # because it accepted proofs in any discharge_status.
        proof_status = proof.get("discharge_status")
        if proof_status != "discharged":
            raise SigningError(
                f"upgrade_reason='discharged' requires record.proof."
                f"discharge_status='discharged'; got {proof_status!r}"
            )
        # And the proof must already carry a V16 verifier_signature (otherwise
        # the upgrade attaches to a discharge_status='discharged' value that
        # itself is forged at the C16 level).
        v16_sig = proof.get("verifier_signature")
        if not isinstance(v16_sig, dict) or not v16_sig.get("mac"):
            raise SigningError(
                "upgrade_reason='discharged' requires record.proof to carry a "
                "V16 verifier_signature with a non-empty mac; the proof itself "
                "must be V16-signed before V14 can attach an upgrade"
            )
    else:
        # predicate_satisfied — discharge_obligation_sha MUST be empty so
        # the canonical payload is unambiguous.
        if discharge_obligation_sha:
            raise SigningError(
                f"upgrade_reason={upgrade_reason!r} requires empty "
                f"discharge_obligation_sha, got {discharge_obligation_sha!r}"
            )

    if timestamp_utc is None:
        timestamp_utc = _now_iso8601_utc()

    payload = _build_stamp_upgrade_payload(
        bundle_id=bundle_id,
        record_idx=record_idx,
        from_stamp=from_stamp,
        to_stamp=to_stamp,
        upgrade_reason=upgrade_reason,
        discharge_obligation_sha=discharge_obligation_sha,
        verifier_id=key.verifier_id,
        timestamp_utc=timestamp_utc,
    )
    mac = _hmac_hex(key, payload)

    new_record = json.loads(json.dumps(record))  # deep copy via JSON round-trip
    new_record["stamp_upgrade"] = {
        "from_stamp": from_stamp,
        "to_stamp": to_stamp,
        "upgrade_reason": upgrade_reason,
        "discharge_obligation_sha": discharge_obligation_sha,
        "verifier_signature": {
            "algorithm": "hmac-sha256",
            "verifier_id": key.verifier_id,
            "timestamp_utc": timestamp_utc,
            "bundle_id": bundle_id,
            "record_idx": record_idx,
            "from_stamp": from_stamp,
            "to_stamp": to_stamp,
            "upgrade_reason": upgrade_reason,
            "discharge_obligation_sha": discharge_obligation_sha,
            "mac": mac,
        },
    }
    return new_record


def verify_stamp_upgrade_signature(
    record: dict, *, key: VerifierSigningKey, bundle_id: str, record_idx: int
) -> bool:
    """Return True iff record['stamp_upgrade']['verifier_signature'] re-verifies
    against `key` and the authoritative ground-truth bindings supplied by
    the caller.

    BUG 3 fix (Sonnet O7 / Opus #7 panel review 2026-05-03): `bundle_id`
    and `record_idx` are MANDATORY. The prior signature accepted them as
    None and fell back to the signature's self-reported values, which the
    attacker controls — that's exactly the C16 BUG 2 confused-deputy
    pattern. Removing the fallback makes the public helper safe by
    construction; every caller must supply authoritative ground truth
    (read from the manifest and from the iteration index respectively).

    The function still rejects when the supplied values disagree with the
    sig's self-report (so a sig that claims bundle_id="A" cannot be
    verified against caller-supplied bundle_id="B").

    Returns False on any structural defect (missing field, malformed dict,
    wrong algorithm, tier-rule violation, MAC mismatch). Never raises on
    invalid input — the C14 plugin's adversarial path yields a clean
    rejection rather than a crash.
    """
    if not isinstance(record, dict):
        return False
    upgrade = record.get("stamp_upgrade")
    if not isinstance(upgrade, dict):
        return False

    sig = upgrade.get("verifier_signature")
    if not isinstance(sig, dict):
        return False
    if sig.get("algorithm") != "hmac-sha256":
        return False
    if sig.get("verifier_id") != key.verifier_id:
        return False

    # Authoritative bundle_id MUST be caller-supplied. Reject anything else
    # (including bool subclass — isinstance(True, int) is True so we exclude
    # it explicitly via the str check).
    if not isinstance(bundle_id, str) or not bundle_id:
        return False
    # Gate 3a frontier-pair P4 (Opus 4.7 §A1 + Sonnet 4.6 §A1/§B1/§D2,
    # 2026-05-19): sig dicts must be self-authenticating, matching V16's
    # pattern at verifier_signing.py:510. The prior `if sig_X is not None
    # and X != sig_X` admits a sig that LACKS the bundle_id/record_idx
    # keys entirely — the cryptographic HMAC still binds the caller-
    # authoritative values, but the persisted sig dict is no longer self-
    # describing for downstream consumers (log indexing, cross-reference,
    # forensics). Closing the asymmetry with V16's hard-reject pattern.
    sig_bundle_id = sig.get("bundle_id")
    if not isinstance(sig_bundle_id, str) or sig_bundle_id != bundle_id:
        return False
    bundle_id_for_verify = bundle_id

    if (
        isinstance(record_idx, bool)
        or not isinstance(record_idx, int)
        or record_idx < 0
    ):
        return False
    sig_record_idx = sig.get("record_idx")
    # Same P4 treatment for record_idx: V16 (line ~516) hard-rejects on
    # missing / non-int / negative; V14 was inconsistent.
    if (
        isinstance(sig_record_idx, bool)
        or not isinstance(sig_record_idx, int)
        or sig_record_idx < 0
    ):
        return False
    if sig_record_idx != record_idx:
        return False
    record_idx_for_verify = record_idx

    # Body-vs-sig consistency: the upgrade body's claim and the signature
    # payload must agree. A signature whose payload says
    # to_stamp=INTERNAL_SOURCE attached to an upgrade body that says
    # to_stamp=CONFIRMED_EXTERNAL is forged — prevents post-signing body
    # tampering.
    body_from = upgrade.get("from_stamp")
    body_to = upgrade.get("to_stamp")
    body_reason = upgrade.get("upgrade_reason")
    body_obl = upgrade.get("discharge_obligation_sha", "")

    sig_from = sig.get("from_stamp")
    sig_to = sig.get("to_stamp")
    sig_reason = sig.get("upgrade_reason")
    sig_obl = sig.get("discharge_obligation_sha", "")

    if (body_from, body_to, body_reason, body_obl) != (
        sig_from,
        sig_to,
        sig_reason,
        sig_obl,
    ):
        return False

    if not isinstance(sig_from, str) or sig_from not in _C14_STAMP_RANK:
        return False
    if not isinstance(sig_to, str) or sig_to not in _C14_STAMP_RANK:
        return False
    if _C14_STAMP_RANK[sig_to] != _C14_STAMP_RANK[sig_from] + 1:
        return False
    if sig_reason not in STAMP_UPGRADE_REASONS:
        return False
    if not isinstance(sig_obl, str):
        return False
    if sig_reason == "discharged" and not sig_obl:
        return False
    if sig_reason != "discharged" and sig_obl:
        return False

    timestamp_utc = sig.get("timestamp_utc")
    if not isinstance(timestamp_utc, str) or not timestamp_utc:
        return False
    # Gate 3a frontier-pair P2 (Sonnet 4.6 §C2, 2026-05-19): without an
    # ISO-8601 grammar check here, a V14 HMAC key-holder can mint a sig
    # with `timestamp_utc="garbage"`. The HMAC binds the literal string so
    # MAC integrity holds. But C14's Defense-7 out-of-order check at
    # `stamp_lattice._compare_timestamps` enters the guard on a truthy
    # `sig_ts`, calls `_parse_iso8601_to_aware` which returns None, and
    # silently skips the comparison — the OOO defense is bypassed. The V15
    # `verify_execution_trace_signature` already runs this grammar check;
    # V14 was inconsistent. Reject before HMAC computation.
    from audit_bundle.effect_runtime.trace_attestation import _is_iso8601_utc

    if not _is_iso8601_utc(timestamp_utc):
        return False
    mac_claimed = sig.get("mac")
    if not isinstance(mac_claimed, str):
        return False

    payload = _build_stamp_upgrade_payload(
        bundle_id=bundle_id_for_verify,
        record_idx=record_idx_for_verify,
        from_stamp=sig_from,
        to_stamp=sig_to,
        upgrade_reason=sig_reason,
        discharge_obligation_sha=sig_obl,
        verifier_id=key.verifier_id,
        timestamp_utc=timestamp_utc,
    )
    mac_expected = _hmac_hex(key, payload)
    return hmac.compare_digest(mac_claimed, mac_expected)


# ===========================================================================
# C16 Fork A — retained, verifier-signed divergence record
# ===========================================================================
#
# When the C16 plugin re-runs Z3 and the runner outcome contradicts the
# producer's signed discharge_status (or the re-substitution fails), the
# bundle is REJECTED (ok=False). But rejection alone discards the evidence.
# Fork A retains the producer's claim alongside the verifier's independent
# computation as a standalone, verifier-signed artifact emitted to the bundle
# event log — the §103 "teaches away from PCC's discard" delta. The record is
# emitted EVEN THOUGH the verdict is still a hard reject (retain-and-still-
# reject), which is the asymmetry vs C18's logging-only/continue tripwire.
#
# Unlike sign_and_write (V16) and sign_stamp_upgrade (V14), this signer does
# NOT mutate or attach to a dispatch record. It produces a free-standing dict.
#
# Replay-defense parity with V14/V16: the HMAC binds bundle_id + record_idx +
# obligation_sha + producer_claimed + verifier_computed + divergence_kind, so
# a divergence record minted for bundle A / row 0 does not re-verify when
# carried into bundle B / row 5.

_DIVERGENCE_RECORD_PAYLOAD_KIND: str = "discharge_divergence_record.v0.2"

# The artifact kind written to events.jsonl detail.record_kind (consumer-
# visible). Distinct from the reason_code DISCHARGE_STATUS_VERIFIER_DIVERGENCE
# (the verdict): the reason_code is why the bundle was rejected; the record
# kind names the retained evidence object.
DIVERGENCE_RECORD_KIND: str = _DIVERGENCE_RECORD_PAYLOAD_KIND

# Divergence-kind discriminator values (verifier_computed semantics differ).
DIVERGENCE_KIND_RUNNER_MISMATCH: str = "runner_status_mismatch"
DIVERGENCE_KIND_CONTEXT_SUBSTITUTION: str = "context_substitution_error"
_VALID_DIVERGENCE_KINDS: frozenset[str] = frozenset(
    {DIVERGENCE_KIND_RUNNER_MISMATCH, DIVERGENCE_KIND_CONTEXT_SUBSTITUTION}
)


def _build_divergence_record_payload(
    *,
    bundle_id: str,
    record_idx: int,
    obligation_sha: str,
    producer_claimed: str,
    verifier_computed: str,
    divergence_kind: str,
    verifier_id: str,
    timestamp_utc: str,
) -> bytes:
    payload = {
        "_kind": _DIVERGENCE_RECORD_PAYLOAD_KIND,
        "bundle_id": bundle_id,
        "record_idx": record_idx,
        "obligation_sha": obligation_sha,
        "producer_claimed": producer_claimed,
        "verifier_computed": verifier_computed,
        "divergence_kind": divergence_kind,
        "verifier_id": verifier_id,
        "timestamp_utc": timestamp_utc,
    }
    return _canonical_bytes(payload)


def sign_divergence_record(
    *,
    key: VerifierSigningKey,
    bundle_id: str,
    record_idx: int,
    obligation_sha: str,
    producer_claimed: str,
    verifier_computed: str,
    divergence_kind: str,
    timestamp_utc: str | None = None,
) -> dict:
    """Mint a verifier-signed divergence record (C16 Fork A).

    Returns a free-standing dict (NOT attached to any dispatch record) suitable
    for emission to the bundle event log. The dict is self-describing and
    re-verifiable via verify_divergence_record.

    Args:
      producer_claimed: the discharge_status the producer signed (e.g.
        'discharged') — what the bundle asserted.
      verifier_computed: what the verifier independently found. For
        divergence_kind='runner_status_mismatch' this is the runner outcome
        ('failed' / 'timeout' / 'unknown'); for 'context_substitution_error'
        it is the sentinel 'context_substitution_error' (Z3 never ran).
      divergence_kind: discriminator in _VALID_DIVERGENCE_KINDS.

    Raises SigningError on invalid inputs (mirrors sign_stamp_upgrade shape
    discipline: non-empty str bundle_id, non-negative int record_idx excluding
    bool, 64-hex obligation_sha, non-empty status strings, known divergence
    kind)."""
    if not isinstance(bundle_id, str) or not bundle_id:
        raise SigningError("bundle_id is required for divergence-record signing")
    if (
        isinstance(record_idx, bool)
        or not isinstance(record_idx, int)
        or record_idx < 0
    ):
        raise SigningError(
            f"record_idx must be a non-negative int (bool excluded), got "
            f"{record_idx!r} of type {type(record_idx).__name__}"
        )
    if not isinstance(obligation_sha, str) or not _SHA256_RE.match(obligation_sha):
        raise SigningError(
            f"obligation_sha={obligation_sha!r} is not a valid 64-character hex SHA-256"
        )
    if not isinstance(producer_claimed, str) or not producer_claimed:
        raise SigningError("producer_claimed must be a non-empty string")
    if not isinstance(verifier_computed, str) or not verifier_computed:
        raise SigningError("verifier_computed must be a non-empty string")
    if divergence_kind not in _VALID_DIVERGENCE_KINDS:
        raise SigningError(
            f"divergence_kind={divergence_kind!r} is not in "
            f"{sorted(_VALID_DIVERGENCE_KINDS)}"
        )

    if timestamp_utc is None:
        timestamp_utc = _now_iso8601_utc()

    payload = _build_divergence_record_payload(
        bundle_id=bundle_id,
        record_idx=record_idx,
        obligation_sha=obligation_sha,
        producer_claimed=producer_claimed,
        verifier_computed=verifier_computed,
        divergence_kind=divergence_kind,
        verifier_id=key.verifier_id,
        timestamp_utc=timestamp_utc,
    )
    mac = _hmac_hex(key, payload)

    return {
        "record_kind": _DIVERGENCE_RECORD_PAYLOAD_KIND,
        "algorithm": "hmac-sha256",
        "verifier_id": key.verifier_id,
        "timestamp_utc": timestamp_utc,
        "bundle_id": bundle_id,
        "record_idx": record_idx,
        "obligation_sha": obligation_sha,
        "producer_claimed": producer_claimed,
        "verifier_computed": verifier_computed,
        "divergence_kind": divergence_kind,
        "mac": mac,
    }


def verify_divergence_record(
    record: dict, *, key: VerifierSigningKey, bundle_id: str, record_idx: int
) -> bool:
    """Return True iff a signed divergence record re-verifies against `key` and
    the caller-supplied authoritative bindings (bundle_id, record_idx).

    Mirrors verify_stamp_upgrade_signature: caller MUST supply authoritative
    bundle_id + record_idx; the record's self-reported values must agree
    (so a record minted for bundle A / row 0 cannot be verified against
    bundle B / row 5). Never raises on record-level defects — returns False
    for clean rejection in adversarial/forensic callers."""
    if not isinstance(record, dict):
        return False
    if record.get("record_kind") != _DIVERGENCE_RECORD_PAYLOAD_KIND:
        return False
    if record.get("algorithm") != "hmac-sha256":
        return False
    if record.get("verifier_id") != key.verifier_id:
        return False

    # Caller-authoritative bindings.
    if not isinstance(bundle_id, str) or not bundle_id:
        return False
    if (
        isinstance(record_idx, bool)
        or not isinstance(record_idx, int)
        or record_idx < 0
    ):
        return False

    # Self-describing fields must match the caller's authoritative values.
    rec_bundle_id = record.get("bundle_id")
    if not isinstance(rec_bundle_id, str) or rec_bundle_id != bundle_id:
        return False
    rec_record_idx = record.get("record_idx")
    if (
        isinstance(rec_record_idx, bool)
        or not isinstance(rec_record_idx, int)
        or rec_record_idx < 0
        or rec_record_idx != record_idx
    ):
        return False

    obligation_sha = record.get("obligation_sha")
    if not isinstance(obligation_sha, str) or not _SHA256_RE.match(obligation_sha):
        return False
    producer_claimed = record.get("producer_claimed")
    if not isinstance(producer_claimed, str) or not producer_claimed:
        return False
    verifier_computed = record.get("verifier_computed")
    if not isinstance(verifier_computed, str) or not verifier_computed:
        return False
    divergence_kind = record.get("divergence_kind")
    if divergence_kind not in _VALID_DIVERGENCE_KINDS:
        return False
    timestamp_utc = record.get("timestamp_utc")
    if not isinstance(timestamp_utc, str) or not timestamp_utc:
        return False
    mac_claimed = record.get("mac")
    if not isinstance(mac_claimed, str):
        return False

    payload = _build_divergence_record_payload(
        bundle_id=bundle_id,
        record_idx=record_idx,
        obligation_sha=obligation_sha,
        producer_claimed=producer_claimed,
        verifier_computed=verifier_computed,
        divergence_kind=divergence_kind,
        verifier_id=key.verifier_id,
        timestamp_utc=timestamp_utc,
    )
    mac_expected = _hmac_hex(key, payload)
    return hmac.compare_digest(mac_claimed, mac_expected)
