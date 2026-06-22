"""BundleManifest dataclass and validator for v-kernel canary4 audit bundles.

Two-mode dispatch mirrors the internal two-mode-dispatch compliance convention:
  'vcp-v1.1-canary4' — canary4 VCP envelope path
  'legacy'           — pre-canary4 bundles verified as-is


"""

from __future__ import annotations

import hashlib
import json
import os
import stat as stat_module
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .admission import InputInadmissible, iter_admitted_jsonl_tolerant
from .fragments.fragment_id import BadFragmentID, fragment_from_dict
from .manifest_three_set import (
    BadVisibilityPolicy,
    PerOutputManifest,
    ThreeSetMismatch,
    validate_per_output_manifest,
)
from .output_modes.mode import BadOutputMode, OutputMode, mode_from_dict
from .retrieval.capture import TraceNotFound, load_trace
from .snapshots.cid import compute_cid
from .source_registry.decision_provenance import read_decisions
from .source_registry.properties import (
    BadPublicationClass,
    validate_publication_class,
)


# ---------------------------------------------------------------------------
# Deep-immutability for a parsed manifest (shared-state invariant lock)
# ---------------------------------------------------------------------------
#
# BundleManifest is @dataclass(frozen=True, slots=True): that freezes the
# TOP-LEVEL bindings (you cannot do `manifest.files = {}`), but the nested
# dict/list VALUES parsed from manifest.json stay mutable. The verifier threads
# ONE manifest object through ~10 sequential pipeline steps and several late
# steps RE-READ fields the early integrity steps already consumed, so
# _load_manifest deep-freezes every parsed collection at the parse boundary.
#
# The freeze machinery lives in audit_bundle._freeze (extracted 2026-06-10 when
# the same frozen-dataclass/mutable-field shape was found on RevocationList and
# other trust-decision carriers — rationale, threat posture, and representation
# choice are documented there). Re-exported here so existing importers
# (verifier.py, tests) keep working unchanged.

from ._freeze import _FrozenDict, _FrozenList, deep_freeze  # noqa: F401


# ---------------------------------------------------------------------------
# TypedCheck registry — plugins call register_typed_check() at import time
# ---------------------------------------------------------------------------

_TYPED_CHECK_REGISTRY: set[str] = set()


def register_typed_check(name: str) -> None:
    """Register a TypedCheck plugin name; idempotent."""
    _TYPED_CHECK_REGISTRY.add(name)


def registered_typed_checks() -> frozenset[str]:
    return frozenset(_TYPED_CHECK_REGISTRY)


# ---------------------------------------------------------------------------
# Receipt-verifier registry — pluggable extension handlers
# ---------------------------------------------------------------------------
# A manifest MAY carry `extension_receipts: {<kind>: <assembly>}`, where each
# entry is an optional extension claim verified by a handler registered here.
# Handlers self-register at import via register_receipt_verifier(). The base
# distribution registers NONE: a deployment that wants an extension verified
# ships (and imports) the handler that registers it. An extension receipt with
# no registered handler is reported NOT EVALUATED by the verifier — present but
# unverified, never silently passed and never used to fail an otherwise-valid
# bundle. This mirrors the register_typed_check() pattern above.

_ReceiptVerifier = Callable[[dict], "tuple[bool, str | None, str]"]
_RECEIPT_VERIFIER_REGISTRY: dict[str, _ReceiptVerifier] = {}


def register_receipt_verifier(kind: str, fn: _ReceiptVerifier) -> None:
    """Register an extension-receipt verifier for `kind`; last registration wins.

    `fn(assembly)` returns (ok, reason, detail): ok=True passes; ok=False rejects
    with a stable machine `reason` plus a human `detail`. The caller treats a
    raised KeyError/TypeError/ValueError as a fail-closed reject.

    Registration is a BOOTSTRAP-time act by verifier-distribution code (handlers
    self-register at import); bundle-supplied code never runs in-process on the
    default path, so it can never reach this function. The registry is NOT
    defended against in-process concurrent mutation — code that can call this
    can equally patch verify() itself. The coherence property the verifier DOES
    hold is per-run: verify() takes ONE snapshot of this registry per run and
    evaluates every receipt against it (see BundleVerifier.
    _step_extension_receipts), and the CLI presents from that run's verdict, so
    one verification can never mix two registry states.
    """
    _RECEIPT_VERIFIER_REGISTRY[kind] = fn


def registered_receipt_verifiers() -> dict[str, _ReceiptVerifier]:
    return dict(_RECEIPT_VERIFIER_REGISTRY)


def evaluate_extension_receipt(
    kind: str,
    assembly: object,
    registry: "dict[str, _ReceiptVerifier] | None" = None,
) -> "tuple[str, str | None, str]":
    """Evaluate one extension receipt. Returns (status, reason, detail) with
    status in {"PASS", "FAIL", "NOT_EVALUATED"}.

    Single source of truth used by BundleVerifier.verify(); the CLI no longer
    re-executes handlers — it presents the per-kind dispositions verify()
    already recorded on the verdict face (one execution per run, so the
    presented lines and the canonical verdict can never come from two
    different handler runs).

    `registry` is the per-run SNAPSHOT discipline (same class as the RES-04
    single-manifest-read): verify() takes one registered_receipt_verifiers()
    copy per run and passes it for every kind, so all kinds in one verdict see
    the SAME registry state even if a (TCB-only) caller mutates the module
    global mid-run. None falls back to a live read for single-shot callers.

      PASS          — a handler is registered for `kind` and it accepted.
      FAIL          — handler rejected, or the assembly is malformed (a
                      malformed assembly is a reject, never a pass).
      NOT_EVALUATED — no handler registered: present but UNVERIFIED. The caller
                      treats this as could-not-conclude (clean-ERROR / exit 2),
                      NEVER a pass — a consumer keying on the verdict must not
                      read OK over an unverified claim.
    """
    fn = (registry if registry is not None else _RECEIPT_VERIFIER_REGISTRY).get(kind)
    if fn is None:
        return (
            "NOT_EVALUATED",
            None,
            f"no verifier registered for receipt kind '{kind}' in this build; the "
            "extension claim is present but UNVERIFIED",
        )
    if not isinstance(assembly, dict):
        return (
            "FAIL",
            "RECEIPT_MALFORMED",
            f"extension_receipts['{kind}'] is not an object",
        )
    try:
        ok, reason, detail = fn(assembly)
    except (KeyError, TypeError, ValueError) as exc:
        return ("FAIL", "RECEIPT_ASSEMBLY_MALFORMED", f"{type(exc).__name__}: {exc}")
    if ok:
        return ("PASS", None, detail or f"{kind} extension receipt verified")
    return ("FAIL", reason or "RECEIPT_REJECT", detail)


# ---------------------------------------------------------------------------
# Valid schema versions (two-mode dispatch)
# ---------------------------------------------------------------------------

_VALID_SCHEMA_VERSIONS: frozenset[str] = frozenset(
    {"vcp-v1.1-canary4", "vcp-v1.1", "legacy", "vcp-v1.2-dsse"}
)

# Post-cutover DSSE schema tags. MEMBERSHIP test only — schema_version is an
# opaque string tag, not an orderable version. Any `>=` comparison on it is
# meaningless (e.g. "vcp-v1.1-canary4" >= X has no defined ordering).
_POST_CUTOVER_SCHEMA_VERSIONS: frozenset[str] = frozenset({"vcp-v1.2-dsse"})


def validate_schema_version(schema_version: object) -> None:
    """Allowlist gate for manifest.schema_version — the contract boundary for
    verifier semantics. Single definition shared by validate_manifest() AND the
    verifier's raw-parse boundary (_validate_manifest_shape) so the two paths
    cannot drift: schema_version selects DSSE-cutover behavior, reserved-field
    handling, and versioned audit semantics, and `is_post_cutover` is total
    over unknown tags (returns False) — so an UN-allowlisted version would not
    merely verify under wrong semantics, it would ride the weaker pre-cutover
    lane. Unknown ⇒ REJECT before any check runs, never best-effort.

    History: the ef9a197 fail-closed refactor moved the CLI off
    validate_manifest() onto BundleVerifier.verify() ("verify() subsumes the
    deep validators") — but this allowlist lived in validate_manifest's
    SHALLOW step 1, which verify()'s parse boundary did not replicate, so
    unknown schema versions verified green through both the library and the
    CLI (ChatGPT BLOCK-03, reproduced 2026-06-11). Raises SchemaVersionError
    (a ManifestError) — verify() maps it to a structured REJECT.
    """
    # Total over ALL inputs: the isinstance guard runs before the frozenset
    # membership test so an unhashable value (list/dict) raises the structured
    # SchemaVersionError, never a TypeError that would classify as crash-ERROR
    # instead of REJECT at the parse boundary.
    if not isinstance(schema_version, str) or (
        schema_version not in _VALID_SCHEMA_VERSIONS
    ):
        raise SchemaVersionError(
            f"schema_version {schema_version!r} is not valid; "
            f"expected one of {sorted(_VALID_SCHEMA_VERSIONS)}"
        )


def is_post_cutover(schema_version: str) -> bool:
    """True iff schema_version is a post-cutover DSSE-sealed schema tag.

    MEMBERSHIP test, not ordering — schema_version is an opaque string tag,
    so any ``>=`` comparison on it is meaningless. Total over all inputs:
    unknown/invalid tags return False (never raises, never KeyError).
    """
    return schema_version in _POST_CUTOVER_SCHEMA_VERSIONS


# C19 Layer A v0.3 event-kind taxonomy. Unknown kinds emit EVENT_KIND_UNKNOWN
# (fail-closed; forward-incompat is the security property). key_rotation
# REGISTERED at v0.3 S19d (rotation event class; designated handler is
# audit_bundle/extensions/c19/layer_a_counter.detect_and_verify_rotation_event,
# NOT yet dispatched from the live layer-A pipeline — tests-only keel).
V0_3_EVENT_KINDS: frozenset[str] = frozenset(
    {
        "retrieval",
        "reasoning_step",
        "tool_call",
        "stamp_emission",
        "dispatch_record",
        "host_message_send",
        "host_message_recv",
        "manifest_dag_emit",
        "key_rotation",
    }
)


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class ManifestError(Exception):
    """Base class for all manifest validation failures."""


class MalformedManifest(ManifestError):
    """manifest.json is not a JSON object, or a field whose value the integrity
    walk dereferences carries the wrong container/value type.

    The 4-step walk and validate_manifest both call ``.items()`` on
    files/spec_files/cross_refs and ``.lower()`` on their SHA values, and iterate
    typed_checks; wrong JSON types otherwise escape as an uncaught AttributeError.
    Single source of truth for this check is _validate_field_shapes() below — it
    feeds BOTH the BundleVerifier.verify parse boundary (audit_bundle/verifier.py)
    and validate_manifest() so the two paths cannot drift. Found by fuzzing;
    subclasses ManifestError so veriker/cli/verify.py's existing ManifestError handler
    catches it without a new except arm."""


class UnsafeBundlePath(ManifestError):
    """A manifest-listed path resolves outside bundle_dir (absolute path,
    .. traversal, or symlink leaving the tree) or resolves to a non-regular
    file (directory, fifo, device).

    Found by atheris coverage-guided fuzzing: the input
    ``{"files":{"/":"a"}}`` made pathlib's ``bundle_dir / "/"`` absolutize to
    ``/``, which then raised ``IsADirectoryError`` from ``read_bytes()`` —
    breaking the §C9 fail-closed contract. The path-escape variant
    (``{"files":{"/etc/hostname":"a"}}``) did not crash but induced the
    verifier to SHA-256 an attacker-chosen file outside the bundle.

    Single source of truth is _safe_bundle_path() below — it feeds both
    BundleVerifier.verify (file_integrity + cross_refs walks) and
    validate_manifest (file + snapshot loops) so the two paths cannot drift.
    Subclasses ManifestError so the veriker/cli/verify.py handler catches it."""


class SchemaVersionError(ManifestError):
    """schema_version is absent, unknown, or malformed."""


class FileSHAMismatch(ManifestError):
    """On-disk file hash does not match the manifest-recorded hash."""


class SpecSHAMissing(ManifestError):
    """A spec_files entry has no SHA recorded (empty value)."""


class CrossRefBroken(ManifestError):
    """A cross_refs target does not resolve to any key in files or spec_files."""


class TypedCheckUnregistered(ManifestError):
    """A typed_checks entry names a plugin not present in the registry."""


class SnapshotPolicyMissing(ManifestError):
    """snapshots is non-empty but snapshot_policy is None."""


class SnapshotCIDMismatch(ManifestError):
    """Computed CID of a snapshot file does not match the manifest-recorded CID string."""


class SnapshotPolicyDriftError(ManifestError):
    """snapshot_policy hash does not match policy_dict_sha256 in one or more ingest records."""


class FragmentSourceUnreachable(ManifestError):
    """A fragment_anchor's source_cid is declared in snapshots but the snapshot file is missing."""


class SourceAttributesOrphan(ManifestError):
    """A source_attributes key (source_cid) has no corresponding snapshot in the bundle."""


class BadDecisionProvenanceLog(ManifestError):
    """decision_provenance_log is set but the referenced path does not exist in bundle_dir."""


class SourceAttributesMalformed(ManifestError):
    """A source_attributes value is not a JSON object (dict) — cannot carry the four-axis claims."""


class SourceProvenanceIncomplete(ManifestError):
    """decision_provenance_log is set but a source_cid has no DecisionProvenance record (replay-incomplete)."""


class SignedArtifactKeyMissing(ManifestError):
    """source_attributes entry claims signed_artifact_present=True but signing_key_id is null/absent."""


class IssuerIdentifierMissing(ManifestError):
    """source_attributes entry claims issuer_identity_verified=True but issuer_identifier is null/absent."""


class MissingRetrievalTraceLog(ManifestError):
    """retrieval_trace_id is set but retrieval_trace_log is None."""


class BadRetrievalTraceLog(ManifestError):
    """retrieval_trace_log is set but the file is missing or load_trace fails."""


class RetrievalTraceOrphan(ManifestError):
    """A candidate_set CID annotated in source_attributes is missing from snapshots."""


class OutputModeMissingForOutputBundle(ManifestError):
    """per_output_manifests is non-empty but output_mode_signal is None."""


class VEModeRequiresQuoteSupport(ManifestError):
    """VE-mode output_mode_signal but a per_output_manifest has no quote_supporting sources."""


class AppendOnlySpecMalformed(ManifestError):
    """An entry in BundleManifest.append_only_files is not a well-formed AppendOnlySpec dict per §C9.1 schema reservation."""


class DispatchRecordFieldAbsent(ManifestError):
    """dispatch_records is non-empty but a per_output entry has no corresponding row."""


class StampAggregateRoundupDetected(ManifestError):
    """aggregate_stamp claims a stronger value than min(per-row stamp_observed)."""


class StampAggregationRuleRejected(ManifestError):
    """Non-min composition rule (avg/vote/weighted) detected on aggregate_stamp."""


class DischargeStatusForged(ManifestError):
    """A dispatch_record carries a non-trivial discharge_status without a valid
    verifier signature (v0.2: signed by audit_bundle.discharge.verifier_signing;
    v0.1 admitted only 'not-attempted')."""


class DischargeStatusVerifierDivergence(ManifestError):
    """v0.2: a verifier-signed discharge_status disagrees with the runner's
    independent re-discharge outcome (the verifier may have signed under stale
    inputs, or the signature may be replayed across different contexts)."""


class DischargeFragmentOutOfScope(ManifestError):
    """v0.2: a dispatch_record output type carries a refine formula outside
    QF_LIA + QF_BV + QF_LRA + QF_UF (e.g. quantifiers, arrays, strings,
    nonlinear arithmetic, recursive datatypes)."""


class RefinementFragmentOutOfScope(ManifestError):
    """A dispatch_record output type carries a refine formula outside the v0.1 fragment.
    Superseded at v0.2 by DischargeFragmentOutOfScope; retained for backward
    compatibility with code that imports the v0.1 name."""


class RefinementDischargeFailed(ManifestError):
    """An in-fragment refinement formula returned unsat at verifier-side discharge
    (v0.2 hook; surfaced via DISCHARGE_STATUS_VERIFIER_DIVERGENCE in the plugin's
    PluginResult)."""


class RefinementTimeout(ManifestError):
    """A refinement-check timed out (v0.2 hook; surfaced via the runner's
    Z3Status.TIMEOUT and the plugin's DISCHARGE_STATUS_VERIFIER_DIVERGENCE)."""


class Z3SubprocessFailure(ManifestError):
    """v0.2: the Z3 invoker reported a process / subprocess-level failure
    (binary missing, segfault, parse error). Surfaced from Z3_SUBPROCESS_FAILURE
    in the C16 plugin."""


class ReservedEffectLabelForward(ManifestError):
    """Advisory: a reserved-but-not-yet-emitted effect label appeared (db/subprocess/random/clock/notify)."""


# ---------------------------------------------------------------------------
# C19 Layer A — causal_chain['layer_a'] discriminated-union sub-key errors
# (S19a stream; sibling sub-streams S19b / S19c add their own error classes
# in their respective tasks; do NOT modify these from S19b / S19c PRDs)
# ---------------------------------------------------------------------------


class ManifestHeaderLeafMismatch(ManifestError):
    """OF1 (v0_3_of1): the stored
    `causal_chain.layer_a.manifest_header_merkle_leaf` field does not match
    the 32-byte sha256 leaf recomputed from `manifest.bundle_id` +
    `manifest.created_at` + `manifest.dispatch_records`. Raised by
    validate_manifest check 10 — the load-bearing v0.3 integrity check
    that lets the C14 defense-7 trust assumption pivot from honest-sealer
    to honest-anchor when the field is present.
    """


class CausalChainLayerASchemaError(ManifestError):
    """causal_chain[layer_a] sub-key shape malformed (S19a contract)."""


class CausalChainLayerAEventKindUnknown(ManifestError):
    """Event kind not in V0_3_EVENT_KINDS frozen set (forward-incompat hard-fail)."""


class CausalChainLayerAChainHeightMismatch(ManifestError):
    """len(events) != chain_height."""


# ---------------------------------------------------------------------------
# C14 v0.2 — stamp_upgrade exception classes (mirror plugin reason codes)
# ---------------------------------------------------------------------------


class StampUpgradeForged(ManifestError):
    """v0.2: a dispatch_record carries a stamp_upgrade without a valid
    verifier signature (or with a signature that fails HMAC verification,
    is replayed across bundles/records, or is signed under a different key)."""


class StampUpgradeConflict(ManifestError):
    """v0.2: two distinct stamp_upgrade signatures appear bound to the same
    record (e.g. via a sibling 'stamp_upgrades' list); the verifier cannot
    arbitrate and rejects the bundle."""


class StampUpgradeOutOfOrder(ManifestError):
    """v0.2: a stamp_upgrade signature timestamp is later than the bundle's
    created_at — the upgrade was applied after the bundle was sealed, which
    breaks the bundle-as-canonical-state invariant from the C16 contract."""


class StampUpgradeTierJumpRejected(ManifestError):
    """v0.2: a stamp_upgrade asks to jump more than one tier (or to downgrade);
    the audit-bundle contract §C16 specifies one-tier-only upgrades."""


class StampUpgradeReasonInvalid(ManifestError):
    """v0.2: a stamp_upgrade carries an upgrade_reason outside the v0.2 enum
    (currently {'discharged', 'predicate_satisfied'})."""


class StampUpgradeDischargeLinkBroken(ManifestError):
    """v0.2: a stamp_upgrade with upgrade_reason='discharged' references a
    discharge_obligation_sha that does not match the row's proof.obligation_sha,
    or the row's V16 verifier_signature is missing or claims a discharge_status
    other than 'discharged'."""


# V15: WASM Component Model effect enforcement.
# When dispatch_record.effect_enforcement_mode == 'wasm', the record MUST
# carry a verifier-signed execution_trace; the C15 plugin verifies the
# signature, the trace's match against declared effects, and the absence
# of reserved-set labels.
class WasmTraceMissing(ManifestError):
    """v0.2: a dispatch_record claims effect_enforcement_mode='wasm' but
    carries no execution_trace, or the execution_trace lacks a
    verifier_signature block. Violates the V15 verifier-set discipline."""


class WasmTraceSignatureInvalid(ManifestError):
    """v0.2: a dispatch_record's execution_trace.verifier_signature failed
    HMAC re-verification. Either the trace was signed under a different
    key, the signed payload was tampered, or the trace was lifted from
    another bundle / record."""


class WasmEffectDivergence(ManifestError):
    """v0.2: the WASM module's observed_imports include at least one
    import that is not admitted by any of the declared_effects. The
    dispatcher silently took an effect it did not declare — exactly
    the lying-dispatcher attack the v0.2 enforcement closes."""


class WasmReservedLabelRejected(ManifestError):
    """v0.2: a dispatch_record claims effect_enforcement_mode='wasm'
    AND declares a reserved-set label (db / subprocess / random / clock /
    notify). Reserved labels have no v0.2 enforcement story; the
    dispatcher must migrate to a locked label or stay on
    mode='advisory'."""


class WasmResourceLimitExceeded(ManifestError):
    """v0.2: the WASM execution trace records a fuel-exhaustion / memory-
    cap / syscall-cap trap. Treated as a verification failure when the
    dispatch_record claims effect_enforcement_mode='wasm' and the trace
    reports return_status != 'ok' — a properly-resourced dispatcher
    should not exhaust the caps it declared."""


# ---------------------------------------------------------------------------
# BundleManifest dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BundleManifest:
    """Canonical schema for the audit bundle's manifest.json.

    Every field below is a TOP-LEVEL key in manifest.json. There are no
    sidecar JSONL files that the verifier reads to populate this dataclass
    — `payload/<name>.jsonl` files are inspection artifacts only and do
    not feed validation. The verifier loads this dataclass via
    audit_bundle.verifier._load_manifest, which reads manifest.json and
    maps each top-level key to the corresponding field; fields absent
    from the JSON take the dataclass default (empty for collections,
    None for optionals).

    Field reference (key in manifest.json | type | required? | validating plugin / verifier step):

    Required at every schema_version:
      schema_version       str             required   verifier (validate against _VALID_SCHEMA_VERSIONS)
      bundle_id            str             required   identifier; HMAC-bound for V15 wasm-mode trace verification
      created_at           str             required   ISO-8601 UTC with 'Z'
      files                dict[str→hex]   required   FileIntegrityManySmall (skips spec/ + snapshots/ trees by convention)
      spec_files           dict[str→hex]   required   SpecShaPinCheck (walks spec/ tree only); empty dict if no spec/ tree
      cross_refs           dict[str→str]   required   verifier step 3 (target must resolve in files OR spec_files)
      payload              dict[str→str]   required   informational; reserved for future use
      typed_checks         list[str]       required   verifier step 4 (every name MUST be registered AND have a plugin instance)

    Optional (W3 additive — defaults to empty / None when absent from manifest.json):
      snapshots                  dict[cid→relpath]      content-addressed snapshots; CID re-computed and verified by validate_manifest
      snapshot_policy            dict | None            policy_to_canonical_dict() output; required when snapshots is non-empty
      fragment_anchors           dict[name→dict]        fragment_id schema; each value parses via fragment_from_dict
      source_attributes          dict[cid→dict]         four-axis source properties; each cid must appear in snapshots
      decision_provenance_log    str | None             bundle-relative path to JSONL of DecisionProvenance entries
      retrieval_trace_id         str | None             references a trace in retrieval_trace_log; None if no retrieval
      retrieval_trace_log        str | None             bundle-relative path to RetrievalTrace JSONL
      per_output_manifests       tuple[dict, ...]       three-set per-output bindings; each parses via PerOutputManifest
      output_mode_signal         dict | None            mode_to_canonical_dict() output; required when per_output_manifests is non-empty

    Optional (Phase-0 substrate extensions C14/C15/C16 — defaults to empty / None when absent):
      dispatch_records   tuple[dict, ...]   DispatchRecordWellformedCheck (C15 well-formedness plugin)
                                            — POPULATED AS A TOP-LEVEL ARRAY in manifest.json under the
                                              "dispatch_records" key. NOT read from a sidecar JSONL file —
                                              `payload/dispatch_records.jsonl` if present is for human inspection
                                              only and is not loaded by the verifier.
                                            — Each record carries its OWN `schema_version: "0.1"` field
                                              (the C15 RECORD schema, distinct from the BUNDLE's
                                              `schema_version: "vcp-v1.1-canary4"`). Records without "0.1"
                                              are rejected with SCHEMA_VERSION_UNRECOGNIZED.
                                            — Register DispatchRecordWellformedCheck with
                                              `op_kinds_admitted=frozenset({...})` to admit domain-specific
                                              op kinds beyond the default enum (RETRIEVAL/FORECAST/TOOL/
                                              COMPUTE/MODEL_CALL).
      aggregate_stamp    str | None         C14 stamp_lattice plugin's min(per-row stamp_observed); None when no
                                            dispatch_records or pre-Phase-0 bundle.
      assurance_profile  str | None         CC-2b D1 declared assurance profile; FOLDED into the OF1 manifest-header
                                            leaf (canonical manifest-header convention) so the claim is tamper-evident.
                                            None when no profile is declared.

    For the full contract semantics see the audit-bundle contract §C1-C16.
    For the canonical builder pattern see examples/<domain>_minimal/_build_bundle.py.
    """

    schema_version: str  # 'vcp-v1.1-canary4' | 'legacy'
    bundle_id: str
    created_at: str  # ISO-8601 UTC with 'Z'
    files: dict[str, str]  # path -> sha256 hex
    spec_files: dict[str, str]  # spec-doc relative path -> SHA at stamp time
    cross_refs: dict[str, str]  # logical-name -> manifest path or spec key
    payload: dict[str, str]  # payload-key -> file path
    typed_checks: list[str]  # registered TypedCheck plugin names
    # Phase-W3 additive; absent in W1-W2 bundles (backward-compat via defaults)
    snapshots: dict[str, str] = field(
        default_factory=dict
    )  # cid_string -> relative path inside bundle
    snapshot_policy: dict | None = None  # policy_to_canonical_dict() output
    fragment_anchors: dict[str, dict] = field(
        default_factory=dict
    )  # logical_anchor_name -> fragment_to_canonical_dict() output
    source_attributes: dict[str, dict] = field(
        default_factory=dict
    )  # source_cid -> properties_to_canonical_dict() output
    decision_provenance_log: str | None = (
        None  # bundle-relative path to JSONL of DecisionProvenance entries
    )
    retrieval_trace_id: str | None = (
        None  # references a trace in retrieval_trace_log; None if no retrieval
    )
    retrieval_trace_log: str | None = (
        None  # bundle-relative path to RetrievalTrace JSONL
    )
    per_output_manifests: tuple[dict, ...] = field(
        default_factory=tuple
    )  # tuple of per_output_manifest_to_canonical_dict() outputs
    output_mode_signal: dict | None = (
        None  # mode_to_canonical_dict() output; required for output-bearing bundles
    )
    # Phase-0 substrate extensions (C14/C15/C16); absent in W3-baseline bundles (backward-compat via defaults)
    dispatch_records: tuple[dict, ...] = field(default_factory=tuple)
    # Schema reservation per the audit-bundle contract §C15 (dispatch_record schema).
    # v0.1 stores the field shape; well-formedness enforcement lives in
    # audit_bundle/plugins/dispatch_record_wellformed.py. Effect labels are advisory
    # at v0.1 — structural enforcement (WASM Component Model) is the v0.2 deliverable
    # per the effect calculus.
    aggregate_stamp: str | None = None
    # min(per-row stamp_observed) per the C14 lattice rule; None for legacy/W3-baseline
    # bundles that emit no dispatch_records. Verifier-set, never dispatcher-trusted
    # (C14 + C16 discipline).
    assurance_profile: str | None = None
    # CC-2b D1: the declared assurance profile (top-level manifest key). When present
    # it is FOLDED into the OF1 manifest-header Merkle leaf (canonical manifest-header
    # convention) so the producer's profile claim is tamper-evident. The profile FLOOR
    # (downgrade protection) is verifier-held OOB, not this field. None for bundles
    # that declare no profile — the leaf then omits it (byte-identity preserved).

    # ─── v0.3 schema reservation stubs ──────────────────────────────────────────
    # Each field is owned by exactly one stream. Stream changes edit ONLY their
    # named field declaration here PLUS their `audit_bundle/extensions/<module>.py`.
    # No other Block-1 stream touches another stream's field.

    # Owner: S§C9.1 — append-only attributed file pinning (extension §C9.1).
    # v0.3 schema reservation only; verifier IGNORES at v0.3 and continues strict-SHA
    # enforcement from manifest.files for all entries. Plugin enforcement
    # (AppendOnlyAttributedCheck) deferred to v0.4.
    #
    # Tuple of AppendOnlySpec dicts. Each dict shape (v0.3 reserved, frozen at this
    # release; additional keys at v0.4 must keep these three required):
    #   {
    #     "path": str,                  # bundle-relative path (e.g. "retrieval_trace_log.jsonl")
    #     "attribution_key": str,       # one of {"trace_id", "source_cid", "session_id"}
    #     "attribution_plugin": str,    # typed_check plugin name (e.g. "three_set_sum_invariant")
    #     "verification_mode": str,     # one of {"first_match", "all_attributed"}
    #   }
    # Empty default (`()`) keeps W3 + v0.2 + v0.2.1 baseline bundles back-compatible.
    # See audit_bundle/extensions/c9_1_append_only_files.py for the well-formedness
    # validator and the v0.4 transition path.
    append_only_files: tuple[dict, ...] = field(default_factory=tuple)

    # Owner: S14v3-RES — rigor profile parameterization.
    # v0.3 schema reservation only; production pipeline deferred to v0.4.
    rigor_profile: dict | None = None

    # Owner: S17-RES — attested serving evidence (RATS-aligned; RFC 9334).
    # v0.3 schema reservation only. Substrate work (S17a Intel TDX parser +
    # S17b AMD SEV-SNP parser + step-10 jurisdiction-routing plugin +
    # vendor-CA TUF integration + assurance-profile mode handling) DEFERRED
    # to v0.4 — the substrate shape was held open after review surfaced ~20
    # substrate-shape attack classes. Shape lives in
    # `audit_bundle/extensions/c17_attested_serving` (TypedDicts) and the
    # audit-bundle contract §C17.
    # v0.3 verifier IGNORES this field if populated (forward-compat for v0.4
    # bundles traversing a v0.3 verifier); default `None` stamps the bundle
    # INFERENCE_UNATTESTED (trust degrades to L1 model-card consumption).
    # The `attested-serving-environment` mode + the `INFERENCE_WEIGHTS_COMPROMISABLE`
    # bundle tag are RESERVED-NAME-ONLY at v0.3 (v0.4 work).
    attested_serving: dict | None = None

    # Owner: S18 — verifier supply chain (production).
    # v0.3 production; the verifier-supply-chain design questions are resolved.
    verifier_identity: dict | None = None

    # Owner: S19a / S19b / S19c — causal DAG + cross-host receipts + selective
    # anchoring (reference implementation, soak-then-harden). Sub-streams write
    # to discriminated-union sub-keys inside this dict; they do NOT touch this
    # field declaration line.
    causal_chain: dict | None = None

    # Owner: S20 — semantic fidelity (schema reservation only at v0.3).
    # NLI / entailment / contradiction plugin work is its own future sprint.
    semantic_fidelity: dict | None = None

    # Pluggable extension receipts — {<kind>: <assembly>}. Each entry is an
    # optional extension claim verified by a handler registered through
    # register_receipt_verifier(<kind>, fn) (see the registry above). The
    # verifier dispatches each present kind to its registered handler and folds
    # the verdict into the overall result; a kind with NO registered handler is
    # reported NOT EVALUATED (present but unverified) — never silently passed and
    # never used to fail an otherwise-valid bundle. IGNORED when absent — baseline
    # bundles that carry no extension receipts are unaffected. The assembly bytes
    # are SHA-covered as part of this manifest key in manifest.files, so an entry
    # cannot be retagged without changing the manifest hash.
    extension_receipts: dict | None = None

    # ─── Spec-pinned type dispatch ──────────────────────────────────────────────
    # Per claimed output, a CONFORMANCE CLAIM: {output_id, type, conforms_to}.
    # The producer claims the output is of type `type` under pinned spec
    # `conforms_to`; the BINDING (primitive_id + comparator{kind,params}) lives
    # in the SHA-pinned, AUDITOR-anchored spec — NOT here (the producer cannot
    # author or select it). When non-empty, BundleVerifier engages the
    # spec-pinned dispatch step (audit_bundle/rederivation/) and REQUIRES an
    # auditor SpecAnchor at construction; when empty (0/56 baseline manifests)
    # the step is wholly inert. The tolerance/comparator do NOT live in the
    # manifest — only the type claim does.
    outputs: tuple[dict, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_bundle_path(bundle_dir: Path, rel_path: str) -> Path:
    """Resolve ``rel_path`` inside ``bundle_dir`` with two fail-closed checks
    that the integrity walk does NOT perform on its own:

      1. The resolved location must stay under ``bundle_dir.resolve()``.
         pathlib's ``/`` operator absolutizes when the RHS is absolute
         (``Path("/bundle") / "/" == Path("/")``) and does not normalize
         ``..`` — so an unguarded ``bundle_dir / rel_path`` lets the
         manifest pick any path the verifier can read.
      2. If the on-disk object exists, it must resolve to a REGULAR FILE —
         checked by ``os.lstat`` (never opens content, so it cannot block).
         A directory, FIFO, socket, or device at a manifest-declared path
         fails closed; a CONTAINED symlink whose target is a regular file is
         tolerated as-built (the strict-SHA walk SHA-pins the dereferenced
         bytes — a symlink that ESCAPED was already rejected by check 1).
         This is the single chokepoint every verdict-path reader routes
         through (the strict-SHA walk's ``read_bytes()``, both ``load_trace``
         callers, the append-only attribution check), so the discipline holds
         package-wide rather than per-reader. Readers that must not follow
         even a contained symlink layer ``O_NOFOLLOW`` on top of this helper.

    Why widen the old ``is_dir()`` check: the integrity walk reads these paths
    with a BLOCKING ``read_bytes()``/``open()``. A directory raised
    ``IsADirectoryError`` (the original atheris finding), but a FIFO or socket
    with no writer does NOT raise on read — it BLOCKS, hanging the verifier
    indefinitely (a DoS that lands BEFORE any verdict, so fail-closed never
    fires). ``lstat`` classifies the object without opening it, so the gate
    rejects a FIFO/socket/device up front. The §C9.2 append-only floor already
    applied this S_ISREG-no-follow rule at its own site; folding it into the
    shared chokepoint stops a sibling reader (BLOCK-01: the append-only
    attribution check) from re-opening what the floor refused to touch.

    Raises ``UnsafeBundlePath`` on violation; call sites collect it as a
    structured failure rather than propagating. Returns the resolved Path; the
    caller still surfaces a "file missing" outcome via the usual
    ``fpath.exists()`` check (this helper fail-closes only on path-escape and
    wrong object-type, NOT absence — a missing path passes through unchanged so
    tests that patch ``Path.exists`` for call-sequence assertions still hold).
    """
    bundle_root = bundle_dir.resolve()
    candidate = (bundle_dir / rel_path).resolve()
    try:
        candidate.relative_to(bundle_root)
    except ValueError as exc:
        raise UnsafeBundlePath(
            f"manifest path {rel_path!r} resolves outside bundle_dir "
            f"({candidate} not under {bundle_root})"
        ) from exc
    # No-follow object-type discipline on the FINAL component. Containment was
    # established above (resolve() follows EVERY component, so an intermediate
    # symlink that escaped the bundle was already rejected). lstat the
    # unresolved join so a final-component symlink is seen AS a symlink, not its
    # target. Absence is the caller's exists() concern — pass through unchanged.
    try:
        st = os.lstat(bundle_dir / rel_path)
    except (FileNotFoundError, NotADirectoryError):
        return candidate
    except OSError as exc:
        raise UnsafeBundlePath(
            f"manifest path {rel_path!r} could not be stat'd "
            f"({type(exc).__name__}: {exc})"
        ) from exc
    mode = st.st_mode
    if stat_module.S_ISDIR(mode):
        raise UnsafeBundlePath(
            f"manifest path {rel_path!r} resolves to a directory ({candidate}); "
            "every files/snapshots entry must point at a regular file"
        )
    if stat_module.S_ISLNK(mode):
        # An in-tree symlink. Containment (above, via resolve()) already proved
        # the target stays under bundle_dir — a symlink that ESCAPED the bundle
        # was rejected as path_escape and never reaches here. The strict-SHA
        # walk TOLERATES a contained symlink as-built because the dereferenced
        # bytes are SHA-pinned (test_declared_in_tree_symlink_keeps_as_built_
        # tolerance), so this shared chokepoint only requires the contained
        # target be a regular file. Surfaces that must not follow EVEN a
        # contained link (the append-only attribution read, which is not
        # SHA-pinned) layer O_NOFOLLOW on top of this helper.
        if candidate.is_file():
            return candidate
        raise UnsafeBundlePath(
            f"manifest path {rel_path!r} is a symlink to a non-regular object "
            f"({candidate}); a manifest-declared path must resolve to a "
            "regular file, never a directory or special file"
        )
    if not stat_module.S_ISREG(mode):
        raise UnsafeBundlePath(
            f"manifest path {rel_path!r} is a non-regular file ({candidate}); "
            "a FIFO, socket, or device would block or mislead a blocking read — "
            "every files/snapshots entry must point at a regular file"
        )
    return candidate


def open_regular_fd_nofollow(path: Path) -> int:
    """Open ``path`` read-only with no-follow + non-blocking semantics and a
    post-open regular-file recheck; return the fd (caller owns ``os.close``).

    This closes the TOCTOU window between ``_safe_bundle_path``'s ``lstat`` and
    the actual read. ``_safe_bundle_path`` classifies the object WITHOUT opening
    it (so it cannot hang), but a concurrent writer could swap a regular file
    for a FIFO/symlink between that stat and the read that follows. The three
    open-time guards here are atomic with the open:

      * ``O_NOFOLLOW`` — refuses a final-component symlink swapped in after the
        stat (raises ``ELOOP``).
      * ``O_NONBLOCK`` — opening a FIFO/socket with no writer returns
        immediately instead of blocking forever (regular files ignore it on
        read, so streaming/whole-file reads are unaffected).
      * ``fstat`` on the returned fd — rejects anything that is not a regular
        file (the FIFO/socket/device that ``O_NONBLOCK`` let us open without
        blocking).

    Raises ``OSError`` on any violation — callers already collect ``OSError``
    as a structured fail-closed outcome rather than propagating.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        if not stat_module.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(
                f"{path.name!r} is not a regular file at open time "
                "(TOCTOU swap to a FIFO/socket/device, or O_NOFOLLOW link); "
                "refusing to read"
            )
    except OSError:
        os.close(fd)
        raise
    return fd


def _validate_field_shapes(
    files: object, spec_files: object, cross_refs: object, typed_checks: object
) -> None:
    """Guard the container/value types the integrity walk dereferences.

    Single source of truth shared by BundleVerifier.verify's parse boundary
    (which passes raw-JSON values) and validate_manifest (which passes the
    constructed BundleManifest's fields). files/spec_files/cross_refs must be
    dict[str, str] (values reach .lower()); typed_checks must be list[str].
    None is accepted (absent field → dataclass default). Raises MalformedManifest.
    """
    for name, val in (
        ("files", files),
        ("spec_files", spec_files),
        ("cross_refs", cross_refs),
    ):
        if val is None:
            continue
        if not isinstance(val, dict):
            raise MalformedManifest(
                f"manifest.{name} must be an object, got {type(val).__name__}"
            )
        for k, v in val.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise MalformedManifest(
                    f"manifest.{name} must map str->str; offending entry "
                    f"{k!r} ({type(k).__name__}) -> {v!r} ({type(v).__name__})"
                )
    if typed_checks is not None:
        if not isinstance(typed_checks, list):
            raise MalformedManifest(
                f"manifest.typed_checks must be a list, got {type(typed_checks).__name__}"
            )
        for entry in typed_checks:
            if not isinstance(entry, str):
                raise MalformedManifest(
                    f"manifest.typed_checks entries must be str, got "
                    f"{type(entry).__name__}: {entry!r}"
                )


# ---------------------------------------------------------------------------
# Top-level field shape table — parse-boundary container-type contract.
#
# Every BundleManifest field, keyed by its manifest.json top-level key, mapped
# to the JSON container type its dataclass annotation declares (dict → JSON
# object, list → JSON array, str → JSON string). Enforced at the verifier's
# parse boundary (verifier._validate_manifest_shape) so that a PRESENT but
# wrong-shape field is a MalformedManifest REJECT, never silently read as
# absent. Before this table, a claim-bearing field whose consuming step
# isinstance-guards before reading — `extension_receipts` (a non-dict receipts
# value skipped receipt dispatch entirely) and `causal_chain` (a non-dict
# value disarmed the A1 cross-host fail-closed guard) — degraded present-but-
# malformed to "no claim", contradicting the present-but-unverified-never-
# silently-passed rule those steps document.
#
# Completeness is ratcheted: tests assert this table's keys equal the
# BundleManifest field set, so a new manifest field cannot ship without
# declaring its parse shape here. Per-field DEEP validation stays with its
# owner (_validate_field_shapes for str→str maps, §C9.1 for
# append_only_files, the v0.3 reservation rules for attested_serving /
# semantic_fidelity / rigor_profile, evaluate_extension_receipt for per-kind
# assemblies) — this table polices only the outermost container type.
# Top-level keys OUTSIDE the table (producer extras like signature_b64) are
# not policed here; that is the PoC1/PoC3 manifest-bytes class, tracked
# separately.
# ---------------------------------------------------------------------------

_TOP_LEVEL_FIELD_SHAPES: dict[str, type] = {
    "schema_version": str,
    "bundle_id": str,
    "created_at": str,
    "files": dict,
    "spec_files": dict,
    "cross_refs": dict,
    "payload": dict,
    "typed_checks": list,
    "snapshots": dict,
    "snapshot_policy": dict,
    "fragment_anchors": dict,
    "source_attributes": dict,
    "decision_provenance_log": str,
    "retrieval_trace_id": str,
    "retrieval_trace_log": str,
    "per_output_manifests": list,
    "output_mode_signal": dict,
    "dispatch_records": list,
    "append_only_files": list,
    "aggregate_stamp": str,
    "assurance_profile": str,
    "rigor_profile": dict,
    "attested_serving": dict,
    "verifier_identity": dict,
    "causal_chain": dict,
    "semantic_fidelity": dict,
    "extension_receipts": dict,
    "outputs": list,
}

_SHAPE_NAMES = {dict: "object", list: "array", str: "string"}


def validate_top_level_field_shapes(raw: dict) -> None:
    """Reject any KNOWN top-level manifest field present (non-null) with the
    wrong JSON container type.

    Raises MalformedManifest, which verify() collects as a VerifyFailure
    (REJECT) — present-but-malformed must never be indistinguishable from
    absent on the verdict path. JSON null is treated as absent, matching the
    dataclass-default semantics of a missing key. bool is an int subclass,
    not a dict/list/str subclass, so JSON true/false can never satisfy any
    shape in the table.
    """
    for name, shape in _TOP_LEVEL_FIELD_SHAPES.items():
        val = raw.get(name)
        if val is not None and not isinstance(val, shape):
            raise MalformedManifest(
                f"manifest.{name} must be a JSON {_SHAPE_NAMES[shape]} when "
                f"present, got {type(val).__name__} — a present-but-malformed "
                f"field is rejected, never treated as absent"
            )

    # The ONE causal_chain sub-key the core verdict path consumes
    # (_step_cross_host_guard): a present-but-non-array value would skip the
    # A1 cross-host fail-closed guard exactly like a malformed top level.
    # Other causal_chain sub-keys belong to their S19 owners and are not
    # policed here.
    cc = raw.get("causal_chain")
    if isinstance(cc, dict):
        edges = cc.get("cross_host_authenticators")
        if edges is not None and not isinstance(edges, list):
            raise MalformedManifest(
                f"manifest.causal_chain.cross_host_authenticators must be a "
                f"JSON array when present, got {type(edges).__name__} — a "
                f"malformed edge list must not disarm the cross-host guard"
            )


# ---------------------------------------------------------------------------
# v0.3 schema-reserved-block fail-closed parse-boundary check.
#
# The verifier loads `attested_serving` / `semantic_fidelity` / `rigor_profile`
# / `append_only_files` from manifest.json but has no v0.3 validator plugin for
# them. Without the rules below, a post-build editor can inject any content
# under these keys, the bundle still verifies GREEN, and downstream consumers
# that treat manifest.json as "verified" trust attacker-controlled bytes — a
# confused-deputy class. The rules below reject any content that does not match the canonical
# reservation shape the legitimate producers (eidas pilot, test_B2) mint, so
# the attack vector closes without breaking the v0.3 "verifier ignores
# semantics, but accepts the marker" contract.
#
# This is the NARROW fix. The broader manifest-bytes integrity gap (any inline
# top-level field loaded raw without byte-level coverage) is a separate class
# tracked by PoC1 (CID salting) and PoC3 (Merkle preimage extension); the
# class-wide fix needs threat-model design and is not addressed here.
# ---------------------------------------------------------------------------

_ATTESTED_SERVING_RESERVATION_ALLOWED_KEYS = frozenset({"mode", "reserved_for_v0_4"})
_ATTESTED_SERVING_RESERVATION_MODE = "attested-serving-environment"
_SEMANTIC_FIDELITY_RESERVATION_CANONICAL = {"reserved_for_v0_4": True}


def _validate_schema_reserved_blocks_v03(raw: dict) -> None:
    """Reject attacker-fabricated content under v0.3 schema-reserved keys.

    Per-field rules (each satisfied by the eidas pilot producer + the test_B2
    fixture; each rejects the PoC4 TARGET 4 attacker payload):

      attested_serving  — absent OR dict with `reserved_for_v0_4: True` and
                          allowed keys ⊆ {mode, reserved_for_v0_4}.
      semantic_fidelity — absent OR exactly {"reserved_for_v0_4": True}.
      rigor_profile     — must be absent at v0.3 (no v0.3 producer populates it).
      append_only_files — NOT validated here. Owned end-to-end by §C9.1:
                          `validate_append_only_files` enforces the closed
                          per-entry schema at the parse boundary (verifier
                          ._load_manifest, immediately after this call), and
                          `AppendOnlyAttributedCheck` enforces attribution
                          coverage at verify time. See the append_only_files
                          note below for why PoC4 no longer path-pins them.

    Raises MalformedManifest, which verify() collects as a VerifyFailure.
    """
    as_val = raw.get("attested_serving")
    if as_val is not None:
        bad_shape = (
            not isinstance(as_val, dict)
            or as_val.get("reserved_for_v0_4") is not True
            or bool(set(as_val.keys()) - _ATTESTED_SERVING_RESERVATION_ALLOWED_KEYS)
            or (
                "mode" in as_val
                and as_val["mode"] != _ATTESTED_SERVING_RESERVATION_MODE
            )
        )
        if bad_shape:
            shape = (
                sorted(as_val.keys(), key=repr)
                if isinstance(as_val, dict)
                else type(as_val).__name__
            )
            raise MalformedManifest(
                f"SCHEMA_RESERVED_NONCONFORMANT: attested_serving must be absent "
                f"or a reservation marker with reserved_for_v0_4=True at v0.3 "
                f"(allowed keys ⊆ {sorted(_ATTESTED_SERVING_RESERVATION_ALLOWED_KEYS)}; "
                f"if mode present, must equal {_ATTESTED_SERVING_RESERVATION_MODE!r}); "
                f"got {shape!r}"
            )

    sf_val = raw.get("semantic_fidelity")
    if sf_val is not None and sf_val != _SEMANTIC_FIDELITY_RESERVATION_CANONICAL:
        raise MalformedManifest(
            f"SCHEMA_RESERVED_NONCONFORMANT: semantic_fidelity must be absent "
            f"or exactly {_SEMANTIC_FIDELITY_RESERVATION_CANONICAL!r} at v0.3; "
            f"got {sf_val!r}"
        )

    rp_val = raw.get("rigor_profile")
    if rp_val is not None:
        raise MalformedManifest(
            "SCHEMA_RESERVED_NONCONFORMANT: rigor_profile must be absent at v0.3 "
            "(no validating plugin at this version; populating ships with the "
            "v0.4 verifier upgrade)"
        )

    # append_only_files — intentionally NOT validated here.
    #
    # PoC4's original rule required every append_only_files[].path to be a key
    # in manifest.files, "binding the declaration to the per-file SHA integrity
    # envelope." That rule was correct ONLY under the v0.3 posture where the
    # verifier ignored append_only_files and strict-SHA'd everything. The §C9.1
    # v0.4 machinery has since landed (sc9_1-003/004/005): the verifier now
    #   (a) populates append_only_files and runs `validate_append_only_files`
    #       (closed per-entry schema) at the parse boundary, AND
    #   (b) SKIPS declared paths from §C9 strict-SHA and instead runs
    #       `AppendOnlyAttributedCheck` (attribution-key coverage) for them.
    # Because (b) skips strict-SHA for declared paths REGARDLESS of files{}
    # membership, the old path-pinning rule only ever recorded a never-enforced,
    # immediately-stale SHA — the very dual-pin tension §C9.1 was built to close
    # (extension docstring step (d): declare "instead of pinning their SHA").
    # PoC4's confused-deputy guarantee survives without it: a fabricated entry
    # fails the closed schema (a), and a non-attributed file fails attribution
    # (b) — neither can verify GREEN. Validation now has a single owner (§C9.1),
    # eliminating the v0.3/v0.4 contradiction that made the mesh pilot (the only
    # append_only_files pilot) fail-closed. The other three reserved blocks above
    # have NO other validator, so PoC4 still owns them.


def validate_manifest(m: BundleManifest, bundle_dir: Path) -> None:
    """Validate a BundleManifest against on-disk bundle contents.

    Checks run in order; raises the first failure encountered within each
    category:
      0. MalformedManifest    — files/spec_files/cross_refs/typed_checks wrong type
      1. SchemaVersionError   — unrecognized schema_version
      2. FileSHAMismatch      — missing file or hash mismatch in m.files
      3. SpecSHAMissing       — empty SHA value in m.spec_files
      4. CrossRefBroken       — m.cross_refs target not in files or spec_files
      5. TypedCheckUnregistered — m.typed_checks name not in registry
    """
    # 0. Field shapes — guard the types the walk dereferences before any .items()
    #    / .lower() call can raise an uncaught AttributeError (fuzzing round 2).
    _validate_field_shapes(m.files, m.spec_files, m.cross_refs, m.typed_checks)

    # 1. schema_version — shared allowlist gate (also enforced at the verifier's
    #    raw-parse boundary; see validate_schema_version's docstring)
    validate_schema_version(m.schema_version)

    # 2. File SHA integrity
    for rel_path, expected_sha in m.files.items():
        # _safe_bundle_path fail-closes on path-escape and non-file targets;
        # propagates UnsafeBundlePath, which is a ManifestError sibling caught
        # by veriker/cli/verify.py's handler.
        fpath = _safe_bundle_path(bundle_dir, rel_path)
        if not fpath.exists():
            raise FileSHAMismatch(
                f"file {rel_path!r} listed in manifest.files is missing from bundle_dir"
            )
        computed = _sha256_file(fpath)
        if computed.lower() != expected_sha.lower():
            raise FileSHAMismatch(
                f"SHA mismatch for {rel_path!r}: "
                f"manifest={expected_sha!r} computed={computed!r}"
            )

    # 3. spec_files — every entry must carry a non-empty SHA
    for spec_path, spec_sha in m.spec_files.items():
        if not spec_sha:
            raise SpecSHAMissing(f"spec_files entry {spec_path!r} has no SHA recorded")

    # 4. cross_refs — target must resolve in files or spec_files
    for logical_name, target in m.cross_refs.items():
        if target not in m.files and target not in m.spec_files:
            raise CrossRefBroken(
                f"cross_refs[{logical_name!r}] = {target!r} does not resolve "
                "to any key in manifest.files or manifest.spec_files"
            )

    # 5. typed_checks — each name must be in the registry
    for check_name in m.typed_checks:
        if check_name not in _TYPED_CHECK_REGISTRY:
            raise TypedCheckUnregistered(
                f"typed_check {check_name!r} is not registered; "
                f"registered: {sorted(_TYPED_CHECK_REGISTRY)}"
            )

    # 6-20: the DEEP validators (snapshots, fragment anchors, source attributes,
    # retrieval traces, per-output manifests, output-mode, OF1 header). Factored out so
    # the BundleVerifier can run JUST these — the checks its shallow 4-step walk does NOT
    # cover — for library consumers of verify() (ADR D5: verify() complete-by-construction).
    _validate_manifest_deep(m, bundle_dir)


def _validate_manifest_deep(
    m: BundleManifest, bundle_dir: Path, *, include_of1_header: bool = True
) -> None:
    """The DEEP manifest validators — steps 6-20 of the original validate_manifest.

    `include_of1_header` gates step 20 (the OF1 manifest-header leaf recompute). Both this
    generic step-20 path AND the `of1_manifest_header_re_derivation` plugin now compute the
    SAME canonical leaf via `compute_manifest_header_leaf_from_manifest` (folding the
    declared `assurance_profile` + `schema_version` when present) — so the verifier can run
    OF1 generically AND via the plugin and they agree by construction. The knob is retained
    for callers that want deep-validation without re-running OF1, but the historical reason
    for defaulting it off in the verifier (the bare-vs-folded divergence) is GONE. The
    verifier unifies on the folded convention: the older bare generic path is retired; the
    only bare-leaf producers were test/redteam/fuzz harnesses that do not run the generic
    validator.

    Each check is presence-gated (a no-op when its manifest field is empty/absent), so
    running this for a bundle that declares none of these fields does nothing. Raises the
    first failure encountered (the ManifestError / BadFragmentID / BadOutputMode /
    ThreeSetMismatch / BadVisibilityPolicy / BadPublicationClass family — see
    `deep_validation_failure` for the catch). Invoked by BOTH `validate_manifest`
    (full shallow + deep, e.g. the CLI fast-path) and the verifier's deep step (deep-only,
    so the shallow checks the 4-step walk already runs are not duplicated)."""
    # 6. Snapshots must carry a policy when non-empty
    if m.snapshots and m.snapshot_policy is None:
        raise SnapshotPolicyMissing(
            "snapshots is non-empty but snapshot_policy is None"
        )

    # 7. Snapshot CID integrity — recompute each CID from the on-disk file
    for cid_string, rel_path in m.snapshots.items():
        # Same path-safety guard as #2 — snapshot paths are equally adversarial.
        spath = _safe_bundle_path(bundle_dir, rel_path)
        if not spath.exists():
            raise SnapshotCIDMismatch(
                f"snapshot path {rel_path!r} for CID {cid_string!r} is missing from bundle_dir"
            )
        computed = compute_cid(spath.read_bytes())
        if computed != cid_string:
            raise SnapshotCIDMismatch(
                f"CID mismatch for snapshot {rel_path!r}: "
                f"manifest={cid_string!r} computed={computed!r}"
            )

    # 8. Snapshot policy drift — verify any JSONL ingest records in m.files
    #    agree with the SHA256 of snapshot_policy
    if m.snapshot_policy is not None:
        expected_policy_sha = hashlib.sha256(
            json.dumps(
                m.snapshot_policy,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        for rel_path in m.files:
            if not rel_path.endswith(".jsonl"):
                continue
            # Same path-safety guard as step #2 — m.files keys may be adversarial
            # even when filtered to .jsonl extension.
            fpath = _safe_bundle_path(bundle_dir, rel_path)
            if not fpath.exists():
                continue
            # RES-02: tolerant admission-bounded scan. Per-line depth bombs used
            # to RecursionError out of json.loads (the old except tuple never
            # caught it); an OVERSIZE file fails CLOSED as SnapshotCIDMismatch —
            # skipping it would let a producer hide exactly the poisoned policy
            # stamp this scan exists to find.
            try:
                admitted_rows = list(iter_admitted_jsonl_tolerant(fpath))
            except InputInadmissible as exc:
                raise SnapshotCIDMismatch(
                    f"policy-stamp scan: {rel_path!r} breached input admission: {exc}"
                ) from exc
            for record in admitted_rows:
                record_sha = record.get("policy_dict_sha256")
                if record_sha is not None and record_sha != expected_policy_sha:
                    raise SnapshotPolicyDriftError(
                        f"snapshot_policy SHA256 {expected_policy_sha!r} does not match "
                        f"policy_dict_sha256 {record_sha!r} in ingest record in {rel_path!r}"
                    )

    # 9. Fragment anchors — each dict must parse as a valid FragmentID
    for anchor_name, fragment_dict in m.fragment_anchors.items():
        try:
            fragment = fragment_from_dict(fragment_dict)
        except BadFragmentID as exc:
            raise BadFragmentID(
                f"fragment_anchors[{anchor_name!r}] is malformed: {exc}"
            ) from exc

        # 10. If source_cid is declared in snapshots, verify the snapshot file is present
        if fragment.source_cid in m.snapshots:
            snap_path = _safe_bundle_path(bundle_dir, m.snapshots[fragment.source_cid])
            if not snap_path.exists():
                raise FragmentSourceUnreachable(
                    f"fragment_anchors[{anchor_name!r}] references source_cid={fragment.source_cid!r} "
                    f"declared in snapshots at {m.snapshots[fragment.source_cid]!r} "
                    f"but the file is missing from bundle_dir"
                )

    # 11. source_attributes — enforce the SAME five consistency invariants the
    #     SourceAttributesConsistencyCheck plugin enforces, but in CORE deep
    #     validation so a LIBRARY `BundleVerifier()` consumer (which does NOT
    #     wire that plugin by default — only veriker/cli/verify.py does) can no longer
    #     read VerdictState.OK over an unverified four-axis source-properties
    #     trust claim. Invariants 2-5 are pure deterministic structural/
    #     consistency checks (no keys, no crypto, no pinned material), so they
    #     live here as REJECTs exactly the way invariant 1 (orphan) already did
    #     — the plugin becomes redundant-but-agreeing (like OF1), not a divergent
    #     second decider. Order mirrors the plugin: malformed → orphan →
    #     publication_class → signed-key → issuer-identifier. Invariant 3
    #     (replay-completeness) needs the provenance log and so rides with
    #     step 12 below.
    for source_cid, props_dict in m.source_attributes.items():
        # Invariant 0 (fail-closed type guard) — source_attributes values are
        # bundle-controlled and not type-validated at parse; a non-dict value
        # would raise AttributeError on the .get() calls below and degrade the
        # run to a VERIFIER crash instead of a recorded REJECT.
        if not isinstance(props_dict, dict):
            raise SourceAttributesMalformed(
                f"source_attributes[{source_cid!r}] must be a JSON object, "
                f"got {type(props_dict).__name__!r}"
            )

        # Invariant 1 (orphan) — source_cid must have a snapshot.
        if source_cid not in m.snapshots:
            raise SourceAttributesOrphan(
                f"source_attributes key {source_cid!r} has no corresponding snapshot in the bundle"
            )

        # Invariant 2 (publication_class) — must be in the v1 enum.
        pub_class = props_dict.get("publication_class", "")
        validate_publication_class(pub_class)

        # Invariant 4 — signed_artifact_present=True requires a non-null signing_key_id.
        if props_dict.get("signed_artifact_present") is True and not props_dict.get(
            "signing_key_id"
        ):
            raise SignedArtifactKeyMissing(
                f"source_attributes[{source_cid!r}]: signed_artifact_present=True "
                "but signing_key_id is null or absent"
            )

        # Invariant 5 — issuer_identity_verified=True requires a non-null issuer_identifier.
        if props_dict.get("issuer_identity_verified") is True and not props_dict.get(
            "issuer_identifier"
        ):
            raise IssuerIdentifierMissing(
                f"source_attributes[{source_cid!r}]: issuer_identity_verified=True "
                "but issuer_identifier is null or absent"
            )

    # 12. decision_provenance_log — if set, the path must exist relative to bundle_dir,
    #     AND (invariant 3, replay-completeness) every annotated source_cid must have at
    #     least one DecisionProvenance record in the log. This is the core counterpart of
    #     the SourceAttributesConsistencyCheck plugin's invariant 3 — moved here so a bare
    #     BundleVerifier() can no longer read OK over a source whose decision history is
    #     simply absent from the declared replay log. _safe_bundle_path keeps the same
    #     containment discipline the plugin uses (it raises UnsafeBundlePath — itself a
    #     ManifestError — on path-escape, a REJECT). The log content is bundle-controlled,
    #     so the read fails CLOSED (BadDecisionProvenanceLog) on an unreadable/malformed
    #     file or an admission breach rather than escaping as a verifier crash.
    if m.decision_provenance_log is not None:
        prov_path = _safe_bundle_path(bundle_dir, m.decision_provenance_log)
        if not prov_path.exists():
            raise BadDecisionProvenanceLog(
                f"decision_provenance_log {m.decision_provenance_log!r} does not exist in bundle_dir"
            )
        if m.source_attributes:
            seen_cids: set[str] = set()
            try:
                for prov in read_decisions(prov_path):
                    seen_cids.add(prov.source_cid)
            except (
                OSError,
                UnicodeDecodeError,
                json.JSONDecodeError,
                KeyError,
                TypeError,
                # read_decisions is admission-bounded (RES-11 reader leg):
                # size/depth/cardinality breaches and malformed lines arrive as
                # InputInadmissible — the same structured reject lane, never an escape.
                InputInadmissible,
            ) as exc:
                raise BadDecisionProvenanceLog(
                    f"decision_provenance_log {m.decision_provenance_log!r} could not be "
                    f"read or parsed: {type(exc).__name__}: {exc}"
                ) from exc
            for source_cid in m.source_attributes:
                if source_cid not in seen_cids:
                    raise SourceProvenanceIncomplete(
                        f"source_cid {source_cid!r} has no DecisionProvenance record "
                        f"in {m.decision_provenance_log!r}"
                    )

    # 13. retrieval_trace_id set → retrieval_trace_log must also be set
    if m.retrieval_trace_id is not None and m.retrieval_trace_log is None:
        raise MissingRetrievalTraceLog(
            f"retrieval_trace_id {m.retrieval_trace_id!r} is set but retrieval_trace_log is None"
        )

    # 14. retrieval_trace_log set → file must exist AND load_trace must succeed
    _loaded_trace = None
    if m.retrieval_trace_log is not None:
        trace_log_path = _safe_bundle_path(bundle_dir, m.retrieval_trace_log)
        if not trace_log_path.exists():
            raise BadRetrievalTraceLog(
                f"retrieval_trace_log {m.retrieval_trace_log!r} does not exist in bundle_dir"
            )
        try:
            _loaded_trace = load_trace(trace_log_path, m.retrieval_trace_id)
        # load_trace normalises every malformed-content failure on the
        # bundle-supplied log to ValueError (RetrievalTraceError) or
        # TraceNotFound; OSError covers unreadable files. Anything else is
        # a verifier bug and must crash, not turn into a REJECT verdict.
        except (TraceNotFound, ValueError, OSError) as exc:
            raise BadRetrievalTraceLog(
                f"load_trace failed for retrieval_trace_log {m.retrieval_trace_log!r} "
                f"with trace_id {m.retrieval_trace_id!r}: {exc}"
            ) from exc

    # 15. retrieval_trace_id set AND snapshots non-empty → orphan check
    #     every candidate_set CID that is annotated in source_attributes must be in snapshots
    if m.retrieval_trace_id is not None and m.snapshots and _loaded_trace is not None:
        orphaned = [
            cid
            for cid in _loaded_trace.candidate_set
            if cid in m.source_attributes and cid not in m.snapshots
        ]
        if orphaned:
            raise RetrievalTraceOrphan(
                f"candidate_set CIDs annotated in source_attributes but missing from snapshots: "
                f"{sorted(orphaned)}"
            )

    # 16. per_output_manifests — validate each entry against the parent manifest
    for entry in m.per_output_manifests:
        try:
            pom = PerOutputManifest(
                output_id=entry["output_id"],
                trace_id=entry["trace_id"],
                three_set=entry["three_set"],
                visibility_policy=entry["visibility_policy"],
                emitted_at=entry["emitted_at"],
            )
        except (KeyError, TypeError) as exc:
            output_id = (
                entry.get("output_id", "<unknown>")
                if isinstance(entry, dict)
                else "<unknown>"
            )
            raise ManifestError(
                f"per_output_manifests entry output_id={output_id!r} is malformed: {exc}"
            ) from exc
        validate_per_output_manifest(pom, m, bundle_dir)

    # 17. output_mode_signal — required when per_output_manifests is non-empty
    if m.per_output_manifests and m.output_mode_signal is None:
        raise OutputModeMissingForOutputBundle(
            "per_output_manifests is non-empty but output_mode_signal is None"
        )

    # 18. output_mode_signal — must parse cleanly via mode_from_dict
    _parsed_mode = None
    if m.output_mode_signal is not None:
        _parsed_mode = mode_from_dict(
            m.output_mode_signal
        )  # raises BadOutputMode on failure

    # 19. VE-mode constraint: every per_output_manifest must have non-empty quote_supporting
    if _parsed_mode is not None and _parsed_mode.mode is OutputMode.VE:
        for entry in m.per_output_manifests:
            output_id = (
                entry.get("output_id", "<unknown>")
                if isinstance(entry, dict)
                else "<unknown>"
            )
            three_set = entry.get("three_set", {}) if isinstance(entry, dict) else {}
            if not three_set.get("quote_supporting"):
                raise VEModeRequiresQuoteSupport(
                    f"VE-mode bundle requires non-empty quote_supporting for each output; "
                    f"output_id={output_id!r} has no quote_supporting sources"
                )

    # 20. OF1 (v0_3_of1) — manifest header integrity. When the optional
    # `manifest_header_merkle_leaf` field is present at `causal_chain.layer_a`, the
    # stored leaf MUST equal the CANONICAL leaf recomputed from `manifest.bundle_id` +
    # `manifest.created_at` + `manifest.dispatch_records`, FOLDING the declared
    # `manifest.assurance_profile` (CC-2b D1) and `manifest.schema_version` (G4) when
    # present. Closes the C14 defense-7 honest-sealer trust assumption gap (a hostile
    # sealer with the V14 HMAC key cannot shift `created_at` — or substitute the
    # declared profile / manifest-format version — without breaking this binding).
    # Bundles without the field continue to verify under the legacy honest-sealer
    # caveat — the OF1 fix is opt-in via field presence.
    #
    # This generic path and the `of1_manifest_header_re_derivation` plugin compute the
    # SAME canonical leaf via the single `compute_manifest_header_leaf_from_manifest`
    # helper — the two divergent covered-field conventions (bare vs G4-folded) are
    # unified. `include_of1_header`
    # remains as a knob, but the BundleVerifier now runs OF1 generically too (it no longer
    # defers to the plugin) since both paths agree by construction.
    if include_of1_header and isinstance(m.causal_chain, dict):
        _layer_a = m.causal_chain.get("layer_a")
        if isinstance(_layer_a, dict):
            _stored_leaf_hex = _layer_a.get("manifest_header_merkle_leaf")
            if _stored_leaf_hex is not None:
                # Local import to avoid a module-level cycle —
                # audit_bundle.extensions.c19.layer_a_counter imports from this
                # module (CausalChainLayerASchemaError + validate_*); we want
                # to invoke its canonical-leaf helper here.
                from audit_bundle.extensions.c19.layer_a_counter import (
                    compute_manifest_header_leaf_from_manifest,
                )

                _expected_leaf = compute_manifest_header_leaf_from_manifest(
                    bundle_id=m.bundle_id,
                    created_at=m.created_at,
                    dispatch_records=m.dispatch_records,
                    assurance_profile=m.assurance_profile,
                    schema_version=m.schema_version,
                )
                if not isinstance(_stored_leaf_hex, str) or (
                    _expected_leaf.hex() != _stored_leaf_hex.lower()
                ):
                    raise ManifestHeaderLeafMismatch(
                        "causal_chain.layer_a.manifest_header_merkle_leaf "
                        f"={_stored_leaf_hex!r} does not match the canonical leaf "
                        f"recomputed from manifest.bundle_id + "
                        f"manifest.created_at + manifest.dispatch_records "
                        f"(+ folded assurance_profile/schema_version when declared) "
                        f"(expected {_expected_leaf.hex()!r})"
                    )


# The exception family the deep validators raise for an artifact-bad manifest. Mirrors
# veriker/cli/verify.py's manifest-validation handler exactly. UnsafeBundlePath is a ManifestError
# subclass (covered by the first arm). Anything OUTSIDE this tuple is NOT an artifact
# property — it propagates so the verifier's fail_closed boundary classifies it as a
# crash-ERROR (VERIFIER_*), never a REJECT.
_DEEP_VALIDATION_REJECTS: tuple[type[Exception], ...] = (
    ManifestError,
    BadFragmentID,
    BadOutputMode,
    ThreeSetMismatch,
    BadVisibilityPolicy,
    BadPublicationClass,
)


def deep_validation_failure(
    m: BundleManifest, bundle_dir: Path, *, skip_of1_header: bool = False
) -> tuple[str, str] | None:
    """Run the DEEP manifest validators and report the first artifact-bad finding as a
    `(reason_code, detail)` pair (reason_code = the exception class name, matching the
    CLI's `[ExcClass]` label), or None when every deep check passes / is inapplicable.

    This is the seam the BundleVerifier uses to become complete-by-construction (ADR D5):
    `verify()` calls it so a LIBRARY consumer of `verify()` gets the same deep coverage
    the CLI fast-path had. Non-manifest exceptions are NOT swallowed — they propagate to
    the verifier's `fail_closed` boundary as a crash-ERROR (the INPUT-vs-VERIFIER seam).

    `skip_of1_header=True` (the verifier's setting) defers the OF1 manifest-header leaf
    check to the dedicated `of1_manifest_header_re_derivation` plugin that `verify()`
    already runs — see `_validate_manifest_deep`'s `include_of1_header`."""
    try:
        _validate_manifest_deep(m, bundle_dir, include_of1_header=not skip_of1_header)
    except _DEEP_VALIDATION_REJECTS as exc:
        return (type(exc).__name__, str(exc))
    return None


# ---------------------------------------------------------------------------
# C19 Layer A — causal_chain['layer_a'] sub-key structural validator (S19a)
# ---------------------------------------------------------------------------
# Helper validates the discriminated-union sub-key shape only. Cryptographic
# verification (SCITT receipt verify, HMAC event-signature verify, Merkle root
# recompute) lives in audit_bundle.extensions.c19.layer_a_counter.
# `verify_bundle_layer_a`. Bundles with `causal_chain == None` continue to
# verify cleanly (backward-compat invariant).


_LAYER_A_ASSURANCE_PROFILES: frozenset[str] = frozenset(
    {"offline-auditor-minimal", "production-standard", "regulated-high-assurance"}
)

_LAYER_A_REQUIRED_KEYS: frozenset[str] = frozenset(
    {
        "event_dag_merkle_root",
        "chain_height",
        "scitt_log_id",
        "assurance_profile",
        "events",
        "protocol_version",
    }
)

_LAYER_A_EVENT_REQUIRED_KEYS: frozenset[str] = frozenset(
    {
        "event_id",
        "prev_event_id",
        "prev_event_hash",
        "monotonic_counter",
        "counter_log_index",
        "scitt_statement_id",
        "scitt_statement_content_sha256",
        "scitt_inclusion_proof",
        "event_kind",
        "payload_hash",
        "event_signature",
    }
)


def _is_hex_64(s: object) -> bool:
    return (
        isinstance(s, str)
        and len(s) == 64
        and all(c in "0123456789abcdefABCDEF" for c in s)
    )


def validate_causal_chain_layer_a_shape(layer_a: dict) -> None:
    """Structural shape validator for `causal_chain['layer_a']` (S19a contract).

    Raises a ManifestError subclass on violation. Does NOT recompute hashes,
    signatures, or receipts — that lives in
    audit_bundle.extensions.c19.layer_a_counter.verify_bundle_layer_a.
    """
    if not isinstance(layer_a, dict):
        raise CausalChainLayerASchemaError(
            f"causal_chain['layer_a'] must be a dict; got {type(layer_a).__name__}"
        )
    missing = _LAYER_A_REQUIRED_KEYS - set(layer_a.keys())
    if missing:
        raise CausalChainLayerASchemaError(
            f"causal_chain['layer_a'] missing required keys: {sorted(missing)}"
        )
    if not _is_hex_64(layer_a["event_dag_merkle_root"]):
        raise CausalChainLayerASchemaError(
            "event_dag_merkle_root must be 64-char hex sha256"
        )
    chain_height = layer_a["chain_height"]
    if not isinstance(chain_height, int) or chain_height < 0:
        raise CausalChainLayerASchemaError("chain_height must be int >= 0")
    if not isinstance(layer_a["scitt_log_id"], str) or not layer_a["scitt_log_id"]:
        raise CausalChainLayerASchemaError("scitt_log_id must be a non-empty string")
    if layer_a["assurance_profile"] not in _LAYER_A_ASSURANCE_PROFILES:
        raise CausalChainLayerASchemaError(
            f"assurance_profile must be one of {sorted(_LAYER_A_ASSURANCE_PROFILES)}"
        )
    if layer_a["protocol_version"] != "v0.3":
        raise CausalChainLayerASchemaError("protocol_version must equal 'v0.3'")
    events = layer_a["events"]
    if not isinstance(events, list):
        raise CausalChainLayerASchemaError("events must be a list")
    if len(events) != chain_height:
        raise CausalChainLayerAChainHeightMismatch(
            f"len(events)={len(events)} != chain_height={chain_height}"
        )
    for idx, ev in enumerate(events):
        if not isinstance(ev, dict):
            raise CausalChainLayerASchemaError(f"events[{idx}] must be dict")
        ev_missing = _LAYER_A_EVENT_REQUIRED_KEYS - set(ev.keys())
        if ev_missing:
            raise CausalChainLayerASchemaError(
                f"events[{idx}] missing required keys: {sorted(ev_missing)}"
            )
        if ev["event_kind"] not in V0_3_EVENT_KINDS:
            raise CausalChainLayerAEventKindUnknown(
                f"events[{idx}].event_kind={ev['event_kind']!r} not in V0_3_EVENT_KINDS"
            )
        if not isinstance(ev["monotonic_counter"], int) or ev["monotonic_counter"] < 1:
            raise CausalChainLayerASchemaError(
                f"events[{idx}].monotonic_counter must be int >= 1"
            )
        if ev["counter_log_index"] != ev["monotonic_counter"]:
            raise CausalChainLayerASchemaError(
                f"events[{idx}].counter_log_index must equal monotonic_counter"
            )
        for hex_field in (
            "prev_event_hash",
            "payload_hash",
            "scitt_statement_content_sha256",
        ):
            if not _is_hex_64(ev[hex_field]):
                raise CausalChainLayerASchemaError(
                    f"events[{idx}].{hex_field} must be 64-char hex sha256"
                )
        sig = ev["event_signature"]
        if not isinstance(sig, dict) or "key_id" not in sig or "sig" not in sig:
            raise CausalChainLayerASchemaError(
                f"events[{idx}].event_signature must be dict with key_id + sig"
            )
