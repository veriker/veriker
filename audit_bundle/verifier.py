"""audit_bundle/verifier.py — generic 4-step bundle integrity walk + plugin slots.

Follows the audit-bundle contract §C9 pattern: many small independent checks, one specific
exception type per step category, no catch-all.  Step order:
  1. file_integrity     — SHA-256 of every manifest.files entry
  2. spec_sha_pinning   — SHA-256 of every manifest.spec_files entry
  3. cross_refs         — every manifest.cross_refs target is reachable
  4. typed_check_plugins — each plugin in self.plugins runs and passes
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass, fields, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Sequence

from .bundle_manifest import (
    BundleManifest,
    MalformedManifest,
    SchemaVersionError,
    UnsafeBundlePath,
    _safe_bundle_path,
    open_regular_fd_nofollow,
    _validate_field_shapes,
    _validate_schema_reserved_blocks_v03,
    validate_top_level_field_shapes,
    validate_schema_version,
    deep_freeze,
    deep_validation_failure,
    evaluate_extension_receipt,
    registered_receipt_verifiers,
    is_post_cutover,
)
from .admission import admit_bytes
from .append_only_floor import check_append_only_floor, validate_min_class_policy
from .conservation import run_conservation, validate_fs_ignore_patterns
from .cross_host_identity import cross_host_edge_keys
from .causal_chain_coverage import (
    accountable_causal_chain_keys,
    layer_a_event_obligation_keys,
)
from .fragments.attestable import attestable_anchor_keys
from .stamp_claims import dispatch_record_key, stamp_claim_key
from .output_modes.mode import OutputMode
from .contract_slots import post_binding_schema_checks
from .extensions.c18_verifier_identity import verify_verifier_identity_structural
from .extensions.c19.profile_completeness_policy import (
    PROFILE_DECLARATION_CONFLICT,
    PROFILE_DECLARED_BUT_UNGRADED,
    PROFILE_DECLARED_UNKNOWN,
    PROFILE_REQUIRED_STRUCTURE_ABSENT,
    STRUCTURE_PATHS as _PROFILE_STRUCTURE_PATHS,
    STRUCTURE_WALK_ORDER as _PROFILE_STRUCTURE_WALK_ORDER,
    ObligationLattice,
    builtin_profile_lattice,
    policy_fingerprint,
    effective_declared_profile,
    resolve_effective_profile,
)
from .extensions.c9_1_append_only_files import (
    AppendOnlyAttributedCheck,
    validate_append_only_files,
)
from .git_blob_resolver import BlobNotFound, resolve_blob_at_sha
from .integrity_ownership import ENVELOPE_PATHS, OwnerKind, classify_path
from .snapshot import (
    SnapshotMaterializationError,
    SnapshotNonQuiescent,
    SnapshotUnsupportedNode,
    sealed_snapshot,
)
from .verdict import (
    VERIFIER_INCOMPLETE,
    VERIFIER_UNEXPECTED_PLUGIN_EXCEPTION,
    Completeness,
    Verdict,
    VerifierError,
    compose,
    fail_closed,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from typing import Protocol

    from .revocation import RevocationList

    class DsseVerifyContext(Protocol):
        """Structural view of the caller-injected DSSE verification context.

        The concrete type lives in ``audit_bundle.orchestrator_turn`` (a
        cross-pillar package that is NOT on this stdlib-only core verify()
        path, and is EXCLUDED from the open drop per
        ``OSS_RELEASE_BOUNDARY.md`` — open-drop callers construct their own
        object with these fields). The core only READS these fields, so it
        depends on the shape, not the import — keeping the core self-typing
        without a hard reference to a package the core does not ship
        alongside.
        """

        allowlist: Mapping[str, bytes]
        verifier_now: int
        revocation_list: RevocationList | None
        require_dsse: bool
        allow_legacy: bool


# ---------------------------------------------------------------------------
# Exception hierarchy — one type per check category (§C9 no-catch-all contract)
# ---------------------------------------------------------------------------


class BadFileSHA(Exception):
    """File is missing from bundle or its SHA-256 does not match the manifest."""


class MissingSpecBlob(Exception):
    """Spec file could not be resolved: offline copy absent or SHA mismatch."""


class BrokenCrossRef(Exception):
    """A cross_refs target does not resolve to any reachable file or spec key."""


class PluginFailed(Exception):
    """A TypedCheck plugin reported a failure."""


# ---------------------------------------------------------------------------
# VerifyFailure / VerifyResult
# ---------------------------------------------------------------------------
#
# VerifyFailure stays as the per-step reason carrier (still appended into the
# `failures` list by every step). VerifyResult is now an ALIAS for the canonical
# tri-state Verdict (ADR D1): verify() returns a Verdict whose back-compat .ok /
# .failures faces keep every existing consumer (and `isinstance(r, VerifyResult)`)
# working, while .state now distinguishes a REJECT (artifact bad) from an ERROR
# (verifier could not conclude).


@dataclass(slots=True)
class VerifyFailure:
    check_name: str
    reason_code: str
    detail: str


VerifyResult = Verdict


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _discover_repo_root(start: Path) -> Path | None:
    """Walk up from start looking for a .git entry (directory or file)."""
    for candidate in [start.resolve(), *start.resolve().parents]:
        if (candidate / ".git").exists():
            return candidate
    return None


def _validate_manifest_shape(raw: Any) -> None:
    """Guard the parse boundary: manifest.json must be a JSON object whose
    walk-dereferenced fields carry the right types.

    Top-level-object check is verifier-specific (raw JSON may be any JSON value);
    the per-field checks delegate to bundle_manifest._validate_field_shapes so
    this path and validate_manifest() share one definition and cannot drift.
    Raises MalformedManifest, which verify() collects as a VerifyFailure.
    """
    if not isinstance(raw, dict):
        raise MalformedManifest(
            f"manifest.json must be a JSON object, got {type(raw).__name__}"
        )
    # Container-type contract for EVERY BundleManifest field (completeness
    # ratcheted against the dataclass): a present-but-wrong-shape field is a
    # REJECT here, never degraded to "absent" by a downstream isinstance
    # guard (extension_receipts / causal_chain were the live instances).
    validate_top_level_field_shapes(raw)
    _validate_field_shapes(
        raw.get("files"),
        raw.get("spec_files"),
        raw.get("cross_refs"),
        raw.get("typed_checks"),
    )
    _validate_schema_reserved_blocks_v03(raw)
    # schema_version allowlist — the same defaulted value the BundleManifest
    # constructor below will carry (absent ⇒ "legacy", matching
    # validate_manifest's semantics on the constructed dataclass). BLOCK-03:
    # this gate lived only in validate_manifest's shallow step 1, which the
    # ef9a197 refactor moved the CLI off of — unknown schema versions verified
    # green AND rode the pre-cutover lane (is_post_cutover is total: unknown
    # ⇒ False). Enforced here so EVERY verifier entry point rejects an
    # unknown contract version before any check runs.
    validate_schema_version(raw.get("schema_version", "legacy"))


def _load_manifest(bundle_dir: Path) -> BundleManifest:
    """Deserialize manifest.json from bundle_dir into a BundleManifest.

    Every BundleManifest field is propagated from the on-disk JSON so that
    validate_manifest() observes the same shape the bundle actually carries.

    Raises MalformedManifest if manifest.json is absent, not valid JSON, or
    carries a field whose type the integrity walk cannot dereference safely.
    """
    manifest_path = bundle_dir / "manifest.json"
    if not manifest_path.exists():
        raise MalformedManifest(f"manifest.json not found in {bundle_dir}")
    return _parse_manifest(manifest_path.read_bytes(), bundle_dir)


def _parse_manifest(raw_bytes: bytes, bundle_dir: Path) -> BundleManifest:
    """Parse manifest BYTES into a BundleManifest (the body of _load_manifest).

    Split from _load_manifest so verify() can parse the SAME byte snapshot it
    admission-bounded and (when the DSSE gate is active) binding-checked —
    manifest.json is read exactly once per verify() call. A re-read between
    the gate and the parse is a TOCTOU window: under flaky storage or a
    post-gate swap, later steps would consume bytes the gate never bound.
    """
    try:
        raw: Any = json.loads(raw_bytes)
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as exc:
        raise MalformedManifest(f"manifest.json is not valid JSON: {exc}") from exc
    _validate_manifest_shape(raw)

    # §C9.1 v0.4 (sc9_1-003): populate `append_only_files` from raw JSON.
    # v0.3 behavior dropped this key on round-trip (documented at
    # tests/test_c9_1_append_only_files.py::test_B3_round_trip_*). v0.4 reads
    # the list-of-dicts and exposes it as a tuple-of-dicts (matches dataclass
    # field type `tuple[dict, ...]`). Validate via the v0.3 well-formedness
    # checker so a malformed declaration raises MalformedManifest at the parse
    # boundary instead of propagating to the AppendOnlyAttributedCheck plugin.
    raw_append_only = raw.get("append_only_files", [])
    if not isinstance(raw_append_only, list):
        raise MalformedManifest(
            f"manifest.append_only_files must be a JSON array, got "
            f"{type(raw_append_only).__name__}"
        )
    append_only_tuple: tuple[dict, ...] = tuple(raw_append_only)
    malformations = validate_append_only_files(append_only_tuple)
    if malformations:
        first = malformations[0]
        raise MalformedManifest(f"manifest.append_only_files malformed: {first}")

    # §C9.1 disjointness: a path declared in append_only_files must
    # NOT also be a key in manifest.files. _step_file_integrity unconditionally
    # SKIPS append_only paths from strict-SHA, so an overlap silently downgrades
    # a byte-pinned file to attribution-only integrity and leaves a never-enforced,
    # misleading SHA in files{}. §C9.1 step (d) moves files INTO append_only
    # INSTEAD of files{} (the only pilot, the mesh pilot, already emits disjoint
    # sets), so this rejects nothing legitimate while closing the downgrade footgun.
    raw_files = raw.get("files") if isinstance(raw.get("files"), dict) else {}
    overlap = sorted(
        spec["path"]
        for spec in append_only_tuple
        if isinstance(spec, dict)
        and isinstance(spec.get("path"), str)
        and spec["path"] in raw_files
    )
    if overlap:
        raise MalformedManifest(
            f"manifest.append_only_files paths must not also be pinned in "
            f"manifest.files (append_only overrides strict-SHA, so an overlap "
            f"downgrades byte-integrity to attribution-only): {overlap}"
        )

    # The former narrow-site type-guards for outputs / per_output_manifests /
    # dispatch_records (non-array → TypeError out of the tuple() wraps below)
    # are subsumed by validate_top_level_field_shapes in
    # _validate_manifest_shape, which now covers every field.

    manifest = BundleManifest(
        schema_version=raw.get("schema_version", "legacy"),
        bundle_id=raw.get("bundle_id", ""),
        created_at=raw.get("created_at", ""),
        files=raw.get("files", {}),
        spec_files=raw.get("spec_files", {}),
        cross_refs=raw.get("cross_refs", {}),
        payload=raw.get("payload", {}),
        typed_checks=raw.get("typed_checks", []),
        snapshots=raw.get("snapshots", {}),
        snapshot_policy=raw.get("snapshot_policy"),
        fragment_anchors=raw.get("fragment_anchors", {}),
        source_attributes=raw.get("source_attributes", {}),
        decision_provenance_log=raw.get("decision_provenance_log"),
        retrieval_trace_id=raw.get("retrieval_trace_id"),
        retrieval_trace_log=raw.get("retrieval_trace_log"),
        per_output_manifests=tuple(raw.get("per_output_manifests", [])),
        output_mode_signal=raw.get("output_mode_signal"),
        dispatch_records=tuple(raw.get("dispatch_records") or []),
        append_only_files=append_only_tuple,
        aggregate_stamp=raw.get("aggregate_stamp"),
        assurance_profile=raw.get("assurance_profile"),
        rigor_profile=raw.get("rigor_profile"),
        attested_serving=raw.get("attested_serving"),
        verifier_identity=raw.get("verifier_identity"),
        causal_chain=raw.get("causal_chain"),
        semantic_fidelity=raw.get("semantic_fidelity"),
        extension_receipts=raw.get("extension_receipts"),
        outputs=tuple(raw.get("outputs") or ()),
    )

    # Deep-immutability lock (see bundle_manifest.deep_freeze): the verifier
    # threads this one object through ~10 sequential pipeline steps and several
    # late steps re-read fields the early integrity steps consumed. Freeze every
    # nested collection so an in-process step that mutates a manifest field in
    # place raises at that line instead of silently laundering a later verdict.
    # frozen=True + object.__setattr__ is the documented escape for rebinding a
    # frozen dataclass's own fields; the values themselves become deeply
    # immutable. Scalar fields pass through deep_freeze unchanged.
    for _f in fields(manifest):
        object.__setattr__(manifest, _f.name, deep_freeze(getattr(manifest, _f.name)))
    return manifest


@dataclass(frozen=True)
class _DsseGatePassed:
    """Returned by _dsse_pre_gate when the gate ran and PASSED.

    Carries forward what the post-binding checks (WS-5a 8a/8b) need from the
    gate's already-verified signed payload, so verify() never re-reads or
    re-verifies the sidecar after the gate. The old post-binding block
    re-read bundle.dsse.json and swallowed OSError (and a failed
    re-verification) into an empty header schema_version — silently
    disabling check 8a under flaky storage or a post-gate sidecar swap.
    """

    header_schema_version: str


# Stamped on every verdict face the unsafe-in-place lane emits: the residual
# the sealed snapshot otherwise closes mechanically must be legible in the
# artifact, not just in SECURITY.md (machine-checkable via
# Completeness.disclosures — a strict downstream consumer can refuse it).
_IN_PLACE_DISCLOSURE = (
    "sealed_snapshot: verified IN PLACE (unsafe_in_place=True) — mid-run-"
    "mutation coherence rests on the caller having sealed bundle_dir; the "
    "verdict conjunction is only as immutable as that directory"
)


# ---------------------------------------------------------------------------
# BundleVerifier
# ---------------------------------------------------------------------------


class BundleVerifier:
    """Generic 4-step audit-bundle integrity verifier with plugin extension slots.

    Construct with an optional list of TypedCheck plugins; call verify() with the
    path to an unpacked bundle directory.  All failures are collected and returned
    in VerifyResult — the method never raises.

    Plugin protocol (forward-ref: audit_bundle.plugin.TypedCheck):
        name: str
        applies_to_files: frozenset[str]
        check(bundle_dir: Path, manifest: BundleManifest) -> Result
    where Result has:
        ok: bool
        detail: str
    """

    def __init__(
        self,
        plugins: Sequence[Any] = (),
        *,
        spec_anchor: Any = None,
        role_policy: dict | None = None,
        fs_ignore: Sequence[str] = (),
        min_class_policy: "Mapping[str, Any] | None" = None,
        allow_spec_git_fallback: bool = True,
        unsafe_in_place: bool = False,
        completeness_policy: Any = None,
        profile_floor: str | None = None,
    ) -> None:
        self._plugins: tuple[Any, ...] = tuple(plugins)
        # Auditor-controlled spec trust anchor (SpecAnchor) + optional
        # output_id->required_type role policy. Both are verifier-side and
        # supplied by the AUDITOR's harness, never by the producer's manifest
        # (SPEC_PINNED_DISPATCH_ARCHITECTURE §4a.1/4a.3). Only consulted when a
        # bundle's manifest declares `outputs`; otherwise wholly inert.
        self._spec_anchor: Any = spec_anchor
        self._role_policy: dict | None = role_policy
        # Auditor fs_ignore view for the conservation gate: optional, default
        # EMPTY, construction-time only (never manifest-controlled), exact
        # paths or root-anchored globs only — validated here so a malformed
        # pattern fails at construction, not mid-verdict. Sealed bundles
        # ignore nothing; full discipline in audit_bundle.conservation.
        self._fs_ignore: tuple[str, ...] = validate_fs_ignore_patterns(fs_ignore)
        # Auditor minimum-class policy for the §C9.2 reclassification floor:
        # path-pattern → minimum OwnerKind, the only authority besides the
        # static (path, attribution_key) allowlist that may LOWER a path's
        # floor to APPEND_ONLY. Construction-time only, same pattern grammar
        # as fs_ignore, never manifest-sourced, never envelope-adjustable.
        self._min_class_policy = validate_min_class_policy(min_class_policy)
        # Auditor policy for the spec_sha_pinning ambient-git fallback on
        # UNSEALED bundles: True (default) keeps the legacy convenience path
        # (always disclosed on the verdict face when taken); False makes the
        # verdict bundle-determined — offline spec/ copy or structured reject.
        # SEALED bundles never consult the fallback regardless of this flag
        # (verifier-in-a-box: compliance state is a function of bundle +
        # injected policy, never of which repository surrounds bundle_dir).
        self._allow_spec_git_fallback: bool = bool(allow_spec_git_fallback)
        # Sealed-snapshot opt-out (loud-unsafe convention, like
        # --unsafe-run-bundle-pack): True skips the verifier-private copy and
        # reads bundle_dir live, so mid-run-mutation coherence rests on the
        # CALLER having sealed the directory — stamped as a completeness
        # DISCLOSURE on every verdict face this verifier emits.
        self._unsafe_in_place: bool = bool(unsafe_in_place)
        # Verifier-held assurance-profile policy + floor (CC-2b D1
        # downgrade protection; label-downgrade fix 2026-06-12). Both are
        # AUDITOR config, never manifest-sourced. completeness_policy is a
        # profile_completeness_policy.CompletenessPolicy carrying the relying
        # party's R(P)/O(S) content; profile_floor names the minimum profile
        # this verifier will grade against. With NEITHER configured, the
        # canonical builtin lattice still governs ADMISSION (unknown profile
        # ID → REJECT) and a declared label must be graded by a wired grader
        # plugin or the verdict is could-not-conclude — a label never rides
        # an OK nothing checked. Validated here so a misconfiguration fails
        # at construction, not mid-verdict.
        if completeness_policy is not None:
            for pid, prof in completeness_policy.profiles.items():
                unmapped = prof.required_structures - set(_PROFILE_STRUCTURE_PATHS)
                if unmapped:
                    raise ValueError(
                        f"completeness_policy profile {pid!r} requires "
                        f"structure(s) with no canonical manifest path: "
                        f"{sorted(unmapped)} (extend "
                        "profile_completeness_policy.STRUCTURE_PATHS first)"
                    )
        if profile_floor is not None:
            held = (
                completeness_policy
                if completeness_policy is not None
                else builtin_profile_lattice()
            )
            if profile_floor not in held.profiles:
                raise ValueError(
                    f"profile_floor {profile_floor!r} is not a profile in the "
                    "held completeness policy"
                )
        self._completeness_policy: Any = completeness_policy
        self._profile_floor: str | None = profile_floor

    def _plugin_files_union(self) -> frozenset[str]:
        """Union of the constructed plugins' applies_to_files sets — the
        verifier-configuration input the integrity-ownership map classifies
        PLUGIN ownership from. One definition for the strict-SHA walk and the
        conservation gate, so the two cannot drift."""
        return frozenset(
            f
            for plugin in self._plugins
            if hasattr(plugin, "applies_to_files")
            for f in plugin.applies_to_files
        )

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    @fail_closed("BundleVerifier.verify")
    def verify(
        self,
        bundle_dir: Path,
        *,
        dsse: "DsseVerifyContext | None" = None,
    ) -> VerifyResult:
        """Run the DSSE pre-gate (if applicable) then the 4-step walk.

        Every verdict-influencing read happens against a SEALED SNAPSHOT — a
        verifier-private copy of ``bundle_dir`` materialized before even the
        manifest read — so the verdict is a conjunction over ONE immutable
        byte-set (mixed-snapshot closure, BLOCK-01 2026-06-11; the strict-SHA
        walk over the snapshot binds those bytes to the manifest pins). A
        bundle that cannot be read as one stable artifact (entry vanishing or
        changing kind mid-copy) is a structured REJECT; a verifier-side
        resource failure (tempdir, ENOSPC) is a clean could-not-conclude
        ERROR. Constructed with ``unsafe_in_place=True``, the copy is skipped,
        ``bundle_dir`` is read live, and every verdict face carries a
        disclosure that coherence rests on the caller having sealed it.

        When ``dsse`` is None and no ``bundle.dsse.json`` sidecar is present,
        behaviour is byte-for-byte identical to the original (back-compat path
        unchanged — no new failure modes introduced).

        When ``dsse`` is provided OR a sidecar is present, the DSSE gate fires
        BEFORE ``_load_manifest``.  A sealed post-cutover bundle whose DSSE gate
        fails is rejected WITHOUT parsing the manifest (invariant: the manifest
        is never parsed if the gate fails).
        """
        # Resolve BEFORE snapshotting: the symlink re-anchoring transform
        # prefix-matches absolute link targets against this resolved root.
        bundle_dir = bundle_dir.resolve()

        # A nonexistent / non-directory bundle_dir takes the in-place lane:
        # there is nothing to copy, and the canonical missing-manifest reject
        # below must keep its face (snapshotting nothing would only rename it).
        if self._unsafe_in_place or not bundle_dir.is_dir():
            extra = (_IN_PLACE_DISCLOSURE,) if self._unsafe_in_place else ()
            return self._verify_in_dir(bundle_dir, dsse=dsse, extra_disclosures=extra)

        try:
            with sealed_snapshot(bundle_dir) as snap_dir:
                # The ambient-git spec fallback (C-1's qualified exception)
                # walks the repository surrounding the ORIGINAL location —
                # the snapshot tempdir has none, and the fallback's read is
                # already digest-bound at its own site.
                return self._verify_in_dir(
                    snap_dir, dsse=dsse, git_fallback_dir=bundle_dir
                )
        except SnapshotUnsupportedNode as exc:
            return Verdict.reject(
                "SNAPSHOT_UNSUPPORTED_NODE", str(exc), "sealed_snapshot"
            )
        except SnapshotNonQuiescent as exc:
            return Verdict.reject(
                "SNAPSHOT_SOURCE_UNSTABLE", str(exc), "sealed_snapshot"
            )
        except SnapshotMaterializationError as exc:
            return Verdict.incomplete(
                "SNAPSHOT_MATERIALIZATION_FAILED", str(exc), "sealed_snapshot"
            )

    def _verify_in_dir(
        self,
        bundle_dir: Path,
        *,
        dsse: "DsseVerifyContext | None" = None,
        extra_disclosures: tuple[str, ...] = (),
        git_fallback_dir: Path | None = None,
    ) -> VerifyResult:
        """The verification body. ``bundle_dir`` is the sealed snapshot on the
        default lane, or the caller's live directory on the unsafe-in-place
        lane (``extra_disclosures`` then carries the in-place stamp)."""
        bundle_dir = bundle_dir.resolve()

        # ------------------------------------------------------------------
        # ONE manifest snapshot (RES-04). manifest.json is read EXACTLY ONCE
        # per verify() call: the DSSE gate's cutover + binding checks, input
        # admission, the manifest parse, and the post-binding schema checks
        # all consume THESE bytes. Each extra read is a TOCTOU window —
        # flaky storage or a post-gate swap feeds later steps bytes the gate
        # never bound — and the old post-binding re-read swallowed OSError
        # into empty values, silently no-opping checks 8a/8b.
        # ------------------------------------------------------------------
        manifest_path = bundle_dir / "manifest.json"
        try:
            raw_manifest_bytes: bytes | None = manifest_path.read_bytes()
        except OSError:
            raw_manifest_bytes = None

        # ------------------------------------------------------------------
        # DSSE pre-gate — must run BEFORE the manifest parse on any path where
        # the gate is applicable. Returns a VerifyResult on failure (short-
        # circuit), a _DsseGatePassed context when the gate ran and passed
        # (carrying the signed header's schema_version for the post-binding
        # checks), or None when the gate is not applicable.
        # ------------------------------------------------------------------
        gate_result = self._dsse_pre_gate(bundle_dir, dsse, raw_manifest_bytes)
        gate_ctx: _DsseGatePassed | None = None
        if isinstance(gate_result, _DsseGatePassed):
            gate_ctx = gate_result
        elif gate_result is not None:
            return gate_result

        # Input-admission (ADR D9): bound size + nesting depth on the raw manifest
        # bytes BEFORE json.loads, so a deeply-nested manifest rejects as a clean
        # INPUT_DEPTH_EXCEEDED here instead of raising RecursionError inside the
        # parser (which the boundary would otherwise classify as a VERIFIER ERROR).
        adm = admit_bytes(raw_manifest_bytes or b"", check_name="manifest_admission")
        if adm is not None:
            return adm

        failures: list[VerifyFailure] = []
        # Clean-ERROR legs from plugins that ran cleanly but could not conclude (D6/D7);
        # composed REJECT-dominant into the final verdict (ADR §5.2 RULING).
        incompletes: list[Verdict] = []
        # Union of cross_host_authenticators edge keys that wired plugins reported
        # as VERIFIED; the cross-host guard asserts present − this == ∅.
        cross_host_verified: set[str] = set()
        # Union of fragment-anchor content keys wired plugins reported as
        # re-derived-and-matched; the anchor guard asserts present ATTESTABLE
        # keys − this == ∅ (RES-06 follow-up, same pattern as cross-host).
        fragment_anchors_verified: set[str] = set()
        # Union of (profile_id, policy_fingerprint) pairs wired grader plugins
        # reported as GRADED; the assurance-profile guard asserts the declared
        # label is in it (label-downgrade fix, same pattern as cross-host).
        profiles_graded: set[tuple[str, str]] = set()
        # Union of dispatch_records content keys wired plugins reported as
        # audited under C15, and of C14 whole-claim stamp keys plugins reported
        # as evaluated; the stamp-claims guard asserts present − these == ∅
        # (per-contract channels — tribunal 2026-06-12, same pattern as above).
        dispatch_records_verified: set[str] = set()
        stamp_claims_verified: set[str] = set()
        # Union of causal_chain sub-key content keys wired plugins reported as
        # verified; the causal-chain coverage guard asserts present accountable
        # sub-key keys − this == ∅ (BLOCK-02, same pattern as cross-host).
        causal_chain_subkeys_verified: set[str] = set()
        # Union of per-event layer_a OBLIGATION keys wired plugins reported as
        # discharged; the obligation guard asserts present obligation keys −
        # this == ∅ (GPT redteam BLOCK-01, 2026-06-12 — the same pattern one
        # level finer than the sub-key coverage above: key_rotation /
        # timestamp_evidence / cross_host_edge inside a layer_a event are
        # admitted by the str-key gate but NOT verified by the generic pipeline).
        layer_a_event_obligations_verified: set[str] = set()
        try:
            if raw_manifest_bytes is None:
                raise MalformedManifest(
                    f"manifest.json not found or unreadable in {bundle_dir}"
                )
            manifest = _parse_manifest(raw_manifest_bytes, bundle_dir)
        except SchemaVersionError as exc:
            # BLOCK-03: an un-allowlisted schema_version is a structured REJECT
            # with its own face — the bundle claims a contract version this
            # verifier does not implement, so no check below is meaningful
            # (and is_post_cutover would route it down the weaker pre-cutover
            # lane). Caught BEFORE MalformedManifest: SchemaVersionError is a
            # ManifestError sibling, not a MalformedManifest subclass.
            return Verdict.reject("schema_version", str(exc), "manifest_load")
        except MalformedManifest as exc:
            # Parse-boundary failure: collect, do not raise. verify()'s contract
            # is that every failure mode surfaces as a VerifyFailure so an
            # adversarial manifest can never crash the verifier (fail-stop) — it
            # is rejected (fail-closed).
            return Verdict.reject("malformed_manifest", str(exc), "manifest_load")

        # ------------------------------------------------------------------
        # Post-binding checks (run after the manifest parse).
        # When the DSSE gate ran and passed, we also check:
        #   8a — schema-version agreement (header vs manifest)
        #   8b — tombstone scan
        # These are appended into failures (not short-circuited) so all
        # step-1–5 failures are visible alongside them.
        # ------------------------------------------------------------------
        if gate_ctx is not None:
            # Both inputs come from the gate's ONE verified snapshot (RES-04):
            # the header schema_version from the signed payload the gate
            # already verified + parsed (no sidecar re-read, no envelope
            # re-verification), and the manifest dict from the SAME bytes the
            # gate binding-checked and _parse_manifest accepted above. The old
            # re-reads here swallowed OSError into empty values, so a
            # transient read failure (or a post-gate swap) silently disabled
            # 8a/8b instead of surfacing — orchestrator_turn.verifier already
            # had the carry-forward shape; this gate had drifted from it.
            # The check bodies live in contract_slots.post_binding_schema_checks
            # — the single implementation shared with orchestrator_turn.verifier
            # (cross-pillar, EXCLUDED from the open drop per
            # OSS_RELEASE_BOUNDARY.md), so the two gates cannot drift.
            try:
                manifest_dict = json.loads(raw_manifest_bytes or b"")
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Unreachable in practice (_parse_manifest accepted these
                # bytes above); kept narrow so a verifier bug crashes instead
                # of silently skipping the checks.
                manifest_dict = {}
            for reason_code, detail in post_binding_schema_checks(
                gate_ctx.header_schema_version, manifest_dict
            ):
                failures.append(
                    VerifyFailure(
                        check_name="dsse_gate",
                        reason_code=reason_code,
                        detail=detail,
                    )
                )

        # ------------------------------------------------------------------
        # Conservation gate — runs UNCONDITIONALLY, regardless of the plugin
        # set (the point: BundleVerifier(plugins=()).verify() on an unsealed
        # sidecar-absent bundle previously got NO surplus sweep, so undeclared
        # on-disk files rode a green verdict). Every path in the conservation
        # universe (on-disk ∪ declared) must be claimed by exactly one
        # integrity-owner class whose checker runs in this method; UNOWNED
        # fails closed with the same artifact-bad class the Pass-3 sweep and
        # the sealed set-closure walk already enforce. Per-lane ENVELOPE
        # semantics: sealed → the DSSE pre-gate above IS the envelope checker
        # (reaching here means it passed); sidecar-present-unsealed → the
        # pre-gate fail-closed-rejected and we never get here; sidecar-absent
        # → manifest.json is parse-validated + admission-bounded only, and
        # that residual is DISCLOSED on the verdict face, never silently
        # passed. The Pass-3 plugin consumes this result via its shim (bound
        # around plugin dispatch below) — one source of the surplus decision.
        # ------------------------------------------------------------------
        conservation = run_conservation(
            bundle_dir,
            manifest,
            self._plugin_files_union(),
            # Gate-time observation, not a fresh stat (RES-04): every
            # sidecar-present path either rejected above or set gate_ctx.
            sealed=gate_ctx is not None,
            fs_ignore=self._fs_ignore,
        )
        disclosures: list[str] = list(extra_disclosures)
        for rel in conservation.envelope_residual:
            disclosures.append(
                f"conservation: {rel} is parse-validated only on the unsealed "
                "(sidecar-absent) lane — byte-integrity-owned by nobody"
            )
        for rel, pattern in conservation.ignored:
            disclosures.append(
                f"conservation: UNOWNED path {rel!r} tolerated by auditor "
                f"fs_ignore pattern {pattern!r}"
            )
        if conservation.unchecked_tree_counts:
            counts = ", ".join(
                f"{n} under {top}/" for top, n in conservation.unchecked_tree_counts
            )
            disclosures.append(
                f"conservation: {counts} carry tree-membership only "
                "(no per-file integrity check)"
            )
        if conservation.nonregular:
            # Fail-closed BEFORE any content step: a non-regular object
            # (FIFO / socket / device) can never satisfy a content contract,
            # and opening one can block the verifier (a declared FIFO would
            # hang the strict-SHA read). Report every unowned path, then stop.
            nonregular_kinds = dict(conservation.nonregular)
            for rel in conservation.unowned:
                if rel in nonregular_kinds:
                    detail = (
                        f"{rel!r}: non-regular file object "
                        f"({nonregular_kinds[rel]}) classifies UNOWNED "
                        "regardless of declaration; rejected before any "
                        "content step opens it"
                    )
                else:
                    detail = (
                        f"{rel!r}: present in bundle_dir but absent from manifest.files"
                    )
                failures.append(
                    VerifyFailure(
                        check_name="conservation",
                        reason_code="EXTRA_FILE_NOT_IN_MANIFEST",
                        detail=detail,
                    )
                )
            return Verdict.from_failures(
                failures,
                completeness=Completeness(
                    layers=("conservation",),
                    deep_validation=False,
                    disclosures=tuple(disclosures),
                ),
            )
        for rel in conservation.unowned:
            failures.append(
                VerifyFailure(
                    check_name="conservation",
                    reason_code="EXTRA_FILE_NOT_IN_MANIFEST",
                    detail=(
                        f"{rel!r}: present in bundle_dir but absent from manifest.files"
                    ),
                )
            )

        # §C9.2 reclassification floor — HARD PRE-CHECK before any guarantee
        # computation: an APPEND_ONLY downgrade is honored only when the
        # static (path, attribution_key) allowlist or an auditor min-class
        # policy entry authorizes it; anything else REJECTS regardless of
        # content (never silently promoted to a byte-check that could pass).
        # An authorization failure cannot be softened by the §C9.1
        # attribution check running afterwards — the REJECT stands.
        floor = check_append_only_floor(bundle_dir, manifest, self._min_class_policy)
        for reason_code, detail in floor.failures:
            failures.append(
                VerifyFailure(
                    check_name="append_only_floor",
                    reason_code=reason_code,
                    detail=detail,
                )
            )
        for rel in floor.policy_lowered:
            disclosures.append(
                f"append_only_floor: {rel!r} floor lowered to APPEND_ONLY by "
                "auditor min-class policy (attribution-key coverage, not "
                "byte-equality)"
            )

        self._step_file_integrity(bundle_dir, manifest, failures)
        # sealed= is the same gate-time observation conservation consumes
        # (RES-04): a sealed bundle's spec pins must be satisfied by SIGNED
        # offline copies — set closure has already pinned on-disk == signed
        # set, so "exists under spec/" ⇒ "in the signed set" on this lane.
        self._step_spec_sha_pinning(
            bundle_dir,
            manifest,
            failures,
            disclosures,
            sealed=gate_ctx is not None,
            git_fallback_dir=git_fallback_dir,
        )
        self._step_cross_refs(bundle_dir, manifest, failures)
        # The Pass-3 shim consumes ONLY the finalized conservation result:
        # bind it for the duration of plugin dispatch, then clear it so a
        # later direct plugin invocation cannot ride a stale binding.
        try:
            for plugin in self._plugins:
                binder = getattr(plugin, "bind_conservation", None)
                if callable(binder):
                    binder(conservation)
            self._step_typed_check_plugins(
                bundle_dir,
                manifest,
                failures,
                incompletes,
                cross_host_verified,
                fragment_anchors_verified,
                profiles_graded,
                dispatch_records_verified,
                stamp_claims_verified,
                causal_chain_subkeys_verified,
                layer_a_event_obligations_verified,
                disclosures,
            )
        finally:
            for plugin in self._plugins:
                binder = getattr(plugin, "bind_conservation", None)
                if callable(binder):
                    binder(None)
        self._step_spec_pinned_dispatch(bundle_dir, manifest, failures)
        # Present-but-unverified gates that previously lived ONLY in veriker/cli/verify.py
        # (so a LIBRARY consumer's verdict laundered them — verdict-divergence
        # sweep, 2026-06-10). Each maps a present-but-unverified claim to a
        # clean-ERROR (could-not-conclude) leg, never a silent OK.
        self._step_extension_receipts(manifest, failures, incompletes, disclosures)
        self._step_cross_host_guard(manifest, cross_host_verified, incompletes)
        self._step_causal_chain_coverage_guard(
            manifest, causal_chain_subkeys_verified, incompletes
        )
        # One level finer than the sub-key coverage guard above: a layer_a EVENT
        # carrying a key_rotation / timestamp_evidence / cross_host_edge
        # obligation the generic pipeline does not verify must be discharged by a
        # dedicated plugin, else could-not-conclude (GPT redteam BLOCK-01).
        self._step_layer_a_event_obligation_guard(
            manifest, layer_a_event_obligations_verified, incompletes
        )
        self._step_fragment_anchor_guard(
            manifest, fragment_anchors_verified, incompletes, disclosures
        )
        self._step_stamp_claims_guard(
            manifest, dispatch_records_verified, stamp_claims_verified, incompletes
        )
        self._step_assurance_profile_guard(
            manifest, profiles_graded, failures, incompletes, disclosures
        )
        # A re_derive/*_pack.py in the VERIFIED snapshot that no wired
        # ReDerivationInvocationCheck instance covers — AND that no spec-pinned
        # dispatch verified — is present-but-unverified (re-derivation TOCTOU
        # sweep, 2026-06-12). Scanned off bundle_dir — the SAME sealed snapshot
        # the verdict is a conjunction over — so the pack-presence decision
        # cannot be raced against a pre-snapshot CLI read.
        self._step_rederivation_pack_guard(bundle_dir, manifest, incompletes)
        self._step_c18_structural(bundle_dir, raw_manifest_bytes, manifest, failures)
        # D5: verify() subsumes the DEEP manifest validators so a LIBRARY consumer of
        # verify() gets the same coverage the CLI fast-path had (snapshots / fragment
        # anchors / source attributes / retrieval traces / per-output manifests /
        # output-mode / OF1). Each deep check is presence-gated; an unexpected (non-
        # manifest) raise propagates to the fail_closed boundary as a crash-ERROR.
        self._step_deep_manifest_validation(bundle_dir, manifest, failures)
        # The verdict declares which layers ran (D5): verify() now always runs the shallow
        # 4-step walk, the deep validators, AND the conservation gate, so a consumer can
        # never mistake a shallow pass for a complete one.
        completeness = Completeness(
            layers=("shallow_walk", "deep_manifest_validation", "conservation"),
            deep_validation=True,
            disclosures=tuple(disclosures),
        )
        base = Verdict.from_failures(failures, completeness=completeness)
        if not incompletes:
            return base
        # Ratified algebra (crash-ERROR > REJECT > clean-ERROR > OK): a real REJECT
        # dominates a clean-ERROR plugin; an otherwise-OK bundle with a could-not-conclude
        # plugin is a clean-ERROR (INCOMPLETE), never a false GREEN. compose() does not
        # carry completeness, so re-attach it to the composite face.
        return replace(compose([base, *incompletes]), completeness=completeness)

    # ------------------------------------------------------------------
    # DSSE pre-gate (private)
    # ------------------------------------------------------------------

    def _dsse_pre_gate(
        self,
        bundle_dir: Path,
        dsse: "DsseVerifyContext | None",
        raw_manifest_bytes: bytes | None,
    ) -> "VerifyResult | _DsseGatePassed | None":
        """Run the DSSE gate BEFORE the manifest parse.

        Returns a failing VerifyResult to short-circuit verify(), a
        _DsseGatePassed context when the gate ran and PASSED (carrying the
        signed header's schema_version so the post-binding checks never
        re-read or re-verify the sidecar — RES-04), or None when the gate is
        not applicable (proceed to the normal 4-step walk).

        ``raw_manifest_bytes`` is verify()'s ONE manifest snapshot (None when
        manifest.json was absent/unreadable); the cutover check and the
        step-5 binding compare both consume it — the gate performs no
        manifest read of its own.

        Lazy-imports the crypto-bearing dsse modules so that
        ``import audit_bundle.verifier`` remains stdlib-only at import time.
        is_post_cutover and scan_manifest_for_tombstoned_fields are stdlib-pure
        and are imported at module top.

        Gate steps (mirror WS-5a normative ordering):
          1. sidecar absent — check cutover / strict-mode branches
          2. sidecar present — fail-closed if no context/allowlist
          3. verify_envelope (envelope + signature check)
          4. revocation via is_revoked
          5. payload-binding (sha256 of manifest bytes vs payload["manifest_sha256"])
             — NEVER reads manifest semantics before this compare
          6. set-closure via snapshot_and_compare
        """

        def _fail(reason_code: str, detail: str) -> VerifyResult:
            return Verdict.reject(reason_code, detail, "dsse_gate")

        sidecar_path = bundle_dir / "bundle.dsse.json"
        sidecar_present = sidecar_path.exists()

        # ------------------------------------------------------------------
        # Step 1 — sidecar absent branch
        # ------------------------------------------------------------------
        if not sidecar_present:
            # Read schema_version from verify()'s manifest snapshot (only for
            # the cutover tag check — no semantic field access beyond this
            # membership test).
            manifest_schema: str = "unknown"
            try:
                manifest_raw: dict = json.loads(
                    (raw_manifest_bytes or b"").decode("utf-8", errors="replace")
                )
                manifest_schema = manifest_raw.get("schema_version", "unknown")
            except (json.JSONDecodeError, AttributeError):
                # Absent/unparseable — fall through to structural verifier
                # which will produce a proper MalformedManifest error.
                pass

            if is_post_cutover(manifest_schema):
                return _fail(
                    "DSSE_ENVELOPE_ABSENT",
                    f"manifest declares post-cutover schema {manifest_schema!r} "
                    "but no bundle.dsse.json sidecar found",
                )

            if dsse is not None and dsse.require_dsse:
                if dsse.allow_legacy:
                    return _fail(
                        "LEGACY_UNSIGNED_REFUSED_SOFT",
                        "strict mode: bundle lacks DSSE sidecar (allow_legacy soft-fail)",
                    )
                else:
                    return _fail(
                        "SCHEMA_PRE_CUTOVER_REFUSED",
                        "strict mode: bundle lacks DSSE sidecar and require_dsse=True",
                    )

            # Gate NOT applicable — proceed to normal verify path.
            return None

        # ------------------------------------------------------------------
        # Sidecar IS present — gate is active.
        # ------------------------------------------------------------------

        # Fail-closed: sidecar present but no DSSE context / allowlist.
        if dsse is None or not dsse.allowlist:
            return _fail(
                "DSSE_SIGNATURE_INVALID",
                "bundle.dsse.json sidecar is present but no DSSE context / allowlist "
                "was injected; cannot verify signature (fail-closed)",
            )

        # ------------------------------------------------------------------
        # Lazy-import the crypto-bearing modules (only when gate is active).
        # This keeps `import audit_bundle.verifier` stdlib-only at import time.
        # ------------------------------------------------------------------
        from .dsse.envelope import verify_envelope  # noqa: PLC0415
        from .dsse.payload import validate_dsse_payload_shape  # noqa: PLC0415
        from .dsse.set_closure import snapshot_and_compare  # noqa: PLC0415
        from .revocation import is_revoked  # noqa: PLC0415

        # ------------------------------------------------------------------
        # Steps 2+3 — read sidecar bytes + verify_envelope (header + sig)
        # ------------------------------------------------------------------
        try:
            sidecar_bytes = sidecar_path.read_bytes()
        except OSError as exc:
            return _fail(
                "DSSE_MALFORMED_ENVELOPE",
                f"failed to read bundle.dsse.json: {exc}",
            )

        res = verify_envelope(sidecar_bytes, dsse.allowlist)
        if not res.ok:
            return _fail(
                res.reason_code or "DSSE_SIGNATURE_INVALID",
                f"envelope verification failed: {res.detail}",
            )

        # ok=True is contracted to guarantee these, but don't let a contract
        # violation ride on `assert` (stripped under python -O) and proceed with
        # None into json.loads. Fail closed explicitly.
        if res.payload_bytes is None or res.kid is None:
            return _fail(
                "DSSE_MALFORMED_ENVELOPE",
                "envelope verified ok but payload_bytes/kid missing — contract violation",
            )
        try:
            payload: dict = json.loads(res.payload_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return _fail(
                "DSSE_MALFORMED_ENVELOPE",
                f"signed payload is not valid JSON: {exc}",
            )

        # Shape-validate the verified payload BEFORE any field deref. A
        # validly-signed but wrong-shape payload (non-object, files as a
        # string / list of non-objects) would otherwise raise out of the
        # payload.get / f["path"] derefs below and be reported by the outer
        # boundary as a crash-class VERIFIER_INTERNAL_ERROR — misattributing a
        # malformed ARTIFACT to a verifier fault. Fail closed as a structured
        # DSSE_MALFORMED_PAYLOAD reject, consistent with the not-valid-JSON
        # path one step above.
        shape_err = validate_dsse_payload_shape(payload)
        if shape_err is not None:
            return _fail(*shape_err)

        kid: str = res.kid

        # ------------------------------------------------------------------
        # Step 4 — revocation
        # ------------------------------------------------------------------
        rv = is_revoked(dsse.revocation_list, kid, dsse.verifier_now)
        if rv.revoked:
            return _fail(
                rv.reason_code or "DSSE_KEY_REVOKED",
                f"key revocation check failed: {rv.reason_code}",
            )

        # ------------------------------------------------------------------
        # Step 5 — payload binding
        # Recompute sha256 of verify()'s ONE manifest snapshot and compare to
        # payload["manifest_sha256"] BEFORE any manifest semantic parsing.
        # This is the FIRST AND ONLY point manifest bytes are consumed in
        # the gate; no manifest semantic field is accessed before this compare.
        # Because every later step parses these SAME bytes, this compare binds
        # the entire verify() call to the signed snapshot (RES-04).
        # ------------------------------------------------------------------
        if raw_manifest_bytes is None:
            return _fail(
                "DSSE_PAYLOAD_BINDING_MISMATCH",
                "cannot read manifest.json for binding check",
            )

        actual_manifest_sha256 = hashlib.sha256(raw_manifest_bytes).hexdigest()
        expected_manifest_sha256: str = payload.get("manifest_sha256", "")
        if actual_manifest_sha256 != expected_manifest_sha256:
            return _fail(
                "DSSE_PAYLOAD_BINDING_MISMATCH",
                f"manifest.json sha256 mismatch: "
                f"payload={expected_manifest_sha256[:12]}... "
                f"actual={actual_manifest_sha256[:12]}...",
            )

        # ------------------------------------------------------------------
        # Step 6 — set-closure
        # The payload "files" array EXCLUDES the structural envelope files
        # (manifest.json, bundle.dsse.json — per seam spec). Re-add them, taken
        # from the integrity-ownership map's ENVELOPE class so this gate and
        # the emitter/Pass-3 sweeps share one source for the seam set (no
        # walk-local literal to drift).
        # ------------------------------------------------------------------
        expected_files: frozenset[str] = (
            frozenset(f["path"] for f in payload.get("files", [])) | ENVELOPE_PATHS
        )
        sc = snapshot_and_compare(bundle_dir, expected_files)
        if not sc.ok:
            return _fail(
                sc.reason_code or "UNLISTED_FILE_IN_SEALED_ROOT",
                f"set-closure check failed ({sc.reason_code}): "
                f"missing={sorted(sc.missing)} surplus={sorted(sc.surplus)} "
                f"unstable={list(sc.unstable)}",
            )

        # Gate passed — proceed to the manifest parse + 4-step walk, carrying
        # the signed header's schema_version so the post-binding checks never
        # touch the sidecar again (RES-04).
        return _DsseGatePassed(header_schema_version=payload.get("schema_version", ""))

    # ------------------------------------------------------------------
    # Step 1 — file integrity
    # ------------------------------------------------------------------

    def _step_file_integrity(
        self,
        bundle_dir: Path,
        manifest: BundleManifest,
        failures: list[VerifyFailure],
    ) -> None:
        """SHA-256 every entry in manifest.files whose integrity-owner class
        is STRICT_SHA.

        Membership is now derived from the integrity-ownership map (audit-
        bundle contract §C9): a path is byte-equality-checked iff
        classify_path(rel, manifest, plugin_files).kind is STRICT_SHA. The map
        encodes, in one place, every exclusion this walk used to assemble as a
        complement skip-set — files covered by an exact-path plugin
        applies_to_files entry (PLUGIN), files declared in append_only_files
        (APPEND_ONLY, §C9.1 v0.4 — substantive guarantee discharged by
        AppendOnlyAttributedCheck after this loop), and the structural envelope
        files. D3 (ratified) dropped the dead typed_checks-as-paths exclusion,
        so a file named like a typed-check plugin is now byte-checked
        (corpus-proven zero collisions). Back-compat: a baseline bundle (no
        plugins, no append_only_files) classifies every files entry STRICT_SHA,
        so the walk is unchanged.
        """
        plugin_files: frozenset[str] = frozenset(
            f
            for plugin in self._plugins
            if hasattr(plugin, "applies_to_files")
            for f in plugin.applies_to_files
        )

        for rel_path, expected_sha in sorted(manifest.files.items()):
            if (
                classify_path(rel_path, manifest, plugin_files).kind
                is not OwnerKind.STRICT_SHA
            ):
                continue
            try:
                # _safe_bundle_path fail-closes on path-escape (absolute path,
                # .. traversal, symlink leaving the tree) and on non-regular
                # files (atheris finding 2026-05-26: rel_path="/" raised
                # IsADirectoryError out of read_bytes(); BLOCK-01 widened it to
                # the FIFO/socket that would BLOCK read_bytes() instead of
                # raising). open_regular_fd_nofollow then closes the TOCTOU
                # window between that stat and this read: a regular→FIFO/symlink
                # swap is caught at open time (O_NONBLOCK + O_NOFOLLOW + fstat),
                # never as a hanging read.
                fpath = _safe_bundle_path(bundle_dir, rel_path)
                if not fpath.exists():
                    raise BadFileSHA(f"file missing from bundle: {rel_path!r}")
                with os.fdopen(open_regular_fd_nofollow(fpath), "rb") as fh:
                    computed = _sha256_bytes(fh.read())
                if computed.lower() != expected_sha.lower():
                    raise BadFileSHA(
                        f"{rel_path!r}: manifest_sha={expected_sha!r} "
                        f"computed_sha={computed!r}"
                    )
            except UnsafeBundlePath as exc:
                failures.append(
                    VerifyFailure(
                        check_name="file_integrity",
                        reason_code="path_escape",
                        detail=str(exc),
                    )
                )
            except BadFileSHA as exc:
                failures.append(
                    VerifyFailure(
                        check_name="file_integrity",
                        reason_code="bad_file_sha",
                        detail=str(exc),
                    )
                )
            except OSError as exc:
                # Belt-and-braces: _safe_bundle_path's is_file() check already
                # blocks IsADirectoryError, but read_bytes() can still surface
                # PermissionError / FileNotFoundError between is_file() and the
                # read (TOCTOU). The §C9 contract is fail-closed, not fail-stop,
                # so we collect rather than propagate.
                failures.append(
                    VerifyFailure(
                        check_name="file_integrity",
                        reason_code="bad_file_sha",
                        detail=f"unreadable {rel_path!r}: {type(exc).__name__}: {exc}",
                    )
                )

        # §C9.1 v0.4 (sc9_1-004): after strict-SHA loop, dispatch
        # AppendOnlyAttributedCheck. Composes with the skip logic above —
        # declared paths were skipped from strict-SHA precisely because this
        # plugin provides their integrity guarantee. Empty append_only_files
        # short-circuits inside the plugin (returns []), so the back-compat
        # invariant is preserved (no behavior change for baseline bundles).
        append_only_check = AppendOnlyAttributedCheck()
        for plugin_failure in append_only_check.check(bundle_dir, manifest):
            failures.append(
                VerifyFailure(
                    check_name="file_integrity",
                    reason_code=plugin_failure.reason_code.lower(),
                    detail=(
                        f"{plugin_failure.path!r} "
                        f"(attribution_plugin={plugin_failure.attribution_plugin!r}): "
                        f"{plugin_failure.detail}"
                    ),
                )
            )

    # ------------------------------------------------------------------
    # Step 2 — spec SHA pinning
    # ------------------------------------------------------------------

    def _step_spec_sha_pinning(
        self,
        bundle_dir: Path,
        manifest: BundleManifest,
        failures: list[VerifyFailure],
        disclosures: list[str],
        *,
        sealed: bool,
        git_fallback_dir: Path | None = None,
    ) -> None:
        """Verify every spec_files entry resolves to bytes matching the recorded SHA.

        Offline-first (§C5 verifier-in-a-box): checks bundle_dir/spec/<basename>
        before falling back to git_blob_resolver.  Bundles are expected to include
        the resolved spec text under spec/ so offline auditors never need git.

        The git fallback is integrity-safe (any blob it yields must hash to the
        manifest-pinned SHA before use) but its PROVENANCE differs from the
        bundle's own spec/ copy: bytes come from whatever repository
        _discover_repo_root finds above bundle_dir, ambient verifier-host
        state the bundle producer never shipped. A pass through that path is
        therefore disclosed on the verdict face (Completeness.disclosures) so
        a consumer can distinguish "verified from the bundle" from "verified
        from the host's git history". A git subprocess failure on that path
        (corrupt repo, missing git binary) is a structured
        git_resolution_error, never an escaping exception.

        SEALED bundles never reach the fallback: the emitter signs every
        spec/ copy into the DSSE payload's files set, and set closure pins
        on-disk == signed set, so a sealed bundle whose pin has no offline
        copy was SIGNED without one — its compliance state would otherwise
        depend on which repository happens to surround bundle_dir on the
        verifier host. That is a structured sealed_spec_offline_copy_missing
        REJECT (host-independence is the point of sealing). Unsealed bundles
        keep the fallback unless the auditor disabled it at construction
        (allow_spec_git_fallback=False → structured spec_git_fallback_disabled).
        """
        use_git_fallback = not sealed and self._allow_spec_git_fallback
        # No ambient host probing at all unless the fallback is reachable.
        # The walk starts from the ORIGINAL bundle location, not the sealed
        # snapshot: this fallback is BY DESIGN a function of the repository
        # surrounding the bundle (C-1's qualified, disclosed exception), and
        # it needs no snapshot coherence — any blob it yields must hash to
        # the manifest-pinned SHA at this read site before use (bound read).
        repo_root = (
            _discover_repo_root(
                git_fallback_dir if git_fallback_dir is not None else bundle_dir
            )
            if use_git_fallback
            else None
        )

        for spec_path, expected_sha in sorted(manifest.spec_files.items()):
            if not expected_sha:
                failures.append(
                    VerifyFailure(
                        check_name="spec_sha_pinning",
                        reason_code="empty_spec_sha",
                        detail=f"spec_files entry {spec_path!r} has no SHA recorded",
                    )
                )
                continue

            try:
                # Route the offline copy through _safe_bundle_path so the spec
                # path gets the SAME fail-closed defenses as manifest.files:
                # .resolve() collapses symlinks and rejects anything escaping
                # bundle_dir (the symlink/hash-oracle finding: spec/leak.md ->
                # /etc/hostname was hashed and the SHA leaked in the failure
                # detail), and is_dir() rejects a directory at that path (which
                # otherwise raised IsADirectoryError -> VerdictState.ERROR).
                offline_copy = _safe_bundle_path(
                    bundle_dir, f"spec/{Path(spec_path).name}"
                )
                via_git = False
                if offline_copy.exists():
                    blob = offline_copy.read_bytes()
                elif sealed:
                    failures.append(
                        VerifyFailure(
                            check_name="spec_sha_pinning",
                            reason_code="sealed_spec_offline_copy_missing",
                            detail=(
                                f"spec {spec_path!r}: sealed bundle pins this "
                                "spec but ships no signed offline copy under "
                                "spec/ — sealed verification never consults "
                                "ambient git (the verdict must be a function "
                                "of the bundle, not of the verifier host)"
                            ),
                        )
                    )
                    continue
                elif not self._allow_spec_git_fallback:
                    failures.append(
                        VerifyFailure(
                            check_name="spec_sha_pinning",
                            reason_code="spec_git_fallback_disabled",
                            detail=(
                                f"spec {spec_path!r}: offline copy absent and "
                                "the ambient-git fallback is disabled by "
                                "verifier policy (allow_spec_git_fallback=False)"
                            ),
                        )
                    )
                    continue
                elif repo_root is not None:
                    try:
                        blob = resolve_blob_at_sha(repo_root, spec_path, expected_sha)
                    except (subprocess.CalledProcessError, OSError) as exc:
                        # A corrupt repo or missing git binary previously
                        # escaped as a crash-ERROR; the verdict face said
                        # nothing about WHICH spec or WHY. Structured reject.
                        failures.append(
                            VerifyFailure(
                                check_name="spec_sha_pinning",
                                reason_code="git_resolution_error",
                                detail=(
                                    f"spec {spec_path!r}: offline copy absent and "
                                    f"the git history walk failed "
                                    f"({exc.__class__.__name__}: {exc})"
                                ),
                            )
                        )
                        continue
                    via_git = True
                else:
                    raise MissingSpecBlob(
                        f"spec {spec_path!r}: offline copy absent "
                        "and no git repository found from bundle_dir"
                    )
                computed = _sha256_bytes(blob)
                if computed.lower() != expected_sha.lower():
                    raise MissingSpecBlob(
                        f"spec {spec_path!r}: manifest_sha={expected_sha!r} "
                        f"computed_sha={computed!r}"
                    )
                if via_git:
                    # Disclosed-not-silently-passed: the bytes are pinned-SHA
                    # equivalent, but they came from ambient host git history,
                    # not from the bundle the producer shipped.
                    disclosures.append(
                        f"spec_sha_pinning: {spec_path!r} resolved from ambient "
                        "git history (offline spec/ copy absent); bytes matched "
                        "the manifest-pinned SHA-256"
                    )
            except MissingSpecBlob as exc:
                failures.append(
                    VerifyFailure(
                        check_name="spec_sha_pinning",
                        reason_code="missing_spec_blob",
                        detail=str(exc),
                    )
                )
            except BlobNotFound as exc:
                failures.append(
                    VerifyFailure(
                        check_name="spec_sha_pinning",
                        reason_code="missing_spec_blob",
                        detail=str(exc),
                    )
                )
            except UnsafeBundlePath as exc:
                failures.append(
                    VerifyFailure(
                        check_name="spec_sha_pinning",
                        reason_code="path_escape",
                        detail=str(exc),
                    )
                )
            except OSError as exc:
                # Belt-and-braces: _safe_bundle_path's is_dir() check blocks the
                # IsADirectoryError case, but read_bytes() can still surface
                # PermissionError / FileNotFoundError in the TOCTOU window. §C9
                # is fail-closed, not fail-stop — collect, don't propagate.
                failures.append(
                    VerifyFailure(
                        check_name="spec_sha_pinning",
                        reason_code="missing_spec_blob",
                        detail=(
                            f"spec {spec_path!r}: unreadable offline copy: "
                            f"{type(exc).__name__}: {exc}"
                        ),
                    )
                )

    # ------------------------------------------------------------------
    # Step 3 — cross-references
    # ------------------------------------------------------------------

    def _step_cross_refs(
        self,
        bundle_dir: Path,
        manifest: BundleManifest,
        failures: list[VerifyFailure],
    ) -> None:
        """Verify every cross_refs target is reachable.

        A target is reachable if it is a key in manifest.files whose on-disk file
        exists, OR a key in manifest.spec_files (spec docs are pinned by SHA and
        may be fetched offline).
        """
        for logical_name, target in sorted(manifest.cross_refs.items()):
            try:
                # Route the .exists() probe through the path-safety helper so
                # an adversarial cross_refs target (e.g. "/") can neither crash
                # the verifier (.is_file() pre-check) nor be used as a
                # file-existence oracle for paths outside the bundle. Treat
                # UnsafeBundlePath as "not reachable" — the cross-ref is broken.
                try:
                    target_path = _safe_bundle_path(bundle_dir, target)
                    target_exists_in_bundle = target_path.exists()
                except UnsafeBundlePath:
                    target_exists_in_bundle = False
                in_files = target in manifest.files and target_exists_in_bundle
                in_spec = target in manifest.spec_files
                if not in_files and not in_spec:
                    raise BrokenCrossRef(
                        f"cross_refs[{logical_name!r}] = {target!r} does not resolve "
                        "to any reachable key in manifest.files or manifest.spec_files"
                    )
            except BrokenCrossRef as exc:
                failures.append(
                    VerifyFailure(
                        check_name="cross_refs",
                        reason_code="broken_cross_ref",
                        detail=str(exc),
                    )
                )

    # ------------------------------------------------------------------
    # Step 4 — typed-check plugins
    # ------------------------------------------------------------------

    def _step_typed_check_plugins(
        self,
        bundle_dir: Path,
        manifest: BundleManifest,
        failures: list[VerifyFailure],
        incompletes: list[Verdict],
        cross_host_verified: set[str],
        fragment_anchors_verified: set[str],
        profiles_graded: set[tuple[str, str]],
        dispatch_records_verified: set[str],
        stamp_claims_verified: set[str],
        causal_chain_subkeys_verified: set[str],
        layer_a_event_obligations_verified: set[str],
        disclosures: list[str],
    ) -> None:
        """Run each registered TypedCheck plugin and aggregate their results.

        Plugins are called via duck-typing: plugin.check(bundle_dir, manifest)
        must return an object with ok: bool and detail: str. A plugin MAY also set an
        optional `incomplete: bool` on its result: `incomplete=True` signals the
        clean-ERROR contract (the plugin ran cleanly but COULD NOT CONCLUDE — e.g. an
        external attestation it depends on is absent). That is NEITHER a REJECT (the
        artifact is not bad) NOR a crash (no exception escaped) — it is recorded as a
        clean-ERROR leg (ADR §5.2 RULING + the unanimous plugin-contract precondition),
        which composes REJECT-dominant in verify().

        After running every plugin instance, cross-check that every name
        listed in manifest.typed_checks has a corresponding plugin instance
        in self._plugins. A name without an instance means the bundle claims
        a check ran when no plugin executed — emit plugin_failed so the
        manifest's typed_checks claim cannot diverge from the verifier's
        actual plugin set (CC2 invariant).
        """
        for plugin in self._plugins:
            plugin_id = getattr(plugin, "name", repr(plugin))
            try:
                result = plugin.check(bundle_dir, manifest)
                # Accumulate the cross-host edges this plugin reported as VERIFIED
                # (per-edge coverage accounting). Unioned across plugins, consumed by
                # _step_cross_host_guard. Read via getattr so non-conforming/legacy
                # results contribute nothing (fail-closed: unreported edges stay in
                # the guard's present − verified difference).
                cross_host_verified |= getattr(
                    result, "verified_cross_host_edges", frozenset()
                )
                # Same accounting for fragment-anchor quote claims: union the
                # anchor content keys this plugin re-derived and matched,
                # consumed by _step_fragment_anchor_guard.
                fragment_anchors_verified |= getattr(
                    result, "verified_fragment_anchors", frozenset()
                )
                # Same accounting for assurance-profile grading: union the
                # (profile_id, policy_fingerprint) pairs this plugin graded,
                # consumed by _step_assurance_profile_guard.
                profiles_graded |= getattr(
                    result, "graded_assurance_profiles", frozenset()
                )
                # Same accounting for the C15 per-record and C14 whole-claim
                # stamp channels, consumed by _step_stamp_claims_guard.
                dispatch_records_verified |= getattr(
                    result, "verified_dispatch_records", frozenset()
                )
                stamp_claims_verified |= getattr(
                    result, "verified_stamp_claims", frozenset()
                )
                # Same accounting for the causal_chain discriminated union,
                # consumed by _step_causal_chain_coverage_guard (BLOCK-02).
                causal_chain_subkeys_verified |= getattr(
                    result, "verified_causal_chain_subkeys", frozenset()
                )
                # Same accounting one level finer — per-event layer_a
                # obligations (key_rotation / timestamp_evidence /
                # cross_host_edge), consumed by
                # _step_layer_a_event_obligation_guard (GPT redteam BLOCK-01).
                layer_a_event_obligations_verified |= getattr(
                    result, "verified_layer_a_event_obligations", frozenset()
                )
                # Honest residuals: merge plugin-reported disclosure strings into
                # the verdict's Completeness.disclosures (same duck-typed getattr
                # idiom as the edge accounting; legacy results contribute none).
                # Accumulated BEFORE the incomplete/ok classification so a
                # could-not-conclude or failing check's residuals still surface.
                disclosures.extend(getattr(result, "disclosures", ()))
                # Clean-ERROR contract (checked BEFORE .ok): a plugin that ran cleanly
                # but cannot conclude sets incomplete=True. Record a clean-ERROR leg and
                # skip the REJECT/OK classification for this plugin.
                if getattr(result, "incomplete", False):
                    incompletes.append(
                        Verdict.incomplete(
                            VERIFIER_INCOMPLETE,
                            f"plugin {plugin_id!r} could not conclude: "
                            f"{getattr(result, 'detail', '')}",
                            check_name=f"typed_check_plugins:{plugin_id}",
                        )
                    )
                    continue
                passed = bool(result.ok)
                detail = "" if passed else getattr(result, "detail", "")
            except PluginFailed as exc:
                failures.append(
                    VerifyFailure(
                        check_name=f"typed_check_plugins:{plugin_id}",
                        reason_code="plugin_failed",
                        detail=str(exc),
                    )
                )
                continue
            except Exception as exc:  # noqa: BLE001
                # BI-4: an UNEXPECTED plugin exception (or a non-conforming result
                # missing .ok) is verifier-side — CLASSIFY, do not bare-widen. Poison
                # the whole verdict to INDETERMINATE and ABORT, carrying plugin_id +
                # stack. NEVER swallow-and-continue: a silently skipped broken check
                # risks a FALSE GREEN.
                raise VerifierError(
                    VERIFIER_UNEXPECTED_PLUGIN_EXCEPTION,
                    f"plugin {plugin_id!r}: {type(exc).__name__}: {exc}",
                ) from exc
            if not passed:
                failures.append(
                    VerifyFailure(
                        check_name=f"typed_check_plugins:{plugin_id}",
                        reason_code="plugin_failed",
                        detail=f"plugin {plugin_id!r} reported failure: {detail}",
                    )
                )

        instance_names: set[str] = {p.name for p in self._plugins if hasattr(p, "name")}
        for claimed_name in manifest.typed_checks:
            if claimed_name not in instance_names:
                failures.append(
                    VerifyFailure(
                        check_name=f"typed_check_plugins:{claimed_name}",
                        reason_code="plugin_failed",
                        detail=(
                            f"manifest.typed_checks lists {claimed_name!r} but no "
                            "matching plugin instance is registered with this "
                            "BundleVerifier — claim cannot be validated"
                        ),
                    )
                )

    # ------------------------------------------------------------------
    # Step 4a2 — present-but-unverified gates (verdict-divergence sweep)
    # ------------------------------------------------------------------
    # These previously lived ONLY in veriker/cli/verify.py, so a direct verify() consumer
    # got VerdictState.OK on claims the CLI refused (trust laundering). They are
    # moved here so library and CLI consumers reach the SAME verdict. veriker/cli/verify.py
    # keeps its own presentation loops, but they now consume the SAME evaluators
    # (one semantics) and agree with this verdict.

    def _step_extension_receipts(
        self,
        manifest: BundleManifest,
        failures: list[VerifyFailure],
        incompletes: list[Verdict],
        disclosures: list[str],
    ) -> None:
        """Dispatch each extension_receipts[kind] to its registered handler.

        A handler PASS is recorded as a prefixed Completeness disclosure (the
        C19 pass-detail channel) so the CLI can PRESENT it without re-executing
        the handler; a handler FAIL (or malformed assembly) is a REJECT leg; a
        kind with NO registered handler is present-but-UNVERIFIED → a
        clean-ERROR (could-not-conclude) leg, never a silent OK.

        Registry-snapshot discipline (same class as the RES-04 single
        manifest read, applied to verifier CONFIGURATION): the handler registry
        is copied ONCE per run and every kind is evaluated against that copy,
        so one verdict can never mix two registry states. This run's handler
        executions are also the ONLY ones — veriker/cli/verify.py presents from the
        legs/disclosures recorded here, so the printed lines and the canonical
        verdict cannot come from two different handler runs.

        A NON-DICT extension_receipts value never reaches this guard from the
        parse path: validate_top_level_field_shapes rejects it as
        MalformedManifest (present-but-malformed must not read as "no claim").
        The isinstance below is defense-in-depth for directly-constructed
        BundleManifest objects only.
        """
        receipts = manifest.extension_receipts
        if not isinstance(receipts, dict):
            return
        registry = registered_receipt_verifiers()
        for kind in sorted(receipts):
            status, reason, detail = evaluate_extension_receipt(
                kind, receipts[kind], registry=registry
            )
            if status == "PASS":
                disclosures.append(f"extension_receipt:{kind}: PASS — {detail}")
                continue
            if status == "NOT_EVALUATED":
                incompletes.append(
                    Verdict.incomplete(
                        VERIFIER_INCOMPLETE,
                        f"extension_receipt {kind!r} present but UNVERIFIED "
                        f"(no registered handler): {detail}",
                        check_name=f"extension_receipt:{kind}",
                    )
                )
                continue
            failures.append(
                VerifyFailure(
                    check_name=f"extension_receipt:{kind}",
                    reason_code=reason or "RECEIPT_REJECT",
                    detail=detail,
                )
            )

    def _step_cross_host_guard(
        self,
        manifest: BundleManifest,
        cross_host_verified: set[str],
        incompletes: list[Verdict],
    ) -> None:
        """Fail closed unless EVERY present cross-host edge was verified (red-team A1).

        Per-edge coverage accounting (verdict-divergence tribunal, ratified
        2026-06-10): each present `causal_chain.cross_host_authenticators` edge is
        keyed by content (cross_host_edge_key); a wired cross-host-verifying plugin
        reports the keys it verified in PluginResult.verified_cross_host_edges, and
        the verify() plugin loop accumulates the union into `cross_host_verified`.
        Here we assert `present_keys − cross_host_verified == ∅`. Any uncovered edge
        is could-not-conclude (clean-ERROR), never a silent OK.

        This is PROOF of coverage, not a promise: the key binds "verified" to the
        exact present edge bytes, so a plugin cannot launder an edge it did not
        verify and the generic consumer (no cross-host plugin → empty verified set)
        still fails closed. It supersedes the coarse boolean
        `verifies_cross_host_authenticators` capability marker. Cross-org COSE_Sign1
        verification itself stays in the pilot/substrate plugins (pinned
        CrossOrgKeyPolicy + stateful PeerReview walk) — importing a second COSE impl
        into this stdlib core is the two-verifier drift these findings came from;
        the core only does set-coverage bookkeeping.
        """
        # A non-dict causal_chain or non-list cross_host_authenticators never
        # reaches these guards from the parse path: validate_top_level_field_
        # shapes rejects both as MalformedManifest, so a malformed claim cannot
        # disarm this guard by failing its shape check. The isinstance guards
        # are defense-in-depth for directly-constructed BundleManifest objects;
        # an EMPTY edge list is genuinely no-claim and stays inert.
        cc = manifest.causal_chain
        if not isinstance(cc, dict):
            return
        edges = cc.get("cross_host_authenticators")
        if not isinstance(edges, list) or not edges:
            return
        present_keys = cross_host_edge_keys(edges)
        n_non_dict = sum(1 for e in edges if not isinstance(e, dict))
        uncovered = present_keys - cross_host_verified
        if not uncovered and n_non_dict == 0:
            return
        n_uncovered = len(uncovered) + n_non_dict
        incompletes.append(
            Verdict.incomplete(
                VERIFIER_INCOMPLETE,
                f"{n_uncovered} of {len(edges)} cross_host_authenticators edge(s) "
                "were NOT verified by any wired plugin (no plugin reported per-edge "
                "coverage for them). Cross-host edges MUST be verified by the "
                "substrate verifier or the per-domain pilot harness (pinned "
                "cross-org policy + stateful PeerReview walk) — could not conclude, "
                "do not accept as OK.",
                check_name="cross_host_authenticators",
            )
        )

    def _step_rederivation_pack_guard(
        self,
        bundle_dir: Path,
        manifest: BundleManifest,
        incompletes: list[Verdict],
    ) -> None:
        """Fail closed on a re_derive pack in the snapshot that nothing verified.

        A ``re_derive/*_pack.py`` is bundle-supplied Python that
        ``ReDerivationInvocationCheck`` evaluates (executing it under
        ``--unsafe-run-bundle-pack``, or — the safe default — emitting
        ``RE_DERIVATION_NOT_EXECUTED`` as a could-not-conclude leg). Whether such
        an instance is in the plugin set was decided ONLY in ``veriker/cli/verify._build_
        plugins`` from a LIVE pre-snapshot read of the tree, so two seams could
        launder a pack to GREEN: (1) a library/custom caller whose plugin set
        omits the check (``BundleVerifier(plugins=())`` runs zero plugins), and
        (2) a TOCTOU race where the pack is absent at the CLI's discovery read
        but present in the snapshot the verdict is computed over. Either way no
        ``RE_DERIVATION_NOT_EXECUTED`` is emitted and the present-but-unverified
        re-derivation rides the verdict unflagged.

        This guard restores the "recompute, don't trust the claim" boundary in
        core ``verify()``: it scans ``bundle_dir`` (the sealed snapshot) for
        packs and fails closed on any pack that NEITHER mechanism covered
        (``present_packs − covered == ∅``), mirroring the per-edge coverage
        guards above. An uncovered pack is could-not-conclude (clean-ERROR),
        never a silent OK.

        Coverage is satisfied by EITHER:
        * a wired ``ReDerivationInvocationCheck`` (duck-typed by ``name`` +
          ``pack_filename``, so the stdlib core need not import the plugin), OR
        * spec-pinned dispatch — when ``manifest.outputs`` is declared, the safe
          recompute-then-compare path (``_step_spec_pinned_dispatch``) verified
          re-derivation from the auditor-anchored spec and the in-bundle pack is
          a redundant unsafe artifact (the pilots ship it for the
          ``--unsafe-run-bundle-pack`` demonstration). Re-derivation is then NOT
          unverified, so the guard does not fire.

        An UNDECLARED pack is already a conservation REJECT (UNOWNED on-disk
        path); this guard additionally catches a pack DECLARED in
        ``manifest.files`` — STRICT_SHA-owned, so conservation passes it — in a
        bundle with NO dispatch and no invocation check (exactly the red-team
        bare-verifier / TOCTOU case).
        """
        re_derive = bundle_dir / "re_derive"
        if not re_derive.is_dir():
            return
        present_packs = {p.name for p in sorted(re_derive.glob("*_pack.py"))}
        if not present_packs:
            return
        # Spec-pinned dispatch covers re-derivation the safe way for the whole
        # bundle; a present pack is then redundant, not present-but-unverified.
        if getattr(manifest, "outputs", ()) or ():
            return
        covered = {
            getattr(plugin, "pack_filename", None)
            for plugin in self._plugins
            if getattr(plugin, "name", None) == "re_derivation_invocation"
        }
        uncovered = present_packs - covered
        if not uncovered:
            return
        incompletes.append(
            Verdict.incomplete(
                VERIFIER_INCOMPLETE,
                f"RE_DERIVATION_PACK_UNCHECKED: {len(uncovered)} re_derive pack(s) "
                f"{sorted(uncovered)!r} present in the verified bundle but covered "
                "by neither a re_derivation_invocation check nor spec-pinned "
                "dispatch (manifest declares no outputs) — the producer-supplied "
                "re-derivation path was NOT evaluated. Could not conclude; do NOT "
                "read a PASS verdict as covering re-derivation. Verify via the CLI "
                "(which wires ReDerivationInvocationCheck) or construct the check "
                "in your plugin set.",
                check_name="re_derivation_pack",
            )
        )

    def _step_causal_chain_coverage_guard(
        self,
        manifest: BundleManifest,
        causal_chain_subkeys_verified: set[str],
        incompletes: list[Verdict],
    ) -> None:
        """Close the WHOLE ``causal_chain`` field: a present sub-key never rides
        a GREEN verdict unless a wired plugin reported it verified (BLOCK-02 —
        the cross-host/fragment-anchor/stamp ``present − verified == ∅`` pattern
        generalized from ONE causal_chain sub-key to the entire field, so the
        class cannot regrow on the next sub-key nobody guarded).

        ``causal_chain`` sub-keys (``layer_a`` SCITT counter DAG,
        ``layer_b_anchors`` trusted-time anchors, ``counter_chain``,
        ``cross_host_edges``, or a pilot's own custom event chain) each carry a
        falsifiable audit-provenance claim. Before this guard, the verdict core
        reached into ``layer_a`` ONLY for the optional OF1 header leaf and
        verified the rest not at all — so a fabricated layer_a (invalid root,
        bogus chain height, forged events) or a forged layer_b_anchors
        trusted-time claim rode ``VerdictState.OK`` under both
        ``BundleVerifier()`` and the shipping CLI default plugin set (only
        ``cross_host_authenticators`` had a guard).

        Coverage is UNIVERSAL, not allowlist-gated: ``causal_chain`` is an open
        namespace (a pilot may emit its own chain), so the invariant is "every
        present sub-key is covered by SOME wired plugin", not "the sub-key name
        is on a known list". This is the strong ratchet — a forged or unknown
        future sub-key with no verifying plugin fails closed identically, no
        per-name exception. Each present sub-key is content-keyed
        (``causal_chain_subkey_key`` — name-bound sha256 over canonical JSON); a
        wired plugin reports the keys it verified in
        ``PluginResult.verified_causal_chain_subkeys`` and the plugin loop
        accumulates the union. Here ``present − verified == ∅`` or clean-ERROR;
        an unkeyable present value (directly-constructed manifest) is uncoverable
        and fails closed.

        ``cross_host_authenticators`` is the ONE excluded name — verified at the
        finer EDGE level by ``_step_cross_host_guard`` (a coarser name-level
        proof would be double jeopardy). The cryptographic semantics (SCITT
        receipt verify, TSA/Roughtime/BLS re-derivation, pilot HMAC chains) stay
        in the substrate/pilot plugins; this step is set-coverage bookkeeping
        only (the two-verifier-drift prohibition the sibling guards observe). A
        bundle with no ``causal_chain`` (or an all-empty one) asserts nothing and
        stays inert (legacy exit-0 preserved).
        """
        cc = manifest.causal_chain
        if not isinstance(cc, dict):
            # A non-dict causal_chain never reaches here from the parse path
            # (validate_top_level_field_shapes rejects it as MalformedManifest);
            # this is defense-in-depth for directly-constructed manifests.
            return

        # Universal coverage — every present sub-key must be verified.
        present_keys, n_unkeyable = accountable_causal_chain_keys(cc)
        uncovered = present_keys - causal_chain_subkeys_verified
        if uncovered or n_unkeyable:
            n_uncovered = len(uncovered) + n_unkeyable
            incompletes.append(
                Verdict.incomplete(
                    VERIFIER_INCOMPLETE,
                    f"{n_uncovered} present causal_chain sub-key structure(s) were "
                    "NOT verified by any wired plugin (no plugin reported per-sub-key "
                    "coverage). Sub-keys such as layer_a (SCITT-bound counter chain) "
                    "and layer_b_anchors (trusted-time anchors) carry audit-provenance "
                    "claims that MUST be cryptographically re-derived by their "
                    "substrate/pilot plugin — could not conclude, do not accept as OK.",
                    check_name="causal_chain",
                )
            )

    def _step_layer_a_event_obligation_guard(
        self,
        manifest: BundleManifest,
        layer_a_event_obligations_verified: set[str],
        incompletes: list[Verdict],
    ) -> None:
        """Fail closed unless EVERY present per-event layer_a obligation was
        discharged by a wired plugin (GPT redteam BLOCK-01, 2026-06-12).

        One level FINER than ``_step_causal_chain_coverage_guard``: that guard
        closes ``causal_chain`` at sub-key granularity (a present ``layer_a`` is
        covered by some plugin reporting ``subkey_coverage("layer_a")``). But a
        ``layer_a`` event may carry a SEMANTIC obligation the generic
        ``verify_bundle_layer_a`` pipeline (SCITT receipt / hash chain / Merkle /
        HMAC signature) does NOT evaluate, yet which ``validate_event_keys_str``
        ADMITS:

        * ``event_kind == "key_rotation"`` — old/new co-signatures, pre-commit
          window, emergency offline-root authorization, validity windows; the
          rotation-derived key schedule that subsequent event signatures depend
          on. Admitted-but-unenforced, the verifier marks an unauthorized key
          transition as verified immutable audit history (the reported gap).
        * ``timestamp_evidence`` present — a per-event TSA/Roughtime trusted-time
          claim nothing in the generic path re-derives.
        * ``cross_host_edge`` present — a per-event cross-host binding the
          top-level ``cross_host_authenticators`` guard does not key on.

        The single coarse ``subkey_coverage("layer_a")`` key papered over all
        three. This guard restores the ``present − verified == ∅`` discipline at
        event-field granularity: each present obligation is content-keyed
        (``event_obligation_key`` — tag-bound sha256 over the canonical event);
        a dedicated verifier (the eidas S19d rotation check, or a future
        timestamp/cross-host event verifier) reports the keys it discharged in
        ``PluginResult.verified_layer_a_event_obligations``; the plugin loop
        accumulates the union. Here ``present − verified == ∅`` or clean-ERROR;
        the GENERIC counter plugin reports none, so a bare-library consumer fails
        closed exactly as intended.

        The cryptographic verification itself stays in the substrate/pilot
        plugin (the two-verifier-drift prohibition the cross-host guard observes
        — this core step is set-coverage bookkeeping only). A bundle with no
        ``layer_a`` events, or only generic events with no obligation field,
        asserts nothing and stays inert (legacy exit-0 preserved).
        """
        cc = manifest.causal_chain
        if not isinstance(cc, dict):
            # Defense-in-depth for directly-constructed manifests; the parse path
            # already rejects a non-dict causal_chain as MalformedManifest.
            return
        layer_a = cc.get("layer_a")
        present_keys, n_unkeyable = layer_a_event_obligation_keys(layer_a)
        uncovered = present_keys - layer_a_event_obligations_verified
        if not uncovered and n_unkeyable == 0:
            return
        n_uncovered = len(uncovered) + n_unkeyable
        incompletes.append(
            Verdict.incomplete(
                VERIFIER_INCOMPLETE,
                f"{n_uncovered} present layer_a event obligation(s) "
                "(key_rotation authorization, timestamp_evidence trusted-time, "
                "and/or cross_host_edge binding) were NOT discharged by any wired "
                "plugin (no plugin reported per-event obligation coverage). The "
                "generic SCITT/chain/Merkle/HMAC pipeline admits these event "
                "fields but does NOT verify them — an unauthorized key transition "
                "or forged per-event trusted-time/cross-host claim must be "
                "re-derived by its dedicated substrate/pilot verifier — could not "
                "conclude, do not accept as OK.",
                check_name="layer_a_event_obligations",
            )
        )

    def _step_fragment_anchor_guard(
        self,
        manifest: BundleManifest,
        fragment_anchors_verified: set[str],
        incompletes: list[Verdict],
        disclosures: list[str],
    ) -> None:
        """Fail closed unless EVERY present ATTESTABLE fragment anchor was re-derived
        (RES-06 follow-up, 2026-06-11 — the cross-host per-edge pattern applied to
        quote claims).

        An anchor carrying ``content_selector.exact`` asserts "source S says 'X'"
        — a falsifiable quote claim. Before this guard, that claim was re-derived
        ONLY when a FragmentAttestationCheck plugin happened to be wired (the CLI
        wires it; ``BundleVerifier()`` defaults to NO plugins), so a library
        consumer's verdict read OK over quote claims nothing had checked —
        "quote-supported" reduced to "has a trusted CID label", the laundering
        shape RES-06 named at the producer layer.

        Accounting is PROOF of coverage, not a promise: each present attestable
        anchor is keyed by content (``fragments.attestable.fragment_anchor_key``);
        a wired plugin reports the keys it actually re-derived AND matched in
        ``PluginResult.verified_fragment_anchors``; here we assert
        ``present − verified == ∅``. Any uncovered claim is could-not-conclude
        (clean-ERROR), never a silent OK. Pure-locator anchors assert nothing
        falsifiable and impose no obligation; a non-dict anchor value is
        uncoverable and fails closed (mirrors the cross-host non-dict-edge
        accounting — the parse path rejects it, this is defense-in-depth for
        directly-constructed manifests).

        This step also emits the VE honesty disclosure: a VE-mode bundle's
        generation constraints are PRODUCER-declared; text-level quote fidelity
        is verified only through attestable anchors, so a VE verdict with zero
        attestable anchors says so on the verdict face rather than letting
        "VE" read as "text verified".
        """
        anchors = getattr(manifest, "fragment_anchors", None)
        anchors = anchors if isinstance(anchors, dict) else {}
        present = attestable_anchor_keys(anchors)
        n_non_dict = sum(1 for a in anchors.values() if not isinstance(a, dict))

        # VE honesty disclosure (independent of coverage outcome).
        sig = getattr(manifest, "output_mode_signal", None)
        if isinstance(sig, dict) and sig.get("mode") == OutputMode.VE.value:
            if present:
                disclosures.append(
                    f"output_mode:VE: generation constraints are producer-declared; "
                    f"text-level quote fidelity is verified through the "
                    f"{len(present)} attestable fragment anchor(s) in this bundle"
                )
            else:
                disclosures.append(
                    "output_mode:VE: generation constraints are producer-declared "
                    "and this bundle carries NO attestable fragment anchors — "
                    "text-level quote fidelity rests on producer-side discipline, "
                    "not on anything this verdict re-derived"
                )

        if not anchors:
            return
        uncovered = present - fragment_anchors_verified
        if not uncovered and n_non_dict == 0:
            return
        n_uncovered = len(uncovered) + n_non_dict
        incompletes.append(
            Verdict.incomplete(
                VERIFIER_INCOMPLETE,
                f"{n_uncovered} attestable fragment anchor(s) (quote claims with "
                "content_selector.exact) were NOT re-derived by any wired plugin "
                "(no plugin reported per-anchor coverage for them). A quote claim "
                "must be re-derived from the frozen source snapshot "
                "(FragmentAttestationCheck) — could not conclude, do not accept "
                "as OK.",
                check_name="fragment_anchors",
            )
        )

    def _step_stamp_claims_guard(
        self,
        manifest: BundleManifest,
        dispatch_records_verified: set[str],
        stamp_claims_verified: set[str],
        incompletes: list[Verdict],
    ) -> None:
        """Fail closed unless the bundle's dispatch-record and stamp-lattice
        claims were verified by a wired plugin (5th instance of the orphaned-
        enforcement class — tribunal 2026-06-12, the cross-host / fragment-
        anchor / assurance-profile pattern applied to §C14/§C15).

        A manifest carrying `dispatch_records` rows asserts C15 well-formedness
        obligations (record schema, op_kind enum, effect labels) and C14 row-
        stamp obligations (stamp_observed enum, signed-upgrade discipline); a
        non-None `aggregate_stamp` asserts the C14 lattice claim the schema doc
        promises is "Verifier-set, never dispatcher-trusted" (aggregate ==
        min(per-row effective stamp)). Before this guard, both were enforced
        only when the caller happened to wire StampLatticeCheck /
        DispatchRecordWellformedCheck (the CLI does; ``BundleVerifier()``
        defaults to NO plugins), so a library consumer's verdict read OK over a
        forged aggregate and garbage rows nothing had checked.

        Accounting is PROOF of coverage, not a promise, and PER-CONTRACT
        (tribunal Q1): the C15 channel carries per-record content keys
        (``stamp_claims.dispatch_record_key``); the C14 channel carries one
        whole-claim key binding the aggregate value AND the full records array
        (``stamp_claims.stamp_claim_key`` — full-array binding, tribunal Q2),
        so wiring only one plugin cannot launder the other contract and a
        plugin cannot claim content it did not read. Any uncovered claim is
        could-not-conclude (clean-ERROR), never a silent OK. A bundle carrying
        neither field makes no claim and stays inert (legacy exit-0 preserved).
        C14/C15 SEMANTICS stay in the plugins — this step is set-coverage
        bookkeeping only (two-verifier drift prohibition).
        """
        records = getattr(manifest, "dispatch_records", ()) or ()
        aggregate = getattr(manifest, "aggregate_stamp", None)
        if not records and aggregate is None:
            return

        # C15 leg — every present record element must have been audited.
        if records:
            present: set[str] = set()
            n_unkeyable = 0
            for record in records:
                key = dispatch_record_key(record)
                if key is None:
                    # Not JSON-canonicalizable (directly-constructed manifest):
                    # uncoverable by construction — fails closed below.
                    n_unkeyable += 1
                else:
                    present.add(key)
            uncovered = present - dispatch_records_verified
            if uncovered or n_unkeyable:
                n_uncovered = len(uncovered) + n_unkeyable
                incompletes.append(
                    Verdict.incomplete(
                        VERIFIER_INCOMPLETE,
                        f"{n_uncovered} of {len(records)} dispatch_records "
                        "element(s) were NOT audited by any wired plugin (no "
                        "plugin reported per-record C15 coverage for them). "
                        "dispatch_records carry §C15 well-formedness "
                        "obligations that MUST be checked "
                        "(DispatchRecordWellformedCheck) — could not conclude, "
                        "do not accept as OK.",
                        check_name="dispatch_records",
                    )
                )

        # C14 leg — the lattice claim must have been evaluated over exactly
        # these rows and exactly this aggregate. Obligation fires when rows
        # are present (row-stamp discipline) OR an aggregate is declared.
        claim_key = stamp_claim_key(aggregate, records)
        if claim_key is None or claim_key not in stamp_claims_verified:
            incompletes.append(
                Verdict.incomplete(
                    VERIFIER_INCOMPLETE,
                    f"the §C14 stamp-lattice claim (aggregate_stamp="
                    f"{aggregate!r} over {len(records)} dispatch_records "
                    "row(s)) was NOT evaluated by any wired plugin (no plugin "
                    "reported whole-claim C14 coverage). aggregate_stamp is "
                    "contract-promised as verifier-set, never "
                    "dispatcher-trusted (StampLatticeCheck) — could not "
                    "conclude, do not accept as OK.",
                    check_name="aggregate_stamp",
                )
            )

    def _step_assurance_profile_guard(
        self,
        manifest: BundleManifest,
        profiles_graded: set[tuple[str, str]],
        failures: list[VerifyFailure],
        incompletes: list[Verdict],
        disclosures: list[str],
    ) -> None:
        """The verifier never certifies the assurance LABEL without the
        obligations behind it (CC-2b D1 downgrade protection; label-downgrade
        fix, tribunal-ratified 2026-06-12).

        Before this guard, ``assurance_profile`` was parsed, folded into the
        OF1 tamper-evidence leaf, and then consulted by NOTHING on the verdict
        path — a minimal bundle declaring ``regulated-high-assurance`` with
        zero high-assurance evidence verified OK. Tamper-evidence without
        enforcement certifies the label, not the obligations.

        Semantics (mirrors the cross-host / fragment-anchor guards):

        * declaration sites disagree (top-level vs ``causal_chain.layer_a``)
          or a site is malformed → REJECT ``PROFILE_DECLARATION_CONFLICT``
          (one canonical reader, ``effective_declared_profile`` — a producer
          cannot dodge the guard by relocating or split-braining the claim);
        * declared profile unknown to the held policy (configured policy, or
          the canonical builtin lattice when none is) → REJECT
          ``PROFILE_DECLARED_UNKNOWN``;
        * verifier-held ``profile_floor`` configured → ``resolve_effective_
          profile`` admission: below / incomparable → REJECT (producer may
          raise its own bar, never select below the relying party's floor);
        * verifier-held ``completeness_policy`` configured → required-
          structure presence walk over ``R(effective) ∪ R(floor)`` → first
          absent structure REJECTs ``PROFILE_REQUIRED_STRUCTURE_ABSENT``;
        * the declared label must have been GRADED — by this core step when
          the held policy's effective obligations are all empty, otherwise by
          a wired grader plugin reporting ``(profile_id, policy_fingerprint)``
          in ``PluginResult.graded_assurance_profiles`` (fingerprint-matched
          when the verifier holds its own policy, so a permissive grader
          cannot satisfy a strict relying-party config). A declared-but-
          ungraded label is could-not-conclude (clean-ERROR,
          ``PROFILE_DECLARED_BUT_UNGRADED``), never a silent OK.

        Core owns SHAPE only: the builtin lattice carries empty ``R(P)``
        everywhere — what a profile REQUIRES is relying-party policy, injected
        via ``BundleVerifier(completeness_policy=..., profile_floor=...)``.
        A bundle declaring no profile with no floor configured is inert
        (nothing asserted, nothing owed).
        """
        declared, conflict = effective_declared_profile(manifest)
        if conflict is not None:
            failures.append(
                VerifyFailure(
                    check_name="assurance_profile",
                    reason_code=PROFILE_DECLARATION_CONFLICT,
                    detail=f"{PROFILE_DECLARATION_CONFLICT}: {conflict}",
                )
            )
            return
        floor = self._profile_floor
        if declared is None and floor is None:
            return
        policy = (
            self._completeness_policy
            if self._completeness_policy is not None
            else builtin_profile_lattice()
        )
        if declared is not None and declared not in policy.profiles:
            failures.append(
                VerifyFailure(
                    check_name="assurance_profile",
                    reason_code=PROFILE_DECLARED_UNKNOWN,
                    detail=(
                        f"{PROFILE_DECLARED_UNKNOWN}: declared assurance_profile "
                        f"{declared!r} is not a profile in the verifier-held "
                        f"policy (known: {sorted(policy.profiles)})"
                    ),
                )
            )
            return
        if floor is not None:
            effective, reason = resolve_effective_profile(
                policy, floor=floor, declared=declared
            )
            if effective is None:
                failures.append(
                    VerifyFailure(
                        check_name="assurance_profile",
                        reason_code=reason or "PROFILE_FLOOR_REJECT",
                        detail=(
                            f"{reason}: declared assurance_profile {declared!r} "
                            f"is not admissible at the verifier-held floor "
                            f"{floor!r}"
                        ),
                    )
                )
                return
        else:
            effective = declared  # not None: the no-claim/no-floor case returned
        if effective is None:
            # Equivalent to the no-claim/no-floor return above (declared and
            # floor both None) — restated here so the narrowing is explicit
            # and a future restructure of the branches cannot fall through
            # with no profile to grade.
            return
        # Required-structure presence walk (belt-and-suspenders union — the
        # floor's structures are mandatory regardless of the graded profile).
        # The builtin lattice has empty R(P) everywhere, so this is inert
        # unless the relying party injected policy content.
        required = policy.effective_required_structures(effective, floor or effective)
        for sid in _PROFILE_STRUCTURE_WALK_ORDER:
            if sid not in required:
                continue
            node: Any = manifest
            for i, key in enumerate(_PROFILE_STRUCTURE_PATHS[sid]):
                node = (
                    getattr(node, key, None)
                    if i == 0
                    else (node.get(key) if isinstance(node, dict) else None)
                )
            if node is None:
                failures.append(
                    VerifyFailure(
                        check_name="assurance_profile",
                        reason_code=PROFILE_REQUIRED_STRUCTURE_ABSENT,
                        detail=(
                            f"{PROFILE_REQUIRED_STRUCTURE_ABSENT}: required "
                            f"structure {sid!r} (at "
                            f"{'.'.join(_PROFILE_STRUCTURE_PATHS[sid])}) is "
                            f"absent, but profile {effective!r} (floor "
                            f"{floor!r}) requires it"
                        ),
                    )
                )
                return
        # Grading coverage: who actually graded this label?
        if self._completeness_policy is None:
            fp_required: str | None = None
            # Core holds no policy content, so core cannot itself grade a
            # declared label — a wired grader plugin must have.
            needs_plugin_grading = declared is not None
        else:
            fp_required = policy_fingerprint(self._completeness_policy)
            # Core graded admission + presence above; O(S) obligation content
            # is plugin work — required iff any effective obligation is
            # non-empty.
            empty = ObligationLattice()
            needs_plugin_grading = any(
                policy.obligation(effective, s) != empty
                for s in policy.required_structures(effective)
            )
        graded_label = declared if declared is not None else effective
        if needs_plugin_grading:
            covered = any(
                pid == graded_label and (fp_required is None or fp == fp_required)
                for (pid, fp) in profiles_graded
            )
            if not covered:
                incompletes.append(
                    Verdict.incomplete(
                        VERIFIER_INCOMPLETE,
                        f"{PROFILE_DECLARED_BUT_UNGRADED}: assurance_profile "
                        f"{graded_label!r} is declared but NO wired plugin "
                        "reported grading it"
                        + (
                            f" against the verifier-held policy (fingerprint "
                            f"{fp_required[:12]}…)"
                            if fp_required is not None
                            else ""
                        )
                        + ". A declared assurance label must be graded (floor "
                        "admission + required structures + obligations) by the "
                        "verifier-held policy or a wired grader plugin — could "
                        "not conclude, do not accept as OK.",
                        check_name="assurance_profile",
                    )
                )
                return
        # Green path: say on the verdict face exactly what the label means here.
        # (fp_required is non-None exactly when the verifier holds a policy.)
        if fp_required is not None:
            disclosures.append(
                f"assurance_profile: graded at {effective!r} against the "
                f"verifier-held policy (fingerprint {fp_required[:12]}…, "
                f"{len(required)} required structure(s) present"
                + (
                    ", obligations graded by wired plugin(s))"
                    if needs_plugin_grading
                    else ", no obligations declared)"
                )
            )
        elif needs_plugin_grading:
            disclosures.append(
                f"assurance_profile: {graded_label!r} graded by wired "
                "plugin(s); the verifier itself holds no completeness policy"
            )
        if declared is not None and floor is None:
            disclosures.append(
                "assurance_profile: no verifier-held floor configured — "
                "admission checked against the canonical lattice only; a "
                "relying party with a minimum tier must set profile_floor"
            )

    def _step_c18_structural(
        self,
        bundle_dir: Path,
        raw_manifest_bytes: bytes,
        manifest: BundleManifest,
        failures: list[VerifyFailure],
    ) -> None:
        """C18 verifier-identity structural gate — the library face of the CLI's
        c18_structural gate (verdict-divergence sweep follow-up, 2026-06-11).

        The structural evaluator previously ran ONLY in veriker/cli/verify.py's
        post-verify() loop (it flipped overall_ok → exit 1), so a LIBRARY
        consumer's verdict stayed OK on a bundle whose verifier_identity block
        is malformed — the same laundering seam the 2026-06-10 sweep closed for
        re-derivation / extension receipts / cross-host edges. Worse, the CLI's
        auto-on probe read ONLY raw `evidence.verifier_identity`, while
        production builders (eidas) emit the block as a TOP-LEVEL manifest key
        — so the production location escaped the CLI gate too unless the
        tripwire plugin happened to be wired. This step decides the same
        structural facts in the verdict-producing core, for BOTH documented
        locations: the top-level key (BundleManifest.verifier_identity) and the
        raw-JSON `evidence.verifier_identity` shape (which _load_manifest does
        not map onto the dataclass — hence the raw-bytes leg).

        Shared single evaluator: extensions.c18_verifier_identity.
        verify_verifier_identity_structural (stdlib-pure at import; its
        docstring names this module as an intended caller), the same function
        the VerifierIdentityTripwireCheck plugin wraps — so core, plugin, and
        substrate cannot drift. When the tripwire plugin is also wired the two
        legs are redundant-but-agreeing (same evaluator), mirroring the OF1
        Option-C posture, never divergent.

        Absent block → inert (legacy / pre-C18 bundles unaffected). Malformed
        block → REJECT legs (artifact-bad — matches the CLI's exit-1 class).
        STRUCTURAL ONLY: the self-check tripwire DISCLOSURE signal stays
        plugin-side (logging-only, never blocks) and is NOT duplicated here.
        """
        try:
            raw = json.loads(raw_manifest_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raw = None
        seen: set[str] = set()
        for shape in (manifest, raw if isinstance(raw, dict) else None):
            if shape is None:
                continue
            for reason in verify_verifier_identity_structural(bundle_dir, shape):
                if reason in seen:
                    continue
                seen.add(reason)
                failures.append(
                    VerifyFailure(
                        check_name="c18_structural",
                        # FIELD_MISSING reasons carry a ':<field>' suffix; the
                        # bare code is the stable face token, the full reason
                        # string rides in detail.
                        reason_code=reason.split(":", 1)[0],
                        detail=(
                            "verifier_identity structural verification failed: "
                            f"{reason}"
                        ),
                    )
                )

    # ------------------------------------------------------------------
    # Step 4b — deep manifest validation (ADR D5: verify() complete-by-construction)
    # ------------------------------------------------------------------

    def _step_deep_manifest_validation(
        self,
        bundle_dir: Path,
        manifest: BundleManifest,
        failures: list[VerifyFailure],
    ) -> None:
        """Run the deep manifest validators (steps 6-20 of `validate_manifest`: snapshots,
        fragment anchors, source attributes, retrieval traces, per-output manifests,
        output-mode, OF1 header) — the checks the shallow 4-step walk does NOT cover — and
        append a REJECT failure on the first artifact-bad finding.

        The deep validators are presence-gated, so this is a no-op for a bundle that
        declares none of the relevant fields (every legacy bundle). An unexpected
        (non-manifest) exception is NOT caught here: it propagates to verify()'s
        `fail_closed` boundary as a crash-ERROR (the INPUT-vs-VERIFIER seam — an artifact
        property is a REJECT; an unanticipated break is a VERIFIER_* ERROR).

        OF1 (the manifest-header leaf recompute) now runs HERE, generically, for every
        bundle. The generic step-20 path and the dedicated `of1_manifest_header_re_derivation`
        plugin compute the SAME canonical leaf (folding the declared assurance_profile +
        schema_version) via `compute_manifest_header_leaf_from_manifest`, so running both is
        redundant-but-agreeing rather than divergent (ADR §9.2 RESOLUTION, 2026-06-05, Option
        C). This INCREASES coverage: a bundle that carries an OF1 leaf but does NOT register
        the plugin now gets its OF1 leaf verified by verify() too. Hence `skip_of1_header=False`."""
        result = deep_validation_failure(manifest, bundle_dir, skip_of1_header=False)
        if result is not None:
            reason_code, detail = result
            failures.append(
                VerifyFailure(
                    check_name="deep_manifest_validation",
                    reason_code=reason_code,
                    detail=detail,
                )
            )

    # ------------------------------------------------------------------
    # Step 5 — spec-pinned type dispatch (SPEC_PINNED_DISPATCH_ARCHITECTURE)
    # ------------------------------------------------------------------

    def _step_spec_pinned_dispatch(
        self,
        bundle_dir: Path,
        manifest: BundleManifest,
        failures: list[VerifyFailure],
    ) -> None:
        """Spec-pinned, auditor-anchored, recompute-then-compare dispatch over
        manifest.outputs (Axis 1 + Axis 2). INERT unless the manifest declares
        `outputs` (0/56 baseline manifests do, so this is a no-op for every
        legacy bundle). When it engages it STRICTLY supersedes legacy
        name-dispatch for the covered outputs and AND-aggregates into the same
        failures list (never any() across the two paths — §4a.7).

        Imported lazily so the rederivation package only loads when a bundle
        actually uses it (keeps the import surface of a plain S0 verify minimal).
        """
        outputs = getattr(manifest, "outputs", ()) or ()
        if not outputs:
            return
        from .rederivation.dispatch import run_spec_pinned_dispatch

        for df in run_spec_pinned_dispatch(
            bundle_dir, manifest, self._spec_anchor, self._role_policy
        ):
            failures.append(
                VerifyFailure(
                    check_name=df.check_name,
                    reason_code=df.reason_code,
                    detail=df.detail,
                )
            )
