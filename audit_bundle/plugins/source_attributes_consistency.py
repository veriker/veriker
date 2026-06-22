"""audit_bundle/plugins/source_attributes_consistency.py — TypedCheck: source attributes consistency.

Follows the audit-bundle contract §C9 typed-check pattern.
Five consistency invariants over manifest.source_attributes:
  1. Every source_cid in source_attributes is in manifest.snapshots (orphan check).
  2. publication_class is in the v1 enum.
  3. If manifest.decision_provenance_log is set, every source_cid has at least one
     DecisionProvenance record (replay-completeness).
  4. For each entry where signed_artifact_present=True, signing_key_id must be non-null.
  5. For each entry where issuer_identity_verified=True, issuer_identifier must be non-null.
"""

from __future__ import annotations

import json
from pathlib import Path

from audit_bundle.admission import InputInadmissible
from audit_bundle.bundle_manifest import (
    UnsafeBundlePath,
    _safe_bundle_path,
    register_typed_check,
)
from audit_bundle.plugin import PluginResult
from audit_bundle.source_registry.decision_provenance import read_decisions
from audit_bundle.source_registry.properties import _V1_PUBLICATION_CLASSES


class SourceAttributesConsistencyCheck:
    name: str = "source_attributes_consistency"
    # exact-path-only: the former {"source_attributes/"} trailing-slash
    # pseudo-prefix was inert (consumed by exact match, never matched). Dropped.
    applies_to_files: frozenset[str] = frozenset()

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        """Walk manifest.source_attributes and enforce five consistency invariants."""
        attrs: dict[str, dict] = manifest.source_attributes
        files_audited: list[str] = []

        for source_cid, props in attrs.items():
            # 0. Fail-closed type guard — source_attributes values are
            # bundle-controlled and never type-validated at parse; a non-dict
            # value would raise AttributeError on the props.get() calls below
            # and degrade the run to a VERIFIER_INTERNAL_ERROR crash instead
            # of a recorded REJECT.
            if not isinstance(props, dict):
                return PluginResult(
                    ok=False,
                    reason_code="SOURCE_ATTRIBUTES_MALFORMED",
                    detail=(
                        f"source_cid {source_cid!r}: source_attributes value "
                        f"must be a JSON object, got {type(props).__name__!r}"
                    ),
                    files_audited=tuple(files_audited),
                )

            # 1. Orphan check — source_cid must have a snapshot.
            if source_cid not in manifest.snapshots:
                return PluginResult(
                    ok=False,
                    reason_code="SOURCE_ATTRIBUTES_ORPHAN",
                    detail=(
                        f"source_attributes key {source_cid!r} has no corresponding "
                        "snapshot in manifest.snapshots"
                    ),
                    files_audited=tuple(files_audited),
                )

            # 2. publication_class must be in the v1 enum.
            pub_class = props.get("publication_class", "")
            if pub_class not in _V1_PUBLICATION_CLASSES:
                return PluginResult(
                    ok=False,
                    reason_code="BAD_PUBLICATION_CLASS",
                    detail=(
                        f"source_cid {source_cid!r}: publication_class {pub_class!r} "
                        f"is not in the v1 set {sorted(_V1_PUBLICATION_CLASSES)}"
                    ),
                    files_audited=tuple(files_audited),
                )

            # 4. signed_artifact_present=True requires non-null signing_key_id.
            if props.get("signed_artifact_present") is True:
                if not props.get("signing_key_id"):
                    return PluginResult(
                        ok=False,
                        reason_code="SIGNED_BUT_NO_KEY_ID",
                        detail=(
                            f"source_cid {source_cid!r}: signed_artifact_present=True "
                            "but signing_key_id is null or absent"
                        ),
                        files_audited=tuple(files_audited),
                    )

            # 5. issuer_identity_verified=True requires non-null issuer_identifier.
            if props.get("issuer_identity_verified") is True:
                if not props.get("issuer_identifier"):
                    return PluginResult(
                        ok=False,
                        reason_code="VERIFIED_BUT_NO_IDENTIFIER",
                        detail=(
                            f"source_cid {source_cid!r}: issuer_identity_verified=True "
                            "but issuer_identifier is null or absent"
                        ),
                        files_audited=tuple(files_audited),
                    )

        # 3. Replay-completeness: every source_cid must appear in the provenance log.
        if manifest.decision_provenance_log is not None:
            # decision_provenance_log is a BUNDLE-CONTROLLED path field. This
            # plugin runs in _step_typed_check_plugins, BEFORE
            # _step_deep_manifest_validation — where the manifest-level
            # containment check for this field lives — and verify() AGGREGATES
            # failures rather than short-circuiting, so that later check cannot
            # protect this read. The containment guard must therefore live HERE,
            # at the read site, exactly as the sibling plugins do
            # (fragment_attestation / file_integrity_many_small /
            # refinement_discharge / spec_sha_pin all route bundle-controlled
            # paths through _safe_bundle_path). It fail-closes on path-escape
            # (absolute path, .. traversal, symlink leaving the tree) and on a
            # directory target, so a malicious decision_provenance_log can never
            # steer an out-of-bundle read here.
            try:
                log_path = _safe_bundle_path(
                    bundle_dir, manifest.decision_provenance_log
                )
            except UnsafeBundlePath as exc:
                return PluginResult(
                    ok=False,
                    reason_code="PROVENANCE_LOG_UNSAFE_PATH",
                    detail=(
                        f"decision_provenance_log "
                        f"{manifest.decision_provenance_log!r} is not a safe "
                        f"bundle-relative path: {exc}"
                    ),
                    files_audited=tuple(files_audited),
                )
            files_audited.append(str(log_path))

            # Build set of source_cids seen in the log. The log file content is
            # still bundle-controlled, so the read fails closed on an
            # absent/unreadable file (OSError), invalid UTF-8 / JSON
            # (UnicodeDecodeError / JSONDecodeError), or a JSONL row that is not
            # a conforming object (KeyError on a required field, TypeError on a
            # non-dict line) — a recorded REJECT, never an escape. (The path is
            # now containment-validated immediately above.)
            seen_cids: set[str] = set()
            try:
                for prov in read_decisions(log_path):
                    seen_cids.add(prov.source_cid)
            except (
                OSError,
                UnicodeDecodeError,
                json.JSONDecodeError,
                KeyError,
                TypeError,
                # read_decisions is admission-bounded (RES-11 reader leg):
                # size/depth/cardinality breaches and malformed lines arrive
                # as InputInadmissible — same structured reject lane as the
                # raw-parse failures above, never a plugin-boundary ERROR.
                InputInadmissible,
            ) as exc:
                return PluginResult(
                    ok=False,
                    reason_code="PROVENANCE_LOG_UNREADABLE",
                    detail=(
                        f"decision_provenance_log "
                        f"{manifest.decision_provenance_log!r} could not be "
                        f"read or parsed: {type(exc).__name__}: {exc}"
                    ),
                    files_audited=tuple(files_audited),
                )

            for source_cid in attrs:
                if source_cid not in seen_cids:
                    return PluginResult(
                        ok=False,
                        reason_code="PROVENANCE_MISSING",
                        detail=(
                            f"source_cid {source_cid!r} has no DecisionProvenance "
                            f"record in {manifest.decision_provenance_log!r}"
                        ),
                        files_audited=tuple(files_audited),
                    )

        checked = len(attrs)
        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail=f"all {checked} source_attributes entr{'y' if checked == 1 else 'ies'} passed consistency checks",
            files_audited=tuple(files_audited),
        )


register_typed_check("source_attributes_consistency")
