"""Stamp provenance lattice — C14 verifier-set discipline per the audit-bundle contract §C14.

The lattice (the ordered stamp ranks below) is the provenance-strength
ordering; effect-row vocabulary is locked separately by the effect calculus.

Layered shipped-vs-deferred disclosure (the "tabs statement"):
  Contract    — audit-bundle contract §C14.
  Plugin code — this file. Wired into veriker/cli/verify.py default plugin set.
  Enforcement scope:
    v0.1 — three sub-invariants enforced: stamp_observed shape validation,
           min-rule on aggregate_stamp, non-min composition rule rejection.
           Multi-row aggregation across mixed-stamp rows treated stamp_observed
           as authoritative; no upgrade discipline.
    v0.2 — multi-row aggregation under signed stamp upgrades. The verifier
           (V16) may write a `stamp_upgrade` field on a row when it
           successfully discharges the row's refinement obligation. The C14
           plugin computes effective_stamp_observed = upgrade.to_stamp for
           upgraded rows and aggregate_stamp = min(effective_stamp_observed
           per row). Signed upgrades require an HMAC signature from
           audit_bundle.discharge.verifier_signing.sign_stamp_upgrade
           that re-verifies under VKERNEL_VERIFIER_HMAC_KEY (mirrors the C16
           fail-closed posture). Adversarial defenses cover forge,
           cross-bundle/cross-record replay, tier-jump, from_stamp drift,
           discharge-link breakage, out-of-order timestamps, and
           sibling-list conflicts.
    v0.3 — cross-bundle upgrade propagation; rollback of upgrades when
           a stamp_observed reverts post-bundle.

Cross-file invariant (V14 + V16):
  Only audit_bundle.discharge.verifier_signing.sign_stamp_upgrade writes
  record['stamp_upgrade']. The C14 plugin enforces this by rejecting
  unsigned upgrades as STAMP_UPGRADE_FORGED (mirrors C16's
  DISCHARGE_STATUS_FORGED discipline).


"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.admission import admit_json_file
from audit_bundle.plugin import PluginResult
from audit_bundle.stamp_claims import stamp_claim_key
from audit_bundle.discharge.verifier_signing import (
    STAMP_UPGRADE_REASONS,
    VerifierSigningKey,
    extract_refine_text,
    verify_signature,
    verify_stamp_upgrade_signature,
)

# ---------------------------------------------------------------------------
# Lattice constants
# ---------------------------------------------------------------------------

STAMP_ORDER: tuple[str, ...] = (
    "UNVERIFIED",  # 0 — weakest
    "COMPOSED_HYPOTHESIS",  # 1
    "TARGET",  # 2
    "INTERNAL_BENCHMARK",  # 3
    "INTERNAL_SOURCE",  # 4
    "WEB_SOURCE",  # 5
    "CONFIRMED_EXTERNAL",  # 6 — strongest
)

STAMP_RANK: dict[str, int] = {s: i for i, s in enumerate(STAMP_ORDER)}

# Non-min aggregation sentinels are rejected by a prefix denylist over the
# `aggregate_stamp_*` namespace rather than a fixed allowlist of names
# (avg/voted/weighted/majority): an allowlist lets future schema drift adding
# `aggregate_stamp_median`, `aggregate_stamp_pareto`, `aggregateStampHarmonic`,
# etc. silently bypass the check. The denylist is case-folded and also handles
# the camelCase `aggregatestamp_*` form, admitting only the canonical singular
# `aggregate_stamp` field. (Mirrors the same fix applied on the stamp_upgrade
# namespace below.)
_CANONICAL_AGGREGATE_FIELD: str = "aggregate_stamp"
_AGGREGATE_NAMESPACE_PREFIXES: tuple[str, ...] = (
    "aggregate_stamp_",
    "aggregatestamp_",
)


def _is_aggregate_namespace_collision(key: str) -> bool:
    """Return True iff `key` looks like a non-canonical aggregate-stamp
    field. Case-insensitive over the underscore AND camelCase variants of
    the namespace. Examples that match:
      'aggregate_stamp_avg', 'aggregate_stamp_median',
      'aggregateStamp_majority', 'AGGREGATE_STAMP_VOTED',
      '_aggregate_stamp_pareto'.
    The canonical singular `aggregate_stamp` is the only admissible form.
    """
    if not isinstance(key, str):
        return False
    if key == _CANONICAL_AGGREGATE_FIELD:
        return False
    folded = key.casefold().lstrip("_")
    return any(folded.startswith(prefix) for prefix in _AGGREGATE_NAMESPACE_PREFIXES)


# Reason → required-checks registry. A hard-coded `if body_reason ==
# 'discharged':` guard would let any future upgrade reason that also requires
# a linked proof (e.g. `manual_override`, `sla_escalation`) silently bypass
# the discharge-link check unless a developer remembered to update the
# conditional. Centralizing the policy here makes adding a reason that
# requires the link one frozenset entry instead of an easy-to-miss code edit.
# New entries here are also the natural extension point for future per-reason
# additional checks (registered in the dispatch table inside _check_upgrade).
_REASONS_REQUIRING_DISCHARGE_LINK: frozenset[str] = frozenset(
    {
        "discharged",
    }
)


# Sibling-conflict guard. A fixed allowlist of sibling names
# {stamp_upgrades, stamp_upgrade_alt, stamp_upgrade_dispatcher} could be
# trivially bypassed with a fourth name like `stamp_upgrade_v2`,
# `stampUpgrade`, or `STAMP_UPGRADE`. Instead this is a denylist over the
# `stamp_upgrade`-prefix namespace: any record key whose case-folded form
# starts with `stamp_upgrade` (or its camelCase equivalent `stampupgrade`)
# but is not the canonical singular `stamp_upgrade` is treated as a
# conflict. The canonical singular itself is the only admissible upgrade
# field on a record.
_CANONICAL_UPGRADE_FIELD: str = "stamp_upgrade"
_UPGRADE_NAMESPACE_PREFIXES: tuple[str, ...] = (
    "stamp_upgrade",
    "stampupgrade",
)


def _is_upgrade_namespace_collision(key: str) -> bool:
    """Return True iff `key` looks like an upgrade field but is not the
    canonical singular form. Case-insensitive match over the underscore
    AND camelCase variants of the namespace. Examples that match:
      'stamp_upgrades', 'stamp_upgrade_v2', 'stampUpgrade', 'STAMP_UPGRADE',
      '_stamp_upgrade', 'stamp_upgrade_pending'.
    """
    if not isinstance(key, str):
        return False
    if key == _CANONICAL_UPGRADE_FIELD:
        return False
    folded = key.casefold().lstrip("_")
    return any(folded.startswith(prefix) for prefix in _UPGRADE_NAMESPACE_PREFIXES)


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


class StampLatticeCheck:
    """TypedCheck plugin enforcing the audit-bundle contract §C14 lattice
    invariants. v0.2 extends with signed-upgrade discipline.

    Constructor:
      `recheck_key` — VerifierSigningKey used to verify HMAC signatures on
        stamp_upgrade records. When None (default), the plugin operates in
        FAIL-CLOSED mode: any record carrying a stamp_upgrade is rejected
        as STAMP_UPGRADE_FORGED (mirrors the C16 fail-closed posture).
        Production deployments MUST wire a key for upgrade-bearing bundles to
        verify; bundles without upgrades verify cleanly with key=None.
    """

    name: str = "stamp_lattice"
    applies_to_files: frozenset[str] = frozenset()

    def __init__(self, *, recheck_key: VerifierSigningKey | None = None):
        self.recheck_key = recheck_key

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        records = getattr(manifest, "dispatch_records", ()) or ()
        bundle_id = getattr(manifest, "bundle_id", None)
        bundle_created_at = getattr(manifest, "created_at", None)

        # Sub-invariant 1 — verifier-set discipline: stamp_observed shape.
        # null is treated as UNVERIFIED for aggregation; non-null outside
        # STAMP_ORDER is HARD-FAIL.
        # Also pre-scan every record's keys for upgrade-namespace collisions
        # even when the canonical `stamp_upgrade` field is absent. The contract
        # rejects any case-insensitive variant in the upgrade namespace —
        # presence-of-variant is the violation, not "presence-of-variant
        # alongside canonical." Without this pre-scan, a record carrying
        # only `STAMP_UPGRADE` (no canonical) is silently ignored because
        # the per-record sibling guard sits inside the
        # `if "stamp_upgrade" in record:` branch.
        for idx, record in enumerate(records):
            if record is None:
                continue
            if not isinstance(record, dict):
                # Fail-closed type guard: a hostile non-dict dispatch_records
                # element would otherwise raise AttributeError out of the
                # plugin (record.get / record.keys) and degrade the run to a
                # VERIFIER_INTERNAL_ERROR crash instead of a recorded REJECT.
                # Returning here also shields _resolve_effective_stamps, which
                # walks the same records after this pre-scan.
                return PluginResult(
                    ok=False,
                    reason_code="DISPATCH_RECORD_MALFORMED",
                    detail=(
                        f"record[{idx}]: dispatch_records element must be a "
                        f"JSON object, got {type(record).__name__!r}"
                    ),
                    files_audited=(),
                )
            stamp_observed = record.get("stamp_observed")
            if stamp_observed is not None and stamp_observed not in STAMP_RANK:
                return PluginResult(
                    ok=False,
                    reason_code="STAMP_OBSERVED_OUT_OF_ENUM",
                    detail=(
                        f"record[{idx}]: stamp_observed={stamp_observed!r} is not in the "
                        f"recognized lattice {list(STAMP_ORDER)}"
                    ),
                    files_audited=(),
                )
            for sibling in sorted(record.keys()):
                if _is_upgrade_namespace_collision(sibling):
                    return PluginResult(
                        ok=False,
                        reason_code="STAMP_UPGRADE_CONFLICT",
                        detail=(
                            f"record[{idx}]: field {sibling!r} is in the "
                            "stamp_upgrade namespace but is not the canonical "
                            "singular `stamp_upgrade` field; only the canonical "
                            "form is admissible (presence of any variant is the "
                            "violation, regardless of whether the canonical "
                            "field is also present)"
                        ),
                        files_audited=(),
                    )

        # v0.2 — verify and resolve effective_stamp_observed per row.
        # Returns either (effective_stamps_list, n_upgrades_admitted) on
        # success, or a PluginResult on failure.
        resolved = self._resolve_effective_stamps(
            records,
            bundle_id=bundle_id,
            bundle_created_at=bundle_created_at,
        )
        if isinstance(resolved, PluginResult):
            return resolved
        effective_stamps, n_upgrades = resolved

        # Sub-invariant 2 — min-rule on aggregate_stamp computed against
        # effective stamps (not raw stamp_observed).
        # The contract requires aggregate_stamp == min(effective per row).
        # Catching only aggregate > min ("round-up") would silently admit both
        # round-down (aggregate < min, which over-promises strength of the
        # weaker side — a soundness violation) and out-of-enum / missing
        # aggregate values on non-empty bundles. So any inequality fires,
        # with a separate reason code per direction so triage can distinguish
        # an over-promise (round-up) from an under-promise (round-down) from
        # a malformed declaration (invalid).
        aggregate_stamp = getattr(manifest, "aggregate_stamp", None)

        # Out-of-enum NON-None aggregate is structurally invalid — checked
        # INDEPENDENT of row count (tribunal 2026-06-12 Q3: the previous
        # rows-gated check let a bogus aggregate over zero rows pass the
        # WIRED plugin vacuously). None remains the v0.1 "no-claim"
        # semantic — no aggregate declared, nothing to validate against the
        # min-rule. v0.3 may tighten this to require an explicit
        # declaration; v0.2 preserves backward-compat with v0.1 manifests
        # that omit the field.
        if aggregate_stamp is not None and aggregate_stamp not in STAMP_RANK:
            return PluginResult(
                ok=False,
                reason_code="STAMP_AGGREGATE_INVALID",
                detail=(
                    f"aggregate_stamp={aggregate_stamp!r} is not in the C14 "
                    f"lattice {list(STAMP_ORDER)}; cannot evaluate min-rule "
                    f"against per-row effective stamps"
                ),
                files_audited=(),
            )

        # A non-None aggregate over ZERO rows is a malformed declaration: the
        # contract defines aggregate_stamp ONLY as min(per-row effective
        # stamp), and min over the empty set is undefined — a summary claim
        # cannot exist without the rows it purports to summarize (tribunal
        # 2026-06-12 Q3 ruling; closes the wired vacuous-pass).
        if aggregate_stamp is not None and not records:
            return PluginResult(
                ok=False,
                reason_code="STAMP_AGGREGATE_INVALID",
                detail=(
                    f"aggregate_stamp={aggregate_stamp!r} declared but "
                    "dispatch_records is empty; the C14 aggregate is defined "
                    "only as min(per-row effective stamp) over a non-empty "
                    "row set — an aggregate claim over zero rows is "
                    "unsupportable"
                ),
                files_audited=(),
            )

        if records:
            observed_min = min(effective_stamps, key=lambda s: STAMP_RANK[s])

            if (
                aggregate_stamp is not None
                and STAMP_RANK[aggregate_stamp] > STAMP_RANK[observed_min]
            ):
                offending_idx = next(
                    i for i, s in enumerate(effective_stamps) if s == observed_min
                )
                return PluginResult(
                    ok=False,
                    reason_code="STAMP_AGGREGATE_ROUNDUP_DETECTED",
                    detail=(
                        f"aggregate_stamp={aggregate_stamp!r} (rank {STAMP_RANK[aggregate_stamp]}) "
                        f"exceeds per-row min={observed_min!r} (rank {STAMP_RANK[observed_min]}); "
                        f"offending row index={offending_idx}"
                    ),
                    files_audited=(),
                )

            if (
                aggregate_stamp is not None
                and STAMP_RANK[aggregate_stamp] < STAMP_RANK[observed_min]
            ):
                return PluginResult(
                    ok=False,
                    reason_code="STAMP_AGGREGATE_ROUNDDOWN_DETECTED",
                    detail=(
                        f"aggregate_stamp={aggregate_stamp!r} (rank {STAMP_RANK[aggregate_stamp]}) "
                        f"is below per-row min={observed_min!r} (rank {STAMP_RANK[observed_min]}); "
                        "the contract requires equality, not floor — declaring a weaker "
                        "aggregate than the per-row min misrepresents the bundle's "
                        "provenance composition"
                    ),
                    files_audited=(),
                )

        # Sub-invariant 3 — non-min composition rule rejection.
        # A prefix denylist over the entire `aggregate_stamp_*` namespace
        # (rather than a fixed allowlist of names) catches future schema drift
        # adding `aggregate_stamp_median`, `aggregate_stamp_pareto`, etc. by
        # construction. Check dataclass-bound fields first.
        for attr in sorted(vars(manifest)) if hasattr(manifest, "__dict__") else ():
            if _is_aggregate_namespace_collision(attr):
                return PluginResult(
                    ok=False,
                    reason_code="STAMP_AGGREGATION_RULE_REJECTED",
                    detail=(
                        f"non-min aggregation field {attr!r} is present on the "
                        "manifest object; only the canonical singular "
                        f"{_CANONICAL_AGGREGATE_FIELD!r} is admissible"
                    ),
                    files_audited=(),
                )

        # Re-read wire-format manifest.json to catch ad-hoc JSON-injected
        # fields that are stripped by the dataclass parser.
        manifest_json_path = bundle_dir / "manifest.json"
        if manifest_json_path.exists():
            try:
                raw_manifest = admit_json_file(manifest_json_path)
            except (ValueError, OSError):
                # UnicodeDecodeError is a ValueError subclass, not an OSError —
                # an invalid-UTF-8 manifest.json must degrade to the same
                # empty-dict fallback, not escape as a crash.
                raw_manifest = {}
            if isinstance(raw_manifest, dict):
                for key in sorted(raw_manifest.keys()):
                    if _is_aggregate_namespace_collision(key):
                        return PluginResult(
                            ok=False,
                            reason_code="STAMP_AGGREGATION_RULE_REJECTED",
                            detail=(
                                f"non-min aggregation field {key!r} present in "
                                "wire-format manifest.json; only the canonical "
                                f"singular {_CANONICAL_AGGREGATE_FIELD!r} is "
                                "admissible"
                            ),
                            files_audited=(),
                        )

        # Whole-claim C14 coverage (proof, not promise): the key binds the
        # aggregate value AND the full records array this check actually
        # evaluated, consumed by BundleVerifier._step_stamp_claims_guard.
        # A non-canonicalizable claim yields no key → nothing claimed → the
        # guard fails closed.
        claim_key = stamp_claim_key(aggregate_stamp, records)
        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail=(
                f"stamp lattice invariants satisfied; {len(records)} records audited; "
                f"{n_upgrades} verifier-signed upgrades admitted"
            ),
            files_audited=(),
            verified_stamp_claims=(
                frozenset({claim_key}) if claim_key is not None else frozenset()
            ),
        )

    # ------------------------------------------------------------------
    # v0.2 — effective_stamp resolution
    # ------------------------------------------------------------------

    def _resolve_effective_stamps(self, records, *, bundle_id, bundle_created_at):
        """For each record, compute effective_stamp_observed:
          - if no stamp_upgrade → effective = stamp_observed (or UNVERIFIED if None)
          - if stamp_upgrade present → run all upgrade defenses; on success,
            effective = upgrade.to_stamp; on failure, return PluginResult.
        Returns (list[str], n_upgrades_admitted) on success.
        """
        effective_stamps: list[str] = []
        n_upgrades = 0
        for idx, record in enumerate(records):
            if record is None:
                effective_stamps.append("UNVERIFIED")
                continue

            base_stamp = record.get("stamp_observed")
            base_effective = base_stamp if base_stamp is not None else "UNVERIFIED"

            if "stamp_upgrade" not in record:
                effective_stamps.append(base_effective)
                continue

            failure = self._check_upgrade(
                idx,
                record,
                base_effective,
                bundle_id=bundle_id,
                bundle_created_at=bundle_created_at,
            )
            if failure is not None:
                return failure

            upgrade = record["stamp_upgrade"]
            effective_stamps.append(upgrade["to_stamp"])
            n_upgrades += 1

        return effective_stamps, n_upgrades

    def _check_upgrade(
        self, idx, record, base_effective, *, bundle_id, bundle_created_at
    ):
        """Run all v0.2 upgrade defenses on a single record. Returns the
        failure PluginResult or None on success."""
        upgrade = record["stamp_upgrade"]

        # (Defense 0a — per-record sibling-conflict guard — is subsumed by
        #  the top-level namespace pre-scan in `check()`. The pre-scan rejects
        #  any upgrade-namespace variant on any record regardless of canonical
        #  presence, which is a strict superset of what defense 0a covered.)

        # 0b. Authoritative bundle_id required. Without a manifest-level
        #     bundle_id the cross-bundle replay defense degrades to
        #     trusting the signature's self-report. Fail-closed when the
        #     manifest is missing the binding.
        if not isinstance(bundle_id, str) or not bundle_id:
            return PluginResult(
                ok=False,
                reason_code="STAMP_UPGRADE_FORGED",
                detail=(
                    f"record[{idx}]: stamp_upgrade present but manifest carries "
                    "no bundle_id (or bundle_id is empty); cross-bundle replay "
                    "defense cannot operate without an authoritative bundle "
                    "binding from the manifest"
                ),
                files_audited=(),
            )

        # 1. Shape — must be a dict; must carry the required keys.
        if not isinstance(upgrade, dict):
            return PluginResult(
                ok=False,
                reason_code="STAMP_UPGRADE_FORGED",
                detail=(
                    f"record[{idx}]: stamp_upgrade must be a dict, "
                    f"got {type(upgrade).__name__!r}"
                ),
                files_audited=(),
            )

        # 2. Reason enum — fast reject on bogus reason values to give
        #    callers a precise message.
        body_reason = upgrade.get("upgrade_reason")
        if body_reason not in STAMP_UPGRADE_REASONS:
            return PluginResult(
                ok=False,
                reason_code="STAMP_UPGRADE_REASON_INVALID",
                detail=(
                    f"record[{idx}]: stamp_upgrade.upgrade_reason="
                    f"{body_reason!r} not in {sorted(STAMP_UPGRADE_REASONS)}"
                ),
                files_audited=(),
            )

        # 3. Body lattice check — to_stamp must exist in the lattice.
        body_to = upgrade.get("to_stamp")
        body_from = upgrade.get("from_stamp")
        if body_to not in STAMP_RANK or body_from not in STAMP_RANK:
            return PluginResult(
                ok=False,
                reason_code="STAMP_UPGRADE_FORGED",
                detail=(
                    f"record[{idx}]: stamp_upgrade.from_stamp={body_from!r} or "
                    f"to_stamp={body_to!r} not in the C14 lattice"
                ),
                files_audited=(),
            )

        # 4. FAIL-CLOSED when no key wired — mirrors the C16 fail-closed posture.
        if self.recheck_key is None:
            return PluginResult(
                ok=False,
                reason_code="STAMP_UPGRADE_FORGED",
                detail=(
                    f"record[{idx}]: stamp_upgrade present but StampLatticeCheck "
                    "was constructed without a recheck_key. Production deployments "
                    "MUST wire a VerifierSigningKey (mirrors the C16 fail-closed "
                    "posture); without "
                    "it the plugin cannot verify the HMAC and falls back to v0.1 "
                    "strict mode (no upgrades admitted)."
                ),
                files_audited=(),
            )

        # 5. HMAC verification with authoritative ground truth bindings.
        if not verify_stamp_upgrade_signature(
            record,
            key=self.recheck_key,
            bundle_id=bundle_id,
            record_idx=idx,
        ):
            return PluginResult(
                ok=False,
                reason_code="STAMP_UPGRADE_FORGED",
                detail=(
                    f"record[{idx}]: stamp_upgrade.verifier_signature failed HMAC "
                    f"verification under verifier_id={self.recheck_key.verifier_id!r}; "
                    "signature is forged, replayed across bundles/records, signed "
                    "under a different key, or the upgrade body was tampered after "
                    "signing"
                ),
                files_audited=(),
            )

        # 6. from_stamp drift — sig.from_stamp must equal the row's
        #    current stamp_observed (effective). Catches post-signing
        #    tamper of stamp_observed.
        if body_from != base_effective:
            return PluginResult(
                ok=False,
                reason_code="STAMP_UPGRADE_FORGED",
                detail=(
                    f"record[{idx}]: stamp_upgrade.from_stamp={body_from!r} drift — "
                    f"row.stamp_observed (effective) is {base_effective!r}. The "
                    "verifier signed an upgrade based on a different starting tier; "
                    "either stamp_observed was tampered after signing, or the "
                    "signature was lifted from a row with a different observed stamp."
                ),
                files_audited=(),
            )

        # 7. Out-of-order timestamp — sig.timestamp_utc must be ≤ bundle.created_at.
        # Comparison parses both timestamps to aware datetimes and compares
        # moments, NOT ISO-8601 strings. A lexical string compare is only sound
        # when both timestamps share the exact same TZ-suffix shape (Z vs
        # +00:00 vs offset, no fractional seconds): e.g. a sig timestamp
        # `2026-05-03T12:00:00.999Z` lex-compares less-than
        # `2026-05-03T12:00:00Z` (because '.' (0x2E) < 'Z' (0x5A)) even though
        # it is 999 ms LATER in real time, silently bypassing the guard.
        # _compare_timestamps accepts either str or aware datetime on either
        # side (an upstream parser may normalize manifest.created_at to a
        # datetime at load time) and fails closed when an input is
        # unrecognizable. The guard skips ONLY when one of the inputs is
        # genuinely absent / empty (legacy v0.1 manifest with no created_at,
        # or upgrade dict with no timestamp_utc).
        #
        # Defense 7's trust in `manifest.created_at` is MODE-DEPENDENT:
        #
        #   Anchored (honest-anchor):  when manifest.causal_chain.layer_a
        #     carries a non-None `manifest_header_merkle_leaf` field,
        #     `created_at` is bound into the canonical Merkle leaf via
        #     compute_manifest_header_leaf_from_manifest(bundle_id, created_at,
        #     dispatch_records_index, + folded assurance_profile/schema_version
        #     when declared) and that leaf participates in the same
        #     event_dag_merkle_root the Layer B Roughtime / TSA path anchors
        #     (C19.A + C19.B + C19.C). validate_manifest's check 20 raises
        #     ManifestHeaderLeafMismatch on any drift. A hostile sealer with
        #     the V14 HMAC key cannot shift `created_at` without breaking this
        #     chain. Trust assumption: honest-anchor (strictly weaker, more
        #     defensible than the honest-sealer mode below — the sealer's claim
        #     is bound into evidence the auditor's independent re-verification
        #     can falsify).
        #
        #   Legacy (honest-sealer):  when `manifest_header_merkle_leaf` is
        #     absent, the honest-sealer caveat applies — a hostile sealer with
        #     the V14 HMAC key can shift `created_at` forward to admit a
        #     later-than-real upgrade signature. Defense 7 is best-effort under
        #     this trust model (tracked against STAMP_UPGRADE_OUT_OF_ORDER).
        sig = upgrade.get("verifier_signature", {})
        sig_ts = sig.get("timestamp_utc")
        if bundle_created_at and sig_ts:
            ts_failure = self._compare_timestamps(idx, sig_ts, bundle_created_at)
            if ts_failure is not None:
                return ts_failure

        # 8. Discharge-link check — for any reason in
        #    _REASONS_REQUIRING_DISCHARGE_LINK (currently just 'discharged'),
        #    the row's proof field must (a) exist, (b) have obligation_sha
        #    matching the upgrade's discharge_obligation_sha, (c) have a V16
        #    verifier_signature whose HMAC re-verifies against the same
        #    recheck_key (a bare `if mac:` truthy-check would be a one-character
        #    cross-plugin contract — the HMAC must actually re-verify),
        #    (d) have proof.discharge_status == 'discharged' (not
        #    failed/timeout/unknown).
        # The per-reason gate is a registry lookup so adding a new
        # proof-requiring reason is a one-line frozenset edit, not a
        # conditional change.
        if body_reason in _REASONS_REQUIRING_DISCHARGE_LINK:
            link_failure = self._check_discharge_link(
                idx,
                record,
                upgrade,
                recheck_key=self.recheck_key,
                bundle_id=bundle_id,
            )
            if link_failure is not None:
                return link_failure

        return None

    @staticmethod
    def _compare_timestamps(idx, sig_ts, bundle_created_at):
        """Compare two ISO-8601 moments — accepting str or aware datetime
        on either side — as aware datetimes, not as strings.

        Returns a STAMP_UPGRADE_OUT_OF_ORDER PluginResult when the sig is
        strictly later than bundle_created_at, OR a STAMP_UPGRADE_FORGED
        PluginResult when either timestamp is unrecognizable (an
        unparseable string, a naive datetime, or a non-string non-datetime
        type is a forgery signal — sign_stamp_upgrade only emits
        well-formed Z-suffix UTC strings, and the manifest dataclass
        normalizes to aware UTC). Returns None on success.
        """
        sig_dt = _coerce_to_aware(sig_ts)
        bundle_dt = _coerce_to_aware(bundle_created_at)
        if sig_dt is None:
            return PluginResult(
                ok=False,
                reason_code="STAMP_UPGRADE_FORGED",
                detail=(
                    f"record[{idx}]: stamp_upgrade.verifier_signature."
                    f"timestamp_utc={sig_ts!r} is not a parseable ISO-8601 "
                    "timestamp; sign_stamp_upgrade always emits well-formed "
                    "Z-suffix UTC, so a malformed timestamp indicates the "
                    "field was written by something other than the verifier"
                ),
                files_audited=(),
            )
        if bundle_dt is None:
            return PluginResult(
                ok=False,
                reason_code="STAMP_UPGRADE_FORGED",
                detail=(
                    f"record[{idx}]: manifest.created_at={bundle_created_at!r} "
                    f"(type={type(bundle_created_at).__name__}) is not a "
                    "recognizable aware-UTC timestamp (string or datetime); "
                    "cannot resolve out-of-order ordering against an "
                    "unparseable bundle creation time"
                ),
                files_audited=(),
            )
        if sig_dt > bundle_dt:
            return PluginResult(
                ok=False,
                reason_code="STAMP_UPGRADE_OUT_OF_ORDER",
                detail=(
                    f"record[{idx}]: stamp_upgrade.verifier_signature."
                    f"timestamp_utc={sig_ts!r} parses to {sig_dt.isoformat()!r} "
                    f"which is later than manifest.created_at="
                    f"{bundle_created_at!r} ({bundle_dt.isoformat()!r}); "
                    "upgrade was applied after the bundle was sealed"
                ),
                files_audited=(),
            )
        return None

    @staticmethod
    def _check_discharge_link(idx, record, upgrade, *, recheck_key, bundle_id):
        proof = record.get("proof")
        if not isinstance(proof, dict):
            return PluginResult(
                ok=False,
                reason_code="STAMP_UPGRADE_DISCHARGE_LINK_BROKEN",
                detail=(
                    f"record[{idx}]: stamp_upgrade.upgrade_reason='discharged' "
                    "but record has no proof field"
                ),
                files_audited=(),
            )
        upgrade_obl = upgrade.get("discharge_obligation_sha", "")
        proof_obl = proof.get("obligation_sha", "")
        if not upgrade_obl or upgrade_obl != proof_obl:
            return PluginResult(
                ok=False,
                reason_code="STAMP_UPGRADE_DISCHARGE_LINK_BROKEN",
                detail=(
                    f"record[{idx}]: stamp_upgrade.discharge_obligation_sha="
                    f"{upgrade_obl!r} does not match record.proof.obligation_sha="
                    f"{proof_obl!r}"
                ),
                files_audited=(),
            )
        proof_status = proof.get("discharge_status")
        if proof_status != "discharged":
            return PluginResult(
                ok=False,
                reason_code="STAMP_UPGRADE_DISCHARGE_LINK_BROKEN",
                detail=(
                    f"record[{idx}]: stamp_upgrade.upgrade_reason='discharged' but "
                    f"record.proof.discharge_status={proof_status!r} (expected "
                    "'discharged'); the C14 upgrade can only attach to a V16-proved "
                    "refinement"
                ),
                files_audited=(),
            )
        # Cross-plugin consistency — V16 must have signed the proof.
        # Checking only that v16_sig is a dict with a truthy `mac` field would
        # be a one-character cross-plugin contract any attacker could defeat by
        # writing `proof.verifier_signature.mac = "x"`. Instead this re-runs
        # V16's verify_signature under the same recheck_key the C14 plugin
        # already holds. C14 does not duplicate C16's full re-discharge — it
        # only re-verifies the HMAC binding the proof to its (bundle, record,
        # formula, context, status). Without this, the cross-plugin
        # discharge-link invariant is hollow whenever C16 isn't wired or runs
        # after C14.
        v16_sig = proof.get("verifier_signature")
        if not isinstance(v16_sig, dict) or not v16_sig.get("mac"):
            return PluginResult(
                ok=False,
                reason_code="STAMP_UPGRADE_DISCHARGE_LINK_BROKEN",
                detail=(
                    f"record[{idx}]: stamp_upgrade.upgrade_reason='discharged' but "
                    "record.proof.verifier_signature is missing or malformed; the "
                    "C14 upgrade requires a V16-signed proof (verifier-set discipline "
                    "across both plugins)"
                ),
                files_audited=(),
            )
        # Re-verify the V16 HMAC end-to-end. Read authoritative refine_text
        # via the shared canonical helper (V14/V16/C14 all share
        # `extract_refine_text` to keep the "first output's refine" convention
        # unified across plugins). Read authoritative recheck_context from
        # proof.recheck_context (NOT from the sig dict) — same ground-truth
        # pattern V16 uses internally.
        refine_text = extract_refine_text(record)
        recheck_context = (
            proof.get("recheck_context")
            if isinstance(proof.get("recheck_context"), dict)
            else None
        )
        if not verify_signature(
            record,
            key=recheck_key,
            bundle_id=bundle_id,
            refine_text=refine_text,
            recheck_context=recheck_context,
            record_idx=idx,
        ):
            return PluginResult(
                ok=False,
                reason_code="STAMP_UPGRADE_DISCHARGE_LINK_BROKEN",
                detail=(
                    f"record[{idx}]: stamp_upgrade.upgrade_reason='discharged' "
                    "but record.proof.verifier_signature failed V16 HMAC re-"
                    f"verification under verifier_id={recheck_key.verifier_id!r}; "
                    "the V14 cross-plugin invariant requires a valid V16 "
                    "signature on the proof, not just a present one"
                ),
                files_audited=(),
            )
        return None


# ---------------------------------------------------------------------------
# Helpers — ISO-8601 parsing for out-of-order timestamp comparison
# ---------------------------------------------------------------------------


def _parse_iso8601_to_aware(s: str):
    """Parse an ISO-8601 timestamp into a timezone-aware datetime, or
    return None on parse failure. Handles the four common shapes the
    codebase emits / accepts:
      - 'YYYY-MM-DDTHH:MM:SSZ'                  (verifier-emitted canonical)
      - 'YYYY-MM-DDTHH:MM:SS+00:00' / '-05:00'  (offset notation)
      - 'YYYY-MM-DDTHH:MM:SS.ssssssZ'           (with fractional seconds)
      - 'YYYY-MM-DDTHH:MM:SS.ssssss+00:00'      (combination)
    Naive datetimes (no TZ info) are explicitly REJECTED — the v0.2
    contract specifies UTC bindings, so a missing tzinfo is a parse error.
    """
    if not isinstance(s, str) or not s:
        return None
    # Python <3.11 fromisoformat does not accept the 'Z' suffix; normalize.
    normalized = s.replace("Z", "+00:00") if s.endswith("Z") else s
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt.astimezone(timezone.utc)


def _coerce_to_aware(value):
    """Normalize a timestamp value of either type (ISO-8601 string OR
    datetime) to a timezone-aware UTC datetime. Returns None on any
    failure — empty string, unparseable string, naive datetime, or
    unrecognized type.

    A string-only comparator would silently bypass the out-of-order guard
    whenever an upstream parser normalized manifest.created_at to a `datetime`
    at load time. This coercion closes that gap by treating either input shape
    uniformly.
    """
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return None
        return value.astimezone(timezone.utc)
    if isinstance(value, str):
        return _parse_iso8601_to_aware(value)
    return None


register_typed_check("stamp_lattice")
