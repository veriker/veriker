"""C19 Layer B — per-batch RFC 3161 TSA + Roughtime quorum + BLS aggregation
(reference implementation, soak-then-harden).

External claim ceiling: REFERENCE IMPLEMENTATION, soak-then-harden — NOT
production-Byzantine-safe at v0.3. v0.4 absorbs later hardening findings.

──────────────────────────────────────────────────────────────────────────────
Standards bound (verifier-binary-pinned; rotation only via verifier binary
release at v0.3; C18 TUF wiring at v0.4):

  - RFC 3161 + ETSI EN 319 421/422   (regulated-high-assurance profile default;
                                      per-batch CMS-SignedData wrapper over a
                                      Merkle root of per-event hashes)
  - draft-ietf-ntp-roughtime-19      (production-standard profile default;
                                      4-server pinned ecosystem; 3-of-4 quorum;
                                      §Misbehavior pairwise interval-overlap
                                      fork detection — hard-fail, no fallback)
  - canonical Cloudflare-maintained `ecosystem.json` (snapshot 2026-05-12;
                                      Google Sandbox ABSENT — went offline
                                      2024-07-01, do NOT include)
  - BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_  (multi-TSA aggregation;
                                      proof-of-possession ciphersuite, the
                                      correctness anchor — STABLE SINCE
                                      draft-irtf-cfrg-bls-signature-04, the
                                      Ethereum-2.0 suite py_ecc implements.
                                      Source draft (-06) is the FINAL revision:
                                      last-updated 2025-11-02, auto-expired
                                      ~2026-05-06 as an I-D with NO successor
                                      and NO RFC. I-D expiry is an IETF process
                                      artifact, NOT a crypto change; the suite
                                      is unaffected. Enforced at verify time by
                                      _assert_bls_ciphersuite_binding(); see
                                      FOLLOWUP_V0_4 below.)

──────────────────────────────────────────────────────────────────────────────
Architectural split (verifier vs emitter):

  - VERIFIER surface — pure-offline. Validates SREP responses + RFC 3161 CMS
    tokens + BLS aggregates against verifier-binary-pinned trust anchors.
    Functions:
        verify_per_batch_tsa_root(...)            -> None | raises C19LayerBError
        verify_per_event_roughtime_quorum(...)    -> None | raises C19LayerBError
        enforce_anchor_window(...)                -> None | raises C19LayerBError
        multi_tsa_quorum_required(...)            -> bool   (policy lookup)
    NO network imports, NO network calls on the verifier path.

  - EMITTER helper — live network. Polls the 4 pinned Roughtime roots and
    mints test/soak fixtures.
        live_poll_roughtime_roots(...)            -> list[dict]
    NOT called by the verifier under any circumstance. Production emitters
    (internal bundle producers) wire to this helper outside this stream.

  - EMITTER assembly helper — pure (no network).
        build_layer_b_anchors_subkey(...)         -> dict
    Returns the canonical `causal_chain["layer_b_anchors"]` discriminated-
    union sub-key dict in the shape the verifier consumes.

──────────────────────────────────────────────────────────────────────────────
Bundle-supplied trust-anchor lists are IGNORED:

  The bundle MAY embed informational `acceptable_tsa_roots`, `roots_attested`,
  `quorum_count`, `required_quorum`, `anchor_window_ms` fields. The verifier
  reads NONE of them for trust decisions; it recomputes against:
        NEXI_TSA_ALLOWLIST                    (5-slot TSA allowlist)
        PINNED_ROUGHTIME_ROOTS                (4-server pinned set)
        MULTI_TSA_QUORUM_M_OF_N               (2-of-3 highest-stakes)
        ROUGHTIME_QUORUM_M_OF_N               (3-of-4 ecosystem quorum)
        MAX_ANCHOR_WINDOW_MS_PER_PROFILE      (hardcoded ceilings)
        PROFILE_MAX_RADIUS_MS                 (hardcoded RADI ceilings)
        ROUGHTIME_NONCE_DOMAIN                (nonce domain-separation label)

──────────────────────────────────────────────────────────────────────────────
`causal_chain["layer_b_anchors"]` discriminated-union sub-key:

  Sub-key of the shared `causal_chain` field in
  audit_bundle/bundle_manifest.py (this module writes to the sub-key only, NOT
  the field declaration line). Sibling sub-keys
  `causal_chain["counter_chain"]` and `causal_chain["cross_host_edges"]`
  are owned by sibling modules — DO NOT touch.

  Shape:
    {
      "per_batch_tsa_root": {                          # OPTIONAL — per-batch TSA path
        "merkle_root_hex":           <64-char hex>,
        "merkle_leaves":             [<{event_id, event_hash_hex, leaf_index}>, ...],
        "rfc3161_tokens":            [<{tsa_name, cms_token_b64, cert_chain_b64,
                                        policy_oid, imprint_algorithm, nonce_hex,
                                        gentime_iso}>, ...],
        "bls_aggregated_root_sig_b64": <BLS aggregate over merkle_root_hex>,
        "required_quorum":           {"m": int, "n": int},   # INFORMATIONAL — IGNORED
        "acceptable_tsa_roots":      [<tsa_name>, ...],      # INFORMATIONAL — IGNORED
        "batched_event_kinds":       [<event_kind>, ...]
      },
      "per_event_roughtime": [                         # OPTIONAL — per-event Roughtime path
        {
          "event_id":         <event_id>,
          "event_hash_hex":   <64-char hex>,
          "preimage_label":   "event" | "send" | "ack",
          "srep_responses":   [<{root_name, srep_bytes_b64, midp_ms, radi_ms, port}>, ...],
          "roots_attested":   [<root_name>, ...],            # INFORMATIONAL — IGNORED
          "quorum_count":     int                            # INFORMATIONAL — IGNORED
        }, ...
      ]
    }

──────────────────────────────────────────────────────────────────────────────
Honest residuals (documented; v0.4 follow-ups):

  - Full 3-US-Roughtime-server collusion (Cloudflare-Roughtime-2 + int08h +
    time.txryan.com) still passes the 3-of-4 quorum because only roughtime.se
    is EU. Test
    `TestVerifyPerEventRoughtimeQuorum::happy_path_3_us_servers_pass_quorum_documented_residual`
    binds this residual into the test suite. v0.4 path adds non-US-non-EU
    production-grade Roughtime operator and raises quorum to 4-of-5 (or
    strengthens geo-distribution requirement) when one becomes available.
    European-root outreach is post-v0.3 CALENDAR work, NOT engineering scope.

  - BLS source I-D draft-irtf-cfrg-bls-signature-06 is the FINAL revision
    (last-updated 2025-11-02; auto-expired ~2026-05-06 as an Internet-Draft;
    NO -07 and NO RFC followed — verified against the IETF datatracker
    2026-05-22). The earlier note framed this as "track the successor draft":
    there is no successor to track. The correctness boundary is the
    proof-of-possession CIPHERSUITE (BLS_CIPHERSUITE_ID), stable since draft-04
    and pinned + enforced here — NOT the I-D's liveness. v0.4 action is to
    monitor for a CFRG successor / RFC, not to chase a ship-blocking pin update.

  - `placeholder-tsa-5` allowlist slot unfilled at v0.3; operator selection
    deferred to v0.4 calendar work.

──────────────────────────────────────────────────────────────────────────────
Substrate dependencies:

    cryptography>=42    # RFC 3161 CMS parsing + X.509 cert chain validation
                        # + Ed25519 SREP verify
    py_ecc>=7           # BLS aggregation verification
    cbor2>=5.6          # deterministic CBOR encoding for the nonce-binding
                        # preimage; not in stdlib

Where these deps are absent, the test suite gates the BLS / CBOR cases on
`pytest.importorskip("py_ecc")` / `pytest.importorskip("cbor2")`.

──────────────────────────────────────────────────────────────────────────────


"""

from __future__ import annotations

from typing import Final


# ──────────────────────────────────────────────────────────────────────────
# Anchor-window ceilings per assurance profile (a 0ms window is physically
# impossible — per-batch TSA closes within a 100ms target batching window).
# Hardcoded; rotatable only via verifier
# binary release (OS-level code signing trust boundary). Bundle-supplied
# `anchor_window_ms` is IGNORED — verifier enforces this table.
# ──────────────────────────────────────────────────────────────────────────
MAX_ANCHOR_WINDOW_MS_PER_PROFILE: Final[dict[str, int]] = {
    "offline-auditor-minimal": 86_400_000,  # 24h — OTS daily anchor only
    "production-standard": 60_000,  # 60s — Roughtime quorum every k=10 events
    "regulated-high-assurance": 100,  # 100ms target batching window — per-batch TSA closes within this
}


# ──────────────────────────────────────────────────────────────────────────
# Per-profile Roughtime RADI ceiling. An SREP whose RADI exceeds the ceiling
# for the assurance profile is rejected.
# ──────────────────────────────────────────────────────────────────────────
PROFILE_MAX_RADIUS_MS: Final[dict[str, int]] = {
    "offline-auditor-minimal": 10_000,
    "production-standard": 100,
    "regulated-high-assurance": 50,
}


# ──────────────────────────────────────────────────────────────────────────
# NEXI-curated TSA allowlist.
#
# Five-slot allowlist: 4 production-grade eIDAS Qualified TSA operators +
# 1 deferred placeholder. Multi-TSA 2-of-3 quorum required for highest-
# stakes events (stamp emissions, evidence-set freezes); single-TSA from
# this allowlist is sufficient for ordinary regulated events.
#
# v0.4 rotation: TUF role `nexi-c19-tsa-roots` (eIDAS Qualified Trust List
# subset). TUF wiring itself is C18 / v0.4 scope.
#
# Entries reference each operator's eIDAS QTL entry by canonical name;
# the certificate-chain pin is computed at verifier-binary build time from
# the operator's published TSA certificate. The chain ships in the verifier
# binary under OS-level code signing (Sigstore BYO-TUF precedent applied to
# the eIDAS QTL snapshot).
# ──────────────────────────────────────────────────────────────────────────
NEXI_TSA_ALLOWLIST: Final[tuple[str, ...]] = (
    "digicert-tsa",  # DigiCert TSA (eIDAS Qualified; CA/Browser Forum)
    "globalsign-tsa",  # GlobalSign TSA (eIDAS Qualified)
    "cellnex-tsa",  # Cellnex (EU-domiciled TSA; eIDAS Qualified)
    "entrust-tsa",  # Entrust TSA (eIDAS Qualified)
    "placeholder-tsa-5",  # Deferred placeholder slot — operator selection deferred to v0.4 calendar work
)


# ──────────────────────────────────────────────────────────────────────────
# Highest-stakes event kinds that require multi-TSA 2-of-3 quorum at
# regulated-high-assurance profile (per the Layer B per-event-kind policy
# table).
# ──────────────────────────────────────────────────────────────────────────
HIGHEST_STAKES_EVENT_KINDS: Final[frozenset[str]] = frozenset(
    {
        "stamp_emission",
        "evidence_set_freeze",
    }
)


# Multi-TSA quorum threshold for HIGHEST_STAKES_EVENT_KINDS at
# regulated-high-assurance profile.
MULTI_TSA_QUORUM_M_OF_N: Final[tuple[int, int]] = (2, 3)  # 2 of 3


# ──────────────────────────────────────────────────────────────────────────
# TSA OPERATOR-ID namespace (verifier-pinned, eIDAS-QTL-anchored).
#
# The multi-TSA quorum exists to require INDEPENDENT operators (resist single-
# operator collusion/compromise). Distinctness MUST therefore be keyed on
# real-world OPERATOR identity, NOT the raw `tsa_name` string a token carries:
# a single legal operator running (or an attacker minting) two tokens under two
# different `tsa_name` labels that resolve to the SAME operator would otherwise
# fill two quorum slots alone. This map collapses `tsa_name` aliases to one
# operator-ID so distinctness counts operators, not labels.
#
# Operator-ID is anchored to the eIDAS QTL LEGAL-ENTITY identifier (the QTSP's
# external trust-list identity — auditor-anchored, not a NEXI-internal label and
# not the issuing-CA DN, since CA != operator). The bare "distinctness is over
# operator-ID, not tsa_name" invariant lives in the SUBSTRATE
# (verify_per_batch_tsa_root below); this map is the pinned sibling-constant to
# NEXI_TSA_ALLOWLIST. Profile thresholds stay in the pilot contract.
#
# HONESTY BOUNDARY (mirrors the CA/BLS pin posture): the VALUES below are
# SYNTHETIC stand-ins keyed `qtl:eu-euid:PENDING-V0.4:<operator>` — the real
# eIDAS QTL EUID/VAT per operator is pinned at production verifier-build time.
# What is load-bearing NOW is the STRUCTURE (one stable external-authority
# handle per legal operator, 1:1 with the four real allowlist operators so every
# clean verdict is unchanged) — not the placeholder string. `placeholder-tsa-5`
# is intentionally UNMAPPED: an allowlisted-but-unmapped TSA does NOT fill a
# quorum slot (fail-closed; never falls back to tsa_name-string distinctness).
#
# MONOTONICITY (documented now, mechanically enforced at v0.4 TUF rotation):
# across verifier-binary epochs this map may SPLIT one operator-ID into two (a
# TSA business genuinely spinning off) but may NEVER MERGE two previously-
# distinct operator-IDs into one — a merge would retroactively shrink a past
# bundle's quorum and invalidate already-issued attestations. The map is static
# and binary-pinned at v0.3 (no rotation path), so monotonicity is trivially
# held; the no-merge guard lands with the TUF rotation wiring that can actually
# mutate it.
NEXI_TSA_OPERATOR_ID: Final[dict[str, str]] = {
    "digicert-tsa": "qtl:eu-euid:PENDING-V0.4:digicert",
    "globalsign-tsa": "qtl:eu-euid:PENDING-V0.4:globalsign",
    "cellnex-tsa": "qtl:eu-euid:PENDING-V0.4:cellnex",
    "entrust-tsa": "qtl:eu-euid:PENDING-V0.4:entrust",
    # placeholder-tsa-5: intentionally absent — unmapped → not counted (fail-closed).
}


# ──────────────────────────────────────────────────────────────────────────
# Roughtime pinned ecosystem (4 servers; canonical Cloudflare-maintained
# `ecosystem.json` snapshot 2026-05-12).
#
# Google Roughtime / Sandbox is ABSENT from ecosystem.json — went offline
# 2024-07-01. Do NOT add.
#
# Cloudflare-Roughtime-2 MUST be pinned to `:2003` NOT `:2002`. The `:2002`
# Cloudflare endpoint was decommissioned; polling :2002 results in a SILENT
# quorum failure (connection refused or response from a different key).
# The v0.3 verifier rejects any SREP whose metadata claims root_name =
# "cloudflare-roughtime-2" but port = 2002 with ROUGHTIME_PORT_DECOMMISSIONED.
# This is a load-bearing detail — fixture set + verifier both encode it.
#
# v0.4 rotation: TUF role `nexi-c19-rt-roots`.
# ──────────────────────────────────────────────────────────────────────────
PINNED_ROUGHTIME_ROOTS: Final[tuple[dict, ...]] = (
    {
        "name": "cloudflare-roughtime-2",
        "address": "roughtime.cloudflare.com",
        "port": 2003,  # NOT 2002 (decommissioned) — silent quorum failure on wrong port
        "pubkey_b64": "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg=",
        "jurisdiction": "US",
        "operator_org": "Cloudflare, Inc.",
    },
    {
        "name": "int08h-roughtime",
        "address": "roughtime.int08h.com",
        "port": 2002,
        "pubkey_b64": "AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE=",
        "jurisdiction": "US",
        "operator_org": "int08h LLC",
    },
    {
        "name": "roughtime-se",
        "address": "roughtime.se",
        "port": 2002,
        "pubkey_b64": "S3AzfZJ5CjSdkJ21ZJGbxqdYP/SoE8fXKY0+aicsehI=",
        "jurisdiction": "EU-SE",  # Stockholm; STUPI AB atomic-clock-rooted
        "operator_org": "STUPI AB",
    },
    {
        "name": "time-txryan-com",
        "address": "time.txryan.com",
        "port": 2002,
        "pubkey_b64": "iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=",
        "jurisdiction": "US",
        "operator_org": "Tx Ryan (independent operator)",
    },
)


# Roughtime quorum threshold: 3-of-4 of the pinned set (tightened from 2-of-4).
# NOTE: only roughtime.se is EU — a coalition of 3
# US servers (Cloudflare-Roughtime-2 + int08h + time.txryan.com) still passes
# the 3-of-4 quorum. This is a DOCUMENTED HONEST RESIDUAL; the v0.4 path adds
# a non-US-non-EU production-grade Roughtime operator (raises quorum to 4-of-5
# or strengthens geo-distribution requirement) when one becomes available.
# European-root outreach is post-v0.3 CALENDAR work, NOT engineering scope.
ROUGHTIME_QUORUM_M_OF_N: Final[tuple[int, int]] = (3, 4)


# Roughtime SREP nonce-binding domain-separation label.
# expected_nonce = sha256(deterministic_cbor(preimage) || ROUGHTIME_NONCE_DOMAIN)
# Domain separation prevents an SREP minted for one preimage_label
# ("event"|"send"|"ack") from being replayed against another. The label is
# baked into the preimage at the emitter side via cbor({"label": preimage_label,
# "preimage": <bytes>}); the verifier reconstructs symmetrically.
ROUGHTIME_NONCE_DOMAIN: Final[bytes] = b"nexi/audit/v0.3/roughtime"


# ──────────────────────────────────────────────────────────────────────────
# BLS aggregation pin.
#
# Multi-TSA quorum at root level aggregates each contributing TSA's BLS
# signature over `merkle_root_hex` into a single `bls_aggregated_root_sig_b64`
# field, verified with py_ecc's G2ProofOfPossession.FastAggregateVerify.
#
# CORRECTNESS ANCHOR = the ciphersuite, NOT the source I-D's liveness.
# `BLS_CIPHERSUITE_ID` is the proof-of-possession ciphersuite that fixes the
# actual signature bytes. It has been STABLE SINCE draft-04 (it is the
# Ethereum-2.0 suite) and is exactly the DST py_ecc implements. We pin it here
# and enforce the binding at verify time (`_assert_bls_ciphersuite_binding`),
# so a py_ecc upgrade that silently changed the suite fails closed instead of
# verifying under an unpinned ciphersuite.
#
# `BLS_SIGNATURE_VERSION` records the source I-D for provenance only (it is NOT
# passed to py_ecc and does not affect any byte). draft-...-06 is the FINAL
# revision: last-updated 2025-11-02, auto-expired ~2026-05-06 as an I-D, with
# NO -07 and NO RFC (verified against the IETF datatracker 2026-05-22). I-D
# expiry is an IETF process artifact — drafts lapse after ~6 months unless
# refreshed — and is independent of the ciphersuite's stability. There is no
# successor to "track"; the v0.4 action is to MONITOR for a future CFRG
# successor / RFC, not to update a ship-blocking pin.
# ──────────────────────────────────────────────────────────────────────────
BLS_CIPHERSUITE_ID: Final[str] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
BLS_SIGNATURE_VERSION: Final[str] = (
    "draft-irtf-cfrg-bls-signature-06"  # provenance only
)
BLS_SIGNATURE_LAST_UPDATED: Final[str] = "2025-11-02"  # I-D last-updated date
BLS_SIGNATURE_EXPIRED_AT: Final[str] = (
    "2026-05-06"  # I-D auto-expiry (~6mo after last-updated); final revision, no successor
)


# ──────────────────────────────────────────────────────────────────────────
# v0.4 follow-up tracker. One additional SOAK_FEEDBACK entry is appended once
# the verifier ships.
# ──────────────────────────────────────────────────────────────────────────
FOLLOWUP_V0_4: Final[tuple[str, ...]] = (
    "BLS_SOURCE_ID_FINAL_NO_SUCCESSOR — draft-irtf-cfrg-bls-signature-06 is the FINAL revision (last-updated 2025-11-02; auto-expired ~2026-05-06 as an I-D; NO -07, NO RFC — verified against the IETF datatracker 2026-05-22). Correctness is bound to the proof-of-possession CIPHERSUITE (BLS_CIPHERSUITE_ID), stable since draft-04 and enforced at verify time by _assert_bls_ciphersuite_binding(); it is NOT bound to the I-D's liveness. v0.4 action = MONITOR for a future CFRG successor / RFC and re-pin the ciphersuite ID if (and only if) one ever changes the suite — this is NOT a ship-blocking item. (Corrected 2026-05-22: the earlier 'MUST track successor draft' framing assumed a successor that does not exist, and dated the expiry to the I-D's last-updated date.)",
    "NON_US_NON_EU_ROUGHTIME_OPERATOR — 3 of 4 pinned Roughtime roots are US-org-operated (Cloudflare-Roughtime-2 + int08h + time.txryan.com); roughtime.se is the sole EU root; full 3-US-server collusion still passes 3-of-4 quorum. v0.4 path adds non-US-non-EU production-grade operator and raises quorum to 4-of-5 (or strengthens geo-distribution requirement) when one becomes available. European-root outreach is post-v0.3 calendar work, NOT engineering scope.",
    "PLACEHOLDER_TSA_5 — `placeholder-tsa-5` slot in NEXI_TSA_ALLOWLIST is unfilled at v0.3; operator selection deferred to v0.4 calendar work",
    "TUF_ROTATION_WIRING — pinned constants (PINNED_ROUGHTIME_ROOTS, NEXI_TSA_ALLOWLIST, NEXI_TSA_OPERATOR_ID, per-TSA BLS pubkeys) currently rotate only via verifier binary release; v0.4 wires them through C18 TUF roles (`nexi-c19-tsa-roots` for TSA + BLS + operator-ID; `nexi-c19-rt-roots` for Roughtime). TUF wiring itself is C18 scope.",
    "TSA_OPERATOR_ID_EUID_PINNING — NEXI_TSA_OPERATOR_ID keys the multi-TSA quorum's distinctness on the eIDAS QTL legal-entity identifier. At v0.3 the values are SYNTHETIC `qtl:eu-euid:PENDING-V0.4:<operator>` stand-ins (1:1 with the four real allowlist operators, so clean verdicts are unchanged); production verifier-build pins each operator's real eIDAS QTL EUID/VAT sourced from the EU Trust List snapshot, alongside the CA/BLS pins. Auditor reproduces the map from the eIDAS trust list and checks it against the verifier binary.",
    "TSA_OPERATOR_ID_MONOTONE_NAMESPACE — the NEXI_TSA_OPERATOR_ID namespace MUST be monotone across verifier-binary epochs: a future map update may SPLIT one operator-ID into two (a TSA business genuinely spinning off) but may NEVER MERGE two previously-distinct operator-IDs into one (a merge retroactively shrinks a past bundle's quorum and invalidates already-issued attestations — corporate M&A must retire the old IDs and mint a new one, NOT collapse them). The map is static and binary-pinned at v0.3 (no rotation path → monotonicity trivially held); the mechanical no-merge guard (append-only epoch-stamped store + unit test) lands with the v0.4 TUF rotation wiring that can actually mutate the map.",
    "SOAK_FEEDBACK — once the verifier ships, production emitter wiring lands as a follow-up; soak findings from the first 30 days feed the v0.4 substrate hardening pass (findings absorption + non-US-non-EU Roughtime operator + TUF rotation).",
)


# ──────────────────────────────────────────────────────────────────────────
# Reason-code-shaped exception classes. Each subclass name IS the substrate
# error code consumers match on (one failure mode = one code per the
# substrate taxonomy). DO NOT add ad-hoc raises; every failure raises one
# of these or is a substrate bug.
# ──────────────────────────────────────────────────────────────────────────


class C19LayerBError(Exception):
    """Base class for all Layer B verification failures.

    Each subclass's name is the substrate error code consumers match on.
    Adding a new subclass is a substrate-level decision (matches a new
    distinct failure mode) — NOT a verifier-impl convenience.
    """


class TSA_NONCE_MISSING(C19LayerBError):
    pass


class TSA_WEAK_ALGORITHM(C19LayerBError):
    pass  # SHA-1 imprint rejected


class TSA_IMPRINT_MISMATCH(C19LayerBError):
    pass


class TSA_CERT_CHAIN_REJECTED(C19LayerBError):
    pass


class TSA_POLICY_OID_NOT_ALLOWED(C19LayerBError):
    pass


class TSA_NOT_IN_ALLOWLIST(C19LayerBError):
    pass


class TSA_QUORUM_INSUFFICIENT_FOR_HIGHEST_STAKES(C19LayerBError):
    pass


class BLS_AGGREGATE_VERIFICATION_FAILED(C19LayerBError):
    pass


class BLS_AGGREGATE_MISSING_FOR_QUORUM(C19LayerBError):
    pass


class ROUGHTIME_QUORUM_INSUFFICIENT(C19LayerBError):
    pass


class ROUGHTIME_FORK_DETECTED(C19LayerBError):
    pass


class ROUGHTIME_NONCE_BINDING_MISMATCH(C19LayerBError):
    pass


class ROUGHTIME_RADI_EXCEEDS_PROFILE_MAX(C19LayerBError):
    pass


class ROUGHTIME_ROOT_NOT_IN_PINNED_SET(C19LayerBError):
    pass


class ROUGHTIME_SREP_SIGNATURE_INVALID(C19LayerBError):
    pass


class ROUGHTIME_PORT_DECOMMISSIONED(C19LayerBError):
    pass


class ANCHOR_WINDOW_EXCEEDS_PROFILE_CEILING(C19LayerBError):
    pass


class TRUSTED_TIME_INCONSISTENT(C19LayerBError):
    """Cross-structure check: the bundle's trusted-time anchors are
    each individually sound but jointly admit no instant — their uncertainty
    windows have an empty intersection (e.g. a TSA genTime and a Roughtime midp a
    year apart). Present-AND-sound per structure != coherent as a SET."""

    pass


# ──────────────────────────────────────────────────────────────────────────
# Private helpers + production-pinned placeholder maps (v0.4 fills via
# C18 TUF roles `nexi-c19-tsa-roots` / `nexi-c19-rt-roots`). The TSA-CA /
# BLS maps are empty placeholders at v0.3; the Roughtime set is populated.
# Tests / demonstration pilots monkeypatch the `_TEST_OVERRIDE_TSA_CA_PEM`
# / `_TEST_OVERRIDE_BLS_PUBKEYS` / `_TEST_OVERRIDE_ROUGHTIME_ROOTS` module
# attributes so production keys are never reached; each override resolver
# logs `_OVERRIDE_MARKER` so the swap is self-announcing across ALL THREE
# pinned-anchor classes (no silent Roughtime-root substitution).
# ──────────────────────────────────────────────────────────────────────────

import logging as _logging

_logger = _logging.getLogger(__name__)
_OVERRIDE_MARKER = (
    "TEST FIXTURE OVERRIDES PINNED CONSTANTS — production keys never reached"
)

_PINNED_TSA_CA_CERTS_PEM: dict[str, str] = {}
_PINNED_TSA_BLS_PUBKEYS: dict[str, bytes] = {}

# ETSI EN 319 421/422 policy OID allowlist (verifier-pinned subset).
_ETSI_POLICY_OID_ALLOWLIST: tuple[str, ...] = (
    "0.4.0.2023.1.1",  # ETSI EN 319 421 baseline policy
    "0.4.0.194112.1.0",  # ETSI EN 319 422 BTSP policy
)


def _get_pinned_tsa_ca_pem(tsa_name: str) -> str | None:
    """Resolve the pinned CA cert PEM for a TSA. At v0.3 production has no
    pinned cert; tests monkeypatch `_TEST_OVERRIDE_TSA_CA_PEM` as a single
    PEM (test-only TSAs share a CA in the fixture-mint). v0.4 wires per-
    TSA pins through TUF role `nexi-c19-tsa-roots`.

    Logs the override marker once per call when the override path is in
    effect — substrate-level audit telemetry that the production trust
    anchors were NOT consulted on this verification."""
    override = globals().get("_TEST_OVERRIDE_TSA_CA_PEM")
    if override is not None:
        _logger.info("%s (tsa_ca_pem; tsa=%s)", _OVERRIDE_MARKER, tsa_name)
        return override
    return _PINNED_TSA_CA_CERTS_PEM.get(tsa_name)


def _get_pinned_bls_pubkey(tsa_name: str) -> bytes | None:
    """Resolve the pinned BLS pubkey for a TSA. Tests monkeypatch
    `_TEST_OVERRIDE_BLS_PUBKEYS` with a dict of name→pubkey_bytes.
    v0.4 wires the production map through TUF role `nexi-c19-tsa-roots`.

    Logs the override marker once per call when the override path is in
    effect — substrate-level audit telemetry."""
    override = globals().get("_TEST_OVERRIDE_BLS_PUBKEYS")
    if override is not None:
        _logger.info("%s (bls_pubkey; tsa=%s)", _OVERRIDE_MARKER, tsa_name)
        return override.get(tsa_name)
    return _PINNED_TSA_BLS_PUBKEYS.get(tsa_name)


def _get_operator_id(tsa_name: str) -> str | None:
    """Resolve the eIDAS-QTL-anchored OPERATOR-ID for an allowlisted TSA name.
    Returns None for an allowlisted-but-unmapped name — the
    caller must NOT count a None toward quorum distinctness (fail-closed; see
    NEXI_TSA_OPERATOR_ID). Unlike the CA/BLS pins this is a non-secret namespace
    label, so the production map is populated (not an empty placeholder); tests
    monkeypatch `_TEST_OVERRIDE_TSA_OPERATOR_ID` with a name→operator_id dict to
    install alias collisions (two names → one operator) without re-minting.

    Logs the override marker when the override path is in effect — substrate
    audit telemetry that the production operator namespace was NOT consulted."""
    override = globals().get("_TEST_OVERRIDE_TSA_OPERATOR_ID")
    if override is not None:
        _logger.info("%s (operator_id; tsa=%s)", _OVERRIDE_MARKER, tsa_name)
        return override.get(tsa_name)
    return NEXI_TSA_OPERATOR_ID.get(tsa_name)


def _resolve_pinned_roughtime_roots() -> tuple[dict, ...]:
    """Resolve the pinned Roughtime ecosystem. Tests / demonstration pilots
    monkeypatch `_TEST_OVERRIDE_ROUGHTIME_ROOTS` with synthetic roots; when
    that override is in effect the override marker is logged — symmetric with
    `_get_pinned_tsa_ca_pem` / `_get_pinned_bls_pubkey` so a swapped Roughtime
    root set self-announces that production roots were NOT consulted, instead
    of being silent. v0.4 wires the production set through TUF role
    `nexi-c19-rt-roots`.

    Unlike the TSA-CA / BLS maps (empty placeholders at v0.3), the production
    Roughtime set is populated, so the non-override fallback returns the real
    `PINNED_ROUGHTIME_ROOTS` constant."""
    override = globals().get("_TEST_OVERRIDE_ROUGHTIME_ROOTS")
    if override is not None:
        _logger.info("%s (roughtime_roots)", _OVERRIDE_MARKER)
        return override
    return PINNED_ROUGHTIME_ROOTS


def _recompute_merkle_root(merkle_leaves: list[dict]) -> str:
    """Recompute the per-batch Merkle root the same way the fixture-mint
    does (and the same way production emitters must): sha256 over the
    canonical-CBOR concatenation of per-event hash bytes. v0.3 reference-
    implementation Merkle recipe (NOT a binary Merkle tree; v0.4 substrate
    hardening adopts a proper binary tree)."""
    import hashlib
    import cbor2

    leaves = [bytes.fromhex(leaf["event_hash_hex"]) for leaf in merkle_leaves]
    blob = cbor2.dumps(leaves, canonical=True)
    return hashlib.sha256(blob).hexdigest()


def _expected_roughtime_nonce(preimage_label: str, preimage: bytes) -> bytes:
    """Nonce-binding: sha256(deterministic_cbor({"label", "preimage"})
    || ROUGHTIME_NONCE_DOMAIN). Verifier and emitter MUST use this exact
    recipe."""
    import hashlib
    import cbor2

    cbor_blob = cbor2.dumps(
        {"label": preimage_label, "preimage": preimage}, canonical=True
    )
    return hashlib.sha256(cbor_blob + ROUGHTIME_NONCE_DOMAIN).digest()


def _parse_tsa_token_payload(token: dict) -> dict:
    """Decode the v0.3 reference-implementation CMS-shape token envelope
    (cms_token_b64 holds canonical-JSON payload bytes)."""
    import base64
    import json

    payload_bytes = base64.b64decode(token["cms_token_b64"])
    return json.loads(payload_bytes.decode("ascii"))


def _verify_tsa_token_cert_chain_and_signature(token: dict) -> None:
    """Path-validate the TSA signing cert to the pinned CA + check
    id-kp-timeStamping EKU + verify the RSA-PKCS1v15-SHA256 signature
    over the canonical-JSON payload. Raises TSA_CERT_CHAIN_REJECTED on
    any failure."""
    import base64
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    tsa_name = token["tsa_name"]

    # placeholder-tsa-5: name reservation only, no cert pinned at v0.3.
    if tsa_name == "placeholder-tsa-5":
        raise TSA_CERT_CHAIN_REJECTED(
            f"TSA '{tsa_name}' is a reserved placeholder slot with no pinned cert at v0.3"
        )

    ca_pem = _get_pinned_tsa_ca_pem(tsa_name)
    if ca_pem is None:
        raise TSA_CERT_CHAIN_REJECTED(f"no pinned CA cert for TSA '{tsa_name}'")

    try:
        ca_cert = x509.load_pem_x509_certificate(ca_pem.encode("ascii"))
        bundle_ca_cert = x509.load_pem_x509_certificate(
            token["ca_chain_pem"].encode("ascii")
        )
        signing_cert = x509.load_pem_x509_certificate(
            token["signing_cert_pem"].encode("ascii")
        )
    except (ValueError, KeyError) as exc:
        raise TSA_CERT_CHAIN_REJECTED(f"cert chain parse failure: {exc}") from None

    # Bundle's CA must match the pinned CA exactly (subject + pubkey identity
    # — a different CA cert is a non-pinned trust path).
    if bundle_ca_cert.subject != ca_cert.subject:
        raise TSA_CERT_CHAIN_REJECTED("bundle CA subject does not match pinned CA")
    if (
        bundle_ca_cert.public_key().public_numbers()
        != ca_cert.public_key().public_numbers()
    ):
        raise TSA_CERT_CHAIN_REJECTED("bundle CA pubkey does not match pinned CA")

    # Signing cert must chain to bundle CA (which we just confirmed == pinned).
    if signing_cert.issuer != ca_cert.subject:
        raise TSA_CERT_CHAIN_REJECTED("signing cert issuer does not match CA subject")
    try:
        ca_cert.public_key().verify(
            signing_cert.signature,
            signing_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            signing_cert.signature_hash_algorithm,
        )
    except InvalidSignature:
        raise TSA_CERT_CHAIN_REJECTED(
            "signing cert sig does not verify under CA"
        ) from None

    # EKU: id-kp-timeStamping required.
    try:
        ext = signing_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        if x509.ObjectIdentifier("1.3.6.1.5.5.7.3.8") not in ext.value:
            raise TSA_CERT_CHAIN_REJECTED("signing cert missing id-kp-timeStamping EKU")
    except x509.ExtensionNotFound:
        raise TSA_CERT_CHAIN_REJECTED("signing cert missing EKU extension") from None

    # Verify signature over payload bytes.
    payload_bytes = base64.b64decode(token["cms_token_b64"])
    signature = base64.b64decode(token["signature_b64"])
    try:
        signing_cert.public_key().verify(
            signature,
            payload_bytes,
            padding.PKCS1v15(),
            crypto_hashes.SHA256(),
        )
    except InvalidSignature:
        raise TSA_CERT_CHAIN_REJECTED(
            "token signature does not verify under signing cert"
        ) from None


def _verify_tsa_token(token: dict, *, recomputed_merkle_root_hex: str) -> str:
    """Run all per-token substrate checks. Returns the tsa_name on success.
    Raises the distinct substrate exception on the FIRST failed check (one
    failure = one code; ordering chosen so the strictest substrate-level
    rejection wins)."""
    payload = _parse_tsa_token_payload(token)

    # 1. Hash algorithm — SHA-1 rejected (R6 weak-algo class).
    hash_alg = payload["messageImprint"]["hashAlgorithm"]
    if hash_alg.lower() == "sha1":
        raise TSA_WEAK_ALGORITHM(f"messageImprint.hashAlgorithm='{hash_alg}' rejected")

    # 2. Nonce — must be present.
    if payload.get("nonce_hex") is None:
        raise TSA_NONCE_MISSING("RFC 3161 token has no nonce")

    # 3. tsa_name claim — must be in NEXI_TSA_ALLOWLIST (bundle-supplied
    # acceptable_tsa_roots IGNORED).
    tsa_name = payload["tsa_name"]
    if tsa_name not in NEXI_TSA_ALLOWLIST:
        raise TSA_NOT_IN_ALLOWLIST(f"tsa_name='{tsa_name}' not in NEXI_TSA_ALLOWLIST")

    # 4. Policy OID — must be in ETSI EN 319 421/422 allowlist.
    if payload["policyOid"] not in _ETSI_POLICY_OID_ALLOWLIST:
        raise TSA_POLICY_OID_NOT_ALLOWED(
            f"policyOid='{payload['policyOid']}' not in ETSI EN 319 421/422 allowlist"
        )

    # 5. Imprint mismatch — recomputed merkle vs token imprint.
    if payload["messageImprint"]["hashedMessage_hex"] != recomputed_merkle_root_hex:
        raise TSA_IMPRINT_MISMATCH(
            "token messageImprint.hashedMessage does not match recomputed Merkle root"
        )

    # 6. Cross-check the wrapper's `tsa_name` matches the payload's claim
    # (caller may have tampered with the wrapper without re-signing the payload).
    if token.get("tsa_name") != tsa_name:
        raise TSA_NOT_IN_ALLOWLIST(
            f"wrapper tsa_name='{token.get('tsa_name')}' "
            f"does not match payload tsa_name='{tsa_name}'"
        )

    # 7. Cert-chain path + EKU + signature.
    _verify_tsa_token_cert_chain_and_signature({**token, **{"tsa_name": tsa_name}})

    return tsa_name


def _parse_srep(srep_b64: str) -> tuple[bytes, bytes, dict]:
    """Decode the transmitted SREP envelope produced by the fixture-mint.
    Returns (srep_inner_bytes, signature, srep_inner_dict).
    Raises ROUGHTIME_SREP_SIGNATURE_INVALID on parse failure."""
    import base64
    import cbor2

    try:
        transmitted = base64.b64decode(srep_b64)
        pkt = cbor2.loads(transmitted)
        srep_inner_bytes = pkt["srep"]
        signature = pkt["sig"]
        srep_inner = cbor2.loads(srep_inner_bytes)
    except (ValueError, KeyError, cbor2.CBORDecodeError) as exc:
        raise ROUGHTIME_SREP_SIGNATURE_INVALID(
            f"SREP packet parse failure: {exc}"
        ) from None
    return srep_inner_bytes, signature, srep_inner


def _verify_srep(srep: dict, *, assurance_profile: str, expected_nonce: bytes) -> str:
    """Run all per-SREP substrate checks. Returns the validated pinned
    root_name on success. Raises the distinct substrate exception on the
    first failed check."""
    import base64
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519

    # 0. Forward-unknown discriminator (fail-closed at v0.3).
    if "kind" in srep and srep["kind"] not in (None, "roughtime"):
        raise ROUGHTIME_ROOT_NOT_IN_PINNED_SET(
            f"SREP carries unknown discriminator kind='{srep['kind']}' — "
            f"forward-unknown evidence shape rejected at v0.3 (fail-closed)"
        )

    # 1. Pinned-root lookup (bundle-supplied roots_attested IGNORED).
    claimed_name = srep["root_name"]
    pinned_root: dict | None = None
    for root in _resolve_pinned_roughtime_roots():
        if root["name"] == claimed_name:
            pinned_root = root
            break
    if pinned_root is None:
        raise ROUGHTIME_ROOT_NOT_IN_PINNED_SET(
            f"root_name='{claimed_name}' not in PINNED_ROUGHTIME_ROOTS"
        )

    # 2. Port-decommissioned trap (Cloudflare-Roughtime-2 :2002 → silent
    # failure; v0.3 verifier rejects explicitly).
    bundle_port = srep.get("port", pinned_root["port"])
    if claimed_name == "cloudflare-roughtime-2" and bundle_port != 2003:
        raise ROUGHTIME_PORT_DECOMMISSIONED(
            f"Cloudflare-Roughtime-2 polled on port {bundle_port}; "
            f"only :2003 is in service (:2002 was decommissioned)"
        )

    # 3. RADI ceiling per profile.
    radi_ms = srep["radi_ms"]
    radi_ceiling = PROFILE_MAX_RADIUS_MS[assurance_profile]
    if radi_ms > radi_ceiling:
        raise ROUGHTIME_RADI_EXCEEDS_PROFILE_MAX(
            f"SREP RADI={radi_ms}ms exceeds profile '{assurance_profile}' "
            f"ceiling {radi_ceiling}ms"
        )

    # 4. Signature verification under the pinned pubkey.
    srep_inner_bytes, signature, srep_inner = _parse_srep(srep["srep_bytes_b64"])
    pinned_pk_raw = base64.b64decode(pinned_root["pubkey_b64"])
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pinned_pk_raw).verify(
            signature,
            srep_inner_bytes,
        )
    except InvalidSignature:
        raise ROUGHTIME_SREP_SIGNATURE_INVALID(
            f"SREP signature does not verify under pinned pubkey for '{claimed_name}'"
        ) from None

    # 5. Nonce binding.
    srep_nonce = srep_inner.get("NONC")
    if srep_nonce != expected_nonce:
        raise ROUGHTIME_NONCE_BINDING_MISMATCH(
            f"SREP NONC does not bind to recomputed expected_nonce "
            f"(nonce domain-separation enforced)"
        )

    return claimed_name


def _check_pairwise_misbehavior(sreps: list[dict]) -> None:
    """draft-19 §Misbehavior pairwise interval-overlap check.

    Each SREP defines a time interval [MIDP - RADI, MIDP + RADI]. The
    substrate-level invariant: for ANY two SREPs i, j the intervals MUST
    overlap (intersection ≠ ∅). Two intervals [a, b] and [c, d] overlap
    iff `a <= d AND c <= b`. Violating EITHER direction = fork detected
    = hard-fail (no silent fallback to TSA — per scoping doc).

    Iterates ALL ordered pairs (i != j) so the violation fires regardless
    of SREP order in the bundle.
    """
    n = len(sreps)
    for i in range(n):
        midp_i = sreps[i]["midp_ms"]
        radi_i = sreps[i]["radi_ms"]
        for j in range(n):
            if i == j:
                continue
            midp_j = sreps[j]["midp_ms"]
            radi_j = sreps[j]["radi_ms"]
            # Interval [midp_i - radi_i, midp_i + radi_i] must overlap
            # [midp_j - radi_j, midp_j + radi_j]. Check left-endpoint of
            # i against right-endpoint of j.
            if (midp_i - radi_i) > (midp_j + radi_j):
                raise ROUGHTIME_FORK_DETECTED(
                    f"draft-19 §Misbehavior: SREP[{i}] interval "
                    f"[{midp_i - radi_i}, {midp_i + radi_i}] does not overlap "
                    f"SREP[{j}] interval [{midp_j - radi_j}, {midp_j + radi_j}] "
                    f"— fork detected, hard-fail (no fallback to TSA)"
                )


# ──────────────────────────────────────────────────────────────────────────
# Verifier surface (pure-offline; NO network).
# ──────────────────────────────────────────────────────────────────────────


def _assert_bls_ciphersuite_binding() -> None:
    """Fail closed unless the installed py_ecc verifies under the pinned BLS
    proof-of-possession ciphersuite (`BLS_CIPHERSUITE_ID`).

    The recorded standards string (`BLS_SIGNATURE_VERSION`) is inert provenance
    metadata — it is never passed to py_ecc and does not influence a single
    signature byte. The actual correctness anchor is the ciphersuite / DST that
    py_ecc's `G2ProofOfPossession` applies, which fixes the hash-to-curve domain
    and therefore the verified bytes. That suite is stable since
    draft-irtf-cfrg-bls-signature-04 (it is the Ethereum-2.0 suite); the -06
    I-D's expiry does not touch it. This check binds the recorded claim to
    library behavior: a py_ecc upgrade that silently changed the DST is caught
    here instead of verifying aggregates under an unpinned ciphersuite.
    """
    from py_ecc.bls import G2ProofOfPossession as bls

    actual = getattr(bls, "DST", None)
    expected = BLS_CIPHERSUITE_ID.encode("ascii")
    if actual != expected:
        raise BLS_AGGREGATE_VERIFICATION_FAILED(
            "py_ecc BLS ciphersuite drift: installed DST "
            f"{actual!r} != pinned {expected!r} ({BLS_CIPHERSUITE_ID}); "
            "refusing to verify a BLS aggregate under an unpinned ciphersuite"
        )


def verify_per_batch_tsa_root(
    layer_b_anchors: dict,
    *,
    assurance_profile: str,
    expected_merkle_root_hex: str,
) -> None:
    """Verify the per-batch RFC 3161 TSA + BLS aggregation path.

    Post-condition on success: returns None. On failure: raises the
    appropriate substrate-defined exception with a DISTINCT error code
    from the set: TSA_NONCE_MISSING, TSA_WEAK_ALGORITHM, TSA_IMPRINT_MISMATCH,
    TSA_CERT_CHAIN_REJECTED, TSA_POLICY_OID_NOT_ALLOWED, TSA_NOT_IN_ALLOWLIST,
    TSA_QUORUM_INSUFFICIENT_FOR_HIGHEST_STAKES, BLS_AGGREGATE_VERIFICATION_FAILED,
    BLS_AGGREGATE_MISSING_FOR_QUORUM.

    Verifier-binary-pinned trust anchors win over bundle-supplied; the
    bundle-supplied `required_quorum` and `acceptable_tsa_roots` fields
    are IGNORED.
    """
    import base64

    per_batch = layer_b_anchors.get("per_batch_tsa_root")
    if per_batch is None:
        # Caller orchestrates per-profile policy — absence of the per-batch
        # path is a different-step concern (the Roughtime path may carry
        # the evidence instead).
        return

    # Recompute Merkle root from merkle_leaves (bundle-supplied merkle_root_hex
    # is INFORMATIONAL; the verifier recomputes).
    merkle_leaves = per_batch["merkle_leaves"]
    recomputed_root = _recompute_merkle_root(merkle_leaves)
    if recomputed_root != expected_merkle_root_hex:
        raise TSA_IMPRINT_MISMATCH(
            "recomputed Merkle root does not match expected_merkle_root_hex"
        )
    if per_batch.get("merkle_root_hex") != recomputed_root:
        raise TSA_IMPRINT_MISMATCH(
            "bundle merkle_root_hex does not match recomputed root"
        )

    # Per-token substrate checks.
    verified_tsa_names: list[str] = []
    tokens = per_batch.get("rfc3161_tokens", [])
    for token in tokens:
        verified_name = _verify_tsa_token(
            token,
            recomputed_merkle_root_hex=recomputed_root,
        )
        verified_tsa_names.append(verified_name)

    # Multi-TSA quorum for highest-stakes events at regulated profile.
    batched_event_kinds = per_batch.get("batched_event_kinds", [])
    highest_stakes_present = any(
        kind in HIGHEST_STAKES_EVENT_KINDS for kind in batched_event_kinds
    )
    if highest_stakes_present and assurance_profile == "regulated-high-assurance":
        m_required, _n = MULTI_TSA_QUORUM_M_OF_N
        # distinct_verified (by tsa_name) drives BLS pubkey resolution below;
        # the QUORUM COUNT is over distinct OPERATOR-IDs so two
        # tsa_name aliases of ONE legal operator cannot fill two quorum slots.
        # An allowlisted-but-unmapped name resolves to None and is NOT counted
        # (fail-closed; never falls back to tsa_name-string distinctness).
        distinct_verified = sorted(set(verified_tsa_names))
        distinct_operators = {
            op
            for op in (_get_operator_id(name) for name in verified_tsa_names)
            if op is not None
        }
        if len(distinct_operators) < m_required:
            raise TSA_QUORUM_INSUFFICIENT_FOR_HIGHEST_STAKES(
                f"highest-stakes event_kinds {sorted(set(batched_event_kinds) & HIGHEST_STAKES_EVENT_KINDS)} "
                f"require {m_required}-of-{_n} INDEPENDENT-OPERATOR TSA quorum at "
                f"regulated-high-assurance; only {len(distinct_operators)} distinct "
                f"verified TSA operator(s) present across {len(distinct_verified)} "
                f"verified token name(s) — distinctness is over the eIDAS-QTL "
                f"operator-ID namespace, not the tsa_name string (unmapped "
                f"allowlisted names are not counted)"
            )
        # BLS aggregate is mandatory for highest-stakes quorum.
        bls_b64 = per_batch.get("bls_aggregated_root_sig_b64")
        if not bls_b64:
            raise BLS_AGGREGATE_MISSING_FOR_QUORUM(
                "highest-stakes regulated event requires bls_aggregated_root_sig_b64"
            )
        try:
            agg_sig = base64.b64decode(bls_b64)
        except Exception as exc:
            raise BLS_AGGREGATE_VERIFICATION_FAILED(
                f"bls_aggregated_root_sig_b64 not valid base64: {exc}"
            ) from None

        from py_ecc.bls import G2ProofOfPossession as bls

        # Bind the recorded standards claim to actual library behavior before
        # trusting any aggregate (BLS_CIPHERSUITE_ID; stable since draft-04).
        _assert_bls_ciphersuite_binding()

        pubkeys: list[bytes] = []
        for name in distinct_verified:
            pk = _get_pinned_bls_pubkey(name)
            if pk is None:
                raise BLS_AGGREGATE_VERIFICATION_FAILED(
                    f"no pinned BLS pubkey for verified TSA '{name}'"
                )
            pubkeys.append(pk)

        msg = bytes.fromhex(recomputed_root)
        try:
            ok = bls.FastAggregateVerify(pubkeys, msg, agg_sig)
        except Exception as exc:
            raise BLS_AGGREGATE_VERIFICATION_FAILED(
                f"BLS aggregate verification raised: {exc}"
            ) from None
        if not ok:
            raise BLS_AGGREGATE_VERIFICATION_FAILED(
                "BLS aggregate signature does not verify under contributing TSAs' pinned BLS pubkeys"
            )


def verify_per_event_roughtime_quorum(
    layer_b_anchors: dict,
    *,
    assurance_profile: str,
    expected_preimage_by_event_id: dict[str, bytes],
) -> None:
    """Verify the per-event Roughtime quorum + nonce-binding path.

    Post-condition on success: returns None. On failure: raises with a
    DISTINCT error code from: ROUGHTIME_QUORUM_INSUFFICIENT,
    ROUGHTIME_FORK_DETECTED, ROUGHTIME_NONCE_BINDING_MISMATCH,
    ROUGHTIME_RADI_EXCEEDS_PROFILE_MAX, ROUGHTIME_ROOT_NOT_IN_PINNED_SET,
    ROUGHTIME_SREP_SIGNATURE_INVALID, ROUGHTIME_PORT_DECOMMISSIONED.

    For each per-event entry: recomputes
        expected_nonce = sha256(deterministic_cbor(expected_preimage_by_event_id[event_id])
                                || ROUGHTIME_NONCE_DOMAIN)
    and rejects any SREP that does not bind to
    expected_nonce. 3-of-4 quorum per ROUGHTIME_QUORUM_M_OF_N. Pairwise
    MIDP-RADI fork check per draft-19 §Misbehavior — hard-fail, no
    silent fall-back to TSA absent TSA evidence.

    Verifier-binary-pinned trust anchors win over bundle-supplied; the
    bundle-supplied `roots_attested` and `quorum_count` fields are
    IGNORED.
    """
    entries = layer_b_anchors.get("per_event_roughtime")
    if entries is None:
        return

    for entry in entries:
        event_id = entry["event_id"]
        preimage_label = entry["preimage_label"]
        preimage = expected_preimage_by_event_id[event_id]
        expected_nonce = _expected_roughtime_nonce(preimage_label, preimage)

        sreps_raw = entry["srep_responses"]
        verified_root_names: list[str] = []
        verified_sreps_for_pairwise: list[dict] = []

        for srep in sreps_raw:
            verified_name = _verify_srep(
                srep,
                assurance_profile=assurance_profile,
                expected_nonce=expected_nonce,
            )
            verified_root_names.append(verified_name)
            verified_sreps_for_pairwise.append(srep)

        # Pairwise §Misbehavior fork detection — hard-fail on any
        # non-overlap. Runs on verified SREPs only (a bogus SREP can't
        # masquerade as a fork because it was rejected earlier).
        _check_pairwise_misbehavior(verified_sreps_for_pairwise)

        # 3-of-4 ecosystem quorum (tightened from 2-of-4).
        # Distinct pinned roots, NOT srep_count (multiple SREPs from same
        # root collapse to one for quorum purposes).
        m_required, n_total = ROUGHTIME_QUORUM_M_OF_N
        distinct_pinned_roots = len(set(verified_root_names))
        if distinct_pinned_roots < m_required:
            raise ROUGHTIME_QUORUM_INSUFFICIENT(
                f"event_id='{event_id}': "
                f"only {distinct_pinned_roots} distinct pinned Roughtime root(s) "
                f"attested; require {m_required}-of-{n_total}"
            )


def enforce_anchor_window(
    assurance_profile: str,
    *,
    bundle_anchor_window_ms: int | None,  # informational only; ignored by verifier
    observed_anchor_window_ms: int,
) -> None:
    """Enforce hardcoded anchor-window ceiling per profile (bundle metadata is
    not in the trust path; verifier uses MAX_ANCHOR_WINDOW_MS_PER_PROFILE).

    Post-condition on success: returns None. On failure raises with error
    code ANCHOR_WINDOW_EXCEEDS_PROFILE_CEILING.
    """
    # bundle_anchor_window_ms is informational only; the verifier uses
    # the hardcoded table.
    ceiling = MAX_ANCHOR_WINDOW_MS_PER_PROFILE[assurance_profile]
    if observed_anchor_window_ms > ceiling:
        raise ANCHOR_WINDOW_EXCEEDS_PROFILE_CEILING(
            f"observed anchor window {observed_anchor_window_ms}ms exceeds "
            f"profile '{assurance_profile}' ceiling {ceiling}ms"
        )


def _gentime_iso_to_ms(value: object) -> int | None:
    """Parse an RFC 3161 `genTime_iso` ('YYYY-MM-DDThh:mm:ssZ') to epoch ms.
    Returns None on any malformed value (the convergence obligation is a
    CROSS-anchor check, not a parse gate — a malformed genTime is the TSA
    path's concern)."""
    if not isinstance(value, str):
        return None
    from datetime import datetime, timezone

    try:
        t = value.strip()
        if t.endswith("Z"):
            t = t[:-1] + "+00:00"
        dt = datetime.fromisoformat(t)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except ValueError:
        return None


def extract_trusted_time_windows(
    layer_b_anchors: dict, *, assurance_profile: str
) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    """Extract the trusted-time uncertainty windows the bundle's anchors assert,
    as `[lo, hi]` epoch-ms closed intervals. Returns `(tsa_windows,
    roughtime_windows)`.

    - **TSA** per-batch RFC 3161 `genTime`: a point assertion, widened by the
      profile's own `MAX_ANCHOR_WINDOW_MS_PER_PROFILE[P]` ceiling `W` →
      `[g - W, g + W]`. Using the profile's *declared max anchor span* as the
      tolerance judges cross-anchor agreement against the SAME slack the profile
      already permits one anchor to span — a principled, profile-pinned bound,
      not an arbitrary constant. (Resolves the "TSA window: point or bounded
      jitter?" design question.)
    - **Roughtime** SREP: the protocol-native `[midp_ms - radi_ms,
      midp_ms + radi_ms]`.

    Only well-formed, decodable time values are returned; malformed/absent
    anchors are silently skipped — each anchor's own per-structure check raises
    its distinct code; convergence is purely the CROSS-anchor obligation.
    """
    w = MAX_ANCHOR_WINDOW_MS_PER_PROFILE.get(assurance_profile, 0)
    tsa_windows: list[tuple[int, int]] = []
    batch = layer_b_anchors.get("per_batch_tsa_root")
    if isinstance(batch, dict):
        for tok in batch.get("rfc3161_tokens", []) or []:
            if not isinstance(tok, dict) or "cms_token_b64" not in tok:
                continue
            try:
                payload = _parse_tsa_token_payload(tok)
            except Exception:
                continue
            g = _gentime_iso_to_ms(
                payload.get("genTime_iso") if isinstance(payload, dict) else None
            )
            if g is not None:
                tsa_windows.append((g - w, g + w))
    roughtime_windows: list[tuple[int, int]] = []
    for entry in layer_b_anchors.get("per_event_roughtime") or []:
        if not isinstance(entry, dict):
            continue
        for srep in entry.get("srep_responses", []) or []:
            if not isinstance(srep, dict):
                continue
            midp = srep.get("midp_ms")
            radi = srep.get("radi_ms")
            if isinstance(midp, int) and isinstance(radi, int):
                roughtime_windows.append((midp - radi, midp + radi))
    return tsa_windows, roughtime_windows


def verify_trusted_time_convergence(
    layer_b_anchors: dict, *, assurance_profile: str
) -> None:
    """Substrate cross-structure obligation `O(SET)` — trusted-time convergence.

    The per-structure validators (`verify_per_batch_tsa_root`,
    `verify_per_event_roughtime_quorum`) check each anchor family in ISOLATION.
    Two individually-sound anchors can still assert mutually contradictory times
    (a TSA `genTime` and a Roughtime `midp` a year apart): present-and-sound per
    structure is NOT the same as coherent as a SET. This binds the set — the
    required anchor windows must JOINTLY admit at least one instant `t`.

    Post-condition on success: returns None. On an empty global intersection:
    raises `TRUSTED_TIME_INCONSISTENT`.

    Fires only when BOTH a TSA `genTime` AND a Roughtime window are extractable —
    otherwise there is no cross-family pair to contradict, so TSA-only,
    Roughtime-only, and non-`genTime`-bearing shapes are vacuously coherent and
    pass (back-compat preserved for every existing C19.C consumer).

    Scope: the BARE non-empty-intersection invariant is a SUBSTRATE soundness
    obligation — re-mintable, binding ALL C19.C consumers, hard-fail. The
    `created_at`∈union and static anti-stale cutoff legs are PROFILE/policy
    obligations and live in the relying party's completeness contract
    (`ProfileFloorGateCheck`).
    now-relative recency is DEFERRED (`freshness_evaluated=False`) — a
    re-derivation verifier proves internal coherence, not real-time freshness.
    """
    tsa_windows, roughtime_windows = extract_trusted_time_windows(
        layer_b_anchors, assurance_profile=assurance_profile
    )
    if not tsa_windows or not roughtime_windows:
        return  # no cross-family pair to cross-check → vacuously coherent
    all_windows = tsa_windows + roughtime_windows
    lo = max(window[0] for window in all_windows)
    hi = min(window[1] for window in all_windows)
    if lo > hi:
        raise TRUSTED_TIME_INCONSISTENT(
            f"trusted-time anchors do not jointly admit any instant: "
            f"max(window lows)={lo}ms > min(window highs)={hi}ms "
            f"(TSA windows={tsa_windows}, Roughtime windows={roughtime_windows}) "
            f"— individually-sound anchors are mutually incoherent as a SET"
        )


def multi_tsa_quorum_required(event_kind: str, assurance_profile: str) -> bool:
    """Return True iff the (event_kind, assurance_profile) tuple requires
    multi-TSA 2-of-3 quorum (HIGHEST_STAKES_EVENT_KINDS at
    `regulated-high-assurance` profile per the Layer B per-event-kind
    policy table).
    """
    return (
        event_kind in HIGHEST_STAKES_EVENT_KINDS
        and assurance_profile == "regulated-high-assurance"
    )


# ──────────────────────────────────────────────────────────────────────────
# Emitter-side helper (NOT verifier surface; LIVE network). Used by
# production bundle producers (internal bundle producers) and the
# fixture-mint helper. The verifier never invokes this — the verifier
# validates the embedded SREPs offline.
# ──────────────────────────────────────────────────────────────────────────


def live_poll_roughtime_roots(
    preimage: bytes,
    *,
    preimage_label: str,  # "event" | "send" | "ack" — nonce domain-separation label
    timeout_s: float = 5.0,
) -> list[dict]:
    """EMITTER-SIDE ONLY — live network helper for minting Roughtime SREP
    fixtures.

    NOT called by the verifier under any circumstance. Polls each entry in
    PINNED_ROUGHTIME_ROOTS with
        nonce = sha256(deterministic_cbor({"label": preimage_label,
                                           "preimage": preimage}) ||
                       ROUGHTIME_NONCE_DOMAIN)
    Returns a list of SREP response dicts in the
    `srep_responses` shape consumed by `verify_per_event_roughtime_quorum`.

    Production emitters (internal bundle producers) call this at
    bundle-creation time to embed Roughtime evidence; the verifier never
    invokes it (the verifier validates the embedded responses offline).
    """
    import os
    import warnings

    if os.environ.get("NEXI_VERIFIER_OFFLINE_ONLY"):
        warnings.warn(
            "live_poll_roughtime_roots called with NEXI_VERIFIER_OFFLINE_ONLY set — "
            "the verifier path MUST NOT invoke this; check the call stack.",
            stacklevel=2,
        )

    # v0.3 reference implementation: the live poll is a thin shim around
    # what production emitters (internal bundle producers) wire to
    # the actual ecosystem.json Roughtime servers. The exact UDP/TCP wire
    # protocol is draft-19 RESP packet shape — outside the substrate
    # verifier surface (verifier validates the EMBEDDED responses offline).
    #
    # The reference helper here is intentionally a stub that documents the
    # contract; production wiring lands as a follow-up (see the FOLLOWUP_V0_4
    # SOAK_FEEDBACK entry).
    raise NotImplementedError(
        "live_poll_roughtime_roots is the emitter-side live-network shim. "
        "v0.3 reference implementation: production wiring (internal bundle producers / "
        "soak harnesses) lands as a follow-up. Use the "
        "fixture-mint helpers in tests/fixtures/c19c/mint_fixtures.py for "
        "test + soak SREP minting until then."
    )


# ──────────────────────────────────────────────────────────────────────────
# Emitter-side assembly helper (pure; NOT live network). Production bundle
# producers (internal bundle producers) call this to assemble the
# `causal_chain["layer_b_anchors"]` discriminated-union sub-key in a
# substrate-compliant shape; the verifier reads the resulting sub-key via
# verify_per_batch_tsa_root + verify_per_event_roughtime_quorum.
# ──────────────────────────────────────────────────────────────────────────


def build_layer_b_anchors_subkey(
    *,
    per_batch_tsa_root: dict | None = None,
    per_event_roughtime: list[dict] | None = None,
) -> dict:
    """Return the canonical `causal_chain["layer_b_anchors"]` discriminated-
    union sub-key dict. Either / both keys may be present; the verifier
    handles each path independently.

    This is the EMITTER-side assembly helper — production bundle producers
    (internal bundle producers) call this to embed Layer B
    evidence; the verifier (`verify_per_batch_tsa_root` /
    `verify_per_event_roughtime_quorum`) reads the resulting sub-key.

    Validation here is structural-shape only (the right keys exist with
    the right types); cryptographic validation runs at the verifier
    surface against verifier-binary-pinned trust anchors.
    """
    out: dict = {}
    if per_batch_tsa_root is not None:
        out["per_batch_tsa_root"] = per_batch_tsa_root
    if per_event_roughtime is not None:
        out["per_event_roughtime"] = per_event_roughtime
    return out
