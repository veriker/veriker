"""C14 v3 — Rigor profile parameterization (schema reservation only at v0.3).

Substrate (verifier pipeline) DEFERRED to v0.4. Mirrors the C17 deferral
pattern: the schema is reserved at v0.3, the verification mechanism lands at
v0.4.

v0.3 ship-list (four items):
  1. `bundle.manifest.rigor_profile` schema namespace
     (field declared on `BundleManifest` with `default=None`; verifier ignores).
  2. `nexi.reference.v1` (canonical) + `deprecated.v0.2` (legacy back-compat)
     profile identifiers as module-level constants.
  3. The corrected `aggregation_semiring` 5-tuple
     `(K_label="rigor_tier_lattice_with_sentinels", plus="min", times="max",
       zero=TOP_SENTINEL, one=BOTTOM_SENTINEL)` — additive identity = lattice
     TOP-sentinel, multiplicative identity = lattice BOTTOM-sentinel, per
     Green-Karvounarakis-Tannen "Provenance Semirings" (PODS 2007) §4
     tropical-semiring example identity-direction logic.
  4. The `COMPOSED_HYPOTHESIS → TARGET` transition forbidding for
     `nexi.reference.v1` (schema-level fix that ships at v0.3 even though the
     rejection mechanism is v0.4).

v0.4-deferred list (six items):
  - SCITT-receipt-gated verification
    (no `scitt_receipts[]` parsing; no IETF SCITT `draft-ietf-scitt-architecture-22`
    integration)
  - M-of-N quorum across pinned TS logs
    (`nexi-trinity-profiles` + `nexi-trinity-ts-roots` TUF roles activate at v0.4)
  - Byte-binding check
    (`sha256(deterministic_cbor(verified statement payload)) == manifest.profile_sha256`)
  - Post-CDDL invariants
    (duplicate-map-key per RFC 8949 §3.1; indefinite-length per §4.2.1;
    recursion-depth cap; CBOR-tag allow-list)
  - Semiring-axiom verifier-side test vector
    (`∀a ∈ K: 0 ⊕ a == a ∧ 1 ⊗ a == a`)
  - HKDF-Expand-then-HMAC key derivation per RFC 5869 §2.2 + RFC 2104 §2
    (no `K_manifest` / `K_record` derivation; no `manifest_mac` / `record_mac`
    emission)

Verifier semantics at v0.3 (load-bearing for downstream consumers):

  Verifier IGNORES the `rigor_profile` field at v0.3. Bundles without
  `rigor_profile` continue verifying via the v0.2-compat path. Bundles WITH
  `rigor_profile` declared verify the same way — the field is opaque advisory
  metadata at v0.3.

The module exists so:
  (a) v0.3 builders that opt into the reserved schema have canonical constants
      to emit against;
  (b) the algebraic-identity fix lands at the reservation level so v0.4
      plugins compose against the correct semiring identities from day one;
  (c) v0.4 substrate work has a stable import surface
      (`from audit_bundle.extensions.c14v3_rigor_profile import ...`) to extend.

This module is stdlib-only and import-side-effect-free. It does NOT call
`audit_bundle.bundle_manifest.register_typed_check`. The verifier ignores the
`rigor_profile` field at v0.3 by construction; no plugin is registered.

(Scope note: the "stdlib-only" property here applies to THIS module and to the
offline-only `verify.py` tool. It does NOT generalize to the substrate
verifier, which depends on JCS today and will add python-tuf at v0.4 when DSSE
lands underneath this work.)
"""

from __future__ import annotations

from typing import Final


# ---------------------------------------------------------------------------
# Profile identifiers
# ---------------------------------------------------------------------------

# v0.3-registered profiles. No other profiles register at v0.3.
PROFILE_ID_NEXI_REFERENCE_V1: Final[str] = "nexi.reference.v1"
PROFILE_ID_DEPRECATED_V0_2: Final[str] = "deprecated.v0.2"

RESERVED_PROFILE_IDS: Final[frozenset[str]] = frozenset(
    {
        PROFILE_ID_NEXI_REFERENCE_V1,
        PROFILE_ID_DEPRECATED_V0_2,
    }
)

# Candidate-slot identifiers reserved for first-tenant-per-profile signal at
# v0.4+. NOT registered at v0.3 — emitters declaring these profile_ids at v0.3
# produce bundles that the v0.3 verifier ignores (same as any unknown
# rigor_profile content), and that the v0.4 verifier rejects until v0.4
# publishes domain-appropriate semirings for them.
CANDIDATE_PROFILE_IDS_V0_4_PLUS: Final[frozenset[str]] = frozenset(
    {
        "clinical.cochrane",
        "supply_chain.slsa",
        "financial.pcaob",
        "scientific.evidence",
    }
)


# ---------------------------------------------------------------------------
# Carrier sentinels (algebraic identities live outside the real tier set so the
# identity role is structurally distinct from any domain tier)
# ---------------------------------------------------------------------------

# Sentinels added to the carrier K to serve as the semiring identities. They
# MUST NEVER appear as a STAMP value on a real record (v0.4 verifier rejects
# any record.stamp == TOP_SENTINEL or BOTTOM_SENTINEL with STAMP_TIER_INVALID).
#
# Derivation per Green-Karvounarakis-Tannen §4 tropical-semiring example
# (paper p. 35, "Examples of commutative ω-continuous semirings"):
#   `(N∞, min, +, ∞, 0)`  →  `min` as the additive operation has additive
#   identity `∞` (the carrier TOP). By the same logic, on the rigor lattice
#   extended with TOP_SENTINEL and BOTTOM_SENTINEL:
#     - ⊕ = min on a totally-ordered lattice ⇒ additive identity = lattice TOP
#       (because min(TOP, a) = a for every a in K).
#     - ⊗ = max on a totally-ordered lattice ⇒ multiplicative identity = lattice
#       BOTTOM (because max(BOTTOM, a) = a for every a in K).
# The previous tuple `(rigor_tier_set, min, max, UNVERIFIED, CONFIRMED_EXTERNAL)`
# inverted BOTH identity directions — explicitly the form the paper's own
# tropical-semiring example rules out.
TOP_SENTINEL: Final[str] = "TOP_SENTINEL"
BOTTOM_SENTINEL: Final[str] = "BOTTOM_SENTINEL"

SENTINEL_TIERS: Final[frozenset[str]] = frozenset({TOP_SENTINEL, BOTTOM_SENTINEL})


# ---------------------------------------------------------------------------
# Tier orderings
# ---------------------------------------------------------------------------

# nexi.reference.v1 — canonical v0.3 profile.
# Ordered HIGH-RIGOR → LOW-RIGOR (≻ = strictly higher rigor). Reorders
# COMPOSED_HYPOTHESIS above TARGET vs the legacy 7-tier ladder to close a
# direct-edge laundering attack (a CH → TARGET upgrade that laundered derived
# content into a higher aggregate under monotone-min).
NEXI_REFERENCE_V1_TIERS: Final[tuple[str, ...]] = (
    "CONFIRMED_EXTERNAL",
    "WEB_SOURCE",
    "INTERNAL_SOURCE",
    "INTERNAL_BENCHMARK",
    "COMPOSED_HYPOTHESIS",
    "TARGET",
    "UNVERIFIED",
)

# deprecated.v0.2 — legacy 7-tier ordering for v0.2-emitter back-compat.
# Hardcoded baseline in the verifier binary at v0.3 (no SCITT distribution).
# Verifier emits STAMP_PROFILE_DEPRECATED_V0_2 soft warning at v0.4 when this
# profile is observed (v0.3 verifier ignores both profiles identically).
# KNOWN-LAUNDERING profile — TARGET sits above COMPOSED_HYPOTHESIS so the
# CH → TARGET upgrade is one-rung-permitted under monotone-min. Documented;
# deprecation target end of v0.3 soak. Do NOT use for new bundles.
DEPRECATED_V0_2_TIERS: Final[tuple[str, ...]] = (
    "CONFIRMED_EXTERNAL",
    "WEB_SOURCE",
    "INTERNAL_SOURCE",
    "INTERNAL_BENCHMARK",
    "TARGET",
    "COMPOSED_HYPOTHESIS",
    "UNVERIFIED",
)


# ---------------------------------------------------------------------------
# Forbidden transitions
# ---------------------------------------------------------------------------

# Direct CH → TARGET upgrade forbidden in nexi.reference.v1. Closes the
# direct-edge laundering attack at the schema level (not pipeline level), so it
# ships at v0.3. Multi-step cumulative-chain residual (CH → IB → IS → WS → CE
# traversal) is the v0.4 honest residual — Myers-Liskov DLM (SOSP 1997 / TOSEM
# 2000) is the v0.4 path; CITATION-ONLY at v0.3 (no DLM primitives invoked).
NEXI_REFERENCE_V1_FORBIDDEN_TRANSITIONS: Final[frozenset[str]] = frozenset(
    {
        "COMPOSED_HYPOTHESIS→TARGET",
    }
)

# deprecated.v0.2 has NO forbidden_transitions — the legacy ladder admits the
# CH → TARGET upgrade by design. Bundles MUST migrate to nexi.reference.v1
# before end of v0.3 soak.
DEPRECATED_V0_2_FORBIDDEN_TRANSITIONS: Final[frozenset[str]] = frozenset()


# ---------------------------------------------------------------------------
# Aggregation semiring (5-tuple shape)
# ---------------------------------------------------------------------------

# The algebraic-identity fix: the aggregation_semiring 5-tuple shape.
# K_label, ⊕ operator, ⊗ operator, additive identity (0), multiplicative
# identity (1). The semiring is (K, ⊕, ⊗, 0, 1) over the totally-ordered
# rigor lattice extended with TOP_SENTINEL and BOTTOM_SENTINEL.
#
#   ⊕ = min   (most-pessimistic aggregation under ≻)
#   ⊗ = max   (least-pessimistic aggregation under ≻)
#   0 = TOP_SENTINEL       (additive identity:        min(TOP_SENTINEL,    a) = a ∀a ∈ K)
#   1 = BOTTOM_SENTINEL    (multiplicative identity:  max(BOTTOM_SENTINEL, a) = a ∀a ∈ K)
#
# Both nexi.reference.v1 and deprecated.v0.2 use the SAME semiring tuple at
# v0.3 (only the tier-ordering differs). v0.4 verifier enforces the tuple via a
# hardcoded (profile_id, expected_semiring_tuple) allow-list + published
# axiom-check test vector; v0.3 ships the tuple shape only.
AGGREGATION_SEMIRING_LATTICE_MIN_MAX: Final[tuple[str, str, str, str, str]] = (
    "rigor_tier_lattice_with_sentinels",  # K_label
    "min",  # ⊕ (plus)
    "max",  # ⊗ (times)
    TOP_SENTINEL,  # 0 (additive identity)
    BOTTOM_SENTINEL,  # 1 (multiplicative identity)
)

# (profile_id → expected_semiring_tuple) allow-list. Hardcoded in the module
# (NOT in TUF) — semiring algebra is a structural invariant of the profile, not
# a rotatable parameter. v0.4 verifier consults this allow-list to reject any
# spec whose declared aggregation_semiring deviates.
EXPECTED_SEMIRING_BY_PROFILE: Final[dict[str, tuple[str, str, str, str, str]]] = {
    PROFILE_ID_NEXI_REFERENCE_V1: AGGREGATION_SEMIRING_LATTICE_MIN_MAX,
    PROFILE_ID_DEPRECATED_V0_2: AGGREGATION_SEMIRING_LATTICE_MIN_MAX,
}


# ---------------------------------------------------------------------------
# Reason-code constants reserved for v0.4 verifier pipeline emission
# ---------------------------------------------------------------------------

# v0.3 module does NOT emit these — they live here so v0.4 plugin work composes
# against a stable string surface (and so external tooling parsing reason codes
# today doesn't see drift between v0.3 reservation and v0.4 substrate ship).
# The full v0.4 reason-code set is larger; this subset is the schema-level
# surface (the cryptographic-pipeline codes —
# STAMP_PROFILE_SCITT_RECEIPT_INVALID, STAMP_PROFILE_RECEIPT_MISMATCH,
# STAMP_PROFILE_TS_QUORUM_UNMET, STAMP_PROFILE_TS_ROLLBACK,
# STAMP_PROFILE_TS_EQUIVOCATION, STAMP_PROFILE_INVALID_SEMIRING,
# STAMP_PROFILE_EPOCH_MISMATCH, STAMP_PROFILE_MANIFEST_MAC_INVALID,
# STAMP_PROFILE_DUP_MAP_KEY, STAMP_PROFILE_NONCANONICAL_CBOR,
# STAMP_PROFILE_RECURSION_DEPTH, STAMP_PROFILE_TAG_DISALLOWED,
# STAMP_PROFILE_SIZE_EXCEEDED, STAMP_PROFILE_SCHEMA_INVALID,
# STAMP_PROFILE_TIER_UNKNOWN — land in c14v3_rigor_profile_plugin.py at v0.4).
REASON_CODE_STAMP_TRANSITION_FORBIDDEN: Final[str] = "STAMP_TRANSITION_FORBIDDEN"
REASON_CODE_STAMP_PROFILE_DEPRECATED_V0_2: Final[str] = "STAMP_PROFILE_DEPRECATED_V0_2"
REASON_CODE_STAMP_PROFILE_PATH_CONFLICT: Final[str] = "STAMP_PROFILE_PATH_CONFLICT"
REASON_CODE_STAMP_TIER_INVALID: Final[str] = "STAMP_TIER_INVALID"
REASON_CODE_STAMP_PROFILE_DIGEST_MISMATCH: Final[str] = "STAMP_PROFILE_DIGEST_MISMATCH"


# ---------------------------------------------------------------------------
# Helpers (v0.3 verifier IGNORES the rigor_profile field; these helpers exist
# so emitters can sanity-check their bundles client-side before emission, and
# so v0.4 plugin work has a stable import surface to extend)
# ---------------------------------------------------------------------------


def is_sentinel(tier: str) -> bool:
    """True iff `tier` is one of the carrier-extension sentinels (must not appear on real records)."""
    return tier in SENTINEL_TIERS


def is_reserved_profile_id(profile_id: str) -> bool:
    """True iff `profile_id` is one of the two v0.3-registered profiles."""
    return profile_id in RESERVED_PROFILE_IDS


def get_tiers_for_profile(profile_id: str) -> tuple[str, ...] | None:
    """Return the ordered tier tuple for a registered profile, or None if unknown at v0.3."""
    if profile_id == PROFILE_ID_NEXI_REFERENCE_V1:
        return NEXI_REFERENCE_V1_TIERS
    if profile_id == PROFILE_ID_DEPRECATED_V0_2:
        return DEPRECATED_V0_2_TIERS
    return None


def get_forbidden_transitions_for_profile(profile_id: str) -> frozenset[str] | None:
    """Return forbidden_transitions for a registered profile, or None if unknown at v0.3."""
    if profile_id == PROFILE_ID_NEXI_REFERENCE_V1:
        return NEXI_REFERENCE_V1_FORBIDDEN_TRANSITIONS
    if profile_id == PROFILE_ID_DEPRECATED_V0_2:
        return DEPRECATED_V0_2_FORBIDDEN_TRANSITIONS
    return None


def get_expected_semiring(profile_id: str) -> tuple[str, str, str, str, str] | None:
    """Return the (profile_id → semiring tuple) allow-list entry, or None if unknown at v0.3."""
    return EXPECTED_SEMIRING_BY_PROFILE.get(profile_id)


def is_forbidden_transition(
    profile_id: str, from_tier: str, to_tier: str
) -> bool | None:
    """Schema-level check: is `from_tier → to_tier` declared STAMP_TRANSITION_FORBIDDEN for `profile_id`?

    Returns True / False for registered profiles; None for unknown profile_id at v0.3 (verifier
    defers to v0.4 plugin for the actual transition rejection — this helper exists so v0.3 builders
    can sanity-check their bundles client-side before emission).
    """
    forbidden = get_forbidden_transitions_for_profile(profile_id)
    if forbidden is None:
        return None
    return f"{from_tier}→{to_tier}" in forbidden
