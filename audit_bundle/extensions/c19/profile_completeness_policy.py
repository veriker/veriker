"""C19 — profile-gated deep-completeness policy.

The verifier-held ``(≤, R, O)`` policy object plus the out-of-band floor
resolution. This is the foundation the rest of the completeness policy binds to:
one stage reads ``required_structures`` for the effective profile, another reads
each structure's obligation lattice, a third reads the cross-structure obligation.

Why a *closed declarative DSL* and not callable obligations (the
Rice's theorem argument): proving two arbitrary ``O()`` programs compare in strength is
undecidable, so a syntactic "monotonicity certificate" over freeform code would
pass a semantically-weaker policy and *relocate* the downgrade into ``O()``.
So the policy is data only:

  * profiles form a verifier-held **preorder** ``≤`` (explicit ≥-edges, NOT
    string comparison; incomparable jurisdictional branches are allowed);
  * ``R(P)`` is an explicit finite set of structure IDs (monotone = ``⊇``);
  * ``O(S)`` is a **parametric lattice** with declared monotone dimensions
    (a bit-set of named checks where superset = stronger, ``min_count`` where
    larger = stronger, a time-tolerance where smaller = stronger, a
    distinctness ordinal and a coverage ordinal where higher = stronger).

Monotonicity (``Pi ≥ Pj`` ⇒ ``R(Pi) ⊇ R(Pj)`` and every ``O_i(S) ≥ O_j(S)``)
is then an ``O(n²)`` lattice comparison over the finite profile set, **enforced
at construction** — a non-monotone policy raises ``ValueError`` and can never
ship (mirrors ``CrossOrgKeyPolicy`` / ``OfflineRootPolicy``: reject a degenerate
pin at build time so the verifier never has to defend it at run time).

Provenance: at v0.x this object is frozen at verifier-binary build time. It
upgrades to a signed C18 TUF target (role parallel to ``nexi-c19-ts-log``) with
anti-rollback — ``policy_epoch`` + ``expiry`` + a born-after timestamp, refused
below a baked-in ``policy_epoch_floor`` even on first boot. The
admissibility primitive (:func:`policy_admissible`) is here; wiring it to a real
TUF client is the C18 integration step, not this module.

Stdlib-only (S0 core-path discipline).


"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Final

# --- Reason codes ---------------------------------------------------------
PROFILE_DECLARED_BELOW_PINNED_FLOOR: Final = "PROFILE_DECLARED_BELOW_PINNED_FLOOR"
PROFILE_NOT_COMPARABLE_TO_FLOOR: Final = "PROFILE_NOT_COMPARABLE_TO_FLOOR"
PROFILE_DECLARED_UNKNOWN: Final = "PROFILE_DECLARED_UNKNOWN"
PROFILE_DECLARATION_REQUIRED_AT_FLOOR: Final = "PROFILE_DECLARATION_REQUIRED_AT_FLOOR"
# Core assurance-profile guard (label-downgrade fix, 2026-06-12): emitted by
# BundleVerifier._step_assurance_profile_guard, defined here so the guard and
# any grader plugin share one vocabulary.
PROFILE_DECLARATION_CONFLICT: Final = "PROFILE_DECLARATION_CONFLICT"
PROFILE_DECLARED_BUT_UNGRADED: Final = "PROFILE_DECLARED_BUT_UNGRADED"
PROFILE_REQUIRED_STRUCTURE_ABSENT: Final = "PROFILE_REQUIRED_STRUCTURE_ABSENT"
# Anti-rollback — policy-target admissibility, checked at load.
POLICY_EPOCH_BELOW_FLOOR: Final = "POLICY_EPOCH_BELOW_FLOOR"
POLICY_EXPIRED: Final = "POLICY_EXPIRED"
POLICY_BORN_BEFORE_CUTOFF: Final = "POLICY_BORN_BEFORE_CUTOFF"

# Sentinel: an obligation dimension with no upper bound on tolerance (weakest).
NO_TOLERANCE_BOUND: Final = -1


@dataclass(frozen=True)
class ObligationLattice:
    """A structure's soundness obligation ``O(S)`` as a point in a product
    lattice of **declared monotone dimensions**. "Stronger" = ``>=`` (no
    freeform code, so monotonicity is decidable).

    Dimensions (all monotone; "stronger" direction noted):
      * ``required_checks`` — named sub-checks the verifier MUST re-derive for
        this structure. **Superset = stronger.** (E.g. for ``per_batch_tsa_root``:
        ``{"root_bound_to_events", "distinct_tsa_quorum", "bls_required"}``.)
      * ``min_count`` — minimum count (quorum / edge-set floor). **Larger =
        stronger.** ``0`` = unconstrained.
      * ``max_time_tolerance_ms`` — trusted-time slack ``δ``. **Smaller =
        stronger.** :data:`NO_TOLERANCE_BOUND` = unconstrained (weakest).
      * ``distinctness_level`` — ``0`` none / ``1`` by-token / ``2`` by-pinned
        operator-id. **Higher = stronger.**
      * ``coverage_level`` — ``0`` none / ``1`` partial / ``2`` bijection.
        **Higher = stronger.**

    The plugin layer reads ``required_checks`` and the numeric dimensions
    to decide what to enforce; this object never enforces, only declares.
    """

    required_checks: frozenset[str] = frozenset()
    min_count: int = 0
    max_time_tolerance_ms: int = NO_TOLERANCE_BOUND
    distinctness_level: int = 0
    coverage_level: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.required_checks, frozenset):
            # Normalise so callers can pass a set/list without breaking ⊇.
            object.__setattr__(self, "required_checks", frozenset(self.required_checks))
        if self.min_count < 0:
            raise ValueError(f"min_count must be >= 0, got {self.min_count}")
        if self.max_time_tolerance_ms < 0 and (
            self.max_time_tolerance_ms != NO_TOLERANCE_BOUND
        ):
            raise ValueError(
                "max_time_tolerance_ms must be >= 0 or NO_TOLERANCE_BOUND, got "
                f"{self.max_time_tolerance_ms}"
            )
        for name in ("distinctness_level", "coverage_level"):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} must be >= 0, got {getattr(self, name)}")

    def _tolerance_rank(self) -> tuple[int, int]:
        """Order key for ``max_time_tolerance_ms`` where smaller-ms = stronger
        and the unbounded sentinel is weakest of all.

        Returns ``(bounded_flag, neg_ms)`` so that a larger tuple = stronger:
        a bounded tolerance always outranks the unbounded sentinel, and among
        bounded tolerances a smaller ms (larger ``-ms``) is stronger.
        """
        if self.max_time_tolerance_ms == NO_TOLERANCE_BOUND:
            return (0, 0)  # weakest
        return (1, -self.max_time_tolerance_ms)

    def at_least_as_strong_as(self, other: "ObligationLattice") -> bool:
        """``self >= other`` in every declared dimension (product lattice)."""
        return (
            self.required_checks >= other.required_checks
            and self.min_count >= other.min_count
            and self._tolerance_rank() >= other._tolerance_rank()
            and self.distinctness_level >= other.distinctness_level
            and self.coverage_level >= other.coverage_level
        )


@dataclass(frozen=True)
class Profile:
    """One node in the policy: its required-structure set ``R(P)`` and the
    obligation ``O(S)`` for each required structure."""

    profile_id: str
    required_structures: frozenset[str] = frozenset()
    obligations: dict[str, ObligationLattice] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.required_structures, frozenset):
            object.__setattr__(
                self, "required_structures", frozenset(self.required_structures)
            )
        # Every obligation must attach to a required structure, and every
        # required structure must carry an obligation (no silent gaps — a
        # required-but-unconstrained structure is an explicit empty lattice).
        extra = set(self.obligations) - self.required_structures
        if extra:
            raise ValueError(
                f"profile {self.profile_id!r}: obligation(s) for non-required "
                f"structure(s): {sorted(extra)}"
            )
        missing = self.required_structures - set(self.obligations)
        if missing:
            raise ValueError(
                f"profile {self.profile_id!r}: required structure(s) without an "
                f"obligation lattice: {sorted(missing)} (use an empty "
                "ObligationLattice() to mean required-but-unconstrained)"
            )

    def obligation(self, structure: str) -> ObligationLattice:
        return self.obligations[structure]


@dataclass(frozen=True)
class CompletenessPolicy:
    """The verifier-held ``(≤, R, O)`` target. Construction enforces the
    monotonicity invariant; a non-monotone policy cannot be built.

    ``order_edges`` are direct ``higher ≥ lower`` covering pairs; the preorder
    is their reflexive-transitive closure. Profiles not connected by any chain
    are **incomparable** (allowed — jurisdictional branches), and a declared
    profile incomparable to the floor is REJECTed at resolution time, never
    silently accepted.
    """

    profiles: dict[str, Profile]
    order_edges: frozenset[tuple[str, str]] = frozenset()
    # Anti-rollback metadata. policy_epoch is the monotone counter the
    # verifier persists and never accepts a rollback of; expiry/born are epoch
    # millis (None = unset at this provenance tier).
    policy_epoch: int = 0
    expiry_ms: int | None = None
    born_at_ms: int | None = None

    # filled in __post_init__: reachable[a] = set of profiles b with a >= b
    _reachable: dict[str, frozenset[str]] = field(
        default_factory=dict, compare=False, repr=False
    )

    def __post_init__(self) -> None:
        if not isinstance(self.order_edges, frozenset):
            object.__setattr__(self, "order_edges", frozenset(self.order_edges))
        # Edges must reference known profiles.
        for hi, lo in self.order_edges:
            for p in (hi, lo):
                if p not in self.profiles:
                    raise ValueError(f"order edge references unknown profile {p!r}")
        if self.policy_epoch < 0:
            raise ValueError(f"policy_epoch must be >= 0, got {self.policy_epoch}")
        object.__setattr__(self, "_reachable", self._compute_reachability())
        self._enforce_monotonicity()  # raises on violation

    # --- preorder --------------------------------------------------------
    def _compute_reachability(self) -> dict[str, frozenset[str]]:
        # reach[a] = {b : a >= b}, reflexive + transitive closure of >=-edges.
        succ: dict[str, set[str]] = {p: {p} for p in self.profiles}
        for hi, lo in self.order_edges:
            succ[hi].add(lo)
        # Floyd-Warshall-ish fixpoint over the finite profile set.
        changed = True
        while changed:
            changed = False
            for a in self.profiles:
                for b in list(succ[a]):
                    new = succ[b] - succ[a]
                    if new:
                        succ[a] |= new
                        changed = True
        return {a: frozenset(bs) for a, bs in succ.items()}

    def geq(self, a: str, b: str) -> bool:
        """``a >= b`` in the held preorder."""
        return b in self._reachable[a]

    def comparable(self, a: str, b: str) -> bool:
        return self.geq(a, b) or self.geq(b, a)

    # --- monotonicity enforcement ----------------------------------------
    def _enforce_monotonicity(self) -> None:
        for hi in self.profiles:
            for lo in self._reachable[hi]:
                if hi == lo:
                    continue
                phi, plo = self.profiles[hi], self.profiles[lo]
                if not phi.required_structures >= plo.required_structures:
                    missing = plo.required_structures - phi.required_structures
                    raise ValueError(
                        f"non-monotone policy: R({hi!r}) must ⊇ R({lo!r}) "
                        f"since {hi!r} >= {lo!r}; missing {sorted(missing)}"
                    )
                for s in plo.required_structures:
                    if not phi.obligation(s).at_least_as_strong_as(plo.obligation(s)):
                        raise ValueError(
                            f"non-monotone policy: O({s!r}) at {hi!r} must "
                            f"be >= at {lo!r} (obligations never weaken upward)"
                        )

    # --- accessors -------------------------------------------------------
    def required_structures(self, profile_id: str) -> frozenset[str]:
        return self.profiles[profile_id].required_structures

    def obligation(self, profile_id: str, structure: str) -> ObligationLattice:
        return self.profiles[profile_id].obligation(structure)

    def effective_required_structures(self, graded: str, floor: str) -> frozenset[str]:
        """Belt-and-suspenders effective set ``R(graded) ∪ R(floor)``:
        the floor's structures are mandatory regardless of the graded profile,
        so a graded profile incomparable-but-admissible never drops a
        floor-required structure."""
        return self.required_structures(graded) | self.required_structures(floor)


# --- floor resolution ------------------------------------------------------


def resolve_effective_profile(
    policy: CompletenessPolicy,
    *,
    floor: str,
    declared: str | None,
    require_declaration: bool = False,
) -> tuple[str | None, str | None]:
    """Resolve the profile a bundle is graded at, or REJECT.

    ``floor`` is the relying party's verifier-held minimum (per-relying
    party; must be a profile in ``policy``). ``declared`` is the bundle's
    covered ``assurance_profile`` (``None`` if absent).

    Returns ``(effective_profile_id, None)`` to grade, or
    ``(None, REASON_CODE)`` to REJECT. Rules:

      * declared ``None`` and not ``require_declaration`` → grade at ``floor``;
      * declared ``None`` and ``require_declaration`` (above the floor's
        ``min_schema_version`` stakes threshold) →
        ``PROFILE_DECLARATION_REQUIRED_AT_FLOOR``;
      * declared not in policy → ``PROFILE_DECLARED_UNKNOWN``;
      * declared incomparable to floor → ``PROFILE_NOT_COMPARABLE_TO_FLOOR``;
      * declared ``< floor`` → ``PROFILE_DECLARED_BELOW_PINNED_FLOOR``;
      * declared ``>= floor`` → grade at ``declared`` (producer may raise its
        own bar, never select below the floor).

    The ``require_declaration`` gate is the stakes threshold: the *caller*
    (the floor-resolution plugin) decides it from the covered-leaf shape, so an
    attacker cannot evade it by editing an uncovered version string.
    """
    if floor not in policy.profiles:
        raise ValueError(f"floor {floor!r} is not a profile in the policy")
    if declared is None:
        if require_declaration:
            return (None, PROFILE_DECLARATION_REQUIRED_AT_FLOOR)
        return (floor, None)
    if declared not in policy.profiles:
        return (None, PROFILE_DECLARED_UNKNOWN)
    if not policy.comparable(declared, floor):
        return (None, PROFILE_NOT_COMPARABLE_TO_FLOOR)
    if not policy.geq(declared, floor):
        return (None, PROFILE_DECLARED_BELOW_PINNED_FLOOR)
    return (declared, None)


# --- anti-rollback admissibility -------------------------------------------


def policy_admissible(
    policy: CompletenessPolicy,
    *,
    policy_epoch_floor: int,
    now_ms: int,
    born_after_ms: int | None = None,
) -> tuple[bool, str | None]:
    """Is the (signed) policy target admissible to load? The verifier
    config carries a **baked-in** ``policy_epoch_floor`` it refuses below even
    on first boot (so a fresh instance can't accept an old-but-validly-signed
    policy, and a fleet can't be split-viewed onto a lagging one), plus expiry
    and a born-after cutoff.

    ``now_ms`` / ``born_after_ms`` are passed in (testable; no ambient clock in
    the substrate). Returns ``(True, None)`` or ``(False, REASON_CODE)``.
    """
    if policy.policy_epoch < policy_epoch_floor:
        return (False, POLICY_EPOCH_BELOW_FLOOR)
    if policy.expiry_ms is not None and now_ms > policy.expiry_ms:
        return (False, POLICY_EXPIRED)
    if born_after_ms is not None:
        if policy.born_at_ms is None or policy.born_at_ms < born_after_ms:
            return (False, POLICY_BORN_BEFORE_CUTOFF)
    return (True, None)


# --- canonical vocabulary + structure-location registry ---------------------
#
# The three substrate profile IDs (MANIFEST_SCHEMA.md causal_chain row) and
# the canonical manifest LOCATION of each known evidentiary structure. These
# are SHAPE, not policy: they say what the IDs are and where a structure
# lives, never which structures a profile requires — R(P)/O(S) content stays
# verifier-held relying-party configuration (one pilot's regulatory map must
# not become core's universal meaning of a label; tribunal-ratified
# 2026-06-12).

CANONICAL_PROFILE_IDS: Final = (
    "offline-auditor-minimal",
    "production-standard",
    "regulated-high-assurance",
)

# Structure-ID → path (tuple of keys from the manifest root) at which the
# structure must be PRESENT. Insertion order is shallow→deep so the FIRST
# absent structure named in a rejection is the outermost one. Promoted from
# the eidas_eudi_minimal pilot (which now imports it) so the core guard and
# pilot graders walk the SAME location registry.
STRUCTURE_PATHS: Final[dict[str, tuple[str, ...]]] = {
    "causal_chain": ("causal_chain",),
    "layer_a": ("causal_chain", "layer_a"),
    "layer_b_anchors": ("causal_chain", "layer_b_anchors"),
    "per_batch_tsa_root": ("causal_chain", "layer_b_anchors", "per_batch_tsa_root"),
    "per_event_roughtime": ("causal_chain", "layer_b_anchors", "per_event_roughtime"),
    "cross_host_authenticators": ("causal_chain", "cross_host_authenticators"),
}
STRUCTURE_WALK_ORDER: Final[tuple[str, ...]] = tuple(STRUCTURE_PATHS)


def builtin_profile_lattice() -> CompletenessPolicy:
    """The canonical three-profile lattice with EMPTY ``R(P)`` everywhere.

    This is the admission vocabulary the core verifier holds when the relying
    party configures no policy: it makes ``unknown profile ID → REJECT`` and
    floor comparison decidable, while deliberately carrying no obligations —
    core never invents what a label REQUIRES, it only refuses to certify a
    label nothing graded.
    """
    return CompletenessPolicy(
        profiles={pid: Profile(pid) for pid in CANONICAL_PROFILE_IDS},
        order_edges=frozenset(
            {
                ("regulated-high-assurance", "production-standard"),
                ("production-standard", "offline-auditor-minimal"),
            }
        ),
        policy_epoch=0,
    )


def policy_fingerprint(policy: CompletenessPolicy) -> str:
    """Stable sha256 fingerprint of the policy CONTENT (profiles + R + O +
    order + epoch). A grader plugin reports ``(profile_id, fingerprint)`` so
    the core guard can require that the grading happened against the SAME
    policy the relying party configured — a permissive grader cannot satisfy
    a strict relying-party config (tribunal Q3 sharpening, 2026-06-12)."""

    def _obligation(o: ObligationLattice) -> dict:
        return {
            "required_checks": sorted(o.required_checks),
            "min_count": o.min_count,
            "max_time_tolerance_ms": o.max_time_tolerance_ms,
            "distinctness_level": o.distinctness_level,
            "coverage_level": o.coverage_level,
        }

    canonical = {
        "profiles": {
            pid: {
                "required_structures": sorted(p.required_structures),
                "obligations": {
                    s: _obligation(p.obligations[s]) for s in sorted(p.obligations)
                },
            }
            for pid, p in sorted(policy.profiles.items())
        },
        "order_edges": sorted(policy.order_edges),
        "policy_epoch": policy.policy_epoch,
    }
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def effective_declared_profile(manifest) -> tuple[str | None, str | None]:
    """The ONE canonical reader of every assurance-profile declaration site.

    Sites: the top-level manifest key (CC-2b D1) and the nested
    ``causal_chain.layer_a.assurance_profile`` (C19 Layer-A header). A
    producer must not be able to dodge the guard by relocating the claim, nor
    split-brain it by declaring different values at different sites.

    Returns ``(declared, None)`` — ``declared`` is ``None`` when NO site
    declares — or ``(None, conflict_detail)`` when sites disagree (including
    a non-string value at any site: a malformed declaration is a conflict
    with itself, never silently coerced to absent).
    """
    sites: list[tuple[str, object]] = []
    top = getattr(manifest, "assurance_profile", None)
    if top is not None:
        sites.append(("assurance_profile", top))
    cc = getattr(manifest, "causal_chain", None)
    if isinstance(cc, dict):
        layer_a = cc.get("layer_a")
        if isinstance(layer_a, dict):
            nested = layer_a.get("assurance_profile")
            if nested is not None:
                sites.append(("causal_chain.layer_a.assurance_profile", nested))
    if not sites:
        return (None, None)
    for site, value in sites:
        if not isinstance(value, str):
            return (
                None,
                f"declaration at {site} is not a string "
                f"({type(value).__name__}) — malformed, refusing to grade",
            )
    values = {value for _, value in sites}
    if len(values) > 1:
        detail = ", ".join(f"{site}={value!r}" for site, value in sites)
        return (None, f"declaration sites disagree: {detail}")
    return (sites[0][1], None)
