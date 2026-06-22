"""audit_bundle/rederivation/spec_binding.py — Axis-1 binding source + anchor.

The per-type binding type -> {primitive_id, comparator{kind,params}} lives in a
SHA-pinned spec file (the spec/ tree the verifier already integrity-checks at
step 2). This module:

  (step 3) parses a spec's binding object and resolves type -> Binding;
  (step 4 — GATING, §4a.1/4a.2) anchors the AUTHORITATIVE spec set to an
    AUDITOR-controlled allowlist (spec_id -> required SHA). SHA-pinning proves a
    named spec's *contents* are immutable; it does NOT prove the producer chose
    the *right* spec. The anchor closes that: a spec is authoritative only if its
    spec_id is in the anchor AND its on-disk SHA equals the anchored SHA. The
    producer cannot author or select around it — a substituted weak spec has a
    SHA the anchor does not list, so it is not authoritative and its types do not
    resolve (fail-closed). `conforms_to` is reduced to a non-load-bearing
    cross-check hint: resolution searches ALL anchored specs and fails closed on
    ambiguity (§4a.2 option (b)), so a producer cannot redirect dispatch by
    pointing `conforms_to` at a weaker spec.
  (step 5 — GATING, §4a.3) the monotone-strictness invariant: across the
    authoritative set, any primitive_id bound by >=2 types must carry an
    IDENTICAL comparator (kind + canonical params). This is the conservative
    instantiation of "comparators must be equally-or-more strict under a partial
    order" — it admits no weaker sibling at all, so the type-substitution attack
    has no weaker type to substitute TO. (A graded partial order is a documented
    future generalization; identical-comparator is sound and the strictest read.)

Stdlib-only (core verify() path). The auditor anchor is supplied to
BundleVerifier at construction (verifier-side, auditor-controlled), never read
from the producer's manifest.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from ..admission import admit_json_file
from .comparators import validate_comparator_params


class SpecBindingError(Exception):
    """Base for all spec-binding / anchor failures (all fail-closed)."""


class MalformedSpec(SpecBindingError):
    """A spec file is not a JSON object or its types/binding shape is invalid."""


class AnchorViolation(SpecBindingError):
    """Spec-pinned dispatch engaged but no auditor anchor supplied, or the
    anchored spec set is empty / unresolvable."""


class AmbiguousTypeBinding(SpecBindingError):
    """A type key is defined by >1 authoritative spec (§4a.2 fail-on-ambiguity)."""


class MonotoneStrictnessViolation(SpecBindingError):
    """A primitive_id is bound by >=2 types with non-identical comparators
    (§4a.3 — admits a weaker sibling; reject the anchored set at load)."""


class UnknownType(SpecBindingError):
    """A claimed output type is not defined by any authoritative spec."""


# ---------------------------------------------------------------------------
# Binding + SpecAnchor
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Binding:
    type_key: str
    primitive_id: str
    comparator_kind: str
    comparator_params: dict
    spec_id: str  # which authoritative spec defined this binding

    def _comparator_canonical(self) -> str:
        """Canonical, order-independent rendering of (kind, params) for the
        monotone-strictness identity check. json.dumps(sort_keys=True) is safe
        here — these are verifier-anchored spec params, NOT adversarial bundle
        dict keys, and all keys are strings."""
        return json.dumps(
            {"kind": self.comparator_kind, "params": self.comparator_params},
            sort_keys=True,
        )


@dataclass(frozen=True, slots=True)
class SpecAnchor:
    """Auditor-controlled allowlist: spec_id -> required SHA-256 hex.

    Supplied to BundleVerifier at construction by the auditor's harness (NOT by
    the producer's manifest). This is the trust root for spec-pinned dispatch:
    only specs whose (spec_id, on-disk-sha) match an entry here are authoritative.
    """

    allowed: dict[str, str]  # spec_id -> sha256 hex (lowercase)

    def matches(self, spec_id: str, computed_sha: str) -> bool:
        want = self.allowed.get(spec_id)
        return want is not None and want.lower() == computed_sha.lower()


# ---------------------------------------------------------------------------
# Spec parsing
# ---------------------------------------------------------------------------


def parse_spec(raw: object, spec_path: str) -> tuple[str, dict[str, Binding]]:
    """Parse one spec's binding object -> (spec_id, {type_key: Binding}).

    Raises MalformedSpec on any shape error (fail-closed). Each comparator's
    params are validated against the closed-world allowlist (§4a.6) here so a
    bad profile/schema is rejected at load, before any dispatch.
    """
    if not isinstance(raw, dict):
        raise MalformedSpec(f"spec {spec_path!r} is not a JSON object")
    spec_id = raw.get("spec_id")
    if not isinstance(spec_id, str) or not spec_id:
        raise MalformedSpec(f"spec {spec_path!r} missing non-empty string 'spec_id'")
    types_obj = raw.get("types")
    if not isinstance(types_obj, dict) or not types_obj:
        raise MalformedSpec(f"spec {spec_path!r} missing non-empty 'types' object")

    bindings: dict[str, Binding] = {}
    for type_key, body in types_obj.items():
        if not isinstance(type_key, str) or not type_key:
            raise MalformedSpec(f"spec {spec_path!r}: type key must be a non-empty string")
        if not isinstance(body, dict):
            raise MalformedSpec(f"spec {spec_path!r}: type {type_key!r} body not an object")
        primitive_id = body.get("primitive_id")
        if not isinstance(primitive_id, str) or not primitive_id:
            raise MalformedSpec(
                f"spec {spec_path!r}: type {type_key!r} missing 'primitive_id'"
            )
        comparator = body.get("comparator")
        if not isinstance(comparator, dict):
            raise MalformedSpec(
                f"spec {spec_path!r}: type {type_key!r} missing 'comparator' object"
            )
        kind = comparator.get("kind")
        if not isinstance(kind, str) or not kind:
            raise MalformedSpec(
                f"spec {spec_path!r}: type {type_key!r} comparator missing 'kind'"
            )
        params = comparator.get("params", {})
        if not isinstance(params, dict):
            raise MalformedSpec(
                f"spec {spec_path!r}: type {type_key!r} comparator.params not an object"
            )
        # §4a.6 closed-world: reject unknown kind / unimplemented profile/schema
        # at load, not at dispatch.
        try:
            validate_comparator_params(kind, params)
        except Exception as exc:
            raise MalformedSpec(
                f"spec {spec_path!r}: type {type_key!r} comparator invalid: {exc}"
            ) from exc
        bindings[type_key] = Binding(
            type_key=type_key,
            primitive_id=primitive_id,
            comparator_kind=kind,
            comparator_params=params,
            spec_id=spec_id,
        )
    return spec_id, bindings


# ---------------------------------------------------------------------------
# AnchoredSpecSet — the authoritative, anchored, conflict-checked binding map
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AnchoredSpecSet:
    """The global type -> Binding map built ONLY from authoritative (anchored)
    specs, after uniqueness + monotone-strictness checks. Frozen at load."""

    by_type: dict[str, Binding]
    authoritative_spec_ids: tuple[str, ...]

    def resolve(self, type_key: str) -> Binding:
        b = self.by_type.get(type_key)
        if b is None:
            raise UnknownType(
                f"output type {type_key!r} is not defined by any authoritative "
                f"(auditor-anchored) spec; anchored spec_ids="
                f"{self.authoritative_spec_ids!r}. A spec the producer named but "
                "the auditor did not anchor (or whose SHA does not match the "
                "anchor) is NOT authoritative — fail-closed."
            )
        return b


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_anchored_spec_set(
    bundle_dir: Path,
    manifest,
    anchor: SpecAnchor | None,
) -> AnchoredSpecSet:
    """Build the authoritative binding map under the auditor anchor.

    Reads each spec named in manifest.spec_files offline-first from
    bundle_dir/spec/<basename> (the §C5 verifier-in-a-box copy step 2 already
    SHA-verifies). A spec is AUTHORITATIVE iff (spec_id, on-disk-sha) matches an
    anchor entry. Non-authoritative specs are excluded. Then:
      - reject duplicate type keys across authoritative specs (§4a.2);
      - reject any primitive_id bound by non-identical comparators (§4a.3).

    Raises AnchorViolation when no anchor is supplied (dispatch engaged but the
    auditor never established authority) or when the authoritative set is empty.
    """
    if anchor is None:
        raise AnchorViolation(
            "spec-pinned dispatch engaged (manifest declares outputs) but no "
            "auditor SpecAnchor was supplied to BundleVerifier. Without an "
            "auditor-controlled spec allowlist the producer's manifest alone "
            "would select authority — refused (§4a.1)."
        )

    spec_dir = bundle_dir / "spec"
    by_type: dict[str, Binding] = {}
    type_origin: dict[str, str] = {}  # type_key -> spec_id that first defined it
    authoritative: list[str] = []

    for spec_path in manifest.spec_files:
        offline_copy = spec_dir / Path(spec_path).name
        if not offline_copy.exists():
            # Not loadable offline -> cannot be authoritative for dispatch.
            continue
        computed_sha = _sha256_file(offline_copy)
        try:
            # Admission-bounded (RES-02): the spec copy is an IN-BUNDLE file and
            # is parsed BEFORE the anchor-authority check, so a hostile
            # non-anchored spec must not reach an unbounded parse.
            # InputInadmissible subclasses ValueError -> MalformedSpec below.
            raw = admit_json_file(offline_copy, check_name="spec_admission")
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as exc:
            raise MalformedSpec(f"spec {spec_path!r} is not valid JSON: {exc}") from exc
        # Only specs that ALSO declare a binding object participate. A plain
        # prose spec (no spec_id/types) is silently skipped for dispatch.
        if not (isinstance(raw, dict) and "types" in raw and "spec_id" in raw):
            continue
        spec_id, bindings = parse_spec(raw, spec_path)
        if not anchor.matches(spec_id, computed_sha):
            # SHA-pinned but NOT auditor-anchored (or substituted) -> not
            # authoritative. This is the spec-selection defense (§4a.1).
            continue
        authoritative.append(spec_id)
        for type_key, binding in bindings.items():
            if type_key in by_type:
                raise AmbiguousTypeBinding(
                    f"type {type_key!r} defined by both spec_id "
                    f"{type_origin[type_key]!r} and {spec_id!r} — ambiguous "
                    "across the authoritative set; fail-closed (§4a.2)."
                )
            by_type[type_key] = binding
            type_origin[type_key] = spec_id

    if not authoritative:
        raise AnchorViolation(
            "no authoritative spec resolved: none of the manifest's spec_files "
            "matched the auditor anchor by (spec_id, sha). Either the producer "
            "supplied no anchored binding spec, or substituted one whose SHA the "
            "anchor does not list — fail-closed (§4a.1)."
        )

    _enforce_monotone_strictness(by_type)
    return AnchoredSpecSet(
        by_type=by_type,
        authoritative_spec_ids=tuple(authoritative),
    )


def _enforce_monotone_strictness(by_type: dict[str, Binding]) -> None:
    """§4a.3: any primitive_id bound by >=2 types must carry an IDENTICAL
    comparator. A differing comparator on a shared primitive admits a weaker
    sibling the producer could substitute to — reject the anchored set."""
    seen: dict[str, tuple[str, str]] = {}  # primitive_id -> (canonical_cmp, type_key)
    for type_key, binding in by_type.items():
        canonical = binding._comparator_canonical()
        prior = seen.get(binding.primitive_id)
        if prior is None:
            seen[binding.primitive_id] = (canonical, type_key)
        elif prior[0] != canonical:
            raise MonotoneStrictnessViolation(
                f"primitive_id {binding.primitive_id!r} is bound by type "
                f"{prior[1]!r} and type {type_key!r} with NON-IDENTICAL "
                f"comparators ({prior[0]} vs {canonical}). This admits a "
                "strength-substitution attack (producer claims the weaker "
                "type); the auditor's anchored spec set is rejected at load "
                "(§4a.3 monotone-strictness)."
            )
