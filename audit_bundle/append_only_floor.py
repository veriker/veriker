"""audit_bundle/append_only_floor.py — the §C9.2 reclassification floor.

``append_only_files`` is a producer-authored declaration that moves a path
from byte-equality (STRICT_SHA: the producer cannot vary a single content
byte undetected) to attribution-key coverage (APPEND_ONLY: the file need only
carry ≥1 record under a declared key; bytes after the first match are
unvalidated). That is a strictly weaker content guarantee, elected by the
untrusted party. Before this floor, nothing constrained WHICH paths could be
downgraded — the file-layer twin of the dispatch-layer "producer claims a
weaker type" attack, which was closed with monotone-strictness + an auditor
role policy. This module closes the file-layer instance the same way.

The guarantee lattice (audit-bundle contract §C9.2)
---------------------------------------------------
A total preorder over ``Guarantee`` by content-integrity strength (higher =
stronger; sha256 is the fixed algorithm — the producer cannot choose):

  rank 3  DSSE_BINDING_SET_CLOSURE   seal binds the entire payload set
                                     (envelope only, never producer-electable)
  rank 2  BYTE_EQUALITY, PINNED_BLOB_HASH, CID_RECOMPUTE
                                     full content determined — no byte may
                                     vary undetected (one equivalence tier:
                                     they differ in MECHANISM, not strength)
  rank 1  ATTRIBUTION_KEY_COVERAGE   partial — ≥1 keyed record asserted;
                                     remaining bytes unvalidated
  rank 0  NONE                       no integrity check

``stronger_of(a, b)`` = the higher-ranked guarantee; ties keep the manifest's
declared mechanism. The only floor-relevant downgrade among regular-file
content guarantees is rank 2 → rank 1 (the APPEND_ONLY election).

The floor predicate
-------------------
1. Default floor = STRICT_SHA (rank 2) for EVERY path, and authorization is
   a HARD PRE-CHECK: it runs BEFORE any guarantee computation. A manifest
   APPEND_ONLY request for a path that is neither (a) statically allowlisted
   nor (b) lowered to rank 1 by a matching auditor policy entry REJECTS with
   ``APPEND_ONLY_FLOOR_VIOLATION`` **regardless of content** — fail-closed,
   "bundle bad". ``stronger_of`` is NOT a salvage lane: an unauthorized
   APPEND_ONLY request is never silently promoted to a rank-2 byte-check
   that could then pass (an append-only path is not in ``manifest.files`` —
   the loader rejects that overlap at parse time — so there is no pinned SHA
   to promote to anyway).
2. Closed static allowlist (verifier-static authority), keyed by
   (path, attribution_key) — exactly the known append-only shapes:
   ``(retrieval_trace_log.jsonl, trace_id)`` and
   ``(source_attributes/source_properties.jsonl, source_cid)``. Match is by
   EXACT bundle-relative path string AND exact attribution_key: a different
   key on an allowlisted path REJECTS (a producer cannot ride a path's
   authorization while swapping in another key from the §C9.1 closed key
   set). An honored declaration additionally requires its on-disk object to
   be a REGULAR FILE (not FIFO / socket / device / symlink / directory — a
   non-regular object can never satisfy a JSONL record-shape contract). The
   allowlist authorizes the downgrade ONLY; the substantive guarantee is
   still attribution-key coverage, discharged by the §C9.1
   ``AppendOnlyAttributedCheck``. Adding an entry to this frozenset is a
   verifier-distribution change (a contract motion), never a manifest field.
3. Auditor-supplied minimum-class policy (construction-time authority): an
   OPTIONAL mapping ``path-pattern → minimum OwnerKind`` supplied at
   ``BundleVerifier`` construction — the only mechanism besides the static
   allowlist that may LOWER a path's floor. Discipline: exact-path or
   root-anchored glob patterns only; never sourced from the manifest; every
   path whose floor a policy entry lowers is reported VERBOSELY on the
   verdict face; a policy entry may never act on an ENVELOPE path.
   Precedence: a path's effective floor is the STRONGER of its
   static-allowlist floor and any matching auditor-policy floor — the two
   authorities compose by ``stronger_of``, never by override (a stricter
   auditor entry on an allowlisted path raises the floor back).
4. Effective guarantee (computed only AFTER the point-1 authorization gate
   passes) = ``stronger_of(manifest_request, policy_floor)``: a producer
   requesting STRICT_SHA against a rank-1 policy floor keeps rank 2 — the
   floor is a MINIMUM, never a cap.
5. Existing shape validation is unchanged and still required:
   ``validate_append_only_files`` (§C9.1) runs exactly as before. A
   declaration must be BOTH well-formed (shape) AND authorized (floor) to be
   honored; either failing is fail-closed.

Pure stdlib (``os``, ``stat``, ``fnmatch``, ``dataclasses``). Imports only
the integrity-ownership vocabulary (``Guarantee``, ``OwnerKind``) and the
envelope name set.
"""

from __future__ import annotations

import os
import stat as stat_module
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Mapping

from .conservation import validate_fs_ignore_patterns
from .integrity_ownership import ENVELOPE_PATHS, Guarantee, OwnerKind

__all__ = [
    "APPEND_ONLY_FLOOR_VIOLATION",
    "GUARANTEE_RANK",
    "STATIC_APPEND_ONLY_ALLOWLIST",
    "FloorResult",
    "check_append_only_floor",
    "stronger_of",
    "validate_min_class_policy",
]

APPEND_ONLY_FLOOR_VIOLATION = "APPEND_ONLY_FLOOR_VIOLATION"

# The §C9.2 guarantee lattice (rank; higher = stronger). Rank 2 is a single
# equivalence tier on purpose: byte-equality, pinned blob hash, and CID
# recompute each fix the file's full content; they differ in mechanism, not
# floor strength, and none is a producer-electable weakening of the others.
GUARANTEE_RANK: Mapping[Guarantee, int] = {
    Guarantee.DSSE_BINDING_SET_CLOSURE: 3,
    Guarantee.BYTE_EQUALITY: 2,
    Guarantee.PINNED_BLOB_HASH: 2,
    Guarantee.CID_RECOMPUTE: 2,
    Guarantee.ATTRIBUTION_KEY_COVERAGE: 1,
    Guarantee.NONE: 0,
}

# Closed static allowlist, keyed by (path, attribution_key) — exactly the two
# live corpus shapes (regular files, JSONL record shape: one JSON object per
# non-blank line). Growing this set is a verifier-distribution change (a
# contract motion under §C9.2), never a manifest field.
STATIC_APPEND_ONLY_ALLOWLIST: frozenset[tuple[str, str]] = frozenset(
    {
        ("retrieval_trace_log.jsonl", "trace_id"),
        ("source_attributes/source_properties.jsonl", "source_cid"),
    }
)

# Floor ranks for the owner classes a min-class policy may name.
_POLICY_KIND_RANK: Mapping[OwnerKind, int] = {
    OwnerKind.APPEND_ONLY: 1,  # authorizes the rank 2 → 1 downgrade
    OwnerKind.STRICT_SHA: 2,  # explicit no-lowering / raises an allowlisted floor back
}

_DEFAULT_FLOOR_RANK = 2  # STRICT_SHA (BYTE_EQUALITY) for every path


def stronger_of(a: Guarantee, b: Guarantee) -> Guarantee:
    """The higher-ranked guarantee; ties keep ``a`` (the manifest's declared
    mechanism — rank-2 members are one equivalence tier)."""
    return b if GUARANTEE_RANK[b] > GUARANTEE_RANK[a] else a


def validate_min_class_policy(
    policy: Mapping[str, Any] | None,
) -> dict[str, OwnerKind]:
    """Validate an auditor min-class policy at construction time (fail early).

    Keys follow the same exact-path / root-anchored-glob discipline as the
    conservation ``fs_ignore`` view (one pattern grammar, no second dialect).
    Values must name a floorable owner class (``append_only`` to authorize
    the downgrade for matching paths, ``strict_sha`` to explicitly hold —
    or raise back — the byte-equality floor). A pattern that could match an
    ENVELOPE path is rejected outright: the envelope's guarantee is never
    policy-adjustable. Raises ``ValueError`` — auditor-side configuration.
    """
    if policy is None:
        return {}
    validated: dict[str, OwnerKind] = {}
    for pattern, kind in policy.items():
        validate_fs_ignore_patterns((pattern,))
        try:
            owner_kind = OwnerKind(kind)
        except ValueError as exc:
            raise ValueError(
                f"min_class_policy[{pattern!r}]: {kind!r} is not an OwnerKind"
            ) from exc
        if owner_kind not in _POLICY_KIND_RANK:
            raise ValueError(
                f"min_class_policy[{pattern!r}]: minimum class must be one of "
                f"{sorted(k.value for k in _POLICY_KIND_RANK)}, got "
                f"{owner_kind.value!r}"
            )
        envelope_hits = sorted(
            name for name in ENVELOPE_PATHS if fnmatchcase(name, pattern)
        )
        if envelope_hits:
            raise ValueError(
                f"min_class_policy pattern {pattern!r} matches ENVELOPE "
                f"path(s) {envelope_hits!r}; the envelope guarantee is never "
                "policy-adjustable"
            )
        validated[pattern] = owner_kind
    return validated


@dataclass(frozen=True, slots=True)
class FloorResult:
    """Outcome of the floor pre-check over a manifest's append-only declarations.

    ``failures`` are (reason_code, detail) pairs (every one is fail-closed:
    the artifact is bad). ``policy_lowered`` lists paths whose downgrade was
    authorized by an auditor policy entry rather than the static allowlist —
    reported verbosely on the verdict face (the downgrade is disclosed,
    never silent).
    """

    failures: tuple[tuple[str, str], ...]
    policy_lowered: tuple[str, ...]


def check_append_only_floor(
    bundle_dir: Path,
    manifest: Any,
    min_class_policy: Mapping[str, OwnerKind] | None = None,
) -> FloorResult:
    """Run the §C9.2 floor predicate over every append-only declaration.

    HARD PRE-CHECK semantics: a failure here is a REJECT regardless of the
    declared file's content — no salvage-to-byte-check, no honoring of an
    unauthorized downgrade. Only inspects the on-disk object with ``lstat``
    (never opens content — a FIFO must not block the gate).
    """
    policy = dict(min_class_policy or {})
    failures: list[tuple[str, str]] = []
    policy_lowered: list[str] = []

    allowlisted_paths = {p for p, _k in STATIC_APPEND_ONLY_ALLOWLIST}

    for spec in getattr(manifest, "append_only_files", ()) or ():
        if not isinstance(spec, dict):
            # Shape malformations are the §C9.1 validator's jurisdiction
            # (rejected at the parse boundary for loader-parsed manifests).
            continue
        path = spec.get("path", "")
        key = spec.get("attribution_key", "")

        # Lexical containment guard BEFORE any authority consult or lstat:
        # the §C9.1 validator rejects these shapes at the parse boundary, but
        # a directly-constructed manifest bypasses the loader, and an lstat
        # on a traversal path would be an out-of-bundle existence oracle.
        if not path or path.startswith("/") or "\\" in path or ".." in path.split("/"):
            failures.append(
                (
                    APPEND_ONLY_FLOOR_VIOLATION,
                    f"append_only_files[{path!r}]: path is not a clean "
                    "bundle-relative file path",
                )
            )
            continue

        # Key-swap guard on an allowlisted path: authorization is per
        # (path, attribution_key) pair, never per path alone.
        if path in allowlisted_paths and (path, key) not in (
            STATIC_APPEND_ONLY_ALLOWLIST
        ):
            failures.append(
                (
                    APPEND_ONLY_FLOOR_VIOLATION,
                    f"append_only_files[{path!r}]: attribution_key {key!r} "
                    "does not match the statically allowlisted key for this "
                    "path — a producer cannot ride a path's authorization "
                    "while swapping in a different attribution key",
                )
            )
            continue

        # Effective floor = stronger_of over every authority that speaks for
        # this path; no authority → the rank-2 default. (Authorities compose
        # by stronger_of, never override: a stricter auditor entry on an
        # allowlisted path raises the floor back.)
        floor_ranks: list[int] = []
        statically_allowlisted = (path, key) in STATIC_APPEND_ONLY_ALLOWLIST
        if statically_allowlisted:
            floor_ranks.append(1)
        policy_matched = False
        for pattern, kind in policy.items():
            if fnmatchcase(path, pattern):
                policy_matched = True
                floor_ranks.append(_POLICY_KIND_RANK[kind])
        effective_floor = max(floor_ranks) if floor_ranks else _DEFAULT_FLOOR_RANK

        if effective_floor > GUARANTEE_RANK[Guarantee.ATTRIBUTION_KEY_COVERAGE]:
            failures.append(
                (
                    APPEND_ONLY_FLOOR_VIOLATION,
                    f"append_only_files[{path!r}]: APPEND_ONLY (rank 1) "
                    "requested but the path's floor is rank "
                    f"{effective_floor} — the downgrade from byte-equality "
                    "is not authorized by the static allowlist or an "
                    "auditor min-class policy entry (rejected regardless of "
                    "content; the floor is a hard pre-check)",
                )
            )
            continue

        # Honored declaration: the on-disk object must be a REGULAR file.
        # lstat (no follow, no open): a symlink, FIFO, socket, device, or
        # directory at an honored append-only path fails closed. Absence is
        # the AppendOnlyAttributedCheck's finding, not the floor's.
        try:
            lst = os.lstat(bundle_dir / path)
        except OSError:
            lst = None
        if lst is not None and not stat_module.S_ISREG(lst.st_mode):
            failures.append(
                (
                    APPEND_ONLY_FLOOR_VIOLATION,
                    f"append_only_files[{path!r}]: on-disk object is not a "
                    "regular file — a non-regular object can never satisfy "
                    "the JSONL record-shape contract",
                )
            )
            continue

        if policy_matched and not statically_allowlisted:
            policy_lowered.append(path)

    return FloorResult(
        failures=tuple(failures),
        policy_lowered=tuple(policy_lowered),
    )
