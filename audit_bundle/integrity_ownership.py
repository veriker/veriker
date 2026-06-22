"""audit_bundle/integrity_ownership.py — path → integrity-owner classification.

One positive classification function for the question every file walk in this
verifier currently answers separately as a complement (a skip-set): "who owns
the integrity of this bundle path, and what does that ownership guarantee?"

Today that decision is encoded five times as complements of each other:

  1. ``verifier._step_file_integrity``       skip = typed_checks ∪ plugin
                                             ``applies_to_files`` ∪ append-only
  2. ``plugins/file_integrity_many_small``   Pass-3 surplus sweep skips the
                                             envelope files, ``spec/`` and
                                             ``snapshots/`` trees, the
                                             ``pilot.json``/``README.md``
                                             basenames, and append-only paths
  3. ``verifier._dsse_pre_gate``             ``_SEAM_EXCLUDED`` (envelope files)
  4. ``orchestrator_turn/verifier``          second copy of ``_SEAM_EXCLUDED``
                                             (cross-pillar; EXCLUDED from the
                                             open drop, OSS_RELEASE_BOUNDARY.md)
  5. ``emitter/pipeline.write_bundle``       DSSE payload "files" excludes the
                                             envelope files by construction

Complement-coding means every walk must know every other owner, so a new file
class must be hand-added to every complement (the DSSE sidecar bug: the Pass-3
sweep rejected every sealed bundle until the sidecar was added to its skips).
This module is the positive encoding: a single total function from a
bundle-relative path to its owner class, guarantee floor, and authority
source. It is the same closed-registry / anchored-authority / fail-closed
machine the spec-pinned dispatch layer already uses for outputs, applied one
layer down to file space.

MAP STATUS — built, not yet consumed. No verifier walk calls this module yet;
landing it changes zero behavior. The parity harness
(``tests/test_integrity_ownership_parity.py``) asserts this map agrees with
each existing walk over the real ``examples/`` corpus; rewiring the walks to
consume the map is a separate, gated step.


Classification contract
-----------------------
``classify_path(rel_path, manifest, plugin_files)`` is pure and total: every
path receives exactly one ``OwnerKind`` (partition property; ``UNOWNED`` is
the explicit default, never an exception). Inputs:

* ``rel_path`` — canonical relative-POSIX string under the bundle root
  (forward slashes, no leading ``./``, no trailing slash; the same
  normalization contract the DSSE set-closure walk uses). The function is
  defined over FILE paths; directories are the walks' concern, not the map's.
* ``manifest`` — a ``BundleManifest`` or any duck-typed stand-in. Fields
  consumed: ``files``, ``spec_files``, ``snapshots`` directly, and
  ``append_only_files`` via ``getattr(..., ())`` — that asymmetry
  deliberately mirrors the as-built walks (the Pass-3 sweep is
  getattr-defensive for pre-v0.4 test stubs; everything else assumes the
  field exists). ``typed_checks`` is no longer read since D3 dropped the
  typed_checks-as-paths PLUGIN leg.
* ``plugin_files`` — the union of the constructed plugins'
  ``applies_to_files`` sets. Passed in by the caller because it is
  verifier-configuration-dependent; this module never imports the plugin
  registry (stdlib-only, import-cycle-free).

Precedence (first match wins; design rationale in parentheses):

  1. ENVELOPE      rel_path is exactly ``manifest.json`` or
                   ``bundle.dsse.json`` (top-level only — a nested
                   ``sub/manifest.json`` is NOT envelope, mirroring the
                   Pass-3 full-rel_path match). Ordered first to mirror the
                   only walk that explicitly orders these rules (Pass 3). A
                   manifest that lists an envelope path in ``files`` is
                   structurally self-contradictory (``manifest.json`` cannot
                   contain its own hash; the sidecar postdates the manifest),
                   so the map classifies ENVELOPE even then.
  2. APPEND_ONLY   rel_path is declared in ``append_only_files`` (the
                   ``.get("path", "")`` extraction below mirrors both
                   as-built sites, including the consequence that a malformed
                   path-less spec dict admits ``""``). Ordered above the
                   ``files`` classes because the strict-SHA walk skips an
                   append-only path even if it also appears in ``files``
                   (the loader separately rejects that overlap at parse
                   time).
  3. PLUGIN        rel_path ∈ ``manifest.files`` AND rel_path ∈
                   ``plugin_files`` (an exact-path plugin ``applies_to_files``
                   entry). ``files`` membership is required: an on-disk path
                   covered by a plugin but absent from ``files`` is surplus to
                   the Pass-3 sweep as-built (no plugin skip exists there),
                   i.e. de-facto UNOWNED. D3 (ratified) removed the dead
                   second leg (typed_checks-as-paths) — see the as-built quirk
                   note below — so PLUGIN is now files ∩ exact-path
                   plugin_files only.
  4. STRICT_SHA    rel_path ∈ ``manifest.files`` (and no rule above fired).
                   Declaration outranks location: ``spec/x`` or
                   ``snapshots/x`` or a scaffold basename listed in ``files``
                   is byte-equality-checked as-built, so it classifies
                   STRICT_SHA, not by its directory or name.
  5. SNAPSHOT      rel_path appears among ``manifest.snapshots`` VALUES
                   (CID-recomputed by the deep validator wherever it lives),
                   or its first path segment is ``snapshots`` (tree
                   convention the Pass-3 sweep skips wholesale). Declared
                   values carry the cid_recompute guarantee; tree-only
                   membership carries none (a surplus file inside
                   ``snapshots/`` is skipped unchecked as-built).
  6. SPEC          first path segment is ``spec``. Guarantee pinned_blob_hash
                   only for ``spec/<basename>`` paths whose basename matches
                   a declared ``spec_files`` key's basename (the pinning walk
                   checks exactly ``spec/<Path(key).name>``, flat — a deeper
                   ``spec/sub/x.md`` is never pinned); tree-only membership
                   carries none (surplus inside ``spec/`` is skipped
                   unchecked as-built, same as SNAPSHOT).
  7. SCAFFOLD      rel_path is exactly ``pilot.json`` or ``README.md`` at the
                   TOP LEVEL (D4, ratified as amended: narrowed from the prior
                   any-depth basename match — a deeper ``deep/dir/README.md``
                   is now UNOWNED). A quiet tolerance with a committed-removal
                   direction; the Pass-3 sweep surfaces every tolerated
                   undeclared scaffold to the auditor.
  8. UNOWNED       everything else. The conservation step (future, gated)
                   will fail closed on these; today only the Pass-3 sweep
                   flags them, and only when that plugin is constructed.

As-built quirks deliberately mirrored (flagged, not resolved)
-------------------------------------------------------------
* ``typed_checks`` entries are PLUGIN NAMES, yet the as-built strict-SHA skip
  set membership-tested file paths against them — so a file literally named
  like a registered plugin was silently exempt from strict-SHA (corpus-proven
  zero collisions). D3 (ratified) DROPPED this dead leg at the rewiring gate:
  the map no longer consults ``typed_checks`` at all, so a typed_checks-named
  file in ``files`` is now STRICT_SHA (strictly stricter). Kept here as the
  historical rationale, not a live behavior.
* Most ``applies_to_files`` declarations are directory prefixes with a
  trailing slash (``"spec/"``, ``"corpus/"``). The skip set consumes them by
  EXACT string match, so they can never match a real file path and are
  de-facto inert; only exact-path entries (e.g. the sensor reference
  plugin's ``energy_score.json``) ever exempt anything. Mirrored exactly:
  this module does no prefix matching.
* The ENVELOPE guarantee is lane-conditional as-built: with a sidecar and a
  DSSE context the full gate enforces it; a sidecar without a context is
  rejected fail-closed; an UNSEALED pre-cutover bundle's ``manifest.json``
  is parse-validated but byte-integrity-owned by nobody. That last lane is
  part of the file-layer conservation gap this map exists to eventually
  close.
* The sealed set-closure walk is STRICTER than the unsealed Pass-3 sweep:
  under seal, every on-disk file must be payload-listed or envelope — the
  SCAFFOLD allowance and the spec/snapshots tree skips do not exist there.
  The map does not erase per-walk differences; each walk derives its own
  membership predicate from the one classification.

Pure stdlib (``dataclasses``, ``enum``). No audit_bundle imports.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

__all__ = [
    "ENVELOPE_PATHS",
    "SCAFFOLD_BASENAMES",
    "SNAPSHOTS_TOP",
    "SPEC_TOP",
    "Authority",
    "Guarantee",
    "Owner",
    "OwnerKind",
    "UnsafeBundleRelPath",
    "append_only_declared_paths",
    "classify_path",
    "require_canonical_rel_path",
]


# ---------------------------------------------------------------------------
# Owner-class vocabulary (closed sets — adding a member is a contract motion)
# ---------------------------------------------------------------------------


class OwnerKind(str, Enum):
    """The closed set of integrity-owner classes. Exactly one per path."""

    ENVELOPE = "envelope"
    STRICT_SHA = "strict_sha"
    SPEC = "spec"
    SNAPSHOT = "snapshot"
    APPEND_ONLY = "append_only"
    PLUGIN = "plugin"
    SCAFFOLD = "scaffold"
    UNOWNED = "unowned"


class Guarantee(str, Enum):
    """The guarantee floor an owner class provides for its paths.

    ``NONE`` is an honest tag, not a placeholder: SCAFFOLD and UNOWNED paths
    have no integrity check as-built, PLUGIN paths delegate to a
    plugin-specific check whose strength this map records as delegation (not
    as a floor), and tree-only SPEC/SNAPSHOT membership is a skip without a
    check.
    """

    BYTE_EQUALITY = "byte_equality"
    ATTRIBUTION_KEY_COVERAGE = "attribution_key_coverage"
    CID_RECOMPUTE = "cid_recompute"
    DSSE_BINDING_SET_CLOSURE = "dsse_binding_set_closure"
    PINNED_BLOB_HASH = "pinned_blob_hash"
    NONE = "none"


class Authority(str, Enum):
    """Who supplies the authority for a path's class membership.

    Same trust frame as the spec-pinned dispatch layer: the verifier does not
    trust the producer; whatever the producer declares is tagged as such, and
    auditor/verifier-side authority arrives at construction time, never via
    the manifest.
    """

    VERIFIER_STATIC = "verifier_static"  # hard-coded in the verifier distribution
    PRODUCER_DECLARED = "producer_declared"  # a manifest field the producer authors
    AUDITOR_SUPPLIED = "auditor_supplied"  # injected at verifier construction


@dataclass(frozen=True, slots=True)
class Owner:
    """The classification result for one path: kind + guarantee + authority."""

    kind: OwnerKind
    guarantee: Guarantee
    authority: Authority


# ---------------------------------------------------------------------------
# Structural constants (the positive encodings of today's literals)
# ---------------------------------------------------------------------------

# The seam spec's structural envelope files. The sidecar is written AFTER the
# manifest and signs its hash, so neither can appear in manifest.files of a
# verifiable bundle. Top-level names only.
ENVELOPE_PATHS: frozenset[str] = frozenset({"manifest.json", "bundle.dsse.json"})

# Pilot dev-dir scaffolding the Pass-3 sweep tolerates at TOP LEVEL only (D4:
# narrowed from any-depth). Matched against the full rel_path, which for a
# top-level file equals its basename. Committed-removal direction.
SCAFFOLD_BASENAMES: frozenset[str] = frozenset({"pilot.json", "README.md"})

# Top-level trees the Pass-3 sweep skips wholesale.
SPEC_TOP = "spec"
SNAPSHOTS_TOP = "snapshots"


# ---------------------------------------------------------------------------
# Canonical rel-path discipline (the write-side counterpart of the verifier's
# read-side containment in bundle_manifest._safe_bundle_path / _safepath)
# ---------------------------------------------------------------------------


class UnsafeBundleRelPath(ValueError):
    """A bundle-relative path failed the canonical-form discipline."""


def require_canonical_rel_path(
    rel_path: object, *, forbid_envelope: bool = True
) -> str:
    """Fail closed unless ``rel_path`` is a canonical bundle-relative POSIX path.

    The verifier's read side resolves manifest paths and asserts containment
    (``_safe_bundle_path``, ``resolve_within``); this is the WRITE-side rule the
    emitter applies to ``BundleContent.files`` / ``spec_files`` keys before any
    byte hits disk. It is deliberately STRICTER than the read side — lexical
    canonical form, not resolve-then-check — because a manifest key is an
    identity the digests and the DSSE sidecar bind to, so two spellings of one
    file (``a/b`` vs ``a/../a/b``) or a per-OS reading (backslash) must never
    exist. Strictly-stricter keeps emit-green ⇒ verifier-green.

    Rejected (raises :class:`UnsafeBundleRelPath`):
      * non-``str``, empty, or NUL-bearing values;
      * absolute paths — POSIX (``/x``) or Windows drive (``C:/x``) — which
        ``pathlib``'s ``/`` operator would let replace the bundle root;
      * backslashes (a separator on Windows, a filename byte on POSIX: the
        same key would name different on-disk trees per OS);
      * any ``.``, ``..``, or empty segment (traversal + non-canonical forms
        like ``a//b``, ``./a``, ``a/``);
      * with ``forbid_envelope`` (the default), the top-level structural
        envelope names in :data:`ENVELOPE_PATHS` — the manifest cannot list
        itself, and the seal path excludes envelope names from the sidecar,
        so admitting one would record a digest the written bundle no longer
        matches and the signature never covered.

    Returns ``rel_path`` unchanged so call sites can validate inline.
    """
    if not isinstance(rel_path, str):
        raise UnsafeBundleRelPath(
            f"bundle rel_path must be str, got {type(rel_path).__name__}"
        )
    if not rel_path:
        raise UnsafeBundleRelPath("bundle rel_path must be non-empty")
    if "\x00" in rel_path:
        raise UnsafeBundleRelPath(f"bundle rel_path {rel_path!r} contains NUL")
    if "\\" in rel_path:
        raise UnsafeBundleRelPath(
            f"bundle rel_path {rel_path!r} contains a backslash — bundle paths "
            "are POSIX-relative ('/' separators only)"
        )
    if rel_path.startswith("/"):
        raise UnsafeBundleRelPath(f"bundle rel_path {rel_path!r} is absolute")
    if len(rel_path) >= 2 and rel_path[1] == ":":
        raise UnsafeBundleRelPath(
            f"bundle rel_path {rel_path!r} looks like a Windows drive path"
        )
    for segment in rel_path.split("/"):
        if segment in ("", ".", ".."):
            raise UnsafeBundleRelPath(
                f"bundle rel_path {rel_path!r} has a {segment!r} segment — "
                "paths must be canonical relative form (no traversal, no "
                "empty or dot segments)"
            )
    if forbid_envelope and rel_path in ENVELOPE_PATHS:
        raise UnsafeBundleRelPath(
            f"bundle rel_path {rel_path!r} is a structural envelope name — "
            "manifest.json/bundle.dsse.json are written by the pipeline, "
            "never supplied as content"
        )
    return rel_path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def append_only_declared_paths(manifest: Any) -> frozenset[str]:
    """The declared append-only path set, extracted exactly as the walks do.

    Mirrors both as-built extraction sites byte-for-byte in semantics:
    ``getattr`` default for pre-v0.4 stubs, ``isinstance(spec, dict)``
    filter, and ``spec.get("path", "")`` — including the consequence that a
    malformed path-less spec dict contributes ``""`` to the set (the §C9.1
    well-formedness validator rejects that shape for loader-parsed manifests,
    so it is reachable only via directly constructed ones).
    """
    return frozenset(
        spec.get("path", "")
        for spec in getattr(manifest, "append_only_files", ())
        if isinstance(spec, dict)
    )


def _basename(rel_path: str) -> str:
    """Final path segment of a relative-POSIX path string."""
    return rel_path.rsplit("/", 1)[-1]


def _top_segment(rel_path: str) -> str:
    """First path segment, exactly as the Pass-3 sweep computes it."""
    return rel_path.split("/")[0]


def _spec_pinned_offline_paths(manifest: Any) -> frozenset[str]:
    """The flat ``spec/<basename>`` paths the spec-pinning walk actually checks.

    ``spec_files`` KEYS are spec-document paths (often repo-relative), not
    bundle paths; the walk resolves each to the offline copy at
    ``spec/<basename(key)>``. Only those exact flat paths carry the pinned
    guarantee.
    """
    spec_files = manifest.spec_files
    return frozenset(f"{SPEC_TOP}/{_basename(key)}" for key in spec_files)


# ---------------------------------------------------------------------------
# The classification function
# ---------------------------------------------------------------------------


def classify_path(
    rel_path: str,
    manifest: Any,
    plugin_files: frozenset[str],
) -> Owner:
    """Classify one bundle-relative path into its integrity-owner class.

    Pure and total: returns exactly one ``Owner`` for any string input,
    ``UNOWNED`` by default. Precedence and the mirrored as-built quirks are
    documented in the module docstring; this function IS that table.
    """
    # 1. ENVELOPE — structural seam files, top-level exact names.
    if rel_path in ENVELOPE_PATHS:
        return Owner(
            kind=OwnerKind.ENVELOPE,
            guarantee=Guarantee.DSSE_BINDING_SET_CLOSURE,
            authority=Authority.VERIFIER_STATIC,
        )

    # 2. APPEND_ONLY — declared reclassification to attribution-key coverage.
    if rel_path in append_only_declared_paths(manifest):
        return Owner(
            kind=OwnerKind.APPEND_ONLY,
            guarantee=Guarantee.ATTRIBUTION_KEY_COVERAGE,
            authority=Authority.PRODUCER_DECLARED,
        )

    # 3 + 4. Declared in manifest.files: PLUGIN if covered by an exact-path
    # plugin applies_to_files entry (auditor-supplied), else STRICT_SHA.
    # D3 (ratified) dropped the second, dead PLUGIN leg — typed_checks
    # entries are plugin NAMES, and membership-testing file PATHS against them
    # exempted a file literally named like a plugin from byte-equality
    # (corpus-proven zero collisions). Removing it makes the verifier strictly
    # stricter: a typed_checks-named file in `files` is now STRICT_SHA.
    if rel_path in manifest.files:
        if rel_path in plugin_files:
            return Owner(
                kind=OwnerKind.PLUGIN,
                guarantee=Guarantee.NONE,
                authority=Authority.AUDITOR_SUPPLIED,
            )
        return Owner(
            kind=OwnerKind.STRICT_SHA,
            guarantee=Guarantee.BYTE_EQUALITY,
            authority=Authority.PRODUCER_DECLARED,
        )

    # 5. SNAPSHOT — declared values (CID-recomputed wherever they live), then
    # the snapshots/ tree convention (skipped unchecked as-built).
    if rel_path in frozenset(manifest.snapshots.values()):
        return Owner(
            kind=OwnerKind.SNAPSHOT,
            guarantee=Guarantee.CID_RECOMPUTE,
            authority=Authority.PRODUCER_DECLARED,
        )
    top = _top_segment(rel_path)
    if top == SNAPSHOTS_TOP:
        return Owner(
            kind=OwnerKind.SNAPSHOT,
            guarantee=Guarantee.NONE,
            authority=Authority.VERIFIER_STATIC,
        )

    # 6. SPEC — the spec/ tree; pinned guarantee only for the flat
    # spec/<basename> paths the pinning walk actually checks.
    if top == SPEC_TOP:
        if rel_path in _spec_pinned_offline_paths(manifest):
            return Owner(
                kind=OwnerKind.SPEC,
                guarantee=Guarantee.PINNED_BLOB_HASH,
                authority=Authority.PRODUCER_DECLARED,
            )
        return Owner(
            kind=OwnerKind.SPEC,
            guarantee=Guarantee.NONE,
            authority=Authority.VERIFIER_STATIC,
        )

    # 7. SCAFFOLD — top-level pilot.json / README.md only (D4, ratified
    # as amended: narrowed from the prior any-depth basename allowance, so a
    # deeper deep/dir/README.md is now UNOWNED → flagged). A top-level file's
    # rel_path IS its basename, so exact membership in SCAFFOLD_BASENAMES
    # encodes "top-level only". This allowance is a quiet tolerance with a
    # committed removal direction (option c): pilots should declare these
    # files in manifest.files; the Pass-3 sweep surfaces every tolerated
    # undeclared scaffold to the auditor until removal lands.
    if rel_path in SCAFFOLD_BASENAMES:
        return Owner(
            kind=OwnerKind.SCAFFOLD,
            guarantee=Guarantee.NONE,
            authority=Authority.VERIFIER_STATIC,
        )

    # 8. UNOWNED — the explicit default.
    return Owner(
        kind=OwnerKind.UNOWNED,
        guarantee=Guarantee.NONE,
        authority=Authority.VERIFIER_STATIC,
    )
