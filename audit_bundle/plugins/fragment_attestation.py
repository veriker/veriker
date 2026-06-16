"""audit_bundle/plugins/fragment_attestation.py — TypedCheck: L8 fragment attestation.

Enforces the L8 fragment-keel deterministic core on the STANDARD verify path:
for every *attestable* fragment
anchor, re-derive the cited span from the frozen source snapshot and assert it
matches the claimed quote under the versioned text canonicalization (D7.d below —
NFC + casefold + punctuation-drop + whitespace-collapse; case/punctuation/
whitespace-insensitive, NOT byte-exact). This closes the "fragment anchors are
informational" gap — before this plugin, BundleVerifier.verify() never re-derived
a span and a fabricated quote attributed to a real, admitted source rode along
inside an otherwise-green bundle.

Data model (canonical — NOT the pilot-private payload/spans.json shape):
    manifest.fragment_anchors : dict[anchor_name -> anchor_dict]
    manifest.snapshots        : dict[source_cid -> relative_path_in_bundle]

Each anchor_dict is a FragmentID canonical dict (kind-discriminated; see
audit_bundle/fragments/fragment_id.py) OPTIONALLY carrying two L8 sibling keys
(ignored by fragment_from_dict, which reads only the locator keys):

    content_selector : { "exact": "<claimed quoted text>", ... }   # the claim
    segmenter_version: "<SEGMENTER_VERSION the anchor was produced under>"

An anchor is ATTESTABLE iff it carries content_selector.exact — i.e. it asserts
"source S says 'X'". A pure-locator anchor (no claim) asserts nothing falsifiable
about a quote and is skipped (preserves legacy informational anchors, e.g.
examples/spectra_minimal whose snapshots are absent).

Keel rules enforced here (ADR §2):
  D3.a — FAIL-CLOSED. An attestable anchor whose source snapshot is unavailable,
         whose offset/sentence-index is unresolvable, or whose re-derived bytes do
         not match the claimed quote => verify() ok=False. Never advisory-pass.
  D3.b — The verdict is rendered SOLELY from the deterministic_offset (byte range,
         or sentence index against the pinned segmenter) over the FROZEN snapshot
         bytes, compared to the claimed `exact` text. The selector's prefix/suffix
         relocation fields are NEVER consulted in this same-snapshot path — they
         only PROPOSE a location when verifying against a different snapshot.
  D7.a — byte offsets are half-open [start, end) over the UTF-8 snapshot bytes.
  D7.b — sentence-id determinism is the pinned segmenter; SEGMENTER_VERSION drift
         on a stored anchor fails closed (SEGMENTER_MISMATCH).
  D7.d — text canonicalization (NFC + casefold + punctuation-drop + whitespace-
         collapse) is versioned (TEXT_CANONICALIZATION_VERSION) and deterministic;
         a normalized-equality verdict is still a model-free verdict.

Stdlib only (json, re, unicodedata, pathlib).
"""

from __future__ import annotations

# Verifier self-pollution guard: disable bytecode generation so importing or
# running this from inside a bundle directory never drops __pycache__/*.pyc
# into the bundle as a side effect.
import sys

sys.dont_write_bytecode = True

import os  # noqa: E402
from pathlib import Path  # noqa: E402

from audit_bundle.bundle_manifest import (  # noqa: E402
    UnsafeBundlePath,
    _safe_bundle_path,
    open_regular_fd_nofollow,
    register_typed_check,
)
from audit_bundle.snapshots.cid import compute_cid  # noqa: E402
from audit_bundle.fragments.fragment_id import (  # noqa: E402
    BadFragmentID,
    ByteOffsetFragment,
    SentenceIDFragment,
    fragment_from_dict,
)
from audit_bundle.fragments.sentence_segmenter import (  # noqa: E402
    SEGMENTER_VERSION,
    resolve_sentence_id,
)
from audit_bundle.plugin import PluginResult  # noqa: E402

# The attestability vocabulary — what counts as a quote claim, the versioned
# text canonicalization (ADR D7.d), and the content key that binds "verified"
# to exact anchor bytes — is SHARED with the core coverage guard and the VE
# producer pipeline (audit_bundle/fragments/attestable.py), so the layers can
# never disagree. The old module-local names are kept as aliases; the version
# constant is re-exported unchanged.
from audit_bundle.fragments.attestable import (  # noqa: E402
    TEXT_CANONICALIZATION_VERSION,
)
from audit_bundle.fragments.attestable import claimed_exact as _claimed_exact  # noqa: E402
from audit_bundle.fragments.attestable import fragment_anchor_key  # noqa: E402
from audit_bundle.fragments.attestable import normalize_text as _normalize  # noqa: E402


class FragmentAttestationCheck:
    """C2-full / L8 deterministic fragment-attestation check (default verify path)."""

    name: str = "fragment_attestation"
    # Owns no files exclusively — snapshot files are still SHA-checked by
    # file_integrity_many_small. Empty so this plugin does not suppress that.
    applies_to_files: frozenset[str] = frozenset()

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        anchors = getattr(manifest, "fragment_anchors", {}) or {}
        snapshots = getattr(manifest, "snapshots", {}) or {}

        if not anchors:
            return PluginResult(
                ok=True,
                reason_code="NO_ANCHORS",
                detail="manifest carries no fragment_anchors — nothing to attest",
                files_audited=(),
            )

        attested = 0
        skipped = 0
        audited: list[str] = []
        verified_keys: set[str] = set()

        for anchor_name, anchor_dict in anchors.items():
            if not isinstance(anchor_dict, dict):
                return self._fail(
                    "FRAGMENT_ANCHOR_MALFORMED",
                    f"fragment_anchors[{anchor_name!r}] is not an object",
                    audited,
                )

            exact = _claimed_exact(anchor_dict)
            if exact is None:
                # Pure locator, no quote claim -> nothing falsifiable to attest.
                skipped += 1
                continue

            # Parse the locator. (validate_manifest already does this, but the
            # plugin must not assume that ran — fail closed if it can't parse.)
            try:
                fragment = fragment_from_dict(anchor_dict)
            except BadFragmentID as exc:
                return self._fail(
                    "FRAGMENT_ANCHOR_MALFORMED",
                    f"fragment_anchors[{anchor_name!r}] does not parse: {exc}",
                    audited,
                )

            source_cid = fragment.source_cid

            # D3.a — an attestable anchor MUST resolve to a bundled snapshot.
            # No snapshot bytes => the quote cannot be re-derived => FAIL CLOSED.
            rel_path = snapshots.get(source_cid)
            if not rel_path:
                return self._fail(
                    "FRAGMENT_SOURCE_UNRESOLVABLE",
                    f"fragment_anchors[{anchor_name!r}] claims quote {exact[:60]!r} "
                    f"from source_cid={source_cid!r} but that CID is not declared in "
                    f"manifest.snapshots — no source bytes to re-derive against",
                    audited,
                )
            # Route the manifest-controlled snapshot path through the shared
            # fail-closed containment helper (every other snapshot/file read in
            # the verifier already does). A `../`-traversal or absolute path
            # resolves outside the bundle => UnsafeBundlePath => fail closed
            # BEFORE any read. Without this, an attacker-controlled snapshots
            # value turned this plugin into an arbitrary host-file read oracle:
            # the out-of-bundle bytes were surfaced in the FRAGMENT_MISQUOTE
            # detail, leaking ~200 bytes of any UTF-8 file per crafted span.
            try:
                snap_path = _safe_bundle_path(bundle_dir, rel_path)
            except UnsafeBundlePath as exc:
                return self._fail(
                    "FRAGMENT_SOURCE_UNRESOLVABLE",
                    f"fragment_anchors[{anchor_name!r}] source snapshot "
                    f"{rel_path!r} (source_cid={source_cid!r}) does not resolve "
                    f"to a path inside the bundle: {exc}",
                    audited,
                )
            if not snap_path.is_file():
                return self._fail(
                    "FRAGMENT_SOURCE_UNRESOLVABLE",
                    f"fragment_anchors[{anchor_name!r}] source snapshot "
                    f"{rel_path!r} (source_cid={source_cid!r}) is missing from the bundle",
                    audited,
                )
            audited.append(str(snap_path))

            # open_regular_fd_nofollow closes the stat→read TOCTOU the same way
            # the strict-SHA walk does: a regular→FIFO/symlink swap after
            # _safe_bundle_path's lstat is refused at open time, never as a
            # hanging or link-following read. (_safe_bundle_path resolves the
            # join, so a contained symlink→regular snapshot still attests —
            # the as-built tolerance the strict-SHA walk preserves.)
            try:
                with os.fdopen(open_regular_fd_nofollow(snap_path), "rb") as fh:
                    snap_bytes = fh.read()
            except OSError as exc:
                return self._fail(
                    "FRAGMENT_SOURCE_UNRESOLVABLE",
                    f"fragment_anchors[{anchor_name!r}] cannot read snapshot "
                    f"{rel_path!r}: {exc}",
                    audited,
                )

            # BLOCK-02 — bind THESE bytes to the CID the verdict is about to
            # name. The misquote/attested claim below literally asserts
            # "matches source_cid=X", but the deep snapshot-CID validator
            # recomputes X from its OWN later read of the same path; nothing
            # ties the two reads to one byte snapshot. Under mid-run mutation
            # the plugin could attest a quote against bytes the CID check never
            # pinned (quote present in bytes A, manifest CID matching bytes B)
            # and the composite verdict would assert a CID-pinned source
            # supports a quote it does not contain. Recomputing the CID over
            # snap_bytes makes the claim self-certifying: by collision
            # resistance, a green attestation and a green CID check can only
            # ever describe the same bytes. (Sibling precedent: the C16
            # refinement_discharge plugin SHA-binds its obligation read;
            # the manifest itself is single-read per RES-04, so source_cid
            # here and the CID the deep validator compares against are the
            # same pin.) v1 CIDs are sha256-only, so a foreign-scheme
            # source_cid can never match a recompute — fail closed, which is
            # correct: a CID this verifier cannot recompute is a quote claim
            # it cannot bind.
            computed_cid = compute_cid(snap_bytes)
            if computed_cid != source_cid:
                return self._fail(
                    "FRAGMENT_SOURCE_CID_MISMATCH",
                    f"fragment_anchors[{anchor_name!r}] snapshot {rel_path!r} read for "
                    f"quote attestation does not hash to the declared source: "
                    f"declared source_cid={source_cid!r} computed={computed_cid!r} — "
                    "refusing to attest a quote against bytes that are not the "
                    "CID-pinned source",
                    audited,
                )

            # Re-derive the span from the FROZEN snapshot bytes (D3.b / D7.a).
            rederived = self._rederive(anchor_name, fragment, anchor_dict, snap_bytes)
            if isinstance(rederived, PluginResult):
                return rederived  # an early fail-closed result

            # Verdict: normalized-equality (D7.d) vs the claimed quote.
            if _normalize(rederived) != _normalize(exact):
                return self._fail(
                    "FRAGMENT_MISQUOTE",
                    f"fragment_anchors[{anchor_name!r}] MISQUOTE: claimed quote does not "
                    f"match source_cid={source_cid!r} at the cited span (under the "
                    f"versioned text normalization).\n"
                    f"  claimed : {exact[:200]!r}\n"
                    f"  source  : {rederived[:200]!r}\n"
                    f"  (normalized under {TEXT_CANONICALIZATION_VERSION})",
                    audited,
                )
            attested += 1
            # Per-anchor coverage accounting (RES-06 follow-up, mirroring the
            # ratified cross-host per-edge pattern): report the content key of
            # each anchor actually re-derived and matched, so the core guard
            # can assert present − verified == ∅ instead of trusting that a
            # fragment-attesting plugin was wired at all.
            verified_keys.add(fragment_anchor_key(anchor_name, anchor_dict))

        return PluginResult(
            ok=True,
            reason_code="FRAGMENTS_ATTESTED",
            detail=(
                f"{attested} fragment anchor(s) re-derived and matched source under the "
                f"versioned text normalization ({skipped} pure-locator anchor(s) skipped); "
                f"segmenter={SEGMENTER_VERSION}, canon={TEXT_CANONICALIZATION_VERSION}"
            ),
            files_audited=tuple(audited),
            verified_fragment_anchors=frozenset(verified_keys),
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _rederive(
        self,
        anchor_name: str,
        fragment,
        anchor_dict: dict,
        snap_bytes: bytes,
    ) -> str | PluginResult:
        """Re-derive the cited span text from frozen snapshot bytes.

        Returns the re-derived text on success, or a fail-closed PluginResult.
        """
        if isinstance(fragment, ByteOffsetFragment):
            if fragment.end > len(snap_bytes):
                return self._fail(
                    "FRAGMENT_OFFSET_OUT_OF_BOUNDS",
                    f"fragment_anchors[{anchor_name!r}] byte range "
                    f"[{fragment.start}, {fragment.end}) exceeds snapshot length "
                    f"{len(snap_bytes)}",
                    [],
                )
            try:
                return snap_bytes[fragment.start : fragment.end].decode("utf-8")
            except UnicodeDecodeError as exc:
                return self._fail(
                    "FRAGMENT_OFFSET_INVALID_UTF8",
                    f"fragment_anchors[{anchor_name!r}] byte range "
                    f"[{fragment.start}, {fragment.end}) is not valid UTF-8: {exc}",
                    [],
                )

        if isinstance(fragment, SentenceIDFragment):
            # D7.b — sentence-id determinism is the pinned segmenter. If the anchor
            # records the segmenter version it was produced under, drift fails closed.
            declared_ver = anchor_dict.get("segmenter_version")
            if declared_ver is not None and declared_ver != SEGMENTER_VERSION:
                return self._fail(
                    "SEGMENTER_MISMATCH",
                    f"fragment_anchors[{anchor_name!r}] sentence anchor was produced "
                    f"under segmenter {declared_ver!r} but the verifier runs "
                    f"{SEGMENTER_VERSION!r}; sentence indices are not comparable across "
                    f"segmenter versions (ADR D7.b)",
                    [],
                )
            try:
                snap_text = snap_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                return self._fail(
                    "FRAGMENT_OFFSET_INVALID_UTF8",
                    f"fragment_anchors[{anchor_name!r}] snapshot is not valid UTF-8: {exc}",
                    [],
                )
            try:
                _start, _end, sentence_text = resolve_sentence_id(
                    snap_text, fragment.sentence_index
                )
            except BadFragmentID as exc:
                return self._fail(
                    "FRAGMENT_SENTENCE_OUT_OF_RANGE",
                    f"fragment_anchors[{anchor_name!r}] sentence_index "
                    f"{fragment.sentence_index} unresolvable: {exc}",
                    [],
                )
            return sentence_text

        # Page-coord / timestamp-sample / opaque are RESERVED (ADR §3): no
        # deterministic resolver is locked. An attestable anchor of a reserved
        # kind cannot be attested on this path -> fail closed (never silent-pass).
        return self._fail(
            "FRAGMENT_KIND_RESERVED",
            f"fragment_anchors[{anchor_name!r}] kind "
            f"{type(fragment).__name__} carries a quote claim but its resolver is "
            f"RESERVED (not in the L8 deterministic core); cannot attest",
            [],
        )

    @staticmethod
    def _fail(reason_code: str, detail: str, audited: list[str]) -> PluginResult:
        # Prefix the reason code into the detail: BundleVerifier wraps only a
        # plugin's `detail` (not its `reason_code`) into VerifyFailure, so the
        # granular code would otherwise be invisible to verify() consumers and
        # the CLI (which shows the generic "plugin_failed" code for plugins).
        return PluginResult(
            ok=False,
            reason_code=reason_code,
            detail=f"[{reason_code}] {detail}",
            files_audited=tuple(audited),
        )


register_typed_check("fragment_attestation")
