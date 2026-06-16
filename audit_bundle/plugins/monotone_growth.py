"""audit_bundle/plugins/monotone_growth.py — TypedCheck: monotone corpus growth (C11).

Implements the audit-bundle contract §C11 (adversarial corpus invariant).
Asserts that the adversarial corpus only ever grows: the set of case IDs in
current_version must be a superset of those in prior_version.

The invariant is HARD-ENFORCED: any removed case ID fails closed
(ADVERSARIAL_CORPUS_SHRANK), with no escape hatch. An earlier version permitted
removals on a major-version bump when a ``removal_authorization.json`` named a
reviewer — but both signals were bundle-controlled (the version strings come
from corpus filenames, and the reviewer assertion was an unsigned bundle file),
so a crafted bundle could self-authorize a removal and ride exit 0. That is a
false-green for the monotone-growth guarantee; the hatch was removed. A real
authorized-removal capability would require a signature over the specific
removal, verified against a key the bundle does not supply (out-of-band /
verifier-pinned) — deferred until such a capability is genuinely needed.
"""

from __future__ import annotations

from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.admission import admit_jsonl_file
from audit_bundle.plugin import PluginResult


class MonotoneGrowthCheck:
    name: str = "monotone_growth"
    # exact-path-only: the former {"corpus/", "previous_corpus/"} trailing-slash
    # pseudo-prefixes were inert (consumed by exact match, never matched). Dropped.
    applies_to_files: frozenset[str] = frozenset()

    def __init__(self, current_version: str, prior_version: str) -> None:
        self.current_version = current_version
        self.prior_version = prior_version

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_corpus_path(self, base: Path, version: str) -> Path:
        """Return the corpus.jsonl path for a given version component.

        If base/version is itself a file, return it directly.
        If it is a directory, return base/version/corpus.jsonl.
        """
        candidate = base / version
        if candidate.is_dir():
            return candidate / "corpus.jsonl"
        return candidate

    def _load_case_ids(self, corpus_file: Path) -> set[str]:
        """Parse a corpus.jsonl file and return the set of case IDs (line keys).

        Raises OSError on an unreadable file and ValueError (which covers
        json.JSONDecodeError, UnicodeDecodeError, and the explicit non-object
        rejection below) on malformed content. check() maps both to a
        fail-closed ADVERSARIAL_CORPUS_UNREADABLE reject.
        """
        ids: set[str] = set()
        for obj in admit_jsonl_file(corpus_file):
            if not isinstance(obj, dict):
                # A valid-JSON non-object line ("foo" / 123 / [...]) would
                # raise AttributeError on obj.get() below.
                raise ValueError(f"corpus line is not a JSON object: {obj!r:.80}")
            # Accept "id", "case_id", or the first key as the canonical ID.
            case_id = (
                obj.get("id") or obj.get("case_id") or next(iter(obj.values()), None)
            )
            if case_id is not None:
                ids.add(str(case_id))
        return ids

    # ------------------------------------------------------------------
    # Protocol method
    # ------------------------------------------------------------------

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        """Assert the current corpus is a strict superset of the prior corpus."""
        current_file = self._resolve_corpus_path(
            bundle_dir / "corpus", self.current_version
        )
        prior_file = self._resolve_corpus_path(
            bundle_dir / "previous_corpus", self.prior_version
        )

        files_audited: list[str] = [str(current_file), str(prior_file)]

        if not current_file.exists():
            return PluginResult(
                ok=False,
                reason_code="ADVERSARIAL_CORPUS_SHRANK",
                detail=(
                    f"current corpus {self.current_version!r} not found at {current_file}"
                ),
                files_audited=tuple(files_audited),
            )

        if not prior_file.exists():
            return PluginResult(
                ok=False,
                reason_code="ADVERSARIAL_CORPUS_SHRANK",
                detail=(
                    f"prior corpus {self.prior_version!r} not found at {prior_file}"
                ),
                files_audited=tuple(files_audited),
            )

        # Corpus bytes are bundle-controlled; an unreadable or malformed file
        # must be a recorded REJECT, not an exception escaping the plugin
        # (which would degrade to a VERIFIER_INTERNAL_ERROR / exit-2 crash).
        # ValueError covers json.JSONDecodeError, UnicodeDecodeError, and the
        # non-object-line rejection raised inside _load_case_ids.
        try:
            current_ids = self._load_case_ids(current_file)
            prior_ids = self._load_case_ids(prior_file)
        except (OSError, ValueError) as exc:
            return PluginResult(
                ok=False,
                reason_code="ADVERSARIAL_CORPUS_UNREADABLE",
                detail=(
                    f"corpus file could not be read or parsed: "
                    f"{type(exc).__name__}: {exc}"
                ),
                files_audited=tuple(files_audited),
            )

        removed = prior_ids - current_ids
        if not removed:
            return PluginResult(
                ok=True,
                reason_code="PASS",
                detail=(
                    f"corpus monotone: {len(current_ids)} current cases "
                    f"⊇ {len(prior_ids)} prior cases"
                ),
                files_audited=tuple(files_audited),
            )

        # HARD-ENFORCED: any removal fails closed. There is no bundle-supplied
        # escape hatch — an unsigned in-bundle authorization carries no authority
        # the bundle's own author couldn't forge (see module docstring).
        return PluginResult(
            ok=False,
            reason_code="ADVERSARIAL_CORPUS_SHRANK",
            detail=f"cases removed: {sorted(removed)}",
            files_audited=tuple(files_audited),
        )


register_typed_check("monotone_growth")
