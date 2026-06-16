"""§C9.1 — Append-only attributed file pinning (extension; schema reservation only at v0.3).

§C9.1 is an EXTENSION to §C9 file_integrity, NOT a new substrate contract — it
mirrors the `human_oversight_attestation` precedent (an extension to C15, not
C21). AI Act C21–C25 stay reserved as planned; C26 is redaction.

v0.3 SCOPE
==========
Schema reservation ONLY. The substrate verifier IGNORES `BundleManifest.append_only_files`
at v0.3 and continues to enforce §C9 strict-SHA from `manifest.files` for every entry.
The `AppendOnlyAttributedCheck` plugin is v0.4 work and is NOT registered here. This
module ships exactly three callable surfaces at v0.3:

  - `AppendOnlySpecMalformed` (re-exported from `audit_bundle.bundle_manifest`)
  - `validate_append_only_files(spec_tuple) -> list[AppendOnlySpecMalformed]`
  - `is_valid_append_only_files(spec_tuple) -> bool`

Both helpers are PURE-FUNCTIONAL over the in-memory tuple: no file I/O, no
`BundleVerifier` import, no `register_typed_check(...)` call. Emitters invoke
the validator at mint time; the verifier never consults it at v0.3.

SIX-SURFACES INVARIANT
======================
§C9 manifest-pinning has SIX surfaces touching `retrieval_trace_log.jsonl`; only
`file_integrity` is strict-SHA. The other five (check #14 path-exists, check #14
`load_trace(path, retrieval_trace_id)`, check #15 candidate_set orphan, check #16
× N per_output_manifests, plugins) are already attribution-scoped via the existing
`load_trace(jsonl_path, trace_id)` machinery. This module does NOT re-engineer any
of the five attribution surfaces — the substrate is already Shape-C-shaped except
for §C9 file_integrity.

CROSS-SUBSTRATE PATH-A (DESIGN STATEMENT, NOT BUG)
==================================================
A consuming product may INTENTIONALLY append RetrievalTrace records to another
substrate's `retrieval_trace_log.jsonl` as a cross-substrate audit channel. The
§C9 strict-SHA invalidation that surfaces from this append is the substrate gap
§C9.1 reserves the v0.4 plugin to close, NOT a bug in either substrate.

TWO-VERIFIER REALITY
====================
The substrate verifier (`audit_bundle.verifier.BundleVerifier`) takes JCS + crypto
+ python-tuf deps post-C18; the offline-only `veriker/cli/verify.py` tool keeps to stdlib.
§C9.1 schema reservation is part of the SUBSTRATE path — this module is stdlib-only
at v0.3 (no new external deps introduced by this stream; JCS + crypto deps belong
to the C18 path).

V0.4 TRANSITION PATH
====================
The v0.4 `AppendOnlyAttributedCheck` plugin sprint will:

  (a) Populate `BundleManifest.append_only_files` from raw JSON in
      `audit_bundle.verifier._load_manifest` (currently the v0.3 round-trip drops
      the field — see `tests/test_c9_1_append_only_files.py::test_B3_...`).
  (b) Skip declared paths in `BundleVerifier._step_file_integrity`.
  (c) Require each declared entry's `attribution_plugin` to return ≥1 matching
      record under the entry's `attribution_key`.
  (d) Migrate the mesh pilot's manifest to declare the shared trace log
      (and the 9 latent log-like files) as `append_only_files` instead of pinning
      their SHA in `manifest.files`.

v0.3 emitters that declare `append_only_files` are FORWARD-COMPATIBLE: the v0.4
plugin reads the same closed-schema shape this module reserves. Extending the
`RESERVED_*` enums at v0.4 must keep the v0.3 values as a subset (monotone-growth
invariant on the schema enums).

Mirrors the schema-reservation pattern shared with S14v3-RES, S17-RES, and S20.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import IO, TYPE_CHECKING

from audit_bundle.admission import admit_bytes
from audit_bundle.bundle_manifest import (
    AppendOnlySpecMalformed,
    UnsafeBundlePath,
    _safe_bundle_path,
    open_regular_fd_nofollow,
)

if TYPE_CHECKING:
    from audit_bundle.bundle_manifest import BundleManifest


# ---------------------------------------------------------------------------
# Reserved enums (v0.3, frozen at this release)
# ---------------------------------------------------------------------------

RESERVED_ATTRIBUTION_KEYS: frozenset[str] = frozenset(
    {"trace_id", "source_cid", "session_id"}
)

RESERVED_VERIFICATION_MODES: frozenset[str] = frozenset(
    {"first_match", "all_attributed"}
)

REQUIRED_SPEC_KEYS: frozenset[str] = frozenset(
    {"path", "attribution_key", "attribution_plugin", "verification_mode"}
)


# ---------------------------------------------------------------------------
# Well-formedness validator
# ---------------------------------------------------------------------------


def _malformation(
    index: int, category: str, observed: object
) -> AppendOnlySpecMalformed:
    """Build an AppendOnlySpecMalformed with a greppable detail string."""
    return AppendOnlySpecMalformed(f"entry[{index}] : {category} : {observed!r}")


def _check_entry(index: int, entry: object) -> list[AppendOnlySpecMalformed]:
    """Per-entry well-formedness check. Returns 0..N malformations for one entry.

    Returns at most one malformation per entry — the first failing check wins.
    Emitters that need to surface multiple issues iterate by fixing the first
    flagged entry and re-running.
    """
    if entry is None:
        return [_malformation(index, "entry-is-None (expected dict)", None)]

    if not isinstance(entry, dict):
        return [
            _malformation(
                index,
                f"entry-is-{type(entry).__name__} (expected dict)",
                entry,
            )
        ]

    entry_keys = frozenset(entry.keys())

    missing = REQUIRED_SPEC_KEYS - entry_keys
    if missing:
        return [
            _malformation(
                index,
                f"missing required key {sorted(missing)[0]!r}",
                sorted(entry.keys(), key=repr),
            )
        ]

    unknown = entry_keys - REQUIRED_SPEC_KEYS
    if unknown:
        return [
            _malformation(
                index,
                f"unknown extra key {sorted(unknown, key=repr)[0]!r} (closed schema at v0.3)",
                sorted(unknown, key=repr),
            )
        ]

    path = entry["path"]
    if not isinstance(path, str):
        return [
            _malformation(index, f"path is {type(path).__name__} (expected str)", path)
        ]
    if path == "":
        return [_malformation(index, "path is empty string", path)]
    if path.startswith("/"):
        return [
            _malformation(
                index, "path is absolute (POSIX-style; must be bundle-relative)", path
            )
        ]
    if len(path) >= 2 and path[0].isalpha() and path[1] == ":":
        return [
            _malformation(
                index,
                "path is absolute (Windows-style; must be bundle-relative)",
                path,
            )
        ]
    # POSIX + Windows separator split; a literal `..` segment in either is rejected.
    segments = path.replace("\\", "/").split("/")
    if ".." in segments:
        return [
            _malformation(
                index, "path contains '..' traversal segment (no path traversal)", path
            )
        ]

    attribution_key = entry["attribution_key"]
    if attribution_key not in RESERVED_ATTRIBUTION_KEYS:
        return [
            _malformation(
                index,
                (
                    f"attribution_key {attribution_key!r} not in reserved enum "
                    f"{sorted(RESERVED_ATTRIBUTION_KEYS)} (closed at v0.3; custom keys defer to v0.4)"
                ),
                attribution_key,
            )
        ]

    attribution_plugin = entry["attribution_plugin"]
    if not isinstance(attribution_plugin, str):
        return [
            _malformation(
                index,
                f"attribution_plugin is {type(attribution_plugin).__name__} (expected str)",
                attribution_plugin,
            )
        ]
    if attribution_plugin == "":
        return [
            _malformation(
                index, "attribution_plugin is empty string", attribution_plugin
            )
        ]

    verification_mode = entry["verification_mode"]
    if verification_mode not in RESERVED_VERIFICATION_MODES:
        return [
            _malformation(
                index,
                (
                    f"verification_mode {verification_mode!r} not in reserved enum "
                    f"{sorted(RESERVED_VERIFICATION_MODES)}"
                ),
                verification_mode,
            )
        ]

    return []


def validate_append_only_files(
    spec_tuple: tuple[dict, ...],
) -> list[AppendOnlySpecMalformed]:
    """Validate an `append_only_files` tuple against the v0.3 closed schema.

    Returns a list of `AppendOnlySpecMalformed` exception instances — one per
    offending entry (or one for tuple-level violations like duplicate paths) —
    so emitters can surface multiple issues in a single validation pass. An
    empty tuple `()` returns `[]` (W3 + v0.2 + v0.2.1 baseline back-compat).

    NOT raised — RETURNED. Callers decide whether to raise, log, or aggregate.
    """
    malformations: list[AppendOnlySpecMalformed] = []
    for i, entry in enumerate(spec_tuple):
        malformations.extend(_check_entry(i, entry))

    # Tuple-level: duplicate-path closure. Only counted if all entries had a
    # string `path` (otherwise per-entry checks have already surfaced the issue).
    str_paths = [
        e["path"]
        for e in spec_tuple
        if isinstance(e, dict) and isinstance(e.get("path"), str)
    ]
    if len(set(str_paths)) != len(str_paths):
        seen: set[str] = set()
        for p in str_paths:
            if p in seen:
                malformations.append(
                    AppendOnlySpecMalformed(
                        f"duplicate path {p!r} declared more than once in append_only_files"
                    )
                )
                break
            seen.add(p)

    return malformations


def is_valid_append_only_files(spec_tuple: tuple[dict, ...]) -> bool:
    """Thin convenience wrapper: True iff `validate_append_only_files` returns `[]`."""
    return len(validate_append_only_files(spec_tuple)) == 0


# ---------------------------------------------------------------------------
# v0.4 AppendOnlyAttributedCheck plugin
# ---------------------------------------------------------------------------
#
# Composes with verifier._step_file_integrity skip logic: when a path is
# declared in append_only_files, verifier skips strict-SHA for that path and
# dispatches THIS plugin for substantive integrity guarantee (attribution-key
# coverage instead of byte-equality).
#
# OQ-C9.1-2 (v0.4 lock): verification_mode default is "first_match" — stop at
# the first record carrying the attribution key. This is the plugin's OWN
# declared semantics for a key-PRESENCE question. (It originally mirrored
# capture.py load_trace's early-exit; load_trace itself full-scans since
# RES-12 because trace_id is a binding IDENTITY and duplicates must reject —
# a presence scan has no identity to shadow, so first_match stays.)
#
# Reason codes follow the str-typed `PluginResult.reason_code` discipline
# (audit_bundle/plugin.py:30) — values are short SCREAMING_SNAKE_CASE strings
# greppable across the codebase + REASON_CODES.md.


class ReasonCode:
    """v0.4 AppendOnlyAttributedCheck reason codes.

    Two-value enum mirroring `PluginResult.reason_code` (str type). Held in a
    class container so callers reference `ReasonCode.AppendOnlyAttributionFailed`
    instead of bare string literals — preserves the `str`-typed contract while
    centralising the spelling.
    """

    AppendOnlyAttributionFailed: str = "APPEND_ONLY_ATTRIBUTION_FAILED"
    AppendOnlyAttributionPartial: str = "APPEND_ONLY_ATTRIBUTION_PARTIAL"


@dataclass(slots=True)
class CheckFailure:
    """One failure record from AppendOnlyAttributedCheck.

    One CheckFailure per declared `append_only_files` entry that fails attribution.
    `record_sample` is the first 3 attribution-key values found in the file (or
    an empty tuple if zero matches were seen).
    """

    path: str
    attribution_plugin: str
    reason_code: str
    detail: str
    record_sample: tuple[str, ...] = ()


class AppendOnlyAttributedCheck:
    """§C9.1 v0.4 plugin — asserts each declared `append_only_files` entry's file
    carries records under the entry's `attribution_key`.

    Composition with verifier._step_file_integrity (sc9_1-004 wires this up):
      - declared paths skip §C9 strict-SHA;
      - AppendOnlyAttributedCheck.check() is invoked after the strict-SHA loop;
      - each declared entry's file is streamed line-by-line per `verification_mode`:
          * "first_match": stop on the first record carrying `attribution_key`
            (the plugin's own declared default per OQ-C9.1-2; a key-presence
            question — unlike load_trace's identity lookup, which full-scans
            and rejects duplicate trace_ids since RES-12).
          * "all_attributed": walk every record; require every record to carry
            `attribution_key`. Returns `AppendOnlyAttributionPartial` if any
            record lacks it. (Stricter v0.4+ mode.)
      - if zero records match in `first_match` mode (or the whole file in
        `all_attributed` mode has zero records carrying the key), emit
        `AppendOnlyAttributionFailed`.

    Standalone callability: this class has no plugin-registry coupling — it
    reads only `bundle_dir` + `manifest.append_only_files` and streams the
    declared files. Registration with BundleVerifier happens at the verifier
    boundary (sc9_1-004), not here.
    """

    name: str = "append_only_attributed"

    def check(self, bundle_dir: Path, manifest: "BundleManifest") -> list[CheckFailure]:
        """Run the v0.4 attribution check.

        Returns a list of CheckFailure — empty == pass. One failure per declared
        entry that fails. Bundles with `append_only_files == ()` return [] (the
        back-compat-invariant pass-through).
        """
        failures: list[CheckFailure] = []

        for spec in manifest.append_only_files:
            # Spec is expected to be a well-formed dict — emitters validate at
            # mint time via validate_append_only_files; _load_manifest reads
            # them through unchanged. Defensive: if any required key is absent,
            # the spec is malformed and the verifier should have rejected the
            # manifest earlier — surface as Failed with a clear detail.
            if not isinstance(spec, dict):
                failures.append(
                    CheckFailure(
                        path="<malformed-spec>",
                        attribution_plugin="<malformed-spec>",
                        reason_code=ReasonCode.AppendOnlyAttributionFailed,
                        detail=(
                            f"append_only_files entry is {type(spec).__name__} "
                            f"(expected dict); manifest-level validation should have rejected"
                        ),
                    )
                )
                continue

            rel_path = spec.get("path", "")
            attribution_key = spec.get("attribution_key", "")
            attribution_plugin = spec.get("attribution_plugin", "")
            verification_mode = spec.get("verification_mode", "first_match")

            # Validate through the shared containment chokepoint like every
            # other verdict-path reader (the strict-SHA walk + both load_trace
            # callers): _safe_bundle_path fail-closes on path-escape and on a
            # FIFO/socket/device/directory without opening content. A raw
            # ``bundle_dir / rel_path`` followed a symlink to host state and
            # BLOCKED on a FIFO at a declared path — the §C9.2 floor
            # lstat-rejected exactly these, but this sibling check re-opened
            # them anyway (BLOCK-01). This check is standalone-callable, so the
            # guard lives here, not on the assumption the floor ran first.
            try:
                _safe_bundle_path(bundle_dir, rel_path)
            except UnsafeBundlePath as exc:
                failures.append(
                    CheckFailure(
                        path=rel_path,
                        attribution_plugin=attribution_plugin,
                        reason_code=ReasonCode.AppendOnlyAttributionFailed,
                        detail=(
                            f"declared append_only file {rel_path!r} is not a "
                            f"containment-safe regular file: {exc}"
                        ),
                    )
                )
                continue

            # Open the RAW declared path (not _safe_bundle_path's resolved
            # return) so _open_contained_text's O_NOFOLLOW refuses a FINAL-
            # component symlink. Append-only files are NOT SHA-pinned, so —
            # unlike the strict-SHA walk, which tolerates a contained symlink
            # because the dereferenced bytes are hash-checked — this surface
            # must read the declared object itself, never a link's target.
            file_path = bundle_dir / rel_path

            if not file_path.exists():
                failures.append(
                    CheckFailure(
                        path=rel_path,
                        attribution_plugin=attribution_plugin,
                        reason_code=ReasonCode.AppendOnlyAttributionFailed,
                        detail=(
                            f"declared append_only file {rel_path!r} not found in "
                            f"bundle (expected at {file_path})"
                        ),
                    )
                )
                continue

            if verification_mode == "first_match":
                failure = _check_first_match(
                    file_path, rel_path, attribution_key, attribution_plugin
                )
                if failure is not None:
                    failures.append(failure)
            elif verification_mode == "all_attributed":
                failure = _check_all_attributed(
                    file_path, rel_path, attribution_key, attribution_plugin
                )
                if failure is not None:
                    failures.append(failure)
            else:
                # The closed v0.3 enum admits only the two values above — this
                # branch is reachable only if the manifest's verification_mode
                # is malformed and slipped past validate_append_only_files.
                failures.append(
                    CheckFailure(
                        path=rel_path,
                        attribution_plugin=attribution_plugin,
                        reason_code=ReasonCode.AppendOnlyAttributionFailed,
                        detail=(
                            f"verification_mode {verification_mode!r} not in reserved enum "
                            f"{sorted(RESERVED_VERIFICATION_MODES)}; manifest-level "
                            f"validation should have rejected"
                        ),
                    )
                )

        return failures


def _open_contained_text(file_path: Path) -> "IO[str]":
    """Open ``file_path`` (the RAW declared path) for UTF-8 text streaming with
    the shared TOCTOU-robust no-hang/no-follow primitive.

    Append-only files are not SHA-pinned, so this surface must read the declared
    object itself, never a link's target — passing the raw path lets
    ``open_regular_fd_nofollow``'s ``O_NOFOLLOW`` refuse a final-component
    symlink (which the strict-SHA walk, by contrast, tolerates as-built).
    ``O_NONBLOCK`` + the post-open regular-file ``fstat`` guarantee a FIFO/
    socket cannot block the read. Raises ``OSError`` (which both callers already
    collect) on any non-regular target.
    """
    return os.fdopen(open_regular_fd_nofollow(file_path), "r", encoding="utf-8")


def _check_first_match(
    file_path: Path,
    rel_path: str,
    attribution_key: str,
    attribution_plugin: str,
) -> CheckFailure | None:
    """Stream `file_path` and return None on the first record carrying
    `attribution_key`. Returns AppendOnlyAttributionFailed if no record matches.

    Early-exit is this check's OWN declared semantics (OQ-C9.1-2): it answers
    key PRESENCE, so it stops on the first hit and malformed later lines never
    need parsing. Bytes after the first match are NOT validated by this check.
    (load_trace, by contrast, answers record IDENTITY and therefore full-scans
    + rejects duplicate trace_ids since RES-12 — the two deliberately differ.)
    """
    try:
        with _open_contained_text(file_path) as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped:
                    continue
                if admit_bytes(stripped.encode("utf-8")) is not None:
                    # RES-02: a per-line depth bomb used to drive json.loads to
                    # RecursionError, which ESCAPED the except below and crashed
                    # the verifier. Depth-scan before parse; an inadmissible
                    # line is tolerated exactly like a malformed one here.
                    continue
                try:
                    record = json.loads(stripped)
                except (json.JSONDecodeError, ValueError):
                    # In first_match we tolerate malformed lines BEFORE a match —
                    # declared per OQ-C9.1-2. (An earlier comment claimed
                    # load_trace skips malformed lines too; it never did — it
                    # raises RetrievalTraceError. The tolerance here is this
                    # mode's own contract, not borrowed.) Keep going.
                    continue
                if isinstance(record, dict) and attribution_key in record:
                    # First match found — early-exit.
                    return None
    except OSError as exc:
        return CheckFailure(
            path=rel_path,
            attribution_plugin=attribution_plugin,
            reason_code=ReasonCode.AppendOnlyAttributionFailed,
            detail=f"could not read {rel_path!r}: {exc}",
        )

    return CheckFailure(
        path=rel_path,
        attribution_plugin=attribution_plugin,
        reason_code=ReasonCode.AppendOnlyAttributionFailed,
        detail=(
            f"no record in {rel_path!r} carries attribution_key {attribution_key!r} "
            f"(first_match mode; attribution_plugin={attribution_plugin!r})"
        ),
    )


def _check_all_attributed(
    file_path: Path,
    rel_path: str,
    attribution_key: str,
    attribution_plugin: str,
) -> CheckFailure | None:
    """Walk every record in `file_path`. Returns None iff every record carries
    `attribution_key`. Returns AppendOnlyAttributionPartial if any record lacks
    the key (or AppendOnlyAttributionFailed if the file is empty / zero records).

    Stricter v0.4+ mode: catches drift where a later append silently dropped
    the attribution key — first_match would still pass on the leading record.
    """
    sample: list[str] = []
    records_seen = 0
    missing_count = 0
    first_missing_line: int | None = None

    try:
        with _open_contained_text(file_path) as fh:
            for lineno, line in enumerate(fh, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                records_seen += 1
                if admit_bytes(stripped.encode("utf-8")) is not None:
                    # RES-02: depth-scan before parse (RecursionError escaped the
                    # except below pre-fix). Inadmissible == cannot certify the
                    # key is present — count as missing, like malformed.
                    missing_count += 1
                    if first_missing_line is None:
                        first_missing_line = lineno
                    continue
                try:
                    record = json.loads(stripped)
                except (json.JSONDecodeError, ValueError):
                    # In all_attributed mode a malformed line means we cannot
                    # certify the key is present — count as missing.
                    missing_count += 1
                    if first_missing_line is None:
                        first_missing_line = lineno
                    continue
                if isinstance(record, dict) and attribution_key in record:
                    if len(sample) < 3:
                        sample.append(str(record[attribution_key]))
                else:
                    missing_count += 1
                    if first_missing_line is None:
                        first_missing_line = lineno
    except OSError as exc:
        return CheckFailure(
            path=rel_path,
            attribution_plugin=attribution_plugin,
            reason_code=ReasonCode.AppendOnlyAttributionFailed,
            detail=f"could not read {rel_path!r}: {exc}",
        )

    if records_seen == 0:
        return CheckFailure(
            path=rel_path,
            attribution_plugin=attribution_plugin,
            reason_code=ReasonCode.AppendOnlyAttributionFailed,
            detail=(
                f"{rel_path!r} is empty / contains no records (all_attributed mode; "
                f"attribution_plugin={attribution_plugin!r})"
            ),
        )

    if missing_count > 0:
        return CheckFailure(
            path=rel_path,
            attribution_plugin=attribution_plugin,
            reason_code=ReasonCode.AppendOnlyAttributionPartial,
            detail=(
                f"{rel_path!r}: {missing_count} of {records_seen} record(s) lack "
                f"attribution_key {attribution_key!r} (first missing on line "
                f"{first_missing_line}; all_attributed mode; "
                f"attribution_plugin={attribution_plugin!r})"
            ),
            record_sample=tuple(sample),
        )

    return None


# Plugin registration happens in audit_bundle.verifier (sc9_1-004); this module
# exposes the class only.
