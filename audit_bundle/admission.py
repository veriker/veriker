"""audit_bundle/admission.py — input-admission boundary (ADR D9 / Q4).

A single substrate admission gate every verdict entry point sits BEHIND, same shape as
the L11 admission gate. Bounds input depth / size / collection cardinality BEFORE the
semantic parser runs, so a hostile shape fails as a clean INPUT_* REJECT instead of a
RecursionError / MemoryError DoS that the outer boundary would have to catch as a
VERIFIER_* ERROR. This converts a class of would-be ERRORs (and the matching DoS
vector) into cheap early REJECTs.

Seam discipline (ADR §5.4): admission = "the input is inadmissible" (a recognized,
bounded property of the artifact) → REJECT; the `fail_closed` outer boundary =
"something we did not anticipate broke" → ERROR. The two compose.

Entry points:
  * admit_bytes(raw, limits)  — size + nesting depth, scanned on RAW BYTES so a deeply
    nested manifest is rejected BEFORE json.loads can raise RecursionError.
  * admit_obj(obj, limits)    — depth + per-collection cardinality on an already-parsed
    structure (for entry points that receive a dict/list directly, e.g. o5).
  * admit_json_file(path, limits) — the SHARED bundle-file loader: stat-then-bound-then-
    parse-then-bound for ANY bundle-controlled single-value JSON a primitive or plugin
    reads. It applies the SAME admission discipline the manifest entry point gets
    (verifier.py), so a hostile input file is a cheap pre-parse REJECT rather than an
    expensive caught-RecursionError / large allocation. Raises InputInadmissible
    (carrying the REJECT Verdict) on breach; returns the parsed object on success.
  * admit_jsonl_file(path, limits) — the line-delimited (.jsonl) analogue: size-bounds
    the file, depth-bounds each line before parsing it, and bounds the row count.
    Returns the list of parsed rows. The standard for every bundle-controlled JSONL
    read (a .jsonl is not a single JSON value, so admit_json_file does not fit).

Scope note (matches SECURITY.md "In scope" / "Out of scope"): bounding DEPTH and
CARDINALITY on attacker-controlled SHAPE is in scope (the cheap-REJECT conversion this
module exists for). A merely-LARGE-but-valid file ("legitimate-shaped but expensive")
is the operator's rate-limiting concern, not the substrate's — admit_json_file still
applies the manifest's 16 MiB ceiling for consistency, but that ceiling is a sanity
bound, not a completeness claim. The final backstop everywhere is the differentiated
`fail_closed` boundary: RecursionError/MemoryError ARE Exceptions → classified ERROR,
never an unhandled crash (verdict.py). admit_json_file makes the common case a clean
localized REJECT *before* that backstop is needed.

stdlib-only. admit_bytes/admit_obj return a REJECT Verdict on breach, or None when
admitted; admit_json_file raises InputInadmissible on breach.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from .verdict import (
    INPUT_CARDINALITY_EXCEEDED,
    INPUT_DEPTH_EXCEEDED,
    INPUT_SIZE_EXCEEDED,
    Verdict,
)


class InputInadmissible(ValueError):
    """A bundle-controlled input breached an admission bound (size / depth /
    cardinality) or could not be read/parsed. Carries the REJECT `verdict` so a
    caller that wants the structured reason can surface it; subclasses ValueError
    so a primitive that simply lets it propagate is recorded fail-closed by the
    dispatch boundary (→ RECOMPUTE_ERROR) exactly like any other malformed-input
    raise."""

    def __init__(self, verdict: Verdict) -> None:
        self.verdict = verdict
        super().__init__(verdict.detail)


@dataclass(frozen=True, slots=True)
class AdmissionLimits:
    """Bounds enforced at the parse boundary. Defaults are generous for real bundles
    (the largest pilot manifests nest only a few levels and are well under a MB) and
    tight enough to stop the RecursionError-DoS shape long before CPython's own
    recursion limit (~1000)."""

    max_bytes: int = 16 * 1024 * 1024  # 16 MiB — far above any real manifest
    max_depth: int = 64  # JSON nesting; real manifests nest < 10
    max_collection: int = 1_000_000  # entries in any single dict/list


_OPENERS = b"[{"
_CLOSERS = b"]}"


def admit_bytes(
    raw: bytes,
    limits: AdmissionLimits = AdmissionLimits(),
    *,
    check_name: str = "admission",
) -> Verdict | None:
    """Size + structural-depth admission on raw bytes (pre-parse).

    Depth is measured by scanning bracket/brace nesting OUTSIDE of JSON string
    literals (so brackets inside a string value never inflate the count, and an
    escaped quote inside a string does not prematurely end it). This is a structural
    upper bound on the nesting json.loads would recurse into — if it exceeds max_depth
    we reject here, before the parser can hit RecursionError. Non-bytes input is itself
    inadmissible.
    """
    if not isinstance(raw, (bytes, bytearray)):
        return Verdict.reject(
            INPUT_SIZE_EXCEEDED,
            f"admission expected bytes, got {type(raw).__name__}",
            check_name,
        )
    if len(raw) > limits.max_bytes:
        return Verdict.reject(
            INPUT_SIZE_EXCEEDED,
            f"input is {len(raw)} bytes, exceeds max {limits.max_bytes}",
            check_name,
        )

    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:  # closing quote
                in_string = False
            continue
        if byte == 0x22:  # opening quote
            in_string = True
        elif byte in _OPENERS:
            depth += 1
            if depth > limits.max_depth:
                return Verdict.reject(
                    INPUT_DEPTH_EXCEEDED,
                    f"input nesting depth exceeds max {limits.max_depth}",
                    check_name,
                )
        elif byte in _CLOSERS:
            if depth > 0:
                depth -= 1
    return None


def admit_obj(
    obj: object,
    limits: AdmissionLimits = AdmissionLimits(),
    *,
    check_name: str = "admission",
) -> Verdict | None:
    """Depth + per-collection cardinality admission on an already-parsed structure.

    Walks the structure ITERATIVELY (an explicit stack — never recursively, so the
    walker itself cannot RecursionError on the very input it is policing). Rejects on
    the first dict/list whose length exceeds max_collection, or the first point the
    structural depth exceeds max_depth.
    """
    # stack of (node, depth)
    stack: list[tuple[object, int]] = [(obj, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > limits.max_depth:
            return Verdict.reject(
                INPUT_DEPTH_EXCEEDED,
                f"parsed nesting depth exceeds max {limits.max_depth}",
                check_name,
            )
        if isinstance(node, dict):
            if len(node) > limits.max_collection:
                return Verdict.reject(
                    INPUT_CARDINALITY_EXCEEDED,
                    f"dict has {len(node)} entries, exceeds max {limits.max_collection}",
                    check_name,
                )
            for value in node.values():
                if isinstance(value, (dict, list)):
                    stack.append((value, depth + 1))
        elif isinstance(node, list):
            if len(node) > limits.max_collection:
                return Verdict.reject(
                    INPUT_CARDINALITY_EXCEEDED,
                    f"list has {len(node)} entries, exceeds max {limits.max_collection}",
                    check_name,
                )
            for value in node:
                if isinstance(value, (dict, list)):
                    stack.append((value, depth + 1))
    return None


def admit_json_file(
    path: Path,
    limits: AdmissionLimits = AdmissionLimits(),
    *,
    check_name: str = "input_admission",
) -> object:
    """Shared admission-bounded loader for a bundle-controlled JSON file.

    The discipline, in order, so a hostile shape fails as a cheap REJECT before the
    expensive operation it would otherwise trigger:
      1. stat the file and reject on size BEFORE read_bytes() — so a multi-GiB file
         never gets allocated into memory just to be rejected.
      2. admit_bytes (depth scan on raw bytes) BEFORE json.loads — so a depth-bomb is
         rejected before the parser can recurse to RecursionError.
      3. json.loads.
      4. admit_obj (per-collection cardinality) on the parsed structure.

    Returns the parsed object. Raises InputInadmissible (carrying the REJECT Verdict)
    on any admission breach, or on an unreadable / malformed file (so every failure on
    this path is one typed, fail-closed exception a caller can either let propagate —
    dispatch records RECOMPUTE_ERROR — or catch to emit a localized reason code).

    This is the helper every primitive/plugin reading bundle JSON should use instead of
    a raw ``json.loads(path.read_bytes())``: it gives those reads the same admission
    treatment the manifest entry point gets, rather than relying solely on the
    downstream catch-all (which holds, but only as a coarser ERROR/INDETERMINATE).
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise InputInadmissible(
            Verdict.reject(
                INPUT_SIZE_EXCEEDED, f"{path.name}: cannot stat: {exc}", check_name
            )
        ) from exc
    if size > limits.max_bytes:
        raise InputInadmissible(
            Verdict.reject(
                INPUT_SIZE_EXCEEDED,
                f"{path.name}: {size} bytes exceeds max {limits.max_bytes}",
                check_name,
            )
        )
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise InputInadmissible(
            Verdict.reject(
                INPUT_SIZE_EXCEEDED, f"{path.name}: unreadable: {exc}", check_name
            )
        ) from exc
    breach = admit_bytes(raw, limits, check_name=check_name)
    if breach is not None:
        raise InputInadmissible(breach)
    try:
        obj = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise InputInadmissible(
            Verdict.reject(
                INPUT_SIZE_EXCEEDED, f"{path.name}: not valid JSON: {exc}", check_name
            )
        ) from exc
    breach = admit_obj(obj, limits, check_name=check_name)
    if breach is not None:
        raise InputInadmissible(breach)
    return obj


def admit_jsonl_file(
    path: Path,
    limits: AdmissionLimits = AdmissionLimits(),
    *,
    check_name: str = "input_admission",
) -> list[object]:
    """Shared admission-bounded loader for a LINE-DELIMITED JSON (.jsonl) bundle file.

    The JSONL analogue of admit_json_file: a .jsonl is not a single JSON value, so
    it cannot go through admit_json_file (which parses the whole file as one value).
    The discipline, in order:
      1. stat + size-reject BEFORE read_bytes() (no huge allocation just to reject);
      2. for each non-blank line, depth-scan the line bytes (admit_bytes) BEFORE
         json.loads so one deeply-nested line cannot drive the parser to
         RecursionError;
      3. bound the ROW COUNT by max_collection (a JSONL with more rows than any
         single in-memory collection is allowed is inadmissible);
      4. admit_obj each parsed row (per-row depth + cardinality).

    Returns the list of parsed rows (blank lines skipped). Raises InputInadmissible
    on any breach / malformed line / unreadable file — one typed, fail-closed
    exception a caller can let propagate (dispatch → RECOMPUTE_ERROR) or catch.
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise InputInadmissible(
            Verdict.reject(
                INPUT_SIZE_EXCEEDED, f"{path.name}: cannot stat: {exc}", check_name
            )
        ) from exc
    if size > limits.max_bytes:
        raise InputInadmissible(
            Verdict.reject(
                INPUT_SIZE_EXCEEDED,
                f"{path.name}: {size} bytes exceeds max {limits.max_bytes}",
                check_name,
            )
        )
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise InputInadmissible(
            Verdict.reject(
                INPUT_SIZE_EXCEEDED, f"{path.name}: unreadable: {exc}", check_name
            )
        ) from exc
    rows: list[object] = []
    for lineno, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        if len(rows) >= limits.max_collection:
            raise InputInadmissible(
                Verdict.reject(
                    INPUT_CARDINALITY_EXCEEDED,
                    f"{path.name}: more than max {limits.max_collection} rows",
                    check_name,
                )
            )
        breach = admit_bytes(line, limits, check_name=check_name)
        if breach is not None:
            raise InputInadmissible(breach)
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            raise InputInadmissible(
                Verdict.reject(
                    INPUT_SIZE_EXCEEDED,
                    f"{path.name}: line {lineno} not valid JSON: {exc}",
                    check_name,
                )
            ) from exc
        breach = admit_obj(row, limits, check_name=check_name)
        if breach is not None:
            raise InputInadmissible(breach)
        rows.append(row)
    return rows


def iter_admitted_jsonl_tolerant(
    path: Path,
    limits: AdmissionLimits = AdmissionLimits(),
    *,
    check_name: str = "input_admission",
) -> Iterator[object]:
    """Lazily yield parsed rows from a line-delimited JSON file, SKIPPING (never
    raising on) malformed or per-line-inadmissible rows.

    The tolerant streaming sibling of admit_jsonl_file, for callers whose
    contract is "scan whatever valid rows exist" (the bundle_manifest
    policy-stamp scan, the C9.1 attribution scan) rather than "load this file
    or reject it". Those scanners deliberately `continue` past malformed lines
    — but their `except (JSONDecodeError, ValueError)` tolerance did NOT cover
    a per-line depth bomb, which drove json.loads to RecursionError and
    crashed the verifier (RES-02 hardening, 2026-06-11). Here every line is
    depth-scanned (admit_bytes) BEFORE json.loads, so an inadmissible line is
    skipped as a cheap structural check instead of reaching the parser at all.

    File-level bounds still fail CLOSED: a file over max_bytes raises
    InputInadmissible BEFORE read_bytes() — skipping an oversize file would
    let a producer hide exactly the rows these scans exist to find, so the
    caller must surface that as its fail-closed path, never as a skip. Rows
    are yielded lazily (no accumulation, no row-count bound) so early-exit
    scans stay memory-light on honest large logs.
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise InputInadmissible(
            Verdict.reject(
                INPUT_SIZE_EXCEEDED, f"{path.name}: cannot stat: {exc}", check_name
            )
        ) from exc
    if size > limits.max_bytes:
        raise InputInadmissible(
            Verdict.reject(
                INPUT_SIZE_EXCEEDED,
                f"{path.name}: {size} bytes exceeds max {limits.max_bytes}",
                check_name,
            )
        )
    try:
        fh = path.open("rb")
    except OSError as exc:
        raise InputInadmissible(
            Verdict.reject(
                INPUT_SIZE_EXCEEDED, f"{path.name}: unreadable: {exc}", check_name
            )
        ) from exc
    with fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if admit_bytes(line, limits, check_name=check_name) is not None:
                continue  # tolerant: inadmissible line skipped like a malformed one
            try:
                row = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                continue
            if admit_obj(row, limits, check_name=check_name) is not None:
                continue
            yield row
