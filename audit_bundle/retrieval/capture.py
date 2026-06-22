"""capture.py — single write-path for RetrievalTrace records.

This is the ONLY place in-product code writes RetrievalTrace records.
Append-only JSONL log invariant is enforced here.

Public API
----------
capture_trace  — build, validate, and persist a RetrievalTrace
load_trace     — read a trace back by trace_id
TraceNotFound  — raised by load_trace when trace_id is absent
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from audit_bundle.retrieval.trace import (
    RetrievalTrace,
    RetrievalTraceError,
    trace_from_dict,
    trace_to_canonical_dict,
)


class TraceNotFound(KeyError):
    """Raised by load_trace when trace_id is not present in the JSONL log."""


def _reject_nonfinite_token(token: str) -> float:
    """parse_constant hook: stdlib json ACCEPTS the non-standard NaN /
    Infinity / -Infinity tokens by default, which would let a hand-edited or
    foreign-producer log line launder a non-finite float past the
    construction-time guard. The log is bundle-supplied data; a line carrying
    one of these tokens is not RFC 8259 JSON and is rejected as such."""
    raise ValueError(f"non-finite JSON token {token!r} is not RFC 8259 JSON")


def capture_trace(
    trace_id: str,
    retriever_name: str,
    retriever_version: str,
    query: str,
    candidate_source_cids: Iterable[str],
    rankings: Iterable[tuple[str, float]],
    selected_chunks: Iterable[dict],
    context_window_source_cids: Iterable[str],
    model_router_version: str,
    output_jsonl_path: Path,
) -> RetrievalTrace:
    """Build a RetrievalTrace, validate it, append to the JSONL log, and return it.

    Parameters
    ----------
    trace_id
        Caller-supplied identifier (UUID or similar); must be unique per output.
    retriever_name
        Logical retriever name, e.g. 'spectra_bm25_v0'.
    retriever_version
        Semver string for the retriever implementation.
    query
        The actual query sent to the retriever.
    candidate_source_cids
        source_cids the retriever considered (superset of selected_chunks).
    rankings
        (source_cid, score) pairs in ranked order.
    selected_chunks
        Dicts with keys 'source_cid', 'fragment', 'rank'.
    context_window_source_cids
        source_cids that fit within the model context window
        (subset of selected_chunks source_cids).
    model_router_version
        Router version string.
    output_jsonl_path
        Path to the append-only JSONL log file.  Parent directory must exist.

    Returns
    -------
    RetrievalTrace
        The constructed and validated trace (also persisted to JSONL).

    Raises
    ------
    RetrievalTraceError
        If any field is invalid, the three-set invariant is violated, or
        trace_id is already present in the log. "Must be unique per output"
        was previously a docstring convention; this is the single write path,
        so it is enforced here (RES-12) — an append-only CORRECTION is a
        status event via ``audit_bundle.event_stream`` (SUPERSEDE/CORRECT)
        plus a fresh trace_id, never a reused lookup key. The pre-append
        uniqueness scan is O(log size); reference-SDK logs are per-bundle
        and small. A log that cannot be scanned cleanly (malformed line)
        also refuses the append — never grow a corrupt log.
    """
    try:
        load_trace(output_jsonl_path, trace_id)
    except TraceNotFound:
        pass  # unique — proceed with the append
    except FileNotFoundError:
        pass  # first record in a new log
    else:
        raise RetrievalTraceError(
            f"trace_id {trace_id!r} is already present in {output_jsonl_path} — "
            "trace identity must be unique per output; append a SUPERSEDE/"
            "CORRECT status event (audit_bundle.event_stream) and mint a "
            "fresh trace_id instead of reusing the lookup key"
        )

    captured_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    trace = RetrievalTrace(
        trace_id=trace_id,
        retriever_name=retriever_name,
        retriever_version=retriever_version,
        query=query,
        candidate_set=tuple(candidate_source_cids),
        rankings=tuple(rankings),
        selected_chunks=tuple(selected_chunks),
        context_window_injected=tuple(context_window_source_cids),
        model_router_version=model_router_version,
        captured_at=captured_at,
    )

    # 'a' mode guarantees we never truncate existing records.
    # allow_nan=False is the whole-record belt over the per-score check in
    # _validate_trace: scores are already rejected at construction, but a
    # non-finite float anywhere else in the record (e.g. inside a fragment
    # dict, which validation treats as opaque) would otherwise serialize as
    # the non-RFC-8259 NaN/Infinity tokens and poison the canonical log.
    try:
        record = json.dumps(
            trace_to_canonical_dict(trace), sort_keys=True, allow_nan=False
        )
    except ValueError as exc:
        raise RetrievalTraceError(
            f"trace {trace_id!r} contains a non-finite float and cannot be "
            f"serialized as RFC 8259 JSON: {exc}"
        ) from exc
    with output_jsonl_path.open("a", encoding="utf-8") as fh:
        fh.write(record + "\n")

    return trace


def load_trace(jsonl_path: Path, trace_id: str) -> RetrievalTrace:
    """Read and return the RetrievalTrace matching trace_id from the JSONL log.

    Streams line-by-line; does not load the full file into memory.

    trace_id is a BINDING IDENTITY (a per-output manifest points at it and the
    verifier checks the three-set against the record it names), so the scan
    reads the WHOLE file and a second record carrying the same trace_id is a
    hard RetrievalTraceError — never first-match-wins (RES-12). A silent
    first-match would let the machine verdict bind record #1 while a human
    reading the log top-to-bottom treats the later row as current: same
    bytes, divergent readings. Byte-identical duplicates are rejected too —
    one identity, one record, no exceptions to reason about. Corrections
    never reuse a trace_id: append a status event via
    ``audit_bundle.event_stream`` (SUPERSEDE / CORRECT) — that IS the
    append-only correction model — and mint a fresh trace_id for the new
    capture. (The C9.1 attribution scans keep their declared early-exit
    semantics: they answer key PRESENCE, not record identity — OQ-C9.1-2.)

    Each line is admission-bounded (``admit_bytes``) before parsing, per the
    package-wide convention for bundle-controlled JSON reads: this reader
    runs on the verdict path (manifest_three_set), and the raw per-line
    ``json.loads`` over a file handle was the iteration shape the admission
    ratchet documents as invisible to its AST scan.

    Parameters
    ----------
    jsonl_path
        Path to the JSONL log written by capture_trace.
    trace_id
        The trace_id to look up.

    Returns
    -------
    RetrievalTrace
        The single record whose trace_id matches.

    Raises
    ------
    TraceNotFound
        If no record in the file matches trace_id.
    RetrievalTraceError
        If a line in the log is not valid JSON, is not a JSON object,
        breaches an admission bound, duplicates the requested trace_id, or
        the matching record is malformed. The log is bundle-supplied data,
        so every malformed-content failure is normalised to this type;
        callers can catch (TraceNotFound, RetrievalTraceError, OSError)
        without a broad except that would also swallow verifier bugs.
    """
    from audit_bundle.admission import admit_bytes  # noqa: PLC0415

    found: dict | None = None
    with jsonl_path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            breach = admit_bytes(line.encode("utf-8"), check_name="retrieval_trace")
            if breach is not None:
                raise RetrievalTraceError(
                    f"{jsonl_path} line {lineno} is inadmissible: {breach.detail}"
                )
            try:
                record = json.loads(line, parse_constant=_reject_nonfinite_token)
            except ValueError as exc:
                raise RetrievalTraceError(
                    f"{jsonl_path} line {lineno} is not valid JSON: {exc}"
                ) from exc
            if not isinstance(record, dict):
                raise RetrievalTraceError(
                    f"{jsonl_path} line {lineno} is not a JSON object: "
                    f"got {type(record).__name__}"
                )
            if record.get("trace_id") == trace_id:
                if found is not None:
                    raise RetrievalTraceError(
                        f"{jsonl_path} line {lineno} duplicates trace_id "
                        f"{trace_id!r} — trace identity must be unique; "
                        "corrections use the event_stream supersession model "
                        "(SUPERSEDE/CORRECT), never a reused trace_id"
                    )
                found = record

    if found is None:
        raise TraceNotFound(f"trace_id {trace_id!r} not found in {jsonl_path}")
    return trace_from_dict(found)
