"""RetrievalTrace — immutable capture of a single retrieval event per output.

Three-set ordering invariant (load-bearing for Component 6):
  candidate_set ⊇ {source_cid for each selected_chunk} ⊇ context_window_injected

Finite-scores invariant (RES-09): every rankings score must be a finite
number. NaN/Infinity are not RFC 8259 JSON — stdlib ``json`` round-trips
them as the non-standard ``NaN``/``Infinity`` tokens (the same laundering
vector the re-derivation dispatch boundary closes with NON_FINITE_VALUE),
which would break this module's "JCS-canonicalizable" contract and make the
captured evidence non-portable. Rejected at construction, the one chokepoint
both the capture write path and trace_from_dict pass through.

Validated in __post_init__; any violation raises RetrievalTraceError.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


class RetrievalTraceError(ValueError):
    """Raised when a RetrievalTrace is malformed or violates the three-set invariant."""


@dataclass(frozen=True)
class RetrievalTrace:
    """Immutable capture of retrieval event metadata for one model output.

    Fields
    ------
    trace_id
        Caller-supplied identifier (UUID or similar); must be unique per output.
    retriever_name
        Logical retriever name, e.g. 'spectra_bm25_v0', 'horizon_dense_v0',
        'mesh_fusion_v0'.
    retriever_version
        Semver string for the retriever implementation.
    query
        The actual query sent to the retriever (post-rewrite if any).
    candidate_set
        Tuple of source_cids the retriever considered (superset of selected_chunks).
    rankings
        Tuple of (source_cid, score) pairs in ranked order.
    selected_chunks
        Tuple of dicts {'source_cid': str, 'fragment': dict, 'rank': int}
        for chunks actually injected into the prompt.  'fragment' must be a
        FragmentID canonical dict.
    context_window_injected
        Tuple of source_cids (subset of selected_chunks source_cids) that
        fit within the model context window.
    model_router_version
        Router version string, e.g. 'claude-flow-router-v0.4'.
    captured_at
        ISO-8601 UTC timestamp with 'Z' suffix.
    """

    trace_id: str
    retriever_name: str
    retriever_version: str
    query: str
    candidate_set: tuple[str, ...]
    rankings: tuple[tuple[str, float], ...]
    selected_chunks: tuple[dict, ...]
    context_window_injected: tuple[str, ...]
    model_router_version: str
    captured_at: str

    def __post_init__(self) -> None:
        _validate_trace(self)


def _validate_trace(trace: RetrievalTrace) -> None:
    if not trace.trace_id:
        raise RetrievalTraceError("trace_id must not be empty")
    if not trace.retriever_name:
        raise RetrievalTraceError("retriever_name must not be empty")
    if not trace.retriever_version:
        raise RetrievalTraceError("retriever_version must not be empty")
    if not trace.model_router_version:
        raise RetrievalTraceError("model_router_version must not be empty")
    if not trace.captured_at:
        raise RetrievalTraceError("captured_at must not be empty")

    # Validate rankings shape + the finite-scores invariant (RES-09): a
    # non-finite score would serialize as a non-RFC-8259 token and poison
    # the canonical form, so it fails closed here — at construction —
    # rather than surfacing as a downstream parse error on someone else's
    # machine.
    for i, entry in enumerate(trace.rankings):
        try:
            _cid, score = entry
        except (TypeError, ValueError):
            raise RetrievalTraceError(
                f"rankings[{i}] must be a (source_cid, score) pair; got {entry!r}"
            ) from None
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise RetrievalTraceError(
                f"rankings[{i}] score must be a finite number; "
                f"got {type(score).__name__}"
            )
        if not math.isfinite(score):
            raise RetrievalTraceError(
                f"rankings[{i}] score is non-finite ({score!r}) — NaN/Infinity "
                "are not RFC 8259 JSON and cannot appear in a canonical trace"
            )

    # Validate selected_chunks shape
    for i, chunk in enumerate(trace.selected_chunks):
        if not isinstance(chunk, dict):
            raise RetrievalTraceError(
                f"selected_chunks[{i}] must be a dict; got {type(chunk)!r}"
            )
        for required_key in ("source_cid", "fragment", "rank"):
            if required_key not in chunk:
                raise RetrievalTraceError(
                    f"selected_chunks[{i}] missing required key {required_key!r}"
                )
        if not isinstance(chunk["fragment"], dict):
            raise RetrievalTraceError(
                f"selected_chunks[{i}]['fragment'] must be a dict; "
                f"got {type(chunk['fragment'])!r}"
            )

    # Three-set invariant: candidate_set ⊇ selected_source_cids ⊇ context_window_injected
    candidate_set = set(trace.candidate_set)
    selected_source_cids = {chunk["source_cid"] for chunk in trace.selected_chunks}
    context_set = set(trace.context_window_injected)

    not_in_candidates = selected_source_cids - candidate_set
    if not_in_candidates:
        raise RetrievalTraceError(
            f"Three-set violation: selected_chunks contains source_cids not in "
            f"candidate_set: {sorted(not_in_candidates)}"
        )

    not_in_selected = context_set - selected_source_cids
    if not_in_selected:
        raise RetrievalTraceError(
            f"Three-set violation: context_window_injected contains source_cids "
            f"not in selected_chunks: {sorted(not_in_selected)}"
        )


def trace_to_canonical_dict(trace: RetrievalTrace) -> dict:
    """Return a JCS-canonicalizable dict for trace.

    Keys are sorted alphabetically at all nesting levels to match JCS (RFC 8785).
    Callers pass the result to json.dumps(sort_keys=True) for a canonical byte string.
    """
    return {
        "candidate_set": list(trace.candidate_set),
        "captured_at": trace.captured_at,
        "context_window_injected": list(trace.context_window_injected),
        "model_router_version": trace.model_router_version,
        "query": trace.query,
        "rankings": [
            {"score": score, "source_cid": cid} for cid, score in trace.rankings
        ],
        "retriever_name": trace.retriever_name,
        "retriever_version": trace.retriever_version,
        "selected_chunks": [
            {
                "fragment": chunk["fragment"],
                "rank": chunk["rank"],
                "source_cid": chunk["source_cid"],
            }
            for chunk in trace.selected_chunks
        ],
        "trace_id": trace.trace_id,
    }


def trace_from_dict(d: dict) -> RetrievalTrace:
    """Reconstruct a RetrievalTrace from a canonical dict.

    Raises RetrievalTraceError on missing fields or three-set violations.
    """
    if not isinstance(d, dict):
        raise RetrievalTraceError(f"Expected a dict; got {type(d)!r}")

    required = (
        "candidate_set",
        "captured_at",
        "context_window_injected",
        "model_router_version",
        "query",
        "rankings",
        "retriever_name",
        "retriever_version",
        "selected_chunks",
        "trace_id",
    )
    missing = [k for k in required if k not in d]
    if missing:
        raise RetrievalTraceError(f"Missing required fields: {missing}")

    try:
        rankings = tuple(
            (entry["source_cid"], float(entry["score"])) for entry in d["rankings"]
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise RetrievalTraceError(
            f"rankings must be a list of {{source_cid, score}} dicts: {exc}"
        ) from exc

    try:
        selected_chunks = tuple(
            {
                "source_cid": chunk["source_cid"],
                "fragment": chunk["fragment"],
                "rank": chunk["rank"],
            }
            for chunk in d["selected_chunks"]
        )
    except (KeyError, TypeError) as exc:
        raise RetrievalTraceError(
            f"selected_chunks must be a list of {{source_cid, fragment, rank}} dicts: {exc}"
        ) from exc

    try:
        return RetrievalTrace(
            trace_id=d["trace_id"],
            retriever_name=d["retriever_name"],
            retriever_version=d["retriever_version"],
            query=d["query"],
            candidate_set=tuple(d["candidate_set"]),
            rankings=rankings,
            selected_chunks=selected_chunks,
            context_window_injected=tuple(d["context_window_injected"]),
            model_router_version=d["model_router_version"],
            captured_at=d["captured_at"],
        )
    except TypeError as exc:
        raise RetrievalTraceError(
            f"trace record has a field of the wrong type: {exc}"
        ) from exc
