"""Generic append-only writer for status-change events per the audit-bundle contract §C7.

Status-change events (retraction, correction, supersession, etc.) are written to an
append-only stream keyed by content-SHA + timestamp.  Prior rows are never mutated —
a new event row supersedes via the stream.

One writer is exposed:

- ``append_event(jsonl_path, event)`` — local JSONL file (the original library writer).

The enum also reserves ingestion/admission event types (INGESTION_VERSION_BUMP,
ENTITY_DRIFT, STRUCTURE_DRIFT, COVERAGE_DRIFT, LANGUAGE_RECALIBRATION,
ADMISSION_DECISION) so this transport can READ a stream that carries them. These
types are *produced by a separate ingestion/admission substrate* (not by this
verifier); this module only appends/reads event rows — it neither makes admission
decisions nor computes drift.

What "append-only" claims (RES-11 scoping)
------------------------------------------
Append-only is a producer-side WRITER-API convention — this module never
rewrites prior rows — NOT a structural tamper-evidence guarantee for the
growing local file. A local process with write access can truncate or rewrite
it, and an unanchored per-row hash chain would not change that (the same
process recomputes the chain — false assurance, deliberately not built). The
structural guarantees each live at the layer where they bind: post-mint the
log's bytes are digest-pinned in its bundle (truncation/rewrite/reorder is a
verifier REJECT); pre-mint continuity as a verifiable CLAIM is C19 Layer A
(extensions/c19/layer_a_counter.py — anchored monotonic counter + hash chain
+ Merkle root, with verify_chain_integrity rejecting truncation, reordering,
and duplicates); absent Layer A, continuity is honestly unclaimed. See
SECURITY.md §"Append-only logs and historical continuity".
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


# Private alias: the v0.1 public surface of this module is locked by
# tests/test_event_stream_lkernel.py::test_no_new_top_level_exports.
from audit_bundle.admission import admit_jsonl_file as _admit_jsonl_file


# ---------------------------------------------------------------------------
# Valid event types (C7 enum)
# ---------------------------------------------------------------------------

_VALID_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "ADMISSION_DECISION",  # per-decision event produced by the external admission substrate (read-only here)
        "COVERAGE_DRIFT",  # coverage-cell drift placeholder; reserved at v0.1
        "CORRECT",  # existing
        "ENTITY_DRIFT",  # produced by the external substrate's drift detector (not computed here)
        "INGESTION_VERSION_BUMP",  # emitted by the external ingestion substrate when a source snapshot rolls forward
        "KEY_REVOKED",  # existing
        "LANGUAGE_RECALIBRATION",  # emitted when a source's language signal is reclassified
        "RECLASSIFY",  # existing — extends the metadata-payload contract (see contract doc)
        "RETRACT",  # existing
        "STRUCTURE_DRIFT",  # produced by the external ingestion substrate on source-schema validation failure
        "SUPERSEDE",  # existing
    }
)


# ---------------------------------------------------------------------------
# StatusEvent dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class StatusEvent:
    event_type: str  # one of {RETRACT, CORRECT, SUPERSEDE, KEY_REVOKED, RECLASSIFY, INGESTION_VERSION_BUMP, ENTITY_DRIFT, STRUCTURE_DRIFT, COVERAGE_DRIFT, LANGUAGE_RECALIBRATION, ADMISSION_DECISION}
    source_id: str
    prior_sha: str | None
    new_sha: str | None
    detected_at: str  # ISO-8601 UTC 'Z'
    metadata: dict


# ---------------------------------------------------------------------------
# append_event
# ---------------------------------------------------------------------------


def append_event(jsonl_path: Path, event: StatusEvent) -> None:
    """Append a StatusEvent to a JSONL file in canonical form.

    Opens the file in append-binary mode and writes one JSON line (no whitespace,
    sort_keys=True) followed by a newline byte.  Prior rows are never touched.

    Raises ValueError if event.event_type is not in the valid enum.
    """
    if event.event_type not in _VALID_EVENT_TYPES:
        raise ValueError(
            f"event_type {event.event_type!r} is not valid; "
            f"expected one of {sorted(_VALID_EVENT_TYPES)}"
        )
    row = dataclasses.asdict(event)
    line = json.dumps(row, separators=(",", ":"), sort_keys=True).encode() + b"\n"
    with jsonl_path.open("ab") as fh:
        fh.write(line)


# ---------------------------------------------------------------------------
# read_events
# ---------------------------------------------------------------------------


def read_events(jsonl_path: Path) -> Iterator[StatusEvent]:
    """Yield StatusEvent objects from a JSONL file.

    Skips blank lines. Event types are validated at append time
    (``append_event``), not on read — this transport reads streams that may
    carry types produced by the external ingestion substrate. (The previous
    docstring claimed a read-side ValueError on unrecognised event_type;
    the code never performed that check — corrected 2026-06-11.)

    Admission-bounded (admit_jsonl_file) per the package-wide convention for
    JSON file reads: the previous raw per-line ``json.loads`` over a file
    handle was the iteration shape the admission ratchet documents as
    invisible to its AST scan. Raises InputInadmissible (a ValueError) on
    size/depth/cardinality breach or a malformed line.
    """
    for obj in _admit_jsonl_file(jsonl_path, check_name="event_stream"):
        yield StatusEvent(
            event_type=obj["event_type"],
            source_id=obj["source_id"],
            prior_sha=obj.get("prior_sha"),
            new_sha=obj.get("new_sha"),
            detected_at=obj["detected_at"],
            metadata=obj.get("metadata", {}),
        )


