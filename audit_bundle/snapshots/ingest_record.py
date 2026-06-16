"""Ingest event envelope for source snapshots.

Each SnapshotIngestRecord documents a single ingest event: which snapshot was
captured (via CID), from where, under which policy, and any domain metadata.
Records are append-only; the JSONL log is never mutated after write.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .cid import CID


@dataclass(frozen=True)
class SnapshotIngestRecord:
    """Frozen ingest event envelope for a single captured snapshot.

    All fields are immutable; designed for append-only serialization to a
    JSONL ingest log where prior rows are never mutated.
    """

    cid: CID
    source_url: str | None
    ingested_at: str         # ISO-8601 UTC 'Z'
    policy_version: str      # SnapshotPolicy.policy_version at ingest time
    policy_dict_sha256: str  # sha256 of policy_to_canonical_dict serialized
    redirect_chain: tuple[str, ...] = ()
    rendered_text_cid: CID | None = None
    ingestion_metadata: dict = field(default_factory=dict)


def _record_to_dict(record: SnapshotIngestRecord) -> dict:
    return {
        'cid': record.cid.as_string,
        'ingested_at': record.ingested_at,
        'ingestion_metadata': record.ingestion_metadata,
        'policy_dict_sha256': record.policy_dict_sha256,
        'policy_version': record.policy_version,
        'redirect_chain': list(record.redirect_chain),
        'rendered_text_cid': (
            record.rendered_text_cid.as_string
            if record.rendered_text_cid is not None
            else None
        ),
        'source_url': record.source_url,
    }


def record_to_canonical_json(record: SnapshotIngestRecord) -> bytes:
    """Return JCS-style canonical JSON bytes for record.

    Uses sort_keys=True + compact separators + ensure_ascii=False as the v1
    canonical form, matching the W1-W2 pattern in audit_bundle.bundle_manifest.
    """
    return json.dumps(
        _record_to_dict(record),
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
    ).encode('utf-8')


def append_ingest_record(jsonl_path: Path, record: SnapshotIngestRecord) -> None:
    """Append record to a JSONL file in canonical form.

    Opens in append-binary mode and writes one canonical JSON line followed by
    a newline byte.  Prior rows are never touched — semantics mirror
    audit_bundle.event_stream.append_event.
    """
    line = record_to_canonical_json(record) + b'\n'
    with jsonl_path.open('ab') as fh:
        fh.write(line)
