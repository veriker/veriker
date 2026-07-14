"""audit_bundle/snapshots — Component 1: Content-addressed source snapshots.

Implements the audit-bundle contract's content-addressed snapshot component.

WARC-or-equivalent capture at ingest with stable CIDs. Snapshot policy
explicit: raw bytes, rendered text extraction version, normalization version.
NO live network calls — snapshots are produced by separate ingestion code
outside this package and PASSED IN as bytes.

Public API (re-exported once sibling modules land):
- SnapshotPolicy — explicit policy for snapshot capture (raw, rendered, normalized)
- compute_cid — compute content-addressed ID for snapshot bytes
- SnapshotStore — interface for snapshot storage and retrieval

See README.md for scope details.
"""
