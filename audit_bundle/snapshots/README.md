# Component 1: Content-Addressed Source Snapshots

**Scope:** Content-addressed source snapshots per the audit-bundle contract §Compose-or-build component table (row 1), revised-kernel item 1.

WARC-or-equivalent capture at ingest with stable content-addressed identifiers (CIDs). Snapshot policy is explicit: **raw bytes**, **rendered text extraction version**, **normalization version**. No live network calls — snapshots are produced by separate ingestion code and **PASSED IN as bytes to this package**. The snapshots themselves are spec-SHA-pin candidates (C1 in the audit-bundle contract).

**Why this matters:** Stable, addressable snapshots of source content are the foundation for reproducible verification. Every span stamp, fragment reference, and audit claim depends on the source content being immutable post-capture. This component provides the policy and identity layer; domain pilots implement capture.

**See also:**
- The audit-bundle contract §Revised kernel item 1 — design rationale and scope boundaries
- The audit-bundle contract §C1 (Spec-SHA pinning) — how snapshots feed into the audit contract
