"""audit_bundle/retrieval — Component 5: Retrieval trace capture per output.

Implements the audit-bundle contract's retrieval-trace component.

Retrieval trace capture: retriever query, candidate set, rankings,
selected chunks, context window actually injected, model/router version.
Captured even if not exposed in consumer UI.

Three-set distinction (retrieved / context_injected / quote_supporting)
lives in this package; the per-output manifest emitter (Component 6)
consumes the trace and splits it into the three sets.

Public API (re-exported once sibling modules land):
- RetrievalTrace — immutable capture of retrieval event metadata
- ThreeSetView — distinguished retrieved / context_injected / quote_supporting sets
- capture_trace — factory for constructing retrieval traces

See README.md for scope details.
"""
