"""audit_bundle/fragments — Component 2: Source fragment addressing.

Implements the audit-bundle contract's source-fragment component.

Stable sub-document IDs (byte offsets + sentence IDs + page coords as
appropriate per source type) baked into the schema from day one.
Fragment addressing enables precise span anchoring, context display,
and later claim-level support without relying on whole-document CIDs.

Public API (re-exported once sibling modules land):
- FragmentID — abstract base for fragment addressing schemes
- ByteOffsetFragment — fragment identified by byte offset range
- SentenceIDFragment — fragment identified by sentence number(s)
- PageCoordFragment — fragment identified by page number and coordinate

See README.md for scope details.
"""
