# Component 2: Source Fragment Addressing

**Scope:** Stable sub-document fragment IDs per the audit-bundle contract §Compose-or-build component table (row 2), revised-kernel item 2.

Whole-document CIDs are not enough. Stable fragment IDs (**byte offsets** / **sentence IDs** / **page coords** / **DOM-XPath+text-offsets**) enable precise quote anchoring, context inspection, and later claim-level support. The schema must support all variants; v1 emits sentence-level + byte-offset; page-coord and DOM-XPath are schema-reserved for future use.

**Why this matters:** Fragment addressing is the foundation for precise, reproducible span-level stamping. Every extracted quote must map back to its exact location in the source via a canonical, immutable fragment ID. Without it, stamps lose context and audit trails become ambiguous.

**See also:**
- The audit-bundle contract §Revised kernel item 2 — design rationale and W3C Web Annotations inspiration
- The audit-bundle contract — component table and contract overview
