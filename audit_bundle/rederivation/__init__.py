"""audit_bundle.rederivation — spec-pinned type dispatch (Axis 1 + Axis 2).

The re-derivation subset of the verifier: per claimed output, recompute a value
with a verifier-side ReDerivationPrimitive (Axis 2 — value return) and compare it
against the producer's claimed value with a generic comparator-kind (Axis 2 —
split), where the binding type -> {primitive_id, comparator{kind,params}} is
resolved from a SHA-pinned spec that the AUDITOR anchors (Axis 1 — the producer
cannot author or select the authoritative spec).

See THREAT_MODEL.md for the as-built attack table for this dispatch path.

Stdlib-only: this package is on the core verify() path and must not import
cryptography / jcs (the H1 boundary).
"""

from __future__ import annotations
