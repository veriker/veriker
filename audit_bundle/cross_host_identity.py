"""audit_bundle/cross_host_identity.py — canonical identity for cross-host edges.

Single source of truth for the key that binds "this cross_host_authenticators
edge is present in the manifest" to "a wired plugin verified THIS edge". Both
the verifier's cross-host coverage guard (BundleVerifier._step_cross_host_guard)
and every cross-host-verifying plugin compute the key from the SAME function over
the SAME edge object, so:

  present_edge_keys − verified_edge_keys == ∅   ⟺   every present edge was verified.

The key is a content hash (canonical JSON → sha256), NOT a list index: a plugin
cannot claim coverage of an edge whose exact bytes are not present, and the check
is order-independent and tamper-evident. Replaced the coarse boolean capability
marker `verifies_cross_host_authenticators` (which promised "I verify cross-host"
without proving WHICH edges) — see the verdict-divergence tribunal disposition
(per-edge coverage accounting, ratified 2026-06-10).

Stdlib only (keeps the core verify() path import-light).
"""

from __future__ import annotations

import hashlib
import json


def cross_host_edge_key(edge: dict) -> str:
    """Canonical content key for one cross_host_authenticators edge.

    sha256 over canonical JSON (sorted keys, compact separators). The edge comes
    from `json.loads(manifest.json)` so it is JSON-serialisable by construction.
    """
    canonical = json.dumps(
        edge, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return "ch:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def cross_host_edge_keys(edges) -> frozenset[str]:
    """Key set for an edge list; non-dict entries are skipped (uncoverable →
    they remain in the guard's `present − verified` difference and fail closed)."""
    if not isinstance(edges, list):
        return frozenset()
    return frozenset(cross_host_edge_key(e) for e in edges if isinstance(e, dict))
