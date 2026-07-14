"""audit_bundle/rederivation/registry.py — verifier-side primitive registry.

Maps primitive_id -> ReDerivationPrimitive INSTANCE. Primitives are
verifier-DISTRIBUTION code: they self-register at import (audit_bundle.
rederivation.primitives.*) and are NEVER bundle-supplied (§C5/§C6).

A primitive_id named in a pinned spec but absent from this registry is
fail-closed at dispatch (UnknownPrimitive) — the same discipline that holds
`custom` comparators. There is exactly one registry namespace; there is no
separate `custom:<id>` governance path.

Stdlib-only (core verify() path).
"""

from __future__ import annotations


class UnknownPrimitive(Exception):
    """A spec names a primitive_id not in the verifier registry (fail-closed)."""


_PRIMITIVE_REGISTRY: dict[str, object] = {}


def register_primitive(primitive: object) -> None:
    """Register a ReDerivationPrimitive instance by its primitive_id. Idempotent
    for an identical id; a conflicting re-registration is a programming error."""
    pid = getattr(primitive, "primitive_id", None)
    if not isinstance(pid, str) or not pid:
        raise ValueError(f"primitive {primitive!r} has no string primitive_id")
    existing = _PRIMITIVE_REGISTRY.get(pid)
    if existing is not None and type(existing) is not type(primitive):
        raise ValueError(
            f"primitive_id {pid!r} already registered to a different class "
            f"({type(existing).__name__} vs {type(primitive).__name__})"
        )
    _PRIMITIVE_REGISTRY[pid] = primitive


def resolve_primitive(primitive_id: str) -> object:
    """Return the registered primitive instance, or raise UnknownPrimitive."""
    prim = _PRIMITIVE_REGISTRY.get(primitive_id)
    if prim is None:
        raise UnknownPrimitive(
            f"primitive_id {primitive_id!r} not in verifier registry "
            f"(registered: {tuple(_PRIMITIVE_REGISTRY)!r}). A primitive a pinned "
            "spec names but the verifier distribution does not implement is "
            "fail-closed — the verifier never loads a primitive from the bundle."
        )
    return prim


def registered_primitives() -> frozenset[str]:
    return frozenset(_PRIMITIVE_REGISTRY)


def _ensure_primitives_loaded() -> None:
    """Import the bundled primitive implementations so they self-register.
    Called by the dispatch step before resolution. Import-on-demand keeps the
    registry populated without import-time side effects in this module."""
    from . import primitives  # noqa: F401  (import triggers self-registration)
