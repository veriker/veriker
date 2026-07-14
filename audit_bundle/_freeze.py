"""audit_bundle._freeze — deep-immutability containers for parse-boundary state.

A recurring shape in this package is a ``@dataclass(frozen=True)`` whose fields
are plain ``dict``/``list`` values parsed from external bytes (a manifest, a
signed revocation list, an anchored spec set, a pinned key policy). ``frozen``
locks only the TOP-LEVEL attribute bindings; the nested containers stay mutable,
so verdict correctness rests on an unenforced convention that no trusted code
mutates them in place after parsing. This module is the ONE mechanism for
locking that convention into a hard invariant: freeze the containers at the
construction boundary and any later in-place mutation raises ``TypeError`` at
the offending line instead of silently laundering a downstream decision.

This is defense-in-depth against accidental mutation by verifier-shipped (TCB)
code — NOT an exploit fix: no attacker-controlled code holds a live reference
to these objects (bundle-supplied execution is subprocess-isolated). It
deliberately does not defend against ``dict.__setitem__(frozen, ...)``-style
explicit bypass; nothing untrusted has the reference.

Representation choice: ``_FrozenDict(dict)`` / ``_FrozenList(list)`` rather than
``MappingProxyType``, because several consumers re-serialize frozen fields
(e.g. ``json.dumps(m.snapshot_policy, ...)`` for the snapshot-policy SHA and the
OF1 manifest-header leaf). A dict/list subclass keeps ``isinstance(x, dict)`` /
``isinstance(x, list)`` True and serializes byte-identically to its base, so
every canonical leaf / SHA is unchanged; only the normal mutation API raises.

Extracted from bundle_manifest.py (manifest deep-immutability lock, 2026-06-10)
when the same class of field was found on RevocationList and other
trust-decision carriers; kept dependency-free (stdlib only, no audit_bundle
imports) so leaf modules with strict import contracts — e.g. revocation.py —
can use it. The package-wide inventory of frozen-dataclass mutable-container
fields is ratcheted by tests/test_frozen_field_ratchet.py.

History note: the original in-manifest machinery is preserved in git history on
bundle_manifest.py; that module now re-exports these names unchanged.
"""

from __future__ import annotations

__all__ = ["deep_freeze"]


_FROZEN_MUTATION_MSG = (
    "this container is deeply immutable: it was frozen at its parse/construction "
    "boundary because it is shared read-only state for later trust decisions. "
    "Copy before mutating (e.g. dict(x) / list(x))."
)


def _frozen_mutation(self, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
    raise TypeError(_FROZEN_MUTATION_MSG)


class _FrozenDict(dict):
    """A dict whose in-place mutation API raises. Still `isinstance(_, dict)` and
    JSON-serializes identically to a plain dict (so canonical leaves / SHAs are
    unchanged). See module note above for why MappingProxyType is unsuitable."""

    __slots__ = ()

    __setitem__ = _frozen_mutation
    __delitem__ = _frozen_mutation
    setdefault = _frozen_mutation
    pop = _frozen_mutation
    popitem = _frozen_mutation
    clear = _frozen_mutation
    update = _frozen_mutation
    __ior__ = _frozen_mutation

    def __reduce__(self):
        # Round-trip as a plain dict (the frozen-ness is a parse-boundary
        # property, not a serialized one).
        return (dict, (dict(self),))


class _FrozenList(list):
    """A list whose in-place mutation API raises. Still `isinstance(_, list)` and
    JSON-serializes identically to a plain list."""

    __slots__ = ()

    __setitem__ = _frozen_mutation
    __delitem__ = _frozen_mutation
    append = _frozen_mutation
    extend = _frozen_mutation
    insert = _frozen_mutation
    remove = _frozen_mutation
    pop = _frozen_mutation
    clear = _frozen_mutation
    sort = _frozen_mutation
    reverse = _frozen_mutation
    __iadd__ = _frozen_mutation
    __imul__ = _frozen_mutation

    def __reduce__(self):
        return (list, (list(self),))


def deep_freeze(value):  # noqa: ANN001, ANN201
    """Recursively wrap a JSON-shaped value into deeply-immutable containers.

    dict -> _FrozenDict, list -> _FrozenList, tuple -> tuple, set -> frozenset;
    every nested value is frozen too. Scalars (str/int/float/bool/None) and any
    other leaf type pass through unchanged. Idempotent: re-freezing a frozen
    value is a no-op-shaped rebuild (cheap, structurally identical).
    """
    if isinstance(value, dict):
        return _FrozenDict((k, deep_freeze(v)) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        frozen_items = [deep_freeze(v) for v in value]
        return (
            tuple(frozen_items)
            if isinstance(value, tuple)
            else _FrozenList(frozen_items)
        )
    if isinstance(value, (set, frozenset)):
        return frozenset(deep_freeze(v) for v in value)
    return value
