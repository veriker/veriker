"""DSSE envelope version → canonicalization tuple map.

This module contains a COMPILE-TIME CONSTANT mapping each known
``dsse_envelope_version`` string to a ``(envelope_pae, manifest_canon)``
tuple.  It is NOT loaded from any file, bundle, or distributed artifact —
the mapping is a literal in source code.

Rationale (DSSE SCOPING v2.2 §6)
---------------------------------
The canonicalization scheme is an implied function of ``dsse_envelope_version``
— there is no separate canonicalization header field.  Future changes require
a ``dsse_envelope_version`` bump, never a second knob.  Keeping the map as a
compile-time source literal (not a JSON config, not a bundle-resident file)
closes the "turtles" problem: a distributed version→tuple table would itself
need integrity protection, re-introducing the dependency it was meant to avoid.

A verifier built against version N rejects all versions ≠ N unless explicitly
upgraded to a new source build that carries the new tuple.

v0.4 tuple
----------
- ``envelope_pae`` = ``"DSSE-PAEv1"``   — in-toto DSSE PAE per spec.md
- ``manifest_canon`` = ``"RFC8785-v1"`` — RFC 8785 JSON Canonicalization Scheme
  pinned at rfc8785==0.1.4 by SRI hash (enforced in WS-1b).

Import safety
-------------
This module imports nothing outside the Python stdlib (types only).
Importing ``cryptography``, ``jcs``, or ``rfc8785`` is FORBIDDEN here.
"""

from __future__ import annotations

from types import MappingProxyType

__all__ = ["VERSION_MAP", "canonicalization_for"]

# ---------------------------------------------------------------------------
# Compile-time constant — do NOT load from any file or distributed artifact.
# ---------------------------------------------------------------------------

VERSION_MAP: MappingProxyType[str, tuple[str, str]] = MappingProxyType(
    {
        # v0.4: DSSE PAE + RFC 8785 manifest canonicalization.
        # envelope_pae = DSSE-PAEv1   (in-toto DSSE spec.md PAE formula)
        # manifest_canon = RFC8785-v1 (rfc8785==0.1.4, pinned by SRI hash in WS-1b)
        "v0.4": ("DSSE-PAEv1", "RFC8785-v1"),
    }
)


def canonicalization_for(version: str) -> tuple[str, str]:
    """Return the (envelope_pae, manifest_canon) tuple for a DSSE version.

    Parameters
    ----------
    version:
        The ``dsse_envelope_version`` string (e.g. ``"v0.4"``).

    Returns
    -------
    tuple[str, str]
        ``(envelope_pae, manifest_canon)`` — the canonicalization identifiers
        implied by this version.  Both are stable string identifiers; they
        are NOT configuration values and are NOT loaded from any external source.

    Raises
    ------
    ValueError
        If ``version`` is not in ``VERSION_MAP``.  A verifier MUST reject any
        version it does not recognize; there is no fallback or default.

    Examples
    --------
    >>> canonicalization_for("v0.4")
    ('DSSE-PAEv1', 'RFC8785-v1')
    >>> canonicalization_for("v99")  # doctest: +IGNORE_EXCEPTION_DETAIL
    Traceback (most recent call last):
      ...
    ValueError: Unknown dsse_envelope_version 'v99'. Known versions: ['v0.4']
    """
    try:
        return VERSION_MAP[version]
    except KeyError:
        known = sorted(VERSION_MAP.keys())
        raise ValueError(
            f"Unknown dsse_envelope_version {version!r}. Known versions: {known}"
        ) from None
