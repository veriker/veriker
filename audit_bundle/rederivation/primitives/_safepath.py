"""_safepath — bundle-path containment for verifier-side re-derivation primitives.

A promoted primitive runs on the SAFE spec-pinned path: no subprocess, no
bundle-supplied code. But "bundle data, not code" is only safe if bundle DATA
cannot steer arbitrary filesystem reads. Some recipes name the files a primitive
must read (build's recipe inputs, scrabble's resolved wordlist_file). Those names
are bundle-controlled, so a hostile bundle could request ``../../etc/passwd`` or
an absolute path and turn a read-bytes into an arbitrary-file oracle on the
VERIFIER's machine.

``resolve_within`` is the single audited containment rule those call sites share.
It mirrors the dispatch.py output-id defense (resolve, then assert the resolved
path stays inside the declared root) so there is ONE definition of "inside the
bundle" rather than per-primitive ad-hoc checks. It fails CLOSED: any path that
resolves outside the root raises ValueError, which the primitive surfaces as a
RECOMPUTE_ERROR rather than reading the out-of-tree file.

Stdlib-only (§C5 core verify() path).
"""

from __future__ import annotations

from pathlib import Path


def resolve_within(root: Path, rel: str) -> Path:
    """Join ``rel`` under ``root`` and return the resolved path, refusing escape.

    ``rel`` is bundle-controlled (it comes from recipe/timeline data). The join
    is resolved (following ``..`` segments and symlinks, and letting an absolute
    ``rel`` discard ``root`` entirely), then asserted to stay inside the resolved
    ``root``. Anything that escapes — a ``..`` traversal, an absolute path, or a
    symlink under ``root`` pointing out of tree — raises ValueError so the caller
    fails closed instead of reading an out-of-bundle file.
    """
    root_resolved = root.resolve()
    candidate = (root / rel).resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError:
        raise ValueError(
            f"bundle path {rel!r} resolves outside {root_resolved} — "
            "refusing the read (path containment)"
        ) from None
    return candidate
