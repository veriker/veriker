"""Deliberately-unverified bootstrap trust-loaders (NOT for production use).

The strict public loaders in :mod:`audit_bundle.extensions.c18_tuf_client`
(``load_bundled_root``, ``fetch_sigstore_trust_root``, ``fetch_plugin_allowlist``,
``fetch_revocation_root``) always fail closed on unsigned / placeholder bootstrap
trust material and carry NO opt-out parameter. That is the only API a verifier
should ever call.

This module is the single, explicitly-named home for the one scenario that
genuinely needs the raw pre-ceremony material: the v0.4 root-seed / dev-bootstrap
path that deliberately hands an unsigned root to python-tuf for the downstream
cryptographic check, plus the test-suite that exercises the bundled placeholder
files. Every entry point here is suffixed ``_bootstrap_unverified`` so a call
site reads as what it is: the material returned is NOT verified trust.

Structural discipline is unchanged — these wrappers skip ONLY the
signature-presence / no-unfilled-``TBD-*`` fail-closed asserts. The role-name,
threshold, key, rotation-policy, and expiry checks all still run (they share the
exact same impl as the strict loaders; validation is never forked). A caller of
anything here takes responsibility for the downstream cryptographic verification.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from audit_bundle.extensions.c18_tuf_client import (
    _fetch_plugin_allowlist_impl,
    _fetch_revocation_root_impl,
    _fetch_sigstore_trust_root_impl,
    _load_bundled_root_impl,
)

__all__ = [
    "fetch_plugin_allowlist_bootstrap_unverified",
    "fetch_revocation_root_bootstrap_unverified",
    "fetch_sigstore_trust_root_bootstrap_unverified",
    "load_bundled_root_bootstrap_unverified",
]


def load_bundled_root_bootstrap_unverified(
    root_path: Path | None = None,
) -> dict[str, Any]:
    """Load the bundled root.json WITHOUT the unsigned/placeholder fail-closed
    asserts. The returned root is NOT verified trust material. v0.4 root-seed /
    dev path only — see the module docstring."""
    return _load_bundled_root_impl(root_path, allow_placeholders=True)


def fetch_sigstore_trust_root_bootstrap_unverified(
    bundled_path: Path | None = None,
) -> dict[str, Any]:
    """Load the sigstore-trust-root role WITHOUT the unfilled-``TBD-*`` assert.
    The returned role is NOT verified trust material. Bootstrap/dev path only."""
    return _fetch_sigstore_trust_root_impl(bundled_path, allow_placeholders=True)


def fetch_plugin_allowlist_bootstrap_unverified(
    bundled_path: Path | None = None,
) -> dict[str, Any]:
    """Load the plugin-allowlist role WITHOUT the unfilled-``TBD-*`` assert.
    The returned allowlist is NOT verified trust material. Bootstrap/dev path only."""
    return _fetch_plugin_allowlist_impl(bundled_path, allow_placeholders=True)


def fetch_revocation_root_bootstrap_unverified(
    bundled_path: Path | None = None,
) -> dict[str, Any]:
    """Load the revocation-root role WITHOUT the unsigned/placeholder asserts.
    The returned role is NOT verified trust material. Bootstrap/dev path only."""
    return _fetch_revocation_root_impl(bundled_path, allow_placeholders=True)
