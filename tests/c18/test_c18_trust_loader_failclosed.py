"""Trust-loader fail-closed contract (redteam 2026-06-09).

The strict public trust-loaders refuse unsigned / placeholder bootstrap trust
material ALWAYS — they carry no opt-out parameter. The raw pre-ceremony material
is reachable only via the explicitly-named ``*_bootstrap_unverified`` functions
in ``c18_tuf_bootstrap``. This moves the protection from the release-only marker
gate (REQUIRE_C18_HARDENING) to an always-on guard at the API boundary, so a
consumer cannot accidentally trust an empty-signature root or a TBD-* placeholder
digest/key just because the release pipeline did not run.

These assertions are exercised against the SHIPPED bundled files, which are
genuine pre-ceremony bootstrap material (empty root sigs + TBD-* values).
"""

from __future__ import annotations

import pytest

from audit_bundle.extensions.c18_tuf_bootstrap import (
    fetch_plugin_allowlist_bootstrap_unverified,
    fetch_sigstore_trust_root_bootstrap_unverified,
    load_bundled_root_bootstrap_unverified,
)
from audit_bundle.extensions.c18_tuf_client import (
    ROLE_PLUGIN_ALLOWLIST,
    ROLE_SIGSTORE_TRUST_ROOT,
    TUFBootstrapPlaceholderPresent,
    fetch_plugin_allowlist,
    fetch_sigstore_trust_root,
    load_bundled_root,
)


def test_load_bundled_root_fails_closed_on_empty_signatures() -> None:
    """The shipped root.json bootstrap has empty signatures — refuse by default."""
    with pytest.raises(TUFBootstrapPlaceholderPresent):
        load_bundled_root()


def test_load_bundled_root_opt_in_returns_unsigned_bootstrap_root() -> None:
    """The documented bootstrap-seed path can still obtain the unsigned root."""
    root = load_bundled_root_bootstrap_unverified()
    assert "signed" in root


def test_fetch_sigstore_trust_root_fails_closed_on_tbd_placeholder() -> None:
    """The shipped sigstore-trust-root carries TBD-* expected_sha256 values."""
    with pytest.raises(TUFBootstrapPlaceholderPresent, match="TBD"):
        fetch_sigstore_trust_root()


def test_fetch_sigstore_trust_root_opt_in_returns_role() -> None:
    role = fetch_sigstore_trust_root_bootstrap_unverified()
    assert role["role_name"] == ROLE_SIGSTORE_TRUST_ROOT


def test_fetch_plugin_allowlist_fails_closed_on_tbd_digest() -> None:
    """The shipped plugin-allowlist carries TBD-* oci_digest placeholders."""
    with pytest.raises(TUFBootstrapPlaceholderPresent, match="TBD"):
        fetch_plugin_allowlist()


def test_fetch_plugin_allowlist_opt_in_returns_role() -> None:
    role = fetch_plugin_allowlist_bootstrap_unverified()
    assert role["role_name"] == ROLE_PLUGIN_ALLOWLIST


def test_placeholder_token_in_prose_does_not_false_trip(tmp_path) -> None:
    """A TBD token in a KEY name or mid-sentence prose VALUE must not trip the
    gate — only a VALUE that BEGINS with the sentinel is an unfilled field."""
    import json

    role = {
        "role_name": ROLE_PLUGIN_ALLOWLIST,
        "registry_org_allowlist": ["ghcr.io/veriker/"],
        "honest_note": "digests are filled at the ceremony; none are TBD now",
        "entries": {
            "p": {
                "oci_artifact": "ghcr.io/veriker/p",
                "oci_digest_at_v0_3_cut": "sha256:" + "ab" * 32,
                "cosign_cert_identity": "https://example/ci",
                "slsa_provenance_digest_at_v0_3_cut": "sha256:" + "cd" * 32,
            }
        },
    }
    path = tmp_path / "plugin_allowlist.json"
    path.write_text(json.dumps(role), encoding="utf-8")
    # Mid-sentence "TBD" in honest_note is NOT at value-start → must load fine.
    loaded = fetch_plugin_allowlist(bundled_path=path)
    assert loaded["role_name"] == ROLE_PLUGIN_ALLOWLIST


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
