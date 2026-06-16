"""Checks a producer-declared issuer against a CONFIGURED allow-list (Property 1).

This module does not decide which issuers are authoritative or trustworthy. The
allow-list is an **exogenous, caller-supplied input** — a JSON file mapping issuer
domain strings to identity metadata, injected by the deployment, **not** a registry
this verifier owns, curates, or governs (see `allow_list_v0.json`'s CANARY-SCOPE
note: it is explicitly NOT an authoritative production registry). Whether a given
allow-list is itself authoritative is a trust-root concern handled by a separate
substrate, out of scope here.

No live DNS lookups or network calls anywhere in this module.
YAML support is deferred to v2; v1 accepts JSON only.
"""

from __future__ import annotations

import json
from pathlib import Path


class AllowListLoadError(ValueError):
    """Raised when the allow-list file cannot be parsed or has unexpected structure."""


class IssuerVerifier:
    """Checks a producer-declared issuer against a configured allow-list (Property 1).

    The allow-list is an exogenous, caller-supplied input; this class does not
    decide issuer authority or trustworthiness.
    v1: allow-list lookup only — no live DNS, no OCSP, no PKI queries.
    v1.1 will add cryptographic verification against the public_key_pem field.

    Usage::

        verifier = IssuerVerifier(default_v1_allow_list_path())
        ok, issuer_id = verifier.verify(source_cid, "sec.gov")
    """

    def __init__(self, allow_list_path: Path | None = None) -> None:
        self.allow_list: dict[str, dict] = (
            self._load(allow_list_path) if allow_list_path else {}
        )

    def _load(self, path: Path) -> dict[str, dict]:
        """Load and validate the allow-list JSON file.

        Expected top-level shape::

            {
              "domain.tld": {
                "identity_method": "curated_allow_list",
                "public_key_pem": null,
                "notes": "..."
              },
              ...
            }

        YAML ingestion is v2 scope; this method accepts JSON only.

        Raises:
            AllowListLoadError: if the file is missing, not valid JSON, or has
                an unexpected top-level structure (non-object root or non-object
                entry values).
        """
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise AllowListLoadError(
                f"Cannot read allow-list at {path}: {exc}"
            ) from exc

        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise AllowListLoadError(
                f"Allow-list at {path} is not valid JSON: {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise AllowListLoadError(
                f"Allow-list at {path} must be a JSON object at the top level; "
                f"got {type(data).__name__}"
            )

        validated: dict[str, dict] = {}
        for key, value in data.items():
            if not isinstance(key, str):
                raise AllowListLoadError(
                    f"Allow-list key {key!r} must be a string (issuer domain)"
                )
            # Keys prefixed with '_' are metadata/comment entries; skip them.
            if key.startswith("_"):
                continue
            if not isinstance(value, dict):
                raise AllowListLoadError(
                    f"Allow-list entry for {key!r} must be a JSON object; "
                    f"got {type(value).__name__}"
                )
            validated[key] = value

        return validated

    def verify(self, source_cid: str, candidate_issuer: str) -> tuple[bool, str | None]:
        """Look up candidate_issuer in the curated allow-list.

        Args:
            source_cid: content-addressed ID of the source snapshot being
                verified (accepted but unused at v1; reserved for future
                per-source allow-list partitioning).
            candidate_issuer: the domain string to verify (e.g. "sec.gov").

        Returns:
            ``(True, candidate_issuer)`` if the issuer is in the allow-list.
            ``(False, None)`` otherwise.
        """
        if candidate_issuer in self.allow_list:
            return True, candidate_issuer
        return False, None


def default_v1_allow_list_path() -> Path:
    """Return the path to the bundled v0 allow-list fixture.

    The fixture (allow_list_v0.json) contains three canonical reference issuers
    for span-provenance + device-mesh integration tests. It is a
    CANARY-SCOPE list, NOT an authoritative production registry.
    """
    return Path(__file__).parent / "allow_list_v0.json"
