"""C18 plugin-OCI-artifact loader.

Substrate-side plugin loader: runtime-loaded plugins are admitted ONLY when
they appear in the TUF-distributed `plugin_allowlist.json` by OCI digest, with
matching cosign + Fulcio claim identity + SLSA provenance digest, and the
registry org matches the hard-pinned `ghcr.io/nexiverify/` allowlist. This
defends against the attack of loading an arbitrary runtime plugin that was
never pinned by OCI digest.

Production verifier runs (the OCI image built by the release flake) hard-fail
on direct-import plugin loads. The `--allow-direct-import` CLI flag (passed
via the loader's `allow_direct_import: bool` constructor arg) is DEV-MODE
ONLY and is explicitly off in production deployments.

Event log: every successful plugin load records a PLUGIN_LOADED row in the
bundle's events.jsonl with the plugin name + oci_digest + cosign_cert
identity + slsa_provenance_digest. Consumers see the full plugin manifest
in the verified bundle.

READ-ONLY-VERIFY CAVEAT (2026-06-10): the PLUGIN_LOADED append mutates
bundle_dir, so this loader MUST NOT run inside BundleVerifier.verify() —
verify() is read-only (a verifier-written events.jsonl classifies as
UNOWNED surplus under the conservation gate and flips re-verification RED).
Plugin admission is a HOST-SIDE step that happens before verification; when
this loader is wired into a verify path, the event must move to the
verdict-face disclosure channel or a caller-owned sink first
(tests/test_verify_readonly_ratchet.py pins the invariant for
audit_bundle/plugins/).

This module is on the SUBSTRATE-VERIFIER side. NOT stdlib-only — invokes
cosign + crane via subprocess, and the c18_tuf_client.fetch_plugin_allowlist
helper (which carries python-tuf deps).


"""

from __future__ import annotations

import hashlib
import json
import subprocess  # noqa: S404 — invoked against cosign + crane only
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# -----------------------------------------------------------------------------
# Reason codes (used in events.jsonl + raised in exceptions)
# -----------------------------------------------------------------------------


REASON_PLUGIN_NOT_IN_ALLOWLIST = "PLUGIN_NOT_IN_ALLOWLIST"
REASON_PLUGIN_OCI_DIGEST_MISMATCH = "PLUGIN_OCI_DIGEST_MISMATCH"
REASON_PLUGIN_COSIGN_VERIFY_FAILED = "PLUGIN_COSIGN_VERIFY_FAILED"
REASON_PLUGIN_SLSA_PROVENANCE_MISMATCH = "PLUGIN_SLSA_PROVENANCE_MISMATCH"
REASON_PLUGIN_REGISTRY_ORG_NOT_ALLOWLISTED = "PLUGIN_REGISTRY_ORG_NOT_ALLOWLISTED"
REASON_PLUGIN_DIRECT_IMPORT_REJECTED_IN_PROD = "PLUGIN_DIRECT_IMPORT_REJECTED_IN_PROD"
REASON_PLUGIN_SLSA_LOOKUP_UNWIRED = "PLUGIN_SLSA_LOOKUP_UNWIRED"
EVENT_KIND_PLUGIN_LOADED = "PLUGIN_LOADED"


# -----------------------------------------------------------------------------
# Errors
# -----------------------------------------------------------------------------


class PluginLoaderError(Exception):
    """Base class for plugin-OCI loader errors."""

    def __init__(self, reason_code: str, detail: str) -> None:
        super().__init__(f"[{reason_code}] {detail}")
        self.reason_code = reason_code
        self.detail = detail


# -----------------------------------------------------------------------------
# Result dataclass
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class PluginLoadOutcome:
    """Outcome of a single plugin load attempt."""

    plugin_name: str
    ok: bool
    reason_code: str | None
    detail: str
    oci_digest: str | None
    cosign_cert_identity: str | None
    slsa_provenance_digest: str | None


# -----------------------------------------------------------------------------
# Loader
# -----------------------------------------------------------------------------


class PluginOCILoader:
    """Loads plugins as TUF-allowlisted OCI artifacts.

    Construct with:
      - bundle_dir: where events.jsonl is written
      - allowlist: dict loaded from plugin_allowlist.json (use
                   audit_bundle.extensions.c18_tuf_client.fetch_plugin_allowlist
                   in production; tests inject a fixture dict)
      - allow_direct_import: DEV-MODE ONLY. PRODUCTION must construct with
                             allow_direct_import=False (default).
      - cosign_runner / slsa_verifier_runner: optional callable overrides
                                                for unit testing; default
                                                invokes the real subprocess.
    """

    def __init__(
        self,
        *,
        bundle_dir: Path,
        allowlist: dict[str, Any],
        allow_direct_import: bool = False,
        cosign_runner: object | None = None,
        slsa_provenance_lookup: object | None = None,
    ) -> None:
        self.bundle_dir = bundle_dir
        self.allowlist = allowlist
        self.allow_direct_import = bool(allow_direct_import)
        self._cosign_runner = cosign_runner or _default_cosign_verify
        self._slsa_provenance_lookup = (
            slsa_provenance_lookup or _default_slsa_provenance_lookup
        )

    # ------------------------------------------------------------------ load_plugin

    def load_plugin(
        self,
        plugin_name: str,
        *,
        local_plugin_bytes: bytes | None = None,
    ) -> PluginLoadOutcome:
        """Admit (or reject) a single plugin.

        If `local_plugin_bytes` is provided, the loader computes its sha256
        and asserts it matches the allowlist's `oci_digest_at_v0_3_cut`.
        For real OCI artifacts the caller fetches the OCI manifest bytes
        from ghcr.io and passes them here.
        """
        # 1. Direct-import bypass guard (production forbids direct-import loads).
        if local_plugin_bytes is None and not self.allow_direct_import:
            return self._reject(
                plugin_name,
                REASON_PLUGIN_DIRECT_IMPORT_REJECTED_IN_PROD,
                (
                    "production verifier refuses direct-import plugin load; "
                    "pass allow_direct_import=True only in a dev-mode bypass"
                ),
            )

        # 2. Allowlist lookup.
        entries = self.allowlist.get("entries", {})
        entry = entries.get(plugin_name)
        if not isinstance(entry, dict):
            return self._reject(
                plugin_name,
                REASON_PLUGIN_NOT_IN_ALLOWLIST,
                f"plugin {plugin_name!r} not in plugin_allowlist.json entries",
            )

        # 3. Registry org allowlist check.
        oci_artifact = str(entry.get("oci_artifact", ""))
        allowed_orgs = self.allowlist.get("registry_org_allowlist", [])
        if not any(oci_artifact.startswith(org) for org in allowed_orgs):
            return self._reject(
                plugin_name,
                REASON_PLUGIN_REGISTRY_ORG_NOT_ALLOWLISTED,
                (
                    f"plugin oci_artifact {oci_artifact!r} not in registry org "
                    f"allowlist {allowed_orgs!r}"
                ),
            )

        # 4. OCI digest match.
        expected_oci_digest = str(entry.get("oci_digest_at_v0_3_cut", ""))
        if local_plugin_bytes is not None:
            local_digest = "sha256:" + hashlib.sha256(local_plugin_bytes).hexdigest()
            if local_digest != expected_oci_digest:
                return self._reject(
                    plugin_name,
                    REASON_PLUGIN_OCI_DIGEST_MISMATCH,
                    (
                        f"local digest {local_digest!r} != allowlist "
                        f"expected {expected_oci_digest!r}"
                    ),
                )

        # 5. cosign signature verification against Fulcio claim identity.
        cosign_cert_identity = str(entry.get("cosign_cert_identity", ""))
        cosign_ok, cosign_err = self._cosign_runner(  # type: ignore[misc]
            oci_artifact=oci_artifact,
            expected_cert_identity=cosign_cert_identity,
        )
        if not cosign_ok:
            return self._reject(
                plugin_name,
                REASON_PLUGIN_COSIGN_VERIFY_FAILED,
                f"cosign verify failed: {cosign_err}",
            )

        # 6. SLSA provenance digest match.
        expected_slsa = str(entry.get("slsa_provenance_digest_at_v0_3_cut", ""))
        actual_slsa = self._slsa_provenance_lookup(oci_artifact=oci_artifact)  # type: ignore[misc]
        if actual_slsa != expected_slsa:
            return self._reject(
                plugin_name,
                REASON_PLUGIN_SLSA_PROVENANCE_MISMATCH,
                (
                    f"SLSA provenance digest {actual_slsa!r} != allowlist "
                    f"expected {expected_slsa!r}"
                ),
            )

        # 7. PASS — record PLUGIN_LOADED in events.jsonl.
        self._emit_event(
            EVENT_KIND_PLUGIN_LOADED,
            {
                "plugin_name": plugin_name,
                "oci_digest": expected_oci_digest,
                "cosign_cert": cosign_cert_identity,
                "slsa_provenance": expected_slsa,
                "ts": datetime.now(timezone.utc).isoformat(),
            },
        )

        return PluginLoadOutcome(
            plugin_name=plugin_name,
            ok=True,
            reason_code=None,
            detail="plugin admitted; PLUGIN_LOADED recorded in events.jsonl",
            oci_digest=expected_oci_digest,
            cosign_cert_identity=cosign_cert_identity,
            slsa_provenance_digest=expected_slsa,
        )

    # ------------------------------------------------------------------ helpers

    def _reject(
        self,
        plugin_name: str,
        reason_code: str,
        detail: str,
    ) -> PluginLoadOutcome:
        return PluginLoadOutcome(
            plugin_name=plugin_name,
            ok=False,
            reason_code=reason_code,
            detail=detail,
            oci_digest=None,
            cosign_cert_identity=None,
            slsa_provenance_digest=None,
        )

    def _emit_event(self, kind: str, detail: dict) -> None:
        self.bundle_dir.mkdir(parents=True, exist_ok=True)
        event = {
            "kind": kind,
            "ts": detail.get("ts") or datetime.now(timezone.utc).isoformat(),
            "detail": detail,
        }
        with (self.bundle_dir / "events.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")


# -----------------------------------------------------------------------------
# Default runners (real subprocess invocations)
# -----------------------------------------------------------------------------


def _default_cosign_verify(
    *,
    oci_artifact: str,
    expected_cert_identity: str,
) -> tuple[bool, str]:
    """Invoke `cosign verify --certificate-identity <URL> <oci_artifact>`."""
    try:
        result = subprocess.run(  # noqa: S603
            [
                "cosign",
                "verify",
                "--certificate-identity",
                expected_cert_identity,
                "--certificate-oidc-issuer",
                "https://token.actions.githubusercontent.com",
                oci_artifact,
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    return result.returncode == 0, result.stderr


def _default_slsa_provenance_lookup(*, oci_artifact: str) -> str:
    """Fail-closed stub: the real implementation invokes `cosign download
    attestation --type slsaprovenance <oci_artifact>` and extracts the
    SLSA-attestation digest; it is wired at the release cut, alongside the
    actual oci_digest fills.

    Raises instead of returning a placeholder: a returned sentinel string
    could tautologically match an allowlist entry that still carries the
    same pre-release placeholder, admitting a plugin with no provenance
    check at all (false green).
    """
    raise PluginLoaderError(
        REASON_PLUGIN_SLSA_LOOKUP_UNWIRED,
        "SLSA provenance lookup is not wired (pre-release-cut stub); "
        "construct PluginOCILoader with a real slsa_provenance_lookup "
        f"to verify {oci_artifact!r}",
    )


__all__ = [
    "EVENT_KIND_PLUGIN_LOADED",
    "PluginLoadOutcome",
    "PluginLoaderError",
    "PluginOCILoader",
    "REASON_PLUGIN_COSIGN_VERIFY_FAILED",
    "REASON_PLUGIN_DIRECT_IMPORT_REJECTED_IN_PROD",
    "REASON_PLUGIN_NOT_IN_ALLOWLIST",
    "REASON_PLUGIN_OCI_DIGEST_MISMATCH",
    "REASON_PLUGIN_REGISTRY_ORG_NOT_ALLOWLISTED",
    "REASON_PLUGIN_SLSA_LOOKUP_UNWIRED",
    "REASON_PLUGIN_SLSA_PROVENANCE_MISMATCH",
]
