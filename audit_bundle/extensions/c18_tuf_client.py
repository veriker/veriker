"""C18 TUF client — substrate-verifier-side trust-bundle fetch + validation.

Wraps `python-tuf >= 6.0` to fetch + validate the v-kernel-audit-bundle TUF
feed at `manifest.vkernel.dev/v0.3.0.json`. The TUF root is EMBEDDED at compile
time under `audit_bundle/extensions/_tuf_root/root.json` — bundled into the OCI
image by the Nix flake so first-trust does not depend on a network fetch at
consumer-verify time. This closes the TUF first-trust MITM threat.

This module lives on the SUBSTRATE-VERIFIER side. It is NOT stdlib-only — it
imports `python-tuf >= 6.0` + `cryptography`. The stdlib-only verifier path
lives at `veriker/cli/verify.py` and does NOT import this module; that two-verifier
boundary is deliberate.

Enforced TUF discipline:

  - Threshold ≥2-of-3 root signers
  - Root expiration ≤90d from issue date
  - Snapshot expiration ≤7d
  - Timestamp expiration ≤24h
  - Monotonic version checks; fail-CLOSED on version decrease
  - Consistent-snapshots invariant; fail-CLOSED on missing inclusion proof
  - Fulcio + CTFE + Rekor pubkeys live in a SEPARATE `sigstore-trust-root`
    TUF role with its own rotation cadence

Typed exceptions:

  TUFRootExpired                   — root.json expires before now()
  TUFRootSignatureThresholdNotMet  — fewer than threshold valid signatures
  TUFSnapshotStale                 — snapshot expiration past max-staleness
  TUFTimestampStale                — timestamp expiration past 24h
  TUFVersionRollback               — newer version on disk than what feed offers
  TUFConsistentSnapshotMissing     — consistent-snapshot pair absent from target
  TUFTargetUnknownPayloadType      — fetched target carries unrecognized payload_type
  TUFRootKeyPrivateMaterialOnDisk  — defensive check; private key bytes under _tuf_root/

The `audit_bundle/extensions/c18_verifier_identity.py` module catches these and
emits reason codes into the bundle event log.


"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Iterator
    # python-tuf APIs are imported lazily; see _import_python_tuf below


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

#: Default TUF feed URL (the actual hosting endpoint for v0.3 releases).
DEFAULT_TUF_FEED_URL = "https://manifest.vkernel.dev/v0.3.0"

#: Bundled root.json — embedded in the OCI image at compile time.
_EMBEDDED_ROOT_PATH = Path(__file__).parent / "_tuf_root" / "root.json"

#: Max-staleness windows. Bounds how stale fetched TUF metadata may be before
#: it is rejected (freeze-attack protection).
MAX_TIMESTAMP_STALENESS_HOURS = 24
MAX_SNAPSHOT_STALENESS_DAYS = 7
MAX_ROOT_EXPIRY_DAYS = 90

#: Minimum threshold for root signatures: require ≥2-of-3 so one compromised
#: root key cannot mint a valid root on its own.
MIN_ROOT_THRESHOLD = 2
MIN_ROOT_KEY_COUNT = 3

#: TUF role names. The `sigstore-trust-root` role is kept SEPARATE from the
#: release role so the two can rotate on independent cadences.
ROLE_VKERNEL_RELEASE = "vkernel-release"
ROLE_SIGSTORE_TRUST_ROOT = "sigstore-trust-root"
ROLE_PLUGIN_ALLOWLIST = "plugin-allowlist"
#: Verifier-side revocation-root role. SEPARATE from the C18 release role AND
#: the sigstore-trust-root role (its own rotation cadence). Signs the revocation
#: list consumed by audit_bundle/revocation.py via an injected resolver.
ROLE_REVOCATION_ROOT = "revocation-root"

#: payload_type declared by the C18 release-manifest target itself (the
#: image_digest pin list). Declared in the SIGNED targets metadata's `custom`
#: field, so it rides the TUF targets-role signature.
RELEASE_MANIFEST_PAYLOAD_TYPE = "application/vnd.nexi.vkernel.release-manifest"

#: Acceptable payload_type values — a fail-closed allowlist ENFORCED by
#: fetch_release_manifest: a target whose signed `custom.payload_type` is
#: unrecognized OR ABSENT is rejected (TUFTargetUnknownPayloadType) — absence
#: must not evade the gate.
ACCEPTABLE_PAYLOAD_TYPES = frozenset(
    {
        RELEASE_MANIFEST_PAYLOAD_TYPE,
        "application/vnd.in-toto+json",
        "application/vnd.cyclonedx+json",
        "application/vnd.spdx+json",
        "application/vnd.dev.sigstore.bundle+json",
        "application/vnd.slsa.provenance+json",
    }
)


# -----------------------------------------------------------------------------
# Typed exceptions (caught by c18_verifier_identity.py)
# -----------------------------------------------------------------------------


class TUFClientError(RuntimeError):
    """Base class for all C18 TUF-client errors."""


class TUFRootExpired(TUFClientError):
    """Bundled root.json has expired; the bundle cannot proceed without an
    out-of-band re-pin of a fresh root."""


class TUFRootSignatureThresholdNotMet(TUFClientError):
    """root.json carries fewer than `threshold` valid signatures; fail-CLOSED
    (threshold ≥2-of-3 always)."""


class TUFSnapshotStale(TUFClientError):
    """snapshot.json expiration is past MAX_SNAPSHOT_STALENESS_DAYS; fail-CLOSED
    (freeze-attack protection)."""


class TUFTimestampStale(TUFClientError):
    """timestamp.json expiration is past MAX_TIMESTAMP_STALENESS_HOURS;
    fail-CLOSED (freeze-attack protection)."""


class TUFVersionRollback(TUFClientError):
    """Feed offers a version-number LOWER than what the substrate has cached;
    fail-CLOSED (rollback protection)."""


class TUFConsistentSnapshotMissing(TUFClientError):
    """Consistent-snapshot pair absent from fetched target; fail-CLOSED."""


class TUFTargetUnknownPayloadType(TUFClientError):
    """Fetched target's payload_type is not in the fail-closed
    ACCEPTABLE_PAYLOAD_TYPES allowlist."""


class TUFRootKeyPrivateMaterialOnDisk(TUFClientError):
    """Defensive: a file under `_tuf_root/` looks like it contains an Ed25519
    or RSA PRIVATE key. The substrate ships only PUBLIC key material; this
    is a hard-stop for the bundle (commit reviewer error)."""


class TUFRoleSeparationViolation(TUFClientError):
    """The `sigstore-trust-root` role is supposed to be distinct from the
    C18 release role. This exception fires if a fetched metadata file
    conflates them."""


class TUFBootstrapPlaceholderPresent(TUFClientError):
    """A trust-loader was asked to load role material that still carries
    UNFILLED ceremony bootstrap state — an empty root signature (``sig == ""``)
    or a ``TBD-*`` placeholder value — without the caller opting into bootstrap
    mode. A real verifier MUST refuse unsigned / placeholder trust anchors;
    this fail-closed default keeps the protection always-on at the API
    boundary, not only in the release gate. Callers that genuinely need the
    raw bootstrap material (e.g. the v0.4 root-seed path) must call the
    explicitly-named ``*_bootstrap_unverified`` loaders in
    ``c18_tuf_bootstrap`` — which acknowledge in the call site that the
    material is NOT verified trust."""


# -----------------------------------------------------------------------------
# Bootstrap-placeholder fail-closed checks (shared by the trust-loaders)
# -----------------------------------------------------------------------------

#: An UNFILLED ceremony placeholder iff the whole string VALUE begins with the
#: TBD sentinel — bare or ``sha256:``-prefixed. Anchored at the start so honest
#: descriptive PROSE that merely names the sentinel mid-sentence does NOT trip
#: the check. Mirrors the release marker-gate's pattern exactly so the runtime
#: loader and the release gate agree on what "filled" means.
_PLACEHOLDER_VALUE_RE = re.compile(r"^(sha256:)?TBD")


def _iter_string_values(node: Any, path: str = "") -> "Iterator[tuple[str, str]]":
    """Yield (json_path, value) for every string VALUE in parsed JSON.

    Object KEYS are never yielded — only values — so a placeholder token in a
    key name or mid-sentence in prose cannot be mistaken for an unfilled field.
    """
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _iter_string_values(v, f"{path}.{k}" if path else str(k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _iter_string_values(v, f"{path}[{i}]")
    elif isinstance(node, str):
        yield path, node


def _assert_no_unfilled_placeholders(
    doc: dict[str, Any], source: Path, *, allow: bool
) -> None:
    """Fail closed if any VALUE in `doc` is an unfilled `TBD-*` ceremony
    placeholder, unless the caller explicitly opted into bootstrap mode."""
    if allow:
        return
    offenders = [
        f"{jpath}={value!r}"
        for jpath, value in _iter_string_values(doc)
        if _PLACEHOLDER_VALUE_RE.match(value)
    ]
    if offenders:
        raise TUFBootstrapPlaceholderPresent(
            f"{source.name} carries unfilled TBD-* ceremony placeholder(s) in "
            f"value position(s): {offenders}. The C18 key ceremony has not "
            "filled production values — refusing to treat this as verified "
            "trust material. Use the c18_tuf_bootstrap.*_bootstrap_unverified "
            "loaders ONLY for the documented v0.4 bootstrap/dev path."
        )


def _assert_root_signatures_filled(
    root_meta: dict[str, Any], source: Path, *, allow: bool
) -> None:
    """Fail closed if a root-role file carries an empty/absent signature set,
    unless the caller explicitly opted into bootstrap mode. This is the
    *presence* of a non-empty signature blob, NOT cryptographic verification
    (python-tuf performs the cryptographic check downstream); an empty `sig`
    means the key ceremony has not run at all."""
    if allow:
        return
    sigs = root_meta.get("signatures")
    if not sigs:
        raise TUFBootstrapPlaceholderPresent(
            f"{source.name} has no signatures block — the C18 key ceremony has "
            "not run. Use the c18_tuf_bootstrap.*_bootstrap_unverified loaders "
            "ONLY for the documented bootstrap-seed path."
        )
    empty = [
        i
        for i, sig in enumerate(sigs)
        if not (isinstance(sig, dict) and sig.get("sig"))
    ]
    if empty:
        raise TUFBootstrapPlaceholderPresent(
            f"{source.name} carries EMPTY root signature(s) at index {empty} — "
            "the C18 key ceremony has not run. Refusing an unsigned root. Use "
            "the c18_tuf_bootstrap.*_bootstrap_unverified loaders ONLY for the "
            "documented bootstrap-seed path."
        )


# -----------------------------------------------------------------------------
# python-tuf lazy import
# -----------------------------------------------------------------------------


def _import_python_tuf() -> dict[str, Any]:
    """Lazily import python-tuf to keep this module importable in stdlib-only
    environments (where the import would fail). Returns the necessary
    classes/functions. Raises ImportError with a clear remediation string
    if python-tuf is not installed.
    """
    try:
        from tuf.api.metadata import Metadata, Root, Snapshot, Targets, Timestamp  # type: ignore[import-not-found]
        from tuf.ngclient import Updater  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ImportError(
            "python-tuf >= 6.0 is required for the substrate verifier. "
            "Install via `pip install tuf>=6.0` or via the Nix flake's "
            "audit_bundle_deps. The offline-only veriker/cli/verify.py does NOT need "
            "python-tuf — use that path for a stdlib-only audit."
        ) from exc
    return {
        "Metadata": Metadata,
        "Root": Root,
        "Snapshot": Snapshot,
        "Targets": Targets,
        "Timestamp": Timestamp,
        "Updater": Updater,
    }


# -----------------------------------------------------------------------------
# Bundled root.json loader + defensive checks
# -----------------------------------------------------------------------------


def _load_bundled_root_impl(
    root_path: Path | None = None,
    *,
    allow_placeholders: bool,
) -> dict[str, Any]:
    """Shared core for :func:`load_bundled_root` (strict) and the bootstrap
    variant in ``c18_tuf_bootstrap``.

    ``allow_placeholders`` skips ONLY the two bootstrap fail-closed asserts
    (signature-blob presence + no unfilled ``TBD-*`` values); every other
    structural/defensive check below runs unconditionally. Production code MUST
    NOT call this directly — use the strict public :func:`load_bundled_root`.
    """
    path = root_path or _EMBEDDED_ROOT_PATH
    if not path.is_file():
        raise TUFClientError(
            f"Bundled TUF root.json missing at {path}. The OCI image build "
            "MUST embed the root.json into _tuf_root/ at compile time. "
            "Re-build the image."
        )

    _assert_no_private_key_material(path.parent)

    try:
        root_meta = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise TUFClientError(
            f"Bundled root.json at {path} is not valid JSON: {exc}"
        ) from exc

    _assert_root_threshold(root_meta)
    _assert_root_not_expired(root_meta)
    _assert_root_expiry_within_window(root_meta)
    _assert_root_signatures_filled(root_meta, path, allow=allow_placeholders)
    _assert_no_unfilled_placeholders(root_meta, path, allow=allow_placeholders)

    return root_meta


def load_bundled_root(root_path: Path | None = None) -> dict[str, Any]:
    """Load + STRUCTURALLY pre-check the bundled root.json (STRICT).

    ⚠️ This does NOT *cryptographically* verify the root — it does not check
    that ``signatures[]`` validate against the root keys (python-tuf performs
    that downstream when the caller drives the full protocol via
    fetch_release_manifest(), which seeds these bytes through
    ``Updater(bootstrap=...)``; ngclient then rejects an under-signed root). A
    successful return is NOT a cryptographic trust-anchor validation.

    Always fails closed: a root with EMPTY ``signatures[]`` (pre-ceremony
    bootstrap) or any ``TBD-*`` value is REJECTED with
    TUFBootstrapPlaceholderPresent. There is NO opt-out parameter on this
    production loader. The deliberately-unverified bootstrap-seed variant lives
    in ``c18_tuf_bootstrap.load_bundled_root_bootstrap_unverified`` (v0.4
    root-seed / dev path only).

    Structural/defensive pre-checks performed here:
      - File exists and is readable JSON
      - No private-key material under _tuf_root/ (TUFRootKeyPrivateMaterialOnDisk)
      - root role DECLARES threshold ≥2-of-3 with that many resolvable keyids
        (a declaration check — NOT a count of valid signatures)
      - Expiration present, not past, and ≤ MAX_ROOT_EXPIRY_DAYS out
      - Non-empty signature blobs present and no TBD-* placeholder values
    """
    return _load_bundled_root_impl(root_path, allow_placeholders=False)


def _assert_no_private_key_material(tuf_root_dir: Path) -> None:
    """Scan _tuf_root/ for anything that looks like private key material.

    Defensive: private-half key material MUST never be committed under
    _tuf_root/ (the substrate ships only PUBLIC keys).
    """
    private_key_markers = (
        b"BEGIN PRIVATE KEY",
        b"BEGIN ENCRYPTED PRIVATE KEY",
        b"BEGIN RSA PRIVATE KEY",
        b"BEGIN EC PRIVATE KEY",
        b"BEGIN OPENSSH PRIVATE KEY",
        b"BEGIN ED25519 PRIVATE KEY",
    )
    for child in tuf_root_dir.rglob("*"):
        if not child.is_file():
            continue
        try:
            head = child.read_bytes()[:4096]
        except OSError:
            continue
        for marker in private_key_markers:
            if marker in head:
                raise TUFRootKeyPrivateMaterialOnDisk(
                    f"File {child} appears to contain {marker.decode()} — "
                    "PRIVATE key material MUST NOT be committed under "
                    "audit_bundle/extensions/_tuf_root/. Remove it before "
                    "committing. The substrate ships only PUBLIC keys."
                )


def _assert_root_threshold(root_meta: dict[str, Any]) -> None:
    """Assert the root role DECLARES threshold ≥2-of-3.

    Structural only: checks the declared threshold integer, the keyid count, and
    that each keyid resolves into signed.keys. It does NOT count or verify the
    cryptographic signatures in root_meta["signatures"] — that is python-tuf's
    job downstream (see load_bundled_root). A root with empty signatures passes
    this check.
    """
    signed = root_meta.get("signed", {})
    roles = signed.get("roles", {})
    keys = signed.get("keys", {})
    root_role = roles.get("root")
    if not isinstance(root_role, dict):
        raise TUFRootSignatureThresholdNotMet(
            "root.json missing roles.root — cannot validate threshold."
        )
    threshold = root_role.get("threshold", 0)
    keyids = root_role.get("keyids", [])
    if not isinstance(threshold, int) or threshold < MIN_ROOT_THRESHOLD:
        raise TUFRootSignatureThresholdNotMet(
            f"root role threshold = {threshold!r}; minimum required = "
            f"{MIN_ROOT_THRESHOLD}."
        )
    if not isinstance(keyids, list) or len(keyids) < MIN_ROOT_KEY_COUNT:
        raise TUFRootSignatureThresholdNotMet(
            f"root role has {len(keyids)} keyids; minimum required = "
            f"{MIN_ROOT_KEY_COUNT}."
        )
    # Each keyid must resolve to a key in `signed.keys`.
    for keyid in keyids:
        if keyid not in keys:
            raise TUFRootSignatureThresholdNotMet(
                f"keyid {keyid} referenced by root role is missing from "
                "signed.keys map — malformed root.json."
            )


def _assert_root_not_expired(root_meta: dict[str, Any]) -> None:
    """Fail-CLOSED if bundled root.json has already expired.

    Wall-clock BY DESIGN (uninjected, unrecorded): this is the verifier's own
    supply-chain freshness check, not a verdict surface — the question is "is
    this root fresh NOW", and python-tuf's authoritative protocol checks
    downstream use the host clock with no injection seam, so injecting only
    this pre-check would split the clock within one validation pass. See
    SECURITY.md "Clocks and determinism (replay map)"."""
    expires_str = root_meta.get("signed", {}).get("expires")
    if not expires_str:
        raise TUFRootExpired("root.json missing signed.expires field.")
    try:
        expires = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TUFRootExpired(
            f"root.json signed.expires {expires_str!r} not ISO 8601: {exc}"
        ) from exc
    if expires <= datetime.now(timezone.utc):
        raise TUFRootExpired(
            f"Bundled root.json expired at {expires.isoformat()}. An "
            "out-of-band re-pin of a fresh root is required."
        )


def _assert_root_expiry_within_window(root_meta: dict[str, Any]) -> None:
    """Fail-CLOSED if root expiration is MORE than MAX_ROOT_EXPIRY_DAYS out.

    A too-long expiry weakens the rotation discipline, so root expiration is
    capped at MAX_ROOT_EXPIRY_DAYS (90d). The cap is on expiry-minus-issue-time;
    for v0.3 we approximate by asserting expiry ≤ now + 90d at load time.

    Wall-clock BY DESIGN — same posture as _assert_root_not_expired (supply-
    chain freshness, not a verdict surface; see SECURITY.md "Clocks and
    determinism (replay map)"). This cap is rotation hygiene, not a trust gate.
    """
    expires_str = root_meta["signed"]["expires"]
    expires = datetime.fromisoformat(expires_str.replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    days_to_expiry = (expires - now).days
    if days_to_expiry > MAX_ROOT_EXPIRY_DAYS:
        raise TUFRootExpired(
            f"Bundled root.json expires {days_to_expiry}d from now — exceeds "
            f"the {MAX_ROOT_EXPIRY_DAYS}d cap. Re-issue with a shorter expiration."
        )


# -----------------------------------------------------------------------------
# TUF feed update + role-scoped target fetch
# -----------------------------------------------------------------------------


def _target_payload_type(target_info) -> str | None:
    """Extract the signed `custom.payload_type` from a python-tuf TargetFile.

    python-tuf parses length+hashes as first-class fields; the TUF-spec
    `custom` object lands in `unrecognized_fields` (older releases) or a
    `custom` attribute (newer). Returns None when absent/malformed — the
    caller treats None as unknown (fail-closed).
    """
    custom = getattr(target_info, "custom", None)
    if custom is None:
        unrec = getattr(target_info, "unrecognized_fields", None) or {}
        custom = unrec.get("custom")
    if not isinstance(custom, dict):
        return None
    pt = custom.get("payload_type")
    return pt if isinstance(pt, str) else None


def fetch_release_manifest(
    *,
    release_version: str,
    feed_url: str = DEFAULT_TUF_FEED_URL,
    trust_dir: Path | None = None,
    allow_ephemeral_trust_dir: bool = False,
) -> dict[str, Any]:
    """Fetch the C18 release manifest from the TUF feed.

    Uses python-tuf's `ngclient.Updater` for full TUF protocol enforcement
    (consistent snapshots; ≤24h timestamp; ≤7d snapshot; monotonic version;
    threshold ≥2-of-3 root signatures). Returns the parsed target file
    contents.

    `trust_dir` MUST be a PERSISTENT directory: TUF rollback/freeze protection
    depends on persisting the last-seen timestamp/snapshot/targets versions
    across invocations. A fresh ephemeral dir per call cannot detect a rollback
    to a previously-valid (older, still-signed) version.
    If `trust_dir is None` the call FAILS CLOSED unless
    `allow_ephemeral_trust_dir=True` is set explicitly (one-shot / test use only,
    where rollback protection is knowingly not required).

    Raises TUFRootExpired / TUFSnapshotStale / TUFTimestampStale /
    TUFVersionRollback / TUFConsistentSnapshotMissing as appropriate.
    """
    tuf = _import_python_tuf()

    # Bundled root.json — embedded at compile time. These bytes are the pinned
    # trust anchor passed to ngclient as `bootstrap` (see below).
    bundled_root = load_bundled_root()
    bundled_root_bytes = json.dumps(bundled_root).encode("utf-8")

    # Fail closed on a missing trust dir: an ephemeral per-call dir silently
    # disables rollback/freeze protection.
    if trust_dir is None:
        if not allow_ephemeral_trust_dir:
            raise TUFClientError(
                "fetch_release_manifest requires a PERSISTENT trust_dir: TUF "
                "rollback/freeze protection depends on persisting last-seen "
                "metadata versions across calls. A fresh dir per call cannot "
                "detect rollback to an older, still-validly-signed version. "
                "Pass trust_dir=<stable path> (e.g. host_digest_verify's "
                "--tuf-trust-bundle), or set allow_ephemeral_trust_dir=True ONLY "
                "for one-shot/test use where rollback protection is not required."
            )
        from tempfile import mkdtemp

        trust_dir = Path(mkdtemp(prefix="vkernel_tuf_"))

    metadata_dir = trust_dir / "metadata"
    targets_dir = trust_dir / "targets"
    metadata_dir.mkdir(parents=True, exist_ok=True)
    targets_dir.mkdir(parents=True, exist_ok=True)

    # Seed the trust dir with bundled root.json (back-compat with tuf<7 layout).
    (metadata_dir / "root.json").write_bytes(bundled_root_bytes)

    try:
        # `bootstrap=` MUST be passed by keyword: it is optional in tuf 6.x but a
        # REQUIRED keyword-only argument in tuf 7.0+. Passing it satisfies the
        # whole declared `tuf>=6.0` range. Omitting it raised TypeError on 7.0,
        # which fail-closed every fetch and meant ngclient's protocol checks
        # (rollback / threshold-on-rotation / consistent-snapshot) never ran.
        #
        updater = tuf["Updater"](
            metadata_dir=str(metadata_dir),
            metadata_base_url=f"{feed_url}/metadata",
            target_dir=str(targets_dir),
            target_base_url=f"{feed_url}/targets",
            bootstrap=bundled_root_bytes,
        )
        updater.refresh()
    except Exception as exc:  # python-tuf raises a wide variety of exceptions
        # Translate python-tuf's exceptions into our typed surface.
        msg = str(exc).lower()
        if "expired" in msg and "snapshot" in msg:
            raise TUFSnapshotStale(str(exc)) from exc
        if "expired" in msg and "timestamp" in msg:
            raise TUFTimestampStale(str(exc)) from exc
        if "expired" in msg and "root" in msg:
            raise TUFRootExpired(str(exc)) from exc
        if "version" in msg and ("rollback" in msg or "decrease" in msg):
            raise TUFVersionRollback(str(exc)) from exc
        if "consistent" in msg and "snapshot" in msg:
            raise TUFConsistentSnapshotMissing(str(exc)) from exc
        raise TUFClientError(f"TUF refresh failed: {exc}") from exc

    target_name = f"{ROLE_VKERNEL_RELEASE}/{release_version}/MANIFEST.txt"
    target_info = updater.get_targetinfo(target_name)
    if target_info is None:
        raise TUFConsistentSnapshotMissing(
            f"Release target {target_name!r} not in TUF feed at {feed_url}. "
            "Either the release has not yet landed or the feed is split-viewed."
        )

    # Fail-closed payload_type allowlist — previously documented but never
    # enforced. The value rides the SIGNED targets metadata (`custom` field),
    # so python-tuf has already authenticated it by the time we read it.
    # Absent counts as unknown: omission must not evade the gate.
    payload_type = _target_payload_type(target_info)
    if payload_type not in ACCEPTABLE_PAYLOAD_TYPES:
        raise TUFTargetUnknownPayloadType(
            f"Release target {target_name!r} declares payload_type="
            f"{payload_type!r}; not in the fail-closed allowlist "
            f"{sorted(ACCEPTABLE_PAYLOAD_TYPES)}. Targets MUST declare an "
            "acceptable custom.payload_type in the signed targets metadata."
        )

    cached_path = updater.download_target(target_info)
    return {
        "target_name": target_name,
        "target_path": cached_path,
        "target_info": {
            "length": target_info.length,
            "hashes": dict(target_info.hashes),
        },
        "feed_url": feed_url,
        "release_version": release_version,
    }


# -----------------------------------------------------------------------------
# Separate-role fetchers (each role rotates on its own cadence)
# -----------------------------------------------------------------------------


_BUNDLED_SIGSTORE_TRUST_ROOT_PATH = (
    Path(__file__).parent / "_tuf_root" / "sigstore_trust_root.json"
)
_BUNDLED_PLUGIN_ALLOWLIST_PATH = (
    Path(__file__).parent / "_tuf_root" / "plugin_allowlist.json"
)
_BUNDLED_REVOCATION_ROOT_PATH = (
    Path(__file__).parent / "_tuf_root" / "revocation_root.json"
)


def _fetch_sigstore_trust_root_impl(
    bundled_path: Path | None = None,
    *,
    allow_placeholders: bool,
) -> dict[str, Any]:
    """Shared core for :func:`fetch_sigstore_trust_root` (strict) and the
    bootstrap variant in ``c18_tuf_bootstrap``.

    ``allow_placeholders`` skips ONLY the unfilled-``TBD-*`` fail-closed assert;
    the role-separation + required-targets checks run unconditionally.
    Production code MUST NOT call this directly — use the strict public wrapper.
    """
    path = bundled_path or _BUNDLED_SIGSTORE_TRUST_ROOT_PATH
    if not path.is_file():
        raise TUFClientError(
            f"sigstore-trust-root role file missing at {path}. The OCI image "
            "build MUST embed this at compile time."
        )
    try:
        role = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise TUFClientError(
            f"sigstore-trust-root role file at {path} is not valid JSON: {exc}"
        ) from exc
    role_name = role.get("role_name")
    if role_name != ROLE_SIGSTORE_TRUST_ROOT:
        raise TUFRoleSeparationViolation(
            f"sigstore-trust-root file declares role_name={role_name!r}; "
            f"expected {ROLE_SIGSTORE_TRUST_ROOT!r}. Role separation "
            "broken — refusing to proceed."
        )
    targets = role.get("targets", {})
    required = {"fulcio.pub", "ctfe.pub", "rekor.pub", "sigstore_root_threshold.json"}
    missing = required - set(targets.keys())
    if missing:
        raise TUFClientError(
            f"sigstore-trust-root missing required targets: {missing}. "
            "The role MUST enumerate Fulcio + CTFE + Rekor pubkeys plus the "
            "rotation-policy doc."
        )
    _assert_no_unfilled_placeholders(role, path, allow=allow_placeholders)
    return role


def fetch_sigstore_trust_root(
    bundled_path: Path | None = None,
) -> dict[str, Any]:
    """Load the bundled `sigstore-trust-root` role file (STRICT).

    This role is SEPARATE from the C18 release role, with a distinct rotation
    cadence (Sigstore key-rotation announcements vs C18 release cuts). A role
    separation violation raises `TUFRoleSeparationViolation`.

    At v0.3 the consumer reads the BUNDLED role file (embedded into the
    OCI image at compile time). When v0.4 lands the TUF feed-fetch path,
    this function will route through `python-tuf`'s ngclient.Updater
    against the `sigstore-trust-root` role's separate metadata file at
    `manifest.vkernel.dev/sigstore-trust-root/`.

    Always fails closed: a role file carrying any ``TBD-*`` ceremony placeholder
    value (e.g. unfilled ``expected_sha256_at_v0_3_cut``) is REJECTED with
    TUFBootstrapPlaceholderPresent. There is NO opt-out parameter here. The
    deliberately-unverified bootstrap variant lives in
    ``c18_tuf_bootstrap.fetch_sigstore_trust_root_bootstrap_unverified``.
    """
    return _fetch_sigstore_trust_root_impl(bundled_path, allow_placeholders=False)


def _fetch_plugin_allowlist_impl(
    bundled_path: Path | None = None,
    *,
    allow_placeholders: bool,
) -> dict[str, Any]:
    """Shared core for :func:`fetch_plugin_allowlist` (strict) and the bootstrap
    variant in ``c18_tuf_bootstrap``.

    ``allow_placeholders`` skips ONLY the unfilled-``TBD-*`` fail-closed assert;
    the role-separation + registry-allowlist + required-fields checks run
    unconditionally. Production code MUST NOT call this directly — use the strict
    public wrapper.
    """
    path = bundled_path or _BUNDLED_PLUGIN_ALLOWLIST_PATH
    if not path.is_file():
        raise TUFClientError(
            f"plugin-allowlist role file missing at {path}. The OCI image "
            "build MUST embed this at compile time."
        )
    try:
        role = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise TUFClientError(
            f"plugin-allowlist role file at {path} is not valid JSON: {exc}"
        ) from exc

    role_name = role.get("role_name")
    if role_name != ROLE_PLUGIN_ALLOWLIST:
        raise TUFRoleSeparationViolation(
            f"plugin-allowlist file declares role_name={role_name!r}; "
            f"expected {ROLE_PLUGIN_ALLOWLIST!r}."
        )

    registry_allowlist = role.get("registry_org_allowlist", [])
    if registry_allowlist != ["ghcr.io/veriker/"]:
        raise TUFRoleSeparationViolation(
            f"plugin-allowlist registry_org_allowlist = {registry_allowlist!r}; "
            "expected exactly ['ghcr.io/veriker/']. Cross-registry plugin "
            "loading requires a separate posture decision."
        )

    entries = role.get("entries", {})
    required_fields = {
        "oci_artifact",
        "oci_digest_at_v0_3_cut",
        "cosign_cert_identity",
        "slsa_provenance_digest_at_v0_3_cut",
    }
    for name, entry in entries.items():
        if not isinstance(entry, dict):
            raise TUFClientError(
                f"plugin-allowlist entry {name!r} malformed (not a dict)"
            )
        missing = required_fields - set(entry.keys())
        if missing:
            raise TUFClientError(
                f"plugin-allowlist entry {name!r} missing fields: {missing}. "
                "Each plugin MUST enumerate (oci_artifact, oci_digest, "
                "cosign_cert_identity, slsa_provenance_digest)."
            )
    _assert_no_unfilled_placeholders(role, path, allow=allow_placeholders)
    return role


def fetch_plugin_allowlist(
    bundled_path: Path | None = None,
) -> dict[str, Any]:
    """Load the bundled `plugin-allowlist` role file (STRICT).

    Every plugin loaded by the substrate verifier MUST appear in this
    TUF-distributed allowlist by OCI digest. The c18_plugin_oci_loader.py
    module consumes this file.

    Defensive checks:
      - registry_org_allowlist contains exactly `ghcr.io/veriker/`
        (TUFRoleSeparationViolation otherwise — cross-registry plugin loading
        is a separate posture decision)
      - Each entry carries oci_artifact + oci_digest_at_v0_3_cut +
        cosign_cert_identity + slsa_provenance_digest_at_v0_3_cut

    Always fails closed: an allowlist carrying any ``TBD-*`` ceremony placeholder
    (e.g. an unfilled ``oci_digest_at_v0_3_cut``) is REJECTED with
    TUFBootstrapPlaceholderPresent — loading plugins against a placeholder digest
    would pin nothing. There is NO opt-out parameter here. The
    deliberately-unverified bootstrap variant lives in
    ``c18_tuf_bootstrap.fetch_plugin_allowlist_bootstrap_unverified``.
    """
    return _fetch_plugin_allowlist_impl(bundled_path, allow_placeholders=False)


def _fetch_revocation_root_impl(
    bundled_path: Path | None = None,
    *,
    allow_placeholders: bool,
) -> dict[str, Any]:
    """Shared core for :func:`fetch_revocation_root` (strict) and the bootstrap
    variant in ``c18_tuf_bootstrap``.

    ``allow_placeholders`` skips ONLY the two bootstrap fail-closed asserts
    (signature-blob presence + no unfilled ``TBD-*`` values); the role-name,
    2-of-3 threshold, Ed25519-keyid, rotation-policy, and expiry checks run
    unconditionally. Production code MUST NOT call this directly — use the strict
    public wrapper.
    """
    path = bundled_path or _BUNDLED_REVOCATION_ROOT_PATH
    if not path.is_file():
        raise TUFClientError(
            f"revocation-root role file missing at {path}. The OCI image build "
            "MUST embed this at compile time (pyproject package-data)."
        )
    try:
        role = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise TUFClientError(
            f"revocation-root role file at {path} is not valid JSON: {exc}"
        ) from exc

    role_name = role.get("role_name")
    if role_name != ROLE_REVOCATION_ROOT:
        raise TUFRoleSeparationViolation(
            f"revocation-root file declares role_name={role_name!r}; "
            f"expected {ROLE_REVOCATION_ROOT!r}. Role separation broken — "
            "refusing to proceed."
        )

    signed = role.get("signed")
    if not isinstance(signed, dict):
        raise TUFClientError("revocation-root file missing a `signed` object.")
    rr = signed.get("roles", {}).get(ROLE_REVOCATION_ROOT)
    if not isinstance(rr, dict):
        raise TUFClientError(
            f"revocation-root file missing signed.roles[{ROLE_REVOCATION_ROOT!r}]."
        )
    if rr.get("threshold") != 2:
        raise TUFClientError(
            f"revocation-root threshold={rr.get('threshold')!r}; must be 2 "
            "(2-of-3 distinct approvers per C18 root discipline)."
        )
    keyids = rr.get("keyids", [])
    if len(keyids) != 3 or len(set(keyids)) != 3:
        raise TUFClientError(
            f"revocation-root must enumerate exactly 3 distinct keyids; got {keyids!r}."
        )
    keys = signed.get("keys", {})
    for kid in keyids:
        key = keys.get(kid)
        if not isinstance(key, dict):
            raise TUFClientError(
                f"revocation-root keyid {kid!r} not under signed.keys."
            )
        if key.get("keytype") != "ed25519":
            raise TUFClientError(
                f"revocation-root keyid {kid!r} keytype={key.get('keytype')!r}; "
                "expected 'ed25519'."
            )
        pub = key.get("keyval", {}).get("public", "")
        if len(pub) != 64:
            raise TUFClientError(
                f"revocation-root keyid {kid!r} public is {len(pub)} hex chars, "
                "expected 64 (Ed25519 raw 32-byte)."
            )
        try:
            int(pub, 16)
        except ValueError as exc:
            raise TUFClientError(
                f"revocation-root keyid {kid!r} public is not valid hex."
            ) from exc

    rotation = role.get("rotation_policy", {})
    max_days = rotation.get("max_validity_days")
    if not isinstance(max_days, int) or max_days > 90:
        raise TUFClientError(
            f"revocation-root rotation_policy.max_validity_days={max_days!r}; "
            "must be an int <= 90 (mirrors C18 release-root rotation discipline)."
        )
    expires = signed.get("expires")
    if not isinstance(expires, str):
        raise TUFClientError("revocation-root signed.expires missing or not a string.")
    try:
        datetime.fromisoformat(expires.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TUFClientError(
            f"revocation-root signed.expires={expires!r} is not ISO-8601."
        ) from exc

    _assert_root_signatures_filled(role, path, allow=allow_placeholders)
    _assert_no_unfilled_placeholders(role, path, allow=allow_placeholders)

    return role


def fetch_revocation_root(
    bundled_path: Path | None = None,
) -> dict[str, Any]:
    """Load + structurally validate the bundled `revocation-root` role file (STRICT).

    Mirrors :func:`fetch_sigstore_trust_root`: at v0.3/v0.4 the consumer reads
    the BUNDLED role file (embedded into the OCI image at compile time via
    pyproject package-data `audit_bundle.extensions = ["_tuf_root/*.json"]`);
    when the TUF feed-fetch path lands this routes through python-tuf against
    the `revocation-root` role's separate metadata at
    `manifest.vkernel.dev/revocation-root/`.

    This role is SEPARATE from the C18 release role AND the sigstore-trust-root
    role — distinct rotation cadence (re-pinned on revocation-key rotation, not
    coupled to C18 release cuts). The root pubkey is the trust anchor for the
    verifier-side revocation list consumed by audit_bundle/revocation.py via an
    INJECTED resolver; the is_revoked logic stays independent of this artifact
    (injected resolver + fixture root). This fetcher makes the embedded
    production distribution LOAD-BEARING: a consumer can resolve the
    revocation-root via the same pattern as the sigstore-trust-root.

    Structural discipline: role_name == 'revocation-root', 2-of-3 threshold over
    exactly 3 distinct Ed25519 keyids enumerated under signed.keys,
    rotation_policy.max_validity_days <= 90, ISO-8601 expiry.

    Always fails closed: an empty signature set (pre-ceremony bootstrap) or any
    ``TBD-*`` placeholder value is REJECTED with TUFBootstrapPlaceholderPresent.
    There is NO opt-out parameter here. The deliberately-unverified bootstrap
    variant lives in
    ``c18_tuf_bootstrap.fetch_revocation_root_bootstrap_unverified``.
    """
    return _fetch_revocation_root_impl(bundled_path, allow_placeholders=False)


# -----------------------------------------------------------------------------
# Public surface
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
# STH-gossip cross-check (Rekor split-view detection)
# -----------------------------------------------------------------------------


REASON_STH_GOSSIP_SIGNATURE_INVALID = "STH_GOSSIP_SIGNATURE_INVALID"
REASON_STH_GOSSIP_CONSISTENCY_PROOF_FAILED = "STH_GOSSIP_CONSISTENCY_PROOF_FAILED"
REASON_STH_GOSSIP_INCLUSION_PROOF_DIVERGES = (
    "STH_GOSSIP_INCLUSION_PROOF_DIVERGES_FROM_GOSSIPED_STH"
)


class SthGossipResult(NamedTuple):
    """Outcome of :func:`check_sth_gossip_structure`.

    ``reasons`` lists the structural divergences detected (empty == none found).
    ``cryptographically_verified`` reports whether the STH's signature was
    actually verified against a pinned key. At v0.3 this is ALWAYS ``False``:
    no signature, witness co-signature, or RFC-6962 consistency-proof
    verification is performed (see the function docstring). An empty
    ``reasons`` with ``cryptographically_verified is False`` therefore means
    "no structural divergence detected" — it does NOT mean the STH was
    verified. Callers must not treat that state as a cryptographic PASS.
    """

    reasons: list[str]
    cryptographically_verified: bool


def check_sth_gossip_structure(
    sth_json: dict,
    rekor_inclusion_proof: dict,
) -> SthGossipResult:
    """Structural pre-check of a gossiped STH against a Rekor inclusion proof.

    NOTE: this is deliberately named ``check_..._structure``, not ``verify_*``.
    It performs structural/shape comparison only and does NOT cryptographically
    verify anything at v0.3 (see below). The ``verify_*`` name is reserved for
    the future witness-key verification path.

    Intended end-state: detect a Rekor split-view (the log serving different
    states to the bundle producer and to a monitor) by cryptographically
    verifying a witness-co-signed STH against a pinned witness key.

    THIS v0.3 IMPLEMENTATION DOES NOT DO THAT. It performs only structural /
    shape comparisons and explicitly does NOT perform any cryptographic
    verification. Specifically, at v0.3 this function does NOT:
      - verify the STH ``signature`` against any key (it only checks that a
        signature field is present — the byte value is never inspected);
      - verify a witness/monitor co-signature against a pinned witness key
        (no witness key is pinned yet — that is v0.4 work, gated on
        second-monitor outreach + a pinned Cloudflare-monitor witness key);
      - verify an RFC-6962 consistency proof (the ``consistency_proof`` field,
        when present, is only shape-checked).

    What it DOES check (structural only, and only when a non-empty
    ``rekor_inclusion_proof`` is supplied):
      - ``sth_json`` carries a ``signed_tree_head``/``sth`` object with
        ``tree_size`` and ``root_hash``, and a ``signature`` field is present;
      - the STH ``tree_size`` is not OLDER than the inclusion-proof tree_size
        (an older STH is a split-view signal → INCLUSION_PROOF_DIVERGES);
      - at equal tree sizes, the ``root_hash`` values match
        (mismatch → CONSISTENCY_PROOF_FAILED);
      - the ``consistency_proof`` field, if present, is well-formed.

    Returns an :class:`SthGossipResult`. ``cryptographically_verified`` is
    always ``False`` until the witness-key verification path lands (v0.4); an
    empty ``reasons`` means only that no structural divergence was found, NOT
    that the STH was verified. Callers must surface the unverified status to
    the user and must not report a cryptographic PASS on this result.
    """
    reasons: list[str] = []
    # No cryptographic verification path is wired at v0.3 — see docstring.
    cryptographically_verified = False

    sth = sth_json.get("signed_tree_head") or sth_json.get("sth") or sth_json
    if not isinstance(sth, dict):
        return SthGossipResult(
            [REASON_STH_GOSSIP_SIGNATURE_INVALID], cryptographically_verified
        )

    required = ("tree_size", "root_hash")
    for k in required:
        if k not in sth:
            reasons.append(REASON_STH_GOSSIP_SIGNATURE_INVALID)
            return SthGossipResult(reasons, cryptographically_verified)

    # Signature PRESENCE check only — the signature bytes are never verified
    # against a key at v0.3 (see docstring). A present-but-bogus signature
    # passes this shape check; that is why an empty reason-set is NOT a
    # cryptographic PASS.
    if "signature" not in sth and "signed_signature" not in sth:
        reasons.append(REASON_STH_GOSSIP_SIGNATURE_INVALID)

    if not rekor_inclusion_proof:
        # Empty inclusion proof — caller passed the STH alone; no structural
        # cross-check is possible. Return the presence-check result as-is.
        return SthGossipResult(reasons, cryptographically_verified)

    sth_tree_size = sth.get("tree_size")
    proof_tree_size = rekor_inclusion_proof.get("tree_size")
    if not isinstance(sth_tree_size, int) or not isinstance(proof_tree_size, int):
        reasons.append(REASON_STH_GOSSIP_INCLUSION_PROOF_DIVERGES)
        return SthGossipResult(reasons, cryptographically_verified)

    if sth_tree_size < proof_tree_size:
        # The gossiped STH is OLDER than the inclusion proof — Rekor served a
        # newer log state to the bundle producer than to the monitor. Split-
        # view attack signal.
        reasons.append(REASON_STH_GOSSIP_INCLUSION_PROOF_DIVERGES)

    # Consistency proof structural check (when present).
    consistency = sth.get("consistency_proof")
    if sth_tree_size == proof_tree_size:
        # Degenerate case — same tree size; root hashes must match.
        if sth.get("root_hash") != rekor_inclusion_proof.get("root_hash"):
            reasons.append(REASON_STH_GOSSIP_CONSISTENCY_PROOF_FAILED)
    elif consistency is not None:
        if not isinstance(consistency, list) or not all(
            isinstance(h, str) for h in consistency
        ):
            reasons.append(REASON_STH_GOSSIP_CONSISTENCY_PROOF_FAILED)

    return SthGossipResult(reasons, cryptographically_verified)


__all__ = [
    "ACCEPTABLE_PAYLOAD_TYPES",
    "DEFAULT_TUF_FEED_URL",
    "MAX_ROOT_EXPIRY_DAYS",
    "RELEASE_MANIFEST_PAYLOAD_TYPE",
    "MAX_SNAPSHOT_STALENESS_DAYS",
    "MAX_TIMESTAMP_STALENESS_HOURS",
    "MIN_ROOT_KEY_COUNT",
    "MIN_ROOT_THRESHOLD",
    "REASON_STH_GOSSIP_CONSISTENCY_PROOF_FAILED",
    "REASON_STH_GOSSIP_INCLUSION_PROOF_DIVERGES",
    "REASON_STH_GOSSIP_SIGNATURE_INVALID",
    "ROLE_PLUGIN_ALLOWLIST",
    "ROLE_REVOCATION_ROOT",
    "ROLE_SIGSTORE_TRUST_ROOT",
    "ROLE_VKERNEL_RELEASE",
    "SthGossipResult",
    "TUFBootstrapPlaceholderPresent",
    "TUFClientError",
    "TUFConsistentSnapshotMissing",
    "TUFRoleSeparationViolation",
    "TUFRootExpired",
    "TUFRootKeyPrivateMaterialOnDisk",
    "TUFRootSignatureThresholdNotMet",
    "TUFSnapshotStale",
    "TUFTargetUnknownPayloadType",
    "TUFTimestampStale",
    "TUFVersionRollback",
    "check_sth_gossip_structure",
    "fetch_plugin_allowlist",
    "fetch_release_manifest",
    "fetch_revocation_root",
    "fetch_sigstore_trust_root",
    "load_bundled_root",
]
