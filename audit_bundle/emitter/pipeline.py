"""audit_bundle/emitter/pipeline.py — the one reference-emitter pipeline.

Every per-pilot _build_bundle.py hand-rolls the same skeleton: scaffold dirs,
write deterministic content while accumulating sha256 digests, assemble a
manifest dict with the fixed top-level keys, and write manifest.json. This
module is that skeleton, extracted once. A pilot becomes a thin caller that
supplies only what VARIES — its content bytes, typed_checks, and (for the
higher-assurance families) the three hook implementations.

Design notes
------------
* Integrity rests on the per-file sha256 digests recorded in manifest.files /
  manifest.spec_files, NOT on the byte layout of manifest.json itself (the
  manifest cannot hash itself; the orchestrator re-canonicalizes it anyway).
  So write_bundle emits a single canonical manifest form and the conformance
  bar is "veriker/cli/verify.py passes", not byte-identity with a pilot's old
  hand-written manifest.
* Hooks default to the stdlib production-standard set (StaticTimestampProvider,
  NullCausalChainEmitter, NullAttestationProvider) so a trivial pilot calls
  write_bundle(out_dir, content) with no hook arguments at all.
* A deployment needing a stronger witness on any seam (e.g. an RFC 3161 TSA +
  Roughtime quorum + BLS timestamp, a cross-host causal chain, or TEE
  attestation) injects its own implementation at the call site — it satisfies
  the same hook Protocols, and this package imports none of them. The defaults
  are a working baseline, not a ceiling. See hooks.py.
* Optional DSSE sealing: pass ``dsse_signing_key`` to emit a ``bundle.dsse.json``
  sidecar alongside the manifest. The sidecar is opt-in — existing callers that
  pass no key are completely unaffected and manifest.json bytes remain identical.
  The seal path imports ``sign_envelope`` / ``rfc8785`` lazily (inside the
  ``if dsse_signing_key is not None`` block) so the default path stays
  import-light. The seal path does NOT import ``audit_bundle.emitter_premium``
  (OSS boundary preserved).

Stdlib-only on the default path — no third-party deps, so the open SDK keeps
the offline-auditor posture. The opt-in paths (dsse_signing_key, validate)
lazily pull the seal/verifier/plugin stack; validate=True imports veriker.cli.verify
for the canonical default plugin set so the self-check runs the verifier's
exact orchestration.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit_bundle.emitter.hooks import (
    AttestationProvider,
    CausalChainEmitter,
    NullAttestationProvider,
    NullCausalChainEmitter,
    StaticTimestampProvider,
    TimestampProvider,
)
from audit_bundle.integrity_ownership import (
    UnsafeBundleRelPath,
    require_canonical_rel_path,
)

_DEFAULT_SCHEMA_VERSION = "vcp-v1.1-canary4"


class BundleSelfCheckFailed(Exception):
    """Raised by write_bundle(validate=True) when the emitted bundle does not
    pass the verifier's own orchestration (BundleVerifier.verify with the CLI's
    default plugin set). The message carries the verdict state and every reason."""


def sha256(data: bytes) -> str:
    """The universal digest helper every builder defines as `_sha256`."""
    return hashlib.sha256(data).hexdigest()


@dataclass
class BundleContent:
    """What a pilot supplies to write_bundle — the part that VARIES per pilot.

    files       : bundle-relative path -> bytes for every non-spec artifact
                  (e.g. "data/dataset.jsonl", "payload/release.json",
                  "proofs/x.smt2"). Written verbatim; digest recorded in
                  manifest.files under the same key. Keys must be canonical
                  relative POSIX paths (see require_canonical_rel_path) and
                  may not name manifest.json / bundle.dsse.json — write_bundle
                  rejects violations fail-closed before writing anything.
    spec_files  : path-relative-to-spec/ -> bytes for pinned spec documents
                  (e.g. "withholding_schedule.json" -> bytes written under
                  spec/). Digest recorded in manifest.spec_files. Same
                  canonical-form discipline as files keys (envelope names are
                  permitted here — they are ordinary doc names under spec/).
    typed_checks: registered TypedCheck plugin names to enable.
    cross_refs / payload : pass-through manifest maps (usually {}).
    extra_manifest_fields: any additional top-level manifest keys this pilot
                  carries that are not produced by a hook — e.g. fragment_anchors,
                  snapshots, snapshot_policy, source_attributes, per_output_manifests.
                  Merged into the manifest last.
    """

    bundle_id: str
    created_at: str
    files: dict[str, bytes] = field(default_factory=dict)
    spec_files: dict[str, bytes] = field(default_factory=dict)
    typed_checks: list[str] = field(default_factory=list)
    cross_refs: dict[str, str] = field(default_factory=dict)
    payload: dict[str, str] = field(default_factory=dict)
    schema_version: str = _DEFAULT_SCHEMA_VERSION
    extra_manifest_fields: dict = field(default_factory=dict)


def _write_file(out_dir: Path, rel_path: str, data: bytes) -> str:
    """Write data at out_dir/rel_path (creating parents) and return its digest.

    ``rel_path`` has already passed :func:`require_canonical_rel_path` (the
    lexical discipline), so the only residual escape is a symlink prefix
    already present under ``out_dir`` redirecting the write out of tree. The
    resolve-then-``relative_to`` assert below is the same last-line containment
    rule the verifier's read side applies (``_safe_bundle_path`` /
    ``resolve_within``), run BEFORE any directory is created or byte written.
    """
    target = out_dir / rel_path
    try:
        target.resolve().relative_to(out_dir.resolve())
    except ValueError:
        raise UnsafeBundleRelPath(
            f"bundle rel_path {rel_path!r} resolves outside the bundle root "
            f"{out_dir} — refusing the write (path containment)"
        ) from None
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return sha256(data)


def assemble_manifest(
    content: BundleContent,
    *,
    timestamp_provider: TimestampProvider | None = None,
    causal_chain_emitter: CausalChainEmitter | None = None,
    attestation_provider: AttestationProvider | None = None,
    files_digests: dict[str, str],
    spec_digests: dict[str, str],
) -> dict:
    """Build the manifest dict from content + hook outputs.

    Pure (no I/O) given precomputed digests — separated from write_bundle so
    callers that need the dict before writing (or that write files themselves)
    can reuse the assembly. Hooks default to the open production-standard set.

    Digest-map keys must pass the canonical rel-path discipline
    (:func:`require_canonical_rel_path`) — the verifier's read side rejects
    traversal/absolute manifest paths fail-closed, so assembling one here
    could only produce a bundle the verifier refuses. Direct callers that
    write files themselves get the same emit-time rejection write_bundle does.
    """
    for rel_path in files_digests:
        require_canonical_rel_path(rel_path)
    for rel_name in spec_digests:
        require_canonical_rel_path(rel_name, forbid_envelope=False)

    ts_provider = timestamp_provider or StaticTimestampProvider(content.created_at)
    cc_emitter = causal_chain_emitter or NullCausalChainEmitter()
    att_provider = attestation_provider or NullAttestationProvider()

    ts = ts_provider.stamp()
    cc = cc_emitter.emit()
    att = att_provider.attest()

    manifest: dict = {
        "schema_version": content.schema_version,
        "bundle_id": content.bundle_id,
        "created_at": ts.created_at,
        "files": dict(files_digests),
        "spec_files": dict(spec_digests),
        "cross_refs": dict(content.cross_refs),
        "payload": dict(content.payload),
        "typed_checks": list(content.typed_checks),
    }

    if cc.dispatch_records:
        manifest["dispatch_records"] = list(cc.dispatch_records)
    # NOTE: no hook seam writes the top-level `aggregate_stamp` key — that is
    # the §C14 lattice aggregate (verifier-set, never dispatcher-trusted). A
    # pilot computing the legitimate C14 min-over-rows value supplies it via
    # pilot-carried optional fields (e.g. gxp_part11 / provenance_upgrade).

    # Pilot-carried optional fields, then hook-produced fields. ONE-LEVEL deep
    # merge (not a shallow replace) so multiple sources can contribute DISTINCT
    # sub-keys of the same composite manifest key — notably `causal_chain`, to
    # which a stronger TimestampProvider adds `layer_b_anchors` and a cross-org
    # CausalChainEmitter adds `cross_host_authenticators`. A shallow
    # `manifest.update` would let the later source clobber the earlier source's
    # sub-keys (dropping layer_b_anchors). For non-dict values, or a sub-key
    # present in both, the later source still wins (last-writer, as before).
    for extra in (
        content.extra_manifest_fields,
        ts.extra_manifest_fields,
        cc.extra_manifest_fields,
        att.extra_manifest_fields,
    ):
        _merge_manifest_extra(manifest, extra)

    return manifest


def _merge_manifest_extra(manifest: dict, extra: dict) -> None:
    """Merge `extra` into `manifest` in place, deep-merging one level for keys
    whose value is a dict in BOTH (so distinct sub-keys union rather than the
    later source replacing the whole key). Everything else is last-writer-wins."""
    for key, value in extra.items():
        existing = manifest.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            merged = dict(existing)
            merged.update(value)
            manifest[key] = merged
        else:
            manifest[key] = value


def write_manifest(out_dir: Path, manifest: dict) -> Path:
    """Write manifest.json in the canonical form (sorted keys, 2-space indent).

    Written via ``write_bytes`` (not text-mode ``write_text``) so the on-disk
    bytes are byte-identical on every platform: ``indent=2`` embeds ``\\n``
    separators, and a text-mode write would translate those to ``\\r\\n`` on
    Windows (the CRT default), making a Windows producer emit a CRLF manifest
    for the same logical content a Linux producer writes as LF. The DSSE hash
    is taken over these on-disk bytes on both emit and verify, so today that
    divergence is merely self-consistent-but-non-canonical; pinning LF here
    forecloses it before any future canonical-bytes comparison can trip on it.
    """
    manifest_path = out_dir / "manifest.json"
    text = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    manifest_path.write_bytes(text.encode("utf-8"))
    return manifest_path


def write_bundle(
    out_dir: Path,
    content: BundleContent,
    *,
    timestamp_provider: TimestampProvider | None = None,
    causal_chain_emitter: CausalChainEmitter | None = None,
    attestation_provider: AttestationProvider | None = None,
    validate: bool = False,
    dsse_signing_key: "Ed25519PrivateKey | None" = None,
    dsse_iat: int | None = None,
) -> dict:
    """Emit a complete bundle into out_dir and return the manifest dict.

    Scaffolds out_dir, writes every content + spec file (accumulating digests),
    runs the three hooks, assembles + writes manifest.json.

    Conformance is `veriker/cli/verify.py --bundle-dir out_dir` (or the pilot's own
    verify path) — emit is deliberately decoupled from verify. validate=True
    runs that SAME orchestration in-process: BundleVerifier.verify() with the
    CLI's default plugin set — not an emitter-side re-implementation — so
    "self-check green" and "verifier green" are one code path and cannot
    drift. Raises BundleSelfCheckFailed on any non-OK verdict, including
    could-not-conclude legs (e.g. a re_derive/ pack present but not executed:
    the CLI exits 2 for that bundle, so the self-check reports it too).
    Sealed bundles (dsse_signing_key given) are verified against the key just
    used. validate stays OFF by default: it pulls the verifier + plugin
    stack, and a bundle claiming pilot-local typed_checks needs those plugin
    modules imported by the caller or the CC2 cross-check fails.

    DSSE sealing (opt-in)
    ---------------------
    When ``dsse_signing_key`` is provided (an ``Ed25519PrivateKey`` from
    ``cryptography``), write_bundle additionally emits ``bundle.dsse.json``
    alongside the bundle — a DSSE v0.4 sidecar that binds the manifest's
    sha256 and every content+spec file digest under a single Ed25519 signature.

    The sidecar payload is the RFC 8785 canonical JSON of:
        {
            "schema_version": <manifest["schema_version"]>,
            "manifest_sha256": "<lowercase hex sha256 of manifest.json bytes>",
            "iat": <int>,
            "files": [
                {"path": "<relative POSIX path>", "sha256": "<lowercase hex>"},
                ...  (sorted by path; excludes manifest.json + bundle.dsse.json)
            ]
        }

    manifest.json bytes are **byte-identical** whether or not a signing key is
    supplied — the sidecar is a separate file and does not alter the manifest.

    ``dsse_iat``: optional integer "issued-at" timestamp for the payload.
    If not supplied, 0 is used (deterministic for tests; non-load-bearing per D1).

    The seal path imports ``sign_envelope`` / ``rfc8785`` lazily inside the
    ``if dsse_signing_key is not None`` block so the default (no-key) path
    stays import-light and third-party-free.  The seal path does NOT import
    ``audit_bundle.emitter_premium`` (OSS boundary preserved).

    When ``dsse_signing_key is None`` (the default), behavior is identical to
    today — no sidecar is written and manifest.json is unchanged.

    Path discipline (fail-closed, RES-07)
    -------------------------------------
    Every ``content.files`` / ``content.spec_files`` key must be a canonical
    bundle-relative POSIX path (no absolute paths, no ``..``/``.``/empty
    segments, no backslashes, and ``files`` may not name the structural
    envelope files manifest.json / bundle.dsse.json). Violations raise
    :class:`~audit_bundle.integrity_ownership.UnsafeBundleRelPath` BEFORE any
    directory or file is created, so a rejected call leaves no partial bundle
    and can never write outside ``out_dir`` — the write-side counterpart of
    the verifier's read-side containment. Keys are validated up front even
    though they may be honest pass-throughs of upstream data (e.g. dataset
    filenames): the emitter is the last point where a hostile name is a
    string and not a write.

    Stale-root posture (deliberate, RES-08)
    ---------------------------------------
    write_bundle overwrites exactly what it writes and never sweeps, deletes,
    or refuses pre-existing entries under ``out_dir``. That is a decision,
    not an omission:

    * builders legitimately write sibling artifacts straight into the bundle
      dir around this call (``re_derive/`` packs, ``inputs/``, plugin-owned
      files) — they are owned by other integrity classes, not by
      ``content.files``, so the emitter cannot tell "stale from a prior run"
      from "sibling the builder just wrote". A clean/temp-dir-rename mode
      would delete or orphan intended content on that ambiguity.
    * the authoritative surplus decision already exists and is fail-closed:
      the conservation gate runs UNCONDITIONALLY inside
      ``BundleVerifier.verify()`` in every lane (UNOWNED on-disk path →
      ``EXTRA_FILE_NOT_IN_MANIFEST`` reject; the sealed set-closure walk is
      stricter still). A stale file can therefore never ride a green
      verdict; trust comes from the verdict path, never from "the emitter
      produced it". A consumer that packages a bundle without verifying it
      is outside the trust model.
    * a caller that wants the stale-root check at emit time has it already:
      ``validate=True`` runs that exact gate in-process and raises
      :class:`BundleSelfCheckFailed` naming the surplus paths (pinned by
      test). It stays opt-in because it pulls the verifier+plugin stack and
      pilot-local typed_checks need their plugin modules imported (CC2).
    """
    for rel_path in content.files:
        require_canonical_rel_path(rel_path)
    for rel_name in content.spec_files:
        # Envelope names are top-level-only; under spec/ they are ordinary
        # pinned-spec document names, so only the canonical-form rule applies.
        require_canonical_rel_path(rel_name, forbid_envelope=False)

    out_dir.mkdir(parents=True, exist_ok=True)

    files_digests: dict[str, str] = {}
    for rel_path, data in content.files.items():
        files_digests[rel_path] = _write_file(out_dir, rel_path, data)

    spec_digests: dict[str, str] = {}
    for rel_name, data in content.spec_files.items():
        spec_digests[rel_name] = _write_file(out_dir, f"spec/{rel_name}", data)

    manifest = assemble_manifest(
        content,
        timestamp_provider=timestamp_provider,
        causal_chain_emitter=causal_chain_emitter,
        attestation_provider=attestation_provider,
        files_digests=files_digests,
        spec_digests=spec_digests,
    )
    manifest_path = write_manifest(out_dir, manifest)

    if dsse_signing_key is not None:
        # Lazy import: only pulled when sealing is requested.  rfc8785 and
        # cryptography are not imported on the default (no-key) code path.
        import rfc8785  # noqa: PLC0415
        from audit_bundle.dsse.envelope import PINNED_URI, sign_envelope  # noqa: PLC0415

        # Read the on-disk manifest bytes (the canonical source for the hash).
        manifest_bytes = manifest_path.read_bytes()
        manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()

        # Build the files list: every content + spec file, sorted by relative
        # POSIX path.  The structural envelope files (manifest.json,
        # bundle.dsse.json) are excluded via the integrity-ownership map's
        # ENVELOPE class — the SAME seam source the verifier's set-closure
        # gates re-add — rather than relying only on the by-construction
        # invariant that they are neither content nor spec files. One source,
        # producer and verifier in lockstep. (Lazy import keeps the default
        # no-key path import-light; integrity_ownership is stdlib-only and
        # pulls no premium / third-party deps.)
        #
        # Content files are stored with their rel_path key as-is.
        # Spec files live under spec/<name>, so we prepend "spec/".
        from audit_bundle.integrity_ownership import ENVELOPE_PATHS  # noqa: PLC0415

        all_files: list[dict[str, str]] = []
        for rel_path, digest in files_digests.items():
            if rel_path in ENVELOPE_PATHS:
                continue
            all_files.append({"path": rel_path, "sha256": digest})
        for rel_name, digest in spec_digests.items():
            all_files.append({"path": f"spec/{rel_name}", "sha256": digest})
        all_files.sort(key=lambda e: e["path"])

        iat_value: int = dsse_iat if dsse_iat is not None else 0

        payload_obj: dict = {
            "schema_version": manifest["schema_version"],
            "manifest_sha256": manifest_sha256,
            "iat": iat_value,
            "files": all_files,
        }

        # RFC 8785 canonical JSON (returns bytes).
        payload_bytes: bytes = rfc8785.dumps(payload_obj)

        sidecar_dict: dict = sign_envelope(
            payload_bytes, dsse_signing_key, payload_type=PINNED_URI
        )

        sidecar_path = out_dir / "bundle.dsse.json"
        sidecar_path.write_text(
            json.dumps(sidecar_dict, ensure_ascii=False),
            encoding="utf-8",
        )

    if validate:
        _self_check(out_dir, dsse_signing_key)

    return manifest


def _self_check(out_dir: Path, dsse_signing_key: "Ed25519PrivateKey | None") -> None:
    """Run the verifier's OWN orchestration over the just-emitted bundle.

    One orchestration, two callers: BundleVerifier.verify() with the CLI's
    default plugin set (veriker.cli.verify._build_plugins). The emitter previously ran
    validate_manifest() here — a parallel shallow walk whose file-integrity
    loop had no typed-check/plugin/append-only skip set, whose spec_files check
    was presence-only, and which never executed plugins, so emitter-green and
    verifier-green could diverge on the same bundle in both directions.

    For a sealed bundle the seal is verified against the signing key just
    used, with a fresh empty in-process revocation list — there is no
    adversary inside the self-check loop; the question answered is "would a
    verifier configured to trust this key accept this bundle right now".

    Everything is imported lazily so a validate=False caller never pays for
    the verifier/plugin/crypto stack.
    """
    import time  # noqa: PLC0415
    from types import SimpleNamespace  # noqa: PLC0415

    from audit_bundle.verifier import BundleVerifier, _load_manifest  # noqa: PLC0415
    from veriker.cli.verify import _build_plugins  # noqa: PLC0415

    manifest = _load_manifest(out_dir)
    plugins = _build_plugins(out_dir, manifest)

    dsse_ctx = None
    if dsse_signing_key is not None:
        from audit_bundle.dsse.pae import kid_from_raw32  # noqa: PLC0415
        from audit_bundle.revocation import RevocationList  # noqa: PLC0415

        pub_raw32 = dsse_signing_key.public_key().public_bytes_raw()
        now = int(time.time())
        dsse_ctx = SimpleNamespace(
            allowlist={kid_from_raw32(pub_raw32): pub_raw32},
            verifier_now=now,
            revocation_list=RevocationList(
                entries={},
                issued_at=now,
                expires=now + 3600,
                revocation_list_hash="",
            ),
            require_dsse=True,
            allow_legacy=False,
        )

    verdict = BundleVerifier(plugins=plugins).verify(out_dir, dsse=dsse_ctx)
    if not verdict.ok:

        def _walk(v) -> list[str]:
            lines = [f"[{r.check_name or '-'}] {r.code}: {r.detail}" for r in v.reasons]
            for leg in v.legs:
                lines.extend(_walk(leg))
            return lines

        raise BundleSelfCheckFailed(
            f"emitted bundle failed verifier self-check "
            f"(state={verdict.state.value}): " + "; ".join(_walk(verdict))
        )


__all__ = [
    "sha256",
    "BundleContent",
    "BundleSelfCheckFailed",
    "assemble_manifest",
    "write_manifest",
    "write_bundle",
]
