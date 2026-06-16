"""audit_bundle.emitter — the open reference-emitter SDK.

One pipeline (`write_bundle`) + three swappable hook seams (`TimestampProvider`,
`CausalChainEmitter`, `AttestationProvider`) with stdlib-only production-standard
defaults. Per-pilot builders become thin callers that supply only the content
that varies; a deployment needing a stronger witness on any seam injects its own
implementation at the call site (the defaults are never a ceiling).

See hooks.py for the seam contracts and the kind of stronger implementations a
caller can inject.
"""

from __future__ import annotations

from audit_bundle.emitter.hooks import (
    AttestationProvider,
    AttestationResult,
    CausalChainEmitter,
    CausalChainResult,
    NullAttestationProvider,
    NullCausalChainEmitter,
    StaticTimestampProvider,
    TimestampProvider,
    TimestampResult,
)
from audit_bundle.emitter.pipeline import (
    BundleContent,
    assemble_manifest,
    sha256,
    write_bundle,
    write_manifest,
)

# Raised by write_bundle/assemble_manifest on a non-canonical or escaping
# content key (RES-07 write-side path discipline). Lives in
# integrity_ownership — the seam vocabulary producer and verifier share —
# re-exported here so SDK callers can catch it without knowing the home module.
from audit_bundle.integrity_ownership import UnsafeBundleRelPath

__all__ = [
    # pipeline
    "BundleContent",
    "write_bundle",
    "assemble_manifest",
    "write_manifest",
    "sha256",
    "UnsafeBundleRelPath",
    # hook interfaces
    "TimestampProvider",
    "CausalChainEmitter",
    "AttestationProvider",
    # hook result records
    "TimestampResult",
    "CausalChainResult",
    "AttestationResult",
    # open production-standard defaults
    "StaticTimestampProvider",
    "NullCausalChainEmitter",
    "NullAttestationProvider",
]
