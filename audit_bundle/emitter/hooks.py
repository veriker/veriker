"""audit_bundle/emitter/hooks.py — emit-side hook interfaces + default implementations.

The reference-emitter SDK is ONE pipeline (pipeline.py) with three swappable
hook seams. This mirrors the verifier's own plugin registry on the emit side:
the SDK ships the stable *interfaces* plus stdlib-only *production-standard*
default implementations. A deployment that needs a stronger witness on any seam
injects its own implementation at the call site — the interfaces are the
contract; the defaults are a working baseline, not a ceiling.

  - TimestampProvider   — the time/ordering witness.
      default       : a fixed, declared created_at (production-standard).
      stronger impl : e.g. an RFC 3161 TSA + Roughtime quorum + BLS-aggregated
                      time anchor, supplied by the caller.

  - CausalChainEmitter  — dispatch records / causal DAG / monotone counter.
      default       : NullCausalChainEmitter (no causal chain, no records).
      opt-in        : Layer-A counter + single-org dispatch records.
      stronger impl : e.g. cross-host / cross-org COSE_Sign1 receipts.

  - AttestationProvider — serving / identity attestation.
      default       : NullAttestationProvider (no attestation block).
      opt-in        : HMAC single-org verifier signing.
      stronger impl : e.g. TEE/RATS attested serving (TDX/SEV-SNP) — C17, v0.4.

Every default here is stdlib-only and emits an OPEN, independently verifiable
bundle. Injecting a stronger provider changes WHO can mint the witness, never
whether the bundle's verify function is public — the verify path stays open
regardless of which provider produced the bundle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


# ---------------------------------------------------------------------------
# Result records — what each hook contributes to the manifest
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TimestampResult:
    """Output of a TimestampProvider.

    created_at is the canonical ISO-8601 UTC ('Z') manifest timestamp. A
    stronger provider additionally returns extra_manifest_fields (e.g.
    causal_chain.layer_b_anchors) that the verifier's C19 verify_* functions
    check — the manifest format is public regardless of which provider minted
    the stamp.

    There is deliberately NO aggregate_stamp field here (removed 2026-06-12):
    the manifest top-level `aggregate_stamp` key is the §C14 stamp-lattice
    aggregate — verifier-set, never dispatcher-trusted, equal to min(per-row
    effective stamp) — and an EMITTER hook minting it is exactly the
    dispatcher-trusted write the contract forbids. The premium tier's
    cross-host quorum witness (BLS aggregated root signature) travels inside
    extra_manifest_fields at causal_chain.layer_b_anchors.per_batch_tsa_root,
    where the C19 legs verify it; the former top-level copy was read by
    nothing and collided with the C14 key.
    """

    created_at: str
    extra_manifest_fields: dict = field(default_factory=dict)


@dataclass(frozen=True)
class CausalChainResult:
    """Output of a CausalChainEmitter: zero or more signed dispatch records plus
    any causal-chain manifest fields (causal_chain, expected_events, layer_a)."""

    dispatch_records: tuple = ()
    extra_manifest_fields: dict = field(default_factory=dict)


@dataclass(frozen=True)
class AttestationResult:
    """Output of an AttestationProvider: attestation manifest fields
    (attested_serving, verifier_identity, ...). Empty in the default."""

    extra_manifest_fields: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Hook protocols
# ---------------------------------------------------------------------------


@runtime_checkable
class TimestampProvider(Protocol):
    def stamp(self) -> TimestampResult: ...


@runtime_checkable
class CausalChainEmitter(Protocol):
    def emit(self) -> CausalChainResult: ...


@runtime_checkable
class AttestationProvider(Protocol):
    def attest(self) -> AttestationResult: ...


# ---------------------------------------------------------------------------
# Production-standard default implementations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StaticTimestampProvider:
    """Default: a fixed, declared created_at — no qualified time witness.

    This is the production-standard baseline. A deployment that needs a
    qualified time witness injects a stronger provider at this seam (e.g. an
    RFC 3161 TSA + Roughtime quorum + BLS aggregation) — it satisfies this same
    interface and additionally populates aggregate_stamp + layer_b_anchors.
    """

    created_at: str

    def stamp(self) -> TimestampResult:
        return TimestampResult(created_at=self.created_at)


class NullCausalChainEmitter:
    """Default: emit no causal chain and no dispatch records.

    Used by the trivial/static and fragment-only families, which carry no
    dispatch_records. Families that DO sign dispatch records (SMT discharge,
    spec-conformance gates) pass a concrete emitter instead.
    """

    def emit(self) -> CausalChainResult:
        return CausalChainResult()


class NullAttestationProvider:
    """Default: emit no attestation block.

    A C17 TEE/RATS attestation provider (attested_serving) implements this same
    interface and is injected by callers that need it.
    """

    def attest(self) -> AttestationResult:
        return AttestationResult()


__all__ = [
    "TimestampResult",
    "CausalChainResult",
    "AttestationResult",
    "TimestampProvider",
    "CausalChainEmitter",
    "AttestationProvider",
    "StaticTimestampProvider",
    "NullCausalChainEmitter",
    "NullAttestationProvider",
]
