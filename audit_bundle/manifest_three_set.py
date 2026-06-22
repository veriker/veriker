"""manifest_three_set.py — per-output manifest with three-set decomposition.

K4 canary4 per-output manifest ties each model output to a retrieval trace and
its derived three-set view, guarding against post-hoc tampering of the
retrieved / context_injected / quote_supporting decomposition.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from audit_bundle.retrieval.capture import TraceNotFound, load_trace
from audit_bundle.retrieval.trace import RetrievalTraceError
from audit_bundle.retrieval.three_set import (
    ThreeSetViolation,
    derive_three_set,
    three_set_to_canonical_dict,
)

if TYPE_CHECKING:
    from audit_bundle.bundle_manifest import BundleManifest


# ---------------------------------------------------------------------------
# K4 v1 visibility policy enum
# ---------------------------------------------------------------------------

_K4_VISIBILITY_POLICIES: frozenset[str] = frozenset(
    {"public", "customer_visible", "access_controlled", "partial_redacted"}
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ThreeSetMismatch(Exception):
    """Stored three_set does not match the three-set derived from the trace."""


class BadVisibilityPolicy(Exception):
    """visibility_policy is not in the K4 v1 enum."""


# ---------------------------------------------------------------------------
# PerOutputManifest dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PerOutputManifest:
    output_id: str  # caller-supplied unique output identifier
    trace_id: str  # references a trace in the bundle's retrieval_trace_log
    three_set: dict  # three_set_to_canonical_dict() output
    emitted_at: str  # ISO-8601 UTC 'Z'
    visibility_policy: str = "customer_visible"  # K4 v1 enum; default per K4 lock


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def validate_per_output_manifest(
    pom: PerOutputManifest,
    parent_bundle_manifest: BundleManifest,
    bundle_dir: Path,
) -> None:
    """Validate a PerOutputManifest against the parent BundleManifest and bundle.

    Raises
    ------
    ThreeSetMismatch
        If the stored three_set does not match the three-set derived from the
        referenced trace (guards against post-hoc tampering), or if the trace
        log is unreachable.
    BadVisibilityPolicy
        If visibility_policy is not in the K4 v1 enum.
    """
    # 1. Locate and load the trace
    trace_log = parent_bundle_manifest.retrieval_trace_log
    if trace_log is None:
        raise ThreeSetMismatch(
            f"output_id={pom.output_id!r}: parent_bundle_manifest has no "
            f"retrieval_trace_log; cannot validate three_set"
        )
    # Path-safety: _safe_bundle_path fail-closes on path-escape (absolute
    # paths, .. traversal, symlinks leaving the tree) and directory targets
    # (atheris finding 2026-05-26 sibling in plugin surface). This function's
    # public failure shape is ThreeSetMismatch, so convert UnsafeBundlePath
    # to ThreeSetMismatch rather than letting it propagate as a separate
    # exception type (preserves caller contract).
    from audit_bundle.bundle_manifest import UnsafeBundlePath, _safe_bundle_path

    try:
        trace_log_path = _safe_bundle_path(bundle_dir, trace_log)
    except UnsafeBundlePath as exc:
        raise ThreeSetMismatch(
            f"output_id={pom.output_id!r}: retrieval_trace_log={trace_log!r} "
            f"is an unsafe bundle path: {exc}"
        ) from exc
    try:
        trace = load_trace(trace_log_path, pom.trace_id)
    except TraceNotFound:
        raise ThreeSetMismatch(
            f"output_id={pom.output_id!r}: trace_id={pom.trace_id!r} not found "
            f"in retrieval_trace_log={trace_log!r}"
        ) from None
    except RetrievalTraceError as exc:
        # Malformed log content, an inadmissible line, or a duplicate
        # trace_id (RES-12 shadowing reject). load_trace's docstring has
        # always listed RetrievalTraceError as a caller-catchable failure;
        # this site previously caught only TraceNotFound/OSError, so a
        # malformed log escaped the ThreeSetMismatch contract as a raw
        # RetrievalTraceError.
        raise ThreeSetMismatch(
            f"output_id={pom.output_id!r}: retrieval_trace_log={trace_log!r} "
            f"is malformed or ambiguous for trace_id={pom.trace_id!r}: {exc}"
        ) from exc
    except OSError as exc:
        raise ThreeSetMismatch(
            f"output_id={pom.output_id!r}: could not read retrieval_trace_log "
            f"{trace_log!r}: {exc}"
        ) from exc

    # 2. Derive expected three-set from trace + quote_supporting cids
    stamped_cids = set(pom.three_set.get("quote_supporting", []))
    try:
        derived_view = derive_three_set(trace, stamped_cids)
    except ThreeSetViolation as exc:
        raise ThreeSetMismatch(
            f"output_id={pom.output_id!r}: three-set subset invariant violated "
            f"for trace_id={pom.trace_id!r}: {exc}"
        ) from exc

    # 3. Canonical dict equality — guards against post-hoc tampering
    expected = three_set_to_canonical_dict(derived_view)
    if pom.three_set != expected:
        raise ThreeSetMismatch(
            f"output_id={pom.output_id!r}: stored three_set does not match the "
            f"three-set derived from trace_id={pom.trace_id!r}"
        )

    # 4. Visibility policy must be in the K4 v1 enum
    if pom.visibility_policy not in _K4_VISIBILITY_POLICIES:
        raise BadVisibilityPolicy(
            f"output_id={pom.output_id!r}: visibility_policy={pom.visibility_policy!r} "
            f"is not a valid K4 v1 policy; expected one of "
            f"{sorted(_K4_VISIBILITY_POLICIES)}"
        )


def per_output_manifest_to_canonical_dict(pom: PerOutputManifest) -> dict:
    """Return a deterministic canonical dict for emission inside BundleManifest."""
    return {
        "emitted_at": pom.emitted_at,
        "output_id": pom.output_id,
        "three_set": pom.three_set,
        "trace_id": pom.trace_id,
        "visibility_policy": pom.visibility_policy,
    }
