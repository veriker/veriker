"""ThreeSetView — derived view of retrieved / context_injected / quote_supporting sets.

SCOPING.md §Revised kernel item 6 + §Frontier-panel convergence item 7.

Subset invariant (load-bearing for Component 6's manifest validator):
  retrieved ⊇ context_injected ⊇ quote_supporting
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from audit_bundle.retrieval.trace import RetrievalTrace


class ThreeSetViolation(ValueError):
    """Raised when the three-set subset chain is violated."""


@dataclass(frozen=True)
class ThreeSetView:
    """Derived three-set view for a single retrieval event.

    retrieved
        All source_cids the retriever considered (= trace.candidate_set).
    context_injected
        Subset that landed in the model's context window
        (= trace.context_window_injected).
    quote_supporting
        Subset of context_injected whose fragments contributed at least one
        stamped quote in the output (passed through extractive stamper).
    """

    retrieved: tuple[str, ...]
    context_injected: tuple[str, ...]
    quote_supporting: tuple[str, ...]


def derive_three_set(
    trace: RetrievalTrace,
    stamped_source_cids: Iterable[str],
) -> ThreeSetView:
    """Derive ThreeSetView from a RetrievalTrace plus the set of stamped source_cids.

    Parameters
    ----------
    trace:
        Validated RetrievalTrace for the output.
    stamped_source_cids:
        Iterable of source_cids whose fragments survived the extractive stamper
        (i.e., appeared as stamped quotes in the output).

    Raises
    ------
    ThreeSetViolation
        If quote_supporting ⊄ context_injected or context_injected ⊄ retrieved.
    """
    retrieved = tuple(trace.candidate_set)
    context_injected = tuple(trace.context_window_injected)
    stamped = set(stamped_source_cids)
    context_set = set(context_injected)

    # quote_supporting is the intersection of stamped cids with context_injected
    quote_supporting = tuple(cid for cid in context_injected if cid in stamped)

    view = ThreeSetView(
        retrieved=retrieved,
        context_injected=context_injected,
        quote_supporting=quote_supporting,
    )

    ok, reason = three_set_sum_invariant_check(view)
    if not ok:
        raise ThreeSetViolation(f"Three-set subset invariant violated: {reason}")

    # Verify any stamped cid that is NOT in context_injected would also violate
    # (caller-supplied stamped_source_cids should only reference context-injected cids;
    # quote_supporting is already filtered to context_injected above, but flag extras)
    extra_stamped = stamped - context_set
    if extra_stamped:
        raise ThreeSetViolation(
            f"QUOTE_NOT_IN_CONTEXT: stamped_source_cids contains cids not in "
            f"context_injected: {sorted(extra_stamped)}"
        )

    return view


def three_set_to_canonical_dict(view: ThreeSetView) -> dict:
    """Return a deterministic dict for inclusion in BundleManifest.

    All three sets are represented as sorted tuples for deterministic output.
    """
    return {
        "context_injected": sorted(view.context_injected),
        "quote_supporting": sorted(view.quote_supporting),
        "retrieved": sorted(view.retrieved),
    }


def three_set_sum_invariant_check(view: ThreeSetView) -> tuple[bool, str | None]:
    """Check that the three-set subset chain holds.

    Returns
    -------
    (True, None)
        If quote_supporting ⊆ context_injected ⊆ retrieved.
    (False, reason_code)
        Otherwise. reason_codes:
          'QUOTE_NOT_IN_CONTEXT'     — quote_supporting has a cid not in context_injected
          'CONTEXT_NOT_IN_RETRIEVED' — context_injected has a cid not in retrieved
    """
    retrieved_set = set(view.retrieved)
    context_set = set(view.context_injected)
    quote_set = set(view.quote_supporting)

    bad_context = context_set - retrieved_set
    if bad_context:
        return (False, "CONTEXT_NOT_IN_RETRIEVED")

    bad_quote = quote_set - context_set
    if bad_quote:
        return (False, "QUOTE_NOT_IN_CONTEXT")

    return (True, None)
