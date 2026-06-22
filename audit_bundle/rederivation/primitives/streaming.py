"""streaming_recompute — verifier-side streaming tumbling-window re-derivation.

Axis-2 value-return form of the streaming re-derivation, PROMOTED into the
shippable core registry (RECIPE_BOOK.md, shape `streaming aggregation`). The
generic verifier recomputes the representative output on the SAFE spec-pinned
path: no subprocess, no bundle-supplied code — the recompute rule lives HERE in
verifier-distribution code and the comparator + tolerance come from the
auditor-anchored spec.

Re-derivation primitive (one sentence):
    per-window aggregate list = replay of the committed event stream
    (events/stream.jsonl) through event-time tumbling-window aggregation per the
    committed windowing spec (spec/segmentation.json: window_size_ms + aggregator
    + late_event_policy), bucketing each event into window index
    `timestamp_ms // window_size_ms`, applying the aggregator per bucket, and
    emitting windows in ascending window_start_ms.

The aggregation rule (window bucketing, aggregator dispatch, late-event "drop"
policy) is FIXED in this primitive — the primitive_id ("streaming_recompute") IS
the rule. The auditor's SHA-pinned spec binds the output type
"streaming_window_aggregates" to this primitive_id and to an `exact` comparator
(element-wise list equality, no params); a producer cannot weaken the aggregation
without changing the primitive_id, which the anchor rejects.

Faithfulness (the only query classes this primitive re-derives):
  - Event-time tumbling-window aggregation (no watermarks; each event falls into
    exactly one window by `timestamp_ms // window_size_ms`).
  - Aggregators: "sum", "count", "max" over INTEGER event values. All three
    produce integer outputs; there is no float summation-order divergence. The
    comparator is therefore `exact` (element-wise equality of the window-dict
    list). A spec that aggregated floats would require a different primitive_id
    and `scalar_epsilon`; this primitive makes no such claim.
  - Late-event policy: only "drop" is implemented at v0.1. Any other policy
    raises ValueError (fail-closed).
  - Windows are emitted in ascending window_start_ms order (sorted by window
    index); the output list is deterministic given the committed stream + spec.

Stdlib-only (§C5 core verify() path).
"""

from __future__ import annotations

from pathlib import Path

from ...admission import admit_json_file, admit_jsonl_file
from ...plugin import ParsedInputs, RecomputedValue
from ..registry import register_primitive


# ---------------------------------------------------------------------------
# Aggregation engine — VERBATIM copy of the producer's aggregation logic
# (examples/streaming_minimal/_build_bundle.py _apply_aggregator / _run_windowing).
# These are NOT two independently-authored implementations and they are NOT
# auto-synced: the re-export shim (streaming_recompute.py) binds the verifier-side
# call sites (spec_pinned_check.py, the promoted test) to THIS module, but the
# producer copy in _build_bundle.py is a separate MANUAL verbatim copy that imports
# nothing from the shim. The producer's checkpoint and this verifier recompute
# agree by construction today; the faithfulness test
# (tests/test_recipe_streaming_promoted.py) is what proves DRIFT DETECTION — it
# derives the claim from the producer artifact and the recompute from this copy, so
# it FAILS if either copy is edited without the other — not an
# independent-algorithm cross-check.
# ---------------------------------------------------------------------------


def _apply_aggregator(values: list[int], aggregator: str) -> int:
    """Apply the declared aggregator to a list of integer values. Mirrors the
    producer's _build_bundle._apply_aggregator EXACTLY.

    Fail-closed integer-only contract: the `exact` comparator and the
    "no float summation-order divergence" claim above are only sound for integer
    values. A non-int (e.g. float) value raises ValueError (-> RECOMPUTE_ERROR)
    rather than silently summing floats, which would make `exact` unsafe.
    `bool` is rejected too (it is an int subclass but not a numeric stream value).
    """
    for v in values:
        if not isinstance(v, int) or isinstance(v, bool):
            raise ValueError(
                f"streaming aggregation is integer-only (exact comparator); "
                f"got non-int value {v!r} ({type(v).__name__})"
            )
    if aggregator == "sum":
        return sum(values)
    if aggregator == "count":
        return len(values)
    if aggregator == "max":
        if not values:
            raise ValueError("max aggregator requires at least one value")
        return max(values)
    raise ValueError(f"unknown aggregator {aggregator!r}")


def compute_window_aggregates(events: list[dict], spec: dict) -> list[dict]:
    """Canonical tumbling-window aggregation re-derivation. Mirrors the producer's
    _build_bundle._run_windowing EXACTLY: bucket each event into window index
    `timestamp_ms // window_size_ms`, apply the aggregator per bucket, and emit
    windows sorted by window_start_ms as
    {window_start_ms, window_end_ms, aggregate, event_count}.

    Fail-closed: raises KeyError/TypeError/ValueError if the spec is missing
    required keys or names an unsupported late_event_policy / aggregator (the
    verifier must not invent an aggregate).
    """
    window_size_ms: int = spec["window_size_ms"]
    aggregator: str = spec["aggregator"]
    late_event_policy: str = spec["late_event_policy"]

    if late_event_policy != "drop":
        raise ValueError(
            f"late_event_policy {late_event_policy!r} is not supported at v0.1; "
            "only 'drop' is implemented"
        )

    # Bucket events by window index.
    buckets: dict[int, list[int]] = {}
    for ev in events:
        ts: int = ev["timestamp_ms"]
        win_idx = ts // window_size_ms
        if win_idx not in buckets:
            buckets[win_idx] = []
        buckets[win_idx].append(ev["value"])

    windows: list[dict] = []
    for win_idx in sorted(buckets):
        w_start = win_idx * window_size_ms
        w_end = w_start + window_size_ms
        values = buckets[win_idx]
        windows.append(
            {
                "window_start_ms": w_start,
                "window_end_ms": w_end,
                "aggregate": _apply_aggregator(values, aggregator),
                "event_count": len(values),
            }
        )

    return windows


def _parse_stream(rows: list[object]) -> list[dict]:
    """Shape admitted stream rows into a list of event dicts. Fail-closed on a
    non-object row (the admission loader already rejected malformed JSON,
    size, depth, and cardinality breaches — RES-02, 2026-06-11)."""
    events: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("events/stream.jsonl: every row must be a JSON object")
        events.append(row)
    return events


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered at import for the core registry)
# ---------------------------------------------------------------------------


class StreamingRecompute:
    """Verifier-side primitive for re-deriving the per-window aggregate list."""

    primitive_id: str = "streaming_recompute"

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        """Recompute the per-window aggregate list by replaying the committed
        event stream through the committed windowing spec.

        Returns the recomputed VALUE only — it reads no acceptance epsilon and
        does not compare; the auditor-anchored `exact` comparator decides
        agreement against outputs/<id>.json.
        """
        bundle_dir: Path = inputs.bundle_dir

        stream_path = bundle_dir / "events" / "stream.jsonl"
        if not stream_path.is_file():
            raise FileNotFoundError(
                f"events/stream.jsonl not found in bundle at {bundle_dir}"
            )
        spec_path = bundle_dir / "spec" / "segmentation.json"
        if not spec_path.is_file():
            raise FileNotFoundError(
                f"spec/segmentation.json not found in bundle at {bundle_dir}"
            )

        events = _parse_stream(
            admit_jsonl_file(stream_path, check_name="streaming_recompute")
        )
        spec = admit_json_file(spec_path)
        if not isinstance(spec, dict):
            raise ValueError("spec/segmentation.json: top-level must be an object")
        for key in ("window_size_ms", "aggregator", "late_event_policy"):
            if key not in spec:
                raise ValueError(f"spec/segmentation.json: missing required {key!r}")

        value = compute_window_aggregates(events, spec)
        return RecomputedValue(
            value=value,
            detail=(
                f"re-derived per-window aggregates ({len(value)} window(s)) "
                f"from {len(events)} event(s), "
                f"window_size_ms={spec['window_size_ms']}"
            ),
        )


register_primitive(StreamingRecompute())
