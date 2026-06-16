#!/usr/bin/env python3
"""streaming_re_derivation.py — LEGACY gated §C6 in-bundle re-derivation PACK.

  *** NOT the promoted recipe's source-of-truth. ***

This file is the legacy §C6 in-bundle code-execution pack: a deliberately
SEPARATE, self-contained stdlib script run as a subprocess by the demo-local
StreamingReDerivationCheck typed-check. By design it CANNOT import audit_bundle
(AB4 "duplicate-don't-import") so that the verifier never imports bundle-supplied
code into its own process.

Executing it is arbitrary local code execution. NOTE — this pack is NOT inert
and is NOT gated on this pilot's own verify path: examples/streaming_minimal/
verify.py registers StreamingReDerivationCheck, whose check() runs this pack via
subprocess UNCONDITIONALLY (no permit_execution gate, no --unsafe flag). That
demo-local check predates, and is distinct from, the generic
audit_bundle/plugins/re_derivation_invocation.py path (the one whose
permit_execution / --unsafe-run-bundle-pack gate yields RE_DERIVATION_NOT_EXECUTED);
this pilot does NOT use that generic check. The genuinely safe path is the generic
spec-pinned dispatch (BundleVerifier + the core registry), which recomputes the
shape in-process via primitives/streaming.py and NEVER runs this pack. This pack
is retained as the legacy demo verification path pending deprecation.

The PROMOTED `streaming aggregation` shape's SINGLE SOURCE OF TRUTH is
audit_bundle/rederivation/primitives/streaming.py (the verifier-distribution
recompute), re-exported into this pilot via streaming_recompute.py. The producer
copy in _build_bundle.py is a verbatim copy held in sync by that re-export shim.
This pack's own _apply_aggregator / _run_windowing below are a THIRD copy that is
intentionally NOT held in sync (it must stay audit_bundle-free); it is exercised
only on the legacy demo-local subprocess path (StreamingReDerivationCheck via
verify.py), not by the promoted recipe.

Re-derives per-window aggregate state by replaying the committed event stream
through tumbling-window aggregation using the committed windowing spec, then
asserts the per-window {window_start_ms, window_end_ms, aggregate, event_count}
matches the bundled checkpoint exactly.

the audit-bundle contract §C6 (re-derivation pack — domain-agnostic substrate).
AB4: stdlib only — json, sys, pathlib. No numpy, no pandas, no third-party deps.

Substrate-decision-forced: the re-derivation primitive is "state-machine state
matches checkpoint" (stateful re-derivation), NOT byte-equal output comparison.
This generalizes the V-Kernel substrate from batch single-pass compute to
event-time stateful computation.

Reads:
  spec/segmentation.json      — windowing parameters (schema streaming-tumbling-v1)
  events/stream.jsonl         — 1000 events, one JSON object per line
  payload/checkpoint.json     — per-window aggregate state produced at bundle time

Re-derivation:
  1. Validate spec schema == "streaming-tumbling-v1".
  2. Assert late_event_policy == "drop" (only supported policy at v0.1).
  3. Stream events/stream.jsonl line-by-line; bucket each event by
     event.timestamp_ms // window_size_ms.
  4. Per window: compute aggregate per declared aggregator (sum/count/max of values).
  5. Compare derived per-window state against payload/checkpoint.json exactly on
     (window_start_ms, window_end_ms, aggregate, event_count).
  6. Exit 0 on match; exit 1 with [STREAMING_REDER_FAIL] <description> on stderr.

Usage:
    python streaming_re_derivation.py --bundle-dir /path/to/bundle
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Aggregators — stdlib only
# ---------------------------------------------------------------------------


def _apply_aggregator(values: list[int], aggregator: str) -> int:
    """Apply the declared aggregator to a list of integer values."""
    if aggregator == "sum":
        return sum(values)
    if aggregator == "count":
        return len(values)
    if aggregator == "max":
        if not values:
            raise ValueError("max aggregator requires at least one value")
        return max(values)
    raise ValueError(f"unknown aggregator {aggregator!r}")


# ---------------------------------------------------------------------------
# Streaming tumbling-window re-derivation
# ---------------------------------------------------------------------------


def _run_windowing(stream_path: Path, spec: dict) -> list[dict]:
    """Replay the event stream through tumbling windows; return sorted window list.

    Each window dict: {window_start_ms, window_end_ms, aggregate, event_count}.

    Reads events/stream.jsonl line-by-line (streaming, not loaded into memory at
    once — demonstrating the stateful stream-replay primitive).

    Late-event policy "drop": events that fall outside any observed window range
    are silently dropped.  Only "drop" is valid at v0.1.
    """
    window_size_ms: int = spec["window_size_ms"]
    aggregator: str = spec["aggregator"]

    buckets: dict[int, list[int]] = {}

    with stream_path.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                ev: dict = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"events/stream.jsonl line {lineno}: invalid JSON: {exc}"
                ) from exc

            ts: int = ev.get("timestamp_ms")
            value: int = ev.get("value")
            if ts is None or value is None:
                raise ValueError(
                    f"events/stream.jsonl line {lineno}: "
                    f"missing required fields 'timestamp_ms' or 'value'"
                )

            win_idx: int = ts // window_size_ms
            if win_idx not in buckets:
                buckets[win_idx] = []
            buckets[win_idx].append(value)

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


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _verify(bundle_dir: Path) -> str | None:
    """Return an error description on mismatch, or None on success."""
    spec_path = bundle_dir / "spec" / "segmentation.json"
    stream_path = bundle_dir / "events" / "stream.jsonl"
    checkpoint_path = bundle_dir / "payload" / "checkpoint.json"

    for p, label in [
        (spec_path, "spec/segmentation.json"),
        (stream_path, "events/stream.jsonl"),
        (checkpoint_path, "payload/checkpoint.json"),
    ]:
        if not p.exists():
            return f"{label} absent from bundle_dir {bundle_dir}"

    # Load and validate spec
    try:
        spec: dict = json.loads(spec_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return f"failed to read spec/segmentation.json: {exc}"

    if spec.get("schema") != "streaming-tumbling-v1":
        return (
            f"spec schema mismatch: expected 'streaming-tumbling-v1', "
            f"got {spec.get('schema')!r}"
        )

    # Enforce late_event_policy at v0.1
    late_event_policy: str = spec.get("late_event_policy", "")
    if late_event_policy != "drop":
        return (
            "STREAMING_LATE_EVENT_POLICY_VIOLATED: "
            f"late_event_policy {late_event_policy!r} is not supported at v0.1; "
            "only 'drop' is implemented"
        )

    # Load bundled checkpoint
    try:
        bundled_windows: list[dict] = json.loads(
            checkpoint_path.read_text(encoding="utf-8")
        )
    except (json.JSONDecodeError, OSError) as exc:
        return f"failed to read payload/checkpoint.json: {exc}"

    if not isinstance(bundled_windows, list):
        return (
            f"payload/checkpoint.json must be a JSON array; "
            f"got {type(bundled_windows).__name__}"
        )

    # Re-derive windows by replaying the event stream
    try:
        derived_windows = _run_windowing(stream_path, spec)
    except (OSError, ValueError) as exc:
        return f"failed to re-derive windows from events/stream.jsonl: {exc}"

    # Compare window counts
    if len(derived_windows) != len(bundled_windows):
        return (
            f"window count mismatch: "
            f"derived={len(derived_windows)}, bundled={len(bundled_windows)}"
        )

    # Compare each window on all four fields
    for idx, (derived, bundled) in enumerate(zip(derived_windows, bundled_windows)):
        for key in ("window_start_ms", "window_end_ms", "aggregate", "event_count"):
            d_val = derived.get(key)
            b_val = bundled.get(key)
            if d_val != b_val:
                return (
                    f"window index {idx} field {key!r} mismatch: "
                    f"derived={d_val!r}, bundled={b_val!r}"
                )

    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Streaming tumbling-window re-derivation check for streaming audit bundles"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    error = _verify(bundle_dir)
    if error is None:
        return 0

    print(f"[STREAMING_REDER_FAIL] {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
