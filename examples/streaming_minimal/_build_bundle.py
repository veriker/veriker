"""_build_bundle.py — build a deterministic streaming_minimal audit bundle.

Generates 1000 synthetic timestamped events at 100 ms spacing, applies
event-time tumbling-window aggregation (60-second windows, sum aggregator),
and emits a standards-compliant manifest.

This pilot forces the substrate stateful question: the re-derivation primitive
is NOT byte-equal output comparison but "state-machine state matches checkpoint"
— per-window aggregate state derived by replaying the committed event stream.

Usage (from v-kernel-audit-bundle root):
    python examples/streaming_minimal/_build_bundle.py --out-dir /tmp/streaming_bundle

Outputs:
  <out-dir>/events/stream.jsonl         (1000 events, one JSON object per line)
  <out-dir>/spec/segmentation.json      (windowing parameters)
  <out-dir>/payload/checkpoint.json     (per-window aggregate state)
  <out-dir>/manifest.json

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.emitter import BundleContent, write_bundle  # noqa: E402

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "streaming-minimal-rc"
_CREATED_AT = "2026-05-09T00:00:00Z"
_TYPED_CHECKS = [
    "spec_sha_pin",
    "file_integrity_many_small",
    "streaming_re_derivation",
]

# ---------------------------------------------------------------------------
# Windowing spec constants (mirrored in spec/segmentation.json)
# ---------------------------------------------------------------------------

_SPEC: dict = {
    "schema": "streaming-tumbling-v1",
    "window_size_ms": 60000,
    "aggregator": "sum",          # one of "sum" | "count" | "max"
    "late_event_policy": "drop",  # "drop" only at v0.1; "include" reserved
    "event_count": 1000,
}


# ---------------------------------------------------------------------------
# Deterministic event generator
#
# For event index i in 0..999:
#   event_id     = i
#   timestamp_ms = i * 100        (events spaced 100 ms apart)
#   value        = (i * 7) % 200 - 100   (integer in [-100, 99])
#
# With window_size_ms=60000 and 1000 events at 100 ms spacing:
#   Window 0: timestamp_ms in [0, 60000)   -> events 0..599   (600 events)
#   Window 1: timestamp_ms in [60000, ...) -> events 600..999 (400 events)
# ---------------------------------------------------------------------------


def _generate_events() -> list[dict]:
    """Return 1000 deterministic events as a list of dicts."""
    events: list[dict] = []
    for i in range(1000):
        events.append({
            "event_id": i,
            "timestamp_ms": i * 100,
            "value": (i * 7) % 200 - 100,
        })
    return events


def _events_to_jsonl(events: list[dict]) -> bytes:
    """Encode events as JSONL bytes (one JSON object per line, newline-terminated)."""
    lines: list[bytes] = []
    for ev in events:
        lines.append(json.dumps(ev, separators=(",", ":")).encode("utf-8"))
    return b"\n".join(lines) + b"\n"


# ---------------------------------------------------------------------------
# Tumbling-window aggregation
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


def _run_windowing(events: list[dict], spec: dict) -> list[dict]:
    """Apply tumbling-window aggregation to the event list.

    Returns list of window dicts sorted by window_start_ms:
      {"window_start_ms": int, "window_end_ms": int, "aggregate": int, "event_count": int}

    Late-event policy "drop": events whose timestamp_ms does not fall within
    any declared window are silently dropped.  Only "drop" is implemented at
    v0.1; "include" rejects with STREAMING_LATE_EVENT_POLICY_VIOLATED.
    """
    window_size_ms: int = spec["window_size_ms"]
    aggregator: str = spec["aggregator"]
    late_event_policy: str = spec["late_event_policy"]

    if late_event_policy != "drop":
        raise ValueError(
            f"late_event_policy {late_event_policy!r} is not supported at v0.1; "
            "only 'drop' is implemented"
        )

    # Bucket events by window index
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
        windows.append({
            "window_start_ms": w_start,
            "window_end_ms": w_end,
            "aggregate": _apply_aggregator(values, aggregator),
            "event_count": len(values),
        })

    return windows


def build(out_dir: Path) -> None:
    # ---- events/stream.jsonl ----
    events = _generate_events()
    jsonl_bytes = _events_to_jsonl(events)

    # ---- spec/segmentation.json ----
    spec_bytes = json.dumps(_SPEC, indent=2).encode("utf-8")

    # ---- derive window checkpoint ----
    windows = _run_windowing(events, _SPEC)
    assert len(windows) == 2, (
        f"Expected 2 tumbling windows with 1000 events at 100ms spacing "
        f"and window_size_ms=60000; got {len(windows)}: {windows}"
    )
    assert windows[0]["event_count"] == 600, (
        f"Window 0 should contain 600 events; got {windows[0]['event_count']}"
    )
    assert windows[1]["event_count"] == 400, (
        f"Window 1 should contain 400 events; got {windows[1]['event_count']}"
    )

    # ---- payload/checkpoint.json ----
    checkpoint_bytes = json.dumps(windows, indent=2).encode("utf-8")

    # ---- emit via the reference-emitter SDK ----
    # events/stream.jsonl + payload/checkpoint.json are in manifest.files
    # spec/ tree is owned by spec_files (walked by SpecShaPinCheck), not files
    # (FileIntegrityManySmall skips spec/). The two plugins cover
    # disjoint trees by construction.
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "events/stream.jsonl": jsonl_bytes,
            "payload/checkpoint.json": checkpoint_bytes,
        },
        spec_files={
            "segmentation.json": spec_bytes,
        },
        typed_checks=_TYPED_CHECKS,
    )
    manifest = write_bundle(out_dir, content)

    print(f"Bundle written to {out_dir}")
    print(f"  events           : {len(events)} events at 100ms spacing")
    print(f"  windows          : {len(windows)}")
    for w in windows:
        print(
            f"    [{w['window_start_ms']}ms, {w['window_end_ms']}ms): "
            f"aggregate={w['aggregate']}, count={w['event_count']}"
        )
    print(f"  manifest files   : {len(manifest['files'])}")
    print(f"  manifest         : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic streaming_minimal audit bundle"
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        type=Path,
        help="Destination directory (created if absent)",
    )
    args = parser.parse_args()
    try:
        build(args.out_dir.resolve())
    except (AssertionError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
