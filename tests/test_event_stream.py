"""Tests for audit_bundle.event_stream — append-only JSONL status-change writer."""

from __future__ import annotations

from pathlib import Path

import pytest

from audit_bundle.event_stream import StatusEvent, append_event, read_events


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TS = "2026-04-30T00:00:00Z"


def _evt(event_type: str, seq: int = 0, **kw) -> StatusEvent:
    return StatusEvent(
        event_type=event_type,
        source_id=f"src-{seq:03d}",
        prior_sha="aa" * 32,
        new_sha="bb" * 32,
        detected_at=_TS,
        metadata={"seq": seq, **kw},
    )


# ---------------------------------------------------------------------------
# append + read — ordering and completeness
# ---------------------------------------------------------------------------


def test_append_three_events_read_back(tmp_path: Path) -> None:
    jsonl = tmp_path / "events.jsonl"
    types = ["RETRACT", "SUPERSEDE", "RECLASSIFY"]
    for i, t in enumerate(types):
        append_event(jsonl, _evt(t, i))

    events = list(read_events(jsonl))
    assert len(events) == 3
    assert [e.event_type for e in events] == types


def test_order_preserved_strictly(tmp_path: Path) -> None:
    jsonl = tmp_path / "stream.jsonl"
    sequence = ["RETRACT", "SUPERSEDE", "RECLASSIFY", "CORRECT", "KEY_REVOKED"]
    for i, t in enumerate(sequence):
        append_event(jsonl, _evt(t, i))

    read_types = [e.event_type for e in read_events(jsonl)]
    assert read_types == sequence


def test_source_id_and_timestamps_round_trip(tmp_path: Path) -> None:
    jsonl = tmp_path / "rt.jsonl"
    evt = _evt("RETRACT", 42)
    append_event(jsonl, evt)

    (result,) = list(read_events(jsonl))
    assert result.source_id == evt.source_id
    assert result.detected_at == evt.detected_at
    assert result.prior_sha == evt.prior_sha
    assert result.new_sha == evt.new_sha


def test_metadata_preserved(tmp_path: Path) -> None:
    jsonl = tmp_path / "meta.jsonl"
    evt = StatusEvent(
        event_type="CORRECT",
        source_id="src-meta",
        prior_sha=None,
        new_sha="cc" * 32,
        detected_at=_TS,
        metadata={"reason": "typo", "reviewer": "alice"},
    )
    append_event(jsonl, evt)

    (result,) = list(read_events(jsonl))
    assert result.metadata == {"reason": "typo", "reviewer": "alice"}


def test_none_sha_fields_preserved(tmp_path: Path) -> None:
    jsonl = tmp_path / "none_sha.jsonl"
    evt = StatusEvent(
        event_type="RETRACT",
        source_id="src-000",
        prior_sha=None,
        new_sha=None,
        detected_at=_TS,
        metadata={},
    )
    append_event(jsonl, evt)

    (result,) = list(read_events(jsonl))
    assert result.prior_sha is None
    assert result.new_sha is None


# ---------------------------------------------------------------------------
# Append-only invariant — file size grows monotonically
# ---------------------------------------------------------------------------


def test_file_size_monotone(tmp_path: Path) -> None:
    jsonl = tmp_path / "grow.jsonl"
    sizes: list[int] = []

    for i, t in enumerate(["RETRACT", "SUPERSEDE", "RECLASSIFY"]):
        append_event(jsonl, _evt(t, i))
        sizes.append(jsonl.stat().st_size)

    for i in range(1, len(sizes)):
        assert sizes[i] > sizes[i - 1], (
            f"File did not grow after appending event {i}: {sizes[i - 1]} → {sizes[i]}"
        )


def test_incremental_read_after_each_append(tmp_path: Path) -> None:
    """Each append extends the readable set — prior rows are not mutated."""
    jsonl = tmp_path / "incremental.jsonl"
    accumulated: list[str] = []

    for i, t in enumerate(["RETRACT", "SUPERSEDE", "RECLASSIFY"]):
        append_event(jsonl, _evt(t, i))
        accumulated.append(t)
        current = [e.event_type for e in read_events(jsonl)]
        assert current == accumulated, f"After {i + 1} appends: expected {accumulated}, got {current}"


# ---------------------------------------------------------------------------
# Invalid event_type → ValueError
# ---------------------------------------------------------------------------


def test_bogus_event_type_raises_value_error(tmp_path: Path) -> None:
    jsonl = tmp_path / "bogus.jsonl"
    with pytest.raises(ValueError):
        append_event(jsonl, _evt("BOGUS", 0))


def test_value_error_message_contains_type(tmp_path: Path) -> None:
    jsonl = tmp_path / "bogus2.jsonl"
    with pytest.raises(ValueError, match="BOGUS"):
        append_event(jsonl, _evt("BOGUS", 0))


def test_bogus_event_not_written_to_disk(tmp_path: Path) -> None:
    """ValueError is raised before any bytes are written."""
    jsonl = tmp_path / "guard.jsonl"
    append_event(jsonl, _evt("RETRACT", 0))
    size_before = jsonl.stat().st_size

    with pytest.raises(ValueError):
        append_event(jsonl, _evt("BOGUS", 1))

    assert jsonl.stat().st_size == size_before, "Bogus event must not grow the file"
    events = list(read_events(jsonl))
    assert len(events) == 1
    assert events[0].event_type == "RETRACT"


def test_empty_event_type_raises(tmp_path: Path) -> None:
    jsonl = tmp_path / "empty_type.jsonl"
    with pytest.raises(ValueError):
        append_event(jsonl, _evt("", 0))


def test_lowercase_valid_type_raises(tmp_path: Path) -> None:
    """Event types are case-sensitive; 'retract' is not 'RETRACT'."""
    jsonl = tmp_path / "lower.jsonl"
    with pytest.raises(ValueError):
        append_event(jsonl, _evt("retract", 0))


# ---------------------------------------------------------------------------
# All five valid event types are accepted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("event_type", ["RETRACT", "CORRECT", "SUPERSEDE", "KEY_REVOKED", "RECLASSIFY"])
def test_all_valid_event_types_accepted(tmp_path: Path, event_type: str) -> None:
    jsonl = tmp_path / "valid.jsonl"
    append_event(jsonl, _evt(event_type, 0))
    (result,) = list(read_events(jsonl))
    assert result.event_type == event_type


# ---------------------------------------------------------------------------
# JSONL file encoding — each line is parseable JSON, no leading whitespace
# ---------------------------------------------------------------------------


def test_each_line_is_valid_json(tmp_path: Path) -> None:
    import json

    jsonl = tmp_path / "lines.jsonl"
    for i, t in enumerate(["RETRACT", "SUPERSEDE", "RECLASSIFY"]):
        append_event(jsonl, _evt(t, i))

    raw_lines = [ln for ln in jsonl.read_bytes().splitlines() if ln.strip()]
    assert len(raw_lines) == 3
    for line in raw_lines:
        obj = json.loads(line)  # must not raise
        assert "event_type" in obj


# ---------------------------------------------------------------------------
# RES-11 reader leg — read_events is admission-bounded (admit_jsonl_file):
# a depth-bomb or malformed line is a typed InputInadmissible at the parse
# boundary, never a RecursionError out of json.loads.
# ---------------------------------------------------------------------------


def test_read_events_rejects_depth_bomb_line(tmp_path: Path) -> None:
    from audit_bundle.admission import InputInadmissible

    jsonl = tmp_path / "events.jsonl"
    append_event(jsonl, _evt("RETRACT", 0))
    with jsonl.open("ab") as fh:
        fh.write(b"[" * 5000 + b"]" * 5000 + b"\n")

    with pytest.raises(InputInadmissible):
        list(read_events(jsonl))


def test_read_events_rejects_torn_tail(tmp_path: Path) -> None:
    """A crash-torn final line is a typed reject, never streamed past."""
    from audit_bundle.admission import InputInadmissible

    jsonl = tmp_path / "events.jsonl"
    append_event(jsonl, _evt("RETRACT", 0))
    with jsonl.open("ab") as fh:
        fh.write(b'{"event_type": "SUPER')  # torn mid-write

    with pytest.raises(InputInadmissible):
        list(read_events(jsonl))
