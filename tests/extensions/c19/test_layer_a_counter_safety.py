"""§C9 regression for validate_event_cddl error-detail formatter.

Same methodological lesson as Layer 2 #4 (atheris cose_bundle finding):
error-detail formatters must survive adversarial dict-key inputs. The
formatter `_decode_keys` previously called `.decode()` on bytes keys
without an encoding/errors policy — an event carrying an extra bytes key
with invalid UTF-8 produced `UnicodeDecodeError` leaking out of
`validate_event_cddl`, violating the §C9 fail-closed contract (the
verifier must raise `LayerAVerificationError`, not arbitrary exceptions).

See also: the internal design notes memory.
"""

from __future__ import annotations

import pytest

from audit_bundle.extensions.c19.layer_a_counter import (
    LayerAVerificationError,
    validate_event_cddl,
)


def _valid_event() -> dict:
    return {
        b"event_id": "evt-x",
        b"event_kind": "reasoning_step",
        b"prev_event_id": None,
        b"prev_event_hash": b"\x00" * 32,
        b"scitt_statement_id": b"\x00" * 32,
        b"scitt_statement_content_sha256": b"\x00" * 32,
        b"scitt_inclusion_proof": b"\x00" * 32,
        b"payload_hash": b"\x00" * 32,
        b"monotonic_counter": 1,
        b"counter_log_index": 1,
        b"event_signature": {},
        b"causal_dependencies": [],
    }


# Each extra-key entry is an adversarial key added to the otherwise-valid event.
# The validator MUST raise LayerAVerificationError (§C9), not the raw exception
# that the pre-fix `_decode_keys` would have leaked.
_ADVERSARIAL_KEYS = [
    pytest.param(b"\xff\xfe\xfd", id="invalid_utf8_bytes_3byte"),
    pytest.param(b"\xff", id="invalid_utf8_bytes_1byte"),
    pytest.param(b"\x80valid_after", id="invalid_utf8_continuation_byte_first"),
    pytest.param(5, id="int_key"),
    pytest.param((1, 2), id="tuple_key"),
    pytest.param(None, id="none_key"),
]


@pytest.mark.parametrize("extra_key", _ADVERSARIAL_KEYS)
def test_validate_event_cddl_fails_closed_on_adversarial_extra_key(extra_key):
    event = _valid_event()
    event[extra_key] = "evil"
    with pytest.raises(LayerAVerificationError) as excinfo:
        validate_event_cddl(event)
    # The detail string MUST be a normal str (the formatter must complete).
    assert "unknown keys" in str(excinfo.value)


def test_validate_event_cddl_mixed_adversarial_keys():
    """All four adversarial shapes in one event — formatter must still complete."""
    event = _valid_event()
    event[b"\xff"] = "a"
    event[5] = "b"
    event[(1, 2)] = "c"
    event[b"valid_extra"] = "d"
    with pytest.raises(LayerAVerificationError) as excinfo:
        validate_event_cddl(event)
    detail = str(excinfo.value)
    # The keys are sorted as strings, so each rendering must appear.
    assert "5" in detail
    assert "(1, 2)" in detail
    assert "valid_extra" in detail
    # Invalid-UTF-8 bytes key renders via repr().
    assert "\\xff" in detail


def test_validate_event_cddl_valid_utf8_bytes_key_still_works():
    """Regression guard: the fix must not break the original happy-path rendering
    (valid UTF-8 bytes keys still render as plain strings, not repr())."""
    event = _valid_event()
    event[b"some_unknown"] = "x"
    with pytest.raises(LayerAVerificationError) as excinfo:
        validate_event_cddl(event)
    detail = str(excinfo.value)
    assert "some_unknown" in detail
    # Must NOT be repr-quoted (no b'...' wrapper for valid UTF-8).
    assert "b'some_unknown'" not in detail
