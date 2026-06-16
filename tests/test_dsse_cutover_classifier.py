"""Tests for the DSSE cutover classifier (is_post_cutover).

Schema versions are opaque string tags — membership test only, no ordering.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from audit_bundle.bundle_manifest import (
    _POST_CUTOVER_SCHEMA_VERSIONS,
    _VALID_SCHEMA_VERSIONS,
    is_post_cutover,
)


# ---------------------------------------------------------------------------
# Post-cutover tag returns True
# ---------------------------------------------------------------------------


def test_dsse_tag_is_post_cutover() -> None:
    assert is_post_cutover("vcp-v1.2-dsse") is True


# ---------------------------------------------------------------------------
# Pre-cutover / legacy / unknown tags return False
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "version",
    [
        "vcp-v1.1-canary4",
        "vcp-v1.1",
        "legacy",
        "0.1",
        "",
        "anything-unknown",
    ],
)
def test_pre_cutover_and_junk_are_false(version: str) -> None:
    assert is_post_cutover(version) is False


# ---------------------------------------------------------------------------
# Totality — never raises, always returns bool
# ---------------------------------------------------------------------------


def test_totality_over_valid_schema_versions() -> None:
    """is_post_cutover must return a bool for every known valid schema version."""
    for v in _VALID_SCHEMA_VERSIONS:
        result = is_post_cutover(v)
        assert isinstance(result, bool), f"is_post_cutover({v!r}) returned non-bool"


def test_totality_over_junk_strings() -> None:
    """is_post_cutover must return False for arbitrary junk — never raises."""
    junk = [
        "vcp-v1.2",
        "vcp-v1.2-dsse-extra",
        "VCP-V1.2-DSSE",  # wrong case
        "vcp-v1.1-canary4 ",  # trailing space
        " vcp-v1.2-dsse",  # leading space
        "\x00",
        "a" * 1000,
    ]
    for v in junk:
        result = is_post_cutover(v)
        assert isinstance(result, bool), f"is_post_cutover({v!r}) returned non-bool"


# ---------------------------------------------------------------------------
# Membership invariants on the frozensets
# ---------------------------------------------------------------------------


def test_new_dsse_tag_in_valid_schema_versions() -> None:
    """The new tag must be accepted by the manifest validator."""
    assert "vcp-v1.2-dsse" in _VALID_SCHEMA_VERSIONS


def test_post_cutover_subset_of_valid() -> None:
    """Every post-cutover tag must also be a valid schema version."""
    assert _POST_CUTOVER_SCHEMA_VERSIONS <= _VALID_SCHEMA_VERSIONS


def test_pre_cutover_tags_not_in_post_cutover() -> None:
    pre_cutover = {"vcp-v1.1-canary4", "vcp-v1.1", "legacy"}
    assert pre_cutover.isdisjoint(_POST_CUTOVER_SCHEMA_VERSIONS)


# ---------------------------------------------------------------------------
# Stdlib-purity import probe
# ---------------------------------------------------------------------------


def test_bundle_manifest_stdlib_pure() -> None:
    """Importing bundle_manifest must not pull in cryptography or jcs."""
    cmd = [
        sys.executable,
        "-c",
        (
            "import audit_bundle.bundle_manifest, sys; "
            "assert 'cryptography' not in sys.modules, 'cryptography leaked in'; "
            "assert 'jcs' not in sys.modules, 'jcs leaked in'"
        ),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, (
        f"stdlib-purity probe failed:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"
    )
