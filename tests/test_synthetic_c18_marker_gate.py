"""WS-6b: synthetic-C18-marker RELEASE gate (carried conformance item #3).

Release-pipeline-only. Guarded by ``REQUIRE_C18_HARDENING=1``: SKIPS in general
PR CI (so the legitimately-synthetic v0.4 chain does not block merges, per v2.2
SCOPING §11 "build/soak/OSS-ship is NOT gated") and ENFORCES only in the
tag-triggered release job. When enforced it FAILS on:

  * any embedded root-role JSON (root.json / revocation_root.json) carrying an
    EMPTY signature (``sig == ""``) — the C18 key ceremony has not run; and
  * any ``_tuf_root/*.json`` still carrying a ``TBD-*`` placeholder digest or
    fingerprint — ceremony tooling has not filled production values.

A separate always-on structural check (NOT flag-gated) asserts the new
revocation_root.json is a well-formed 2-of-3 / <=90-day revocation-root role.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

import pytest

_TUF_ROOT = (
    Path(__file__).resolve().parent.parent / "audit_bundle" / "extensions" / "_tuf_root"
)

_REQUIRE_HARDENING = os.environ.get("REQUIRE_C18_HARDENING") == "1"
_SKIP_REASON = (
    "REQUIRE_C18_HARDENING != 1 — the synthetic-C18 marker gate is "
    "release-pipeline-only (it would otherwise block every merge while the "
    "v0.4 chain is legitimately synthetic, per v2.2 SCOPING §11). The "
    "tag-triggered release job sets the flag and enforces."
)

requires_hardening = pytest.mark.skipif(not _REQUIRE_HARDENING, reason=_SKIP_REASON)

_ROOT_ROLE_FILES = ("root.json", "revocation_root.json")


def _load(name: str) -> dict:
    path = _TUF_ROOT / name
    assert path.is_file(), f"{name} missing under {_TUF_ROOT}"
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Always-on structural check (runs in PR CI too — validates the new artifact)
# ---------------------------------------------------------------------------


def test_revocation_root_is_wellformed_2of3_role() -> None:
    role = _load("revocation_root.json")
    assert role.get("role_name") == "revocation-root"
    signed = role["signed"]
    rr = signed["roles"]["revocation-root"]
    assert rr["threshold"] == 2, "revocation-root must be 2-of-3 (C18 root discipline)"
    keyids = rr["keyids"]
    assert len(keyids) == 3 and len(set(keyids)) == 3, "exactly 3 distinct keyids"
    for kid in keyids:
        assert kid in signed["keys"], f"keyid {kid} not enumerated under signed.keys"
        key = signed["keys"][kid]
        assert key["keytype"] == "ed25519"
        # ed25519 raw public is 32 bytes == 64 hex chars
        pub = key["keyval"]["public"]
        assert len(pub) == 64, (
            f"keyid {kid} public is {len(pub)} hex chars, expected 64"
        )
        int(pub, 16)  # must be valid hex
    assert role["rotation_policy"]["max_validity_days"] <= 90
    # expires must parse as ISO-8601 (Z or offset)
    datetime.fromisoformat(signed["expires"].replace("Z", "+00:00"))


# ---------------------------------------------------------------------------
# Release-gated marker checks (skip in PR CI; enforce in the release job)
# ---------------------------------------------------------------------------


@requires_hardening
def test_no_empty_root_signatures() -> None:
    offenders: list[str] = []
    for name in _ROOT_ROLE_FILES:
        doc = _load(name)
        sigs = doc.get("signatures")
        assert sigs, f"{name} has no signatures block at all"
        for i, sig in enumerate(sigs):
            if not sig.get("sig"):
                offenders.append(
                    f"{name}[sig#{i} keyid={str(sig.get('keyid', '?'))[:12]}]"
                )
    assert not offenders, (
        "Synthetic C18 chain: EMPTY root signatures present — the C18 key "
        "ceremony has not run. Release is BLOCKED until real signatures exist. "
        f"Offenders: {offenders}"
    )


# A value is an UNFILLED ceremony placeholder iff (the whole string value)
# begins with the TBD sentinel — bare or `sha256:`-prefixed. Anchored at the
# start, so honest descriptive PROSE that names the sentinel mid-sentence (e.g.
# the comment_bootstrap_disposition / honest_hedge fields) does NOT trip the
# gate. This is what makes the gate SATISFIABLE: a real ceremony that fills
# every placeholder VALUE turns it green, while the comments survive untouched.
# Before this fix the gate did a whole-line substring scan for "TBD" and so
# matched its own prose, staying red forever even after a real ceremony.
_PLACEHOLDER_VALUE_RE = re.compile(r"^(sha256:)?TBD")


def _string_values(node: object, path: str = "") -> Iterator[tuple[str, str]]:
    """Yield (json_path, value) for every string VALUE in parsed JSON. Object
    KEYS are never yielded — only values — so a placeholder token appearing in a
    key name or mid-sentence in prose cannot be mistaken for an unfilled field."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _string_values(v, f"{path}.{k}" if path else str(k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _string_values(v, f"{path}[{i}]")
    elif isinstance(node, str):
        yield path, node


@requires_hardening
def test_no_tbd_placeholder_markers() -> None:
    offenders: list[str] = []
    for path in sorted(_TUF_ROOT.glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        for jpath, value in _string_values(doc):
            if _PLACEHOLDER_VALUE_RE.match(value):
                offenders.append(f"{path.name}:{jpath} = {value!r}")
    assert not offenders, (
        "Synthetic C18 chain: TBD-* placeholder digests/fingerprints present in "
        "VALUE positions — ceremony tooling has not filled production values. "
        f"Release is BLOCKED. Offenders: {offenders}"
    )
