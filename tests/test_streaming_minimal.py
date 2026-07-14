"""Round-trip integration test for examples/streaming_minimal/verify.py.

Test flow:
  1. (test_clean_bundle_passes) Build a clean bundle into a temp directory.
     Run the verifier with the pilot's plugin set. Assert result.ok is True.

  2. (test_tamper_event_timestamp_fails_rederivation) Mutate event 599's
     timestamp_ms from 59900 to 60000, pushing it from window 0 into window 1.
     Re-align events/stream.jsonl SHA in manifest.files so FileIntegrityManySmall
     passes. Assert STREAMING_REDERIV substring appears in failures — caught
     exclusively by StreamingReDerivationCheck.

  3. (test_tamper_spec_segmentation_fails_spec_sha) Append trailing whitespace
     to spec/segmentation.json (SHA changes; parsed JSON is identical). Do NOT
     realign manifest.spec_files SHA. Assert SpecShaPinCheck catches the divergence
     — SPEC_SHA_MISMATCH or missing_spec_blob substring in failures.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PKG_ROOT = Path(__file__).resolve().parents[1]  # v-kernel-audit-bundle/
_PILOT_DIR = _PKG_ROOT / "examples" / "streaming_minimal"

# Ensure both pkg root and pilot dir are importable
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

# ---------------------------------------------------------------------------
# Lazy imports (after path setup)
# ---------------------------------------------------------------------------

from examples.streaming_minimal._build_bundle import build  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from StreamingReDerivationCheck import StreamingReDerivationCheck  # noqa: E402


# ---------------------------------------------------------------------------
# Helper: build verifier
# ---------------------------------------------------------------------------


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(plugins=[
        SpecShaPinCheck(),
        FileIntegrityManySmall(),
        StreamingReDerivationCheck(),
    ])


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_clean_bundle_passes(tmp_path: Path) -> None:
    """build + verify on a clean bundle must return result.ok == True."""
    bundle_dir = tmp_path / "streaming_bundle"
    build(bundle_dir)
    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is True, (
        f"expected ok=True; failures: {result.failures}"
    )


def test_tamper_event_timestamp_fails_rederivation(tmp_path: Path) -> None:
    """Pushing event 599's timestamp from 59900 to 60000 must trigger
    STREAMING_REDERIVATION_MISMATCH.

    Event 599 sits at the boundary: timestamp_ms=59900 puts it in window 0
    [0, 60000). Bumping to 60000 moves it into window 1 [60000, ...), changing:
      - window 0: count 600→599, aggregate -300→-393  (loses value 93)
      - window 1: count 400→401, aggregate -200→-107  (gains value 93)

    The events/stream.jsonl SHA in manifest.files is re-aligned so
    FileIntegrityManySmall passes. The failure is caught exclusively by
    StreamingReDerivationCheck.
    """
    bundle_dir = tmp_path / "streaming_bundle_tamper"
    build(bundle_dir)

    stream_path = bundle_dir / "events" / "stream.jsonl"

    # Read all lines, find event 599, mutate its timestamp_ms
    lines = stream_path.read_text(encoding="utf-8").splitlines(keepends=True)

    mutated = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        ev = json.loads(stripped)
        if ev.get("event_id") == 599:
            assert ev["timestamp_ms"] == 59900, (
                f"expected event 599 timestamp_ms=59900, got {ev['timestamp_ms']}"
            )
            ev["timestamp_ms"] = 60000  # push into window 1
            lines[i] = json.dumps(ev, separators=(",", ":")) + "\n"
            mutated = True
            break

    assert mutated, "event 599 not found in stream.jsonl"
    tampered_bytes = "".join(lines).encode("utf-8")
    stream_path.write_bytes(tampered_bytes)

    # Re-align manifest SHA so FileIntegrityManySmall does not fire first
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"]["events/stream.jsonl"] = hashlib.sha256(tampered_bytes).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)

    assert result.ok is False, (
        "expected ok=False after pushing event 599 across window boundary"
    )
    # Accept STREAMING_REDERIVATION_MISMATCH reason_code or [STREAMING_REDER_FAIL] in detail
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    assert "STREAMING_REDERIV" in combined or "STREAMING_REDER_FAIL" in combined, (
        f"expected STREAMING_REDERIVATION_MISMATCH or STREAMING_REDER_FAIL in failures; "
        f"got: {result.failures}"
    )


def test_tamper_spec_segmentation_fails_spec_sha(tmp_path: Path) -> None:
    """Mutate spec/segmentation.json with a SHA-changing-but-semantics-preserving
    edit (trailing whitespace; ignored by json.loads). manifest.spec_files SHA is
    NOT realigned, so SpecShaPinCheck catches the divergence in isolation —
    re-derivation still passes because parsed JSON is identical.
    """
    bundle_dir = tmp_path / "streaming_bundle_spec_tamper"
    build(bundle_dir)

    spec_path = bundle_dir / "spec" / "segmentation.json"
    original = spec_path.read_text(encoding="utf-8")
    spec_path.write_text(original + "\n   \n", encoding="utf-8")

    result = _make_verifier().verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False after tampering spec/segmentation.json without realigning manifest.spec_files"
    )
    combined = " ".join(
        f.reason_code + " " + f.detail for f in result.failures
    ).upper()
    assert (
        "SPEC_SHA_MISMATCH" in combined
        or "MISSING_SPEC_BLOB" in combined
        or ("SPEC" in combined and "SHA MISMATCH" in combined)
    ), f"expected spec-SHA-mismatch indicator in failures; got: {result.failures}"
