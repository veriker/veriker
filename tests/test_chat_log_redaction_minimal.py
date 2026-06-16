"""Round-trip integration test for examples/chat_log_redaction_minimal.

Test flow:
  1. Import _build_bundle.build from the pilot directory dynamically.
  2. Build the bundle into tmp_path (out-of-tree fresh build).
  3. Run the verifier with the pilot's plugin set (file_integrity_many_small +
     re_derivation_invocation + ChatLogRedactionReDerivationCheck).
  4. Assert result.ok is True on the clean bundle.

Tamper tests (4 total per SKILL.md + prompt discipline):
  tamper-transcript-byte      : edit one byte in transcript.txt WITHOUT updating
                                manifest SHA → FileIntegrityManySmall catches it.
  tamper-policy               : modify redaction_policy.json regex + re-align SHA
                                → re-derivation produces different spans → caught.
  tamper-payload-spans        : mutate one span's end_byte + re-align manifest SHA
                                → re-derivation mismatch caught.
  happy-path build+verify     : clean bundle passes all checks.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

# Suppress .pyc generation so the pilot dir stays clean.
sys.dont_write_bytecode = True

# ---------------------------------------------------------------------------
# Paths + dynamic import of pilot modules
# ---------------------------------------------------------------------------

_PKG_ROOT = Path(__file__).resolve().parents[1]  # v-kernel-audit-bundle/
_PILOT_DIR = _PKG_ROOT / "examples" / "chat_log_redaction_minimal"

if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))


def _import_module_from_path(name: str, path: Path):
    """Dynamically import a module from an absolute path."""
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_build_bundle_mod = _import_module_from_path(
    "chat_log_redaction_minimal._build_bundle",
    _PILOT_DIR / "_build_bundle.py",
)
_check_mod = _import_module_from_path(
    "ChatLogRedactionReDerivationCheck",
    _PILOT_DIR / "ChatLogRedactionReDerivationCheck.py",
)

from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.re_derivation_invocation import ReDerivationInvocationCheck  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402

ChatLogRedactionReDerivationCheck = _check_mod.ChatLogRedactionReDerivationCheck


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_verifier() -> BundleVerifier:
    return BundleVerifier(
        plugins=[
            FileIntegrityManySmall(),
            ReDerivationInvocationCheck(pack_filename="chat_log_redaction_pack.py", permit_execution=True),
            ChatLogRedactionReDerivationCheck(),
        ]
    )


def _build_clean(tmp_path: Path) -> Path:
    """Build a fresh bundle out-of-tree."""
    bundle_dir = tmp_path / "clr_bundle"
    _build_bundle_mod.build(bundle_dir)
    return bundle_dir


def _canonical_bytes(obj) -> bytes:
    return (
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _patch_manifest_sha(manifest_path: Path, rel: str, new_sha: str) -> None:
    """Re-align manifest.files[rel] to new_sha."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][rel] = new_sha
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Test 1 — happy-path build + verify
# ---------------------------------------------------------------------------


def test_clean_bundle_passes(tmp_path: Path) -> None:
    """Build + verify on a clean bundle must return result.ok == True."""
    bundle_dir = _build_clean(tmp_path)
    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is True, (
        f"expected ok=True on clean bundle; failures: {result.failures}"
    )


# ---------------------------------------------------------------------------
# Test 2 — tamper transcript byte (SHA mismatch)
# ---------------------------------------------------------------------------


def test_tamper_transcript_byte_fails(tmp_path: Path) -> None:
    """Edit one byte in transcript.txt WITHOUT updating manifest SHA.
    FileIntegrityManySmall must catch the SHA divergence."""
    bundle_dir = _build_clean(tmp_path)

    txt_path = bundle_dir / "inputs" / "transcript.txt"
    original = txt_path.read_bytes()
    # Flip one byte in the middle of the file.
    mid = len(original) // 2
    tampered = original[:mid] + bytes([original[mid] ^ 0xFF]) + original[mid + 1 :]
    txt_path.write_bytes(tampered)
    # Intentionally do NOT update the manifest SHA.

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False after mutating transcript.txt without re-aligning SHA"
    )
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures).upper()
    assert "BAD_FILE_SHA" in combined or "FILE_INTEGRITY" in combined, (
        f"expected BAD_FILE_SHA / file_integrity failure; got: {result.failures}"
    )


# ---------------------------------------------------------------------------
# Test 3 — tamper policy (re-derivation mismatch)
# ---------------------------------------------------------------------------


def test_tamper_policy_fails(tmp_path: Path) -> None:
    """Modify redaction_policy.json (change EMAIL pattern to NOMATCH) and
    re-align manifest SHA so file_integrity passes but re-derivation catches
    the span-count divergence."""
    bundle_dir = _build_clean(tmp_path)

    policy_path = bundle_dir / "inputs" / "redaction_policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    # Swap EMAIL regex to a pattern that matches nothing.
    policy["regex_patterns"]["EMAIL"] = "NOMATCH_NEVER_FIRES"
    tampered_bytes = _canonical_bytes(policy)
    policy_path.write_bytes(tampered_bytes)
    _patch_manifest_sha(
        bundle_dir / "manifest.json",
        "inputs/redaction_policy.json",
        hashlib.sha256(tampered_bytes).hexdigest(),
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is False, (
        "expected ok=False after disabling EMAIL pattern (span count changes)"
    )
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures).upper()
    assert (
        "CLR_REDER_FAIL" in combined
        or "RE_DERIVATION_MISMATCH" in combined
        or "CHAT_LOG_REDACTION_REDERIVATION_MISMATCH" in combined
    ), f"expected re-derivation failure; got: {result.failures}"


# ---------------------------------------------------------------------------
# Test 4 — tamper payload spans (mutate one span end byte)
# ---------------------------------------------------------------------------


def test_tamper_payload_span_end_byte_fails(tmp_path: Path) -> None:
    """Mutate the end_byte of span[0] in redaction_result.json and re-align
    manifest SHA so file_integrity passes but re-derivation catches the mismatch."""
    bundle_dir = _build_clean(tmp_path)

    result_path = bundle_dir / "payload" / "redaction_result.json"
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    assert len(payload["spans"]) > 0, "need at least one span to tamper"
    # Inflate the first span's end_byte by 3 (or reduce, either breaks equality).
    original_end = payload["spans"][0]["end_byte"]
    payload["spans"][0]["end_byte"] = original_end + 3
    tampered_bytes = _canonical_bytes(payload)
    result_path.write_bytes(tampered_bytes)
    _patch_manifest_sha(
        bundle_dir / "manifest.json",
        "payload/redaction_result.json",
        hashlib.sha256(tampered_bytes).hexdigest(),
    )

    verifier = _make_verifier()
    result = verifier.verify(bundle_dir)
    assert result.ok is False, "expected ok=False after mutating a span's end_byte"
    combined = " ".join(f.reason_code + " " + f.detail for f in result.failures).upper()
    assert (
        "CLR_REDER_FAIL" in combined
        or "RE_DERIVATION_MISMATCH" in combined
        or "CHAT_LOG_REDACTION_REDERIVATION_MISMATCH" in combined
    ), f"expected re-derivation failure; got: {result.failures}"
