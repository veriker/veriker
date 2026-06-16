"""tests/test_dsse_payload_shape.py — verified-but-malformed DSSE payload shape.

Security property under test (red-team DSSE payload-shape finding,
2026-06-11): a validly-SIGNED DSSE payload that decodes to JSON of the WRONG
SHAPE must fail closed as a STRUCTURED ``DSSE_MALFORMED_PAYLOAD`` reject — not
as a crash-class ``VERIFIER_INTERNAL_ERROR`` (INDETERMINATE).

Before the fix, the gate json.loads()'d the verified payload and then ran
``payload.get(...)`` and ``f["path"]`` with no shape check. A non-object
payload, or ``files`` as a string / list of non-objects, raised
AttributeError / TypeError / KeyError out of the gate; the verifier's outer
fail-closed boundary caught it as VERIFIER_INTERNAL_ERROR — the bundle still
failed closed, but a malformed ARTIFACT was misattributed to a verifier fault.
The gate already returned a structured DSSE_MALFORMED_ENVELOPE reject for a
not-valid-JSON payload one step earlier; this pins the same discipline onto the
shape the gate then dereferences.

Two layers:
  * Pure-function unit tests of validate_dsse_payload_shape (fast, exhaustive).
  * End-to-end: SIGN a malformed payload with an allowlisted key and run the
    real core BundleVerifier gate — assert a structured REJECT, NOT an ERROR.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.dsse.envelope import sign_envelope  # noqa: E402
from audit_bundle.dsse.pae import kid_from_raw32  # noqa: E402
from audit_bundle.dsse.payload import (  # noqa: E402
    DSSE_MALFORMED_PAYLOAD,
    validate_dsse_payload_shape,
)
from audit_bundle.revocation import RevocationList  # noqa: E402
from audit_bundle.verdict import VerdictState  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402

_NOW = 1_770_000_000


# ---------------------------------------------------------------------------
# Layer 1 — pure-function unit tests
# ---------------------------------------------------------------------------


def _well_formed() -> dict:
    return {
        "schema_version": "vcp-v1.2-dsse",
        "manifest_sha256": "0" * 64,
        "iat": _NOW,
        "files": [{"path": "a.txt", "sha256": "ab"}, {"path": "b.txt"}],
    }


def test_well_formed_payload_passes() -> None:
    assert validate_dsse_payload_shape(_well_formed()) is None


def test_empty_files_list_passes() -> None:
    p = _well_formed()
    p["files"] = []
    assert validate_dsse_payload_shape(p) is None


def test_unknown_fields_are_ignored() -> None:
    """Forward-compat: the emitter emits `iat` (gate ignores it); a future
    additive field must not be rejected, mirroring the manifest posture."""
    p = _well_formed()
    p["iat"] = 123
    p["some_future_field"] = {"nested": True}
    assert validate_dsse_payload_shape(p) is None


@pytest.mark.parametrize("bad", [[], "verified", True, 7, None, 3.14])
def test_non_object_payload_rejected(bad: object) -> None:
    out = validate_dsse_payload_shape(bad)
    assert out is not None and out[0] == DSSE_MALFORMED_PAYLOAD


@pytest.mark.parametrize("bad", [123, None, [], {}, True])
def test_non_string_schema_version_rejected(bad: object) -> None:
    p = _well_formed()
    p["schema_version"] = bad
    out = validate_dsse_payload_shape(p)
    assert out is not None and out[0] == DSSE_MALFORMED_PAYLOAD


def test_missing_schema_version_rejected() -> None:
    p = _well_formed()
    del p["schema_version"]
    out = validate_dsse_payload_shape(p)
    assert out is not None and out[0] == DSSE_MALFORMED_PAYLOAD


@pytest.mark.parametrize("bad", [123, None, [], {}, True])
def test_non_string_manifest_sha256_rejected(bad: object) -> None:
    p = _well_formed()
    p["manifest_sha256"] = bad
    out = validate_dsse_payload_shape(p)
    assert out is not None and out[0] == DSSE_MALFORMED_PAYLOAD


@pytest.mark.parametrize("bad", ["string-not-list", {"path": "x"}, 7, None, True])
def test_non_list_files_rejected(bad: object) -> None:
    p = _well_formed()
    p["files"] = bad
    out = validate_dsse_payload_shape(p)
    assert out is not None and out[0] == DSSE_MALFORMED_PAYLOAD


@pytest.mark.parametrize("bad_entry", ["x", 7, ["path"], None, True])
def test_files_entry_not_object_rejected(bad_entry: object) -> None:
    p = _well_formed()
    p["files"] = [{"path": "ok.txt"}, bad_entry]
    out = validate_dsse_payload_shape(p)
    assert out is not None and out[0] == DSSE_MALFORMED_PAYLOAD


@pytest.mark.parametrize("bad_path", [123, None, [], {}, True])
def test_files_entry_path_not_string_rejected(bad_path: object) -> None:
    p = _well_formed()
    p["files"] = [{"path": bad_path}]
    out = validate_dsse_payload_shape(p)
    assert out is not None and out[0] == DSSE_MALFORMED_PAYLOAD


def test_files_entry_missing_path_rejected() -> None:
    p = _well_formed()
    p["files"] = [{"sha256": "ab"}]
    out = validate_dsse_payload_shape(p)
    assert out is not None and out[0] == DSSE_MALFORMED_PAYLOAD


def test_duplicate_paths_rejected() -> None:
    p = _well_formed()
    p["files"] = [{"path": "dup.txt"}, {"path": "dup.txt"}]
    out = validate_dsse_payload_shape(p)
    assert out is not None and out[0] == DSSE_MALFORMED_PAYLOAD
    assert "duplicate" in out[1]


# ---------------------------------------------------------------------------
# Layer 2 — end-to-end: a SIGNED malformed payload is a structured REJECT,
# never a crash-class verifier ERROR.
# ---------------------------------------------------------------------------


@dataclass
class _DsseCtx:
    allowlist: Mapping[str, bytes]
    revocation_list: RevocationList | None
    verifier_now: int = _NOW
    require_dsse: bool = True
    allow_legacy: bool = False


def _make_manifest(bundle_dir: Path) -> bytes:
    manifest = {
        "schema_version": "vcp-v1.2-dsse",
        "bundle_id": "dsse-payload-shape",
        "created_at": "2026-06-11T00:00:00Z",
        "files": {},
        "spec_files": {},
        "cross_refs": {},
        "payload": {},
        "typed_checks": [],
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    (bundle_dir / "manifest.json").write_bytes(manifest_bytes)
    return manifest_bytes


def _seal_with_payload(
    bundle_dir: Path, key: Ed25519PrivateKey, payload_obj
) -> _DsseCtx:
    """Sign an ARBITRARY payload object with an allowlisted key and write the
    sidecar. Returns a verify() DSSE context trusting that key."""
    payload_bytes = rfc8785.dumps(payload_obj)
    sidecar = sign_envelope(payload_bytes, key)
    (bundle_dir / "bundle.dsse.json").write_bytes(
        json.dumps(sidecar, ensure_ascii=False).encode("utf-8")
    )
    pub_raw32 = key.public_key().public_bytes_raw()
    return _DsseCtx(
        allowlist={kid_from_raw32(pub_raw32): pub_raw32},
        revocation_list=RevocationList(
            entries={}, issued_at=_NOW, expires=_NOW + 3600, revocation_list_hash=""
        ),
    )


def _malformed_payloads(manifest_sha: str) -> list:
    """Payloads that are valid JSON + validly signed, but wrong-shape at a
    field the gate dereferences."""
    return [
        # non-object top level → payload.get(...) was an AttributeError
        ["not", "an", "object"],
        "a-bare-string",
        # files as a string → iterating yields chars, f["path"] was TypeError
        {
            "schema_version": "vcp-v1.2-dsse",
            "manifest_sha256": manifest_sha,
            "iat": _NOW,
            "files": "prompt.txt",
        },
        # files as a list of non-objects → f["path"] was TypeError
        {
            "schema_version": "vcp-v1.2-dsse",
            "manifest_sha256": manifest_sha,
            "iat": _NOW,
            "files": ["prompt.txt", "events.jsonl"],
        },
        # files entry missing "path" → f["path"] was KeyError
        {
            "schema_version": "vcp-v1.2-dsse",
            "manifest_sha256": manifest_sha,
            "iat": _NOW,
            "files": [{"sha256": "ab"}],
        },
    ]


def test_signed_malformed_payload_is_structured_reject_not_error(
    tmp_path: Path,
) -> None:
    for i, bad_payload in enumerate(_malformed_payloads("0" * 64)):
        bundle_dir = tmp_path / f"sealed_{i}"
        bundle_dir.mkdir(parents=True, exist_ok=True)
        manifest_bytes = _make_manifest(bundle_dir)
        # Bind the real manifest sha where the payload is otherwise well-shaped,
        # so the ONLY defect is the wrong shape (not a binding mismatch).
        if isinstance(bad_payload, dict) and "manifest_sha256" in bad_payload:
            bad_payload["manifest_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
        key = Ed25519PrivateKey.generate()
        ctx = _seal_with_payload(bundle_dir, key, bad_payload)

        result = BundleVerifier().verify(bundle_dir, dsse=ctx)

        assert result.ok is False, f"payload #{i} must fail closed: {result}"
        # The crux: structured REJECT, NOT a crash-class verifier ERROR.
        assert result.state is VerdictState.REJECT, (
            f"payload #{i}: a signed-but-malformed payload must be a structured "
            f"REJECT, got {result.state} — a malformed artifact is being "
            f"misreported as a verifier fault"
        )
        codes = {r.code for r in result.reasons}
        assert DSSE_MALFORMED_PAYLOAD in codes, (
            f"payload #{i}: expected {DSSE_MALFORMED_PAYLOAD} in {codes}"
        )


def test_signed_well_formed_payload_still_verifies(tmp_path: Path) -> None:
    """Guardrail: the validator does not reject a legitimate signed payload."""
    bundle_dir = tmp_path / "sealed_ok"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    manifest_bytes = _make_manifest(bundle_dir)
    good = {
        "schema_version": "vcp-v1.2-dsse",
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "iat": _NOW,
        "files": [],
    }
    key = Ed25519PrivateKey.generate()
    ctx = _seal_with_payload(bundle_dir, key, good)
    result = BundleVerifier().verify(bundle_dir, dsse=ctx)
    assert result.ok, f"well-formed signed bundle must verify: {result}"
