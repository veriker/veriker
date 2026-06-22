"""Fuzzing round 2 — parse-boundary type-confusion regression for BundleVerifier.

BundleVerifier.verify() contracts that it NEVER raises: every failure mode must
surface as a collected VerifyFailure so an adversarial manifest can crash neither
the reference verifier (a DoS / fail-stop) nor sneak past it (a fail-open). These
cases were hand-found by feeding type-confused manifest.json values to verify()
before any coverage-guided fuzzer; all of them raised an uncaught AttributeError
(or FileNotFoundError / JSONDecodeError) until the parse-boundary guard
(_validate_manifest_shape + MalformedManifest collection) was added.

Root cause: _load_manifest deserialized manifest.json with presence-only checks
(raw.get with defaults) but no type validation, while the 4-step integrity walk
dereferences .items() on files/spec_files/cross_refs and .lower() on their SHA
values. Wrong JSON types therefore escaped as exceptions.

Oracle (cheap, mechanical): verify() must return a VerifyResult and must not
raise. For malformed input it must additionally report ok=False. This is the
shallow tier (parse-boundary). The catastrophic tier — a mutated-signature
bundle that verify() wrongly ACCEPTS — belongs to the COSE-envelope fuzz
harness, which lives alongside this file in tests/fuzz/ (see
atheris_verify_cose_*.py). Until 2026-05-26 the docstring claimed the COSE
harness already existed; it did not. The hand-crafted Stream A red-team
PoCs under redteam/streamA_cose/ covered specific thought-of attacks; the
coverage-guided harness is the unknown-unknown complement.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from audit_bundle.bundle_manifest import (
    BundleManifest,
    MalformedManifest,
    validate_manifest,
)
from audit_bundle.verifier import (
    BundleVerifier,
    VerifyResult,
    _load_manifest,
)


def _bundle(
    tmp_path: Path, *, manifest_text: str | None, files: dict[str, bytes] | None = None
) -> Path:
    """Write a minimal bundle dir; manifest_text=None means omit manifest.json."""
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    if manifest_text is not None:
        (bundle / "manifest.json").write_text(manifest_text)
    for name, content in (files or {}).items():
        fp = bundle / name
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_bytes(content)
    return bundle


# (case_id, manifest_text or None, extra_files) — every one must be rejected, not crash.
MALFORMED_CASES: list[tuple[str, str | None, dict[str, bytes]]] = [
    ("files_is_list", json.dumps({"files": ["a.txt", "b.txt"]}), {}),
    ("files_is_str", json.dumps({"files": "not-a-dict"}), {}),
    ("spec_files_is_list", json.dumps({"files": {}, "spec_files": ["x"]}), {}),
    ("cross_refs_is_list", json.dumps({"files": {}, "cross_refs": ["x"]}), {}),
    # SHA values dereferenced via .lower(); file must be present to reach that line
    ("sha_value_is_int", json.dumps({"files": {"a.txt": 12345}}), {"a.txt": b"hi"}),
    ("sha_value_is_null", json.dumps({"files": {"a.txt": None}}), {"a.txt": b"hi"}),
    (
        "file_key_is_nonstr_via_str",
        json.dumps({"files": {"a.txt": ["nested"]}}),
        {"a.txt": b"hi"},
    ),
    ("typed_checks_is_dict", json.dumps({"files": {}, "typed_checks": {"k": "v"}}), {}),
    ("typed_checks_entry_is_int", json.dumps({"files": {}, "typed_checks": [123]}), {}),
    ("top_level_is_array", "[1, 2, 3]", {}),
    ("top_level_is_string", '"just a string"', {}),
    ("not_valid_json", "{not valid json", {}),
    ("empty_file", "", {}),
    ("manifest_absent", None, {}),
]


@pytest.mark.parametrize(
    "case_id,manifest_text,extra_files",
    MALFORMED_CASES,
    ids=[c[0] for c in MALFORMED_CASES],
)
def test_malformed_manifest_is_rejected_not_crashed(
    tmp_path: Path,
    case_id: str,
    manifest_text: str | None,
    extra_files: dict[str, bytes],
) -> None:
    """verify() must reject every malformed manifest as a collected failure, never raise."""
    bundle = _bundle(tmp_path, manifest_text=manifest_text, files=extra_files)

    result = BundleVerifier().verify(bundle)  # must not raise

    assert isinstance(result, VerifyResult), (
        f"{case_id}: verify() returned non-VerifyResult"
    )
    assert result.ok is False, f"{case_id}: malformed manifest was accepted (ok=True)"
    assert result.failures, f"{case_id}: rejected with no failure recorded"
    assert result.failures[0].reason_code == "malformed_manifest", (
        f"{case_id}: expected reason_code=malformed_manifest, "
        f"got {result.failures[0].reason_code!r}"
    )


@pytest.mark.parametrize(
    "case_id,manifest_text,extra_files",
    MALFORMED_CASES,
    ids=[c[0] for c in MALFORMED_CASES],
)
def test_load_manifest_raises_typed_error(
    tmp_path: Path,
    case_id: str,
    manifest_text: str | None,
    extra_files: dict[str, bytes],
) -> None:
    """The parse boundary raises the one typed exception verify() knows to collect."""
    bundle = _bundle(tmp_path, manifest_text=manifest_text, files=extra_files)
    with pytest.raises(MalformedManifest):
        _load_manifest(bundle)


def test_well_typed_empty_manifest_still_verifies(tmp_path: Path) -> None:
    """Guard must not reject a well-typed manifest: shape check is necessary, not sufficient-blocking."""
    bundle = _bundle(
        tmp_path,
        manifest_text=json.dumps(
            {"schema_version": "vcp-v1.1-canary4", "files": {}, "spec_files": {}, "cross_refs": {}}
        ),
    )
    result = BundleVerifier().verify(bundle)
    assert result.ok is True, (
        f"well-typed empty manifest wrongly rejected: {result.failures}"
    )


# ---------------------------------------------------------------------------
# Twin path: validate_manifest() shares the same field-shape guard. A
# BundleManifest can be constructed directly with wrong field types (the
# dataclass does not enforce annotations), e.g. by a programmatic caller or
# test helper; validate_manifest must reject it rather than crash on .items().
# ---------------------------------------------------------------------------


def _manifest(**overrides) -> BundleManifest:
    base = dict(
        schema_version="legacy",
        bundle_id="b",
        created_at="2026-01-01T00:00:00Z",
        files={},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
    )
    base.update(overrides)
    return BundleManifest(**base)


TWIN_BAD_FIELDS = [
    ("files_is_list", {"files": ["a.txt"]}),
    ("spec_files_is_str", {"spec_files": "nope"}),
    ("cross_refs_is_int", {"cross_refs": 7}),
    ("sha_value_is_int", {"files": {"a.txt": 123}}),
    ("typed_checks_is_dict", {"typed_checks": {"k": "v"}}),
    ("typed_checks_entry_is_none", {"typed_checks": [None]}),
]


@pytest.mark.parametrize(
    "case_id,overrides", TWIN_BAD_FIELDS, ids=[c[0] for c in TWIN_BAD_FIELDS]
)
def test_validate_manifest_rejects_bad_field_shapes(
    tmp_path: Path, case_id: str, overrides: dict
) -> None:
    """validate_manifest must raise MalformedManifest (a ManifestError) — not AttributeError."""
    m = _manifest(**overrides)
    with pytest.raises(MalformedManifest):
        validate_manifest(m, tmp_path)


def test_validate_manifest_accepts_well_typed(tmp_path: Path) -> None:
    """Shape guard must not reject a well-typed empty manifest on the validate_manifest path."""
    validate_manifest(_manifest(), tmp_path)  # must not raise
