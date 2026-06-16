"""§C9.1 — Append-only attributed file pinning — schema-reservation + v0.4 plugin test suite.

24 v0.3 tests covering the well-formedness validator
`audit_bundle.extensions.c9_1_append_only_files.validate_append_only_files`:
  - 16 adversarial (A1-A16): the closed v0.3 schema MUST reject.
  - 5 positive   (P1-P5):    the v0.3 schema MUST accept.
  - 3 back-compat (B1-B2 v0.3, B3 v0.4): verifier consumption semantics.

v0.4 EXTENSION (B3 flipped + B4-B8 NEW):
  - B3: round-trip preserves append_only_files (was: drops at v0.3).
  - B4: verifier skips §C9 strict-SHA for declared paths.
  - B5: AppendOnlyAttributedCheck emits AppendOnlyAttributionFailed on zero matches.
  - B6: AppendOnlyAttributedCheck passes on >=1 match.
  - B7: verification_mode == "first_match" stops scanning on first match.
  - B8: verification_mode == "all_attributed" requires every record to carry the key.

Written test-first per `the internal design notes`:
B4-B8 land BEFORE the AppendOnlyAttributedCheck class lands in
`audit_bundle/extensions/c9_1_append_only_files.py`. Initial pytest run MUST fail
B4-B8 with ImportError on `AppendOnlyAttributedCheck` (does not exist at M0). That
confirms broken-first state. sc9_1-002..004 land the plugin + verifier wiring;
B4-B8 flip to passing.

Stdlib-only (json, tempfile, hashlib, pathlib, pytest, dataclasses, audit_bundle.*).
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

import pytest

from audit_bundle.bundle_manifest import (
    AppendOnlySpecMalformed,
    BundleManifest,
)
from audit_bundle.extensions.c9_1_append_only_files import (
    AppendOnlyAttributedCheck,
    ReasonCode,
    validate_append_only_files,
)
from audit_bundle.verifier import BundleVerifier, _load_manifest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _well_formed(path: str = "retrieval_trace_log.jsonl") -> dict:
    """Return a fresh well-formed AppendOnlySpec dict."""
    return {
        "path": path,
        "attribution_key": "trace_id",
        "attribution_plugin": "three_set_sum_invariant",
        "verification_mode": "first_match",
    }


def _assert_one_malformation(spec_tuple: tuple[dict, ...]) -> AppendOnlySpecMalformed:
    """Assert validate_append_only_files returns exactly one malformation; return it."""
    result = validate_append_only_files(spec_tuple)
    assert isinstance(result, list), f"expected list, got {type(result).__name__}"
    assert len(result) == 1, (
        f"expected exactly one malformation; got {len(result)}: {[str(e) for e in result]}"
    )
    err = result[0]
    assert isinstance(err, AppendOnlySpecMalformed), (
        f"expected AppendOnlySpecMalformed, got {type(err).__name__}"
    )
    return err


# ---------------------------------------------------------------------------
# Adversarial — the v0.3 schema contract MUST reject (16 cases)
# ---------------------------------------------------------------------------


def test_A1_entry_not_a_dict() -> None:
    """A1: entry is a list (not a dict) → malformation citing index + type."""
    err = _assert_one_malformation(([1, 2, 3],))
    assert "0" in str(err) and ("list" in str(err) or "dict" in str(err))


def test_A2_missing_path_key() -> None:
    """A2: entry missing required key `path`."""
    spec = _well_formed()
    del spec["path"]
    err = _assert_one_malformation((spec,))
    assert "path" in str(err)


def test_A3_missing_attribution_key() -> None:
    """A3: entry missing required key `attribution_key`."""
    spec = _well_formed()
    del spec["attribution_key"]
    err = _assert_one_malformation((spec,))
    assert "attribution_key" in str(err)


def test_A4_missing_attribution_plugin() -> None:
    """A4: entry missing required key `attribution_plugin`."""
    spec = _well_formed()
    del spec["attribution_plugin"]
    err = _assert_one_malformation((spec,))
    assert "attribution_plugin" in str(err)


def test_A5_missing_verification_mode() -> None:
    """A5: entry missing required key `verification_mode`."""
    spec = _well_formed()
    del spec["verification_mode"]
    err = _assert_one_malformation((spec,))
    assert "verification_mode" in str(err)


def test_A6_path_not_a_string() -> None:
    """A6: `path` is an int (not a string)."""
    spec = _well_formed()
    spec["path"] = 42
    err = _assert_one_malformation((spec,))
    assert "path" in str(err)


def test_A7_path_empty_string() -> None:
    """A7: `path` is an empty string."""
    spec = _well_formed()
    spec["path"] = ""
    err = _assert_one_malformation((spec,))
    assert "path" in str(err)


@pytest.mark.parametrize(
    "absolute_path",
    [
        "/etc/secret",  # POSIX-style absolute
        "C:/Windows/system32/secret",  # Windows-style absolute
    ],
)
def test_A8_path_absolute(absolute_path: str) -> None:
    """A8: `path` is absolute (POSIX `/...` or Windows `[A-Za-z]:...`)."""
    spec = _well_formed()
    spec["path"] = absolute_path
    err = _assert_one_malformation((spec,))
    assert "path" in str(err)


def test_A9_path_contains_traversal() -> None:
    """A9: `path` contains a `..` segment."""
    spec = _well_formed()
    spec["path"] = "logs/../../../etc/passwd"
    err = _assert_one_malformation((spec,))
    assert "path" in str(err)


def test_A10_attribution_key_not_in_enum() -> None:
    """A10: `attribution_key` is not in the reserved enum."""
    spec = _well_formed()
    spec["attribution_key"] = "merkle_leaf"
    err = _assert_one_malformation((spec,))
    assert "attribution_key" in str(err)


def test_A11_attribution_plugin_not_a_string() -> None:
    """A11: `attribution_plugin` is not a string."""
    spec = _well_formed()
    spec["attribution_plugin"] = ["three_set_sum_invariant"]
    err = _assert_one_malformation((spec,))
    assert "attribution_plugin" in str(err)


def test_A12_attribution_plugin_empty_string() -> None:
    """A12: `attribution_plugin` is an empty string."""
    spec = _well_formed()
    spec["attribution_plugin"] = ""
    err = _assert_one_malformation((spec,))
    assert "attribution_plugin" in str(err)


def test_A13_verification_mode_not_in_enum() -> None:
    """A13: `verification_mode` is not in the reserved enum."""
    spec = _well_formed()
    spec["verification_mode"] = "merkle_proof"
    err = _assert_one_malformation((spec,))
    assert "verification_mode" in str(err)


def test_A14_unknown_extra_key() -> None:
    """A14: entry has an unknown extra key (closed schema at v0.3)."""
    spec = _well_formed()
    spec["merkle_root"] = "0xdeadbeef"
    err = _assert_one_malformation((spec,))
    assert "merkle_root" in str(err)


def test_A15_duplicate_path() -> None:
    """A15: two entries with the same `path` in the tuple."""
    a = _well_formed()
    b = _well_formed()
    b["attribution_key"] = "source_cid"
    err = _assert_one_malformation((a, b))
    assert "retrieval_trace_log.jsonl" in str(err) or "duplicate" in str(err).lower()


def test_A16_none_entry() -> None:
    """A16: tuple contains a None entry."""
    err = _assert_one_malformation((None,))
    assert "0" in str(err) and ("None" in str(err) or "dict" in str(err))


# A17-A19: §C9 fail-closed discipline for the error-detail formatter — see
# the [[the internal design notes]] memory. The validator's
# documented contract is "NOT raised — RETURNED" (see validate_append_only_files
# docstring); a TypeError from `sorted()` on mixed-type entry keys would
# violate that contract. Same methodological lesson as the Layer 2 #4 finding
# in the COSE fuzz harness — error-detail formatters must survive adversarial
# dict keys.


def test_A17_missing_branch_with_mixed_type_extras() -> None:
    """A17: entry missing required keys AND carrying mixed-type extra keys.

    Pre-fix: `sorted(entry.keys())` at the missing branch's `observed` slot
    raised TypeError comparing `int` to `str` (mixed-type sort). The fix
    sorts by `repr` so mixed types remain orderable as their string forms.
    """
    spec = ({"path": "foo.txt", 5: "x", (1, 2): "y", b"\xff": "z"},)
    result = validate_append_only_files(spec)
    assert isinstance(result, list)
    assert len(result) >= 1
    assert all(isinstance(m, AppendOnlySpecMalformed) for m in result)


def test_A18_unknown_branch_with_multiple_mixed_type_extras() -> None:
    """A18: full required set present + 2+ mixed-type extra keys.

    Pre-fix: `sorted(unknown)[0]` and `sorted(unknown)` in the unknown-extras
    branch both raised TypeError on multiple mixed-type keys. The fix sorts
    by `repr` so the formatter survives.
    """
    spec = (
        {
            "path": "foo.txt",
            "attribution_key": "trace_id",
            "attribution_plugin": "plug",
            "verification_mode": "first_match",
            5: "a",
            (1, 2): "b",
        },
    )
    result = validate_append_only_files(spec)
    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], AppendOnlySpecMalformed)
    assert "unknown extra key" in str(result[0])


def test_A19_unknown_branch_with_bytes_extras() -> None:
    """A19: bytes-typed extra keys (no UTF-8 decode invariant assumed)."""
    spec = (
        {
            "path": "foo.txt",
            "attribution_key": "trace_id",
            "attribution_plugin": "plug",
            "verification_mode": "first_match",
            b"\xff\xfe": "x",
            b"valid_bytes": "y",
        },
    )
    result = validate_append_only_files(spec)
    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], AppendOnlySpecMalformed)


# ---------------------------------------------------------------------------
# Positive — the v0.3 schema contract MUST accept (5 cases)
# ---------------------------------------------------------------------------


def test_P1_empty_tuple() -> None:
    """P1: empty tuple `()` (W3 + v0.2 baseline) → no malformations."""
    assert validate_append_only_files(()) == []


def test_P2_single_well_formed_entry() -> None:
    """P2: a single well-formed entry → no malformations."""
    assert validate_append_only_files((_well_formed(),)) == []


def test_P3_two_distinct_paths_trace_id_and_source_cid() -> None:
    """P3: two well-formed entries with distinct paths covering trace_id + source_cid."""
    a = _well_formed("retrieval_trace_log.jsonl")
    b = _well_formed("source_attributes/source_properties.jsonl")
    b["attribution_key"] = "source_cid"
    assert validate_append_only_files((a, b)) == []


def test_P4_three_entries_all_reserved_attribution_keys() -> None:
    """P4: three well-formed entries covering trace_id, source_cid, session_id."""
    a = _well_formed("retrieval_trace_log.jsonl")
    b = _well_formed("source_attributes/source_properties.jsonl")
    b["attribution_key"] = "source_cid"
    c = _well_formed("status_events/2026-04-30.jsonl")
    c["attribution_key"] = "session_id"
    assert validate_append_only_files((a, b, c)) == []


def test_P5_verification_mode_all_attributed() -> None:
    """P5: `verification_mode = "all_attributed"` (reserved alternative) → no malformations."""
    spec = _well_formed()
    spec["verification_mode"] = "all_attributed"
    assert validate_append_only_files((spec,)) == []


# ---------------------------------------------------------------------------
# Back-compat / verifier-doesn't-care (3 cases)
# ---------------------------------------------------------------------------


def test_B1_default_empty_tuple_validates() -> None:
    """B1: a BundleManifest with the default `()` validates with no malformations."""
    m = BundleManifest(
        schema_version="vcp-v1.1-canary4",
        bundle_id="b1-default",
        created_at="2026-05-19T00:00:00Z",
        files={},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
        snapshots={},
        fragment_anchors={},
        source_attributes={},
    )
    assert m.append_only_files == ()
    assert validate_append_only_files(m.append_only_files) == []


def _build_minimal_bundle(bundle_dir: Path, payload: bytes, *, tamper: bool) -> str:
    """Materialise a 2-file synthetic bundle (manifest.json + payload.bin) with
    EMPTY append_only_files (W3 / v0.2 / v0.2.1 / pre-v0.4 baseline shape).

    Returns the recorded SHA. If `tamper=True`, payload.bin is rewritten after the
    manifest is computed so that the on-disk SHA diverges from the manifest record.

    v0.4 NOTE (sc9_1-004): with empty append_only_files the v0.4 skip logic is
    a no-op and §C9 strict-SHA is enforced unchanged — this is the load-bearing
    back-compat invariant verified by test_B2_back_compat_*.
    """
    payload_path = bundle_dir / "payload.bin"
    payload_path.write_bytes(payload)
    recorded_sha = hashlib.sha256(payload).hexdigest()
    manifest = {
        "schema_version": "vcp-v1.1-canary4",
        "bundle_id": "b2-minimal",
        "created_at": "2026-05-19T00:00:00Z",
        "files": {"payload.bin": recorded_sha},
        "spec_files": {},
        "cross_refs": {},
        "payload": {},
        "typed_checks": [],
        "snapshots": {},
        "fragment_anchors": {},
        "source_attributes": {},
        # Empty append_only_files — baseline shape. v0.4 skip logic is a no-op
        # for this bundle (back-compat invariant); strict-SHA enforced on every entry.
        "append_only_files": [],
    }
    (bundle_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    if tamper:
        # Mutate payload.bin AFTER manifest is sealed so the §C9 strict-SHA pin
        # fails — exercises that strict-SHA fires when append_only_files is
        # empty (no skip), preserving v0.3 behavior at v0.4.
        payload_path.write_bytes(payload + b"_tampered")
    return recorded_sha


def test_B2_back_compat_empty_append_only_preserves_v03_strict_sha() -> None:
    """B2: LOAD-BEARING BACK-COMPAT BEHAVIORAL TEST (v0.3 -> v0.4 invariant).

    Renamed from `test_B2_verifier_ignores_append_only_files_at_v03` at v0.4
    (sc9_1-001). The v0.3 ignore-semantic is RETIRED — v0.4 consumes the field.
    The new contract this test pins is the PRD's load-bearing back-compat
    invariant (global_constraints item 5): bundles with empty append_only_files
    (W3 / v0.2 / v0.2.1 / pre-v0.4 baseline) verify with NO behavior change.

    Construct a synthetic bundle where `payload.bin` is pinned in
    `manifest.files` and append_only_files is EMPTY:
      - clean bundle: verifies (ok=True; back-compat).
      - tampered bundle: fails on file_integrity / bad_file_sha (back-compat —
        v0.4 skip logic is a no-op when append_only_files is empty, so strict-SHA
        still fires).
    """
    payload = b"hello v0.4 back-compat invariant\n"

    # (a) clean bundle verifies — empty append_only_files preserves v0.3 pass.
    with tempfile.TemporaryDirectory() as td:
        bundle_dir = Path(td) / "bundle"
        bundle_dir.mkdir()
        _build_minimal_bundle(bundle_dir, payload, tamper=False)
        result = BundleVerifier().verify(bundle_dir)
        assert result.ok is True, (
            f"clean baseline bundle (empty append_only_files) must verify; "
            f"failures={result.failures}"
        )

    # (b) tampered bundle fails on file_integrity — declaration has NO effect
    with tempfile.TemporaryDirectory() as td:
        bundle_dir = Path(td) / "bundle"
        bundle_dir.mkdir()
        _build_minimal_bundle(bundle_dir, payload, tamper=True)
        result = BundleVerifier().verify(bundle_dir)
        assert result.ok is False, (
            "tampered bundle MUST fail at v0.3 — append_only_files is schema-only, "
            "verifier ignores it and continues §C9 strict-SHA enforcement"
        )
        check_names = {f.check_name for f in result.failures}
        assert "file_integrity" in check_names, (
            f"expected file_integrity failure; got {check_names}"
        )


def test_B3_round_trip_preserves_append_only_files_at_v04() -> None:
    """B3: a manifest serialized with `append_only_files` set reloads with the tuple preserved at v0.4.

    v0.3 SEMANTIC (RETIRED): roundtrip DROPPED to () because _load_manifest ignored the key.
    v0.4 SEMANTIC (ACTIVE):  roundtrip PRESERVES the tuple — _load_manifest reads
    `raw.get("append_only_files", [])` and converts the list-of-dicts to a tuple-of-dicts.

    Renamed from `test_B3_round_trip_drops_append_only_files_at_v03` (PRD sc9_1-001).
    """
    # UPDATED 2026-06-01 (Design 2 + §C9.1 disjointness, default_plus_deepseek
    # tribunal): the declared append_only path must NOT also be pinned in
    # manifest.files (append_only overrides strict-SHA, so an overlap would be
    # rejected by the disjointness guard in _load_manifest). The 2026-05-26 PoC4
    # pin rule that forced `payload.bin` into BOTH sets has been removed; the
    # round-trip intent — _load_manifest preserves the tuple at v0.4 — is
    # unchanged and is now exercised on a DISJOINT declaration, matching the real
    # §C9.1 shape (declare instead of pinning the SHA).
    declared = (
        {
            "path": "retrieval_trace_log.jsonl",
            "attribution_key": "trace_id",
            "attribution_plugin": "three_set_sum_invariant",
            "verification_mode": "first_match",
        },
    )
    with tempfile.TemporaryDirectory() as td:
        bundle_dir = Path(td) / "bundle"
        bundle_dir.mkdir()
        payload = b"round-trip test\n"
        payload_sha = hashlib.sha256(payload).hexdigest()
        (bundle_dir / "payload.bin").write_bytes(payload)
        manifest = {
            "schema_version": "vcp-v1.1-canary4",
            "bundle_id": "b3-round-trip",
            "created_at": "2026-05-19T00:00:00Z",
            "files": {"payload.bin": payload_sha},
            "spec_files": {},
            "cross_refs": {},
            "payload": {},
            "typed_checks": [],
            "snapshots": {},
            "fragment_anchors": {},
            "source_attributes": {},
            "append_only_files": [dict(d) for d in declared],
        }
        (bundle_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )

        # v0.4: _load_manifest reads the key and preserves the declarations.
        loaded = _load_manifest(bundle_dir)
        assert loaded.append_only_files == declared, (
            "v0.4 _load_manifest must preserve append_only_files; "
            f"got {loaded.append_only_files!r}, expected {declared!r}"
        )


# ---------------------------------------------------------------------------
# v0.4 plugin contract (B4-B8) — broken-first per
# `the internal design notes`.
# Run pytest BEFORE sc9_1-002 lands — expect B4-B8 to fail with ImportError or
# AttributeError on `AppendOnlyAttributedCheck` (does not exist at M0). That
# confirms broken-first state. sc9_1-002..004 land the plugin + verifier wiring;
# B4-B8 flip to passing.
# ---------------------------------------------------------------------------


def _build_bundle_with_append_only(
    bundle_dir: Path,
    *,
    file_path: str,
    file_bytes: bytes,
    declared_sha: str,
    append_only_specs: list[dict],
) -> None:
    """Materialise a synthetic bundle that declares `file_path` in BOTH manifest.files
    (with `declared_sha`) AND `append_only_files` (with the given specs).

    Caller controls whether `declared_sha` matches the on-disk SHA (passes the
    string explicitly so callers can deliberately tamper).
    """
    (bundle_dir / file_path).parent.mkdir(parents=True, exist_ok=True)
    (bundle_dir / file_path).write_bytes(file_bytes)
    manifest = {
        "schema_version": "vcp-v1.1-canary4",
        "bundle_id": "b-plugin-test",
        "created_at": "2026-05-26T00:00:00Z",
        "files": {file_path: declared_sha},
        "spec_files": {},
        "cross_refs": {},
        "payload": {},
        "typed_checks": [],
        "snapshots": {},
        "fragment_anchors": {},
        "source_attributes": {},
        "append_only_files": append_only_specs,
    }
    (bundle_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )


def _jsonl_bytes(records: list[dict]) -> bytes:
    """Serialise a list of dicts to JSONL bytes (one JSON object per line)."""
    return ("\n".join(json.dumps(r, sort_keys=True) for r in records) + "\n").encode(
        "utf-8"
    )


def test_B4_verifier_skips_declared_path_at_v04() -> None:
    """B4: bundle declares `append_only_files = [<spec for foo.jsonl>]`; manifest.files
    entry for `foo.jsonl` has a WRONG sha; v0.4 verifier MUST NOT emit
    file_integrity / bad_file_sha for that path (skip logic active).

    Back-compat: bundles with `append_only_files == []` MUST still emit
    file_integrity / bad_file_sha on wrong sha (covered by test_B2).
    """
    records = [{"trace_id": "t-001", "value": 42}]
    on_disk_bytes = _jsonl_bytes(records)
    wrong_sha = "0" * 64  # deliberately incorrect

    spec = {
        "path": "foo.jsonl",
        "attribution_key": "trace_id",
        "attribution_plugin": "three_set_sum_invariant",
        "verification_mode": "first_match",
    }

    with tempfile.TemporaryDirectory() as td:
        bundle_dir = Path(td) / "bundle"
        bundle_dir.mkdir()
        _build_bundle_with_append_only(
            bundle_dir,
            file_path="foo.jsonl",
            file_bytes=on_disk_bytes,
            declared_sha=wrong_sha,
            append_only_specs=[spec],
        )
        result = BundleVerifier().verify(bundle_dir)
        check_names = {f.check_name for f in result.failures}
        assert "file_integrity" not in check_names, (
            f"v0.4 verifier must SKIP §C9 strict-SHA for declared path; "
            f"got failures: {[(f.check_name, f.reason_code, f.detail) for f in result.failures]}"
        )


def _in_memory_manifest(append_only_specs: tuple[dict, ...]) -> BundleManifest:
    """Construct a minimal in-memory BundleManifest with the given append_only_files.

    Used by B5-B8 to test the AppendOnlyAttributedCheck plugin standalone,
    bypassing _load_manifest (which only preserves append_only_files at v0.4
    once sc9_1-003 lands). The plugin's contract is in-memory: it consumes
    `manifest.append_only_files` directly, so in-memory construction validates
    the plugin contract independent of verifier-integration order.
    """
    return BundleManifest(
        schema_version="vcp-v1.1-canary4",
        bundle_id="b-plugin-test",
        created_at="2026-05-26T00:00:00Z",
        files={},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
        snapshots={},
        fragment_anchors={},
        source_attributes={},
        append_only_files=append_only_specs,
    )


def test_B5_append_only_attributed_check_emits_attribution_failed_on_zero_matches() -> None:
    """B5: declared entry's file has 0 records carrying the attribution_key; plugin
    MUST emit `AppendOnlyAttributionFailed`. Distinct from file_integrity / bad_file_sha.

    Standalone test: uses in-memory BundleManifest construction so it passes
    against sc9_1-002 plugin landing (BEFORE sc9_1-003 wires _load_manifest).
    """
    # All records lack 'trace_id' — zero matches under attribution_key.
    records = [{"value": 1}, {"value": 2}]
    file_bytes = _jsonl_bytes(records)

    spec = {
        "path": "foo.jsonl",
        "attribution_key": "trace_id",
        "attribution_plugin": "three_set_sum_invariant",
        "verification_mode": "first_match",
    }

    with tempfile.TemporaryDirectory() as td:
        bundle_dir = Path(td) / "bundle"
        bundle_dir.mkdir()
        (bundle_dir / "foo.jsonl").write_bytes(file_bytes)
        manifest = _in_memory_manifest((spec,))
        check = AppendOnlyAttributedCheck()
        failures = check.check(bundle_dir, manifest)
        reason_codes = [f.reason_code for f in failures]
        assert ReasonCode.AppendOnlyAttributionFailed in reason_codes, (
            f"expected AppendOnlyAttributionFailed in failures; got reason_codes={reason_codes}"
        )


def test_B6_append_only_attributed_check_passes_on_one_match() -> None:
    """B6: declared entry's file has >=1 record carrying the attribution_key; plugin
    MUST pass (no reason code for this entry).

    Standalone test: in-memory BundleManifest.
    """
    records = [
        {"value": 1},
        {"trace_id": "t-001", "value": 2},  # one match — enough for first_match
        {"value": 3},
    ]
    file_bytes = _jsonl_bytes(records)

    spec = {
        "path": "foo.jsonl",
        "attribution_key": "trace_id",
        "attribution_plugin": "three_set_sum_invariant",
        "verification_mode": "first_match",
    }

    with tempfile.TemporaryDirectory() as td:
        bundle_dir = Path(td) / "bundle"
        bundle_dir.mkdir()
        (bundle_dir / "foo.jsonl").write_bytes(file_bytes)
        manifest = _in_memory_manifest((spec,))
        check = AppendOnlyAttributedCheck()
        failures = check.check(bundle_dir, manifest)
        assert failures == [], (
            f"expected empty failure list on >=1 match; got {[(f.reason_code, f.detail) for f in failures]}"
        )


def test_B7_verification_mode_first_match_returns_on_first() -> None:
    """B7: verification_mode == "first_match" — plugin scans only until the first
    match (matches capture.py:131-132 load_trace semantics: stop at first match).

    Observable test: a file with the first record matching AND a later record
    LACKING the key. In all_attributed mode this would emit Partial; in
    first_match mode the early-exit means the second record is never inspected
    and the plugin passes.

    Standalone test: in-memory BundleManifest.
    """
    # Line 1: matches. Line 2: would fail all_attributed (no trace_id) but
    # first_match exits on line 1 so it's never inspected.
    records = [
        {"trace_id": "t-001", "value": 1},
        {"value": 2},  # would trigger Partial under all_attributed
    ]
    file_bytes = _jsonl_bytes(records)

    spec = {
        "path": "foo.jsonl",
        "attribution_key": "trace_id",
        "attribution_plugin": "three_set_sum_invariant",
        "verification_mode": "first_match",
    }

    with tempfile.TemporaryDirectory() as td:
        bundle_dir = Path(td) / "bundle"
        bundle_dir.mkdir()
        (bundle_dir / "foo.jsonl").write_bytes(file_bytes)
        manifest = _in_memory_manifest((spec,))
        check = AppendOnlyAttributedCheck()
        failures = check.check(bundle_dir, manifest)
        # first_match found the key on line 1; the missing-key line 2 was
        # never inspected, so the plugin passes.
        assert failures == [], (
            f"first_match must early-exit on first match; got failures={[(f.reason_code, f.detail) for f in failures]}"
        )


def test_B8_verification_mode_all_attributed_requires_every_record() -> None:
    """B8: verification_mode == "all_attributed" — plugin walks EVERY record and
    requires every record to carry the attribution_key. Returns
    `AppendOnlyAttributionPartial` if any record lacks the key.

    (Stricter v0.4+ mode; v0.3 default = first_match for back-compat.)

    Standalone test: in-memory BundleManifest.
    """
    records = [
        {"trace_id": "t-001", "value": 1},
        {"value": 2},  # lacks trace_id — should trigger Partial
        {"trace_id": "t-003", "value": 3},
    ]
    file_bytes = _jsonl_bytes(records)

    spec = {
        "path": "foo.jsonl",
        "attribution_key": "trace_id",
        "attribution_plugin": "three_set_sum_invariant",
        "verification_mode": "all_attributed",
    }

    with tempfile.TemporaryDirectory() as td:
        bundle_dir = Path(td) / "bundle"
        bundle_dir.mkdir()
        (bundle_dir / "foo.jsonl").write_bytes(file_bytes)
        manifest = _in_memory_manifest((spec,))
        check = AppendOnlyAttributedCheck()
        failures = check.check(bundle_dir, manifest)
        reason_codes = [f.reason_code for f in failures]
        assert ReasonCode.AppendOnlyAttributionPartial in reason_codes, (
            "all_attributed must emit AppendOnlyAttributionPartial when any "
            f"record lacks the attribution_key; got reason_codes={reason_codes}"
        )


# ---------------------------------------------------------------------------
# BLOCK-01 — Append-only symlink dereference / FIFO hang after floor reject.
#
# The §C9.2 floor lstat-rejects a symlink/FIFO/non-regular object at a declared
# append-only path, but AppendOnlyAttributedCheck used to raw-open
# ``bundle_dir / rel_path`` regardless: it FOLLOWED a symlink to host state
# (host-state-dependent verdict / out-of-bundle read) and BLOCKED forever on a
# FIFO with no writer (DoS before any verdict). The check is standalone-
# callable, so it must fail closed on its own — not on the assumption the floor
# ran first. These regressions pin: (a) no host-state follow, (b) no hang.
# ---------------------------------------------------------------------------

_AO_SPEC = {
    "path": "retrieval_trace_log.jsonl",
    "attribution_key": "trace_id",
    "attribution_plugin": "retrieval",
    "verification_mode": "first_match",
}


def test_block01_rejects_symlink_to_external_file() -> None:
    """A declared append-only path that is a symlink to a file OUTSIDE the
    bundle must be rejected, never followed — even though the external file
    carries a matching attribution_key (which would otherwise pass)."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        bundle = root / "bundle"
        bundle.mkdir()
        external = root / "host_state.jsonl"
        external.write_text(json.dumps({"trace_id": "FROM-HOST"}) + "\n")
        (bundle / "retrieval_trace_log.jsonl").symlink_to(external)

        failures = AppendOnlyAttributedCheck().check(bundle, _in_memory_manifest((_AO_SPEC,)))
        assert failures, "symlink-to-external must NOT pass on host-state bytes"
        assert failures[0].reason_code == ReasonCode.AppendOnlyAttributionFailed


def test_block01_rejects_symlink_to_internal_file() -> None:
    """Append-only files are not SHA-pinned, so even an IN-TREE symlink must be
    refused at the read (O_NOFOLLOW): the check must read the declared object,
    not a link's target. (The strict-SHA walk tolerates in-tree symlinks; this
    surface deliberately does not.)"""
    with tempfile.TemporaryDirectory() as td:
        bundle = Path(td) / "bundle"
        bundle.mkdir()
        (bundle / "real.jsonl").write_text(json.dumps({"trace_id": "X"}) + "\n")
        (bundle / "retrieval_trace_log.jsonl").symlink_to(bundle / "real.jsonl")

        failures = AppendOnlyAttributedCheck().check(bundle, _in_memory_manifest((_AO_SPEC,)))
        assert failures, "in-tree symlink at an append-only path must be refused"


def test_block01_fifo_does_not_hang(tmp_path: Path) -> None:
    """A FIFO at a declared append-only path must fail closed WITHOUT blocking.
    Run on a worker thread with a hard join timeout: a regression that reaches a
    blocking open() leaves the thread alive and fails the assert (rather than
    hanging the suite)."""
    import os
    import threading

    bundle = tmp_path / "bundle"
    bundle.mkdir()
    os.mkfifo(bundle / "retrieval_trace_log.jsonl")

    box: dict[str, object] = {}
    done = threading.Event()

    def run() -> None:
        box["failures"] = AppendOnlyAttributedCheck().check(
            bundle, _in_memory_manifest((_AO_SPEC,))
        )
        done.set()

    threading.Thread(target=run, daemon=True).start()
    assert done.wait(timeout=5.0), "AppendOnlyAttributedCheck HUNG on a FIFO"
    assert box["failures"], "FIFO at an append-only path must fail closed"


def test_block01_rejects_symlink_to_fifo_no_hang(tmp_path) -> None:
    """A declared append-only path that is a symlink whose target is a FIFO:
    must fail closed without blocking (O_NOFOLLOW rejects the link before the
    FIFO could be opened)."""
    import os
    import threading

    bundle = tmp_path / "bundle"
    bundle.mkdir()
    os.mkfifo(bundle / "real.fifo")
    (bundle / "retrieval_trace_log.jsonl").symlink_to(bundle / "real.fifo")

    box: dict = {}
    done = threading.Event()

    def run() -> None:
        box["failures"] = AppendOnlyAttributedCheck().check(
            bundle, _in_memory_manifest((_AO_SPEC,))
        )
        done.set()

    threading.Thread(target=run, daemon=True).start()
    assert done.wait(timeout=5.0), "check HUNG on a symlink-to-FIFO append-only path"
    assert box["failures"], "symlink-to-FIFO at an append-only path must fail closed"


def test_block01_opener_toctou_fifo_swap_no_hang(tmp_path) -> None:
    """The append-only stream opener is the per-read TOCTOU guard: if the
    declared regular file is swapped for a FIFO before the read, the open must
    raise (O_NONBLOCK + fstat), never block. Opening a FIFO directly is the
    deterministic stand-in for that race."""
    import os
    import threading

    from audit_bundle.extensions.c9_1_append_only_files import _open_contained_text

    os.mkfifo(tmp_path / "swapped")

    box: dict = {}
    done = threading.Event()

    def run() -> None:
        try:
            _open_contained_text(tmp_path / "swapped")
        except OSError as exc:
            box["exc"] = exc
        done.set()

    threading.Thread(target=run, daemon=True).start()
    assert done.wait(timeout=5.0), "_open_contained_text HUNG on a FIFO (TOCTOU swap)"
    assert isinstance(box.get("exc"), OSError)
