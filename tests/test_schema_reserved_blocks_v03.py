"""v0.3 schema-reserved-block fail-closed regressions (PoC4 TARGET 4).

Lock down `_validate_schema_reserved_blocks_v03` against the confused-deputy
class PoC4 TARGET 4 demonstrated 2026-05-26: the verifier loaded
`attested_serving` / `semantic_fidelity` / `rigor_profile` / `append_only_files`
from manifest.json without enforcing what they may contain, so a post-build
editor could inject any payload and the bundle still verified GREEN. A
downstream consumer treating the verified bundle as "these manifest fields are
authoritative" then trusted attacker bytes.

The fix (audit_bundle/bundle_manifest.py:_validate_schema_reserved_blocks_v03)
enforces per-field rules at the parse boundary, raising MalformedManifest
collected by verify() as a VerifyFailure.

PoC4 owns the three markers that have no other validator (attested_serving,
semantic_fidelity, rigor_profile). `append_only_files` is owned end-to-end by
§C9.1 (`validate_append_only_files` closed schema at parse + AppendOnlyAttributed
Check attribution at verify); PoC4's former path-pinning rule was removed once
that v0.4 machinery landed — declaring a path "instead of pinning its SHA" is the
intended §C9.1 design, so unpinned-but-attributed paths are now accepted. This
suite covers:
  - the three marker PoC4 attacker payloads must all reject
  - the canonical reservation markers (eidas pilot, test_B2 fixture) must accept
  - boundary cases (mode-string substitution, reserved_for_v0_4=False, extra keys)
  - append_only_files: §C9.1 closed-schema rejection of fabricated/lightweight
    entries; acceptance of well-formed entries whether or not path-pinned
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from audit_bundle.bundle_manifest import MalformedManifest
from audit_bundle.verifier import _load_manifest


_BASE_MANIFEST = {
    "schema_version": "vcp-v1.1-canary4",
    "bundle_id": "schema-reserved-test",
    "created_at": "2026-05-26T00:00:00Z",
    "files": {},
    "spec_files": {},
    "cross_refs": {},
    "payload": {},
    "typed_checks": [],
}


def _write_manifest(tmp_path: Path, **extra) -> Path:
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    manifest = {**_BASE_MANIFEST, **extra}
    (bundle_dir / "manifest.json").write_bytes(
        json.dumps(manifest).encode("utf-8")
    )
    return bundle_dir


# ---------------------------------------------------------------------------
# attested_serving — accept the canonical marker; reject anything else.
# ---------------------------------------------------------------------------


def test_attested_serving_accepts_canonical_marker(tmp_path):
    bundle_dir = _write_manifest(
        tmp_path,
        attested_serving={
            "mode": "attested-serving-environment",
            "reserved_for_v0_4": True,
        },
    )
    m = _load_manifest(bundle_dir)
    assert m.attested_serving == {
        "mode": "attested-serving-environment",
        "reserved_for_v0_4": True,
    }


def test_attested_serving_accepts_minimal_marker_without_mode(tmp_path):
    bundle_dir = _write_manifest(
        tmp_path, attested_serving={"reserved_for_v0_4": True}
    )
    m = _load_manifest(bundle_dir)
    assert m.attested_serving == {"reserved_for_v0_4": True}


def test_attested_serving_accepts_absence(tmp_path):
    bundle_dir = _write_manifest(tmp_path)
    m = _load_manifest(bundle_dir)
    assert m.attested_serving is None


def test_attested_serving_rejects_poc4_attacker_payload(tmp_path):
    """The exact payload from PoC4 TARGET 4 — must reject."""
    bundle_dir = _write_manifest(
        tmp_path,
        attested_serving={
            "tee_vendor": "Intel TDX",
            "measurement": "ATTACKER-FABRICATED-MEASUREMENT",
            "attested_at": "2099-01-01T00:00:00Z",
            "claim": "model weights attested uncompromised",
        },
    )
    with pytest.raises(MalformedManifest, match="attested_serving"):
        _load_manifest(bundle_dir)


def test_attested_serving_rejects_marker_with_attacker_mode_string(tmp_path):
    """Tightening test: attacker includes `reserved_for_v0_4=True` (passes the
    obvious check) but substitutes `mode` with arbitrary content. The mode
    value is constrained to the canonical string."""
    bundle_dir = _write_manifest(
        tmp_path,
        attested_serving={
            "mode": "attacker-controlled-mode-string",
            "reserved_for_v0_4": True,
        },
    )
    with pytest.raises(MalformedManifest, match="attested_serving"):
        _load_manifest(bundle_dir)


def test_attested_serving_rejects_marker_with_reserved_false(tmp_path):
    bundle_dir = _write_manifest(
        tmp_path,
        attested_serving={"reserved_for_v0_4": False, "mode": "x"},
    )
    with pytest.raises(MalformedManifest, match="attested_serving"):
        _load_manifest(bundle_dir)


def test_attested_serving_rejects_extra_keys_alongside_marker(tmp_path):
    """Attacker keeps the marker but adds an exfiltrated-claim sidecar."""
    bundle_dir = _write_manifest(
        tmp_path,
        attested_serving={
            "reserved_for_v0_4": True,
            "claim": "attacker side-channel content",
        },
    )
    with pytest.raises(MalformedManifest, match="attested_serving"):
        _load_manifest(bundle_dir)


def test_attested_serving_rejects_non_dict(tmp_path):
    bundle_dir = _write_manifest(tmp_path, attested_serving="just a string")
    with pytest.raises(MalformedManifest, match="attested_serving"):
        _load_manifest(bundle_dir)


# ---------------------------------------------------------------------------
# semantic_fidelity — exact-match canonical marker only.
# ---------------------------------------------------------------------------


def test_semantic_fidelity_accepts_canonical_marker(tmp_path):
    bundle_dir = _write_manifest(
        tmp_path, semantic_fidelity={"reserved_for_v0_4": True}
    )
    m = _load_manifest(bundle_dir)
    assert m.semantic_fidelity == {"reserved_for_v0_4": True}


def test_semantic_fidelity_rejects_poc4_attacker_payload(tmp_path):
    bundle_dir = _write_manifest(
        tmp_path,
        semantic_fidelity={
            "nli_label": "ENTAILMENT",
            "contradiction_score": 0.0,
            "note": "ATTACKER claims output fully entailed by sources",
        },
    )
    with pytest.raises(MalformedManifest, match="semantic_fidelity"):
        _load_manifest(bundle_dir)


def test_semantic_fidelity_rejects_marker_with_extras(tmp_path):
    bundle_dir = _write_manifest(
        tmp_path,
        semantic_fidelity={
            "reserved_for_v0_4": True,
            "side_channel": "attacker bytes",
        },
    )
    with pytest.raises(MalformedManifest, match="semantic_fidelity"):
        _load_manifest(bundle_dir)


# ---------------------------------------------------------------------------
# rigor_profile — must be absent at v0.3.
# ---------------------------------------------------------------------------


def test_rigor_profile_accepts_absence(tmp_path):
    bundle_dir = _write_manifest(tmp_path)
    m = _load_manifest(bundle_dir)
    assert m.rigor_profile is None


def test_rigor_profile_rejects_poc4_attacker_payload(tmp_path):
    bundle_dir = _write_manifest(
        tmp_path,
        rigor_profile={
            "profile": "regulated-high-assurance",
            "note": "ATTACKER upgraded rigor tier",
        },
    )
    with pytest.raises(MalformedManifest, match="rigor_profile"):
        _load_manifest(bundle_dir)


def test_rigor_profile_rejects_even_well_meaning_content(tmp_path):
    """No legit v0.3 producer populates this — even legitimate-looking content
    must reject until the v0.4 validator ships."""
    bundle_dir = _write_manifest(
        tmp_path, rigor_profile={"tier": "auditor-baseline"}
    )
    with pytest.raises(MalformedManifest, match="rigor_profile"):
        _load_manifest(bundle_dir)


# ---------------------------------------------------------------------------
# append_only_files — owned by §C9.1 (closed schema + attribution), NOT by
# PoC4 path-pinning. See _validate_schema_reserved_blocks_v03's append_only_files
# note for why the v0.3 path-pinning rule was removed once the §C9.1 v0.4
# machinery (validate_append_only_files + AppendOnlyAttributedCheck) landed.
# ---------------------------------------------------------------------------


def test_append_only_files_lightweight_shape_rejected_post_c9_1(tmp_path):
    """A lightweight `{path, spec_version}` entry is REJECTED — fabricated /
    attribution-less declarations cannot slip through.

    The rejection comes from §C9.1's closed per-entry schema
    (`validate_append_only_files`, wired in verifier._load_manifest): exactly
    `{path, attribution_key, attribution_plugin, verification_mode}` is required,
    unknown/missing keys reject. PoC4 no longer path-pins append_only_files (the
    §C9.1 machinery owns them end-to-end), so this entry being pinned or not is
    irrelevant — it is rejected for missing the required attribution keys. This
    is the surviving half of PoC4's confused-deputy guarantee at the parse
    boundary; the other half (a well-formed entry pointing at a non-attributed
    file) is caught at verify time by AppendOnlyAttributedCheck."""
    bundle_dir = _write_manifest(
        tmp_path,
        files={"audit_trail.jsonl": "ab" * 32},
        append_only_files=[
            {"path": "audit_trail.jsonl", "spec_version": "c9.1-v1"}
        ],
    )
    # Rejected by the §C9.1 closed schema (missing attribution_key et al.).
    with pytest.raises(MalformedManifest):
        _load_manifest(bundle_dir)


def test_append_only_files_rejects_pinned_overlap(tmp_path):
    """§C9.1 disjointness (default_plus_deepseek tribunal hardening): a path
    declared in append_only_files must NOT also be a key in manifest.files.

    _step_file_integrity unconditionally SKIPS append_only paths from strict-SHA,
    so an overlap silently downgrades a byte-pinned file to attribution-only
    integrity and leaves a never-enforced, stale SHA in files{}. The entry below
    is a well-formed §C9.1 spec — it would have been accepted before the
    disjointness guard — but its path IS pinned in files{}, so _load_manifest must
    reject it. §C9.1 step (d) declares append_only paths INSTEAD of pinning their
    SHA, so no legitimate bundle overlaps (the mesh pilot emits disjoint sets)."""
    bundle_dir = _write_manifest(
        tmp_path,
        files={"payload.bin": "cd" * 32},
        append_only_files=[
            {
                "path": "payload.bin",
                "attribution_key": "trace_id",
                "attribution_plugin": "three_set_sum_invariant",
                "verification_mode": "first_match",
            }
        ],
    )
    with pytest.raises(MalformedManifest, match="must not also be pinned"):
        _load_manifest(bundle_dir)


def test_append_only_files_accepts_unpinned_attributed_path(tmp_path):
    """the mesh pilot's exact case: a well-formed §C9.1 entry whose path is NOT
    pinned in manifest.files is ACCEPTED at the parse boundary.

    This INVERTS the former `test_append_only_files_rejects_poc4_unpinned_path`.
    Under the v0.3 posture (verifier ignored append_only_files, strict-SHA'd
    everything) an unpinned declaration was an attack vector, so PoC4 rejected it.
    Once the §C9.1 v0.4 machinery landed, the verifier SKIPS declared paths from
    strict-SHA and provides their integrity via AppendOnlyAttributedCheck instead
    — so declaring a path "instead of pinning its SHA in manifest.files" is the
    INTENDED design (extension docstring step (d)), and forcing files{} membership
    only recorded a never-enforced, stale SHA. The confused-deputy guarantee is
    preserved at verify time: `attribution_plugin` here is a placeholder, and
    AppendOnlyAttributedCheck will fail the bundle at verify() if the on-disk file
    carries no records under `attribution_key`. Parse-boundary load must NOT
    raise."""
    bundle_dir = _write_manifest(
        tmp_path,
        files={"unrelated.txt": "ef" * 32},
        append_only_files=[
            {
                "path": "retrieval_trace_log.jsonl",
                "attribution_key": "trace_id",
                "attribution_plugin": "three_set_sum_invariant",
                "verification_mode": "first_match",
            }
        ],
    )
    # Design 2: unpinned but well-formed → accepted at load (integrity deferred
    # to AppendOnlyAttributedCheck at verify time).
    _load_manifest(bundle_dir)


def test_append_only_files_rejects_non_list(tmp_path):
    bundle_dir = _write_manifest(
        tmp_path, append_only_files={"this": "is a dict, not a list"}
    )
    with pytest.raises(MalformedManifest, match="append_only_files"):
        _load_manifest(bundle_dir)


def test_append_only_files_rejects_non_string_path(tmp_path):
    bundle_dir = _write_manifest(
        tmp_path,
        files={"a": "00" * 32},
        append_only_files=[{"path": 42, "spec_version": "x"}],
    )
    with pytest.raises(MalformedManifest, match="append_only_files"):
        _load_manifest(bundle_dir)


def test_append_only_files_accepts_empty_list(tmp_path):
    """An empty list is structurally valid; no paths to bind. Must not raise."""
    bundle_dir = _write_manifest(tmp_path, append_only_files=[])
    _load_manifest(bundle_dir)


# ---------------------------------------------------------------------------
# End-to-end via BundleVerifier — confirms the parse-boundary check fires
# through the public verify() entry point with a VerifyFailure (not an
# uncaught exception — the §C9 fail-closed contract).
# ---------------------------------------------------------------------------


def test_poc4_payload_surfaces_as_verify_failure_not_uncaught_exception(tmp_path):
    """End-to-end: BundleVerifier.verify() must collect the MalformedManifest
    as a VerifyFailure (per §C9 'never raise')."""
    from audit_bundle.verifier import BundleVerifier

    bundle_dir = _write_manifest(
        tmp_path,
        attested_serving={
            "tee_vendor": "Intel TDX",
            "measurement": "ATTACKER-FABRICATED",
        },
    )
    result = BundleVerifier().verify(bundle_dir)
    assert result.ok is False
    assert any(
        "SCHEMA_RESERVED_NONCONFORMANT" in str(f) for f in result.failures
    ), f"expected SCHEMA_RESERVED_NONCONFORMANT in failures; got {result.failures!r}"
