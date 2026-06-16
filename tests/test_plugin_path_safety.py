"""Plugin path-safety regression suite — sibling of tests/fuzz/test_manifest_path_safety.py.

The verifier path was closed by ``_safe_bundle_path`` in commit 375d43b5f
(2026-05-26 atheris finding: ``{"files":{"/":"a"}}`` → ``IsADirectoryError``
out of ``read_bytes()``, breaking §C9 "verify never raises"). The same
bug shape lives in three plugin path-handling sites that
``BundleVerifier.verify()`` does not reach:

  - ``audit_bundle/plugins/refinement_discharge.py`` line ~333
    (``bundle_dir / obligation_uri``)
  - ``audit_bundle/manifest_three_set.py`` line ~88
    (``bundle_dir / trace_log``)
  - ``audit_bundle/plugins/spec_sha_pin.py`` line ~26
    (``bundle_dir / "spec" / spec_path`` — the ``"spec"`` literal anchors
    most absolute-path attacks but ``..``-traversal in spec_path still
    escapes; verify with
    ``(bundle_dir / "spec" / "../../../etc/hostname").resolve()``.)

Each plugin surface is wired to ``_safe_bundle_path`` and converts
``UnsafeBundlePath`` to its native failure shape:
  - refinement_discharge → ``PluginResult(ok=False, reason_code="PROOF_OBLIGATION_PATH_UNSAFE")``
  - manifest_three_set → ``ThreeSetMismatch`` (raises; its public contract)
  - spec_sha_pin → ``PluginResult(ok=False, reason_code="SPEC_PATH_UNSAFE")``

This suite codifies the threat model so the breaks cannot silently regress.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from audit_bundle.bundle_manifest import BundleManifest
from audit_bundle.manifest_three_set import (
    PerOutputManifest,
    ThreeSetMismatch,
    validate_per_output_manifest,
)
from audit_bundle.plugins.refinement_discharge import RefinementDischargeCheck
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck


# ---------------------------------------------------------------------------
# Evil-path corpus — adapted from tests/fuzz/test_manifest_path_safety.py.
# ``filesystem_root`` and ``bundle_self_dir`` exercise the directory-target
# guard (atheris IsADirectoryError finding); the absolute and dotdot
# variants exercise the path-escape guard.
# ---------------------------------------------------------------------------
EVIL_PATHS: list[tuple[str, str]] = [
    ("/", "filesystem_root"),
    (".", "bundle_self_dir"),
    ("/etc/hostname", "absolute_outside_bundle"),
    ("../../etc/hostname", "dotdot_traversal"),
    ("some_existing_dir/", "trailing_slash_directory_target"),
]


# ---------------------------------------------------------------------------
# refinement_discharge — obligation_uri path safety
# ---------------------------------------------------------------------------


def _make_manifest_with_dispatch_record(
    bundle_id: str, obligation_uri: str, obligation_sha: str
) -> BundleManifest:
    """Build a BundleManifest carrying one not-attempted dispatch_record.

    The plugin walks dispatch_records → proof → obligation_uri before
    consulting the discharge_status; ``not-attempted`` keeps signature
    machinery from short-circuiting before the path-safety guard fires.
    """
    return BundleManifest(
        schema_version="legacy",
        bundle_id=bundle_id,
        created_at="2026-01-01T00:00:00Z",
        files={},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
        dispatch_records=[
            {
                "proof": {
                    "kind": "smt-z3",
                    "obligation_uri": obligation_uri,
                    "obligation_sha": obligation_sha,
                    "discharge_status": "not-attempted",
                }
            }
        ],
    )


@pytest.mark.parametrize(
    "rel_path,label", EVIL_PATHS, ids=[p[1] for p in EVIL_PATHS]
)
def test_refinement_discharge_rejects_unsafe_obligation_uri(
    tmp_path: Path, rel_path: str, label: str
) -> None:
    """obligation_uri with an unsafe path: ok=False, PROOF_OBLIGATION_PATH_UNSAFE,
    no raise."""
    # Pre-create a directory for the trailing-slash case so the helper's
    # is_dir() check has something to land on (escape-cases hit the
    # relative_to() guard before the FS state matters).
    (tmp_path / "some_existing_dir").mkdir()

    manifest = _make_manifest_with_dispatch_record(
        bundle_id="b", obligation_uri=rel_path, obligation_sha="ab" * 32
    )
    plugin = RefinementDischargeCheck()
    result = plugin.check(tmp_path, manifest)  # must not raise

    assert result.ok is False, f"{label}: evil path accepted"
    assert result.reason_code == "PROOF_OBLIGATION_PATH_UNSAFE", (
        f"{label}: expected PROOF_OBLIGATION_PATH_UNSAFE, got {result.reason_code!r}"
    )


def test_refinement_discharge_accepts_legitimate_obligation(tmp_path: Path) -> None:
    """Sanity: a normal in-bundle obligation_uri must NOT be rejected by the
    new path-safety guard. The plugin's downstream existence + SHA checks
    still apply."""
    obligation_path = tmp_path / "obligations" / "ob1.smt2"
    obligation_path.parent.mkdir(parents=True)
    obligation_path.write_text("(declare-const x Int) (assert (> x 0)) (check-sat)")
    obligation_sha = hashlib.sha256(obligation_path.read_bytes()).hexdigest()

    manifest = _make_manifest_with_dispatch_record(
        bundle_id="b",
        obligation_uri="obligations/ob1.smt2",
        obligation_sha=obligation_sha,
    )
    result = RefinementDischargeCheck().check(tmp_path, manifest)
    assert result.ok is True, f"legitimate path rejected: {result.detail}"


# ---------------------------------------------------------------------------
# manifest_three_set — retrieval_trace_log path safety
# ---------------------------------------------------------------------------


def _make_pom_with_trace_log(trace_log: str) -> tuple[PerOutputManifest, BundleManifest]:
    pom = PerOutputManifest(
        output_id="o1",
        trace_id="t1",
        three_set={"retrieved": [], "context_injected": [], "quote_supporting": []},
        emitted_at="2026-01-01T00:00:00Z",
    )
    manifest = BundleManifest(
        schema_version="legacy",
        bundle_id="b",
        created_at="2026-01-01T00:00:00Z",
        files={},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
        retrieval_trace_log=trace_log,
    )
    return pom, manifest


@pytest.mark.parametrize(
    "rel_path,label", EVIL_PATHS, ids=[p[1] for p in EVIL_PATHS]
)
def test_manifest_three_set_rejects_unsafe_trace_log_path(
    tmp_path: Path, rel_path: str, label: str
) -> None:
    """retrieval_trace_log with an unsafe path raises ThreeSetMismatch
    (manifest_three_set's public contract — see ThreeSetMismatch docstring).
    Crucially it MUST NOT propagate UnsafeBundlePath; callers handle the
    documented exception."""
    (tmp_path / "some_existing_dir").mkdir()

    pom, manifest = _make_pom_with_trace_log(rel_path)
    with pytest.raises(ThreeSetMismatch, match="unsafe bundle path"):
        validate_per_output_manifest(pom, manifest, tmp_path)


# ---------------------------------------------------------------------------
# spec_sha_pin — "spec/" + spec_path safety
# ---------------------------------------------------------------------------


# spec_sha_pin's `"spec"` literal anchors most absolute-path attacks under
# bundle/spec/, but ``..``-traversal in spec_path still escapes and
# directory-target attacks still land. We exercise the corpus that survives
# the "spec/" prefix.
SPEC_EVIL_PATHS: list[tuple[str, str]] = [
    ("../../etc/hostname", "dotdot_escapes_spec_prefix"),
    ("../..", "dotdot_only_escapes_spec_prefix"),
    ("../../../", "deeper_dotdot_filesystem_root"),
    ("", "empty_resolves_to_spec_dir"),  # bundle_dir/spec/ is itself a directory
]


@pytest.mark.parametrize(
    "rel_path,label", SPEC_EVIL_PATHS, ids=[p[1] for p in SPEC_EVIL_PATHS]
)
def test_spec_sha_pin_rejects_unsafe_spec_path(
    tmp_path: Path, rel_path: str, label: str
) -> None:
    """spec_files entry with an unsafe path: ok=False, SPEC_PATH_UNSAFE, no raise."""
    # spec_sha_pin only walks spec_files, so we need the bundle/spec/ dir
    # to exist for the empty-string case (it resolves to that directory).
    (tmp_path / "spec").mkdir()

    manifest = BundleManifest(
        schema_version="legacy",
        bundle_id="b",
        created_at="2026-01-01T00:00:00Z",
        files={},
        spec_files={rel_path: "ab" * 32},
        cross_refs={},
        payload={},
        typed_checks=[],
    )
    result = SpecShaPinCheck().check(tmp_path, manifest)  # must not raise

    assert result.ok is False, f"{label}: evil path accepted"
    assert result.reason_code == "SPEC_PATH_UNSAFE", (
        f"{label}: expected SPEC_PATH_UNSAFE, got {result.reason_code!r}"
    )


def test_spec_sha_pin_dotdot_escape_does_not_leak_external_hash(
    tmp_path: Path,
) -> None:
    """Probe-oracle defence: when spec_path is ``../../etc/hostname``,
    spec_sha_pin must NOT SHA-256 the attacker-chosen file and echo the
    digest back through the failure detail. The guard fires before
    read_bytes() runs, so neither the digest nor the read-attempt
    surfaces."""
    (tmp_path / "spec").mkdir()
    # Create a sibling file the manifest could try to read if the guard fails
    sibling = tmp_path.parent / "external_target.txt"
    sibling.write_text("attacker-visible-marker")
    try:
        manifest = BundleManifest(
            schema_version="legacy",
            bundle_id="b",
            created_at="2026-01-01T00:00:00Z",
            files={},
            spec_files={"../../external_target.txt": "ab" * 32},
            cross_refs={},
            payload={},
            typed_checks=[],
        )
        result = SpecShaPinCheck().check(tmp_path, manifest)
        assert result.ok is False
        assert result.reason_code == "SPEC_PATH_UNSAFE"
        # The detail must not contain the SHA-256 of the external file.
        external_sha = hashlib.sha256(sibling.read_bytes()).hexdigest()
        assert external_sha not in result.detail, (
            "spec_sha_pin leaked external file SHA through failure detail"
        )
    finally:
        if sibling.exists():
            sibling.unlink()


def test_spec_sha_pin_accepts_legitimate_spec_file(tmp_path: Path) -> None:
    """Sanity: a normal spec/<file> path must NOT be rejected."""
    (tmp_path / "spec").mkdir()
    (tmp_path / "spec" / "schema.json").write_text('{"k": "v"}')
    spec_sha = hashlib.sha256((tmp_path / "spec" / "schema.json").read_bytes()).hexdigest()
    manifest = BundleManifest(
        schema_version="legacy",
        bundle_id="b",
        created_at="2026-01-01T00:00:00Z",
        files={},
        spec_files={"schema.json": spec_sha},
        cross_refs={},
        payload={},
        typed_checks=[],
    )
    result = SpecShaPinCheck().check(tmp_path, manifest)
    assert result.ok is True, f"legitimate spec path rejected: {result.detail}"
