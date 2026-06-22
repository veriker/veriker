"""Tests for the core source_attributes consistency guard.

This is the next confirmed instance of the present-but-unverified /
library-laundering class (immediately after causal_chain BLOCK-02): the
SourceAttributesConsistencyCheck plugin enforces five invariants over
manifest.source_attributes, but it is only wired into the veriker/cli/verify.py default
set — NOT into a bare ``BundleVerifier()``. So a LIBRARY consumer could read
``VerdictState.OK`` over a bundle claiming ``issuer_identity_verified=True`` with
``issuer_identifier=None`` (or ``signed_artifact_present=True`` with no key) —
a four-axis trust claim that NOTHING checked.

The fix moves invariants 2-5 into core ``_validate_manifest_deep`` (invariant 1,
the snapshot-orphan check, was already there). They are pure deterministic
structural/consistency checks (no keys, no crypto, no pinned material), so they
land as REJECTs the same way invariant 1 does, and the plugin becomes
redundant-but-agreeing (like OF1) rather than the sole decider.

These tests pin, EACH under a bare ``BundleVerifier()`` (no plugins wired):
  * each present-but-false invariant (1-5) REJECTs;
  * a non-dict source_attributes value fails closed as a REJECT, not a crash;
  * a well-formed honest bundle (and an absent/empty source_attributes) stays GREEN;
  * the SourceAttributesConsistencyCheck plugin still AGREES (no double-REJECT
    divergence) on the same bad bundles.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.plugins.source_attributes_consistency import (  # noqa: E402
    SourceAttributesConsistencyCheck,
)
from audit_bundle.snapshots.cid import compute_cid  # noqa: E402
from audit_bundle.snapshots.snapshot_policy import (  # noqa: E402
    default_v1_policy,
    policy_to_canonical_dict,
)
from audit_bundle.source_registry.decision_provenance import (  # noqa: E402
    DecisionProvenance,
)
from audit_bundle.verdict import VerdictState  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402

_RAW = b"a reviewed source document for source_attributes consistency"
_PROV_REL = "provenance.jsonl"


def _provenance_for(source_cid: str) -> DecisionProvenance:
    return DecisionProvenance(
        source_cid=source_cid,
        property_name="issuer_identity_verified",
        decided_by="auditor:a",
        decided_at="2026-06-11T00:00:00Z",
        policy_version="props_v0.1",
        evidence={},
        prior_value=None,
        new_value=True,
    )


def _build_bundle(
    tmp_path: Path,
    *,
    source_attributes: dict,
    use_real_cid: bool = True,
    provenance_records: list[DecisionProvenance] | None = None,
) -> tuple[Path, str]:
    """Write a clean single-snapshot bundle to ``tmp_path`` and return (dir, cid).

    Produces a REAL content-addressed snapshot CID + snapshot_policy so deep
    validation's snapshot-CID binding (which fires before source_attributes)
    passes — the bundle is rejected for the source_attributes invariant under
    test, never for the wrong reason. The caller's ``source_attributes`` dict is
    written verbatim; placeholder ``{cid}`` keys are substituted with the real
    CID so callers can express "the entry for the real snapshot".

    When ``provenance_records`` is given, they are written to a JSONL log,
    the log is registered (decision_provenance_log + SHA-pinned in files so the
    conservation gate accounts for it), and invariant 3 reads them.
    """
    bundle_dir = tmp_path / "bundle"
    (bundle_dir / "corpus").mkdir(parents=True)
    (bundle_dir / "corpus" / "doc.txt").write_bytes(_RAW)
    cid = compute_cid(_RAW)

    resolved_attrs = {
        (cid if k == "{cid}" else k): v for k, v in source_attributes.items()
    }

    files: dict[str, str] = {}
    decision_provenance_log: str | None = None
    if provenance_records is not None:
        import dataclasses

        resolved_records = [
            dataclasses.replace(p, source_cid=cid) if p.source_cid == "{cid}" else p
            for p in provenance_records
        ]
        lines = b"".join(
            json.dumps(
                dataclasses.asdict(p), separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
            + b"\n"
            for p in resolved_records
        )
        (bundle_dir / _PROV_REL).write_bytes(lines)
        files[_PROV_REL] = __import__("hashlib").sha256(lines).hexdigest()
        decision_provenance_log = _PROV_REL

    manifest: dict = {
        "schema_version": "legacy",
        "bundle_id": "b",
        "created_at": "2026-06-11T00:00:00Z",
        "files": files,
        "spec_files": {},
        "cross_refs": {},
        "snapshots": {cid: "corpus/doc.txt"} if use_real_cid else {},
        "snapshot_policy": policy_to_canonical_dict(default_v1_policy()),
        "source_attributes": resolved_attrs,
    }
    if decision_provenance_log is not None:
        manifest["decision_provenance_log"] = decision_provenance_log
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest))
    return bundle_dir, cid


def _reason_codes(verdict) -> set[str]:
    return {f.reason_code for f in verdict.failures}


def _honest_entry() -> dict:
    """A source_attributes entry that satisfies all four axes honestly."""
    return {
        "publication_class": "regulatory",
        "issuer_identity_verified": True,
        "issuer_identifier": "did:web:sec.gov",
        "signed_artifact_present": True,
        "signing_key_id": "key-1",
        "schema_version": "0.1",
    }


# ---------------------------------------------------------------------------
# Each present-but-false invariant REJECTs under a bare BundleVerifier()
# ---------------------------------------------------------------------------


def test_invariant1_orphan_rejects(tmp_path):
    phantom = "sha256:" + "ff" * 32
    bundle_dir, _ = _build_bundle(
        tmp_path,
        source_attributes={phantom: {"publication_class": "unknown"}},
    )
    v = BundleVerifier().verify(bundle_dir)
    assert v.state is VerdictState.REJECT, v.state
    assert "SourceAttributesOrphan" in _reason_codes(v), _reason_codes(v)


def test_invariant2_bad_publication_class_rejects(tmp_path):
    bundle_dir, _ = _build_bundle(
        tmp_path,
        source_attributes={"{cid}": {"publication_class": "novel"}},
    )
    v = BundleVerifier().verify(bundle_dir)
    assert v.state is VerdictState.REJECT, v.state
    assert "BadPublicationClass" in _reason_codes(v), _reason_codes(v)


def test_invariant4_signed_but_no_key_rejects(tmp_path):
    bundle_dir, _ = _build_bundle(
        tmp_path,
        source_attributes={
            "{cid}": {
                "publication_class": "unknown",
                "signed_artifact_present": True,
                "signing_key_id": None,
            }
        },
    )
    v = BundleVerifier().verify(bundle_dir)
    assert v.state is VerdictState.REJECT, v.state
    assert "SignedArtifactKeyMissing" in _reason_codes(v), _reason_codes(v)


def test_invariant5_verified_but_no_identifier_rejects(tmp_path):
    bundle_dir, _ = _build_bundle(
        tmp_path,
        source_attributes={
            "{cid}": {
                "publication_class": "unknown",
                "issuer_identity_verified": True,
                "issuer_identifier": None,
            }
        },
    )
    v = BundleVerifier().verify(bundle_dir)
    assert v.state is VerdictState.REJECT, v.state
    assert "IssuerIdentifierMissing" in _reason_codes(v), _reason_codes(v)


def test_invariant3_provenance_incomplete_rejects(tmp_path):
    # Log exists but records a decision for a DIFFERENT source_cid, so the
    # annotated cid is replay-incomplete.
    bundle_dir, cid = _build_bundle(
        tmp_path,
        source_attributes={"{cid}": {"publication_class": "unknown"}},
        provenance_records=[_provenance_for("sha256:" + "ab" * 32)],
    )
    v = BundleVerifier().verify(bundle_dir)
    assert v.state is VerdictState.REJECT, v.state
    assert "SourceProvenanceIncomplete" in _reason_codes(v), _reason_codes(v)


def test_malformed_non_dict_value_fails_closed(tmp_path):
    bundle_dir, _ = _build_bundle(
        tmp_path,
        source_attributes={"{cid}": "not-a-dict"},
    )
    v = BundleVerifier().verify(bundle_dir)
    # Must be a recorded REJECT, never a VERIFIER crash-ERROR.
    assert v.state is VerdictState.REJECT, v.state
    assert "SourceAttributesMalformed" in _reason_codes(v), _reason_codes(v)


# ---------------------------------------------------------------------------
# Honest / inert bundles stay GREEN
# ---------------------------------------------------------------------------


def test_well_formed_honest_bundle_stays_green(tmp_path):
    # A matching provenance record satisfies invariant 3; all four axes honest.
    bundle_dir, cid = _build_bundle(
        tmp_path,
        source_attributes={"{cid}": _honest_entry()},
        provenance_records=[_provenance_for("{cid}")],
    )
    v = BundleVerifier().verify(bundle_dir)
    assert v.state is VerdictState.OK, [
        (f.check_name, f.reason_code, f.detail) for f in v.failures
    ]


def test_absent_source_attributes_stays_green(tmp_path):
    bundle_dir, _ = _build_bundle(
        tmp_path,
        source_attributes={},
    )
    v = BundleVerifier().verify(bundle_dir)
    assert v.state is VerdictState.OK, [
        (f.check_name, f.reason_code, f.detail) for f in v.failures
    ]


def test_honest_false_claims_stay_green(tmp_path):
    # The axes are CLAIMED False — there is nothing to back, so nothing to reject.
    bundle_dir, _ = _build_bundle(
        tmp_path,
        source_attributes={
            "{cid}": {
                "publication_class": "blog",
                "issuer_identity_verified": False,
                "issuer_identifier": None,
                "signed_artifact_present": False,
                "signing_key_id": None,
            }
        },
    )
    v = BundleVerifier().verify(bundle_dir)
    assert v.state is VerdictState.OK, [
        (f.check_name, f.reason_code, f.detail) for f in v.failures
    ]


# ---------------------------------------------------------------------------
# The plugin still AGREES (redundant-but-agreeing, no divergence)
# ---------------------------------------------------------------------------


def test_plugin_agrees_with_core_on_bad_claim(tmp_path):
    from audit_bundle.bundle_manifest import BundleManifest

    bundle_dir, cid = _build_bundle(
        tmp_path,
        source_attributes={
            "{cid}": {
                "publication_class": "unknown",
                "issuer_identity_verified": True,
                "issuer_identifier": None,
            }
        },
    )
    manifest = json.loads((bundle_dir / "manifest.json").read_text())
    m = BundleManifest(
        schema_version="legacy",
        bundle_id="b",
        created_at="2026-06-11T00:00:00Z",
        files={},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
        snapshots=dict(manifest["snapshots"]),
        snapshot_policy=manifest["snapshot_policy"],
        source_attributes=dict(manifest["source_attributes"]),
    )
    result = SourceAttributesConsistencyCheck().check(bundle_dir, m)
    # Plugin reaches the SAME conclusion (its own reason vocabulary) — core and
    # plugin agree the claim is bad; neither laundered it.
    assert not result.ok
    assert result.reason_code == "VERIFIED_BUT_NO_IDENTIFIER", result.reason_code
