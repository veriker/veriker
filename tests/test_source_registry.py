"""Tests for audit_bundle source_registry components + manifest integration + plugin.

Covers:
  - properties: default_v1_property_set, validate_publication_class
  - issuer_verifier: allow-list load + lookup
  - signature_verifier: Ed25519 roundtrip + unknown key_id
  - decision_provenance: append-only record + filtered read
  - BundleManifest + source_attributes integration
  - SourceAttributesConsistencyCheck plugin: pass + all five failure reason codes
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from audit_bundle.source_registry.properties import (
    BadPublicationClass,
    PublicationClass,
    default_v1_property_set,
    validate_publication_class,
)
from audit_bundle.source_registry.issuer_verifier import (
    IssuerVerifier,
    default_v1_allow_list_path,
)
from audit_bundle.source_registry.signature_verifier import SignatureVerifier
from audit_bundle.source_registry.decision_provenance import (
    DecisionProvenance,
    record_decision,
    read_decisions,
)
from audit_bundle.bundle_manifest import (
    BundleManifest,
    SourceAttributesOrphan,
    validate_manifest,
)
from audit_bundle.snapshots.cid import compute_cid
from audit_bundle.snapshots.snapshot_policy import (
    default_v1_policy,
    policy_to_canonical_dict,
)
from audit_bundle.plugins.source_attributes_consistency import (
    SourceAttributesConsistencyCheck,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_manifest(
    source_attributes: dict,
    snapshots: dict,
    decision_provenance_log: str | None = None,
) -> SimpleNamespace:
    """Duck-typed manifest for plugin tests — only attributes the plugin reads."""
    return SimpleNamespace(
        source_attributes=source_attributes,
        snapshots=snapshots,
        decision_provenance_log=decision_provenance_log,
    )


def _make_decision(
    source_cid: str, property_name: str = "publication_class"
) -> DecisionProvenance:
    return DecisionProvenance(
        source_cid=source_cid,
        property_name=property_name,
        decided_by="auto:test_agent",
        decided_at="2026-04-30T00:00:00Z",
        policy_version="props_v0.1+iv_v0.1",
        evidence={"test": True},
        prior_value=None,
        new_value="regulatory",
    )


def _regulatory_props(source_cid: str) -> dict:
    """Minimal valid source_attributes entry."""
    return {
        "issuer_identity_verified": False,
        "issuer_identifier": None,
        "signed_artifact_present": False,
        "signing_key_id": None,
        "publication_class": "regulatory",
        "external_status_flags": [],
        "schema_version": "0.1",
        "source_cid": source_cid,
    }


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------


def test_default_v1_property_set():
    """default_v1_property_set returns no-claims baseline for all four axes."""
    props = default_v1_property_set("sha256:aabb")
    assert props.source_cid == "sha256:aabb"
    assert props.issuer_identity_verified is False
    assert props.issuer_identifier is None
    assert props.signed_artifact_present is False
    assert props.signing_key_id is None
    assert props.publication_class == PublicationClass.UNKNOWN
    assert props.external_status_flags == ()


def test_validate_publication_class():
    """Every v1 enum value passes; 'novel' raises BadPublicationClass."""
    for cls in PublicationClass:
        validate_publication_class(cls.value)  # must not raise

    with pytest.raises(BadPublicationClass):
        validate_publication_class("novel")


# ---------------------------------------------------------------------------
# RES-10 — SourceProperties deep immutability + construction validation.
# frozen=True only locks top-level bindings; the old list[str] flags field
# could drift in place after the snapshot was stamped (instance #3 of the
# frozen-dataclass mutable-field class the ratchet inventories). Now a
# coerced tuple — no mutation API exists — and the closed v1 publication
# vocabulary is enforced where the snapshot is minted.
# ---------------------------------------------------------------------------


def _props_kwargs(**overrides) -> dict:
    kwargs = dict(
        source_cid="sha256:aabb",
        issuer_identity_verified=False,
        issuer_identifier=None,
        signed_artifact_present=False,
        signing_key_id=None,
        publication_class="regulatory",
        external_status_flags=["flag_a"],
    )
    kwargs.update(overrides)
    return kwargs


def test_source_properties_list_flags_coerced_to_tuple():
    """Existing callers pass lists; the snapshot stores a tuple."""
    from audit_bundle.source_registry.properties import (
        SourceProperties,
        properties_to_canonical_dict,
    )

    props = SourceProperties(**_props_kwargs())
    assert props.external_status_flags == ("flag_a",)
    assert isinstance(props.external_status_flags, tuple)
    # No in-place mutation API exists at all on the stored value.
    assert not hasattr(props.external_status_flags, "append")
    # Canonical form unchanged: flags still serialize as a JSON array.
    assert properties_to_canonical_dict(props)["external_status_flags"] == ["flag_a"]


def test_source_properties_rejects_bare_string_flags():
    """tuple('ab') would silently char-split one flag — rejected loudly."""
    from audit_bundle.source_registry.properties import SourceProperties

    with pytest.raises(TypeError, match="single str"):
        SourceProperties(**_props_kwargs(external_status_flags="lgpd_art20"))


def test_source_properties_rejects_non_str_flag_elements():
    from audit_bundle.source_registry.properties import SourceProperties

    with pytest.raises(TypeError, match="must be str"):
        SourceProperties(**_props_kwargs(external_status_flags=["ok", 7]))


def test_source_properties_rejects_off_vocabulary_publication_class():
    """Property 4's v1 set is closed — enforced at construction, not first
    discovered at the manifest parse boundary."""
    from audit_bundle.source_registry.properties import SourceProperties

    with pytest.raises(BadPublicationClass):
        SourceProperties(**_props_kwargs(publication_class="novel"))


# ---------------------------------------------------------------------------
# IssuerVerifier
# ---------------------------------------------------------------------------


def test_issuer_verifier_loads_allow_list():
    """Bundled allow_list_v0.json loads; 'sec.gov' resolves to (True, 'sec.gov')."""
    verifier = IssuerVerifier(default_v1_allow_list_path())
    ok, issuer_id = verifier.verify("sha256:any", "sec.gov")
    assert ok is True
    assert issuer_id == "sec.gov"


def test_issuer_verifier_unknown_issuer():
    """Unregistered domain resolves to (False, None)."""
    verifier = IssuerVerifier(default_v1_allow_list_path())
    ok, issuer_id = verifier.verify("sha256:any", "random.example")
    assert ok is False
    assert issuer_id is None


# ---------------------------------------------------------------------------
# SignatureVerifier
# ---------------------------------------------------------------------------


def test_signature_verifier_ed25519_roundtrip():
    """Sign then verify returns (True, key_id); tampered bytes return (False, None)."""
    private_key = Ed25519PrivateKey.generate()
    public_key_pem = private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )

    verifier = SignatureVerifier()
    key_id = "test-key-001"
    verifier.register_key(key_id, public_key_pem)

    artifact = b"signed content for test"
    sig = private_key.sign(artifact)

    ok, returned_key_id = verifier.verify("sha256:any", artifact, sig, key_id)
    assert ok is True
    assert returned_key_id == key_id

    # Tamper: append a null byte to artifact
    ok2, returned_key_id2 = verifier.verify(
        "sha256:any", artifact + b"\x00", sig, key_id
    )
    assert ok2 is False
    assert returned_key_id2 is None


def test_signature_verifier_unknown_key_id():
    """Unregistered key_id returns (False, None) without raising."""
    verifier = SignatureVerifier()
    ok, returned_key_id = verifier.verify(
        "sha256:any", b"data", b"\x00" * 64, "nonexistent-key"
    )
    assert ok is False
    assert returned_key_id is None


# ---------------------------------------------------------------------------
# DecisionProvenance
# ---------------------------------------------------------------------------


def test_record_decision_append_only(tmp_path):
    """Three appended entries grow the file monotonically; source_cid filter works."""
    log_path = tmp_path / "provenance.jsonl"

    cid_x = "sha256:" + "a" * 64
    cid_y = "sha256:" + "b" * 64

    entries = [
        _make_decision(cid_x, "issuer_identity_verified"),
        _make_decision(cid_y, "publication_class"),
        _make_decision(cid_x, "signed_artifact_present"),
    ]

    sizes: list[int] = []
    for entry in entries:
        record_decision(log_path, entry)
        sizes.append(log_path.stat().st_size)

    assert sizes[0] < sizes[1] < sizes[2], "File must grow after each append"

    results = list(read_decisions(log_path, source_cid=cid_x))
    assert len(results) == 2
    assert all(r.source_cid == cid_x for r in results)


# ---------------------------------------------------------------------------
# BundleManifest + source_attributes integration
# ---------------------------------------------------------------------------


def test_manifest_with_source_attributes(tmp_path):
    """Valid manifest passes; source_attribute pointing to non-snapshot CID raises SourceAttributesOrphan."""
    bundle_dir = tmp_path / "bundle"
    snap_dir = bundle_dir / "snapshots"
    snap_dir.mkdir(parents=True)

    content = b"source snapshot content"
    cid_str = compute_cid(content)
    snap_file = snap_dir / (cid_str.split(":")[1][:16] + ".bin")
    snap_file.write_bytes(content)
    rel_path = snap_file.relative_to(bundle_dir).as_posix()

    policy_dict = policy_to_canonical_dict(default_v1_policy())

    # Valid manifest: source_attributes key is present in snapshots
    manifest = BundleManifest(
        schema_version="vcp-v1.1-canary4",
        bundle_id="test-bundle-sa-001",
        created_at="2026-04-30T00:00:00Z",
        files={},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
        snapshots={cid_str: rel_path},
        snapshot_policy=policy_dict,
        source_attributes={cid_str: _regulatory_props(cid_str)},
    )
    validate_manifest(manifest, bundle_dir)  # must not raise

    # Orphan: source_attributes key is NOT in snapshots
    orphan_cid = "sha256:" + "f" * 64
    manifest_orphan = BundleManifest(
        schema_version="vcp-v1.1-canary4",
        bundle_id="test-bundle-sa-002",
        created_at="2026-04-30T00:00:00Z",
        files={},
        spec_files={},
        cross_refs={},
        payload={},
        typed_checks=[],
        snapshots={cid_str: rel_path},
        snapshot_policy=policy_dict,
        source_attributes={orphan_cid: _regulatory_props(orphan_cid)},
    )
    with pytest.raises(SourceAttributesOrphan):
        validate_manifest(manifest_orphan, bundle_dir)


# ---------------------------------------------------------------------------
# SourceAttributesConsistencyCheck plugin
# ---------------------------------------------------------------------------


def test_source_attributes_consistency_plugin_pass(tmp_path):
    """One snapshot + one matching source_attribute → ok=True."""
    cid_str = "sha256:" + "a" * 64
    props = {
        "issuer_identity_verified": True,
        "issuer_identifier": "sec.gov",
        "signed_artifact_present": False,
        "signing_key_id": None,
        "publication_class": "regulatory",
        "external_status_flags": [],
        "schema_version": "0.1",
        "source_cid": cid_str,
    }
    manifest = _fake_manifest(
        source_attributes={cid_str: props},
        snapshots={cid_str: "snapshots/snap.bin"},
    )
    result = SourceAttributesConsistencyCheck().check(tmp_path, manifest)
    assert result.ok is True


def test_plugin_orphan(tmp_path):
    """source_cid not in snapshots → reason_code='SOURCE_ATTRIBUTES_ORPHAN'."""
    real_cid = "sha256:" + "a" * 64
    orphan_cid = "sha256:" + "b" * 64
    manifest = _fake_manifest(
        source_attributes={orphan_cid: _regulatory_props(orphan_cid)},
        snapshots={real_cid: "snapshots/snap.bin"},
    )
    result = SourceAttributesConsistencyCheck().check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "SOURCE_ATTRIBUTES_ORPHAN"


def test_plugin_bad_class(tmp_path):
    """Invalid publication_class → reason_code='BAD_PUBLICATION_CLASS'."""
    cid_str = "sha256:" + "a" * 64
    props = _regulatory_props(cid_str)
    props["publication_class"] = "novel"
    manifest = _fake_manifest(
        source_attributes={cid_str: props},
        snapshots={cid_str: "snapshots/snap.bin"},
    )
    result = SourceAttributesConsistencyCheck().check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "BAD_PUBLICATION_CLASS"


def test_plugin_signed_but_no_key_id(tmp_path):
    """signed_artifact_present=True with null signing_key_id → reason_code='SIGNED_BUT_NO_KEY_ID'."""
    cid_str = "sha256:" + "a" * 64
    props = _regulatory_props(cid_str)
    props["signed_artifact_present"] = True
    props["signing_key_id"] = None
    manifest = _fake_manifest(
        source_attributes={cid_str: props},
        snapshots={cid_str: "snapshots/snap.bin"},
    )
    result = SourceAttributesConsistencyCheck().check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "SIGNED_BUT_NO_KEY_ID"


def test_plugin_verified_but_no_identifier(tmp_path):
    """issuer_identity_verified=True with null issuer_identifier → reason_code='VERIFIED_BUT_NO_IDENTIFIER'."""
    cid_str = "sha256:" + "a" * 64
    props = _regulatory_props(cid_str)
    props["issuer_identity_verified"] = True
    props["issuer_identifier"] = None
    manifest = _fake_manifest(
        source_attributes={cid_str: props},
        snapshots={cid_str: "snapshots/snap.bin"},
    )
    result = SourceAttributesConsistencyCheck().check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "VERIFIED_BUT_NO_IDENTIFIER"


def test_plugin_provenance_missing(tmp_path):
    """decision_provenance_log set but source_cid absent from log → reason_code='PROVENANCE_MISSING'."""
    cid_str = "sha256:" + "a" * 64
    other_cid = "sha256:" + "b" * 64

    # Write log covering only other_cid, not cid_str
    log_path = tmp_path / "provenance.jsonl"
    record_decision(log_path, _make_decision(other_cid, "publication_class"))

    manifest = _fake_manifest(
        source_attributes={cid_str: _regulatory_props(cid_str)},
        snapshots={cid_str: "snapshots/snap.bin"},
        decision_provenance_log="provenance.jsonl",
    )
    result = SourceAttributesConsistencyCheck().check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "PROVENANCE_MISSING"


# ---------------------------------------------------------------------------
# RES-11 reader leg — read_decisions runs on the verdict path against a
# bundle-controlled file, so it reads through the admission loaders
# (admit_jsonl_file): a depth-bomb line is a cheap structured reject at the
# parse boundary, never a RecursionError escaping the plugin's handler. The
# old raw per-line json.loads over a file handle was the iteration shape the
# admission ratchet documents as invisible to its AST scan.
# ---------------------------------------------------------------------------


def test_read_decisions_rejects_depth_bomb(tmp_path):
    from audit_bundle.admission import InputInadmissible

    log_path = tmp_path / "provenance.jsonl"
    record_decision(log_path, _make_decision("sha256:" + "a" * 64))
    with log_path.open("ab") as fh:
        fh.write(b"[" * 5000 + b"]" * 5000 + b"\n")

    with pytest.raises(InputInadmissible):
        list(read_decisions(log_path))


def test_plugin_depth_bomb_log_is_structured_reject(tmp_path):
    """A depth-bomb line in the bundle-supplied provenance log lands in the
    plugin's PROVENANCE_LOG_UNREADABLE lane — a recorded REJECT with the
    other malformed-content shapes, not a plugin-boundary ERROR."""
    cid_str = "sha256:" + "a" * 64
    log_path = tmp_path / "provenance.jsonl"
    log_path.write_bytes(b"[" * 5000 + b"]" * 5000 + b"\n")

    manifest = _fake_manifest(
        source_attributes={cid_str: _regulatory_props(cid_str)},
        snapshots={cid_str: "snapshots/snap.bin"},
        decision_provenance_log="provenance.jsonl",
    )
    result = SourceAttributesConsistencyCheck().check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "PROVENANCE_LOG_UNREADABLE"


def test_plugin_torn_tail_log_is_structured_reject(tmp_path):
    """A truncated-mid-record tail (the crash-torn-write shape from RES-11)
    is a structured PROVENANCE_LOG_UNREADABLE reject, never streamed past."""
    cid_str = "sha256:" + "a" * 64
    log_path = tmp_path / "provenance.jsonl"
    record_decision(log_path, _make_decision(cid_str))
    with log_path.open("ab") as fh:
        fh.write(b'{"source_cid": "sha256:tr')  # torn mid-write, no newline

    manifest = _fake_manifest(
        source_attributes={cid_str: _regulatory_props(cid_str)},
        snapshots={cid_str: "snapshots/snap.bin"},
        decision_provenance_log="provenance.jsonl",
    )
    result = SourceAttributesConsistencyCheck().check(tmp_path, manifest)
    assert result.ok is False
    assert result.reason_code == "PROVENANCE_LOG_UNREADABLE"
