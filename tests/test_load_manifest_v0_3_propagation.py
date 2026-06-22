"""Round-trip propagation tests for BundleManifest fields through
`audit_bundle.verifier._load_manifest`.

Surfaces the v0.3 loader propagation gap documented in
the internal design notes
— `_load_manifest` historically dropped 6 of 25 BundleManifest fields. The two
load-bearing ones (`causal_chain` + `verifier_identity`) caused the substrate's
own LayerACounterPlugin / CrossHostPeerReviewAuthenticatorCheck / C19.C plugin
to silently early-return PASS on bundles that should have been adversarially
exercised. 88 substrate tests over those primitives were green via
direct-BundleManifest construction; this file is the missing coverage at the
verifier-entry path BundleVerifier.verify(bundle_dir).

Scope of this file — 5 of the 6 fields:
    causal_chain         (S19a/b/c/d — LIVE v0.3, retires C19 half-truth)
    verifier_identity    (S18 — LIVE v0.3 post C18 OQ-1-8 resolution)
    attested_serving     (S17-RES schema reservation)
    semantic_fidelity    (S20 schema reservation)
    rigor_profile        (S14v3-RES schema reservation)

The 6th field (`append_only_files`) is NOT propagated in this commit. The
substrate-side test `tests/test_c9_1_append_only_files.py::test_B3_round_trip_
drops_append_only_files_at_v03` explicitly encodes the v0.3 drop-semantics as
a contract whose retirement belongs to the v0.4 c9_1 sprint that also lands
the AppendOnlyAttributedCheck plugin (see c9_1_append_only_files.py lines
53-66). Landing (a) loader propagation without (b)(c)(d) plugin + test flip +
docstring update would orphan three v0.4 sub-tasks. Coherent bundle ships
with that sprint owner.

Broken-first per `the internal design notes` —
draft the tests first, expect them red, then patch `_load_manifest` to flip
them green.

The load-bearing test (test_layer_a_plugin_fires_on_tamper_via_verifier_entry)
mints a substrate-conformant `causal_chain.layer_a` (real COSE_Sign1 SCITT
receipts via pycose, real HMAC-SHA256 event signatures) so the substrate's
LayerACounterPlugin actually engages when registered. It then writes a
tampered version of the same manifest where one byte of
events[0].event_signature.sig is flipped, and asserts the verifier-entry path
surfaces the substrate's EVENT_SIGNATURE_INVALID failure. Pre-patch this test
would have returned ok=True (plugin silently no-op'd because manifest.causal_chain
came back None from the loader). Post-patch it returns ok=False with the
substrate reason code surfaced through PluginResult.reason_code.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from audit_bundle.verifier import BundleVerifier, _load_manifest


# ---------------------------------------------------------------------------
# Helpers — minimal manifest builder used by the simple propagation tests.
# ---------------------------------------------------------------------------


_MINIMAL_BASE_FIELDS: dict = {
    "schema_version": "vcp-v1.1",
    "bundle_id": "00000000-0000-4000-8000-000000000000",
    "created_at": "2026-05-20T00:00:00Z",
    "files": {},
    "spec_files": {},
    "cross_refs": {},
    "payload": {},
    "typed_checks": [],
}


def _write_manifest(bundle_dir: Path, **extra) -> Path:
    """Write a minimal manifest.json at bundle_dir merging extra fields."""
    bundle_dir.mkdir(parents=True, exist_ok=True)
    manifest = {**_MINIMAL_BASE_FIELDS, **extra}
    manifest_path = bundle_dir / "manifest.json"
    manifest_path.write_bytes(json.dumps(manifest).encode("utf-8"))
    return manifest_path


# ---------------------------------------------------------------------------
# Five simple round-trip propagation tests — one per LIVE-or-schema-reservation
# field landing in this commit. `append_only_files` deferred to the v0.4 c9_1
# sprint per the file-header note above.
# ---------------------------------------------------------------------------


def test_load_manifest_propagates_causal_chain(tmp_path):
    """S19a/b/c/d owner; LIVE v0.3. Loader-drop → C19 plugins silent no-op."""
    causal_chain = {
        "layer_a": {
            "event_dag_merkle_root": "ab" * 32,
            "chain_height": 0,
            "scitt_log_id": "test-log",
            "assurance_profile": "offline-auditor-minimal",
            "protocol_version": "v0.3",
            "events": [],
        }
    }
    _write_manifest(tmp_path, causal_chain=causal_chain)
    m = _load_manifest(tmp_path)
    assert m.causal_chain is not None
    assert m.causal_chain["layer_a"]["event_dag_merkle_root"] == "ab" * 32
    assert m.causal_chain["layer_a"]["scitt_log_id"] == "test-log"


def test_load_manifest_propagates_verifier_identity(tmp_path):
    """S18 owner; LIVE v0.3 post C18 OQ-1-8 resolution 2026-05-19."""
    verifier_identity = {
        "issuer": "nexi-c18",
        "subject": "verifier@veriker",
        "fulcio_root": "test-fulcio",
    }
    _write_manifest(tmp_path, verifier_identity=verifier_identity)
    m = _load_manifest(tmp_path)
    assert m.verifier_identity is not None
    assert m.verifier_identity["issuer"] == "nexi-c18"
    assert m.verifier_identity["subject"] == "verifier@veriker"


def test_load_manifest_propagates_attested_serving(tmp_path):
    """S17-RES schema reservation; v0.3 propagates the canonical reservation
    marker. UPDATED 2026-05-26 (PoC4 TARGET 4): the prior payload
    ({"vendor": ..., "quote": ...}) was the exact attacker shape the PoC
    exploited — the verifier propagated raw attacker content into the
    dataclass for downstream "verified" consumption. Fixed by enforcing the
    canonical reservation marker at the parse boundary; this test now
    confirms the legitimate marker still propagates."""
    attested_serving = {
        "mode": "attested-serving-environment",
        "reserved_for_v0_4": True,
    }
    _write_manifest(tmp_path, attested_serving=attested_serving)
    m = _load_manifest(tmp_path)
    assert m.attested_serving == attested_serving


def test_load_manifest_propagates_semantic_fidelity(tmp_path):
    """S20 schema reservation; v0.3 propagates the canonical reservation
    marker. UPDATED 2026-05-26 (PoC4 TARGET 4) — see attested_serving
    sibling test for the same rationale (prior payload was the attacker
    shape; fix enforces marker shape at parse boundary)."""
    semantic_fidelity = {"reserved_for_v0_4": True}
    _write_manifest(tmp_path, semantic_fidelity=semantic_fidelity)
    m = _load_manifest(tmp_path)
    assert m.semantic_fidelity == semantic_fidelity


def test_load_manifest_rejects_rigor_profile_at_v03(tmp_path):
    """S14v3-RES schema reservation; v0.3 has no legitimate producer that
    populates rigor_profile, so the verifier rejects any value as
    SCHEMA_RESERVED_NONCONFORMANT. UPDATED 2026-05-26 (PoC4 TARGET 4): prior
    test asserted propagation of arbitrary content — that was the bug PoC4
    exploited. v0.4 introduces the validator alongside relaxation of this
    must-be-absent rule."""
    rigor_profile = {"tier": "regulated-high-assurance", "version": "v0.3"}
    _write_manifest(tmp_path, rigor_profile=rigor_profile)
    from audit_bundle.bundle_manifest import MalformedManifest

    with pytest.raises(MalformedManifest, match="SCHEMA_RESERVED_NONCONFORMANT"):
        _load_manifest(tmp_path)


# ---------------------------------------------------------------------------
# Load-bearing substrate-conformant Layer A fixture for the tamper test.
# ---------------------------------------------------------------------------


@pytest.fixture
def _pinned_ed25519_kid() -> bytes:
    return b"nexi-c19-test-kid-01"


@pytest.fixture
def _host_ikm() -> bytes:
    return b"\x11" * 32


@pytest.fixture
def _host_id() -> str:
    return "host-A"


def _build_signed_single_event_layer_a(
    *,
    bundle_id: str,
    pinned_kid: bytes,
    pinned_signing_key,
    host_ikm: bytes,
    host_id: str,
    payload_blob: bytes = b"event-1 payload",
) -> dict:
    """Mint a substrate-conformant single-event Layer A dict.

    All hashes / signatures / receipts are computed from real primitives lifted
    from audit_bundle.extensions.c19.layer_a_counter — NOT synthetic fixtures.
    Routes cleanly through _verify_layer_a_pipeline (stages 1.5 → 6).
    """
    from audit_bundle.extensions.c19.layer_a_counter import (
        canonical_event_preimage,
        compute_event_signature,
        derive_event_signature_key,
        issue_scitt_statement,
        verify_chain_integrity,
    )

    payload_hash = hashlib.sha256(payload_blob).digest()
    prev_event_hash = b"\x00" * 32

    statement_payload = {
        "event_id": "ev-1",
        "payload_hash": payload_hash,
        "host_id": host_id,
    }
    receipt_bytes, statement_content_sha256 = issue_scitt_statement(
        issuer_signing_key=pinned_signing_key,
        issuer_kid=pinned_kid,
        payload=statement_payload,
        alg=-8,
    )

    k_event = derive_event_signature_key(host_ikm)
    preimage = canonical_event_preimage(
        host_id=host_id,
        event_id="ev-1",
        prev_event_hash=prev_event_hash,
        bundle_id=bundle_id,
        monotonic_counter=1,
        payload_hash=payload_hash,
    )
    sig_bytes = compute_event_signature(k_event, preimage)

    event = {
        "event_id": "ev-1",
        "prev_event_id": None,
        "prev_event_hash": prev_event_hash.hex(),
        "monotonic_counter": 1,
        "counter_log_index": 1,
        "scitt_statement_id": statement_content_sha256.hex(),
        "scitt_statement_content_sha256": statement_content_sha256.hex(),
        "scitt_inclusion_proof": receipt_bytes.hex(),
        "event_kind": "retrieval",
        "payload_hash": payload_hash.hex(),
        "event_signature": {
            "key_id": host_id,
            "sig": sig_bytes.hex(),
        },
    }

    normalized = [
        {
            "event_id": event["event_id"],
            "prev_event_id": event["prev_event_id"],
            "prev_event_hash": prev_event_hash,
            "monotonic_counter": event["monotonic_counter"],
            "counter_log_index": event["counter_log_index"],
            "event_kind": event["event_kind"],
            "payload_hash": payload_hash,
        }
    ]
    merkle_root = verify_chain_integrity(normalized)

    return {
        "event_dag_merkle_root": merkle_root.hex(),
        "chain_height": 1,
        "scitt_log_id": "nexi-c19-test-log",
        "assurance_profile": "offline-auditor-minimal",
        "protocol_version": "v0.3",
        "bundle_id": bundle_id,
        "events": [event],
    }


def _make_layer_a_plugin(
    pinned_kid: bytes, verifying_key, host_id: str, host_ikm: bytes
):
    from audit_bundle.extensions.c19.layer_a_counter import LayerACounterPlugin

    return LayerACounterPlugin(
        pinned_ts_key_ids=frozenset({pinned_kid}),
        pinned_ts_verifying_keys={pinned_kid: verifying_key},
        pinned_issuer_keys={host_id: host_ikm},
    )


# ---------------------------------------------------------------------------
# Round-trip happy path + tamper through BundleVerifier.verify with
# LayerACounterPlugin registered. Pre-loader-patch: plugin sees
# manifest.causal_chain=None and early-returns PASS regardless of clean-vs-tamper.
# Post-patch: plugin sees the real causal_chain and runs the full
# verify-then-parse pipeline (stages 1.5 → 6) end-to-end.
# ---------------------------------------------------------------------------


def test_layer_a_plugin_passes_via_verifier_entry_on_clean_bundle(
    tmp_path, _pinned_ed25519_kid, _host_ikm, _host_id
):
    from tests.extensions.c19.test_layer_a_counter import _fresh_eddsa_keypair

    keypair = _fresh_eddsa_keypair(_pinned_ed25519_kid)
    bundle_id = "11111111-1111-4111-8111-111111111111"
    layer_a = _build_signed_single_event_layer_a(
        bundle_id=bundle_id,
        pinned_kid=_pinned_ed25519_kid,
        pinned_signing_key=keypair["signing"],
        host_ikm=_host_ikm,
        host_id=_host_id,
    )
    _write_manifest(
        tmp_path,
        bundle_id=bundle_id,
        causal_chain={"layer_a": layer_a},
    )
    plugin = _make_layer_a_plugin(
        _pinned_ed25519_kid, keypair["verifying"], _host_id, _host_ikm
    )
    # The Layer-A header declares offline-auditor-minimal (a canonical
    # declaration site), and a declared label must be GRADED (label-downgrade
    # fix 2026-06-12). Hold the canonical lattice: empty R(P), no obligations,
    # so the core grades admission itself and the clean bundle stays green.
    from audit_bundle.extensions.c19.profile_completeness_policy import (
        builtin_profile_lattice,
    )

    verifier = BundleVerifier(
        plugins=[plugin], completeness_policy=builtin_profile_lattice()
    )
    result = verifier.verify(tmp_path)
    assert result.ok is True, f"unexpected failures: {result.failures}"


def test_layer_a_plugin_fires_on_tamper_via_verifier_entry(
    tmp_path, _pinned_ed25519_kid, _host_ikm, _host_id
):
    """Load-bearing — retires the 'C19 enforces at v0.3 verifier-entry path'
    half-truth. Mint a clean conformant Layer A, then flip one byte of
    events[0].event_signature.sig on disk. Pre-patch: result.ok was True
    because LayerACounterPlugin saw manifest.causal_chain=None and returned
    PASS. Post-patch: result.ok is False and the substrate's
    EVENT_SIGNATURE_INVALID code is surfaced via PluginResult.reason_code.
    """
    from tests.extensions.c19.test_layer_a_counter import _fresh_eddsa_keypair

    keypair = _fresh_eddsa_keypair(_pinned_ed25519_kid)
    bundle_id = "22222222-2222-4222-8222-222222222222"
    layer_a = _build_signed_single_event_layer_a(
        bundle_id=bundle_id,
        pinned_kid=_pinned_ed25519_kid,
        pinned_signing_key=keypair["signing"],
        host_ikm=_host_ikm,
        host_id=_host_id,
    )

    # Tamper one byte of the event_signature.sig hex string at-rest.
    original_sig_hex = layer_a["events"][0]["event_signature"]["sig"]
    flipped_first_nibble = "0" if original_sig_hex[0] != "0" else "f"
    tampered_sig_hex = flipped_first_nibble + original_sig_hex[1:]
    assert tampered_sig_hex != original_sig_hex
    layer_a["events"][0]["event_signature"]["sig"] = tampered_sig_hex

    _write_manifest(
        tmp_path,
        bundle_id=bundle_id,
        causal_chain={"layer_a": layer_a},
    )
    plugin = _make_layer_a_plugin(
        _pinned_ed25519_kid, keypair["verifying"], _host_id, _host_ikm
    )
    verifier = BundleVerifier(plugins=[plugin])
    result = verifier.verify(tmp_path)

    assert result.ok is False, (
        "tampered sig should fail; if ok=True the loader is still dropping "
        "causal_chain OR a second silent-noop sits between _load_manifest and "
        "the plugin's check() — see the internal design notes"
    )
    assert any("c19_layer_a_counter" in f.check_name for f in result.failures), (
        f"LayerACounterPlugin failure not surfaced: {result.failures}"
    )

    # The substrate's EVENT_SIGNATURE_INVALID code surfaces via the
    # plugin's PluginResult.reason_code. Confirm it directly on the plugin
    # so the assertion does not depend on PluginFailed wrapping (the outer
    # VerifyFailure.reason_code is the generic 'plugin_failed' string).
    manifest = _load_manifest(tmp_path)
    direct = plugin.check(tmp_path, manifest)
    assert direct.ok is False
    assert direct.reason_code == "EVENT_SIGNATURE_INVALID", (
        f"expected EVENT_SIGNATURE_INVALID, got reason_code={direct.reason_code!r} "
        f"detail={direct.detail!r}"
    )
