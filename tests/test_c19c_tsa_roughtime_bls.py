"""S19c adversarial + positive test suite — Layer B real-time anchoring.

Encodes every attack class the Round-1..R6 tribunal surfaced + the happy-
path positive cases. Written FIRST against the broken stand-in (c19c-002);
c19c-004 audits that every test fails LOUDLY in V0_3_S19c_BROKEN_STAND_IN
mode; c19c-005 replaces stand-in bodies and turns every test green.

Test-side dep gating: BLS / CBOR fixture deps are required for the test
suite. The substrate-level pyproject.toml addition is captured at the top
of `audit_bundle/extensions/c19/tsa_roughtime_bls.py` as a
PYPROJECT_TODO_FOR_INTEGRATION block; the v0.3 block-1 integration handler
picks it up. Until then the test suite imports cbor2 + py_ecc directly and
fails import if missing — equivalent to importorskip at module level.

Fixture-mint discipline: every test that touches the verifier MUST
monkeypatch the verifier's pinned constants (`PINNED_ROUGHTIME_ROOTS`,
`NEXI_TSA_ALLOWLIST`, plus the verifier-internal CA / BLS-pubkey
registries) with TEST keys. The monkeypatch fixture emits a marker log
line that the test caplog-asserts on, binding the discipline.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import sys
from pathlib import Path

import pytest

# Ensure the package is importable when tests are run from repo root.
_PRODUCT_ROOT = Path(__file__).resolve().parents[1]
if str(_PRODUCT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PRODUCT_ROOT))

from audit_bundle.extensions.c19 import tsa_roughtime_bls as m  # noqa: E402
from tests.fixtures.c19c import mint_fixtures as fx  # noqa: E402


# ──────────────────────────────────────────────────────────────────────────
# Monkeypatch fixture: swap verifier's pinned constants with TEST keys.
# Logs a marker line "TEST FIXTURE OVERRIDES PINNED CONSTANTS" — test
# caplog-asserts on this to bind the discipline (production keys never
# reached during tests).
# ──────────────────────────────────────────────────────────────────────────


@pytest.fixture
def test_pinned(monkeypatch, caplog):
    caplog.set_level(
        logging.INFO, logger="audit_bundle.extensions.c19.tsa_roughtime_bls"
    )

    test_roots = fx.make_test_pinned_roughtime_roots()
    # Install via the override seam (not a direct PINNED_ROUGHTIME_ROOTS
    # monkeypatch) so the Roughtime resolution self-announces through
    # _OVERRIDE_MARKER, symmetric with the TSA-CA / BLS overrides below.
    monkeypatch.setattr(m, "_TEST_OVERRIDE_ROUGHTIME_ROOTS", test_roots, raising=False)
    # Allowlist stays the same (just operator names) but the underlying
    # cert chains + BLS pubkeys come from the test mint.
    test_ca_pem = fx.get_test_tsa_ca_pem()
    monkeypatch.setattr(m, "_TEST_OVERRIDE_TSA_CA_PEM", test_ca_pem, raising=False)
    # Pinned BLS pubkey lookup the verifier resolves through its module
    # surface — verifier reads `_TEST_OVERRIDE_BLS_PUBKEY_FOR_TSA` if set.
    bls_pubkeys = {
        name: fx.bls_pk_for_tsa(name)
        for name in m.NEXI_TSA_ALLOWLIST
        if name != "placeholder-tsa-5"
    }
    monkeypatch.setattr(m, "_TEST_OVERRIDE_BLS_PUBKEYS", bls_pubkeys, raising=False)

    logging.getLogger("audit_bundle.extensions.c19.tsa_roughtime_bls").info(
        "TEST FIXTURE OVERRIDES PINNED CONSTANTS — production keys never reached"
    )
    return {
        "roots": test_roots,
        "ca_pem": test_ca_pem,
        "bls_pubkeys": bls_pubkeys,
    }


@pytest.fixture
def event_hashes() -> list[str]:
    """Three synthetic per-event hashes for a per-batch payload."""
    return [
        hashlib.sha256(f"S19c-test-event-{i}".encode()).hexdigest() for i in range(3)
    ]


@pytest.fixture
def merkle_root(event_hashes) -> str:
    return fx.merkle_root_of(event_hashes)


@pytest.fixture
def merkle_leaves(event_hashes) -> list[dict]:
    return [
        {"event_id": f"event-{i}", "event_hash_hex": h, "leaf_index": i}
        for i, h in enumerate(event_hashes)
    ]


@pytest.fixture
def nonce_bytes() -> bytes:
    return secrets.token_bytes(8)


# ──────────────────────────────────────────────────────────────────────────
# TestVerifyPerBatchTSARoot — RFC 3161 TSA + BLS aggregation path
# ──────────────────────────────────────────────────────────────────────────


class TestVerifyPerBatchTSARoot:
    def _build_layer_b(
        self,
        *,
        tokens,
        merkle_root,
        merkle_leaves,
        bls_agg=None,
        batched_event_kinds=("retrieval",),
        required_quorum=None,
        acceptable_tsa_roots=None,
    ):
        per_batch = {
            "merkle_root_hex": merkle_root,
            "merkle_leaves": merkle_leaves,
            "rfc3161_tokens": tokens,
            "batched_event_kinds": list(batched_event_kinds),
        }
        if bls_agg is not None:
            per_batch["bls_aggregated_root_sig_b64"] = bls_agg
        if required_quorum is not None:
            per_batch["required_quorum"] = required_quorum
        if acceptable_tsa_roots is not None:
            per_batch["acceptable_tsa_roots"] = acceptable_tsa_roots
        return {"per_batch_tsa_root": per_batch}

    def test_happy_path_single_tsa_from_allowlist_at_production_standard(
        self, test_pinned, merkle_root, merkle_leaves, nonce_bytes, caplog
    ):
        token = fx.mint_tsa_token(
            tsa_name="digicert-tsa",
            merkle_root_hex=merkle_root,
            nonce_bytes=nonce_bytes,
        )
        layer_b = self._build_layer_b(
            tokens=[token],
            merkle_root=merkle_root,
            merkle_leaves=merkle_leaves,
        )
        m.verify_per_batch_tsa_root(
            layer_b,
            assurance_profile="production-standard",
            expected_merkle_root_hex=merkle_root,
        )
        assert "TEST FIXTURE OVERRIDES PINNED CONSTANTS" in caplog.text

    def test_happy_path_2_of_3_quorum_at_regulated_high_assurance_stamp_emission(
        self, test_pinned, merkle_root, merkle_leaves, nonce_bytes
    ):
        tokens = [
            fx.mint_tsa_token(
                tsa_name=n, merkle_root_hex=merkle_root, nonce_bytes=nonce_bytes
            )
            for n in ("digicert-tsa", "globalsign-tsa", "cellnex-tsa")
        ]
        bls_agg = fx.mint_bls_aggregate(
            tsa_names=["digicert-tsa", "globalsign-tsa", "cellnex-tsa"],
            merkle_root_hex=merkle_root,
        )
        layer_b = self._build_layer_b(
            tokens=tokens,
            merkle_root=merkle_root,
            merkle_leaves=merkle_leaves,
            bls_agg=bls_agg,
            batched_event_kinds=("stamp_emission",),
        )
        m.verify_per_batch_tsa_root(
            layer_b,
            assurance_profile="regulated-high-assurance",
            expected_merkle_root_hex=merkle_root,
        )

    def test_happy_path_2_of_3_quorum_at_regulated_high_assurance_evidence_set_freeze(
        self, test_pinned, merkle_root, merkle_leaves, nonce_bytes
    ):
        tokens = [
            fx.mint_tsa_token(
                tsa_name=n, merkle_root_hex=merkle_root, nonce_bytes=nonce_bytes
            )
            for n in ("digicert-tsa", "globalsign-tsa")
        ]
        bls_agg = fx.mint_bls_aggregate(
            tsa_names=["digicert-tsa", "globalsign-tsa"],
            merkle_root_hex=merkle_root,
        )
        layer_b = self._build_layer_b(
            tokens=tokens,
            merkle_root=merkle_root,
            merkle_leaves=merkle_leaves,
            bls_agg=bls_agg,
            batched_event_kinds=("evidence_set_freeze",),
        )
        m.verify_per_batch_tsa_root(
            layer_b,
            assurance_profile="regulated-high-assurance",
            expected_merkle_root_hex=merkle_root,
        )

    def test_reject_tsa_not_in_allowlist(
        self, test_pinned, merkle_root, merkle_leaves, nonce_bytes
    ):
        token = fx.mint_tsa_token(
            tsa_name="digicert-tsa",
            merkle_root_hex=merkle_root,
            nonce_bytes=nonce_bytes,
        )
        token["tsa_name"] = "rogue-tsa"  # claims a TSA name NOT in NEXI_TSA_ALLOWLIST
        layer_b = self._build_layer_b(
            tokens=[token],
            merkle_root=merkle_root,
            merkle_leaves=merkle_leaves,
        )
        with pytest.raises(m.TSA_NOT_IN_ALLOWLIST):
            m.verify_per_batch_tsa_root(
                layer_b,
                assurance_profile="production-standard",
                expected_merkle_root_hex=merkle_root,
            )

    def test_reject_sha1_imprint(
        self, test_pinned, merkle_root, merkle_leaves, nonce_bytes
    ):
        token = fx.mint_tsa_token(
            tsa_name="digicert-tsa",
            merkle_root_hex=merkle_root,
            nonce_bytes=nonce_bytes,
            hash_algorithm="sha1",
        )
        layer_b = self._build_layer_b(
            tokens=[token],
            merkle_root=merkle_root,
            merkle_leaves=merkle_leaves,
        )
        with pytest.raises(m.TSA_WEAK_ALGORITHM):
            m.verify_per_batch_tsa_root(
                layer_b,
                assurance_profile="production-standard",
                expected_merkle_root_hex=merkle_root,
            )

    def test_reject_missing_nonce(self, test_pinned, merkle_root, merkle_leaves):
        token = fx.mint_tsa_token(
            tsa_name="digicert-tsa",
            merkle_root_hex=merkle_root,
            nonce_bytes=None,
        )
        layer_b = self._build_layer_b(
            tokens=[token],
            merkle_root=merkle_root,
            merkle_leaves=merkle_leaves,
        )
        with pytest.raises(m.TSA_NONCE_MISSING):
            m.verify_per_batch_tsa_root(
                layer_b,
                assurance_profile="production-standard",
                expected_merkle_root_hex=merkle_root,
            )

    def test_reject_imprint_does_not_match_recomputed_merkle_root(
        self, test_pinned, merkle_root, merkle_leaves, nonce_bytes
    ):
        wrong_imprint = hashlib.sha256(b"wrong-imprint").hexdigest()
        token = fx.mint_tsa_token(
            tsa_name="digicert-tsa",
            merkle_root_hex=merkle_root,
            nonce_bytes=nonce_bytes,
            imprint_hex_override=wrong_imprint,
        )
        layer_b = self._build_layer_b(
            tokens=[token],
            merkle_root=merkle_root,
            merkle_leaves=merkle_leaves,
        )
        with pytest.raises(m.TSA_IMPRINT_MISMATCH):
            m.verify_per_batch_tsa_root(
                layer_b,
                assurance_profile="production-standard",
                expected_merkle_root_hex=merkle_root,
            )

    def test_reject_invalid_cert_chain_to_eidas_qtl(
        self, test_pinned, merkle_root, merkle_leaves, nonce_bytes
    ):
        # Mint a token whose signing-cert is issued by a DIFFERENT, non-pinned CA.
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes as crypto_hashes
        from cryptography.x509.oid import NameOID
        import datetime

        rogue_ca_key = fx._det_rsa_key("S19c-test-rogue-ca")
        rogue_subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "Rogue CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Attacker"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
            ]
        )
        rogue_ca_cert = (
            x509.CertificateBuilder()
            .subject_name(rogue_subject)
            .issuer_name(rogue_subject)
            .public_key(rogue_ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2024, 1, 1))
            .not_valid_after(datetime.datetime(2030, 1, 1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .sign(rogue_ca_key, crypto_hashes.SHA256())
        )
        token = fx.mint_tsa_token(
            tsa_name="digicert-tsa",
            merkle_root_hex=merkle_root,
            nonce_bytes=nonce_bytes,
            issuing_ca_cert_override=rogue_ca_cert,
        )
        layer_b = self._build_layer_b(
            tokens=[token],
            merkle_root=merkle_root,
            merkle_leaves=merkle_leaves,
        )
        with pytest.raises(m.TSA_CERT_CHAIN_REJECTED):
            m.verify_per_batch_tsa_root(
                layer_b,
                assurance_profile="production-standard",
                expected_merkle_root_hex=merkle_root,
            )

    def test_reject_policy_oid_not_in_etsi_319_421_422_allowlist(
        self, test_pinned, merkle_root, merkle_leaves, nonce_bytes
    ):
        token = fx.mint_tsa_token(
            tsa_name="digicert-tsa",
            merkle_root_hex=merkle_root,
            nonce_bytes=nonce_bytes,
            policy_oid="1.2.3.4.5.6.7.8.9",
        )
        layer_b = self._build_layer_b(
            tokens=[token],
            merkle_root=merkle_root,
            merkle_leaves=merkle_leaves,
        )
        with pytest.raises(m.TSA_POLICY_OID_NOT_ALLOWED):
            m.verify_per_batch_tsa_root(
                layer_b,
                assurance_profile="production-standard",
                expected_merkle_root_hex=merkle_root,
            )

    def test_reject_highest_stakes_event_with_only_1_tsa(
        self, test_pinned, merkle_root, merkle_leaves, nonce_bytes
    ):
        token = fx.mint_tsa_token(
            tsa_name="digicert-tsa",
            merkle_root_hex=merkle_root,
            nonce_bytes=nonce_bytes,
        )
        layer_b = self._build_layer_b(
            tokens=[token],
            merkle_root=merkle_root,
            merkle_leaves=merkle_leaves,
            batched_event_kinds=("stamp_emission",),
        )
        with pytest.raises(m.TSA_QUORUM_INSUFFICIENT_FOR_HIGHEST_STAKES):
            m.verify_per_batch_tsa_root(
                layer_b,
                assurance_profile="regulated-high-assurance",
                expected_merkle_root_hex=merkle_root,
            )

    def test_reject_quorum_alias_collision_two_tsa_names_one_operator(
        self, test_pinned, monkeypatch, merkle_root, merkle_leaves, nonce_bytes
    ):
        """CC-2b R3-G6: two DISTINCT tsa_names that resolve to the SAME operator-ID
        do NOT satisfy the 2-of-3 quorum — distinctness is over the operator-ID
        namespace, not the tsa_name string. tsa_name-string distinctness (the
        pre-G6 behaviour) would have PASSED this (2 distinct names); operator-ID
        distinctness REJECTS it (1 real operator cannot fill 2 quorum slots)."""
        # Alias map: both allowlisted names belong to ONE legal operator.
        monkeypatch.setattr(
            m,
            "_TEST_OVERRIDE_TSA_OPERATOR_ID",
            {"digicert-tsa": "op:colluding-one", "globalsign-tsa": "op:colluding-one"},
            raising=False,
        )
        tokens = [
            fx.mint_tsa_token(
                tsa_name=n, merkle_root_hex=merkle_root, nonce_bytes=nonce_bytes
            )
            for n in ("digicert-tsa", "globalsign-tsa")
        ]
        bls_agg = fx.mint_bls_aggregate(
            tsa_names=["digicert-tsa", "globalsign-tsa"],
            merkle_root_hex=merkle_root,
        )
        layer_b = self._build_layer_b(
            tokens=tokens,
            merkle_root=merkle_root,
            merkle_leaves=merkle_leaves,
            bls_agg=bls_agg,
            batched_event_kinds=("stamp_emission",),
        )
        with pytest.raises(m.TSA_QUORUM_INSUFFICIENT_FOR_HIGHEST_STAKES):
            m.verify_per_batch_tsa_root(
                layer_b,
                assurance_profile="regulated-high-assurance",
                expected_merkle_root_hex=merkle_root,
            )

    def test_reject_quorum_unmapped_allowlisted_name_not_counted_fail_closed(
        self, test_pinned, monkeypatch, merkle_root, merkle_leaves, nonce_bytes
    ):
        """CC-2b R3-G6 fail-closed: an allowlisted TSA name with NO operator-ID
        mapping is not counted toward the quorum (it never falls back to
        tsa_name-string distinctness). With one name mapped and one unmapped,
        only 1 distinct operator is present → REJECT."""
        # Only digicert-tsa is mapped; globalsign-tsa is allowlisted but unmapped.
        monkeypatch.setattr(
            m,
            "_TEST_OVERRIDE_TSA_OPERATOR_ID",
            {"digicert-tsa": "op:mapped-one"},
            raising=False,
        )
        tokens = [
            fx.mint_tsa_token(
                tsa_name=n, merkle_root_hex=merkle_root, nonce_bytes=nonce_bytes
            )
            for n in ("digicert-tsa", "globalsign-tsa")
        ]
        bls_agg = fx.mint_bls_aggregate(
            tsa_names=["digicert-tsa", "globalsign-tsa"],
            merkle_root_hex=merkle_root,
        )
        layer_b = self._build_layer_b(
            tokens=tokens,
            merkle_root=merkle_root,
            merkle_leaves=merkle_leaves,
            bls_agg=bls_agg,
            batched_event_kinds=("stamp_emission",),
        )
        with pytest.raises(m.TSA_QUORUM_INSUFFICIENT_FOR_HIGHEST_STAKES):
            m.verify_per_batch_tsa_root(
                layer_b,
                assurance_profile="regulated-high-assurance",
                expected_merkle_root_hex=merkle_root,
            )

    def test_happy_path_quorum_distinct_operators_default_map_1to1(
        self, test_pinned, merkle_root, merkle_leaves, nonce_bytes
    ):
        """CC-2b R3-G6 positive: under the default NEXI_TSA_OPERATOR_ID (1:1 with
        the four real allowlist operators) two distinct tsa_names ARE two distinct
        operators, so the 2-of-3 quorum passes unchanged — the G6 refinement does
        not regress the clean-operator case."""
        tokens = [
            fx.mint_tsa_token(
                tsa_name=n, merkle_root_hex=merkle_root, nonce_bytes=nonce_bytes
            )
            for n in ("digicert-tsa", "entrust-tsa")
        ]
        bls_agg = fx.mint_bls_aggregate(
            tsa_names=["digicert-tsa", "entrust-tsa"],
            merkle_root_hex=merkle_root,
        )
        layer_b = self._build_layer_b(
            tokens=tokens,
            merkle_root=merkle_root,
            merkle_leaves=merkle_leaves,
            bls_agg=bls_agg,
            batched_event_kinds=("stamp_emission",),
        )
        m.verify_per_batch_tsa_root(
            layer_b,
            assurance_profile="regulated-high-assurance",
            expected_merkle_root_hex=merkle_root,
        )

    def test_reject_highest_stakes_event_missing_bls_aggregate(
        self, test_pinned, merkle_root, merkle_leaves, nonce_bytes
    ):
        tokens = [
            fx.mint_tsa_token(
                tsa_name=n, merkle_root_hex=merkle_root, nonce_bytes=nonce_bytes
            )
            for n in ("digicert-tsa", "globalsign-tsa")
        ]
        # No bls_agg supplied.
        layer_b = self._build_layer_b(
            tokens=tokens,
            merkle_root=merkle_root,
            merkle_leaves=merkle_leaves,
            batched_event_kinds=("evidence_set_freeze",),
        )
        with pytest.raises(m.BLS_AGGREGATE_MISSING_FOR_QUORUM):
            m.verify_per_batch_tsa_root(
                layer_b,
                assurance_profile="regulated-high-assurance",
                expected_merkle_root_hex=merkle_root,
            )

    def test_reject_bls_aggregate_verification_failure(
        self, test_pinned, merkle_root, merkle_leaves, nonce_bytes
    ):
        tokens = [
            fx.mint_tsa_token(
                tsa_name=n, merkle_root_hex=merkle_root, nonce_bytes=nonce_bytes
            )
            for n in ("digicert-tsa", "globalsign-tsa")
        ]
        # Aggregate is OVER A DIFFERENT MESSAGE — verification fails.
        wrong_msg = hashlib.sha256(b"not-the-merkle-root").hexdigest()
        bls_agg = fx.mint_bls_aggregate(
            tsa_names=["digicert-tsa", "globalsign-tsa"],
            merkle_root_hex=wrong_msg,
        )
        layer_b = self._build_layer_b(
            tokens=tokens,
            merkle_root=merkle_root,
            merkle_leaves=merkle_leaves,
            bls_agg=bls_agg,
            batched_event_kinds=("stamp_emission",),
        )
        with pytest.raises(m.BLS_AGGREGATE_VERIFICATION_FAILED):
            m.verify_per_batch_tsa_root(
                layer_b,
                assurance_profile="regulated-high-assurance",
                expected_merkle_root_hex=merkle_root,
            )

    def test_reject_bls_aggregate_with_fabricated_tsa_key(
        self, test_pinned, merkle_root, merkle_leaves, nonce_bytes
    ):
        tokens = [
            fx.mint_tsa_token(
                tsa_name=n, merkle_root_hex=merkle_root, nonce_bytes=nonce_bytes
            )
            for n in ("digicert-tsa", "globalsign-tsa")
        ]
        bls_agg = fx.mint_bls_aggregate(
            tsa_names=["digicert-tsa", "globalsign-tsa"],
            merkle_root_hex=merkle_root,
            spurious_extra_key_seed=b"\x99" * 32,
        )
        layer_b = self._build_layer_b(
            tokens=tokens,
            merkle_root=merkle_root,
            merkle_leaves=merkle_leaves,
            bls_agg=bls_agg,
            batched_event_kinds=("stamp_emission",),
        )
        with pytest.raises(
            (m.BLS_AGGREGATE_VERIFICATION_FAILED, m.TSA_NOT_IN_ALLOWLIST)
        ):
            m.verify_per_batch_tsa_root(
                layer_b,
                assurance_profile="regulated-high-assurance",
                expected_merkle_root_hex=merkle_root,
            )

    def test_ignore_bundle_supplied_required_quorum_recompute_per_profile(
        self, test_pinned, merkle_root, merkle_leaves, nonce_bytes
    ):
        # Bundle CLAIMS required_quorum {m:1, n:1} for a stamp_emission event
        # — verifier IGNORES bundle metadata, recomputes from
        # MULTI_TSA_QUORUM_M_OF_N + HIGHEST_STAKES_EVENT_KINDS, with only 1 TSA
        # present, raises TSA_QUORUM_INSUFFICIENT_FOR_HIGHEST_STAKES.
        token = fx.mint_tsa_token(
            tsa_name="digicert-tsa",
            merkle_root_hex=merkle_root,
            nonce_bytes=nonce_bytes,
        )
        layer_b = self._build_layer_b(
            tokens=[token],
            merkle_root=merkle_root,
            merkle_leaves=merkle_leaves,
            batched_event_kinds=("stamp_emission",),
            required_quorum={"m": 1, "n": 1},
        )
        with pytest.raises(m.TSA_QUORUM_INSUFFICIENT_FOR_HIGHEST_STAKES):
            m.verify_per_batch_tsa_root(
                layer_b,
                assurance_profile="regulated-high-assurance",
                expected_merkle_root_hex=merkle_root,
            )

    def test_ignore_bundle_supplied_acceptable_tsa_roots_recompute_against_allowlist(
        self, test_pinned, merkle_root, merkle_leaves, nonce_bytes
    ):
        token = fx.mint_tsa_token(
            tsa_name="digicert-tsa",
            merkle_root_hex=merkle_root,
            nonce_bytes=nonce_bytes,
        )
        token["tsa_name"] = "fake-tsa-1"
        layer_b = self._build_layer_b(
            tokens=[token],
            merkle_root=merkle_root,
            merkle_leaves=merkle_leaves,
            acceptable_tsa_roots=["fake-tsa-1"],  # bundle SUPPLIES — verifier IGNORES
        )
        with pytest.raises(m.TSA_NOT_IN_ALLOWLIST):
            m.verify_per_batch_tsa_root(
                layer_b,
                assurance_profile="production-standard",
                expected_merkle_root_hex=merkle_root,
            )

    def test_placeholder_tsa_5_slot_not_yet_filled_rejects_real_tokens(
        self, test_pinned, merkle_root, merkle_leaves, nonce_bytes
    ):
        # Even though `placeholder-tsa-5` is in NEXI_TSA_ALLOWLIST as a name
        # reservation, the verifier has no cert chain pinned — should reject.
        token = fx.mint_tsa_token(
            tsa_name="placeholder-tsa-5",
            merkle_root_hex=merkle_root,
            nonce_bytes=nonce_bytes,
        )
        layer_b = self._build_layer_b(
            tokens=[token],
            merkle_root=merkle_root,
            merkle_leaves=merkle_leaves,
        )
        with pytest.raises((m.TSA_CERT_CHAIN_REJECTED, m.TSA_NOT_IN_ALLOWLIST)):
            m.verify_per_batch_tsa_root(
                layer_b,
                assurance_profile="production-standard",
                expected_merkle_root_hex=merkle_root,
            )


# ──────────────────────────────────────────────────────────────────────────
# TestVerifyPerEventRoughtimeQuorum — Roughtime 3-of-4 quorum + nonce-binding
# + draft-19 §Misbehavior pairwise fork detection
# ──────────────────────────────────────────────────────────────────────────


class TestVerifyPerEventRoughtimeQuorum:
    def _build_layer_b(
        self,
        *,
        sreps,
        event_id="event-0",
        event_hash_hex=None,
        preimage_label="event",
        roots_attested=None,
        quorum_count=None,
    ):
        if event_hash_hex is None:
            event_hash_hex = hashlib.sha256(b"event-0").hexdigest()
        entry = {
            "event_id": event_id,
            "event_hash_hex": event_hash_hex,
            "preimage_label": preimage_label,
            "srep_responses": sreps,
        }
        if roots_attested is not None:
            entry["roots_attested"] = roots_attested
        if quorum_count is not None:
            entry["quorum_count"] = quorum_count
        return {"per_event_roughtime": [entry]}

    def _preimage_and_nonce(self, event_id="event-0", preimage_label="event"):
        preimage = f"S19c-preimage-{event_id}".encode()
        nonce = fx.expected_nonce_for(preimage_label, preimage)
        return preimage, nonce

    def test_happy_path_3_of_4_pinned_roots_distinct_orgs_radi_within_profile_max(
        self, test_pinned
    ):
        preimage, nonce = self._preimage_and_nonce()
        sreps = [
            fx.mint_srep(
                root_name="cloudflare-roughtime-2",
                midp_ms=1_700_000_000_000,
                radi_ms=50,
                nonce=nonce,
            ),
            fx.mint_srep(
                root_name="int08h-roughtime",
                midp_ms=1_700_000_000_010,
                radi_ms=50,
                nonce=nonce,
            ),
            fx.mint_srep(
                root_name="roughtime-se",
                midp_ms=1_700_000_000_020,
                radi_ms=50,
                nonce=nonce,
            ),
        ]
        layer_b = self._build_layer_b(sreps=sreps)
        m.verify_per_event_roughtime_quorum(
            layer_b,
            assurance_profile="production-standard",
            expected_preimage_by_event_id={"event-0": preimage},
        )

    def test_happy_path_event_preimage_nonce_binding(self, test_pinned):
        preimage, nonce = self._preimage_and_nonce(preimage_label="event")
        sreps = [
            fx.mint_srep(
                root_name=n, midp_ms=1_700_000_000_000, radi_ms=50, nonce=nonce
            )
            for n in ("cloudflare-roughtime-2", "int08h-roughtime", "roughtime-se")
        ]
        layer_b = self._build_layer_b(sreps=sreps, preimage_label="event")
        m.verify_per_event_roughtime_quorum(
            layer_b,
            assurance_profile="production-standard",
            expected_preimage_by_event_id={"event-0": preimage},
        )

    def test_roughtime_root_override_emits_marker(self, test_pinned, caplog):
        """Swapping the pinned Roughtime roots self-announces through
        _OVERRIDE_MARKER (the `roughtime_roots` resolve) — closing the prior
        silent-substitution gap, symmetric with the TSA-CA / BLS resolvers."""
        preimage, nonce = self._preimage_and_nonce(preimage_label="event")
        sreps = [
            fx.mint_srep(
                root_name=n, midp_ms=1_700_000_000_000, radi_ms=50, nonce=nonce
            )
            for n in ("cloudflare-roughtime-2", "int08h-roughtime", "roughtime-se")
        ]
        layer_b = self._build_layer_b(sreps=sreps, preimage_label="event")
        caplog.clear()
        m.verify_per_event_roughtime_quorum(
            layer_b,
            assurance_profile="production-standard",
            expected_preimage_by_event_id={"event-0": preimage},
        )
        # The marker fires from the Roughtime resolver itself, not just the
        # fixture's own manual log line.
        assert "production keys never reached" in caplog.text
        assert "roughtime_roots" in caplog.text

    def test_happy_path_send_preimage_label_nonce_binding(self, test_pinned):
        preimage, nonce = self._preimage_and_nonce(preimage_label="send")
        sreps = [
            fx.mint_srep(
                root_name=n, midp_ms=1_700_000_000_000, radi_ms=50, nonce=nonce
            )
            for n in ("cloudflare-roughtime-2", "int08h-roughtime", "roughtime-se")
        ]
        layer_b = self._build_layer_b(sreps=sreps, preimage_label="send")
        m.verify_per_event_roughtime_quorum(
            layer_b,
            assurance_profile="production-standard",
            expected_preimage_by_event_id={"event-0": preimage},
        )

    def test_happy_path_ack_preimage_label_nonce_binding(self, test_pinned):
        preimage, nonce = self._preimage_and_nonce(preimage_label="ack")
        sreps = [
            fx.mint_srep(
                root_name=n, midp_ms=1_700_000_000_000, radi_ms=50, nonce=nonce
            )
            for n in ("cloudflare-roughtime-2", "int08h-roughtime", "roughtime-se")
        ]
        layer_b = self._build_layer_b(sreps=sreps, preimage_label="ack")
        m.verify_per_event_roughtime_quorum(
            layer_b,
            assurance_profile="production-standard",
            expected_preimage_by_event_id={"event-0": preimage},
        )

    def test_reject_only_2_of_4_pinned_roots_responded(self, test_pinned):
        preimage, nonce = self._preimage_and_nonce()
        sreps = [
            fx.mint_srep(
                root_name=n, midp_ms=1_700_000_000_000, radi_ms=50, nonce=nonce
            )
            for n in ("cloudflare-roughtime-2", "int08h-roughtime")
        ]
        layer_b = self._build_layer_b(sreps=sreps)
        with pytest.raises(m.ROUGHTIME_QUORUM_INSUFFICIENT):
            m.verify_per_event_roughtime_quorum(
                layer_b,
                assurance_profile="production-standard",
                expected_preimage_by_event_id={"event-0": preimage},
            )

    def test_reject_pairwise_midp_radi_fork(self, test_pinned):
        # Construct three SREPs whose [MIDP-RADI, MIDP+RADI] intervals are
        # NON-OVERLAPPING for at least one pair — per draft-19 §Misbehavior
        # this MUST raise ROUGHTIME_FORK_DETECTED.
        #
        # SREP_A: MIDP=1_700_000_000_000, RADI=50 -> interval [...-50, ...+50]
        # SREP_B: MIDP=1_700_000_000_010, RADI=50 -> overlaps with A
        # SREP_C: MIDP=1_700_001_000_000, RADI=50 -> interval far in future,
        #         NON-OVERLAPPING with A and B -> forks detected.
        preimage, nonce = self._preimage_and_nonce()
        sreps = [
            fx.mint_srep(
                root_name="cloudflare-roughtime-2",
                midp_ms=1_700_000_000_000,
                radi_ms=50,
                nonce=nonce,
            ),
            fx.mint_srep(
                root_name="int08h-roughtime",
                midp_ms=1_700_000_000_010,
                radi_ms=50,
                nonce=nonce,
            ),
            fx.mint_srep(
                root_name="roughtime-se",
                midp_ms=1_700_001_000_000,
                radi_ms=50,
                nonce=nonce,
            ),
        ]
        layer_b = self._build_layer_b(sreps=sreps)
        with pytest.raises(m.ROUGHTIME_FORK_DETECTED):
            m.verify_per_event_roughtime_quorum(
                layer_b,
                assurance_profile="production-standard",
                expected_preimage_by_event_id={"event-0": preimage},
            )

    def test_reject_pairwise_midp_radi_fork_reverse_direction(self, test_pinned):
        # Same fork pattern but with the "far-future" SREP listed first —
        # the pairwise check must catch the violation regardless of order.
        preimage, nonce = self._preimage_and_nonce()
        sreps = [
            fx.mint_srep(
                root_name="roughtime-se",
                midp_ms=1_700_001_000_000,
                radi_ms=50,
                nonce=nonce,
            ),
            fx.mint_srep(
                root_name="cloudflare-roughtime-2",
                midp_ms=1_700_000_000_000,
                radi_ms=50,
                nonce=nonce,
            ),
            fx.mint_srep(
                root_name="int08h-roughtime",
                midp_ms=1_700_000_000_010,
                radi_ms=50,
                nonce=nonce,
            ),
        ]
        layer_b = self._build_layer_b(sreps=sreps)
        with pytest.raises(m.ROUGHTIME_FORK_DETECTED):
            m.verify_per_event_roughtime_quorum(
                layer_b,
                assurance_profile="production-standard",
                expected_preimage_by_event_id={"event-0": preimage},
            )

    def test_reject_srep_nonce_does_not_bind_to_recomputed_expected_nonce(
        self, test_pinned
    ):
        preimage, _ = self._preimage_and_nonce()
        bogus_nonce = secrets.token_bytes(32)  # random — not bound to preimage
        sreps = [
            fx.mint_srep(
                root_name=n, midp_ms=1_700_000_000_000, radi_ms=50, nonce=bogus_nonce
            )
            for n in ("cloudflare-roughtime-2", "int08h-roughtime", "roughtime-se")
        ]
        layer_b = self._build_layer_b(sreps=sreps)
        with pytest.raises(m.ROUGHTIME_NONCE_BINDING_MISMATCH):
            m.verify_per_event_roughtime_quorum(
                layer_b,
                assurance_profile="production-standard",
                expected_preimage_by_event_id={"event-0": preimage},
            )

    def test_reject_srep_obtained_for_different_preimage_label(self, test_pinned):
        # SREP minted with preimage_label="event"; bundle claims preimage_label="send"
        # — same preimage bytes but different domain-separator nonce; raises.
        preimage, nonce_event = self._preimage_and_nonce(preimage_label="event")
        sreps = [
            fx.mint_srep(
                root_name=n, midp_ms=1_700_000_000_000, radi_ms=50, nonce=nonce_event
            )
            for n in ("cloudflare-roughtime-2", "int08h-roughtime", "roughtime-se")
        ]
        layer_b = self._build_layer_b(sreps=sreps, preimage_label="send")  # MISMATCH
        with pytest.raises(m.ROUGHTIME_NONCE_BINDING_MISMATCH):
            m.verify_per_event_roughtime_quorum(
                layer_b,
                assurance_profile="production-standard",
                expected_preimage_by_event_id={"event-0": preimage},
            )

    def test_reject_radi_exceeds_profile_max(self, test_pinned):
        preimage, nonce = self._preimage_and_nonce()
        sreps = [
            fx.mint_srep(
                root_name="cloudflare-roughtime-2",
                midp_ms=1_700_000_000_000,
                radi_ms=200,
                nonce=nonce,
            ),  # >100 ceiling
            fx.mint_srep(
                root_name="int08h-roughtime",
                midp_ms=1_700_000_000_010,
                radi_ms=50,
                nonce=nonce,
            ),
            fx.mint_srep(
                root_name="roughtime-se",
                midp_ms=1_700_000_000_020,
                radi_ms=50,
                nonce=nonce,
            ),
        ]
        layer_b = self._build_layer_b(sreps=sreps)
        with pytest.raises(m.ROUGHTIME_RADI_EXCEEDS_PROFILE_MAX):
            m.verify_per_event_roughtime_quorum(
                layer_b,
                assurance_profile="production-standard",
                expected_preimage_by_event_id={"event-0": preimage},
            )

    def test_reject_root_not_in_pinned_set(self, test_pinned):
        preimage, nonce = self._preimage_and_nonce()
        sreps = [
            fx.mint_srep(
                root_name=n, midp_ms=1_700_000_000_000, radi_ms=50, nonce=nonce
            )
            for n in ("cloudflare-roughtime-2", "int08h-roughtime", "roughtime-se")
        ]
        # Add a 4th SREP claiming a non-pinned root name.
        extra = fx.mint_srep(
            root_name="cloudflare-roughtime-2",
            midp_ms=1_700_000_000_030,
            radi_ms=50,
            nonce=nonce,
        )
        extra["root_name"] = "rogue-root"
        sreps.append(extra)
        layer_b = self._build_layer_b(sreps=sreps)
        with pytest.raises(m.ROUGHTIME_ROOT_NOT_IN_PINNED_SET):
            m.verify_per_event_roughtime_quorum(
                layer_b,
                assurance_profile="production-standard",
                expected_preimage_by_event_id={"event-0": preimage},
            )

    def test_reject_invalid_srep_signature_under_pinned_key(self, test_pinned):
        preimage, nonce = self._preimage_and_nonce()
        # Mint SREP with an attacker key — bundle claims `cloudflare-roughtime-2`
        # but the signature does NOT verify under the pinned pubkey.
        from cryptography.hazmat.primitives.asymmetric import ed25519

        attacker_sk = ed25519.Ed25519PrivateKey.from_private_bytes(b"\xaa" * 32)
        attacker_pk = attacker_sk.public_key().public_bytes(
            encoding=__import__(
                "cryptography"
            ).hazmat.primitives.serialization.Encoding.Raw,
            format=__import__(
                "cryptography"
            ).hazmat.primitives.serialization.PublicFormat.Raw,
        )
        bad = fx.mint_srep(
            root_name="cloudflare-roughtime-2",
            midp_ms=1_700_000_000_000,
            radi_ms=50,
            nonce=nonce,
            pubkey_override=attacker_pk,
            signing_key_override=attacker_sk,
        )
        sreps = [bad] + [
            fx.mint_srep(
                root_name=n, midp_ms=1_700_000_000_000 + 10 * i, radi_ms=50, nonce=nonce
            )
            for i, n in enumerate(("int08h-roughtime", "roughtime-se"), start=1)
        ]
        layer_b = self._build_layer_b(sreps=sreps)
        with pytest.raises(m.ROUGHTIME_SREP_SIGNATURE_INVALID):
            m.verify_per_event_roughtime_quorum(
                layer_b,
                assurance_profile="production-standard",
                expected_preimage_by_event_id={"event-0": preimage},
            )

    def test_reject_cloudflare_polled_on_2002_decommissioned_port(self, test_pinned):
        preimage, nonce = self._preimage_and_nonce()
        # SREP claims root_name="cloudflare-roughtime-2" but metadata port=2002 (decommissioned).
        bad = fx.mint_srep(
            root_name="cloudflare-roughtime-2",
            midp_ms=1_700_000_000_000,
            radi_ms=50,
            nonce=nonce,
        )
        bad["port"] = 2002  # SILENT-FAILURE TRAP
        sreps = [bad] + [
            fx.mint_srep(
                root_name=n, midp_ms=1_700_000_000_000 + 10 * i, radi_ms=50, nonce=nonce
            )
            for i, n in enumerate(("int08h-roughtime", "roughtime-se"), start=1)
        ]
        layer_b = self._build_layer_b(sreps=sreps)
        with pytest.raises(m.ROUGHTIME_PORT_DECOMMISSIONED):
            m.verify_per_event_roughtime_quorum(
                layer_b,
                assurance_profile="production-standard",
                expected_preimage_by_event_id={"event-0": preimage},
            )

    def test_ignore_bundle_supplied_roots_attested_recompute_against_pinned_set(
        self, test_pinned
    ):
        preimage, nonce = self._preimage_and_nonce()
        # Bundle SUPPLIES fake roots_attested + fake SREPs from non-pinned keys.
        from cryptography.hazmat.primitives.asymmetric import ed25519

        attacker_sks = [
            ed25519.Ed25519PrivateKey.from_private_bytes(bytes([i]) * 32)
            for i in (0xAA, 0xBB, 0xCC)
        ]
        attacker_pks = [
            sk.public_key().public_bytes(
                encoding=__import__(
                    "cryptography"
                ).hazmat.primitives.serialization.Encoding.Raw,
                format=__import__(
                    "cryptography"
                ).hazmat.primitives.serialization.PublicFormat.Raw,
            )
            for sk in attacker_sks
        ]
        sreps = []
        for i, (sk, pk) in enumerate(zip(attacker_sks, attacker_pks)):
            srep = fx.mint_srep(
                root_name="cloudflare-roughtime-2",
                midp_ms=1_700_000_000_000 + 10 * i,
                radi_ms=50,
                nonce=nonce,
                pubkey_override=pk,
                signing_key_override=sk,
            )
            srep["root_name"] = f"fake-root-{i + 1}"
            sreps.append(srep)
        layer_b = self._build_layer_b(
            sreps=sreps,
            roots_attested=["fake-root-1", "fake-root-2", "fake-root-3"],
        )
        with pytest.raises(m.ROUGHTIME_ROOT_NOT_IN_PINNED_SET):
            m.verify_per_event_roughtime_quorum(
                layer_b,
                assurance_profile="production-standard",
                expected_preimage_by_event_id={"event-0": preimage},
            )

    def test_ignore_bundle_supplied_quorum_count_recompute_per_overlay(
        self, test_pinned
    ):
        # Bundle claims quorum_count=2 + 2 valid SREPs — verifier recomputes
        # against ROUGHTIME_QUORUM_M_OF_N = (3, 4) and raises.
        preimage, nonce = self._preimage_and_nonce()
        sreps = [
            fx.mint_srep(
                root_name=n, midp_ms=1_700_000_000_000, radi_ms=50, nonce=nonce
            )
            for n in ("cloudflare-roughtime-2", "int08h-roughtime")
        ]
        layer_b = self._build_layer_b(sreps=sreps, quorum_count=2)
        with pytest.raises(m.ROUGHTIME_QUORUM_INSUFFICIENT):
            m.verify_per_event_roughtime_quorum(
                layer_b,
                assurance_profile="production-standard",
                expected_preimage_by_event_id={"event-0": preimage},
            )

    def test_happy_path_3_us_servers_pass_quorum_documented_residual(self, test_pinned):
        # DOCUMENTED HONEST RESIDUAL — Cloudflare + int08h + time.txryan.com
        # are all US-org-operated; this MUST PASS at v0.3 (geo-distribution
        # tightening is the v0.4 follow-up). This test binds the residual
        # into the suite so we never tighten the rule without updating both
        # this test and FOLLOWUP_V0_4.
        preimage, nonce = self._preimage_and_nonce()
        sreps = [
            fx.mint_srep(
                root_name="cloudflare-roughtime-2",
                midp_ms=1_700_000_000_000,
                radi_ms=50,
                nonce=nonce,
            ),
            fx.mint_srep(
                root_name="int08h-roughtime",
                midp_ms=1_700_000_000_010,
                radi_ms=50,
                nonce=nonce,
            ),
            fx.mint_srep(
                root_name="time-txryan-com",
                midp_ms=1_700_000_000_020,
                radi_ms=50,
                nonce=nonce,
            ),
        ]
        layer_b = self._build_layer_b(sreps=sreps)
        m.verify_per_event_roughtime_quorum(
            layer_b,
            assurance_profile="production-standard",
            expected_preimage_by_event_id={"event-0": preimage},
        )
        # Hard-coded reminder: if this test ever needs to be tightened, both
        # this test and FOLLOWUP_V0_4 must change together.
        assert any(
            "NON_US_NON_EU_ROUGHTIME_OPERATOR" in entry for entry in m.FOLLOWUP_V0_4
        )

    def test_happy_path_3_servers_including_roughtime_se_passes_quorum(
        self, test_pinned
    ):
        preimage, nonce = self._preimage_and_nonce()
        sreps = [
            fx.mint_srep(
                root_name="cloudflare-roughtime-2",
                midp_ms=1_700_000_000_000,
                radi_ms=50,
                nonce=nonce,
            ),
            fx.mint_srep(
                root_name="int08h-roughtime",
                midp_ms=1_700_000_000_010,
                radi_ms=50,
                nonce=nonce,
            ),
            fx.mint_srep(
                root_name="roughtime-se",
                midp_ms=1_700_000_000_020,
                radi_ms=50,
                nonce=nonce,
            ),
        ]
        layer_b = self._build_layer_b(sreps=sreps)
        m.verify_per_event_roughtime_quorum(
            layer_b,
            assurance_profile="production-standard",
            expected_preimage_by_event_id={"event-0": preimage},
        )


# ──────────────────────────────────────────────────────────────────────────
# TestEnforceAnchorWindow — hardcoded ceilings; bundle-supplied ignored
# ──────────────────────────────────────────────────────────────────────────


class TestEnforceAnchorWindow:
    def test_happy_path_observed_within_profile_ceiling(self):
        m.enforce_anchor_window(
            "regulated-high-assurance",
            bundle_anchor_window_ms=None,
            observed_anchor_window_ms=50,
        )

    def test_reject_observed_exceeds_regulated_ceiling(self):
        with pytest.raises(m.ANCHOR_WINDOW_EXCEEDS_PROFILE_CEILING):
            m.enforce_anchor_window(
                "regulated-high-assurance",
                bundle_anchor_window_ms=None,
                observed_anchor_window_ms=150,
            )

    def test_reject_observed_exceeds_production_ceiling(self):
        with pytest.raises(m.ANCHOR_WINDOW_EXCEEDS_PROFILE_CEILING):
            m.enforce_anchor_window(
                "production-standard",
                bundle_anchor_window_ms=None,
                observed_anchor_window_ms=120_000,
            )

    def test_bundle_supplied_anchor_window_ms_ignored_observed_used(self):
        # Bundle claims a tiny 50ms window, but observed is 120s — verifier
        # IGNORES bundle metadata and uses observed against the profile table.
        with pytest.raises(m.ANCHOR_WINDOW_EXCEEDS_PROFILE_CEILING):
            m.enforce_anchor_window(
                "production-standard",
                bundle_anchor_window_ms=50,
                observed_anchor_window_ms=120_000,
            )

    def test_offline_auditor_24h_ceiling_holds(self):
        # 23h is within the 24h ceiling — should not raise.
        m.enforce_anchor_window(
            "offline-auditor-minimal",
            bundle_anchor_window_ms=None,
            observed_anchor_window_ms=23 * 60 * 60 * 1000,
        )


# ──────────────────────────────────────────────────────────────────────────
# TestMultiTSAQuorumRequired — pure policy lookup
# ──────────────────────────────────────────────────────────────────────────


class TestMultiTSAQuorumRequired:
    def test_stamp_emission_at_regulated_returns_true(self):
        assert (
            m.multi_tsa_quorum_required("stamp_emission", "regulated-high-assurance")
            is True
        )

    def test_evidence_set_freeze_at_regulated_returns_true(self):
        assert (
            m.multi_tsa_quorum_required(
                "evidence_set_freeze", "regulated-high-assurance"
            )
            is True
        )

    def test_retrieval_at_regulated_returns_false(self):
        assert (
            m.multi_tsa_quorum_required("retrieval", "regulated-high-assurance")
            is False
        )

    def test_stamp_emission_at_production_standard_returns_false(self):
        assert (
            m.multi_tsa_quorum_required("stamp_emission", "production-standard")
            is False
        )

    def test_stamp_emission_at_offline_auditor_returns_false(self):
        assert (
            m.multi_tsa_quorum_required("stamp_emission", "offline-auditor-minimal")
            is False
        )

    def test_reasoning_step_at_regulated_returns_false(self):
        assert (
            m.multi_tsa_quorum_required("reasoning_step", "regulated-high-assurance")
            is False
        )


# ──────────────────────────────────────────────────────────────────────────
# TestPipelineDisciplineDoNotFallback — fork → hard-fail; tee_counter →
# fail-closed at v0.3
# ──────────────────────────────────────────────────────────────────────────


class TestPipelineDisciplineDoNotFallback:
    def test_roughtime_fork_does_not_silent_fall_to_tsa(self, test_pinned):
        # layer_b carries forking Roughtime evidence AND no per_batch_tsa_root.
        # Verifier MUST raise ROUGHTIME_FORK_DETECTED, MUST NOT silently
        # degrade to "TSA-only therefore pass".
        preimage = b"S19c-preimage-event-fork"
        nonce = fx.expected_nonce_for("event", preimage)
        sreps = [
            fx.mint_srep(
                root_name="cloudflare-roughtime-2",
                midp_ms=1_700_000_000_000,
                radi_ms=50,
                nonce=nonce,
            ),
            fx.mint_srep(
                root_name="int08h-roughtime",
                midp_ms=1_700_000_000_010,
                radi_ms=50,
                nonce=nonce,
            ),
            fx.mint_srep(
                root_name="roughtime-se",
                midp_ms=1_700_001_000_000,
                radi_ms=50,
                nonce=nonce,
            ),
        ]
        layer_b = {
            "per_event_roughtime": [
                {
                    "event_id": "event-fork",
                    "event_hash_hex": hashlib.sha256(b"event-fork").hexdigest(),
                    "preimage_label": "event",
                    "srep_responses": sreps,
                }
            ],
        }
        with pytest.raises(m.ROUGHTIME_FORK_DETECTED):
            m.verify_per_event_roughtime_quorum(
                layer_b,
                assurance_profile="production-standard",
                expected_preimage_by_event_id={"event-fork": preimage},
            )

    def test_tee_counter_kind_hard_fails_at_v0_3(self, test_pinned):
        # An SREP-like entry carrying an unrecognized `kind="tee_counter"` —
        # at the S19c Layer B verifier surface, this is forward-unknown
        # evidence at v0.3 (C17 deferred per the internal design notes).
        # Verifier MUST treat as unrecognized and hard-fail rather than
        # silently accept.
        preimage = b"S19c-preimage-event-tee"
        nonce = fx.expected_nonce_for("event", preimage)
        srep = fx.mint_srep(
            root_name="cloudflare-roughtime-2",
            midp_ms=1_700_000_000_000,
            radi_ms=50,
            nonce=nonce,
        )
        srep["kind"] = "tee_counter"  # forward-unknown discriminator
        layer_b = {
            "per_event_roughtime": [
                {
                    "event_id": "event-tee",
                    "event_hash_hex": hashlib.sha256(b"event-tee").hexdigest(),
                    "preimage_label": "event",
                    "srep_responses": [srep],
                }
            ],
        }
        # The exact code here may be ROUGHTIME_QUORUM_INSUFFICIENT (the
        # tee_counter entry is rejected and the quorum then short-falls) OR
        # a dedicated rejection — the assertion is "MUST raise some
        # C19LayerBError", encoding the fail-closed discipline without
        # over-specifying which code applies.
        with pytest.raises(m.C19LayerBError):
            m.verify_per_event_roughtime_quorum(
                layer_b,
                assurance_profile="production-standard",
                expected_preimage_by_event_id={"event-tee": preimage},
            )


# ──────────────────────────────────────────────────────────────────────────
# TestBuildLayerBAnchorsSubkey — c19c-008 emitter-side assembly helper
# ──────────────────────────────────────────────────────────────────────────


class TestBuildLayerBAnchorsSubkey:
    def test_empty_returns_empty_dict(self):
        out = m.build_layer_b_anchors_subkey()
        assert out == {}

    def test_per_batch_only_round_trips(self):
        per_batch = {
            "merkle_root_hex": "ab" * 32,
            "merkle_leaves": [],
            "rfc3161_tokens": [],
            "batched_event_kinds": ["retrieval"],
        }
        out = m.build_layer_b_anchors_subkey(per_batch_tsa_root=per_batch)
        assert out == {"per_batch_tsa_root": per_batch}
        assert "per_event_roughtime" not in out

    def test_per_event_only_round_trips(self):
        per_event = [
            {
                "event_id": "event-0",
                "event_hash_hex": "cd" * 32,
                "preimage_label": "event",
                "srep_responses": [],
            }
        ]
        out = m.build_layer_b_anchors_subkey(per_event_roughtime=per_event)
        assert out == {"per_event_roughtime": per_event}
        assert "per_batch_tsa_root" not in out

    def test_both_present_round_trips(self):
        per_batch = {
            "merkle_root_hex": "ab" * 32,
            "merkle_leaves": [],
            "rfc3161_tokens": [],
            "batched_event_kinds": ["retrieval"],
        }
        per_event = [
            {
                "event_id": "event-0",
                "event_hash_hex": "cd" * 32,
                "preimage_label": "event",
                "srep_responses": [],
            }
        ]
        out = m.build_layer_b_anchors_subkey(
            per_batch_tsa_root=per_batch,
            per_event_roughtime=per_event,
        )
        assert out == {
            "per_batch_tsa_root": per_batch,
            "per_event_roughtime": per_event,
        }

    def test_verifier_reads_what_emitter_wrote(self, test_pinned):
        # End-to-end: build sub-key via helper → pass to
        # verify_per_batch_tsa_root with matching expected_merkle_root_hex
        # → verifier accepts.
        import secrets

        event_hashes = [
            hashlib.sha256(f"S19c-roundtrip-event-{i}".encode()).hexdigest()
            for i in range(3)
        ]
        merkle = fx.merkle_root_of(event_hashes)
        leaves = [
            {"event_id": f"event-{i}", "event_hash_hex": h, "leaf_index": i}
            for i, h in enumerate(event_hashes)
        ]
        nonce = secrets.token_bytes(8)
        token = fx.mint_tsa_token(
            tsa_name="digicert-tsa",
            merkle_root_hex=merkle,
            nonce_bytes=nonce,
        )
        per_batch = {
            "merkle_root_hex": merkle,
            "merkle_leaves": leaves,
            "rfc3161_tokens": [token],
            "batched_event_kinds": ["retrieval"],
        }
        layer_b = m.build_layer_b_anchors_subkey(per_batch_tsa_root=per_batch)
        m.verify_per_batch_tsa_root(
            layer_b,
            assurance_profile="production-standard",
            expected_merkle_root_hex=merkle,
        )


class TestBLSCiphersuiteBinding:
    """The standards-currency must-fix: the BLS correctness anchor is the
    ciphersuite (BLS_CIPHERSUITE_ID), not the inert source-I-D version string.
    These bind that claim to the installed py_ecc's actual DST."""

    def test_pinned_id_matches_installed_pyecc_dst(self):
        # The pin must equal the DST py_ecc actually applies; if py_ecc is
        # upgraded to a different suite this test fails before any verify does.
        from py_ecc.bls import G2ProofOfPossession as bls

        assert bls.DST == m.BLS_CIPHERSUITE_ID.encode("ascii")

    def test_binding_guard_passes_under_real_pyecc(self):
        # No raise under the real, correctly-pinned library.
        m._assert_bls_ciphersuite_binding()

    def test_binding_guard_fails_closed_on_ciphersuite_drift(self, monkeypatch):
        # Simulate a py_ecc upgrade that silently changed the suite: the guard
        # must refuse rather than verify under an unpinned ciphersuite.
        monkeypatch.setattr(
            m, "BLS_CIPHERSUITE_ID", "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
        )
        with pytest.raises(m.BLS_AGGREGATE_VERIFICATION_FAILED):
            m._assert_bls_ciphersuite_binding()

    def test_version_string_is_provenance_not_expiry_claim(self):
        # Documents the correction: -06 is the final revision; the recorded
        # expiry is the I-D auto-expiry, not its last-updated date.
        assert m.BLS_SIGNATURE_VERSION == "draft-irtf-cfrg-bls-signature-06"
        assert m.BLS_SIGNATURE_LAST_UPDATED == "2025-11-02"
        assert m.BLS_SIGNATURE_EXPIRED_AT == "2026-05-06"
