"""Tests for SCITT v0.5 Phase B+C — Rekor anchor (audit_bundle/extensions/rekor_anchor.py).

Teeth come from three places, NOT a build-then-check roundtrip:
  1. The test builds proofs with the RECURSIVE RFC 6962 definitions (MTH/PATH); the module
     verifies with the ITERATIVE path-walk algorithm. Agreement across two distinct
     implementations of the same spec is meaningful.
  2. A from-scratch, hand-derived 2-leaf known-answer pins the RFC 6962 hashing convention
     using raw hashlib (independent of the module's primitives).
  3. Negative tests: tampered hash / wrong index / wrong root / wrong leaf MUST fail.
Plus a lock that the RFC 6962 convention is the INVERSE of the in-tree per-bundle convention,
so nobody "consolidates" the two Merkle helpers and silently breaks Rekor verification.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from audit_bundle.extensions.rekor_anchor import (
    REASON_CHECKPOINT_NOT_EVALUATED,
    REASON_CHECKPOINT_ROOT_MISMATCH,
    REASON_CHECKPOINT_SIGNATURE_INVALID,
    REASON_INCLUSION_PROOF_FAILED,
    REASON_MALFORMED_BUNDLE,
    RekorAnchor,
    RekorAnchorError,
    ReplayTransport,
    assemble_rekor_backed_statement,
    load_rekor_log_public_key,
    parse_checkpoint_note,
    register_signed_statement,
    rekor_anchor_from_sigstore_bundle,
    rekor_key_hint,
    rfc6962_leaf_hash,
    rfc6962_node_hash,
    root_from_inclusion_proof,
    verify_checkpoint_signature,
    verify_inclusion_proof,
    verify_rekor_backed_statement,
)

_FIXTURE = Path(__file__).parent / "fixtures" / "rekor_real_entry_v1.json"

# A REAL Sigstore STAGING bundle (Fulcio cert + Rekor staging tlog entry),
# keyless-minted by the .github/workflows/keyless-attest-staging.yml run over the
# verifier sdist. Grounds the native inclusion recompute against a live staging
# entry — distinct from the production rekor_real_entry_v1.json fixture.
_STAGING_BUNDLE_FIXTURE = (
    Path(__file__).parent / "fixtures" / "sigstore_staging_bundle_v0_3.json"
)


def _p256_signed_note(origin: str, tree_size: int, root: bytes, sk) -> str:
    """Build a valid Go signed-note checkpoint over (origin, size, base64(root)), ECDSA P-256.

    Mirrors the real Rekor checkpoint format so the synthetic Phase-C tests exercise the SAME
    parse + ECDSA-verify path as the real-fixture test (no special-cased checkpoint shape).
    """
    body = f"{origin}\n{tree_size}\n{base64.b64encode(root).decode()}\n"
    sig = sk.sign(body.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    hint = rekor_key_hint(sk.public_key())
    sigline = f"— {origin.split(' ')[0]} {base64.b64encode(hint + sig).decode()}"
    return body + "\n" + sigline + "\n"


# --- Independent RFC 6962 reference (recursive MTH / PATH per RFC 6962 §2.1). ---


def _largest_power_of_two_below(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _mth(leaves: list[bytes]) -> bytes:
    """Merkle Tree Hash over leaf PREIMAGES (recursive RFC 6962 definition)."""
    if len(leaves) == 1:
        return rfc6962_leaf_hash(leaves[0])
    k = _largest_power_of_two_below(len(leaves))
    return rfc6962_node_hash(_mth(leaves[:k]), _mth(leaves[k:]))


def _path(m: int, leaves: list[bytes]) -> list[bytes]:
    """Audit path (sibling hashes) for leaf index m (recursive RFC 6962 definition)."""
    if len(leaves) == 1:
        return []
    k = _largest_power_of_two_below(len(leaves))
    if m < k:
        return _path(m, leaves[:k]) + [_mth(leaves[k:])]
    return _path(m - k, leaves[k:]) + [_mth(leaves[:k])]


def _leaves(n: int) -> list[bytes]:
    return [f"rekor-leaf-{i}".encode() for i in range(n)]


# --- 1. From-scratch known answer (no module primitives) pins the convention. ---


def test_two_leaf_known_answer_from_raw_hashlib() -> None:
    d0, d1 = b"alpha", b"beta"
    leaf0 = hashlib.sha256(b"\x00" + d0).digest()
    leaf1 = hashlib.sha256(b"\x00" + d1).digest()
    expected_root = hashlib.sha256(b"\x01" + leaf0 + leaf1).digest()

    # module primitives agree with the raw expressions
    assert rfc6962_leaf_hash(d0) == leaf0
    assert rfc6962_node_hash(leaf0, leaf1) == expected_root
    # and the iterative verifier recomputes the same root for leaf 0 (sibling = leaf1)
    assert root_from_inclusion_proof(leaf0, 0, 2, [leaf1]) == expected_root
    assert root_from_inclusion_proof(leaf1, 1, 2, [leaf0]) == expected_root


# --- 2. Recursive-vs-iterative agreement across tree sizes (incl. non-powers-of-two). ---


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 9, 16, 17])
def test_recursive_proofs_verify_under_iterative_algorithm(n: int) -> None:
    leaves = _leaves(n)
    root = _mth(leaves)
    for m in range(n):
        proof = _path(m, leaves)
        recomputed = root_from_inclusion_proof(
            rfc6962_leaf_hash(leaves[m]), m, n, proof
        )
        assert recomputed == root, f"n={n} m={m} root mismatch"


# --- 3. Negative teeth: tamper must fail. ---


def test_tampered_proof_hash_is_rejected() -> None:
    leaves = _leaves(8)
    m = 3
    proof = _path(m, leaves)
    bad = list(proof)
    bad[0] = bytes([bad[0][0] ^ 0x01]) + bad[0][1:]  # flip one bit in a sibling
    recomputed = root_from_inclusion_proof(rfc6962_leaf_hash(leaves[m]), m, 8, bad)
    assert recomputed != _mth(leaves)


def test_wrong_leaf_is_rejected() -> None:
    leaves = _leaves(8)
    m = 3
    proof = _path(m, leaves)
    recomputed = root_from_inclusion_proof(
        rfc6962_leaf_hash(b"not-the-leaf"), m, 8, proof
    )
    assert recomputed != _mth(leaves)


def test_out_of_range_and_malformed_raise() -> None:
    leaf = rfc6962_leaf_hash(b"x")
    with pytest.raises(RekorAnchorError):
        root_from_inclusion_proof(leaf, 5, 5, [])  # index == size
    with pytest.raises(RekorAnchorError):
        root_from_inclusion_proof(leaf, 0, 4, [b"too-short"])  # 9 bytes, not 32
    with pytest.raises(RekorAnchorError):
        root_from_inclusion_proof(leaf, 0, 8, [])  # proof too short for size


# --- 4. Convention lock: RFC 6962 is the INVERSE of the in-tree per-bundle convention. ---


def test_rfc6962_convention_differs_from_inner_tree() -> None:
    from audit_bundle.extensions.c19.layer_a_counter import (
        _MERKLE_LEAF_PREFIX,
        _MERKLE_NODE_PREFIX,
    )

    # Rekor / RFC 6962: leaf 0x00, node 0x01. Inner per-bundle tree: leaf 0x01, node 0x00.
    assert _MERKLE_LEAF_PREFIX == b"\x01"
    assert _MERKLE_NODE_PREFIX == b"\x00"
    # i.e. exactly swapped — reusing the inner helper for Rekor would compute wrong roots.
    assert rfc6962_leaf_hash(b"d") == hashlib.sha256(b"\x00" + b"d").digest()
    assert (
        rfc6962_leaf_hash(b"d") != hashlib.sha256(_MERKLE_LEAF_PREFIX + b"d").digest()
    )


# --- 5. Anchor parse + the Rekor-backed-statement assembly + replay registration. ---


def _rekor_verification(
    leaves: list[bytes], m: int, log_index_base: int = 1000
) -> dict:
    """Build a Rekor-shaped `verification` object around a genuine RFC 6962 proof."""
    proof = _path(m, leaves)
    return {
        "inclusionProof": {
            "logIndex": m,
            "treeSize": len(leaves),
            "rootHash": _mth(leaves).hex(),
            "hashes": [h.hex() for h in proof],
            "checkpoint": f"rekor.example\n{len(leaves)}\n{_mth(leaves).hex()}\n",
        },
        "integratedTime": log_index_base + m,
    }


def test_anchor_parse_and_verify_roundtrip() -> None:
    leaves = _leaves(9)
    m = 4
    anchor = RekorAnchor.from_rekor_verification(
        "test-log", _rekor_verification(leaves, m)
    )
    assert anchor.tree_size == 9
    assert anchor.root_hash == _mth(leaves)
    assert verify_inclusion_proof(leaves[m], anchor) is True
    assert verify_inclusion_proof(b"wrong-leaf", anchor) is False


def test_assemble_bundle_is_honest_about_format() -> None:
    leaves = _leaves(4)
    anchor = RekorAnchor.from_rekor_verification("L", _rekor_verification(leaves, 1))
    bundle = assemble_rekor_backed_statement(b"\xd2\x84cose-statement", anchor)
    assert bundle["format"].startswith("vkernel/rekor-backed-transparent-statement")
    assert "NOT a SCITT Transparent Statement" in bundle["transparency_note"]
    assert bundle["rekor"]["root_hash"] == _mth(leaves).hex()
    # the COSE statement is carried verbatim (hex), not a receipt
    assert (
        bytes.fromhex(bundle["signed_statement_cose_hex"]) == b"\xd2\x84cose-statement"
    )


def test_register_via_replay_transport_verifies_and_fails_closed() -> None:
    leaves = _leaves(8)
    m = 5
    statement = b"\xd2\x84phase-a-signed-statement-bytes"  # opaque to registration

    # The leaf Rekor logs is its canonical entry body; offline we model it as the submitted
    # bytes (the deferred fidelity gap). Build the proof over THAT preimage so it self-checks.
    leaves_with_stmt = list(leaves)
    leaves_with_stmt[m] = statement
    good = _rekor_verification(leaves_with_stmt, m)
    bundle = register_signed_statement(statement, ReplayTransport("L", good))
    assert bundle["rekor"]["root_hash"] == _mth(leaves_with_stmt).hex()

    # A transport whose proof does not re-derive its own root must fail closed.
    tampered = _rekor_verification(leaves_with_stmt, m)
    tampered["inclusionProof"]["rootHash"] = "00" * 32
    with pytest.raises(RekorAnchorError, match="fail-closed"):
        register_signed_statement(statement, ReplayTransport("L", tampered))


# --- 6. Phase C: consumer verification verdict (both legs required for ok=True). ---


def _backed_bundle(statement: bytes, sk=None, m: int = 3, n: int = 8) -> dict:
    """A Rekor-backed bundle whose embedded proof is over `statement` at leaf m of n.

    If `sk` (an ECDSA P-256 private key) is given, the checkpoint is replaced with a REAL
    signed-note over the proof's root signed by `sk` — modelling Rekor's pinned log key signing
    its tree head. Otherwise the placeholder checkpoint from `_rekor_verification` is kept (used
    by the inclusion-only honesty test, which never parses the checkpoint).
    """
    leaves = _leaves(n)
    leaves[m] = statement
    anchor = RekorAnchor.from_rekor_verification("L", _rekor_verification(leaves, m))
    bundle = assemble_rekor_backed_statement(statement, anchor)
    if sk is not None:
        bundle["rekor"]["checkpoint"] = _p256_signed_note(
            "rekor.example - 1", anchor.tree_size, anchor.root_hash, sk
        )
    return bundle


def test_verify_inclusion_only_is_INCOMPLETE_not_a_pass() -> None:
    """THE honesty test: a valid inclusion proof WITHOUT the checkpoint-signature leg must NOT
    report ok=True — the embedded root is only a CLAIMED root until bound to Rekor's pinned key."""
    bundle = _backed_bundle(b"\xd2\x84stmt")
    verdict = verify_rekor_backed_statement(bundle)  # no pinned key supplied
    assert verdict.inclusion_verified is True
    assert verdict.checkpoint_verified is None
    assert verdict.ok is False
    assert REASON_CHECKPOINT_NOT_EVALUATED in verdict.reasons


def test_verify_both_legs_pass_is_ok() -> None:
    statement = b"\xd2\x84stmt-ok"
    sk = ec.generate_private_key(ec.SECP256R1())
    bundle = _backed_bundle(statement, sk=sk)

    verdict = verify_rekor_backed_statement(bundle, rekor_log_pubkey=sk.public_key())
    assert verdict.inclusion_verified is True
    assert verdict.checkpoint_verified is True
    assert verdict.ok is True
    assert verdict.reasons == ()


def test_verify_wrong_checkpoint_signature_fails() -> None:
    sk = ec.generate_private_key(ec.SECP256R1())
    wrong_pk = ec.generate_private_key(ec.SECP256R1()).public_key()
    bundle = _backed_bundle(b"\xd2\x84stmt2", sk=sk)  # signed by sk

    verdict = verify_rekor_backed_statement(bundle, rekor_log_pubkey=wrong_pk)
    assert verdict.checkpoint_verified is False
    assert verdict.ok is False
    assert REASON_CHECKPOINT_SIGNATURE_INVALID in verdict.reasons


def test_verify_checkpoint_over_different_root_is_rejected() -> None:
    """A checkpoint validly signed by the log key but over a DIFFERENT root than the inclusion
    proof must NOT pass — the two legs would otherwise attest different trees."""
    sk = ec.generate_private_key(ec.SECP256R1())
    bundle = _backed_bundle(b"\xd2\x84stmt-rootmismatch", sk=sk)
    # Re-sign a checkpoint over an unrelated root (still a valid signature by the same key).
    bundle["rekor"]["checkpoint"] = _p256_signed_note(
        "rekor.example - 1", 8, hashlib.sha256(b"other-tree").digest(), sk
    )
    verdict = verify_rekor_backed_statement(bundle, rekor_log_pubkey=sk.public_key())
    assert verdict.inclusion_verified is True
    assert verdict.checkpoint_verified is False
    assert verdict.ok is False
    assert REASON_CHECKPOINT_ROOT_MISMATCH in verdict.reasons


def test_verify_tampered_root_fails_inclusion() -> None:
    sk = ec.generate_private_key(ec.SECP256R1())
    bundle = _backed_bundle(b"\xd2\x84stmt3", sk=sk)
    bundle["rekor"]["root_hash"] = "00" * 32  # claim a different root
    verdict = verify_rekor_backed_statement(bundle, rekor_log_pubkey=sk.public_key())
    assert verdict.inclusion_verified is False
    assert verdict.ok is False
    assert REASON_INCLUSION_PROOF_FAILED in verdict.reasons


def test_verify_malformed_bundle() -> None:
    assert verify_rekor_backed_statement({}).reasons == (REASON_MALFORMED_BUNDLE,)
    assert (
        verify_rekor_backed_statement(
            {"rekor": 5, "signed_statement_cose_hex": "ab"}
        ).ok
        is False
    )


# --- 7. REAL Rekor entry: ground leaf canonicalization + checkpoint key against live bytes. ---
#
# These are the non-tautological teeth. The fixture is a REAL public Rekor v1 response captured
# read-only (no write/POST); a fabricated fixture would re-create the very tautology this exists
# to kill. See tests/fixtures/rekor_real_entry_v1.json._provenance.


def _load_real_entry() -> tuple[dict, bytes]:
    fx = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    response = fx["response"]
    entry = response[next(iter(response))]
    return entry, fx["rekor_public_key_pem"].encode("utf-8")


def test_real_rekor_leaf_canonicalization_recomputes_real_root() -> None:
    """GROUNDS the leaf-canonicalization gap: leaf preimage = base64decode(entry.body); the
    RFC 6962 inclusion proof must recompute the entry's REAL inclusionProof.rootHash."""
    entry, _ = _load_real_entry()
    ip = entry["verification"]["inclusionProof"]
    leaf_preimage = base64.b64decode(entry["body"])
    anchor = RekorAnchor.from_rekor_verification(entry["logID"], entry["verification"])
    assert anchor.root_hash == bytes.fromhex(ip["rootHash"])
    assert verify_inclusion_proof(leaf_preimage, anchor) is True
    # And the recompute is the canonical one (independent of any tree we built).
    recomputed = root_from_inclusion_proof(
        rfc6962_leaf_hash(leaf_preimage),
        anchor.log_index,
        anchor.tree_size,
        list(anchor.hashes),
    )
    assert recomputed == anchor.root_hash


def test_real_rekor_leaf_tamper_fails() -> None:
    """A single flipped proof hash must NOT recompute the real root (negative tooth on real data)."""
    entry, _ = _load_real_entry()
    leaf_preimage = base64.b64decode(entry["body"])
    anchor = RekorAnchor.from_rekor_verification(entry["logID"], entry["verification"])
    tampered = list(anchor.hashes)
    tampered[0] = bytes([tampered[0][0] ^ 0x01]) + tampered[0][1:]
    recomputed = root_from_inclusion_proof(
        rfc6962_leaf_hash(leaf_preimage), anchor.log_index, anchor.tree_size, tampered
    )
    assert recomputed != anchor.root_hash


def test_real_rekor_checkpoint_signature_verifies_against_pinned_key() -> None:
    """GROUNDS the checkpoint-key gap: the real checkpoint's ECDSA P-256 signature verifies
    against the real rekor.pub (both the fixture-pinned PEM and the module's pinned constant),
    and the checkpoint's root binds to the inclusion proof's root."""
    entry, fixture_pem = _load_real_entry()
    ip = entry["verification"]["inclusionProof"]
    checkpoint = ip["checkpoint"].encode("utf-8")

    # The pinned constant in the module IS the published rekor.pub captured in the fixture.
    pinned = load_rekor_log_public_key()
    from_fixture = load_rekor_log_public_key(fixture_pem)
    assert rekor_key_hint(pinned) == rekor_key_hint(from_fixture)

    assert verify_checkpoint_signature(checkpoint, pinned) is True
    assert verify_checkpoint_signature(checkpoint, from_fixture) is True

    # The signed checkpoint's root equals the inclusion proof's root (binds the two legs).
    note = parse_checkpoint_note(checkpoint)
    assert note.root_hash == bytes.fromhex(ip["rootHash"])
    assert note.origin.startswith("rekor.sigstore.dev")


def test_real_rekor_checkpoint_tamper_fails() -> None:
    """Flipping one byte of the real checkpoint root line must break the ECDSA verification."""
    entry, _ = _load_real_entry()
    checkpoint = entry["verification"]["inclusionProof"]["checkpoint"]
    note = parse_checkpoint_note(checkpoint.encode("utf-8"))
    # Corrupt the base64 root line in the signed body; signature can no longer verify.
    bad_root_b64 = base64.b64encode(
        bytes([note.root_hash[0] ^ 0x01]) + note.root_hash[1:]
    )
    lines = checkpoint.split("\n")
    lines[2] = bad_root_b64.decode()
    tampered = "\n".join(lines).encode("utf-8")
    assert verify_checkpoint_signature(tampered, load_rekor_log_public_key()) is False


def test_real_rekor_full_verdict_both_legs_pass() -> None:
    """End-to-end: assemble the bundle from real data and verify_rekor_backed_statement passes
    BOTH legs (inclusion + ECDSA checkpoint) against the pinned real key."""
    entry, _ = _load_real_entry()
    leaf_preimage = base64.b64decode(entry["body"])
    anchor = RekorAnchor.from_rekor_verification(entry["logID"], entry["verification"])
    bundle = assemble_rekor_backed_statement(leaf_preimage, anchor)
    verdict = verify_rekor_backed_statement(
        bundle,
        rekor_log_pubkey=load_rekor_log_public_key(),
        leaf_preimage=leaf_preimage,
    )
    assert verdict.inclusion_verified is True
    assert verdict.checkpoint_verified is True
    assert verdict.ok is True
    assert verdict.reasons == ()


# -----------------------------------------------------------------------------
# SCITT v0.5 Tier-1 — cosign Sigstore-bundle reshape (option (ii) verify-only path).
# -----------------------------------------------------------------------------
# rekor_anchor_from_sigstore_bundle parses cosign's NEW bundle format
# (application/vnd.dev.sigstore.bundle.v0.3+json) tlog entry into a RekorAnchor so the grounded
# offline verifier checks cosign's OWN Rekor entry natively (cosign = sole writer; verify-only
# re-derivation). These tests are NON-TAUTOLOGICAL: they re-encode the REAL Rekor v1 fixture into
# the cosign-bundle envelope (hex->base64, int->string, nested checkpoint, canonicalizedBody),
# so the SAME real Merkle data + real checkpoint must still verify through the reshaped path.


def _real_entry_as_sigstore_bundle() -> tuple[dict, bytes]:
    """Re-encode the real Rekor v1 fixture into a cosign Sigstore protobuf-bundle v0.3 layout.

    Returns (bundle, expected_leaf_preimage). Only the ENVELOPE is synthetic; every byte of the
    inclusion proof, checkpoint, and body is the real captured public Rekor entry.
    """
    entry, _ = _load_real_entry()
    ip = entry["verification"]["inclusionProof"]

    def _hex_to_b64(h: str) -> str:
        return base64.b64encode(bytes.fromhex(h)).decode("ascii")

    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "tlogEntries": [
                {
                    "logIndex": str(ip["logIndex"]),
                    "logId": {
                        "keyId": base64.b64encode(bytes.fromhex(entry["logID"])).decode(
                            "ascii"
                        )
                    },
                    "integratedTime": str(entry["integratedTime"]),
                    "inclusionProof": {
                        "logIndex": str(ip["logIndex"]),
                        "rootHash": _hex_to_b64(ip["rootHash"]),
                        "treeSize": str(ip["treeSize"]),
                        "hashes": [_hex_to_b64(h) for h in ip["hashes"]],
                        "checkpoint": {"envelope": ip["checkpoint"]},
                    },
                    # cosign records the canonicalized Rekor body base64-encoded, same as the
                    # REST `body` field; the Merkle leaf preimage is its base64-decode.
                    "canonicalizedBody": entry["body"],
                }
            ]
        },
    }
    return bundle, base64.b64decode(entry["body"])


def test_sigstore_bundle_reshape_recomputes_real_root() -> None:
    """The reshaped anchor carries the REAL root + the inclusion proof still re-derives it."""
    bundle, leaf_preimage = _real_entry_as_sigstore_bundle()
    entry, _ = _load_real_entry()
    ip = entry["verification"]["inclusionProof"]

    anchor, parsed_leaf = rekor_anchor_from_sigstore_bundle(bundle)

    assert parsed_leaf == leaf_preimage
    assert anchor.root_hash == bytes.fromhex(ip["rootHash"])
    assert anchor.log_index == int(ip["logIndex"])
    assert anchor.tree_size == int(ip["treeSize"])
    assert anchor.log_id == entry["logID"]  # base64 keyId surfaced as hex
    assert verify_inclusion_proof(parsed_leaf, anchor) is True


def test_sigstore_bundle_reshape_full_verdict_both_legs_pass() -> None:
    """End-to-end through the cosign-bundle envelope: BOTH legs pass against the pinned key.

    This is the consumer path option (ii) relies on — cosign writes, the native verifier checks.
    """
    bundle, leaf_preimage = _real_entry_as_sigstore_bundle()
    anchor, parsed_leaf = rekor_anchor_from_sigstore_bundle(bundle)
    backed = assemble_rekor_backed_statement(b"\x18cose-statement-bytes", anchor)
    verdict = verify_rekor_backed_statement(
        backed,
        rekor_log_pubkey=load_rekor_log_public_key(),
        leaf_preimage=parsed_leaf,
    )
    assert verdict.inclusion_verified is True
    assert verdict.checkpoint_verified is True
    assert verdict.ok is True
    assert verdict.reasons == ()


def test_sigstore_bundle_reshape_tampered_hash_fails() -> None:
    """A flipped proof hash in the cosign bundle reshapes fine but FAILS inclusion (real teeth)."""
    bundle, _ = _real_entry_as_sigstore_bundle()
    hashes_list = bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"][
        "hashes"
    ]
    raw = bytearray(base64.b64decode(hashes_list[0]))
    raw[0] ^= 0x01
    hashes_list[0] = base64.b64encode(bytes(raw)).decode("ascii")
    anchor, parsed_leaf = rekor_anchor_from_sigstore_bundle(bundle)
    assert verify_inclusion_proof(parsed_leaf, anchor) is False


def test_sigstore_bundle_reshape_malformed_raises() -> None:
    with pytest.raises(RekorAnchorError):
        rekor_anchor_from_sigstore_bundle({"verificationMaterial": {"tlogEntries": []}})
    with pytest.raises(RekorAnchorError):
        rekor_anchor_from_sigstore_bundle({"nope": True})


def test_real_staging_sigstore_bundle_inclusion_grounds() -> None:
    """The native RFC 6962 inclusion recompute reproduces the Merkle root of a REAL
    Sigstore STAGING Rekor entry — a freshly keyless-minted bundle from the
    keyless-attest-staging workflow, not a hand-built or modelled fixture. This
    grounds the inclusion-proof path against a live (staging) transparency log."""
    bundle = json.loads(_STAGING_BUNDLE_FIXTURE.read_text(encoding="utf-8"))
    anchor, parsed_leaf = rekor_anchor_from_sigstore_bundle(bundle)
    assert verify_inclusion_proof(parsed_leaf, anchor) is True


def test_real_staging_sigstore_bundle_tampered_hash_fails() -> None:
    """Teeth: flip one byte of one proof hash in the real staging bundle and the
    inclusion recompute must FAIL (wrong root), not silently pass."""
    bundle = json.loads(_STAGING_BUNDLE_FIXTURE.read_text(encoding="utf-8"))
    hashes_list = bundle["verificationMaterial"]["tlogEntries"][0]["inclusionProof"][
        "hashes"
    ]
    raw = bytearray(base64.b64decode(hashes_list[0]))
    raw[0] ^= 0x01
    hashes_list[0] = base64.b64encode(bytes(raw)).decode("ascii")
    anchor, parsed_leaf = rekor_anchor_from_sigstore_bundle(bundle)
    assert verify_inclusion_proof(parsed_leaf, anchor) is False
