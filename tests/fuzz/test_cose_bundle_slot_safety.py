"""Layer-2 atheris finding 2026-05-26 — COSE_Sign1 slot-type bypass.

The Layer 2 catastrophic-tier harness (tests/fuzz/atheris_verify_cose_bundle.py)
found `[protected_bstr, 1, 0, signature]` was accepted by
verify_cross_host_authenticator_cose under the canonical (pubkey, preimage):

  - protected_bstr: byte-identical to a real valid envelope (so Sig_structure
    matches the one EdDSA signed over)
  - unprotected slot: integer 1 (RFC 9052 §4.2 requires a CBOR header_map)
  - payload slot: integer 0 (cross-host contract requires nil — detached)
  - signature: byte-identical to the real signed signature

verify returned (True, 'PASS', ''). No cryptographic forgery (the signature
still verifies over the unchanged Sig_structure), but a parser/protocol-
conformance bypass — a strict RFC 9052 consumer would reject the envelope,
so two verifiers reach opposite verdicts on the same bytes (same class as
Stream A's A4 non-canonical-protected-header finding).

Fixed by adding slot-type validation immediately after the 4-element unpack
in verify_cross_host_authenticator_cose (cross_host_peerreview.py:350). New
reason codes:
  - COSE_UNPROTECTED_MALFORMED — slot 1 not a CBOR map
  - COSE_PAYLOAD_NOT_DETACHED  — slot 2 not nil (cross-host detached contract)

This suite codifies the threat model so the bypass cannot silently regress.
The crash artifact at tests/fuzz/crashes/cose_bundle/crash-cc8de4f8… replays
through the harness in single-shot mode (`-runs=1`) — was True before the
fix, must be False after.
"""

from __future__ import annotations

import cbor2
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit_bundle.extensions.c19.cross_host_peerreview import (
    sign_cross_host_authenticator_cose,
    verify_cross_host_authenticator_cose,
)


# Deterministic keypair + preimage — match what the Layer-2 atheris harness
# pins (tests/fuzz/atheris_verify_cose_bundle.py) so the crash artifact
# replays correctly here.
_PRIV_SEED = bytes.fromhex(
    "00010203" "04050607" "08090a0b" "0c0d0e0f"
    "10111213" "14151617" "18191a1b" "1c1d1e1f"
)


@pytest.fixture(scope="module")
def signed_env() -> tuple[bytes, bytes, bytes]:
    """Return (pubkey_raw, preimage, canonical_cose_bytes) for the pinned
    deterministic keypair. Decomposing the canonical envelope gives the
    protected_bstr + signature we splice into bypass-attempt cases below."""
    priv = Ed25519PrivateKey.from_private_bytes(_PRIV_SEED)
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    preimage = b"v-kernel layer-2 cose fuzz canonical preimage"
    canonical = sign_cross_host_authenticator_cose(
        private_key=priv, preimage=preimage
    )
    return pub_raw, preimage, canonical


def test_canonical_envelope_still_verifies(signed_env) -> None:
    """Fix must not over-reject — a legitimate envelope still passes."""
    pub_raw, preimage, canonical = signed_env
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=pub_raw, preimage=preimage, cose_bytes=canonical, role="sender"
    )
    assert ok is True
    assert code == "PASS"


# Non-map values that must be rejected at the unprotected slot. Each splices
# the bad value into [protected_bstr, BAD, None, signature] under the
# canonical protected+sig, so the signature itself still verifies — only
# the slot-type guard can save us.
_BAD_UNPROTECTED: list[tuple[str, object]] = [
    ("integer_1", 1),                          # the original crash-artifact shape
    ("integer_negative", -42),
    ("string", "evil"),
    ("bytes", b"evil"),
    ("list", [1, 2, 3]),
    ("none", None),
    ("bool", True),
    ("float", 3.14),
]


@pytest.mark.parametrize("label,bad", _BAD_UNPROTECTED, ids=[c[0] for c in _BAD_UNPROTECTED])
def test_unprotected_slot_must_be_map(signed_env, label: str, bad: object) -> None:
    pub_raw, preimage, canonical = signed_env
    protected_bstr, _unprotected, _payload, signature = cbor2.loads(canonical)
    evil = cbor2.dumps([protected_bstr, bad, None, signature])
    ok, code, detail = verify_cross_host_authenticator_cose(
        public_key_raw=pub_raw, preimage=preimage, cose_bytes=evil, role="sender"
    )
    assert ok is False, (
        f"{label}: bypass — verify accepted unprotected={bad!r} (detail={detail!r})"
    )
    assert code == "COSE_UNPROTECTED_MALFORMED", (
        f"{label}: wrong reason_code {code!r}"
    )


# Non-nil values that must be rejected at the payload slot. Cross-host
# detached-payload contract — payload MUST be None even though RFC 9052 §4.2
# allows bstr-or-nil generically.
_BAD_PAYLOAD: list[tuple[str, object]] = [
    ("integer_0", 0),                          # crash-artifact second mutation
    ("integer_positive", 42),
    ("string", "evil"),
    ("bytes_empty", b""),
    ("bytes_data", b"inline payload"),
    ("list", [1, 2, 3]),
    ("dict", {"k": "v"}),
    ("bool", False),
    ("float", 0.0),
]


@pytest.mark.parametrize("label,bad", _BAD_PAYLOAD, ids=[c[0] for c in _BAD_PAYLOAD])
def test_payload_slot_must_be_nil(signed_env, label: str, bad: object) -> None:
    pub_raw, preimage, canonical = signed_env
    protected_bstr, _unprotected, _payload, signature = cbor2.loads(canonical)
    evil = cbor2.dumps([protected_bstr, {}, bad, signature])
    ok, code, detail = verify_cross_host_authenticator_cose(
        public_key_raw=pub_raw, preimage=preimage, cose_bytes=evil, role="sender"
    )
    assert ok is False, (
        f"{label}: bypass — verify accepted payload={bad!r} (detail={detail!r})"
    )
    assert code == "COSE_PAYLOAD_NOT_DETACHED", (
        f"{label}: wrong reason_code {code!r}"
    )


def test_both_slots_bad_unprotected_wins(signed_env) -> None:
    """When both unprotected and payload are wrong, unprotected check fires
    first (declared order). Documents the fail-order so callers reading
    failure codes know which slot to fix first."""
    pub_raw, preimage, canonical = signed_env
    protected_bstr, _unprotected, _payload, signature = cbor2.loads(canonical)
    evil = cbor2.dumps([protected_bstr, 99, 88, signature])
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=pub_raw, preimage=preimage, cose_bytes=evil, role="sender"
    )
    assert ok is False
    assert code == "COSE_UNPROTECTED_MALFORMED"


def test_crash_artifact_replays_rejected(signed_env) -> None:
    """The exact bytes atheris saved when the bug was live, replayed here.
    Must return False; True would mean the regression has unfixed itself."""
    from pathlib import Path

    pub_raw, preimage, _ = signed_env
    artifact = Path(__file__).parent / "crashes" / "cose_bundle" / (
        "crash-cc8de4f8f55c473563b16a08b9d902d6df72f56b"
    )
    crash_bytes = artifact.read_bytes()
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=pub_raw, preimage=preimage, cose_bytes=crash_bytes, role="sender"
    )
    assert ok is False, "Layer-2 crash artifact regressed: bypass is back"
    assert code == "COSE_UNPROTECTED_MALFORMED"


def test_role_ack_also_enforces_slot_types(signed_env) -> None:
    """The fix applies regardless of role — ack path must also reject."""
    pub_raw, preimage, canonical = signed_env
    protected_bstr, _unprotected, _payload, signature = cbor2.loads(canonical)
    evil = cbor2.dumps([protected_bstr, 1, 0, signature])
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=pub_raw, preimage=preimage, cose_bytes=evil, role="ack"
    )
    assert ok is False
    assert code == "COSE_UNPROTECTED_MALFORMED"


# ---------------------------------------------------------------------------
# Layer-2 finding #2 (2026-05-26): CBOR trailing-bytes acceptance.
#
# cbor2.loads consumes the first complete CBOR data item and silently
# ignores trailing bytes. atheris appended 8 bytes to a valid envelope and
# verify returned (True, 'PASS', ''). Two-verifier differential (any
# strict RFC 8949 §5.1 consumer rejects the same bytes) + audit-trail
# confusion (N byte-different envelopes verify under one signature).
#
# Closed by switching to cbor2.load(stream) + tell()==len(input) check,
# emitting new reason_code COSE_TRAILING_BYTES.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "n_trailing,filler",
    [
        (1, b"\x00"),
        (8, b"\x00" * 8),
        (100, b"\x00" * 100),
        (1, b"\xff"),
        (8, b"\x84\x43\x21\x10\x27\xa0\xf6\x10"),  # the crash-26deeb… trailer
        (16, b"\xa1\x00\x00" * 6 + b"X" * 0 + b"\x00"),  # CBOR-looking trailer
    ],
    ids=[
        "1_null_byte",
        "8_null_bytes",
        "100_null_bytes",
        "1_ff_byte",
        "crash_artifact_trailer",
        "cbor_looking_trailer",
    ],
)
def test_trailing_bytes_rejected(
    signed_env, n_trailing: int, filler: bytes
) -> None:
    pub_raw, preimage, canonical = signed_env
    evil = canonical + filler
    ok, code, detail = verify_cross_host_authenticator_cose(
        public_key_raw=pub_raw, preimage=preimage, cose_bytes=evil, role="sender"
    )
    assert ok is False, (
        f"trailing-bytes bypass: verify accepted canonical + {len(filler)}B "
        f"trailer (detail={detail!r})"
    )
    assert code == "COSE_TRAILING_BYTES", (
        f"expected COSE_TRAILING_BYTES, got {code!r}"
    )


def test_trailing_bytes_crash_artifact_replays_rejected(signed_env) -> None:
    """The second saved crash artifact (canonical + 8 trailing bytes).
    Replay must return False with COSE_TRAILING_BYTES; True would mean the
    fix regressed."""
    from pathlib import Path

    pub_raw, preimage, _ = signed_env
    artifact = Path(__file__).parent / "crashes" / "cose_bundle" / (
        "crash-26deeb60d56cd1359e6381ea2718ae471d13a21b"
    )
    crash_bytes = artifact.read_bytes()
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=pub_raw, preimage=preimage, cose_bytes=crash_bytes, role="sender"
    )
    assert ok is False
    assert code == "COSE_TRAILING_BYTES"


def test_canonical_exactly_consumes_input(signed_env) -> None:
    """Sanity twin: a canonical envelope must NOT trip the trailing-bytes
    check. Tell()==len(input) at the exact byte boundary."""
    pub_raw, preimage, canonical = signed_env
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=pub_raw, preimage=preimage, cose_bytes=canonical, role="sender"
    )
    assert ok is True
    assert code == "PASS"


# ---------------------------------------------------------------------------
# Layer-2 finding #3 (2026-05-26): arbitrary unprotected dict accepted.
#
# Finding #1's slot-type fix required unprotected to be a dict. Finding #3
# discovered that any dict was accepted — including ones with a fake `alg`
# (label 1) or fake `kid` (label 4) sitting alongside the valid signature.
# Tightened to require unprotected to be exactly empty ({}), symmetric with
# the protected-header strict-allow-list at cross_host_peerreview.py:~385.
# New reason_code: COSE_UNPROTECTED_NOT_EMPTY.
#
# Risk this closes: two-verifier differential (strict RFC 9052 readers
# forbid alg-in-unprotected); C2b doctrine break (downstream consumer that
# mistakenly inspects unprotected.get(4) for kid would be served attacker-
# chosen bytes alongside a valid signature).
# ---------------------------------------------------------------------------


# Arbitrary unprotected-dict contents — each spliced into a verify-able
# envelope under canonical (pubkey, preimage, protected, sig). Must reject.
_NONEMPTY_UNPROTECTED: list[tuple[str, dict]] = [
    ("nested_empty_map_at_alg_label", {1: {}}),     # the crash-f9a66… shape
    ("fake_alg_in_unprotected", {1: -8}),           # RFC 9052 §3 forbids
    ("fake_alg_wrong_value", {1: -7}),
    ("fake_kid_in_unprotected", {4: b"fake_kid"}),  # C2b break (kid is OOB)
    ("arbitrary_key_arbitrary_value", {99: "evil"}),
    ("arbitrary_key_bytes_value", {77: b"\x00" * 32}),
    ("multiple_arbitrary_entries", {1: -8, 4: b"x", 99: "y"}),
    ("single_zero_key", {0: 0}),
    ("nested_dict_value", {7: {"hidden": "metadata"}}),
]


@pytest.mark.parametrize(
    "label,unprotected", _NONEMPTY_UNPROTECTED, ids=[c[0] for c in _NONEMPTY_UNPROTECTED]
)
def test_nonempty_unprotected_rejected(
    signed_env, label: str, unprotected: dict
) -> None:
    pub_raw, preimage, canonical = signed_env
    protected_bstr, _empty, _none, signature = cbor2.loads(canonical)
    evil = cbor2.dumps([protected_bstr, unprotected, None, signature])
    ok, code, detail = verify_cross_host_authenticator_cose(
        public_key_raw=pub_raw, preimage=preimage, cose_bytes=evil, role="sender"
    )
    assert ok is False, (
        f"{label}: bypass — verify accepted unprotected={unprotected!r} "
        f"(detail={detail!r})"
    )
    assert code == "COSE_UNPROTECTED_NOT_EMPTY", (
        f"{label}: expected COSE_UNPROTECTED_NOT_EMPTY, got {code!r}"
    )


def test_nonempty_unprotected_crash_artifact_replays_rejected(signed_env) -> None:
    """The third saved crash artifact (unprotected = {1: {}}). Must reject
    with COSE_UNPROTECTED_NOT_EMPTY."""
    from pathlib import Path

    pub_raw, preimage, _ = signed_env
    artifact = Path(__file__).parent / "crashes" / "cose_bundle" / (
        "crash-f9a66157827f19882731421cded000f587c4110b"
    )
    crash_bytes = artifact.read_bytes()
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=pub_raw, preimage=preimage, cose_bytes=crash_bytes, role="sender"
    )
    assert ok is False
    assert code == "COSE_UNPROTECTED_NOT_EMPTY"


def test_unprotected_check_fires_before_payload(signed_env) -> None:
    """When unprotected is nonempty AND payload is wrong, unprotected wins.
    Documents the fail-order so callers know which slot to fix first."""
    pub_raw, preimage, canonical = signed_env
    protected_bstr, _, _, signature = cbor2.loads(canonical)
    evil = cbor2.dumps([protected_bstr, {1: -8}, b"inline_payload", signature])
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=pub_raw, preimage=preimage, cose_bytes=evil, role="sender"
    )
    assert ok is False
    assert code == "COSE_UNPROTECTED_NOT_EMPTY"


# ---------------------------------------------------------------------------
# Layer-2 finding #4 (2026-05-26, immediate follow-up to #3): the COSE_
# UNPROTECTED_NOT_EMPTY detail-formatter for finding #3 called
# `sorted(_unprotected.keys())`. CBOR maps can mix int and None keys
# (atheris produced `{None: 0, 0: 0}`); Python 3 refuses to compare those
# and sorted() raised TypeError out of the verifier — breaking the very
# §C9 contract the check was supposed to enforce.
#
# Closed by listing keys in insertion order via repr() (no comparison).
# ---------------------------------------------------------------------------


_MIXED_KEY_DICTS: list[tuple[str, dict]] = [
    ("int_and_none", {0: 0, None: 0}),
    ("str_and_int", {"k": 1, 0: 2}),
    ("bytes_and_none", {b"x": 1, None: 2}),
    ("bytes_int_str", {b"x": 1, 0: 2, "k": 3}),
    ("only_none_key", {None: None}),
    ("tuple_key", {(1, 2): "evil"}),  # tuples are hashable
]


@pytest.mark.parametrize(
    "label,d", _MIXED_KEY_DICTS, ids=[c[0] for c in _MIXED_KEY_DICTS]
)
def test_mixed_unsortable_keys_dont_raise(
    signed_env, label: str, d: dict
) -> None:
    """The detail-formatter must survive CBOR maps with unsortable key sets.
    Pre-fix, sorted() raised TypeError out of the verifier (§C9 break)."""
    pub_raw, preimage, canonical = signed_env
    protected_bstr, _, _, signature = cbor2.loads(canonical)
    evil = cbor2.dumps([protected_bstr, d, None, signature])
    ok, code, detail = verify_cross_host_authenticator_cose(
        public_key_raw=pub_raw, preimage=preimage, cose_bytes=evil, role="sender"
    )  # MUST NOT RAISE
    assert ok is False
    assert code == "COSE_UNPROTECTED_NOT_EMPTY"
    assert isinstance(detail, str)


def test_mixed_keys_crash_artifact_replays_rejected(signed_env) -> None:
    """The fourth saved crash artifact (decoded shape:
    [b'\\x10', {None: 0, 0: 0}, 0, None]). Must reject without raising."""
    from pathlib import Path

    pub_raw, preimage, _ = signed_env
    artifact = Path(__file__).parent / "crashes" / "cose_bundle" / (
        "crash-5d6ee02c562a8e5e1d49fd1e2401391f4fbeb5d4"
    )
    crash_bytes = artifact.read_bytes()
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=pub_raw, preimage=preimage, cose_bytes=crash_bytes, role="sender"
    )
    # The decoded value's protected_bstr is also non-canonical here, so
    # multiple checks could fire — what matters is no raise and ok=False.
    assert ok is False


# ---------------------------------------------------------------------------
# Sibling §C9 detail-formatter bug — same class as the Layer-2 #4 unprotected-
# slot fix above, but on the PROTECTED header. atheris differential pycose
# harness (tests/fuzz/atheris_differential_pycose.py) surfaced this on iter
# 6.69M with protected_bstr decoding to `{0:-17, 1:-8, 32:0, (0,):0}` — three
# int keys plus one tuple key (cbor2 coerces CBOR-array map keys to Python
# tuples for hashability). The verifier path is: alg-pin passes (alg = -8 =
# EdDSA), `extra_labels = {0, 32, (0,)}`, and `sorted(extra_labels)` in the
# CROSS_HOST_COSE_HEADER_UNSUPPORTED detail-formatter raises TypeError out of
# the verifier — §C9 break from inside the very check that rejects the
# unsupported labels.
#
# The prior session's §C9 grep audit (commit d30b886ba) closed the
# unprotected-slot, layer_a_counter, and c9_1_append_only_files sites but
# missed the protected-header sibling. The offline_root verifier carries an
# identical sister check (offline_root.py:~272) so it shares the bug class.
# Both fixed: `sorted(extra_labels, key=repr)` — same pattern as
# c9_1_append_only_files.py.
# ---------------------------------------------------------------------------


# Each protected_bstr below: passes the alg-pin (carries `{1: -8}` = EdDSA)
# so execution reaches the extra-labels detail-formatter, and contains at
# least one non-int extra key (the trigger condition for the TypeError).
_MIXED_PROTECTED_HEADERS: list[tuple[str, dict]] = [
    # The exact decoded shape the differential atheris harness surfaced.
    ("crash_repro_int_and_tuple", {0: -17, 1: -8, 32: 0, (0,): 0}),
    ("int_and_tuple_alone", {1: -8, (0,): 0}),
    ("int_and_none_extra", {1: -8, None: 0}),
    ("int_and_str_extra", {1: -8, "kid": b"x"}),
    ("int_and_bytes_extra", {1: -8, b"x": 1}),
    ("nested_tuple_key", {1: -8, (1, 2, 3): 0}),
    # Three different mixed types in extras — full mixed-set sort.
    ("triple_mixed_extras", {1: -8, 0: 0, None: 0, (1,): 0}),
]


@pytest.mark.parametrize(
    "label,protected_obj",
    _MIXED_PROTECTED_HEADERS,
    ids=[c[0] for c in _MIXED_PROTECTED_HEADERS],
)
def test_protected_header_extras_mixed_keys_dont_raise(
    signed_env, label: str, protected_obj: dict
) -> None:
    """Verifier must survive a protected header whose extra labels include
    non-int CBOR keys. Pre-fix, `sorted(extra_labels)` raised TypeError out
    of CROSS_HOST_COSE_HEADER_UNSUPPORTED — §C9 break from the very check
    that rejects the unsupported labels."""
    pub_raw, preimage, canonical = signed_env
    _, unprotected, payload, signature = cbor2.loads(canonical)
    protected_bstr = cbor2.dumps(protected_obj)
    evil = cbor2.dumps([protected_bstr, unprotected, payload, signature])
    ok, code, detail = verify_cross_host_authenticator_cose(
        public_key_raw=pub_raw, preimage=preimage, cose_bytes=evil, role="sender"
    )  # MUST NOT RAISE
    assert ok is False
    # The protected header is non-canonical for some of these (e.g. tuple
    # keys violate RFC 9052), so either the canonicalness check OR the
    # extras check may fire. Both are acceptable §C9 outcomes — what we are
    # guarding against is the TypeError that previously escaped the verifier.
    assert code in {
        "CROSS_HOST_COSE_HEADER_UNSUPPORTED",
        "COSE_PROTECTED_HEADER_NONCANONICAL",
    }
    assert isinstance(detail, str)


def test_protected_header_extras_crash_artifact_replays_rejected(
    signed_env,
) -> None:
    """Single-shot replay of the saved atheris crash artifact through the
    patched code: must return (False, <some-reason>, <some-detail>) without
    raising. Decoded shape:
        [b'protected={0:-17, 1:-8, 32:0, (0,):0}', {}, None, <64-byte sig>]
    Pre-fix, verify raised TypeError("'<' not supported between instances of
    'tuple' and 'int'") out of the CROSS_HOST_COSE_HEADER_UNSUPPORTED branch.
    """
    from pathlib import Path

    pub_raw, preimage, _ = signed_env
    artifact = Path(__file__).parent / "crashes" / "differential_pycose" / (
        "crash-80bea7a83ac7c87faf79184fac0ac8b73cbe26c3"
    )
    crash_bytes = artifact.read_bytes()
    ok, _code, detail = verify_cross_host_authenticator_cose(
        public_key_raw=pub_raw, preimage=preimage, cose_bytes=crash_bytes, role="sender"
    )  # MUST NOT RAISE
    assert ok is False
    assert isinstance(detail, str)


def test_offline_root_protected_header_extras_mixed_keys_dont_raise() -> None:
    """Sister verifier (offline_root) carries the identical bug class on the
    same surface. Pre-fix, the SAME mixed-key extra-labels set raised
    TypeError out of OFFLINE_ROOT_SIGNATURE_INVALID's detail formatter,
    breaking the LayerAVerificationError contract from inside the very
    check that rejects the unsupported labels. Post-fix, the verifier must
    raise LayerAVerificationError (the contract), not TypeError.
    """
    from audit_bundle.extensions.c19.layer_a_counter import (
        LayerAVerificationError,
    )
    from audit_bundle.extensions.c19.offline_root import (
        OFFLINE_ROOT_COSE_DOMAIN_AAD,
        OfflineRootPolicy,
        offline_root_cose_sig_structure,
        verify_emergency_offline_root_signature,
    )

    priv = Ed25519PrivateKey.from_private_bytes(_PRIV_SEED)
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    preimage = b"v-kernel layer-2 cose fuzz canonical preimage"
    offline_root_key_id = b"\xab" * 32
    policy = OfflineRootPolicy(
        pinned_offline_root_key_ids=frozenset({offline_root_key_id}),
        pinned_offline_root_verifying_keys={offline_root_key_id: pub_raw},
    )

    # Protected header with mixed extra-label key types. alg = -8 passes the
    # alg-pin check; extra_labels = {0, (0,), None} — the offending sort.
    protected_obj = {1: -8, 0: 0, (0,): 0, None: 0}
    protected_bstr = cbor2.dumps(protected_obj)
    sig_input = offline_root_cose_sig_structure(
        preimage,
        external_aad=OFFLINE_ROOT_COSE_DOMAIN_AAD,
        protected_bstr=protected_bstr,
    )
    sig = priv.sign(sig_input)
    cose_bytes = cbor2.dumps([protected_bstr, {}, None, sig])

    # Must raise the typed contract exception, NOT TypeError. Either the
    # canonicalness check or the extras check may fire (depending on cbor2's
    # canonical encoding of these keys); both are LayerAVerificationError.
    with pytest.raises(LayerAVerificationError):
        verify_emergency_offline_root_signature(
            rotation_preimage=preimage,
            emergency_offline_root_signature=cose_bytes,
            offline_root_key_id=offline_root_key_id,
            policy=policy,
        )


# ---------------------------------------------------------------------------
# Algorithmic-DoS via protected_bstr canonical re-encode — atheris differential
# (2026-05-26, second finding of the session) hit a >300 s hang on a single
# mutated input inside `cbor2.dumps(decoded, canonical=True)` in
# is_canonical_cose_protected_header. The verifier never returned, completely
# starving the fuzzer (libfuzzer's 300 s timeout watchdog dumped the Python
# stack but couldn't force the fuzz target to exit cleanly, so no artifact
# was saved).
#
# Closed by capping protected_bstr at COSE_PROTECTED_HEADER_MAX_BYTES = 256
# at the entry of BOTH verifiers (cross_host + offline_root), BEFORE the
# cbor2.loads + downstream canonical re-encode. Real protected headers in
# this protocol are 3 bytes canonical (`a1 01 27` = {1:EdDSA}); with a kid
# label the worst-case legit is < 40 bytes. 256 is generous for legit, tight
# against the canonical-encoder DoS. Defense-in-depth: the helper itself also
# short-circuits oversized inputs.
#
# This regression locks the size cap behaviour with explicit time budgets:
# pre-fix the canonical re-encode of a moderately-large nested CBOR structure
# was slow enough that fuzzing wedged; post-fix the verifier must return
# (False, COSE_PROTECTED_HEADER_OVERSIZED, ...) in < 100 ms even on a
# protected_bstr that decodes to something maximally adversarial.
# ---------------------------------------------------------------------------

import time as _time


def test_oversized_protected_header_rejected_fast(signed_env) -> None:
    """A 300-byte protected_bstr (just above the 256 cap) must be rejected
    with COSE_PROTECTED_HEADER_OVERSIZED in well under 100 ms — the cap fires
    BEFORE any cbor2.loads / canonical re-encode work."""
    pub_raw, preimage, canonical = signed_env
    _, unprotected, payload, signature = cbor2.loads(canonical)
    # 100 small int-keyed entries => ~278 bytes encoded, just over the cap.
    oversized_protected = cbor2.dumps({i: 0 for i in range(100)})
    assert len(oversized_protected) > 256
    evil = cbor2.dumps([oversized_protected, unprotected, payload, signature])
    t0 = _time.monotonic()
    ok, code, detail = verify_cross_host_authenticator_cose(
        public_key_raw=pub_raw, preimage=preimage, cose_bytes=evil, role="sender"
    )
    elapsed = _time.monotonic() - t0
    assert ok is False
    assert code == "COSE_PROTECTED_HEADER_OVERSIZED"
    assert isinstance(detail, str)
    # 100 ms is a very loose budget — the actual reject is microseconds.
    # The point is: NO canonical re-encode work is done on attacker bytes.
    assert elapsed < 0.1, f"oversized reject took too long: {elapsed:.3f}s"


def test_at_cap_size_protected_header_proceeds_to_canonical_check(
    signed_env,
) -> None:
    """A protected_bstr EXACTLY at the 256-byte cap must NOT be rejected by
    the size guard (boundary off-by-one regression). Such an input would still
    fail downstream checks (alg-pin or non-canonical), but with a different
    reason code — locking the cap at 256 inclusive."""
    pub_raw, preimage, canonical = signed_env
    _, unprotected, payload, signature = cbor2.loads(canonical)
    # Construct a protected_bstr of length exactly 256. Encode {0: bstr(N)}
    # with a length chosen so total bytes == 256.
    for n in range(200, 256):
        candidate = cbor2.dumps({1: -8, 99: bytes(n)})
        if len(candidate) == 256:
            at_cap = candidate
            break
    else:
        # Fallback: pad freely under 256 to confirm the boundary still passes.
        at_cap = cbor2.dumps({1: -8, 99: bytes(200)})
        assert len(at_cap) <= 256
    evil = cbor2.dumps([at_cap, unprotected, payload, signature])
    ok, code, _ = verify_cross_host_authenticator_cose(
        public_key_raw=pub_raw, preimage=preimage, cose_bytes=evil, role="sender"
    )
    assert ok is False
    # Must NOT be the oversized code — the size guard does not fire at the cap.
    assert code != "COSE_PROTECTED_HEADER_OVERSIZED"


def test_oversized_protected_header_offline_root_rejected_fast() -> None:
    """Sister verifier (offline_root) carries the same cap. Pre-fix could
    wedge on the same algorithmic-DoS class; post-fix must raise
    LayerAVerificationError fast."""
    from audit_bundle.extensions.c19.layer_a_counter import (
        LayerAVerificationError,
    )
    from audit_bundle.extensions.c19.offline_root import (
        OFFLINE_ROOT_COSE_DOMAIN_AAD,
        OfflineRootPolicy,
        offline_root_cose_sig_structure,
        verify_emergency_offline_root_signature,
    )

    priv = Ed25519PrivateKey.from_private_bytes(_PRIV_SEED)
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    preimage = b"v-kernel layer-2 cose fuzz canonical preimage"
    offline_root_key_id = b"\xab" * 32
    policy = OfflineRootPolicy(
        pinned_offline_root_key_ids=frozenset({offline_root_key_id}),
        pinned_offline_root_verifying_keys={offline_root_key_id: pub_raw},
    )

    oversized_protected = cbor2.dumps({i: 0 for i in range(100)})
    assert len(oversized_protected) > 256
    # Sign over the oversized header so the envelope is well-formed except
    # for the cap violation — proves the guard fires BEFORE the cbor2.loads
    # / canonical re-encode path.
    sig_input = offline_root_cose_sig_structure(
        preimage,
        external_aad=OFFLINE_ROOT_COSE_DOMAIN_AAD,
        protected_bstr=oversized_protected,
    )
    sig = priv.sign(sig_input)
    cose_bytes = cbor2.dumps([oversized_protected, {}, None, sig])

    t0 = _time.monotonic()
    with pytest.raises(LayerAVerificationError) as ei:
        verify_emergency_offline_root_signature(
            rotation_preimage=preimage,
            emergency_offline_root_signature=cose_bytes,
            offline_root_key_id=offline_root_key_id,
            policy=policy,
        )
    elapsed = _time.monotonic() - t0
    assert "oversized" in ei.value.detail.lower()
    assert elapsed < 0.1, f"oversized reject took too long: {elapsed:.3f}s"
