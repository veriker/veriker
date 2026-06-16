"""SCITT v0.5 Phase B — anchor a Signed Statement to Rekor and embed its NATIVE proof.

Builds the "Rekor-backed transparent statement" = the COSE_Sign1 Signed Statement
(`release/scitt_signed_statement.py`) + Rekor's NATIVE inclusion proof + signed checkpoint.

WHY "Rekor-backed", NOT "SCITT Receipt" (grounded against current drafts):
  Rekor does NOT issue a SCITT COSE Receipt. Its `cose` entry type is for *submitting* a COSE
  object to be logged, not for issuing a COSE_Sign1 Receipt; Rekor returns a native inclusion
  proof + a signed checkpoint under its log key. The proof MATH bridges (Rekor's tree IS the
  RFC9162_SHA256 / RFC 6962 tree the COSE-Receipts draft profiles), but a conformant Receipt
  needs a COSE_Sign1 signed over the tree head — a signer Rekor does not provide, and which only
  a real SCITT TS (the reserved premium leg) would. So this module verifies Rekor's NATIVE
  artifacts; external copy must say "Rekor-backed", never "SCITT Receipt".

‼ MERKLE CONVENTION — RFC 6962, NOT the in-tree per-bundle convention. Rekor/RFC 6962 use
  leaf = H(0x00 || data), node = H(0x01 || left || right). The codebase's
  `audit_bundle.extensions.c19.layer_a_counter.compute_bundle_merkle_root` uses the INVERTED
  prefixes (leaf 0x01 / node 0x00) for its own per-bundle event DAG — do NOT reuse it here; it
  would compute wrong roots against real Rekor data and only fail against a live log.
  `test_rekor_anchor.test_rfc6962_convention_differs_from_inner_tree` locks the distinction.

WHAT IS REAL HERE (offline, non-tautological):
  * `verify_inclusion_proof` — the canonical RFC 6962 §2.1.1 inclusion-proof recompute. Real
    teeth: a tampered hash / wrong root / wrong index / wrong leaf all fail.
  * `verify_checkpoint_signature` — parses Rekor's Go signed-note checkpoint and verifies its
    ECDSA P-256 signature against the pinned `rekor.sigstore.dev` log key.
  * `assemble_rekor_backed_statement` / `register_signed_statement` — the bundle shape + a
    transport-abstracted registration client (replayable for tests).

GROUNDED against a REAL public Rekor v1 entry (read-only fetch, no write/POST) — see
`tests/fixtures/rekor_real_entry_v1.json` and `tests/test_rekor_anchor.py::test_real_rekor_*`.
The two former "deferred fidelity" gaps are now pinned empirically against live Rekor bytes:

  * LEAF CANONICALIZATION (resolved). The Merkle leaf preimage is the base64-DECODED `body`
    field of the Rekor entry; the RFC 6962 leaf hash is `SHA256(0x00 || base64decode(body))`.
    Verified: `root_from_inclusion_proof(rfc6962_leaf_hash(base64decode(body)), ip.logIndex,
    ip.treeSize, ip.hashes)` equals the real `inclusionProof.rootHash`. (Pass `leaf_preimage =
    base64decode(entry["body"])` to the verifiers.)
  * CHECKPOINT KEY + NOTE FORMAT (resolved). The checkpoint is a Go sumdb / c2sp.org
    signed-note: a text body (line 1 = origin `<host> - <treeID>`, line 2 = tree size,
    line 3 = base64 root hash), a BLANK separator line, then one or more signature lines
    `— <name> <base64(4-byte key-hint || ECDSA-DER-sig)>`. The SIGNED bytes are the body
    plus a single trailing newline (`checkpoint.split("\\n\\n", 1)[0] + "\\n"`) — the blank
    line and signature block are NOT signed. Rekor's `rekor.sigstore.dev` log key is ECDSA
    P-256 (NOT Ed25519); the 4-byte key-hint is `SHA256(DER SubjectPublicKeyInfo)[:4]`, which
    also equals the leading 4 bytes of every active-shard entry's `logID`. The pinned key is
    `REKOR_SIGSTORE_LOG_PUBLIC_KEY_PEM` (provenance: GET .../api/v1/log/publicKey).

WHAT REMAINS DEFERRED (gated, NOT a fidelity gap):
  * The LIVE network POST to a Rekor instance (`LiveRekorTransport` raises until enabled).
  * NEXI signing its OWN Signed Statement under a Fulcio-rooted keyless release identity, and
    REGISTERING its own releases to the log (a write + posture decision). The Ed25519 issuer-
    statement path lives in `release/scitt_signed_statement.py`, not here — the checkpoint path
    above is its own (ECDSA P-256) key type.

Tier-2 / network-substrate side (sibling to c18_tuf_client.py). Pure-stdlib Merkle (hashlib);
checkpoint-sig + key load use `cryptography` (an existing substrate dep). MUST NOT be pulled
onto the offline stdlib core (`veriker/cli/verify.py` / `audit_bundle/verifier.py`) per the
two-verifier boundary.


"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_public_key,
)

# --- RFC 6962 §2.1 domain-separated hashing (NOTE: opposite prefixes to the inner-tree). ---
_RFC6962_LEAF_PREFIX = b"\x00"
_RFC6962_NODE_PREFIX = b"\x01"


class RekorAnchorError(RuntimeError):
    """Raised on a malformed anchor or a failed inclusion-proof recompute."""


def rfc6962_leaf_hash(leaf_preimage: bytes) -> bytes:
    """RFC 6962 leaf hash: SHA-256(0x00 || leaf_preimage)."""
    return hashlib.sha256(_RFC6962_LEAF_PREFIX + leaf_preimage).digest()


def rfc6962_node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 interior node hash: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(_RFC6962_NODE_PREFIX + left + right).digest()


def root_from_inclusion_proof(
    leaf_hash: bytes, leaf_index: int, tree_size: int, proof: list[bytes]
) -> bytes:
    """Recompute the Merkle tree root from an RFC 6962 §2.1.1 inclusion proof.

    `leaf_hash` is the already-computed RFC6962 leaf hash (see `rfc6962_leaf_hash`),
    `leaf_index` is 0-based, `proof` is the ordered list of sibling node hashes. Returns the
    recomputed 32-byte root. Raises :class:`RekorAnchorError` if the proof is the wrong length
    for the (index, size) pair. This is the canonical algorithm (RFC 6962; matches the
    certificate-transparency reference) — independent of how any tree was built, so a wrong
    proof yields a wrong root rather than silently passing.
    """
    if tree_size <= 0:
        raise RekorAnchorError(f"tree_size must be positive, got {tree_size}")
    if not 0 <= leaf_index < tree_size:
        raise RekorAnchorError(
            f"leaf_index {leaf_index} out of range for tree_size {tree_size}"
        )
    if len(leaf_hash) != 32:
        raise RekorAnchorError(f"leaf_hash must be 32 bytes, got {len(leaf_hash)}")

    fn = leaf_index
    sn = tree_size - 1
    r = leaf_hash
    for sibling in proof:
        if len(sibling) != 32:
            raise RekorAnchorError("proof entry is not a 32-byte hash")
        if sn == 0:
            raise RekorAnchorError("inclusion proof too long for tree_size")
        if (fn & 1) == 1 or fn == sn:
            r = rfc6962_node_hash(sibling, r)
            # When fn is even but fn == sn (we are the rightmost node at this level),
            # ascend past the run of left-edges until the LSB is set.
            while (fn & 1) == 0:
                fn >>= 1
                sn >>= 1
        else:
            r = rfc6962_node_hash(r, sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise RekorAnchorError("inclusion proof too short for tree_size")
    return r


@dataclass(frozen=True)
class RekorAnchor:
    """Rekor's native proof-of-inclusion for one logged entry (NOT a SCITT COSE Receipt).

    Mirrors the fields of Rekor's `verification.inclusionProof` block plus entry metadata.
    `root_hash` / `hashes` are raw 32-byte digests (decode hex at the parse boundary).
    `checkpoint` is the signed-note bytes (verified separately, against the pinned log key).
    """

    log_id: str
    log_index: int
    tree_size: int
    root_hash: bytes
    hashes: tuple[bytes, ...]
    checkpoint: bytes
    integrated_time: int | None = None

    @classmethod
    def from_rekor_verification(cls, log_id: str, verification: dict) -> "RekorAnchor":
        """Parse a Rekor `verification` object (the `inclusionProof` sub-block + metadata)."""
        proof = verification.get("inclusionProof")
        if not isinstance(proof, dict):
            raise RekorAnchorError(
                "verification.inclusionProof missing or not an object"
            )
        try:
            log_index = int(proof["logIndex"])
            tree_size = int(proof["treeSize"])
            root_hash = bytes.fromhex(proof["rootHash"])
            hashes = tuple(bytes.fromhex(h) for h in proof["hashes"])
            checkpoint = str(proof["checkpoint"]).encode("utf-8")
        except (KeyError, TypeError, ValueError) as exc:
            raise RekorAnchorError(f"malformed inclusionProof: {exc}") from exc
        integrated = verification.get("integratedTime")
        return cls(
            log_id=log_id,
            log_index=log_index,
            tree_size=tree_size,
            root_hash=root_hash,
            hashes=hashes,
            checkpoint=checkpoint,
            integrated_time=int(integrated) if integrated is not None else None,
        )


def verify_inclusion_proof(leaf_preimage: bytes, anchor: RekorAnchor) -> bool:
    """Recompute the root from `leaf_preimage` + the anchor's proof and compare to `root_hash`.

    Returns True iff the leaf is provably included at `anchor.log_index` in a tree whose root
    is `anchor.root_hash`. This binds the leaf to the checkpoint root; it does NOT by itself
    prove the root is Rekor's genuine tree head — that is `verify_checkpoint_signature` against
    the pinned Rekor log key. For a real Rekor entry, `leaf_preimage = base64decode(entry["body"])`
    (the grounded leaf canonicalization — see module docstring).
    """
    leaf_hash = rfc6962_leaf_hash(leaf_preimage)
    try:
        recomputed = root_from_inclusion_proof(
            leaf_hash, anchor.log_index, anchor.tree_size, list(anchor.hashes)
        )
    except RekorAnchorError:
        return False
    return recomputed == anchor.root_hash


# --- Rekor log key (ECDSA P-256) + Go signed-note checkpoint parsing. ---

#: The published `rekor.sigstore.dev` transparency-log public key (ECDSA P-256 / secp256r1).
#: Provenance: GET https://rekor.sigstore.dev/api/v1/log/publicKey (a public, read-only fetch).
#: SHA-256(DER SubjectPublicKeyInfo) = c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d,
#: whose 4-byte prefix (c0d23d6a) is BOTH the checkpoint signed-note key-hint AND the leading
#: bytes of every active-shard entry's `logID`. Pinned here as the trust anchor; in the C18
#: substrate it can equivalently be resolved from the `sigstore-trust-root` TUF role
#: (c18_tuf_client.fetch_sigstore_trust_root, which already requires `rekor.pub`).
REKOR_SIGSTORE_LOG_PUBLIC_KEY_PEM = (
    b"-----BEGIN PUBLIC KEY-----\n"
    b"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\n"
    b"kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n"
    b"-----END PUBLIC KEY-----\n"
)


def load_rekor_log_public_key(
    pem: bytes | None = None,
) -> ec.EllipticCurvePublicKey:
    """Load the Rekor log public key (ECDSA P-256). Defaults to the pinned published key.

    Raises :class:`RekorAnchorError` if the PEM is not an ECDSA P-256 (secp256r1) key — the
    Rekor checkpoint key type, distinct from the Ed25519 issuer-statement key.
    """
    try:
        key = load_pem_public_key(
            pem if pem is not None else REKOR_SIGSTORE_LOG_PUBLIC_KEY_PEM
        )
    except (ValueError, TypeError) as exc:
        raise RekorAnchorError(f"could not parse Rekor log public key: {exc}") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != "secp256r1":
        raise RekorAnchorError(
            "Rekor log key must be ECDSA P-256 (secp256r1); got "
            f"{type(key).__name__}/{getattr(getattr(key, 'curve', None), 'name', '?')}"
        )
    return key


def rekor_key_hint(rekor_log_pubkey: ec.EllipticCurvePublicKey) -> bytes:
    """The 4-byte signed-note key-hint for a Rekor log key = SHA-256(DER SPKI)[:4].

    Empirically equals the checkpoint signature-line prefix and the entry logID prefix.
    """
    der = rekor_log_pubkey.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).digest()[:4]


@dataclass(frozen=True)
class CheckpointNote:
    """A parsed Rekor checkpoint (Go sumdb / c2sp.org signed-note).

    `signed_body` is the exact byte string the signature covers (origin/size/root lines plus a
    single trailing newline — NOT the blank separator or signature block). `signatures` is a
    tuple of (name, 4-byte key_hint, signature_bytes).
    """

    origin: str
    tree_size: int
    root_hash: bytes
    signed_body: bytes
    signatures: tuple[tuple[str, bytes, bytes], ...]


def parse_checkpoint_note(checkpoint: bytes) -> CheckpointNote:
    """Parse a Rekor signed-note checkpoint into its body fields + signature lines.

    Format (c2sp.org/tlog-checkpoint over golang.org/x/mod/sumdb/note):
        <origin: "<host> - <treeID>">\\n<tree size>\\n<base64 root hash>\\n[<other lines>\\n]
        \\n                                     # blank separator (NOT signed)
        — <name> <base64(4-byte key-hint || signature)>\\n   # one or more

    The SIGNED bytes are `checkpoint.split(b"\\n\\n", 1)[0] + b"\\n"`. Raises
    :class:`RekorAnchorError` on a malformed note.
    """
    try:
        text = checkpoint.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RekorAnchorError(f"checkpoint is not valid UTF-8: {exc}") from exc
    if "\n\n" not in text:
        raise RekorAnchorError(
            "checkpoint is not a signed note (no blank-line body/signature separator)"
        )
    body_part, sig_part = text.split("\n\n", 1)
    signed_body = (body_part + "\n").encode("utf-8")
    lines = body_part.split("\n")
    if len(lines) < 3:
        raise RekorAnchorError(
            "checkpoint body must have >=3 lines (origin, tree size, root hash)"
        )
    origin = lines[0]
    try:
        tree_size = int(lines[1])
    except ValueError as exc:
        raise RekorAnchorError(f"checkpoint tree-size line malformed: {exc}") from exc
    try:
        root_hash = base64.b64decode(lines[2], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RekorAnchorError(f"checkpoint root-hash line not base64: {exc}") from exc

    signatures: list[tuple[str, bytes, bytes]] = []
    for line in sig_part.split("\n"):
        if not line.startswith("— "):  # signature lines begin with U+2014 + space
            continue
        parts = line.split(" ")
        if len(parts) < 3:
            raise RekorAnchorError(f"malformed checkpoint signature line: {line!r}")
        name = parts[1]
        try:
            raw = base64.b64decode(parts[2], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise RekorAnchorError(f"checkpoint signature not base64: {exc}") from exc
        if len(raw) <= 4:
            raise RekorAnchorError("checkpoint signature too short (key-hint only)")
        signatures.append((name, raw[:4], raw[4:]))
    if not signatures:
        raise RekorAnchorError("checkpoint carries no signature lines")
    return CheckpointNote(origin, tree_size, root_hash, signed_body, tuple(signatures))


def verify_checkpoint_signature(
    checkpoint: bytes, rekor_log_pubkey: ec.EllipticCurvePublicKey
) -> bool:
    """Verify the ECDSA P-256 signature carried in a Rekor checkpoint against the log key.

    Parses the signed-note (`parse_checkpoint_note`), selects the signature line whose 4-byte
    key-hint matches `rekor_log_pubkey`, and ECDSA/SHA-256-verifies it over the note's signed
    body. The signature is embedded IN the checkpoint (a Go signed-note) — not supplied
    separately. Returns False on a malformed note, a missing matching signature, or a bad sig.

    GROUNDED: verifies the real `rekor.sigstore.dev` checkpoint in
    `tests/fixtures/rekor_real_entry_v1.json` against the pinned ECDSA P-256 log key.
    """
    try:
        note = parse_checkpoint_note(checkpoint)
    except RekorAnchorError:
        return False
    key_hint = rekor_key_hint(rekor_log_pubkey)
    for _name, hint, signature in note.signatures:
        if hint != key_hint:
            continue
        try:
            rekor_log_pubkey.verify(
                signature, note.signed_body, ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False
    return False  # no signature line matched the pinned log key's hint


def assemble_rekor_backed_statement(
    signed_statement_cose: bytes, anchor: RekorAnchor
) -> dict:
    """Assemble the Rekor-backed transparent statement: Signed Statement + native Rekor anchor.

    NOTE: "transparent" here means "anchored to Rekor's append-only log", verified by
    re-deriving the inclusion proof — NOT a SCITT Transparent Statement (no COSE Receipt).
    """
    return {
        "format": "vkernel/rekor-backed-transparent-statement/v0.5-draft",
        "signed_statement_cose_hex": signed_statement_cose.hex(),
        "rekor": {
            "log_id": anchor.log_id,
            "log_index": anchor.log_index,
            "tree_size": anchor.tree_size,
            "root_hash": anchor.root_hash.hex(),
            "hashes": [h.hex() for h in anchor.hashes],
            "checkpoint": anchor.checkpoint.decode("utf-8", errors="replace"),
            "integrated_time": anchor.integrated_time,
        },
        "transparency_note": (
            "Rekor-backed (Sigstore transparency log). NOT a SCITT Transparent Statement: "
            "Rekor returns a native inclusion proof + signed checkpoint, not a COSE Receipt."
        ),
    }


class RekorTransport(Protocol):
    """Abstracts the act of submitting a leaf preimage to a Rekor log and getting back its
    `(log_id, verification)` response. The live transport is network; tests replay a fixture."""

    def submit(self, leaf_preimage: bytes) -> tuple[str, dict]: ...


class ReplayTransport:
    """A RekorTransport that returns a pre-recorded `(log_id, verification)` response.

    For offline development + tests. A REAL captured Rekor response lives at
    `tests/fixtures/rekor_real_entry_v1.json` and validates Rekor's leaf-canonicalization +
    checkpoint key against live bytes; the synthetic RFC-6962 fixtures additionally exercise the
    recompute math across tree sizes (see module docstring).
    """

    def __init__(self, log_id: str, verification: dict) -> None:
        self._log_id = log_id
        self._verification = verification

    def submit(self, leaf_preimage: bytes) -> tuple[str, dict]:  # noqa: ARG002
        return self._log_id, self._verification


class LiveRekorTransport:
    """Placeholder for the live network transport. Deferred to a runner with network access and
    a pinned Rekor endpoint; raises until that wiring lands, so it cannot silently no-op."""

    def __init__(self, base_url: str) -> None:
        self._base_url = base_url

    def submit(self, leaf_preimage: bytes) -> tuple[str, dict]:  # noqa: ARG002
        raise NotImplementedError(
            "LiveRekorTransport is deferred to a networked runner (network POST to "
            f"{self._base_url}/api/v1/log/entries + response parse). Offline builds use "
            "ReplayTransport. See this module's docstring."
        )


def register_signed_statement(
    signed_statement_cose: bytes,
    transport: RekorTransport,
    *,
    leaf_preimage: bytes | None = None,
    verify: bool = True,
) -> dict:
    """Submit the Signed Statement to a Rekor log (via `transport`) and assemble the bundle.

    `leaf_preimage` defaults to the COSE statement bytes; a real Rekor entry canonicalizes the
    submitted object into its `body`, whose base64-decode is the logged leaf preimage (see module
    docstring on leaf canonicalization). When `verify` is True (default), the
    returned anchor's inclusion proof is re-derived and a mismatch raises — so a transport that
    returns a proof inconsistent with the leaf fails closed at registration time.
    """
    preimage = leaf_preimage if leaf_preimage is not None else signed_statement_cose
    log_id, verification = transport.submit(preimage)
    anchor = RekorAnchor.from_rekor_verification(log_id, verification)
    if verify and not verify_inclusion_proof(preimage, anchor):
        raise RekorAnchorError(
            "Rekor returned an inclusion proof that does not re-derive its own root for the "
            "submitted leaf — refusing to assemble (fail-closed)."
        )
    return assemble_rekor_backed_statement(signed_statement_cose, anchor)


def rekor_anchor_from_sigstore_bundle(bundle: dict) -> tuple[RekorAnchor, bytes]:
    """Lossless reshape of a cosign Sigstore protobuf-bundle tlog entry → (anchor, leaf_preimage).

    `cosign sign-blob --bundle` (the NEW bundle format,
    `application/vnd.dev.sigstore.bundle.v0.3+json`) records the Rekor entry under
    `verificationMaterial.tlogEntries[0]`. This extracts that entry's inclusion proof +
    signed checkpoint + canonicalized body into the in-tree :class:`RekorAnchor` shape, so the
    grounded offline verifier (`verify_rekor_backed_statement`) can check cosign's OWN entry
    WITHOUT re-running cosign or trusting its verdict — cosign is the sole Fulcio+Rekor *writer*;
    this keeps the *verify* side native (one write stack, verify-only re-derivation).

    PURE field extraction + decode — NO Merkle recompute, NO re-canonicalization of the body or
    checkpoint (a re-canonicalization would silently become a SECOND verification path;
    losslessness is a binding condition). Field-encoding deltas vs the Rekor v1 REST
    shape (:meth:`RekorAnchor.from_rekor_verification`):

      * `rootHash` / `hashes` are base64 (protobuf `bytes`) here, hex in the REST API;
      * `logIndex` / `treeSize` are strings (protobuf int64→JSON) here, ints in REST;
      * the checkpoint is nested at `inclusionProof.checkpoint.envelope`;
      * the Merkle leaf preimage is `base64decode(tlogEntries[0].canonicalizedBody)`.

    Returns `(anchor, leaf_preimage)`; pass `leaf_preimage` to `verify_rekor_backed_statement`.
    Raises :class:`RekorAnchorError` on a malformed bundle.

    GROUNDING: the field MAPPING is verified against the sigstore protobuf-bundle spec AND a
    fixture re-encoded from the REAL Rekor v1 entry (`test_rekor_anchor.test_sigstore_bundle_*`) —
    same real Merkle data + real checkpoint, only the cosign-bundle envelope around them. The
    remaining deferred check is that cosign emits exactly this layout for OUR own `.cose` on the
    first live registration (`LiveRekorTransport` still raises). The
    leaf-canon rule `SHA256(0x00 ‖ base64decode(body))` is Trillian-level so it holds across
    `cose`/`dsse`/`hashedrekord` kinds — but confirm once on the first own entry.
    """
    try:
        entries = bundle["verificationMaterial"]["tlogEntries"]
        if not entries:
            raise RekorAnchorError("Sigstore bundle has no tlogEntries")
        entry = entries[0]
        proof = entry["inclusionProof"]
        log_index = int(proof["logIndex"])
        tree_size = int(proof["treeSize"])
        root_hash = base64.b64decode(proof["rootHash"], validate=True)
        hashes = tuple(base64.b64decode(h, validate=True) for h in proof["hashes"])
        checkpoint = str(proof["checkpoint"]["envelope"]).encode("utf-8")
        # protobuf logId.keyId is base64; surface as hex to match the REST `log_id` convention.
        key_id_b64 = (entry.get("logId") or {}).get("keyId")
        log_id = base64.b64decode(key_id_b64, validate=True).hex() if key_id_b64 else ""
        integrated = entry.get("integratedTime")
        leaf_preimage = base64.b64decode(entry["canonicalizedBody"], validate=True)
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise RekorAnchorError(
            f"malformed Sigstore protobuf-bundle tlog entry: {exc}"
        ) from exc
    anchor = RekorAnchor(
        log_id=log_id,
        log_index=log_index,
        tree_size=tree_size,
        root_hash=root_hash,
        hashes=hashes,
        checkpoint=checkpoint,
        integrated_time=int(integrated) if integrated is not None else None,
    )
    return anchor, leaf_preimage


# -----------------------------------------------------------------------------
# Phase C — consumer-side verification of a Rekor-backed transparent statement.
# -----------------------------------------------------------------------------

# Reason codes (returned in the verdict; stable strings for callers to branch on).
REASON_MALFORMED_BUNDLE = "MALFORMED_BUNDLE"
REASON_MALFORMED_ANCHOR = "MALFORMED_ANCHOR"
REASON_INCLUSION_PROOF_FAILED = "INCLUSION_PROOF_DOES_NOT_REDERIVE_ROOT"
REASON_CHECKPOINT_SIGNATURE_INVALID = "CHECKPOINT_SIGNATURE_INVALID"
REASON_CHECKPOINT_NOT_EVALUATED = "CHECKPOINT_SIGNATURE_NOT_EVALUATED"
REASON_CHECKPOINT_ROOT_MISMATCH = "CHECKPOINT_ROOT_DISAGREES_WITH_INCLUSION_PROOF"


@dataclass(frozen=True)
class RekorVerdict:
    """Outcome of verifying a Rekor-backed transparent statement.

    ‼ `ok` is True ONLY when BOTH legs pass. `inclusion_verified` alone is necessary but NOT
    sufficient: an inclusion proof shows "this leaf is in a tree whose root is R", but R is the
    root the bundle CLAIMS — only `checkpoint_verified` (the checkpoint signed by Rekor's pinned
    log key) binds R to Rekor's genuine tree head. Without it an adversary can forge an entire
    tree with any root. So a verdict with `checkpoint_verified is None` (no pinned key supplied)
    is INCOMPLETE and reports `ok=False`, never a pass. The checkpoint leg ALSO requires the
    signed checkpoint's root to equal the inclusion proof's root (else the two legs attest
    different trees) — a mismatch is a checkpoint failure, not a pass.
    """

    ok: bool
    inclusion_verified: bool
    checkpoint_verified: bool | None  # None => not evaluated (no pinned key supplied)
    reasons: tuple[str, ...]


def verify_anchor(
    anchor: RekorAnchor,
    leaf_preimage: bytes,
    *,
    rekor_log_pubkey: ec.EllipticCurvePublicKey | None = None,
) -> RekorVerdict:
    """Verify a parsed :class:`RekorAnchor` + its leaf preimage — both legs, fail-closed.

    The shared core of :func:`verify_rekor_backed_statement`, exposed so a caller that already
    holds an extracted anchor (e.g. ``rekor_anchor_from_sigstore_bundle`` on a cosign
    ``.sigstore-bundle.json``) can verify WITHOUT re-serialising into the assembled-statement
    dict shape:
      1. re-derive the inclusion proof (`verify_inclusion_proof`) — always evaluated;
      2. verify the checkpoint's ECDSA P-256 signature against Rekor's PINNED log key AND bind
         the signed checkpoint's root to the inclusion proof's root — ONLY when
         ``rekor_log_pubkey`` is supplied.

    ``ok`` is True iff BOTH legs pass. A None checkpoint (no pinned key) is INCOMPLETE => not ok
    (the contract on :class:`RekorVerdict`): an inclusion proof alone binds the leaf to a CLAIMED
    root; only the pinned-key checkpoint binds that root to Rekor's genuine tree head.
    """
    reasons: list[str] = []

    inclusion_ok = verify_inclusion_proof(leaf_preimage, anchor)
    if not inclusion_ok:
        reasons.append(REASON_INCLUSION_PROOF_FAILED)

    checkpoint_ok: bool | None
    if rekor_log_pubkey is not None:
        sig_ok = verify_checkpoint_signature(anchor.checkpoint, rekor_log_pubkey)
        if not sig_ok:
            checkpoint_ok = False
            reasons.append(REASON_CHECKPOINT_SIGNATURE_INVALID)
        else:
            # Signature valid — now bind the signed checkpoint's root to the proof's root,
            # else the checkpoint attests a DIFFERENT tree than the inclusion proof re-derives.
            try:
                note = parse_checkpoint_note(anchor.checkpoint)
            except RekorAnchorError:
                checkpoint_ok = False
                reasons.append(REASON_CHECKPOINT_SIGNATURE_INVALID)
            else:
                if note.root_hash == anchor.root_hash:
                    checkpoint_ok = True
                else:
                    checkpoint_ok = False
                    reasons.append(REASON_CHECKPOINT_ROOT_MISMATCH)
    else:
        checkpoint_ok = None
        reasons.append(REASON_CHECKPOINT_NOT_EVALUATED)

    # Both legs required for a pass. checkpoint_ok None (no pinned key) => INCOMPLETE => not ok.
    ok = inclusion_ok and checkpoint_ok is True
    return RekorVerdict(ok, inclusion_ok, checkpoint_ok, tuple(reasons))


def verify_rekor_backed_statement(
    bundle: dict,
    *,
    rekor_log_pubkey: ec.EllipticCurvePublicKey | None = None,
    leaf_preimage: bytes | None = None,
) -> RekorVerdict:
    """Verify a `assemble_rekor_backed_statement` bundle on the tier-2 network verifier.

    Composes the two real verifiers into one verdict:
      1. re-derive the inclusion proof (`verify_inclusion_proof`) — always evaluated;
      2. verify the checkpoint's ECDSA P-256 signature against Rekor's PINNED log key
         (`verify_checkpoint_signature`) AND bind the signed checkpoint's root to the inclusion
         proof's root — evaluated ONLY when `rekor_log_pubkey` is supplied (e.g. via
         `load_rekor_log_public_key()` or the `sigstore-trust-root` TUF role). The signature is
         carried inside the checkpoint signed-note; it is NOT a separate argument.

    `leaf_preimage` defaults to the embedded COSE statement bytes (the default registration used
    by `register_signed_statement`); for a real Rekor entry pass `base64decode(entry["body"])`
    (the grounded leaf canonicalization — see module docstring).
    """
    rekor = bundle.get("rekor")
    statement_hex = bundle.get("signed_statement_cose_hex")
    if not isinstance(rekor, dict) or not isinstance(statement_hex, str):
        return RekorVerdict(False, False, None, (REASON_MALFORMED_BUNDLE,))
    try:
        preimage = (
            leaf_preimage if leaf_preimage is not None else bytes.fromhex(statement_hex)
        )
        anchor = RekorAnchor(
            log_id=str(rekor["log_id"]),
            log_index=int(rekor["log_index"]),
            tree_size=int(rekor["tree_size"]),
            root_hash=bytes.fromhex(rekor["root_hash"]),
            hashes=tuple(bytes.fromhex(h) for h in rekor["hashes"]),
            checkpoint=str(rekor["checkpoint"]).encode("utf-8"),
            integrated_time=rekor.get("integrated_time"),
        )
    except (KeyError, TypeError, ValueError):
        return RekorVerdict(False, False, None, (REASON_MALFORMED_ANCHOR,))

    return verify_anchor(anchor, preimage, rekor_log_pubkey=rekor_log_pubkey)
