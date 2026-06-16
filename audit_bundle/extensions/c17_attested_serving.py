"""C17 — Attested serving evidence (RATS-aligned; schema reservation only at v0.3).

v0.3 scope: schema reservation ONLY. Substrate (parser/verification) work is
DEFERRED to v0.4 — the substrate shape has many attack classes still to work
through, so the schema is reserved now and the verification logic is NOT
locked yet. v0.3 reserves:
  - `bundle.evidence.attested_serving` namespace
  - `tee_kind` enum: nitro | tdx | sev-snp | nvidia-cc | none
  - RATS three-layer shape (evidence / reference_values / endorsements)
  - `serving_jurisdiction` + `expected_jurisdictions` reservation fields
  - Default mode `none` for all v0.3 bundles; bundles stamped INFERENCE_UNATTESTED

NO production parsers at v0.3. NO plugin verification logic. The TDX and
SEV-SNP parsers + jurisdiction-routing + assurance-profile mode handling all
defer to v0.4 against the cleaned schema.


"""

from __future__ import annotations

from typing import Literal, TypedDict

# ─── v0.3 schema-reservation constants ──────────────────────────────────────
# Per the audit-bundle contract §C17. Substrate (parser/verification) work is
# DEFERRED to v0.4.

# `tee_kind` enum — wire-format vocabulary. Only `none` is honored at v0.3;
# the four named TEE platforms are reserved for v0.4 parser composition
# (S17a Intel TDX + S17b AMD SEV-SNP land first; AWS Nitro + NVIDIA CC defer
# pending production partner adoption).
TeeKind = Literal["nitro", "tdx", "sev-snp", "nvidia-cc", "none"]

TEE_KIND_VALUES: frozenset[str] = frozenset(
    {"nitro", "tdx", "sev-snp", "nvidia-cc", "none"}
)

# Bundle tag emitted when `attested_serving` is None or its `evidence.tee_kind`
# is `none` (the v0.3 default). Trust degrades to L1 model-card consumption.
BUNDLE_TAG_INFERENCE_UNATTESTED: str = "INFERENCE_UNATTESTED"

# RESERVED bundle tag — semantics belong to v0.4 `attested-serving-environment`
# mode (CPU-TEE-only paths where GPU memory is host-readable). v0.3 verifier
# MUST NOT emit this tag on any bundle. Named here for forward-compat only.
BUNDLE_TAG_INFERENCE_WEIGHTS_COMPROMISABLE_RESERVED: str = (
    "INFERENCE_WEIGHTS_COMPROMISABLE"
)

# RESERVED verification-result enum — full 4-value enum lands at v0.4. v0.3
# bundles that populate `attested_serving` at all (forward-compat path) use
# `not-verified` because no v0.3 verifier runs the 10-step pipeline.
VerificationResult = Literal["passed", "failed", "soft-failed", "not-verified"]
VERIFICATION_RESULT_V03_DEFAULT: VerificationResult = "not-verified"

# RESERVED assurance-profile names — semantics belong to v0.4 mode handling.
# Named here so v0.4 sprint composes against the same string vocabulary.
AssuranceProfile = Literal[
    "offline-auditor-minimal",
    "production-standard",
    "regulated-high-assurance",
    "attested-serving-environment",
    "none",
]
ASSURANCE_PROFILE_V03_DEFAULT: AssuranceProfile = "none"


# ─── RATS layer 1: evidence ─────────────────────────────────────────────────
# TEE-signed quote + request/response binding fields. RESERVED at v0.3;
# substrate parsers compose against this shape at v0.4.
class AttestedServingEvidence(TypedDict, total=False):
    tee_kind: TeeKind
    attestation_document: str  # base64 of TEE-signed quote
    attested_pubkey: str  # ephemeral PK bound into report-data
    transcript_hash: str  # sha256 of canonical transcript bytes
    response_signature: str  # enclave-signed transcript_hash
    serving_jurisdiction: str | None  # ISO 3166-1 alpha-2


# ─── RATS layer 2: reference_values ─────────────────────────────────────────
# What the verifier expects the attested artifact to be. RESERVED at v0.3.
class AttestedServingArtifactManifest(TypedDict, total=False):
    weights_shards: list[dict]  # Merkle leaves over the weight shards (v0.4 substrate)
    adapters: list[dict]
    tokenizer_files: list[dict]
    config: str  # sha256
    chat_template: str  # sha256
    runtime_binary: dict
    kernel_set: list[dict]
    generation_config: str  # sha256


class AttestedServingReferenceValues(TypedDict, total=False):
    artifact_manifest_root: str  # Merkle root over the artifact manifest
    artifact_manifest: AttestedServingArtifactManifest
    serving_runtime_reference: str  # signed reference-values manifest
    expected_jurisdictions: list[str] | None  # list of ISO 3166-1 alpha-2


# ─── RATS layer 3: endorsements ─────────────────────────────────────────────
# Vendor / platform attestations the verifier trusts. RESERVED at v0.3.
class AttestedServingEndorsements(TypedDict, total=False):
    attestation_chain: str  # CA path from quote key to vendor root
    tcb_status: str  # vendor-defined platform health
    min_tcb_policy: str  # SVN floor required for profile
    collateral_hash: str  # vendor-issued collateral consulted
    collateral_fetched_at: str  # ISO-8601
    revocation_checked_at: str  # ISO-8601
    runtime_publisher_signature: str


# ─── RATS challenge (relying-party nonce) ──────────────────────────────────
class AttestedServingChallenge(TypedDict, total=False):
    nonce: str  # relying-party-issued, single-use
    challenge_source: Literal["relying_party", "dispatcher", "cached"]
    challenge_time: str  # ISO-8601


# ─── Privacy-safe prompt commitments ───────────────────────────────────────
class AttestedServingPromptCommitment(TypedDict, total=False):
    kind: Literal["hmac", "salted_sha256", "encrypted_with_escrow"]
    value: str  # base64
    key_id: str  # auditor-held HMAC key id or escrow key id


class AttestedServingSamplingParams(TypedDict, total=False):
    temperature: float
    top_p: float
    max_tokens: int
    seed: int
    stop: list[str]


class AttestedServingCommitments(TypedDict, total=False):
    system_prompt_commitment: AttestedServingPromptCommitment
    user_prompt_commitment: AttestedServingPromptCommitment
    sampling_params: AttestedServingSamplingParams


# ─── Top-level namespace ───────────────────────────────────────────────────
# `bundle.evidence.attested_serving` — the BundleManifest `attested_serving`
# field MUST conform to this shape when populated. v0.3 default is `None`
# (field absent), which stamps the bundle `INFERENCE_UNATTESTED`. v0.3
# verifier IGNORES the field if present (forward-compat for v0.4 bundles
# traversing a v0.3 verifier).
class AttestedServingNamespace(TypedDict, total=False):
    evidence: AttestedServingEvidence
    reference_values: AttestedServingReferenceValues
    endorsements: AttestedServingEndorsements
    challenge: AttestedServingChallenge
    commitments: AttestedServingCommitments
    verification_result: VerificationResult
    verification_failures: list[str]


def is_v03_default_unattested(attested_serving: dict | None) -> bool:
    """Return True when the bundle is in the v0.3 default `none` mode.

    Used by emit-side code to stamp `INFERENCE_UNATTESTED` on bundles that
    omit `attested_serving` OR explicitly populate `evidence.tee_kind = 'none'`.
    NOT a verifier — performs no chain-of-trust check, no signature validation,
    no manifest-hash recomputation. Pure shape inspection.
    """
    if attested_serving is None:
        return True
    evidence = attested_serving.get("evidence")
    if not isinstance(evidence, dict):
        return True
    return evidence.get("tee_kind") == "none"
