"""content_provenance_recompute.py — verifier-side content-provenance re-derivation primitive.

Axis-2 value-return form (SPEC_PINNED_DISPATCH_ARCHITECTURE §3.3). Self-contained
per-dir migration of the content_provenance pilot onto spec-pinned dispatch: the
recompute primitive lives HERE (verifier-distribution code, registered by the
spec-pinned builder), NOT in audit_bundle/rederivation/primitives/.

Re-derivation primitive (one sentence):
    content_sha = hashlib.sha256(bytes(artifact/content.txt)).hexdigest()

The representative re-derived output is the SHA-256 hex digest of the published
content bytes. The hashing rule is FIXED in this primitive — the primitive_id
("content_provenance_recompute") IS the rule. The auditor's SHA-pinned spec binds
the output type "content_sha" to this primitive_id and to an `exact` comparator
(byte-exact string equality); a producer cannot weaken the hashing or the
comparison without changing the primitive_id / spec SHA, which the anchor rejects.

content_sha is chosen as the representative value because it is a deterministic,
key-free recompute (a plain SHA-256 over committed bytes). The producer_hmac field
is NOT used here: it requires the synthetic producer key, whereas the content_sha
re-derivation needs only the committed artifact bytes.

Stdlib-only (§C5 contract). This module is importable WITHOUT audit_bundle on
sys.path (the RecomputedValue import is deferred into recompute()), so the
spec-pinned builder can import compute_content_sha() standalone.
"""

from __future__ import annotations

from pathlib import Path


# ---------------------------------------------------------------------------
# Canonical computation (shared by the builder and the verifier — ONE source)
# ---------------------------------------------------------------------------


def compute_content_sha(content_bytes: bytes) -> str:
    """Canonical content SHA-256 hex digest. Mirrors the legacy builder's
    _sha256(content_bytes): a plain SHA-256 over the published content bytes,
    returned as a lowercase hex string. Builder and verifier share this ONE
    definition so the honest claimed sha and the re-derivation cannot drift.
    """
    import hashlib  # noqa: PLC0415

    return hashlib.sha256(content_bytes).hexdigest()


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered before BundleVerifier)
# ---------------------------------------------------------------------------


class ContentProvenanceRecompute:
    """Verifier-side primitive for re-deriving the published content SHA-256."""

    primitive_id: str = "content_provenance_recompute"

    def recompute(self, inputs, pack_section: dict):
        """Recompute the content SHA-256 hex digest from artifact/content.txt.

        inputs.bundle_dir is a read-only Path. pack_section carries
        {output_id, type, params} from the auditor's spec binding. Returns a
        RecomputedValue carrying the hex string; the verifier's `exact`
        comparator compares it against the producer-claimed value.
        """
        # Deferred import keeps this module importable standalone (builder use).
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        bundle_dir: Path = inputs.bundle_dir
        content_path = bundle_dir / "artifact" / "content.txt"
        if not content_path.is_file():
            raise FileNotFoundError(
                f"artifact/content.txt not found in bundle at {bundle_dir}"
            )
        content_bytes = content_path.read_bytes()
        value = compute_content_sha(content_bytes)
        return RecomputedValue(
            value=value,
            detail=f"re-derived content sha256 over {len(content_bytes)} content byte(s)",
        )
