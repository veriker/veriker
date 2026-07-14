"""chat_log_redaction_recompute.py — verifier-side chat-log PII-redaction re-derivation primitive.

Axis-2 value-return form (SPEC_PINNED_DISPATCH_ARCHITECTURE §3.3). Self-contained
per-dir migration of the chat_log_redaction pilot onto spec-pinned dispatch: the
recompute primitive lives HERE (verifier-distribution code, registered by the
spec-pinned builder), NOT in audit_bundle/rederivation/primitives/.

Re-derivation primitive (one sentence):
    redacted_output_sha = sha256(redacted_transcript).hexdigest(), where the
    redacted transcript is produced by re-running the bundled deterministic
    regex + entity-dict PII scan over inputs/transcript.txt under
    inputs/redaction_policy.json (identical span ordering + greedy-cover overlap
    resolution + right-to-left [REDACTED:<kind>] substitution).

The representative re-derived output is the SHA-256 hex digest of the redacted
transcript bytes. The redaction rule is FIXED in this primitive — the
primitive_id ("chat_log_redaction_recompute") IS the rule, and it mirrors the
legacy build's _apply_redaction_policy + _sha256 EXACTLY (same regex iteration
order, same byte-offset conversion, same `sort(key=(start, -(end-start)))`,
same greedy-cover overlap merge, same reversed-application substitution). The
auditor's SHA-pinned spec binds the output type "redacted_output_sha" to this
primitive_id and to an `exact` comparator (byte-exact hex-string equality); a
producer cannot weaken the redaction or the comparison without changing the
primitive_id / spec SHA, which the anchor rejects.

redacted_output_sha is chosen as the representative value because it is a
deterministic, key-free recompute (regex + dict scan + SHA-256 over committed
bytes). It collapses the whole span-list + redacted-output into one exact-safe
hex string.

Stdlib-only (§C5 contract). This module is importable WITHOUT audit_bundle on
sys.path (the RecomputedValue import is deferred into recompute()), so the
spec-pinned builder can import compute_redacted_output_sha() standalone.
"""

from __future__ import annotations

from pathlib import Path


# ---------------------------------------------------------------------------
# Canonical computation (shared by the builder and the verifier — ONE source)
# ---------------------------------------------------------------------------


def _apply_redaction_policy(transcript, policy):
    """Mirror of the legacy builder's _apply_redaction_policy (byte-for-byte).

    Returns (accepted_spans, redacted_str). accepted_spans is a list of
    (start_byte, end_byte, entity_kind) in ascending start order after
    greedy-cover overlap resolution.
    """
    import re  # noqa: PLC0415

    transcript_bytes = transcript.encode("utf-8")
    raw_spans = []

    # Step 1 — regex patterns (iterated in policy dict order).
    for kind, pattern in policy["regex_patterns"].items():
        for m in re.finditer(pattern, transcript):
            start_b = len(transcript[: m.start()].encode("utf-8"))
            end_b = len(transcript[: m.end()].encode("utf-8"))
            raw_spans.append((start_b, end_b, kind))

    # Step 2 — entity dict (exact string match, case-sensitive, kind=PERSON).
    for name in policy["entity_dict"]:
        for m in re.finditer(re.escape(name), transcript):
            start_b = len(transcript[: m.start()].encode("utf-8"))
            end_b = len(transcript[: m.end()].encode("utf-8"))
            raw_spans.append((start_b, end_b, "PERSON"))

    # Step 3 — sort by start, resolve overlaps (greedy cover, keep first kind on tie).
    raw_spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    accepted = []
    for span in raw_spans:
        if not accepted:
            accepted.append(span)
            continue
        last = accepted[-1]
        if span[0] < last[1]:
            if span[1] > last[1]:
                accepted[-1] = (last[0], span[1], last[2])
        else:
            accepted.append(span)

    # Step 4 — apply substitutions right-to-left to keep byte offsets stable.
    result_bytes = bytearray(transcript_bytes)
    for start_b, end_b, kind in reversed(accepted):
        replacement = f"[REDACTED:{kind}]".encode("utf-8")
        result_bytes[start_b:end_b] = replacement

    redacted_str = result_bytes.decode("utf-8")
    return accepted, redacted_str


def compute_redacted_output_sha(transcript: str, policy: dict) -> str:
    """Canonical redacted-output SHA-256 hex digest. Mirrors the legacy builder's
    _sha256(redacted_str.encode("utf-8")): re-run the deterministic redaction
    policy over the transcript, then hash the redacted transcript bytes. Builder
    and verifier share this ONE definition so the honest claimed sha and the
    re-derivation cannot drift.
    """
    import hashlib  # noqa: PLC0415

    _spans, redacted_str = _apply_redaction_policy(transcript, policy)
    return hashlib.sha256(redacted_str.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered before BundleVerifier)
# ---------------------------------------------------------------------------


class ChatLogRedactionRecompute:
    """Verifier-side primitive for re-deriving the redacted-output SHA-256."""

    primitive_id: str = "chat_log_redaction_recompute"

    def recompute(self, inputs, pack_section: dict):
        """Recompute redacted_output_sha from inputs/transcript.txt under
        inputs/redaction_policy.json.

        inputs.bundle_dir is a read-only Path. pack_section carries
        {output_id, type, params} from the auditor's spec binding. Returns a
        RecomputedValue carrying the hex string; the verifier's `exact`
        comparator compares it against the producer-claimed value.
        """
        # Deferred import keeps this module importable standalone (builder use).
        import json  # noqa: PLC0415

        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        bundle_dir: Path = inputs.bundle_dir
        transcript_path = bundle_dir / "inputs" / "transcript.txt"
        policy_path = bundle_dir / "inputs" / "redaction_policy.json"
        if not transcript_path.is_file():
            raise FileNotFoundError(
                f"inputs/transcript.txt not found in bundle at {bundle_dir}"
            )
        if not policy_path.is_file():
            raise FileNotFoundError(
                f"inputs/redaction_policy.json not found in bundle at {bundle_dir}"
            )
        transcript = transcript_path.read_text(encoding="utf-8")
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        value = compute_redacted_output_sha(transcript, policy)
        return RecomputedValue(
            value=value,
            detail=(
                f"re-derived redacted_output_sha over {len(transcript.encode('utf-8'))} "
                f"transcript byte(s) under the bundled redaction policy"
            ),
        )
