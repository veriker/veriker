"""Strict shape validation for a verified DSSE payload (stdlib-only).

A DSSE gate verifies the envelope signature first, then json.loads() the signed
payload and dereferences a handful of fields — `manifest_sha256` (binding
compare), `schema_version` (carried to post-binding checks), and `files`
(set-closure). The signature guarantees the bytes came from an allowlisted
signer; it does NOT guarantee the decoded JSON has the expected SHAPE.

Before this validator, a validly-signed payload that was JSON-but-wrong-shape
(a non-object top level, `files` as a string, or `files` as a list of
non-objects / objects missing `path`) flowed straight into `payload.get(...)`
and `f["path"]`, raising AttributeError / TypeError / KeyError. Those escaped
the gate and were caught by the verifier's outer fail-closed boundary as a
crash-class VERIFIER_INTERNAL_ERROR (INDETERMINATE) — the bundle still failed
closed, but a malformed *artifact* was misreported as a *verifier* fault. The
gate already returns a structured DSSE_MALFORMED_ENVELOPE reject when the
payload is not valid JSON (one step earlier); this validator extends that same
present-but-malformed-signed-payload → structured-REJECT discipline to the
shape the gate then dereferences.

Scope discipline — validate ONLY the fields the gate consumes:
  * Container shapes (object / array / object-with-`path`) prevent the crash.
  * `manifest_sha256` / `schema_version` are required to be `str`; their VALUES
    are still checked downstream (the binding compare and the post-binding
    schema check respectively) — this validator does not duplicate that.
  * Forward-compatible payload fields the gate ignores (e.g. the emitter's
    `iat`) are LEFT ALONE. An unknown-field rejection would break the real
    producer and any additive payload evolution, so it is deliberately omitted
    (the analogue of the manifest's "verifier ignores unknown reserved keys"
    posture). This is the one point where the recommendation that motivated the
    fix over-reaches for this codebase.
"""

from __future__ import annotations

DSSE_MALFORMED_PAYLOAD: str = "DSSE_MALFORMED_PAYLOAD"


def validate_dsse_payload_shape(payload: object) -> "tuple[str, str] | None":
    """Validate the gate-consumed shape of a decoded DSSE payload.

    Returns ``None`` when the payload is safe to dereference, or
    ``(DSSE_MALFORMED_PAYLOAD, detail)`` when a consumed field has the wrong
    container type — the caller routes that through its structured DSSE REJECT
    helper, never a crash-class ERROR. Total over all inputs; never raises.
    """
    if not isinstance(payload, dict):
        return (
            DSSE_MALFORMED_PAYLOAD,
            f"signed payload must be a JSON object, got {type(payload).__name__}",
        )

    schema_version = payload.get("schema_version")
    if not isinstance(schema_version, str):
        return (
            DSSE_MALFORMED_PAYLOAD,
            f"payload.schema_version must be a string, got "
            f"{type(schema_version).__name__}",
        )

    manifest_sha256 = payload.get("manifest_sha256")
    if not isinstance(manifest_sha256, str):
        return (
            DSSE_MALFORMED_PAYLOAD,
            f"payload.manifest_sha256 must be a string, got "
            f"{type(manifest_sha256).__name__}",
        )

    files = payload.get("files")
    if not isinstance(files, list):
        return (
            DSSE_MALFORMED_PAYLOAD,
            f"payload.files must be a JSON array, got {type(files).__name__}",
        )

    seen_paths: set[str] = set()
    for i, entry in enumerate(files):
        if not isinstance(entry, dict):
            return (
                DSSE_MALFORMED_PAYLOAD,
                f"payload.files[{i}] must be a JSON object, got {type(entry).__name__}",
            )
        path = entry.get("path")
        if not isinstance(path, str):
            return (
                DSSE_MALFORMED_PAYLOAD,
                f"payload.files[{i}].path must be a string, got {type(path).__name__}",
            )
        # Duplicate paths collapse silently in the set-closure frozenset, so a
        # payload that lists one path twice is malformed-but-tolerated. Reject
        # it (belt-and-braces: the emitter sorts unique paths, so this never
        # fires on a legitimate producer).
        if path in seen_paths:
            return (
                DSSE_MALFORMED_PAYLOAD,
                f"payload.files contains duplicate path {path!r}",
            )
        seen_paths.add(path)

    return None
