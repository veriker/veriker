"""Manifest-field disposition ratchet — every claim-bearing field is PLUGGED IN
somewhere, on purpose, in writing (BLOCK-01 profile-downgrade structural
follow-up, 2026-06-12).

The failure class this kills: ``assurance_profile`` was parsed into the
manifest, documented as tamper-evident, and consulted by NOTHING on the
verdict path — and no inventory existed that would have noticed. The same
shape had already bitten three times (CLI-only gates / orphaned shallow
checks / pilot-only fragment re-derivation). The shallow-parity ratchet
(BLOCK-03) covers validate_manifest checks; THIS ratchet covers the manifest
FIELDS themselves:

  1. TOTALITY — every ``BundleManifest`` dataclass field has an entry in the
     disposition table below AND a row in MANIFEST_SCHEMA.md. A new field
     cannot ship undispositioned.
  2. STEP LIVENESS — a field dispositioned ``step:<name>`` must name a symbol
     that EXISTS in audit_bundle.verifier AND is actually INVOKED in
     ``_verify_in_dir`` source. Defined-but-never-called (the ef9a197 /
     BLOCK-01 failure mode) fails here.
  3. RESERVED CLOSURE — the set of fields documented "IGNORED" in
     MANIFEST_SCHEMA.md must EXACTLY equal the burn-down list below. A field
     cannot quietly become ignored, an ignored field cannot lose its doc row,
     and a previously-guarded field (assurance_profile, verifier_identity,
     causal_chain) can never be re-listed as ignored.

Burn-down direction: RESERVED and PLUGIN_DEPENDENT entries shrink; they never
grow without editing this file (which is the point — the diff is the
disclosure).
"""

from __future__ import annotations

import dataclasses
import inspect
import re
from pathlib import Path

import audit_bundle.verifier as verifier_module
from audit_bundle.bundle_manifest import BundleManifest
from audit_bundle.verifier import BundleVerifier

_PKG_ROOT = Path(__file__).resolve().parent.parent
_MANIFEST_SCHEMA_MD = _PKG_ROOT / "MANIFEST_SCHEMA.md"

# --- the disposition table ---------------------------------------------------
#
# kind ∈ {
#   "step":   enforced by a named core verdict-path step/guard — liveness-checked
#   "parse":  enforced at the parse boundary — named symbol must exist in the
#             verifier module source (e.g. the schema-version allowlist gate)
#   "metadata": identity/bookkeeping only — makes no falsifiable claim core
#             must check (it may still be covered by tamper-evidence)
#   "plugin_dependent": semantic enforcement lives in caller-supplied plugins;
#             a plugin-less verify() shape-checks only. DISCLOSED residual of
#             the BLOCK-01 class — burn down, do not grow.
#   "reserved": v0.3 schema reservation — verifier IGNORES by documented
#             design; must carry an "IGNORED" row in MANIFEST_SCHEMA.md
# }
_DISPOSITIONS: dict[str, tuple[str, str | None]] = {
    "schema_version": ("parse", "SchemaVersionError"),
    "bundle_id": ("metadata", None),
    "created_at": ("metadata", None),
    "files": ("step", "_step_file_integrity"),
    "spec_files": ("step", "_step_spec_sha_pinning"),
    "cross_refs": ("step", "_step_cross_refs"),
    "payload": ("metadata", None),
    "typed_checks": ("step", "_step_typed_check_plugins"),
    "snapshots": ("step", "_step_deep_manifest_validation"),
    "snapshot_policy": ("step", "_step_deep_manifest_validation"),
    "fragment_anchors": ("step", "_step_fragment_anchor_guard"),
    "source_attributes": ("step", "_step_deep_manifest_validation"),
    "decision_provenance_log": ("step", "_step_deep_manifest_validation"),
    "retrieval_trace_id": ("step", "_step_deep_manifest_validation"),
    "retrieval_trace_log": ("step", "_step_deep_manifest_validation"),
    "per_output_manifests": ("step", "_step_deep_manifest_validation"),
    "output_mode_signal": ("step", "_step_deep_manifest_validation"),
    "dispatch_records": ("step", "_step_stamp_claims_guard"),
    "aggregate_stamp": ("step", "_step_stamp_claims_guard"),
    "assurance_profile": ("step", "_step_assurance_profile_guard"),
    "append_only_files": ("step", "_step_file_integrity"),
    "rigor_profile": ("reserved", None),
    "attested_serving": ("reserved", None),
    "verifier_identity": ("step", "_step_c18_structural"),
    "causal_chain": ("step", "_step_cross_host_guard"),
    "semantic_fidelity": ("reserved", None),
    "extension_receipts": ("step", "_step_extension_receipts"),
    "outputs": ("step", "_step_spec_pinned_dispatch"),
}

# Fields whose MANIFEST_SCHEMA.md row may say "IGNORED". EXACT match enforced.
_RESERVED_IGNORED: frozenset[str] = frozenset(
    {"rigor_profile", "attested_serving", "semantic_fidelity"}
)


def _manifest_fields() -> set[str]:
    return {f.name for f in dataclasses.fields(BundleManifest)}


def _doc_rows() -> dict[str, str]:
    """field name → full table row text, parsed from MANIFEST_SCHEMA.md."""
    rows: dict[str, str] = {}
    for line in _MANIFEST_SCHEMA_MD.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\|\s*`([a-z_0-9]+)`\s*\|", line)
        if m:
            rows.setdefault(m.group(1), line)
    return rows


def test_every_field_has_a_disposition_entry():
    fields = _manifest_fields()
    missing = fields - set(_DISPOSITIONS)
    stale = set(_DISPOSITIONS) - fields
    assert not missing, (
        f"BundleManifest field(s) with NO disposition entry: {sorted(missing)}. "
        "A new manifest field must say WHO enforces it (step/parse), or be "
        "explicitly metadata / plugin_dependent / reserved — silence is how "
        "assurance_profile shipped unwired."
    )
    assert not stale, (
        f"disposition entries for nonexistent field(s): {sorted(stale)} — "
        "remove them so the table mirrors the dataclass."
    )


def test_every_field_has_a_doc_row():
    fields = _manifest_fields()
    rows = _doc_rows()
    missing = fields - set(rows)
    assert not missing, (
        f"BundleManifest field(s) with NO row in MANIFEST_SCHEMA.md: "
        f"{sorted(missing)}. The schema doc is the relying party's contract — "
        "every field gets a row naming its validating step or its reservation."
    )


def test_step_dispositions_are_alive_on_the_verdict_path():
    """A 'step' disposition must name a symbol that exists AND is invoked in
    _verify_in_dir — defined-but-never-called fails (the orphaned-enforcement
    failure mode this finding and BLOCK-03 share)."""
    verdict_path_source = inspect.getsource(BundleVerifier._verify_in_dir)
    module_source = inspect.getsource(verifier_module)
    for field, (kind, symbol) in sorted(_DISPOSITIONS.items()):
        if kind == "step":
            assert symbol is not None
            exists = hasattr(BundleVerifier, symbol) or hasattr(verifier_module, symbol)
            assert exists, (
                f"{field}: disposition names step {symbol!r} which does not "
                "exist in audit_bundle.verifier"
            )
            assert symbol in verdict_path_source, (
                f"{field}: step {symbol!r} exists but is NOT invoked in "
                "BundleVerifier._verify_in_dir — an enforcement step that the "
                "verdict path never calls is an orphan, not a guarantee"
            )
        elif kind == "parse":
            assert symbol is not None and symbol in module_source, (
                f"{field}: parse-boundary symbol {symbol!r} not referenced in "
                "audit_bundle.verifier source"
            )


def test_reserved_ignored_set_is_closed():
    rows = _doc_rows()
    documented_ignored = {
        name for name, row in rows.items() if "IGNORED" in row
    } & _manifest_fields()
    assert documented_ignored == _RESERVED_IGNORED, (
        "MANIFEST_SCHEMA.md 'IGNORED' rows must exactly match the reserved "
        f"burn-down list.\n  documented ignored: {sorted(documented_ignored)}\n"
        f"  allowlisted:        {sorted(_RESERVED_IGNORED)}\n"
        "A field cannot quietly become ignored (add it here, on purpose, in "
        "this diff), and a guarded field can never be re-listed as ignored."
    )
    reserved_in_table = {
        f for f, (kind, _) in _DISPOSITIONS.items() if kind == "reserved"
    }
    assert reserved_in_table == _RESERVED_IGNORED, (
        "disposition 'reserved' entries and the IGNORED allowlist drifted: "
        f"{sorted(reserved_in_table)} vs {sorted(_RESERVED_IGNORED)}"
    )


def test_assurance_profile_is_guarded_not_reserved():
    """The BLOCK-01 field itself can never regress to ignored/reserved."""
    kind, symbol = _DISPOSITIONS["assurance_profile"]
    assert (kind, symbol) == ("step", "_step_assurance_profile_guard")
    assert "assurance_profile" not in _RESERVED_IGNORED
