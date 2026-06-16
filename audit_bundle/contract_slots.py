"""V-Kernel contract-slots registry.

Image-resident registry of V-Kernel contract slots (active + tombstoned).
The registry JSON lives next to this module and is NEVER loaded from a
bundle directory or a caller-supplied path.

Substrate invariant: any tool that encounters a tombstoned slot id MUST
raise (not warn).  Use resolve_slot() to enforce this at every call site.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from typing import Any

_REGISTRY_PATH = Path(__file__).resolve().parent / "contract_slots.json"
_EXPECTED_SCHEMA = "nexi.v_kernel.contract_slots.v1"
_VALID_STATUSES = frozenset({"active", "tombstoned"})


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ContractSlotsError(Exception):
    """Raised for structural violations in the contract-slots registry."""


class TombstonedSlotError(ContractSlotsError):
    """Raised when a tombstoned slot id is resolved."""


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SlotEntry:
    """A single entry in the contract-slots registry."""

    id: str
    field: str
    since_version: str
    status: str
    note: str | None = dataclass_field(default=None)
    tombstone_of: str | None = dataclass_field(default=None)
    replaces: str | None = dataclass_field(default=None)


@dataclass(frozen=True)
class ContractSlots:
    """Frozen view of the loaded contract-slots registry."""

    _slots: tuple[SlotEntry, ...]

    # ------------------------------------------------------------------
    # Public surface
    # ------------------------------------------------------------------

    def active_field_names(self) -> frozenset[str]:
        """Field names of all active slots."""
        return frozenset(s.field for s in self._slots if s.status == "active")

    def tombstoned_field_names(self) -> frozenset[str]:
        """Field names of all tombstoned slots."""
        return frozenset(s.field for s in self._slots if s.status == "tombstoned")

    def resolve_slot(self, slot_id: str) -> SlotEntry:
        """Return the SlotEntry for *slot_id*.

        Raises
        ------
        TombstonedSlotError
            If the slot is tombstoned.  This is the substrate invariant:
            callers MUST NOT silently accept a retired slot.
        ContractSlotsError
            If the slot id is not found in the registry.
        """
        for s in self._slots:
            if s.id == slot_id:
                if s.status == "tombstoned":
                    raise TombstonedSlotError(
                        f"Slot {slot_id!r} is tombstoned "
                        f"(field={s.field!r}, tombstone_of={s.tombstone_of!r}). "
                        "Do not use tombstoned slots."
                    )
                return s
        raise ContractSlotsError(
            f"Unknown contract slot id {slot_id!r}. "
            "Check contract_slots.json for the authoritative registry."
        )


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def _parse_slot(raw: Any, index: int) -> SlotEntry:
    """Validate and convert one raw slot dict to a SlotEntry."""
    if not isinstance(raw, dict):
        raise ContractSlotsError(f"slots[{index}] is not an object")
    for required_key in ("id", "field", "since_version", "status"):
        if required_key not in raw:
            raise ContractSlotsError(
                f"slots[{index}] missing required key {required_key!r}"
            )
    status = raw["status"]
    if status not in _VALID_STATUSES:
        raise ContractSlotsError(
            f"slots[{index}] has invalid status {status!r}; "
            f"must be one of {sorted(_VALID_STATUSES)}"
        )
    return SlotEntry(
        id=raw["id"],
        field=raw["field"],
        since_version=raw["since_version"],
        status=status,
        note=raw.get("note"),
        tombstone_of=raw.get("tombstone_of"),
        replaces=raw.get("replaces"),
    )


def load_contract_slots() -> ContractSlots:
    """Load the image-resident contract-slots registry.

    The JSON file is resolved from the package directory (next to this
    module).  No external path argument is accepted — the registry is
    image-resident only.

    Returns
    -------
    ContractSlots
        Frozen registry object.

    Raises
    ------
    ContractSlotsError
        On any structural violation (missing schema, bad status, duplicate
        ids, missing required keys).
    """
    try:
        raw_text = _REGISTRY_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise ContractSlotsError(
            f"Cannot read contract_slots.json from {_REGISTRY_PATH}: {exc}"
        ) from exc

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ContractSlotsError(
            f"contract_slots.json is not valid JSON: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise ContractSlotsError("contract_slots.json root must be a JSON object")

    schema = data.get("$schema")
    if schema != _EXPECTED_SCHEMA:
        raise ContractSlotsError(
            f"contract_slots.json has unexpected $schema {schema!r}; "
            f"expected {_EXPECTED_SCHEMA!r}"
        )

    raw_slots = data.get("slots")
    if not isinstance(raw_slots, list):
        raise ContractSlotsError("contract_slots.json must have a 'slots' array")

    entries: list[SlotEntry] = []
    seen_ids: set[str] = set()
    for i, raw in enumerate(raw_slots):
        entry = _parse_slot(raw, i)
        if entry.id in seen_ids:
            raise ContractSlotsError(f"Duplicate slot id {entry.id!r} at index {i}")
        seen_ids.add(entry.id)
        entries.append(entry)

    return ContractSlots(_slots=tuple(entries))


# ---------------------------------------------------------------------------
# Manifest scanner (consumed by WS-5a step 8)
# ---------------------------------------------------------------------------


def post_binding_schema_checks(
    header_schema_version: str, manifest: Any
) -> tuple[tuple[str, str], ...]:
    """WS-5a post-binding steps 8a+8b — the ONE implementation for both verifiers.

    8a: the schema_version carried in the DSSE-signed payload header must agree
    with the manifest's schema_version (checked only when both are present and
    truthy, mirroring the gate's historical semantics).
    8b: the manifest must not carry a tombstoned contract-slot field.

    Returns ordered ``(reason_code, detail)`` findings — empty when clean.
    ``audit_bundle.verifier`` appends each finding as a dsse_gate failure;
    ``audit_bundle.orchestrator_turn.verifier`` (cross-pillar, EXCLUDED from
    the open drop per ``OSS_RELEASE_BOUNDARY.md``) fatals on the first. Both
    consume THIS function so the two gates cannot drift (the M9 class — they
    previously carried near-verbatim copies of these checks).

    A non-dict ``manifest`` is treated as absent ({}): both callers reject a
    malformed manifest on their own earlier steps, so these checks no-op
    rather than crash on it.
    """
    if not isinstance(manifest, dict):
        manifest = {}
    findings: list[tuple[str, str]] = []
    manifest_schema_version = manifest.get("schema_version", "")
    if (
        header_schema_version
        and manifest_schema_version
        and header_schema_version != manifest_schema_version
    ):
        findings.append(
            (
                "SCHEMA_VERSION_HEADER_MANIFEST_DISAGREE",
                f"schema_version disagrees: signed_header={header_schema_version!r} "
                f"manifest={manifest_schema_version!r}",
            )
        )
    if scan_manifest_for_tombstoned_fields(manifest) == "TOMBSTONED_FIELD_PRESENT":
        findings.append(
            (
                "TOMBSTONED_FIELD_PRESENT",
                "manifest contains a tombstoned contract-slot field",
            )
        )
    return tuple(findings)


def scan_manifest_for_tombstoned_fields(manifest: dict[str, Any]) -> str | None:
    """Check whether *manifest* contains any tombstoned field name as a key.

    Parameters
    ----------
    manifest:
        The bundle manifest dict (keys are field names).

    Returns
    -------
    ``"TOMBSTONED_FIELD_PRESENT"``
        If any key in *manifest* appears in the tombstoned-field set.
    ``None``
        If the manifest is clean.
    """
    slots = load_contract_slots()
    tombstoned = slots.tombstoned_field_names()
    for key in manifest:
        if key in tombstoned:
            return "TOMBSTONED_FIELD_PRESENT"
    return None
