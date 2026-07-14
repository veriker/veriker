"""Tests for audit_bundle.contract_slots — image-resident slot registry."""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from audit_bundle.contract_slots import (
    ContractSlots,
    ContractSlotsError,
    TombstonedSlotError,
    load_contract_slots,
    scan_manifest_for_tombstoned_fields,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

EXPECTED_TOMBSTONED_FIELDS = frozenset(
    {
        "canonical_bytes_version",
        "bundle_sha_composition_version",
        "status_change_in_band_marker",
    }
)

EXPECTED_ACTIVE_FIELDS = frozenset(
    {
        "file_integrity",
        "append_only_files",
        "dsse_envelope_version",
    }
)


# ---------------------------------------------------------------------------
# 1. Basic load + field-set correctness
# ---------------------------------------------------------------------------


class TestLoadContractSlots:
    def test_loads_successfully(self) -> None:
        slots = load_contract_slots()
        assert isinstance(slots, ContractSlots)

    def test_exactly_six_slots(self) -> None:
        slots = load_contract_slots()
        # 3 active + 3 tombstoned = 6 total
        assert len(slots._slots) == 6

    def test_active_field_names(self) -> None:
        slots = load_contract_slots()
        assert slots.active_field_names() == EXPECTED_ACTIVE_FIELDS

    def test_tombstoned_field_names(self) -> None:
        slots = load_contract_slots()
        assert slots.tombstoned_field_names() == EXPECTED_TOMBSTONED_FIELDS

    def test_active_and_tombstoned_are_disjoint(self) -> None:
        slots = load_contract_slots()
        assert slots.active_field_names().isdisjoint(slots.tombstoned_field_names())


# ---------------------------------------------------------------------------
# 2. resolve_slot invariants
# ---------------------------------------------------------------------------


class TestResolveSlot:
    def test_resolve_active_slot_c9(self) -> None:
        slots = load_contract_slots()
        entry = slots.resolve_slot("C9")
        assert entry.id == "C9"
        assert entry.field == "file_integrity"
        assert entry.status == "active"

    def test_resolve_tombstoned_c9_2_raises(self) -> None:
        slots = load_contract_slots()
        with pytest.raises(TombstonedSlotError):
            slots.resolve_slot("C9.2")

    def test_resolve_tombstoned_c9_3_raises(self) -> None:
        slots = load_contract_slots()
        with pytest.raises(TombstonedSlotError):
            slots.resolve_slot("C9.3")

    def test_resolve_tombstoned_c9_4_raises(self) -> None:
        slots = load_contract_slots()
        with pytest.raises(TombstonedSlotError):
            slots.resolve_slot("C9.4")

    def test_tombstoned_slot_error_is_contract_slots_error_subclass(self) -> None:
        slots = load_contract_slots()
        with pytest.raises(ContractSlotsError):
            slots.resolve_slot("C9.2")

    def test_unknown_slot_id_raises_contract_slots_error(self) -> None:
        slots = load_contract_slots()
        with pytest.raises(ContractSlotsError):
            slots.resolve_slot("C99")

    def test_unknown_slot_id_does_not_raise_tombstoned_error(self) -> None:
        slots = load_contract_slots()
        with pytest.raises(ContractSlotsError) as exc_info:
            slots.resolve_slot("C99")
        assert not isinstance(exc_info.value, TombstonedSlotError)

    def test_resolve_c9_5_active(self) -> None:
        slots = load_contract_slots()
        entry = slots.resolve_slot("C9.5")
        assert entry.field == "dsse_envelope_version"
        assert entry.status == "active"


# ---------------------------------------------------------------------------
# 3. scan_manifest_for_tombstoned_fields
# ---------------------------------------------------------------------------


class TestScanManifest:
    def test_tombstoned_field_present_canonical_bytes(self) -> None:
        manifest = {"canonical_bytes_version": "x", "schema_version": "vcp-v1.1"}
        assert (
            scan_manifest_for_tombstoned_fields(manifest) == "TOMBSTONED_FIELD_PRESENT"
        )

    def test_tombstoned_field_present_bundle_sha(self) -> None:
        manifest = {"bundle_sha_composition_version": "1", "file_integrity": "ok"}
        assert (
            scan_manifest_for_tombstoned_fields(manifest) == "TOMBSTONED_FIELD_PRESENT"
        )

    def test_tombstoned_field_present_status_change_marker(self) -> None:
        manifest = {"status_change_in_band_marker": True}
        assert (
            scan_manifest_for_tombstoned_fields(manifest) == "TOMBSTONED_FIELD_PRESENT"
        )

    def test_clean_manifest_returns_none(self) -> None:
        manifest = {"schema_version": "vcp-v1.1", "file_integrity": "sha256:abc"}
        assert scan_manifest_for_tombstoned_fields(manifest) is None

    def test_empty_manifest_returns_none(self) -> None:
        assert scan_manifest_for_tombstoned_fields({}) is None

    def test_active_field_only_returns_none(self) -> None:
        manifest = {"dsse_envelope_version": "v0.4", "append_only_files": True}
        assert scan_manifest_for_tombstoned_fields(manifest) is None

    def test_return_type_is_string_not_bool(self) -> None:
        manifest = {"canonical_bytes_version": "x"}
        result = scan_manifest_for_tombstoned_fields(manifest)
        assert result == "TOMBSTONED_FIELD_PRESENT"
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# 4. Image-resident invariant: no external path arg accepted
# ---------------------------------------------------------------------------


class TestImageResidentInvariant:
    def test_load_contract_slots_takes_no_parameters(self) -> None:
        sig = inspect.signature(load_contract_slots)
        # Must have zero parameters (no bundle-dir / external-path argument)
        assert len(sig.parameters) == 0, (
            f"load_contract_slots() must accept no arguments; "
            f"got: {list(sig.parameters)}"
        )

    def test_registry_resolves_next_to_module(self) -> None:
        from audit_bundle import contract_slots as cs_module

        module_dir = Path(cs_module.__file__).resolve().parent  # type: ignore[arg-type]
        registry = module_dir / "contract_slots.json"
        assert registry.exists(), (
            f"contract_slots.json must live next to contract_slots.py; "
            f"expected at {registry}"
        )

    def test_broken_schema_raises_contract_slots_error(self) -> None:
        """Verify that a structurally broken $schema raises ContractSlotsError.

        We patch the internal _parse_slot path by feeding a malformed data
        dict directly through the private loader logic via monkeypatching
        _REGISTRY_PATH to point at bad JSON in memory.
        """
        bad_data = json.dumps({"$schema": "wrong.schema.value", "slots": []})
        with patch("audit_bundle.contract_slots._REGISTRY_PATH") as mock_path:
            mock_path.read_text.return_value = bad_data
            with pytest.raises(ContractSlotsError, match="unexpected .schema"):
                load_contract_slots()

    def test_missing_schema_key_raises_contract_slots_error(self) -> None:
        bad_data = json.dumps({"slots": []})
        with patch("audit_bundle.contract_slots._REGISTRY_PATH") as mock_path:
            mock_path.read_text.return_value = bad_data
            with pytest.raises(ContractSlotsError):
                load_contract_slots()

    def test_missing_slots_key_raises_contract_slots_error(self) -> None:
        bad_data = json.dumps({"$schema": "nexi.v_kernel.contract_slots.v1"})
        with patch("audit_bundle.contract_slots._REGISTRY_PATH") as mock_path:
            mock_path.read_text.return_value = bad_data
            with pytest.raises(ContractSlotsError):
                load_contract_slots()

    def test_duplicate_slot_ids_raise_contract_slots_error(self) -> None:
        bad_data = json.dumps(
            {
                "$schema": "nexi.v_kernel.contract_slots.v1",
                "slots": [
                    {
                        "id": "C9",
                        "field": "f1",
                        "since_version": "v0.1",
                        "status": "active",
                    },
                    {
                        "id": "C9",
                        "field": "f2",
                        "since_version": "v0.1",
                        "status": "active",
                    },
                ],
            }
        )
        with patch("audit_bundle.contract_slots._REGISTRY_PATH") as mock_path:
            mock_path.read_text.return_value = bad_data
            with pytest.raises(ContractSlotsError, match="Duplicate"):
                load_contract_slots()

    def test_invalid_status_raises_contract_slots_error(self) -> None:
        bad_data = json.dumps(
            {
                "$schema": "nexi.v_kernel.contract_slots.v1",
                "slots": [
                    {
                        "id": "C9",
                        "field": "f1",
                        "since_version": "v0.1",
                        "status": "deprecated",
                    }
                ],
            }
        )
        with patch("audit_bundle.contract_slots._REGISTRY_PATH") as mock_path:
            mock_path.read_text.return_value = bad_data
            with pytest.raises(ContractSlotsError, match="invalid status"):
                load_contract_slots()
