"""tests/test_manifest_field_shape_ratchet.py — top-level field shape contract.

Security property under test (red-team receipts-shape finding, 2026-06-11): a
top-level manifest field that is PRESENT but carries the wrong JSON container
type must REJECT at the parse boundary — never degrade to "absent". Before the
fix, two claim-bearing fields whose consuming steps isinstance-guard before
reading silently laundered malformed claims:

  extension_receipts  — {"extension_receipts": []} / "verified" / true skipped
                        receipt dispatch entirely, so a present-but-malformed
                        provenance claim read exactly like no claim, against
                        the step's own present-but-unverified-never-silently-
                        passed rule.
  causal_chain        — a non-dict causal_chain (or non-list
                        cross_host_authenticators) disarmed the A1 cross-host
                        fail-closed guard the same way.

The fix is the declarative bundle_manifest._TOP_LEVEL_FIELD_SHAPES table,
enforced in verifier._validate_manifest_shape for EVERY BundleManifest field.
The ratchet here pins table completeness against the dataclass field set, so a
future manifest field cannot ship without declaring its parse shape.
"""

from __future__ import annotations

import dataclasses
import json
import sys
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.bundle_manifest import (  # noqa: E402
    _TOP_LEVEL_FIELD_SHAPES,
    BundleManifest,
)
from audit_bundle.verdict import VerdictState  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import (  # noqa: E402
    FileIntegrityManySmall,
)
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck  # noqa: E402

# Clean OK-passing base bundle: the only reason a verdict turns non-OK in the
# injection tests below is the field we inject.
from examples.streaming_minimal._build_bundle import build as _build_streaming  # noqa: E402

sys.path.insert(0, str(_PKG_ROOT / "examples" / "streaming_minimal"))
from StreamingReDerivationCheck import StreamingReDerivationCheck  # noqa: E402


def _plugins() -> list:
    return [SpecShaPinCheck(), FileIntegrityManySmall(), StreamingReDerivationCheck()]


def _build_clean(tmp_path: Path) -> Path:
    bundle_dir = tmp_path / "streaming_bundle"
    _build_streaming(bundle_dir)
    return bundle_dir


def _inject_and_verify(bundle_dir: Path, key: str, value: object):
    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    manifest[key] = value
    (bundle_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return BundleVerifier(plugins=_plugins()).verify(bundle_dir)


def _assert_shape_reject(result, key: str) -> None:
    assert result.ok is False, (
        f"present-but-malformed manifest.{key} must not verify OK — a "
        f"wrong-shape claim field must never read as absent"
    )
    assert result.state is VerdictState.REJECT, (
        f"expected REJECT (artifact-bad), got {result.state}"
    )
    assert any(r.code == "malformed_manifest" for r in result.reasons), (
        f"expected a malformed_manifest reason; got {result.reasons}"
    )


# ---------------------------------------------------------------------------
# Ratchet: the shape table covers every BundleManifest field, exactly.
# ---------------------------------------------------------------------------


def test_shape_table_covers_every_manifest_field() -> None:
    """A new manifest field must declare its parse shape in
    _TOP_LEVEL_FIELD_SHAPES (and a removed field must leave the table)."""
    field_names = {f.name for f in dataclasses.fields(BundleManifest)}
    table_names = set(_TOP_LEVEL_FIELD_SHAPES)
    assert table_names == field_names, (
        f"shape table out of sync with BundleManifest: "
        f"missing={sorted(field_names - table_names)} "
        f"stale={sorted(table_names - field_names)}"
    )


def test_shape_table_values_are_json_container_types() -> None:
    assert set(_TOP_LEVEL_FIELD_SHAPES.values()) <= {dict, list, str}


# ---------------------------------------------------------------------------
# Baseline: the clean bundle passes OK, and JSON null reads as absent.
# ---------------------------------------------------------------------------


def test_baseline_clean_bundle_is_ok(tmp_path: Path) -> None:
    bundle_dir = _build_clean(tmp_path)
    result = BundleVerifier(plugins=_plugins()).verify(bundle_dir)
    assert result.ok is True, f"base bundle must be OK; got {result.reasons}"


def test_null_optional_field_is_absent_not_malformed(tmp_path: Path) -> None:
    """JSON null keeps the dataclass-default (absent) semantics — the shape
    table rejects wrong CONTAINER types, not explicit nulls."""
    bundle_dir = _build_clean(tmp_path)
    result = _inject_and_verify(bundle_dir, "extension_receipts", None)
    assert result.ok is True, f"null field must read as absent; got {result.reasons}"


def test_empty_dict_extension_receipts_still_ok(tmp_path: Path) -> None:
    """An empty receipts object is a well-formed no-claim — back-compat."""
    bundle_dir = _build_clean(tmp_path)
    result = _inject_and_verify(bundle_dir, "extension_receipts", {})
    assert result.ok is True, f"empty receipts dict must stay OK; got {result.reasons}"


# ---------------------------------------------------------------------------
# The reported instance: malformed extension_receipts must REJECT.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", [[], "verified", True, 0, ["receipt"]])
def test_non_dict_extension_receipts_rejects(tmp_path: Path, bad: object) -> None:
    bundle_dir = _build_clean(tmp_path)
    result = _inject_and_verify(bundle_dir, "extension_receipts", bad)
    _assert_shape_reject(result, "extension_receipts")


# ---------------------------------------------------------------------------
# The security-relevant twin: a malformed cross-host claim must not disarm
# the A1 cross-host fail-closed guard.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad", ["tampered", [], True, 7])
def test_non_dict_causal_chain_rejects(tmp_path: Path, bad: object) -> None:
    bundle_dir = _build_clean(tmp_path)
    result = _inject_and_verify(bundle_dir, "causal_chain", bad)
    _assert_shape_reject(result, "causal_chain")


@pytest.mark.parametrize("bad", ["verified", {}, True, 7])
def test_non_list_cross_host_authenticators_rejects(
    tmp_path: Path, bad: object
) -> None:
    bundle_dir = _build_clean(tmp_path)
    result = _inject_and_verify(
        bundle_dir, "causal_chain", {"cross_host_authenticators": bad}
    )
    _assert_shape_reject(result, "causal_chain.cross_host_authenticators")


# ---------------------------------------------------------------------------
# The full class: EVERY manifest field present with a wrong container type
# rejects at the parse boundary (none crash, none silently read as absent).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("field_name", sorted(_TOP_LEVEL_FIELD_SHAPES))
def test_every_field_wrong_container_type_rejects(
    tmp_path: Path, field_name: str
) -> None:
    bundle_dir = _build_clean(tmp_path)
    # An int satisfies none of the table's shapes (dict / list / str).
    result = _inject_and_verify(bundle_dir, field_name, 12345)
    _assert_shape_reject(result, field_name)
