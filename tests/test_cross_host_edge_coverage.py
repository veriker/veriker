"""tests/test_cross_host_edge_coverage.py — per-edge cross-host coverage accounting.

Property under test (verdict-divergence tribunal follow-up, ratified 2026-06-10):
a bundle carrying `causal_chain.cross_host_authenticators` edges verifies OK only
if EVERY present edge was verified by a wired plugin. The core asserts
`present_edge_keys − verified_edge_keys == ∅`.

This closes the residual false-GREEN the tribunal flagged in the prior coarse
boolean marker (`verifies_cross_host_authenticators`): a plugin that merely
*claimed* to verify cross-host let the guard defer wholesale, so a plugin with a
coverage GAP (verifies some edges, not all) could ride a green verdict. With
per-edge accounting the guard sees the uncovered edge and fails closed.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.cross_host_identity import cross_host_edge_key, cross_host_edge_keys  # noqa: E402
from audit_bundle.plugin import PluginResult  # noqa: E402
from audit_bundle.verdict import VerdictState  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402

from examples.streaming_minimal._build_bundle import build as _build_streaming  # noqa: E402
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck  # noqa: E402

sys.path.insert(0, str(_PKG_ROOT / "examples" / "streaming_minimal"))
from StreamingReDerivationCheck import StreamingReDerivationCheck  # noqa: E402


_EDGE_A = {"from_host": "org-a", "to_host": "org-b", "channel": "x", "counter": 1}
_EDGE_B = {"from_host": "org-b", "to_host": "org-c", "channel": "y", "counter": 2}


def _base_plugins() -> list:
    return [SpecShaPinCheck(), FileIntegrityManySmall(), StreamingReDerivationCheck()]


def _bundle_with_edges(tmp_path: Path, edges: list[dict]) -> Path:
    bundle_dir = tmp_path / "bundle"
    _build_streaming(bundle_dir)
    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    cc = manifest.get("causal_chain")
    cc = cc if isinstance(cc, dict) else {}
    cc["cross_host_authenticators"] = edges
    manifest["causal_chain"] = cc
    (bundle_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    return bundle_dir


class _CoverageReporter:
    """A minimal wired plugin that reports coverage for a fixed key set."""

    name = "test_cross_host_coverage_reporter"
    applies_to_files: frozenset[str] = frozenset()

    def __init__(self, verified_keys: frozenset[str]) -> None:
        self._verified = verified_keys

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        return PluginResult(
            ok=True,
            reason_code="PASS",
            detail="synthetic cross-host coverage",
            files_audited=(),
            verified_cross_host_edges=self._verified,
        )


# ---------------------------------------------------------------------------


def test_key_is_deterministic_and_content_bound() -> None:
    assert cross_host_edge_key(_EDGE_A) == cross_host_edge_key(dict(_EDGE_A))
    assert cross_host_edge_key(_EDGE_A) != cross_host_edge_key(_EDGE_B)
    # Order-independent (canonical JSON sorts keys).
    reordered = {"counter": 1, "channel": "x", "to_host": "org-b", "from_host": "org-a"}
    assert cross_host_edge_key(_EDGE_A) == cross_host_edge_key(reordered)


def test_full_coverage_passes(tmp_path: Path) -> None:
    bundle = _bundle_with_edges(tmp_path, [_EDGE_A, _EDGE_B])
    all_keys = cross_host_edge_keys([_EDGE_A, _EDGE_B])
    plugins = _base_plugins() + [_CoverageReporter(all_keys)]
    result = BundleVerifier(plugins=plugins).verify(bundle)
    assert result.ok is True, f"full coverage should pass; failures: {result.failures}"


def test_partial_coverage_fails_closed(tmp_path: Path) -> None:
    """THE point of per-edge accounting: a plugin that covers edge A but NOT edge
    B must not let the bundle ride green — the boolean marker could not catch this."""
    bundle = _bundle_with_edges(tmp_path, [_EDGE_A, _EDGE_B])
    only_a = frozenset({cross_host_edge_key(_EDGE_A)})
    plugins = _base_plugins() + [_CoverageReporter(only_a)]
    result = BundleVerifier(plugins=plugins).verify(bundle)
    assert result.ok is False, "partial cross-host coverage laundered to OK"
    assert result.state is VerdictState.ERROR, (
        f"expected could-not-conclude, got {result.state}"
    )


def test_no_coverage_fails_closed(tmp_path: Path) -> None:
    """Generic consumer (no cross-host plugin) — the A1 case — still fails closed."""
    bundle = _bundle_with_edges(tmp_path, [_EDGE_A, _EDGE_B])
    result = BundleVerifier(plugins=_base_plugins()).verify(bundle)
    assert result.ok is False
    assert result.state is VerdictState.ERROR


def test_coverage_of_absent_edge_does_not_help(tmp_path: Path) -> None:
    """A plugin reporting a key for an edge NOT present cannot cover a present
    edge — coverage is content-bound, so a mismatched claim leaves the real edge
    uncovered and the verdict fails closed."""
    bundle = _bundle_with_edges(tmp_path, [_EDGE_A])
    wrong_key = frozenset({cross_host_edge_key(_EDGE_B)})  # not the present edge
    plugins = _base_plugins() + [_CoverageReporter(wrong_key)]
    result = BundleVerifier(plugins=plugins).verify(bundle)
    assert result.ok is False
    assert result.state is VerdictState.ERROR
