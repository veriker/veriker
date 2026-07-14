"""tests/test_rederivation_pack_core_guard.py — re-derivation pack TOCTOU seam.

Security property under test (ChatGPT red-team, 2026-06-12):

    A ``re_derive/*_pack.py`` present in the VERIFIED bundle that no wired
    ``ReDerivationInvocationCheck`` covers is present-but-unverified and MUST
    fail closed (could-not-conclude / ERROR) in core ``verify()`` — never a
    silent OK.

Why the existing machinery did not already close this: whether a
``ReDerivationInvocationCheck`` instance is in the plugin set was decided ONLY
in ``veriker/cli/verify._build_plugins`` from a LIVE pre-snapshot read of the tree. Two
seams laundered a pack to GREEN:

  (1) Library / custom caller — ``BundleVerifier(plugins=...)`` with a set that
      omits the check (``plugins=()`` runs zero plugins). No race needed.

  (2) TOCTOU — the pack is absent at the CLI's discovery read (so no check is
      constructed) but present in the sealed snapshot the verdict is computed
      over. The verdict says OK; the producer-supplied re-derivation path was
      never evaluated.

An UNDECLARED pack is already a conservation REJECT (UNOWNED on-disk path). The
hard case — and the one these tests isolate — is a pack DECLARED in
``manifest.files`` (STRICT_SHA-owned, so conservation passes it) for which no
invocation check was constructed. The fix is ``_step_rederivation_pack_guard``
scanning the sealed snapshot in core ``verify()``.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.re_derivation_invocation import (  # noqa: E402
    ReDerivationInvocationCheck,
)
from audit_bundle.plugins.spec_sha_pin import SpecShaPinCheck  # noqa: E402
from audit_bundle.verdict import VerdictState  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from veriker.cli.verify import _bundle_pack_files  # noqa: E402

from examples.streaming_minimal._build_bundle import build as _build_streaming  # noqa: E402

sys.path.insert(0, str(_PKG_ROOT / "examples" / "streaming_minimal"))
from StreamingReDerivationCheck import StreamingReDerivationCheck  # noqa: E402

_PACK_SRC = (
    "# A pack that does NOT re-derive anything — it just exits 0 (the producer\n"
    "# grading its own homework). The point is that nothing should EXECUTE or\n"
    "# trust it; an unevaluated pack must not ride a GREEN verdict.\n"
    "import sys\n"
    "sys.exit(0)\n"
)


def _plugins_without_rederiv() -> list:
    """A plausible library/custom plugin set that omits ReDerivationInvocationCheck.

    Includes StreamingReDerivationCheck (name ``streaming_re_derivation``, a
    spec-pinned domain check — NOT the bundle-pack invocation check) so the
    streaming bundle's ``typed_checks`` claim is satisfied; the only thing absent
    is the ``re_derivation_invocation`` pack check this guard is about.
    """
    return [SpecShaPinCheck(), FileIntegrityManySmall(), StreamingReDerivationCheck()]


def _build_clean_streaming(tmp_path: Path) -> Path:
    bundle_dir = tmp_path / "streaming_bundle"
    _build_streaming(bundle_dir)
    return bundle_dir


def _drop_declared_pack(bundle_dir: Path, pack_name: str = "evil_pack.py") -> None:
    """Materialize re_derive/<pack> and DECLARE it in manifest.files with its
    real sha256 — so the conservation gate classifies it STRICT_SHA and passes
    it. This isolates the re-derivation-pack guard: any non-OK verdict is from
    the guard, not from a conservation surplus REJECT."""
    re_derive = bundle_dir / "re_derive"
    re_derive.mkdir(exist_ok=True)
    pack_path = re_derive / pack_name
    pack_path.write_text(_PACK_SRC, encoding="utf-8")
    rel = f"re_derive/{pack_name}"
    digest = hashlib.sha256(pack_path.read_bytes()).hexdigest()
    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    manifest["files"][rel] = digest
    (bundle_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Baseline: clean bundle (no re_derive dir) with a no-rederiv plugin set is OK —
# the guard is inert when there is no pack.
# ---------------------------------------------------------------------------


def test_baseline_no_pack_is_ok(tmp_path: Path) -> None:
    bundle_dir = _build_clean_streaming(tmp_path)
    result = BundleVerifier(plugins=_plugins_without_rederiv()).verify(bundle_dir)
    assert result.ok is True, (
        f"clean base bundle must be OK; failures: {result.failures}"
    )


# ---------------------------------------------------------------------------
# THE GAP: a declared pack present in the verified tree, plugin set has NO
# ReDerivationInvocationCheck. Conservation passes (declared) but the producer's
# re-derivation path was never evaluated → must be could-not-conclude.
# ---------------------------------------------------------------------------


def test_declared_pack_without_check_is_not_ok(tmp_path: Path) -> None:
    bundle_dir = _build_clean_streaming(tmp_path)
    _drop_declared_pack(bundle_dir)

    result = BundleVerifier(plugins=_plugins_without_rederiv()).verify(bundle_dir)

    assert result.ok is False, (
        "library verify() returned OK on a DECLARED re_derive pack that no "
        "ReDerivationInvocationCheck covered — the re-derivation path was present "
        "but never evaluated (TOCTOU / custom-plugin-set laundering)"
    )
    assert result.state is VerdictState.ERROR, (
        f"present-but-unverified is could-not-conclude (ERROR), got {result.state}"
    )
    codes = " ".join(r.detail for r in result.reasons) + " ".join(
        r.code for r in result.reasons
    )
    assert "RE_DERIVATION_PACK_UNCHECKED" in codes, (
        f"expected the pack-guard leg; reasons were {[(r.code, r.detail) for r in result.reasons]}"
    )


def test_toctou_pack_added_after_plugin_discovery_is_not_ok(tmp_path: Path) -> None:
    """Model the exact TOCTOU: the plugin set is FROZEN against a tree with no
    pack — so pack discovery (``_bundle_pack_files``) yields nothing and no
    ReDerivationInvocationCheck is constructed — and the pack is materialized only
    afterward. The core scan over the sealed snapshot must catch it even though
    the frozen plugin set has no covering check."""
    bundle_dir = _build_clean_streaming(tmp_path)

    # Discovery runs against the PRE-mutation tree: no pack → no check constructed.
    assert _bundle_pack_files(bundle_dir) == [], (
        "precondition: clean tree exposes no pack at discovery time"
    )
    plugins = _plugins_without_rederiv()  # the set discovery would freeze

    # Racing producer swaps the pack in before the verdict snapshot.
    _drop_declared_pack(bundle_dir)

    result = BundleVerifier(plugins=plugins).verify(bundle_dir)
    assert result.ok is False, (
        "TOCTOU: a pack swapped in after plugin discovery rode a GREEN verdict"
    )
    assert result.state is VerdictState.ERROR


# ---------------------------------------------------------------------------
# Covered case: when a ReDerivationInvocationCheck DOES cover the present pack,
# that check concludes (NOT_EXECUTED on the safe default) and the new guard
# stays SILENT — no double-reporting, no spurious UNCHECKED leg.
# ---------------------------------------------------------------------------


def test_covered_pack_concludes_via_check_not_guard(tmp_path: Path) -> None:
    bundle_dir = _build_clean_streaming(tmp_path)
    _drop_declared_pack(bundle_dir)

    plugins = _plugins_without_rederiv() + [
        ReDerivationInvocationCheck(
            pack_filename="evil_pack.py", permit_execution=False
        )
    ]
    result = BundleVerifier(plugins=plugins).verify(bundle_dir)

    # Still not OK — the safe default does not execute the pack.
    assert result.ok is False
    assert result.state is VerdictState.ERROR
    blob = " ".join(r.code for r in result.reasons) + " ".join(
        r.detail for r in result.reasons
    )
    # The could-not-conclude leg comes from the wired re_derivation_invocation
    # check (core wraps a plugin's incomplete leg as VERIFIER_INCOMPLETE with the
    # plugin id + "could not conclude" in the detail), NOT from the pack guard.
    assert "re_derivation_invocation" in blob and "could not conclude" in blob, (
        f"the wired check should report the unexecuted pack; reasons were "
        f"{[(r.code, r.detail) for r in result.reasons]}"
    )
    assert "RE_DERIVATION_PACK_UNCHECKED" not in blob, (
        "the core pack-guard must stay SILENT when a check covers the pack "
        "(no double-reporting)"
    )


# ---------------------------------------------------------------------------
# Coverage-by-dispatch boundary (the option-(b) design decision, 2026-06-12):
# a pack present in a bundle whose re-derivation IS verified by spec-pinned
# dispatch (manifest.outputs + auditor anchor) is a redundant unsafe artifact,
# NOT present-but-unverified — the guard must NOT fire. This is exercised live
# by the spec-pinned pilots (which ship their pack), asserted here in isolation
# so the boundary cannot silently regress to firing on every pack.
# ---------------------------------------------------------------------------


def test_pack_with_spec_pinned_dispatch_is_not_flagged(tmp_path: Path) -> None:
    import tests.test_climate_emission_spec_pinned as spc  # noqa: PLC0415

    bundle_dir = spc._spc.build_spec_pinned(tmp_path / "bundle")
    assert _bundle_pack_files(bundle_dir), (
        "precondition: the spec-pinned pilot ships a re_derive pack"
    )
    anchor = spc._spc.anchor_from_committed_spec()
    result = spc._spc.make_verifier(anchor).verify(bundle_dir)

    assert result.ok is True, (
        "a pack alongside spec-pinned dispatch is redundant, not unverified — "
        f"the pack guard must not fire; reasons {[(r.code, r.detail) for r in result.reasons]}"
    )
    blob = " ".join(r.code + r.detail for r in result.reasons)
    assert "RE_DERIVATION_PACK_UNCHECKED" not in blob


# ---------------------------------------------------------------------------
# CLI/library convergence (option c, 2026-06-12): _build_plugins must NOT wire
# the pack-invocation check for a dispatch bundle (manifest declares outputs),
# so an anchored verifier using the default CLI set reaches the SAME OK verdict
# the library guard allows — no spurious RE_DERIVATION_NOT_EXECUTED leg. CC2 is
# preserved: a manifest that explicitly claims re_derivation_invocation still
# gets the instance.
# ---------------------------------------------------------------------------


class _DispatchManifestStub:
    """Duck-typed manifest: declares outputs (dispatch covers) + a domain pack
    claim absent, so _build_plugins should skip the pack check."""

    def __init__(self, *, outputs, typed_checks=()):  # noqa: ANN001
        self.outputs = outputs
        self.typed_checks = typed_checks


def test_build_plugins_skips_pack_check_for_dispatch_bundle(tmp_path: Path) -> None:
    from veriker.cli.verify import _build_plugins  # noqa: PLC0415

    (tmp_path / "re_derive").mkdir()
    (tmp_path / "re_derive" / "x_pack.py").write_text("import sys; sys.exit(0)\n")
    manifest = _DispatchManifestStub(outputs=({"output_id": "o", "type": "t"},))

    plugins = _build_plugins(tmp_path, manifest)
    assert not any(
        getattr(p, "name", None) == "re_derivation_invocation" for p in plugins
    ), "dispatch bundle (outputs declared) must not wire the pack-invocation check"


def test_build_plugins_wires_pack_check_when_explicitly_claimed(tmp_path: Path) -> None:
    from veriker.cli.verify import _build_plugins  # noqa: PLC0415

    (tmp_path / "re_derive").mkdir()
    (tmp_path / "re_derive" / "x_pack.py").write_text("import sys; sys.exit(0)\n")
    # Even with outputs declared, an explicit typed_checks claim means the
    # producer asked for the pack to be evaluated → CC2 requires the instance.
    manifest = _DispatchManifestStub(
        outputs=({"output_id": "o", "type": "t"},),
        typed_checks=("re_derivation_invocation",),
    )

    plugins = _build_plugins(tmp_path, manifest)
    assert any(
        getattr(p, "name", None) == "re_derivation_invocation" for p in plugins
    ), "an explicit re_derivation_invocation claim must still wire the check (CC2)"


def test_anchored_dispatch_bundle_with_pack_converges_to_ok(tmp_path: Path) -> None:
    """The convergence target: an anchored verifier using the default CLI plugin
    set (_build_plugins) reaches OK on a pack+dispatch bundle — the same verdict
    the library pack guard allows. Before option (c), the wired pack check forced
    a spurious RE_DERIVATION_NOT_EXECUTED → ERROR."""
    import tests.test_climate_emission_spec_pinned as spc  # noqa: PLC0415
    from veriker.cli.verify import _build_plugins, _load_manifest  # noqa: PLC0415

    bundle_dir = spc._spc.build_spec_pinned(tmp_path / "bundle")
    assert _bundle_pack_files(bundle_dir), "precondition: pilot ships a pack"
    anchor = spc._spc.anchor_from_committed_spec()
    _ = spc._spc.make_verifier(anchor)  # registers the in-dir primitive

    plugins = _build_plugins(bundle_dir, _load_manifest(bundle_dir))
    result = BundleVerifier(plugins=plugins, spec_anchor=anchor).verify(bundle_dir)

    assert result.ok is True, (
        f"anchored default-set verify must converge to OK on pack+dispatch; "
        f"reasons {[(r.code, r.detail) for r in result.reasons]}"
    )
