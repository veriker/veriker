"""tests/test_unsafe_pack_execution_gate.py — the re-derivation code-execution gate.

Security property under test (red-team finding, 2026-06-06): an untrusted bundle
must NOT cause code execution on the verifier's machine in the default verify
path. A re_derive/*_pack.py is bundle-supplied Python; ReDerivationInvocationCheck
runs it via subprocess. The gate:

  - `permit_execution` is a REQUIRED constructor keyword (no default) — every
    call site must state the trust decision.
  - With permit_execution=False (the default for veriker/cli/verify.py) the pack is NOT
    executed: no subprocess, no side effects, reason RE_DERIVATION_NOT_EXECUTED.
  - With permit_execution=True (opt-in --unsafe-run-bundle-pack) the legacy
    subprocess invocation runs (RE_DERIVED / RE_DERIVATION_MISMATCH as before).
  - veriker/cli/verify.py's _build_plugins propagates the flag: default → not executed,
    --unsafe-run-bundle-pack → executed.

The decisive proof is the side-effect marker: a pack that writes a file when it
runs. If the file appears, the pack executed; if not, it did not.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.plugins.re_derivation_invocation import (  # noqa: E402
    NOT_EXECUTED_REASON,
    ReDerivationInvocationCheck,
)


class _Manifest:
    """Minimal manifest stand-in; the check does not read it."""


def _write_side_effect_pack(bundle_dir: Path, marker: Path) -> str:
    """Write a pack that, IF executed, creates `marker` and exits 0.

    Returns the pack filename. The marker's existence is the proof of execution.
    """
    rederive = bundle_dir / "re_derive"
    rederive.mkdir(parents=True, exist_ok=True)
    pack = rederive / "evil_pack.py"
    pack.write_text(
        "import sys\n"
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed')\n"
        "sys.exit(0)\n",
        encoding="utf-8",
    )
    return pack.name


# ---------------------------------------------------------------------------
# The teeth: side-effect marker proves execute / no-execute
# ---------------------------------------------------------------------------


def test_pack_not_executed_when_not_permitted(tmp_path: Path) -> None:
    marker = tmp_path / "marker.txt"
    pack_name = _write_side_effect_pack(tmp_path, marker)

    result = ReDerivationInvocationCheck(pack_name, permit_execution=False).check(
        tmp_path, _Manifest()
    )

    # Decisive: the pack's side effect did NOT happen.
    assert not marker.exists(), "pack executed despite permit_execution=False"
    # Surfaced honestly: not RE_DERIVED, not a silent pass.
    assert result.reason_code == NOT_EXECUTED_REASON
    assert result.reason_code != "RE_DERIVED"
    # ok=True (NOT-EVALUATED posture) — does not fail an otherwise-valid bundle.
    assert result.ok is True
    assert "not executed" in result.detail.lower()


def test_pack_executed_when_permitted(tmp_path: Path) -> None:
    marker = tmp_path / "marker.txt"
    pack_name = _write_side_effect_pack(tmp_path, marker)

    result = ReDerivationInvocationCheck(pack_name, permit_execution=True).check(
        tmp_path, _Manifest()
    )

    # Decisive: with the opt-in, the pack DID run.
    assert marker.exists(), "pack did not execute despite permit_execution=True"
    assert marker.read_text() == "executed"
    assert result.ok is True
    assert result.reason_code == "RE_DERIVED"


def test_not_executed_takes_priority_over_running_a_failing_pack(
    tmp_path: Path,
) -> None:
    """A pack that would exit non-zero (RE_DERIVATION_MISMATCH) is still NOT run
    when execution is not permitted — the gate short-circuits before subprocess."""
    rederive = tmp_path / "re_derive"
    rederive.mkdir()
    (rederive / "fail_pack.py").write_text(
        "import sys; sys.exit(1)\n", encoding="utf-8"
    )
    result = ReDerivationInvocationCheck("fail_pack.py", permit_execution=False).check(
        tmp_path, _Manifest()
    )
    assert result.reason_code == NOT_EXECUTED_REASON
    assert result.ok is True


# ---------------------------------------------------------------------------
# Constructor requires the explicit trust decision
# ---------------------------------------------------------------------------


def test_constructor_requires_permit_execution_keyword() -> None:
    with pytest.raises(TypeError):
        ReDerivationInvocationCheck("pack.py")  # type: ignore[call-arg]


def test_no_pack_still_short_circuits_regardless_of_permit(tmp_path: Path) -> None:
    # No pack present → NO_PACK either way; nothing is executed.
    for permit in (False, True):
        result = ReDerivationInvocationCheck(
            "missing.py", permit_execution=permit
        ).check(tmp_path, _Manifest())
        assert result.reason_code == "NO_PACK"
        assert result.ok is True


# ---------------------------------------------------------------------------
# CLI wiring: _build_plugins propagates the flag (default = not permitted)
# ---------------------------------------------------------------------------


def _rederive_plugin(plugins: list):
    return next((p for p in plugins if p.name == "re_derivation_invocation"), None)


def test_build_plugins_default_does_not_permit_execution(tmp_path: Path) -> None:
    from veriker.cli.verify import _build_plugins

    _write_side_effect_pack(tmp_path, tmp_path / "m.txt")
    # _build_plugins only reads manifest.typed_checks (for unrelated domain
    # plugins); a stub suffices and avoids the heavy BundleManifest ctor.
    manifest = _Manifest()
    manifest.typed_checks = ("re_derivation_invocation",)

    plugins = _build_plugins(tmp_path, manifest)  # default permit_pack_execution
    plugin = _rederive_plugin(plugins)
    assert plugin is not None, "check must be constructed for CC2 even when not run"
    assert plugin.permit_execution is False


def test_build_plugins_flag_permits_execution(tmp_path: Path) -> None:
    from veriker.cli.verify import _build_plugins

    _write_side_effect_pack(tmp_path, tmp_path / "m.txt")
    manifest = _Manifest()
    manifest.typed_checks = ("re_derivation_invocation",)

    plugins = _build_plugins(tmp_path, manifest, permit_pack_execution=True)
    plugin = _rederive_plugin(plugins)
    assert plugin is not None
    assert plugin.permit_execution is True


# ---------------------------------------------------------------------------
# CLI exit-code contract: re-derivation is GATING (the core verified property).
# Codex residual (2026-06-06): exit-code-only consumers must not overread a
# NOT-RUN as covered. Claimed-but-NOT-RUN => ERROR (exit 2), never exit 0.
# ---------------------------------------------------------------------------

_CLIMATE_BUNDLE = _PKG_ROOT / "examples" / "climate_emission_minimal"


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(_PKG_ROOT / "veriker" / "cli" / "verify.py"),
         "--bundle-dir", str(_CLIMATE_BUNDLE), *args],
        capture_output=True, text=True, cwd=str(_PKG_ROOT),
    )


@pytest.mark.skipif(not _CLIMATE_BUNDLE.is_dir(), reason="climate example bundle absent")
def test_cli_default_not_run_is_error_exit_2():
    """Bare default verify on a pack bundle: re-derivation NOT evaluated -> the
    process exit is 2 (ERROR/do-not-accept), NOT 0. This is the exit-code-only
    consumer protection — exit 0 would overclaim the core property."""
    cp = _run_cli()
    assert cp.returncode == 2, f"expected ERROR exit 2, got {cp.returncode}\n{cp.stdout}\n{cp.stderr}"
    combined = cp.stdout + cp.stderr
    assert "RE_DERIVATION_NOT_EXECUTED" in combined
    assert "COULD NOT CONCLUDE" in combined
    # The summary must NOT read as a clean pass.
    assert "INCOMPLETE" in cp.stdout


@pytest.mark.skipif(not _CLIMATE_BUNDLE.is_dir(), reason="climate example bundle absent")
def test_cli_unsafe_flag_runs_rederivation_exit_0():
    """With the explicit opt-in, re-derivation actually runs and a clean bundle
    certifies: exit 0."""
    cp = _run_cli("--unsafe-run-bundle-pack")
    assert cp.returncode == 0, f"expected OK exit 0, got {cp.returncode}\n{cp.stdout}\n{cp.stderr}"
    assert "re_derivation_invocation" in cp.stdout
