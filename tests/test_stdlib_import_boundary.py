"""tests/test_stdlib_import_boundary.py — the stdlib-only claim gets a ratchet.

Why this exists
---------------
"Stdlib-only" is a load-bearing claim of the offline verifier surface (README,
SECURITY.md, the in-code _DSSE_SUBSTRATE_VERIFIER_HINT): an auditor must be
able to run veriker/cli/verify.py on a bare Python with NO third-party packages and
get an honest verdict. Until now that claim was true but UNENFORCED — the only
probe was test_dsse_cutover_classifier.test_bundle_manifest_stdlib_pure, which
checks one module against two named packages. A single careless top-level
import (cryptography, jcs, tuf, z3, ...) anywhere on the core path would
silently break the claim while every other test stayed green, because dev/CI
environments HAVE those packages installed.

This file generalizes the probe into a boundary: every subprocess here runs
under a sys.meta_path blocker that raises ImportError for ANY module that is
neither stdlib nor first-party (audit_bundle / the CLI scripts themselves).
That simulates the bare-Python auditor environment exactly.

Two guarantee classes are locked:

  A. IMPORT CLEANLINESS — the core library path (audit_bundle.verifier,
     audit_bundle.verdict, audit_bundle.bundle_manifest, audit_bundle.admission)
     and the veriker/cli/verify.py module BOTH import successfully with third-party
     imports blocked. Dependency-bearing code (Ed25519, COSE, TUF, Z3) must
     stay behind function-local deferred imports — a new TOP-LEVEL third-party
     import on this path fails here with the offending module named.

  B. DEPS-ABSENT HONESTY — with third-party imports blocked, advanced evidence
     must fail CLOSED, never silently upgrade (ADR D8; the CLI-vs-library
     divergence campaign invariant: present-but-unverified -> exit 2, never
     exit 0 + prose):
       * clean structural bundle        -> exit 0 (control: the boundary does
                                          not blanket-fail every bundle)
       * DSSE-sealed (post-cutover)     -> non-zero +
                                          DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO
       * extension receipt, no handler  -> exit 2 +
                                          EXTENSION_RECEIPT_NOT_EVALUATED
       * re-derivation pack, not run    -> exit 2 +
                                          RE_DERIVATION_NOT_EXECUTED

The blocker self-test (test_blocker_actually_blocks) keeps the harness honest:
if the meta-path hook ever stops firing, that test goes red rather than the
whole file passing vacuously.

Stdlib only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import textwrap
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[1]

# First-party top-level names permitted on the stdlib-only path. Anything
# else that is not stdlib is blocked. Keep this list SHORT and first-party
# only — adding a third-party name here is the ratchet turning backward and
# needs the same scrutiny as a new runtime dependency.
_FIRST_PARTY_ALLOWLIST = ("audit_bundle",)

# Installed FIRST on sys.meta_path inside every subprocess, before any
# package import runs. MetaPathFinder.find_spec raising ImportError aborts
# the import outright — deferred (function-local) third-party imports on
# untaken branches stay invisible, which is exactly the boundary we want:
# top-level = forbidden, deferred = the documented escape hatch.
_BLOCKER_PRELUDE = textwrap.dedent(
    f"""\
    import sys

    _ALLOWED_FIRST_PARTY = {_FIRST_PARTY_ALLOWLIST!r}

    class _ThirdPartyBlocker:
        def find_spec(self, fullname, path=None, target=None):
            top = fullname.split(".")[0]
            if top in sys.stdlib_module_names:
                return None
            if top in _ALLOWED_FIRST_PARTY:
                return None
            raise ImportError(
                "IMPORT-BOUNDARY VIOLATION: %r is neither stdlib nor "
                "first-party; the stdlib-only verifier path must not import "
                "it at module load. Defer it behind a function-local import "
                "on the substrate (dependency-bearing) path instead." % fullname
            )

    sys.meta_path.insert(0, _ThirdPartyBlocker())
    """
)


def _run_blocked(code: str) -> subprocess.CompletedProcess:
    """Run `code` in a fresh interpreter with the third-party blocker installed."""
    return subprocess.run(
        [sys.executable, "-c", _BLOCKER_PRELUDE + code],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
    )


def _run_cli_blocked(bundle_dir: Path, *extra_args: str) -> subprocess.CompletedProcess:
    """Run veriker/cli/verify.py end-to-end under the blocker; real process exit code."""
    argv = ["veriker/cli/verify.py", "--bundle-dir", str(bundle_dir), *extra_args]
    code = textwrap.dedent(
        f"""\
        import runpy
        sys.argv = {argv!r}
        runpy.run_path({str(_PKG_ROOT / "veriker" / "cli" / "verify.py")!r}, run_name="__main__")
        """
    )
    return _run_blocked(code)


def _b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _write_bundle(
    tmp_path: Path,
    *,
    extension_receipts: dict | None = None,
    rederive_pack: bool = False,
    dsse_sealed: bool = False,
) -> Path:
    """Minimal integrity-clean bundle, optionally carrying ONE advanced-evidence
    type (same fixture shape as test_extension_receipt_exit_code._write_bundle)."""
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    corpus_dir = bundle_dir / "corpus"
    corpus_dir.mkdir()
    content = b"synthetic corpus entry for stdlib import-boundary test"
    (corpus_dir / "entry0.txt").write_bytes(content)
    files = {"corpus/entry0.txt": hashlib.sha256(content).hexdigest()}

    if rederive_pack:
        pack_dir = bundle_dir / "re_derive"
        pack_dir.mkdir()
        pack_src = b"# synthetic re-derivation pack; must NOT be executed\n"
        (pack_dir / "synthetic_pack.py").write_bytes(pack_src)
        files["re_derive/synthetic_pack.py"] = hashlib.sha256(pack_src).hexdigest()

    manifest = {
        "schema_version": "legacy",
        "bundle_id": "stdlib-import-boundary-test",
        "created_at": "2026-01-01T00:00:00Z",
        "files": files,
        "spec_files": {},
        "cross_refs": {},
        "payload": {},
        "typed_checks": [],
        "per_output_manifests": [],
    }
    if extension_receipts is not None:
        manifest["extension_receipts"] = extension_receipts
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    if dsse_sealed:
        # Post-cutover sidecar shape: enough for the D4-safe cutover sniff
        # (payload.schema_version membership test). No real signature — the
        # point is that the stdlib path must fail closed WITHOUT checking one.
        payload = _b64url_nopad(
            json.dumps({"schema_version": "vcp-v1.2-dsse"}).encode("utf-8")
        )
        sidecar = {
            "payloadType": "application/vnd.vkernel.bundle+json",
            "payload": payload,
            "signatures": [{"keyid": "synthetic", "sig": _b64url_nopad(b"\x00" * 64)}],
        }
        (bundle_dir / "bundle.dsse.json").write_text(
            json.dumps(sidecar), encoding="utf-8"
        )
    return bundle_dir


# ---------------------------------------------------------------------------
# Harness self-test
# ---------------------------------------------------------------------------


def test_blocker_actually_blocks() -> None:
    """The meta-path hook must fire — otherwise every test below is vacuous."""
    result = _run_blocked("import cryptography\n")
    assert result.returncode != 0, (
        "Blocker failed to block 'import cryptography' — the boundary harness "
        f"is broken; every other test in this file is vacuous.\n{result.stdout}"
    )
    assert "IMPORT-BOUNDARY VIOLATION" in result.stderr, result.stderr


# ---------------------------------------------------------------------------
# A. Import cleanliness
# ---------------------------------------------------------------------------


def test_core_library_imports_stdlib_clean() -> None:
    """The core library path imports with all third-party modules blocked."""
    result = _run_blocked(
        textwrap.dedent(
            """\
            import audit_bundle.verifier
            import audit_bundle.verdict
            import audit_bundle.bundle_manifest
            import audit_bundle.admission
            # Exercise a construction, not just the import:
            v = audit_bundle.verdict.Verdict.reject("BOUNDARY_PROBE")
            assert v.state is audit_bundle.verdict.VerdictState.REJECT
            """
        )
    )
    assert result.returncode == 0, (
        "Core library path pulled a third-party module at import time — the "
        "stdlib-only claim is broken. Move the import behind a function-local "
        f"deferred import.\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )


def test_cli_verify_module_loads_stdlib_clean() -> None:
    """veriker/cli/verify.py (the offline tool) loads with third-party imports blocked."""
    result = _run_blocked(
        textwrap.dedent(
            f"""\
            import importlib.util
            spec = importlib.util.spec_from_file_location(
                "cli_verify_under_blocker",
                {str(_PKG_ROOT / "veriker" / "cli" / "verify.py")!r},
            )
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            """
        )
    )
    assert result.returncode == 0, (
        "veriker/cli/verify.py pulled a third-party module at load time — the offline "
        "stdlib-only tool claim is broken.\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )


# ---------------------------------------------------------------------------
# B. Deps-absent honesty (fail closed, never silently upgrade)
# ---------------------------------------------------------------------------


def test_clean_bundle_verifies_green_deps_absent(tmp_path: Path) -> None:
    """Control: a clean structural bundle still verifies at exit 0 with deps
    blocked — the boundary does not blanket-fail every bundle."""
    bundle_dir = _write_bundle(tmp_path)
    result = _run_cli_blocked(bundle_dir)
    assert result.returncode == 0, (
        f"Clean bundle should verify green in a deps-absent environment; got "
        f"{result.returncode}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )


def test_dsse_sealed_bundle_fails_closed_deps_absent(tmp_path: Path) -> None:
    """A post-cutover DSSE-sealed bundle must NOT verify green when no crypto
    is importable: signature unchecked -> fail closed with the named code."""
    bundle_dir = _write_bundle(tmp_path, dsse_sealed=True)
    result = _run_cli_blocked(bundle_dir)
    combined = result.stdout + result.stderr
    assert result.returncode != 0, (
        f"DSSE-sealed bundle rode a green exit code with crypto absent.\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    assert "DSSE_SIGNATURE_UNCHECKED_NO_CRYPTO" in combined, combined


def test_extension_receipt_fails_closed_deps_absent(tmp_path: Path) -> None:
    """Present-but-unverified extension receipt -> exit 2, also in the
    deps-absent environment (the receipt gate itself is stdlib, but it must
    keep firing when the blocker is up)."""
    bundle_dir = _write_bundle(
        tmp_path,
        extension_receipts={"some_unregistered_kind": {"opaque": "assembly"}},
    )
    result = _run_cli_blocked(bundle_dir)
    combined = result.stdout + result.stderr
    assert result.returncode == 2, (
        f"Expected exit 2 (could-not-conclude); got {result.returncode}\n"
        f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    assert "EXTENSION_RECEIPT_NOT_EVALUATED" in combined, combined


def test_rederivation_pack_not_run_deps_absent(tmp_path: Path) -> None:
    """A bundle-supplied re-derivation pack is NOT executed by default and must
    not ride a green exit code — also with deps blocked."""
    bundle_dir = _write_bundle(tmp_path, rederive_pack=True)
    result = _run_cli_blocked(bundle_dir)
    combined = result.stdout + result.stderr
    assert result.returncode == 2, (
        f"Expected exit 2 (claimed-but-NOT-RUN re-derivation); got "
        f"{result.returncode}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    assert "RE_DERIVATION_NOT_EXECUTED" in combined, combined
