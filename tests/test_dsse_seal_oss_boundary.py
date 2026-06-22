"""tests/test_dsse_seal_oss_boundary.py — DSSE WS-2: open seal path OSS boundary.

Asserts that the open seal path (emitter/pipeline + vkernel_key_loader +
dsse/envelope) does NOT import audit_bundle.emitter_premium — the closed
money-line tier must remain decoupled from the open seal substrate.

Two complementary checks:
1. Runtime: a FRESH interpreter imports the three open-seal modules and
   asserts ``emitter_premium`` is not present in ``sys.modules``. The
   subprocess is what makes the assertion meaningful in full-suite runs:
   earlier tests legitimately import emitter_premium into THIS process, so an
   in-process check would trip on pollution the seal modules didn't cause
   (and evicting the loaded module mid-suite would corrupt other tests'
   module identity). Same fresh-interpreter pattern as
   tests/test_stdlib_import_boundary.py.
2. Static (AST): none of the three module source files contain a static import
   of ``audit_bundle.emitter_premium``.
"""

from __future__ import annotations

import ast
import importlib.util
import subprocess
import sys
import textwrap
from pathlib import Path

_PREMIUM_MODULE = "audit_bundle.emitter_premium"
_PRODUCT_ROOT = Path(__file__).resolve().parents[1]

# The three modules that form the open seal path.
_SEAL_MODULES = [
    "audit_bundle.emitter.pipeline",
    "audit_bundle.vkernel_key_loader",
    "audit_bundle.dsse.envelope",
]


def _module_source_path(module_name: str) -> Path:
    """Return the source file path for an already-imported module."""
    spec = importlib.util.find_spec(module_name)
    assert spec is not None and spec.origin is not None, (
        f"Cannot find source for module {module_name!r}"
    )
    return Path(spec.origin)


def _static_imports_premium(path: Path) -> list[str]:
    """Return a list of AST-level import statements that import the premium namespace."""
    source = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        raise AssertionError(f"SyntaxError parsing {path}: {exc}") from exc

    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == _PREMIUM_MODULE or alias.name.startswith(
                    _PREMIUM_MODULE + "."
                ):
                    violations.append(f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module == _PREMIUM_MODULE or module.startswith(_PREMIUM_MODULE + "."):
                names = ", ".join(a.name for a in node.names)
                violations.append(f"from {module} import {names}")
    return violations


# ---------------------------------------------------------------------------
# Test 1: runtime — importing the open seal modules must not pull in premium.
# ---------------------------------------------------------------------------


def test_seal_modules_do_not_pull_in_premium_at_import_time() -> None:
    """A fresh interpreter importing the open seal path must not load premium.

    Runs in a subprocess: sys.modules in THIS process is already polluted by
    earlier tests that legitimately import emitter_premium, and evicting a
    loaded module mid-suite would corrupt other tests' module identity. Only
    an interpreter that has imported NOTHING but the seal path can attribute
    a resident emitter_premium to the seal modules themselves.
    """
    code = textwrap.dedent(
        f"""\
        import importlib
        import sys

        for mod_name in {_SEAL_MODULES!r}:
            importlib.import_module(mod_name)

        assert {_PREMIUM_MODULE!r} not in sys.modules, (
            "Importing the open seal path pulled in {_PREMIUM_MODULE} -- "
            "OSS boundary violated. Check for a top-level import of "
            "emitter_premium in one of: " + ", ".join({_SEAL_MODULES!r})
        )
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=str(_PRODUCT_ROOT),
    )
    assert result.returncode == 0, (
        "Open seal path pulled in emitter_premium in a fresh interpreter -- "
        f"OSS boundary violated.\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )


# ---------------------------------------------------------------------------
# Test 2: static — source files must not contain a premium import statement.
# ---------------------------------------------------------------------------


def test_seal_module_sources_contain_no_premium_import() -> None:
    """AST scan: none of the open seal module sources import emitter_premium."""
    for mod_name in _SEAL_MODULES:
        path = _module_source_path(mod_name)
        violations = _static_imports_premium(path)
        assert not violations, (
            f"Module {mod_name!r} ({path}) contains a static import of "
            f"{_PREMIUM_MODULE!r}: {violations}"
        )
