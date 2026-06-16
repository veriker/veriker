"""tests/test_bundle_exec_gate_structural.py — structural lint: bundle-supplied exec must be gated.

Companion to tests/test_unsafe_pack_execution_gate.py. That test is BEHAVIORAL
and single-plugin: it proves ReDerivationInvocationCheck does not execute a
bundle pack by default. This test is STRUCTURAL and whole-tree: it enforces the
invariant that PREVENTS a *future* plugin from shipping the same arbitrary-code-
execution class ungated.

INVARIANT (the trust-origin rule, verified 2026-06-10 census):
    A plugin that runs a subprocess / exec / eval whose EXECUTED PROGRAM is
    derived from `bundle_dir` (i.e. bundle-supplied, therefore untrusted) MUST
    gate it behind a `permit_execution`-style explicit opt-in. A plugin whose
    executed program is `Path(__file__).parent`-relative (verifier-distribution
    code that merely READS bundle data via --bundle-dir) is exempt — that is the
    safe pattern and needs no gate.

This is exactly the asymmetric-hardening trap: the gate lives at
re_derivation_invocation.py (pack_path = bundle_dir/...) but the four reference
re-derivation plugins (pack_path = Path(__file__).parent/...) are correctly
ungated because they execute verifier code, not bundle bytes. The lint encodes
WHY that asymmetry is correct so a reviewer never has to re-derive it, and a new
bundle-rooted-exec plugin that forgets the gate fails CI.

The lint keys on the EXECUTED-PROGRAM position only (argv[1] after the
interpreter, or the exec/eval code arg), NOT on data flags — passing
str(bundle_dir) as --bundle-dir to a TRUSTED script is the safe pattern and must
not trip the lint.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

_PLUGINS_DIR = _PKG_ROOT / "audit_bundle" / "plugins"

_EXEC_CALLS = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
}
_GATE_MARKER = "permit_execution"  # the required opt-in keyword


def _dotted(node: ast.AST) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts)) if parts else None


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _refs(node: ast.AST, name: str) -> bool:
    return any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(node))


def _is_interpreter(node: ast.AST) -> bool:
    """sys.executable, or a "python"-ish string literal."""
    if isinstance(node, ast.Attribute) and node.attr == "executable":
        return True
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return "python" in node.value.lower()
    return False


def _exec_target_node(call: ast.Call) -> ast.AST | None:
    """The AST node for the EXECUTED PROGRAM of an exec-family call, or None."""
    fn = _dotted(call.func)
    if fn in _EXEC_CALLS:
        if not call.args:
            return None
        a0 = call.args[0]
        if isinstance(a0, ast.List) and a0.elts:
            elts = a0.elts
            idx = 1 if _is_interpreter(elts[0]) and len(elts) > 1 else 0
            return elts[idx]
        return a0  # shell-string program
    if fn in {"exec", "eval"} and call.args:
        return call.args[0]
    return None


def _func_assignments(func: ast.AST) -> dict[str, ast.AST]:
    """varname -> last-assigned RHS within a function (sufficient for these plugins)."""
    out: dict[str, ast.AST] = {}
    for n in ast.walk(func):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    out[t.id] = n.value
    return out


def find_ungated_bundle_exec(source: str) -> list[str]:
    """Return human-readable violations: bundle-rooted exec targets with no gate.

    A violation is an exec-family call whose executed-program node is derived
    from `bundle_dir` (directly, or via a same-function assignment) while the
    module never references the `permit_execution` gate marker.
    """
    tree = ast.parse(source)
    gated = _GATE_MARKER in {
        n.id for n in ast.walk(tree) if isinstance(n, ast.Name)
    } or _GATE_MARKER in {
        n.arg for n in ast.walk(tree) if isinstance(n, ast.arg) and n.arg
    }

    violations: list[str] = []
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        assigns = _func_assignments(func)
        for call in ast.walk(func):
            if not isinstance(call, ast.Call):
                continue
            target = _exec_target_node(call)
            if target is None:
                continue
            # bundle-rooted directly in the target expr (inline bundle_dir / "x.py")?
            untrusted = _refs(target, "bundle_dir")
            # ...or via a same-function assignment whose RHS roots in bundle_dir
            # and NOT in __file__ (the verifier-distribution exemption).
            if not untrusted:
                for name in _names_in(target):
                    rhs = assigns.get(name)
                    if (
                        rhs is not None
                        and _refs(rhs, "bundle_dir")
                        and not _refs(rhs, "__file__")
                    ):
                        untrusted = True
                        break
            if untrusted and not gated:
                violations.append(
                    f"{func.name}:{call.lineno} executes a bundle-rooted program "
                    f"without a {_GATE_MARKER} gate"
                )
    return violations


# ---------------------------------------------------------------------------
# The lint over the real plugin tree
# ---------------------------------------------------------------------------


def _plugin_sources() -> list[tuple[str, str]]:
    return [
        (p.relative_to(_PKG_ROOT).as_posix(), p.read_text(encoding="utf-8"))
        for p in sorted(_PLUGINS_DIR.rglob("*.py"))
        if p.name != "__init__.py"
    ]


def test_no_ungated_bundle_supplied_exec_in_plugins() -> None:
    offenders: dict[str, list[str]] = {}
    for rel, src in _plugin_sources():
        v = find_ungated_bundle_exec(src)
        if v:
            offenders[rel] = v
    assert not offenders, (
        "bundle-supplied code executed without a permit_execution gate:\n"
        + "\n".join(f"  {rel}: {'; '.join(v)}" for rel, v in offenders.items())
    )


# ---------------------------------------------------------------------------
# Teeth: the lint must catch the bad shape and exempt the good ones
# ---------------------------------------------------------------------------

_BAD_UNGATED = """
import subprocess, sys
from pathlib import Path
class BadCheck:
    def check(self, bundle_dir, manifest):
        pack_path = bundle_dir / "re_derive" / "pack.py"
        return subprocess.run([sys.executable, str(pack_path), "--bundle-dir", str(bundle_dir)])
"""

_GOOD_GATED = """
import subprocess, sys
from pathlib import Path
class GoodCheck:
    def __init__(self, *, permit_execution: bool):
        self.permit_execution = permit_execution
    def check(self, bundle_dir, manifest):
        pack_path = bundle_dir / "re_derive" / "pack.py"
        if not self.permit_execution:
            return "NOT_EXECUTED"
        return subprocess.run([sys.executable, str(pack_path), "--bundle-dir", str(bundle_dir)])
"""

_GOOD_VERIFIER_SHIPPED = """
import subprocess, sys
from pathlib import Path
class RefCheck:
    def check(self, bundle_dir, manifest):
        pack_path = Path(__file__).parent / "span_re_derivation.py"
        spans = bundle_dir / "payload" / "spans.json"
        return subprocess.run([sys.executable, str(pack_path), "--bundle-dir", str(bundle_dir)])
"""


def test_lint_flags_ungated_bundle_exec() -> None:
    assert find_ungated_bundle_exec(_BAD_UNGATED), (
        "lint missed an ungated bundle-rooted exec"
    )


def test_lint_exempts_gated_bundle_exec() -> None:
    assert not find_ungated_bundle_exec(_GOOD_GATED), (
        "lint false-flagged a gated plugin"
    )


def test_lint_exempts_verifier_shipped_exec() -> None:
    # __file__-rooted program that merely reads bundle data is the safe pattern.
    assert not find_ungated_bundle_exec(_GOOD_VERIFIER_SHIPPED), (
        "lint false-flagged a verifier-distribution re-derivation plugin"
    )
