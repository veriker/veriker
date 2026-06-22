"""tests/test_recipe_producer_verifier_disjoint.py — STRUCTURAL guard for the
recipe-book Gate B (producer↔verifier non-tautology).

Every promoted re-derivation recipe ships a `test_recipe_<shape>_promoted.py` that
proves the verifier's recompute agrees with the producer's INDEPENDENTLY-emitted
artifact (not f(x)==f(x)). That non-tautology rests on a structural property that
the per-recipe tests cannot themselves observe: the producer build script
(`examples/<pilot>/_build_bundle.py`) must compute its emitted artifact WITHOUT
importing the verifier's recompute path — neither the core primitives
(`audit_bundle.rederivation.primitives.*`) nor the pilot's re-export shim
(`<shape>_recompute`, which now re-exports the core class).

If a future edit wired a promoted pilot's producer to import the core `compute_*`
(e.g. "to avoid duplicating the algorithm"), the producer artifact would become
the verifier's own output, every promoted test would silently degrade to
f(x)==f(x) while still passing GREEN, and the drift-detection capability the
recipe-book advertises would be hollow. This guard fails closed on exactly that
regression.

Scope: the PROMOTED recipes only (auto-discovered from tests/test_recipe_*_promoted.py).
Non-promoted pilots may legitimately share a demo-local recompute helper between
their producer and their own verify path — they do not claim the core-registry
promotion property, so they are out of scope here.

Mechanism: static AST import analysis (no execution). For each promoted pilot we
read `_PILOT_DIR` / `_BUILD_SCRIPT` from its promoted test, identify the pilot's
re-export shim module stems (the `*_recompute.py` files whose source imports the
core primitives package), then assert the producer's `_build_bundle.py` imports
neither the core primitives package nor any shim stem.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[1]
_TESTS_DIR = _PKG_ROOT / "tests"
_EXAMPLES_DIR = _PKG_ROOT / "examples"

_CORE_PRIMITIVES_PKG = "audit_bundle.rederivation.primitives"
_PILOT_DIR_RE = re.compile(
    r'_PILOT_DIR\s*=\s*_PKG_ROOT\s*/\s*"examples"\s*/\s*"([^"]+)"'
)


def _promoted_pilot_dirs() -> list[tuple[str, Path]]:
    """Auto-discover (test_name, pilot_dir) for every promoted recipe."""
    out: list[tuple[str, Path]] = []
    for test_path in sorted(_TESTS_DIR.glob("test_recipe_*_promoted.py")):
        m = _PILOT_DIR_RE.search(test_path.read_text(encoding="utf-8"))
        assert m, (
            f"{test_path.name} has no recognizable _PILOT_DIR assignment; the "
            f"disjointness guard cannot locate its producer build script"
        )
        pilot_dir = _EXAMPLES_DIR / m.group(1)
        assert pilot_dir.is_dir(), (
            f"{test_path.name} points at missing pilot {pilot_dir}"
        )
        out.append((test_path.name, pilot_dir))
    return out


def _shim_module_stems(pilot_dir: Path) -> set[str]:
    """Module stems in pilot_dir that re-export the core primitives (shims)."""
    stems: set[str] = set()
    for py in pilot_dir.glob("*_recompute.py"):
        if _CORE_PRIMITIVES_PKG in py.read_text(encoding="utf-8"):
            stems.add(py.stem)
    return stems


def _imported_module_paths(py_path: Path) -> set[str]:
    """All module paths a file imports (dotted for `from x.y import z`, bare for
    `import a` / `from a import b`)."""
    tree = ast.parse(py_path.read_text(encoding="utf-8"), filename=str(py_path))
    paths: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                paths.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            # level>0 (relative) has no module name we care about; absolute only.
            if node.module and node.level == 0:
                paths.add(node.module)
    return paths


def test_promoted_recipes_have_tests():
    """Sanity: the guard found promoted recipes to protect (else it's vacuous)."""
    pilots = _promoted_pilot_dirs()
    assert len(pilots) >= 10, (
        f"expected the full promoted set, found only {len(pilots)} "
        f"test_recipe_*_promoted.py — guard may be silently scoped to nothing"
    )


def test_promoted_producers_do_not_import_verifier_recompute():
    """The load-bearing guard: no promoted producer imports the core primitives
    or its pilot's re-export shim."""
    violations: list[str] = []
    for test_name, pilot_dir in _promoted_pilot_dirs():
        build_script = pilot_dir / "_build_bundle.py"
        if not build_script.is_file():
            # Some pilots build via a differently-named producer; the promoted
            # test names the real one in _BUILD_SCRIPT. Fall back to that.
            test_src = (_TESTS_DIR / test_name).read_text(encoding="utf-8")
            bm = re.search(r'_BUILD_SCRIPT\s*=\s*_PILOT_DIR\s*/\s*"([^"]+)"', test_src)
            assert bm, (
                f"{test_name}: no _build_bundle.py and no _BUILD_SCRIPT to fall back to"
            )
            build_script = pilot_dir / bm.group(1)
        assert build_script.is_file(), f"{test_name}: producer {build_script} missing"

        imported = _imported_module_paths(build_script)
        shim_stems = _shim_module_stems(pilot_dir)

        core_hits = {
            p
            for p in imported
            if p == _CORE_PRIMITIVES_PKG or p.startswith(_CORE_PRIMITIVES_PKG + ".")
        }
        shim_hits = imported & shim_stems

        if core_hits:
            violations.append(
                f"{pilot_dir.name}/_build_bundle.py imports the CORE primitives "
                f"{sorted(core_hits)} — producer artifact would equal the verifier's "
                f"recompute, making {test_name} a tautology"
            )
        if shim_hits:
            violations.append(
                f"{pilot_dir.name}/_build_bundle.py imports the re-export shim "
                f"{sorted(shim_hits)} (which re-exports the core primitive) — same "
                f"tautology risk for {test_name}"
            )

    assert not violations, "producer↔verifier disjointness broken:\n  " + "\n  ".join(
        violations
    )
