"""BuildPyReDerivationCheck — TypedCheck plugin for deterministic Python compiler re-derivation.

Wraps build_py_re_derivation.py via subprocess, mirroring the re_derivation_invocation
pattern in audit_bundle/plugins/re_derivation_invocation.py.

The substrate claim: V-Kernel re-derivation extends to **actual deterministic
compilation** — re-compiling committed .py sources with py_compile under
SOURCE_DATE_EPOCH=0 + PycInvalidationMode.CHECKED_HASH yields byte-identical
.pyc output, anchored by the recipe's `cache_tag` (interpreter family + version).

the audit-bundle contract §C6 (domain-agnostic re-derivation substrate).
name='build_py_re_derivation'
Stdlib only (subprocess, sys, pathlib).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from audit_bundle.bundle_manifest import register_typed_check
from audit_bundle.plugin import PluginResult


class BuildPyReDerivationCheck:
    name: str = "build_py_re_derivation"
    applies_to_files: frozenset[str] = frozenset({
        "sources/",
        "recipe/build_recipe.json",
        "payload/artifacts/",
    })

    def check(self, bundle_dir: Path, manifest) -> PluginResult:
        pack_path = Path(__file__).parent / "build_py_re_derivation.py"

        if not pack_path.exists():
            return PluginResult(
                ok=True,
                reason_code="NO_PACK",
                detail=(
                    "build_py_re_derivation.py not found alongside BuildPyReDerivationCheck.py; "
                    "domain pilot opted out"
                ),
                files_audited=(),
            )

        recipe_path = bundle_dir / "recipe" / "build_recipe.json"
        sources_dir = bundle_dir / "sources"
        artifacts_dir = bundle_dir / "payload" / "artifacts"

        if not recipe_path.exists() or not sources_dir.is_dir() or not artifacts_dir.is_dir():
            return PluginResult(
                ok=True,
                reason_code="NO_PAYLOAD",
                detail=(
                    "recipe/build_recipe.json, sources/, or payload/artifacts/ absent — "
                    "no compiled artifacts to re-derive"
                ),
                files_audited=(),
            )

        try:
            result = subprocess.run(
                [sys.executable, str(pack_path), "--bundle-dir", str(bundle_dir)],
                capture_output=True,
                timeout=60,
            )
        except subprocess.TimeoutExpired:
            return PluginResult(
                ok=False,
                reason_code="BUILD_PY_REDERIVATION_TIMEOUT",
                detail="build_py_re_derivation.py exceeded 60 s timeout",
                files_audited=(str(recipe_path),),
            )

        if result.returncode == 0:
            return PluginResult(
                ok=True,
                reason_code="BUILD_PY_REDERIVED",
                detail=(
                    "build_py_re_derivation.py exited 0 — "
                    "all .pyc bytes match re-compiled output"
                ),
                files_audited=(str(recipe_path),),
            )

        stderr_snippet = (result.stderr or b"").decode("utf-8", errors="replace")[:512]

        # Classify the failure by inspecting the reason_code emitted by the pack.
        if "BUILD_PY_TOOLCHAIN_MISMATCH" in stderr_snippet:
            reason_code = "BUILD_PY_TOOLCHAIN_MISMATCH"
        else:
            reason_code = "BUILD_PY_REDERIVATION_MISMATCH"

        return PluginResult(
            ok=False,
            reason_code=reason_code,
            detail=stderr_snippet,
            files_audited=(str(recipe_path),),
        )


register_typed_check("build_py_re_derivation")
