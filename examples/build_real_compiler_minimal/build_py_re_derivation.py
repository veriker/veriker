#!/usr/bin/env python3
"""build_py_re_derivation.py -- stdlib re-derivation pack for the Python compiler domain.

Re-compiles each committed .py source file using py_compile with the pinned
toolchain (cache_tag) and SOURCE_DATE_EPOCH=0, then asserts that the produced
.pyc bytes equal the bundled .pyc bytes.

the internal design notes S6 (re-derivation pack -- domain-agnostic substrate).
AB4: stdlib only, no imports from audit_bundle.

Reads:
  recipe/build_recipe.json              -- pinned recipe (interpreter, cache_tag, sources)
  sources/<name>.py                     -- committed Python source files
  payload/artifacts/<name>.pyc          -- bundled .pyc bytes to match against

Re-derivation procedure:
  1. Parse recipe/build_recipe.json; verify schema == "build-recipe-py-v1".
  2. Check that recipe.cache_tag matches sys.implementation.cache_tag.
     If not: exit 1 with [BUILD_PY_REDER_FAIL] BUILD_PY_TOOLCHAIN_MISMATCH on stderr.
  3. Set os.environ["SOURCE_DATE_EPOCH"] = "0".
  4. For each source name in recipe.sources (in order):
       a. Read sources/<name> bytes.
       b. Write bytes to a temp file with the base name as filename; compile to
          temp .pyc using py_compile.compile(..., dfile=source_name, optimize=-1,
                             invalidation_mode=PycInvalidationMode.CHECKED_HASH).
       c. Read the fresh .pyc bytes; compare against payload/artifacts/<stem>.pyc.
       d. On first mismatch: exit 1 with [BUILD_PY_REDER_FAIL] BUILD_PY_REDERIVATION_MISMATCH.
  5. Exit 0 if all sources re-derive to matching .pyc bytes.

Why CHECKED_HASH (PEP 552) + SOURCE_DATE_EPOCH=0?
  * TIMESTAMP mode (default): the header encodes the source file's mtime.
    mtime varies between the build machine and verifier -- not re-derivable.
  * CHECKED_HASH mode (flag=0x03): the header encodes a hash of the source
    content instead of the mtime.  The output is purely a function of
    (source_bytes, dfile, cache_tag, optimize_level) -- fully re-derivable.
  * SOURCE_DATE_EPOCH=0 is the standard reproducible-builds.org environment
    variable; CPython respects it as the epoch anchor for timestamp fields.

dfile as the determinism anchor:
  py_compile embeds the source file path as co_filename in the .pyc bytecode.
  If we write to a random temp path, that path becomes part of the output,
  breaking determinism.  Passing dfile=source_name (e.g. "mod_a.py") pins
  co_filename to just the base name, so both build and verify produce
  identical .pyc bytes regardless of temp directory layout.

gcc-equivalent note: the same pattern works for native code via
  subprocess.run(['gcc', '-c', '-o', out, src], env={'SOURCE_DATE_EPOCH': '0'}).
This pack uses py_compile only because the v-kernel-pilot skill mandates stdlib.

Exits 0 on full match; 1 on first mismatch with a [BUILD_PY_REDER_FAIL] line on stderr.

Usage:
    python build_py_re_derivation.py --bundle-dir /path/to/bundle
"""

from __future__ import annotations

import argparse
import json
import os
import py_compile
import sys
import tempfile
from pathlib import Path


# ---------------------------------------------------------------------------
# Compilation helper
# ---------------------------------------------------------------------------


def _compile_to_pyc(source_bytes: bytes, source_name: str) -> bytes:
    """Compile source_bytes to .pyc bytes using CHECKED_HASH mode.

    Uses a temp directory with the base source_name as the filename so that
    dfile can pin co_filename independently of temp dir layout.
    Cleans up both files unconditionally via TemporaryDirectory context.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = Path(tmpdir) / source_name
        src_path.write_bytes(source_bytes)
        out_path = Path(tmpdir) / (source_name + "c")
        py_compile.compile(
            str(src_path),
            cfile=str(out_path),
            dfile=source_name,   # pin co_filename to base name for determinism
            doraise=True,
            optimize=-1,
            invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH,
        )
        return out_path.read_bytes()


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _verify(bundle_dir: Path) -> tuple[str | None, str | None]:
    """Return (error_description, reason_code) on failure, or (None, None) on success."""
    recipe_path = bundle_dir / "recipe" / "build_recipe.json"
    sources_dir = bundle_dir / "sources"
    artifacts_dir = bundle_dir / "payload" / "artifacts"

    if not recipe_path.exists():
        return (
            f"recipe/build_recipe.json absent from bundle_dir {bundle_dir}",
            "BUILD_PY_REDERIVATION_MISMATCH",
        )
    if not sources_dir.is_dir():
        return (
            f"sources/ directory absent from bundle_dir {bundle_dir}",
            "BUILD_PY_REDERIVATION_MISMATCH",
        )
    if not artifacts_dir.is_dir():
        return (
            f"payload/artifacts/ directory absent from bundle_dir {bundle_dir}",
            "BUILD_PY_REDERIVATION_MISMATCH",
        )

    try:
        recipe: dict = json.loads(recipe_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return f"failed to read recipe/build_recipe.json: {exc}", "BUILD_PY_REDERIVATION_MISMATCH"

    schema = recipe.get("schema")
    if schema != "build-recipe-py-v1":
        return (
            f"unsupported recipe.schema={schema!r}; expected 'build-recipe-py-v1'",
            "BUILD_PY_REDERIVATION_MISMATCH",
        )

    # Toolchain match: verifier must run the same CPython family + major/minor
    recipe_cache_tag = recipe.get("cache_tag", "")
    runtime_cache_tag = sys.implementation.cache_tag
    if recipe_cache_tag != runtime_cache_tag:
        return (
            f"BUILD_PY_TOOLCHAIN_MISMATCH: "
            f"recipe.cache_tag={recipe_cache_tag!r} "
            f"!= runtime sys.implementation.cache_tag={runtime_cache_tag!r}",
            "BUILD_PY_TOOLCHAIN_MISMATCH",
        )

    # Pin SOURCE_DATE_EPOCH before any compilation. The var is process-global, so
    # save/restore around the whole compile loop: leaving it set leaks into any
    # code that runs later in the same interpreter (e.g. another pilot's in-place
    # rebuild re-stamping its committed manifests to 1970-01-01). The finally must
    # span every return below so the pin stays live through the last
    # _compile_to_pyc call.
    _prev_sde = os.environ.get("SOURCE_DATE_EPOCH")
    os.environ["SOURCE_DATE_EPOCH"] = str(recipe.get("source_date_epoch", 0))
    try:
        sources_list = recipe.get("sources")
        if not isinstance(sources_list, list) or not sources_list:
            return "recipe.sources missing or empty", "BUILD_PY_REDERIVATION_MISMATCH"

        for source_name in sources_list:
            src_path = sources_dir / source_name
            if not src_path.exists():
                return (
                    f"source file {source_name!r} absent from sources/",
                    "BUILD_PY_REDERIVATION_MISMATCH",
                )

            stem = Path(source_name).stem
            pyc_name = stem + ".pyc"
            bundled_pyc_path = artifacts_dir / pyc_name
            if not bundled_pyc_path.exists():
                return (
                    f"bundled .pyc {pyc_name!r} absent from payload/artifacts/",
                    "BUILD_PY_REDERIVATION_MISMATCH",
                )

            source_bytes = src_path.read_bytes()

            try:
                fresh_pyc = _compile_to_pyc(source_bytes, source_name)
            except py_compile.PyCompileError as exc:
                return (
                    f"py_compile failed for {source_name!r}: {exc}",
                    "BUILD_PY_REDERIVATION_MISMATCH",
                )

            bundled_pyc = bundled_pyc_path.read_bytes()
            if fresh_pyc != bundled_pyc:
                # Find the first differing offset for diagnostic detail
                n = min(len(fresh_pyc), len(bundled_pyc))
                first_diff = n
                for i in range(n):
                    if fresh_pyc[i] != bundled_pyc[i]:
                        first_diff = i
                        break
                return (
                    f"BUILD_PY_REDERIVATION_MISMATCH for {source_name!r}: "
                    f"re-derived={len(fresh_pyc)} bytes, "
                    f"bundled={len(bundled_pyc)} bytes, "
                    f"first-diff-offset={first_diff}",
                    "BUILD_PY_REDERIVATION_MISMATCH",
                )

        return None, None
    finally:
        if _prev_sde is None:
            os.environ.pop("SOURCE_DATE_EPOCH", None)
        else:
            os.environ["SOURCE_DATE_EPOCH"] = _prev_sde


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Python py_compile re-derivation check for compiler audit bundles"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    error, reason_code = _verify(bundle_dir)
    if error is None:
        return 0

    print(f"[BUILD_PY_REDER_FAIL] {reason_code}: {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
