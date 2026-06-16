"""_build_bundle.py -- build a deterministic build_real_compiler_minimal audit bundle.

Synthesizes three small Python source modules, compiles them to .pyc using
py_compile with SOURCE_DATE_EPOCH=0 and PycInvalidationMode.CHECKED_HASH (PEP
552), and emits a standards-compliant manifest that pins interpreter identity
via sys.implementation.cache_tag.

The substrate claim this pilot establishes: V-Kernel re-derivation generalizes
to **actual deterministic compilation** -- the reproducible-builds.org shape --
where the re-derivation primitive is "re-compile the committed .py sources with
the pinned toolchain and assert the produced .pyc bytes match the bundled .pyc
bytes."  Toolchain identity is anchored by cache_tag (e.g. "cpython-314"),
which encodes interpreter family + major/minor version.  CHECKED_HASH mode
(PEP 552 flag byte 0x03) makes the 16-byte header source-content-addressed
rather than timestamp-addressed.

Determinism key: the dfile parameter of py_compile.compile() pins the
co_filename stored in the .pyc bytecode to just the base name (e.g.
"mod_a.py"), making it independent of the actual temp directory path.  Without
this pin, each compile embeds the random temp path, producing non-deterministic
.pyc bytes even with CHECKED_HASH mode.

Scope (honest): what is built, tested, and promoted is py_compile only — single
CPython, single cache_tag, fail-closed across that boundary. A native-toolchain
variant (e.g. subprocess.run(['gcc', '-c', '-o', out, src],
env={'SOURCE_DATE_EPOCH': '0'})) would be the same recompile-then-digest SHAPE,
but NONE of that is implemented here; do not read this pilot as covering native
compilation. This pilot uses py_compile because the v-kernel-pilot skill mandates
stdlib (no cross-platform toolchain dependency).

Usage (from v-kernel-audit-bundle root):
    python examples/build_real_compiler_minimal/_build_bundle.py --out-dir /tmp/build_real_compiler_bundle

Outputs:
  <out-dir>/sources/mod_a.py
  <out-dir>/sources/mod_b.py
  <out-dir>/sources/mod_c.py
  <out-dir>/recipe/build_recipe.json
  <out-dir>/payload/artifacts/mod_a.pyc
  <out-dir>/payload/artifacts/mod_b.pyc
  <out-dir>/payload/artifacts/mod_c.pyc
  <out-dir>/manifest.json

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import json
import os
import py_compile
import sys
import tempfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.emitter import BundleContent, write_bundle  # noqa: E402

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "build-real-compiler-minimal-rc"
_CREATED_AT = "2026-05-09T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
    "build_py_re_derivation",
]

# ---------------------------------------------------------------------------
# Synthetic source tree -- three deterministic Python modules
#
# Content is fixed ASCII-only and LF-terminated so the pilot is byte-stable
# across platforms (CRLF/LF surprises cannot drift the bundled .pyc bytes).
# In a real integration these would be committed repo source files.
# ---------------------------------------------------------------------------

_SOURCES: dict[str, bytes] = {
    "mod_a.py": b"# mod_a - deterministic constant module\nMOD_A_VALUE = 42\nMOD_A_NAME = 'alpha'\n",
    "mod_b.py": b"# mod_b - deterministic computation module\nMOD_B_BASE = 100\n\ndef add(x, y):\n    return x + y\n\nMOD_B_RESULT = add(MOD_B_BASE, 7)\n",
    "mod_c.py": b"# mod_c - deterministic class module\n\nclass Config:\n    version = '1.0'\n    debug = False\n\n    @classmethod\n    def default(cls):\n        return cls()\n",
}

_SOURCE_ORDER = ["mod_a.py", "mod_b.py", "mod_c.py"]


def _compile_source(source_bytes: bytes, source_name: str) -> bytes:
    """Compile source_bytes to .pyc using CHECKED_HASH mode and SOURCE_DATE_EPOCH=0.

    Returns the raw .pyc bytes.

    CHECKED_HASH (PEP 552 flag=0x03): the 16-byte .pyc header embeds a hash of
    the source bytes rather than the file's mtime, making the output independent
    of filesystem timestamp and purely a function of (source_bytes, dfile,
    cache_tag, optimize level).

    dfile pins the co_filename stored in the .pyc bytecode to just the base name
    (e.g. "mod_a.py"), making it independent of the actual temp directory path.
    This is the key determinism knob for the re-derivation verifier: both the
    build and the verify step pass the same dfile, so the .pyc bytes match.

    SOURCE_DATE_EPOCH=0 is set in the calling environment (see build()) -- it
    is the standard reproducible-builds.org environment variable.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = Path(tmpdir) / source_name
        src_path.write_bytes(source_bytes)
        out_path = Path(tmpdir) / (source_name + "c")
        py_compile.compile(
            str(src_path),
            cfile=str(out_path),
            dfile=source_name,  # pin co_filename to base name for determinism
            doraise=True,
            optimize=-1,
            invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH,
        )
        return out_path.read_bytes()


def build(out_dir: Path) -> None:
    # Pin SOURCE_DATE_EPOCH for the duration of the compilation, then restore it.
    # The var is process-global, so leaving it set leaks into any code that runs
    # later in the same interpreter (e.g. another pilot's in-place rebuild
    # re-stamping its committed manifests to 1970-01-01). Save/restore around the
    # whole build body keeps it live across every _compile_source call.
    _prev_sde = os.environ.get("SOURCE_DATE_EPOCH")
    os.environ["SOURCE_DATE_EPOCH"] = "0"
    try:
        sources_dir = out_dir / "sources"
        recipe_dir = out_dir / "recipe"
        artifacts_dir = out_dir / "payload" / "artifacts"
        sources_dir.mkdir(parents=True, exist_ok=True)
        recipe_dir.mkdir(parents=True, exist_ok=True)
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        # Capture toolchain identity at build time.
        cache_tag = sys.implementation.cache_tag

        # Build recipe -- pins interpreter identity and all determinism knobs.
        recipe: dict = {
            "schema": "build-recipe-py-v1",
            "interpreter": "cpython",
            "interpreter_minimum": "3.10",
            "cache_tag": cache_tag,
            "source_date_epoch": 0,
            "sources": _SOURCE_ORDER,
        }
        recipe_bytes = json.dumps(recipe, indent=2, sort_keys=True).encode("utf-8")

        # Compile each source to .pyc (bytes produced in-memory).
        pyc_bytes: dict[str, bytes] = {}
        for name in _SOURCE_ORDER:
            stem = name[:-3]  # strip .py
            pyc_name = stem + ".pyc"
            pyc_bytes[pyc_name] = _compile_source(_SOURCES[name], name)

        # ---- assemble the content file set + emit via the reference-emitter SDK ----
        files: dict[str, bytes] = {}
        for name in _SOURCE_ORDER:
            files[f"sources/{name}"] = _SOURCES[name]
        files["recipe/build_recipe.json"] = recipe_bytes
        for pyc_name, data in pyc_bytes.items():
            files[f"payload/artifacts/{pyc_name}"] = data

        content = BundleContent(
            bundle_id=_BUNDLE_ID,
            created_at=_CREATED_AT,
            schema_version=_SCHEMA_VERSION,
            files=files,
            typed_checks=_TYPED_CHECKS,
        )
        manifest = write_bundle(out_dir, content)
    finally:
        if _prev_sde is None:
            os.environ.pop("SOURCE_DATE_EPOCH", None)
        else:
            os.environ["SOURCE_DATE_EPOCH"] = _prev_sde

    total_pyc = sum(len(v) for v in pyc_bytes.values())
    print(f"Bundle written to {out_dir}")
    print("  interpreter       : cpython")
    print(f"  cache_tag         : {cache_tag}")
    print(f"  source files      : {len(_SOURCE_ORDER)}")
    print(f"  compiled .pyc     : {len(pyc_bytes)} files ({total_pyc} bytes total)")
    print(f"  manifest files    : {len(manifest['files'])}")
    print(f"  manifest          : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic build_real_compiler_minimal audit bundle"
    )
    parser.add_argument(
        "--out-dir",
        required=True,
        type=Path,
        help="Destination directory (created if absent)",
    )
    args = parser.parse_args()
    try:
        build(args.out_dir.resolve())
    except (AssertionError, py_compile.PyCompileError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
