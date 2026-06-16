"""build_real_compiler_recompute — verifier-side real-compiler build re-derivation.

Axis-2 value-return form of the build_real_compiler re-derivation, PROMOTED into
the shippable core registry (RECIPE_BOOK.md, shape `real-compiler build digest`).
The generic verifier recomputes the representative output on the SAFE spec-pinned
path: no subprocess, no bundle-supplied code — the recompile rule lives HERE in
verifier-distribution code and the comparator comes from the auditor-anchored spec.

Re-derivation primitive (one sentence):
    pyc_sha = sha256( py_compile(sources/mod_a.py, CHECKED_HASH,
                                 dfile="mod_a.py", SOURCE_DATE_EPOCH=0) ).hexdigest()

The representative re-derived output is the SHA-256 hex digest of the recompiled
.pyc bytes for ONE representative source module (mod_a.py -> mod_a.pyc). The
compilation rule is FIXED in this primitive and exactly mirrors the legacy pack
(build_py_re_derivation.py) and the legacy builder (_build_bundle.py): py_compile
with PycInvalidationMode.CHECKED_HASH, optimize=-1, dfile pinned to the base name,
and SOURCE_DATE_EPOCH=0. The primitive_id ("build_real_compiler_recompute") IS
the rule. The auditor's SHA-pinned spec binds the output type "pyc_sha" to this
primitive_id and to an `exact` comparator (byte-exact hex-string equality); a
producer cannot weaken the compilation knobs or the comparison without changing
the primitive_id / spec SHA, which the anchor rejects.

Toolchain guard (replicates the legacy pack, fail-closed): before recompiling,
the primitive reads recipe/build_recipe.json and asserts
recipe.cache_tag == sys.implementation.cache_tag. A mismatch means the verifier
is running a different CPython family/major.minor than the one that produced the
bundled .pyc; .pyc bytes are not re-derivable across that boundary, so the
primitive RAISES (fail-closed) rather than silently producing a value that can
never match.

Faithfulness (verifier-side reimplementation — Gate B):
  - The recompile mirrors the producer pack's _compile_to_pyc EXACTLY: same
    CHECKED_HASH invalidation, same dfile pin, same optimize=-1, same
    SOURCE_DATE_EPOCH=0 pin. The promoted test (test_recipe_build_real_compiler_
    promoted.py) derives the honest claim from the producer's OWN emitted
    payload/artifacts/mod_a.pyc bytes — NOT from this module — so an honest PASS
    proves the verifier recompile reproduces the producer's bundled .pyc within
    one CPython/cache_tag and catches edit-drift between the two recompile copies.
  - Cross-CPython .pyc stability is not claimed; the cache_tag guard fails closed
    across that boundary instead.

pyc_sha is chosen as the representative value because it is a deterministic,
key-free recompute (re-compile committed sources + SHA-256 over the produced
bytes). The producer key / HMAC is NOT used here: the re-derivation needs only
the committed source bytes + recipe + the pinned interpreter.

Stdlib-only (§C5 core verify() path): py_compile / hashlib / importlib are stdlib.
"""

from __future__ import annotations

import hashlib
import os
import py_compile
import sys
import tempfile
from pathlib import Path

from ...admission import admit_json_file
from ...plugin import ParsedInputs, RecomputedValue
from ..registry import register_primitive

# The ONE representative source module the pilot re-derives. mod_a.py compiles to
# mod_a.pyc; the representative output is sha256(mod_a.pyc bytes).
REPR_SOURCE_NAME = "mod_a.py"


# ---------------------------------------------------------------------------
# Canonical compilation (shared by builder and verifier -- ONE source of truth)
# ---------------------------------------------------------------------------


def _compile_to_pyc(source_bytes: bytes, source_name: str) -> bytes:
    """Compile source_bytes to .pyc bytes EXACTLY as the legacy pilot does.

    CHECKED_HASH (PEP 552 flag=0x03): the 16-byte header embeds a hash of the
    source content, not the mtime -- output is a pure function of
    (source_bytes, dfile, cache_tag, optimize). dfile pins co_filename to the
    base name so the temp dir layout does not leak into the bytes. The caller
    pins SOURCE_DATE_EPOCH=0 before invoking this (see compute_pyc_sha).
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


def compute_pyc_sha(source_bytes: bytes, source_name: str) -> str:
    """Canonical representative output: SHA-256 hex of the recompiled .pyc bytes.

    Pins SOURCE_DATE_EPOCH=0 (reproducible-builds.org anchor) for the compile,
    mirroring the legacy builder/pack, then hashes the produced .pyc bytes.
    Builder and verifier share this ONE definition so the honest claimed sha and
    the re-derivation cannot drift.

    The pin is save/restored: SOURCE_DATE_EPOCH is process-global, so leaving it
    set leaks into any code that runs later in the same interpreter. The var is
    live only across _compile_to_pyc, then restored to its prior value (or unset).
    """
    _prev = os.environ.get("SOURCE_DATE_EPOCH")
    os.environ["SOURCE_DATE_EPOCH"] = "0"
    try:
        pyc_bytes = _compile_to_pyc(source_bytes, source_name)
        return hashlib.sha256(pyc_bytes).hexdigest()
    finally:
        if _prev is None:
            os.environ.pop("SOURCE_DATE_EPOCH", None)
        else:
            os.environ["SOURCE_DATE_EPOCH"] = _prev


class _ToolchainMismatch(RuntimeError):
    """Raised (fail-closed) when recipe.cache_tag != runtime cache_tag."""


def compute_repr_pyc_sha_from_bundle(bundle_dir: Path) -> str:
    """Re-derive the representative pyc_sha from a bundle on disk.

    Replicates the legacy pack's guard order: first assert the recipe schema and
    that recipe.cache_tag matches the runtime interpreter (fail-closed raise on
    mismatch), then recompile the representative source and SHA-256 the bytes.
    """
    recipe_path = bundle_dir / "recipe" / "build_recipe.json"
    if not recipe_path.is_file():
        raise FileNotFoundError(
            f"recipe/build_recipe.json not found in bundle at {bundle_dir}"
        )
    recipe = admit_json_file(recipe_path)

    schema = recipe.get("schema")
    if schema != "build-recipe-py-v1":
        raise ValueError(
            f"unsupported recipe.schema={schema!r}; expected 'build-recipe-py-v1'"
        )

    # Toolchain guard FIRST (fail-closed) -- exactly as the legacy pack.
    recipe_cache_tag = recipe.get("cache_tag", "")
    runtime_cache_tag = sys.implementation.cache_tag
    if recipe_cache_tag != runtime_cache_tag:
        raise _ToolchainMismatch(
            f"BUILD_PY_TOOLCHAIN_MISMATCH: recipe.cache_tag={recipe_cache_tag!r} "
            f"!= runtime sys.implementation.cache_tag={runtime_cache_tag!r}"
        )

    src_path = bundle_dir / "sources" / REPR_SOURCE_NAME
    if not src_path.is_file():
        raise FileNotFoundError(
            f"representative source {REPR_SOURCE_NAME!r} absent from sources/ in {bundle_dir}"
        )
    source_bytes = src_path.read_bytes()
    return compute_pyc_sha(source_bytes, REPR_SOURCE_NAME)


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered at import for the core registry)
# ---------------------------------------------------------------------------


class BuildRealCompilerRecompute:
    """Verifier-side primitive for re-deriving the representative .pyc SHA-256."""

    primitive_id: str = "build_real_compiler_recompute"

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        """Recompute the representative pyc_sha from the bundle.

        Guards on the recipe toolchain (cache_tag) first -- raises (fail-closed)
        on mismatch -- then recompiles sources/mod_a.py and returns the .pyc
        SHA-256 hex string. Returns the recomputed VALUE only; the
        auditor-anchored `exact` comparator decides agreement.
        """
        bundle_dir: Path = inputs.bundle_dir
        value = compute_repr_pyc_sha_from_bundle(bundle_dir)
        return RecomputedValue(
            value=value,
            detail=(
                f"re-derived sha256 of recompiled {REPR_SOURCE_NAME[:-3]}.pyc "
                f"(CHECKED_HASH, SOURCE_DATE_EPOCH=0, cache_tag-guarded)"
            ),
        )


register_primitive(BuildRealCompilerRecompute())
