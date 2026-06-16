"""build_real_compiler_recompute.py — re-export shim for the PROMOTED primitive.

The build_real_compiler re-derivation primitive has been promoted into the
shippable core registry: audit_bundle/rederivation/primitives/build_real_compiler.py
(RECIPE_BOOK.md, shape `real-compiler build digest`). The recompile rule now
lives in verifier-DISTRIBUTION code and the generic verifier carries it — a third
party running the generic verifier against a build_real_compiler bundle recomputes
on the SAFE spec-pinned path with no demo-local code.

This module is kept as a thin re-export so the existing per-dir call sites
(spec_pinned_check.py, tests/test_build_real_compiler_spec_pinned.py) import the
SAME `compute_repr_pyc_sha_from_bundle` / `compute_pyc_sha` / class object that
the core registry uses. Sharing ONE definition is the point: the honest producer
claim and the verifier's re-derivation cannot drift, and registering
`BuildRealCompilerRecompute()` from a call site is idempotent with the core
auto-registration (same class object — register_primitive raises only on
same-id/DIFFERENT-class).

Importing this module now requires audit_bundle on sys.path (the core package).
Every real call site already puts the package root on sys.path.
"""

from __future__ import annotations

from audit_bundle.rederivation.primitives.build_real_compiler import (  # noqa: F401
    REPR_SOURCE_NAME,
    BuildRealCompilerRecompute,
    compute_pyc_sha,
    compute_repr_pyc_sha_from_bundle,
)

__all__ = [
    "REPR_SOURCE_NAME",
    "BuildRealCompilerRecompute",
    "compute_pyc_sha",
    "compute_repr_pyc_sha_from_bundle",
]
