"""build_recompute.py — re-export shim for the PROMOTED build primitive.

The build re-derivation primitive has been promoted into the shippable core
registry: audit_bundle/rederivation/primitives/build.py (RECIPE_BOOK.md, shape
`build artifact digest`). The recompute rule now lives in verifier-DISTRIBUTION
code and the generic verifier carries it — a third party running the generic
verifier against a build bundle recomputes on the SAFE spec-pinned path with no
demo-local code.

This module is kept as a thin re-export so the existing per-dir call sites
(spec_pinned_check.py, tests/test_build_spec_pinned.py) import the SAME
`compute_artifact_sha`, `recompute_artifact_bytes`, and `BuildRecompute` that
the core registry uses. Sharing ONE definition is the point: the honest producer
claim and the verifier's re-derivation cannot drift, and registering
`BuildRecompute()` here is idempotent with the core auto-registration (same
class object — register_primitive raises only on same-id/DIFFERENT-class).

Importing this module now requires audit_bundle on sys.path (the core package).
Every real call site already puts the package root on sys.path; nothing imports
this module standalone.
"""

from __future__ import annotations

from audit_bundle.rederivation.primitives.build import (  # noqa: F401
    BuildRecompute,
    compute_artifact_sha,
    recompute_artifact_bytes,
)

__all__ = [
    "BuildRecompute",
    "compute_artifact_sha",
    "recompute_artifact_bytes",
]
