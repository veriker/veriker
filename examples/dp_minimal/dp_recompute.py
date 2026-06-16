"""dp_recompute.py — re-export shim for the PROMOTED dp primitive.

The DP noised-count re-derivation primitive has been promoted into the shippable
core registry: audit_bundle/rederivation/primitives/dp.py (RECIPE_BOOK.md,
shape `differential privacy (Laplace seeded-noise aggregate)`). The recompute
rule now lives in verifier-DISTRIBUTION code and the generic verifier carries
it — a third party running the generic verifier against a dp bundle recomputes
on the SAFE spec-pinned path with no demo-local code.

This module is kept as a thin re-export so the existing per-dir call sites
(spec_pinned_check.py, DpReDerivationCheck.py) import the SAME
`compute_noised_count`, `compute_laplace_noise`, and `DpRecompute` that the
core registry uses. Sharing ONE definition is the point: the honest producer
claim and the verifier's re-derivation cannot drift. This shim only re-exports;
registration happens once, in the core package's primitives/__init__.py auto-
load. (A call site that does re-register the same class object is harmless —
register_primitive is a no-op on a same-id/same-class re-bind — but this module
does not itself call register_primitive.)

Importing this module now requires audit_bundle on sys.path (the core package).
Every real call site already puts the package root on sys.path; the builder
(_build_bundle.py) carries its own producer-side compute copy and does not
import from here.
"""

from __future__ import annotations

from audit_bundle.rederivation.primitives.dp import (  # noqa: F401
    DpRecompute,
    compute_laplace_noise,
    compute_noised_count,
)

__all__ = [
    "DpRecompute",
    "compute_noised_count",
    "compute_laplace_noise",
]
