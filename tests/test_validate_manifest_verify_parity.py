"""Shallow-check parity ratchet — validate_manifest() vs BundleVerifier.verify().

BLOCK-03 (2026-06-11) was a REFACTOR-shaped gap: ef9a197 moved the CLI off
validate_manifest() onto verify() on the claim "verify() subsumes the deep
validators" — true for DEEP (steps 6-20, which verify() runs via the shared
deep_validation_failure → _validate_manifest_deep chain), silently false for
SHALLOW (steps 0-5). The schema_version allowlist was orphaned on a path
nothing on the verdict route called, and unknown schema versions verified
green for weeks — long enough that 9 in-house fixtures invented 'v0.2'/'v0.4'
tags and nothing pushed back.

This file is the structural answer, in three locked layers:

  1. AST INVENTORY — the shallow slice of validate_manifest (every statement
     before the _validate_manifest_deep call) is enumerated: directly-raised
     exception classes + called helper validators. Pinned EXACTLY. Adding a
     new shallow check (a new raise or helper) fails the pin with
     instructions; so does removing one.

  2. DIFFERENTIAL CORPUS — one minimal mutated bundle per shallow check,
     asserted to reject through BOTH entry points: validate_manifest raises
     AND BundleVerifier.verify() is not-OK. This is the reachability proof
     the BLOCK-03 comment claimed and never had.

  3. CLOSURE — every exception class the AST inventory finds must be
     witnessed by a corpus entry's validate-side raise. A new shallow check
     therefore cannot go green here until a corpus entry EXISTS and that
     entry PROVES verify() rejects it too.

Protocol when the inventory pin fails: you added/changed a shallow check in
validate_manifest. (a) wire its counterpart into verify()'s path (parse
boundary, 4-step walk, or a dedicated step); (b) add a corpus entry below
that trips it; (c) update the pinned inventory. Never just update the pin.

The DEEP half needs no corpus: test_deep_half_is_the_same_function_object
pins the call chain (validate_manifest → _validate_manifest_deep AND
verify() → deep_validation_failure → _validate_manifest_deep), so deep
checks are shared by construction and cannot drift.
"""

from __future__ import annotations

import ast
import builtins
import hashlib
import inspect
import json
import textwrap
from pathlib import Path

import pytest

import audit_bundle.bundle_manifest as bundle_manifest_mod
import audit_bundle.verifier as verifier_mod
from audit_bundle.bundle_manifest import ManifestError, validate_manifest
from audit_bundle.verifier import BundleVerifier, _load_manifest

# ---------------------------------------------------------------------------
# Layer 1 — AST inventory of the shallow slice
# ---------------------------------------------------------------------------

# The pinned inventory. A mismatch means the shallow slice changed — follow
# the protocol in the module docstring, do NOT just edit these sets.
EXPECTED_SHALLOW_RAISES = frozenset(
    {
        "FileSHAMismatch",  # step 2 — missing file / SHA mismatch
        "SpecSHAMissing",  # step 3 — empty spec SHA
        "CrossRefBroken",  # step 4 — cross_ref target unresolvable
        "TypedCheckUnregistered",  # step 5 — unregistered typed_check name
    }
)
EXPECTED_SHALLOW_HELPERS = frozenset(
    {
        "_validate_field_shapes",  # step 0 — raises MalformedManifest
        "validate_schema_version",  # step 1 — raises SchemaVersionError (BLOCK-03)
        "_safe_bundle_path",  # step 2 guard — raises UnsafeBundlePath
        "_sha256_file",  # step 2 recompute (no raise of its own)
    }
)

_BUILTIN_NAMES = frozenset(dir(builtins))


def _shallow_slice() -> list[ast.stmt]:
    """validate_manifest's body up to (excluding) the _validate_manifest_deep
    call. Fails loudly if the deep call disappears or stops being last —
    that structure is what makes 'shallow slice' a well-defined drift surface."""
    tree = ast.parse(inspect.getsource(bundle_manifest_mod))
    fn = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "validate_manifest"
    )

    def _is_deep_call(stmt: ast.stmt) -> bool:
        return (
            isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Call)
            and isinstance(stmt.value.func, ast.Name)
            and stmt.value.func.id == "_validate_manifest_deep"
        )

    deep_calls = [i for i, s in enumerate(fn.body) if _is_deep_call(s)]
    assert deep_calls, (
        "validate_manifest no longer calls _validate_manifest_deep — the "
        "shallow/deep split this ratchet pins has been restructured; "
        "re-derive the parity surface before changing this test"
    )
    assert deep_calls == [len(fn.body) - 1], (
        "_validate_manifest_deep must be the LAST statement of "
        "validate_manifest (statements after it would be un-inventoried "
        "shallow checks)"
    )
    return fn.body[: deep_calls[0]]


def _inventory() -> tuple[frozenset[str], frozenset[str]]:
    """(raised exception class names, helper Name-calls) in the shallow slice.

    Raise classes come from `raise X(...)` nodes. Helper calls are every
    Name-function call OUTSIDE raise nodes, minus Python builtins — so a
    future check guarded by `if not _check_foo(m):` or computed via
    `x = _helper(...)` is inventoried wherever it appears, not only at
    statement level.
    """
    raises: set[str] = set()
    helpers: set[str] = set()
    raise_descendants: set[int] = set()
    slice_ = _shallow_slice()
    for stmt in slice_:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Raise) and node.exc is not None:
                for sub in ast.walk(node):
                    raise_descendants.add(id(sub))
                exc = node.exc
                if isinstance(exc, ast.Call) and isinstance(exc.func, ast.Name):
                    raises.add(exc.func.id)
    for stmt in slice_:
        for node in ast.walk(stmt):
            if id(node) in raise_descendants:
                continue
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id not in _BUILTIN_NAMES
            ):
                helpers.add(node.func.id)
    return frozenset(raises), frozenset(helpers)


def test_shallow_inventory_is_pinned() -> None:
    raises, helpers = _inventory()
    assert raises == EXPECTED_SHALLOW_RAISES and helpers == EXPECTED_SHALLOW_HELPERS, (
        "validate_manifest's SHALLOW slice changed.\n"
        f"  raises:  found {sorted(raises)}\n"
        f"           pinned {sorted(EXPECTED_SHALLOW_RAISES)}\n"
        f"  helpers: found {sorted(helpers)}\n"
        f"           pinned {sorted(EXPECTED_SHALLOW_HELPERS)}\n"
        "A shallow check was added/removed/renamed. BLOCK-03 protocol:\n"
        "  (a) wire the check's counterpart into BundleVerifier.verify()\n"
        "      (parse boundary / 4-step walk / dedicated step);\n"
        "  (b) add a _CORPUS entry in this file that trips it;\n"
        "  (c) THEN update the pinned inventory here.\n"
        "Never just update the pin — that re-opens the BLOCK-03 class."
    )


# ---------------------------------------------------------------------------
# Layer 1b — the deep half is drift-proof by shared function object
# ---------------------------------------------------------------------------


def _fn_calls_name(module: object, fn_name: str, callee: str) -> bool:
    """True iff function `fn_name` (module-level or method — source is
    dedented so a class-indented body parses) contains a call to `callee`."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(module)))
    fn = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == fn_name
    )
    return any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == callee
        for n in ast.walk(fn)
    )


def test_deep_half_is_the_same_function_object() -> None:
    """validate_manifest and verify() must reach the deep validators through
    ONE shared function (_validate_manifest_deep) — that is what exempts the
    deep half from needing a differential corpus. If either edge of the chain
    breaks, deep checks become copy-drift candidates and this ratchet's scope
    is wrong."""
    assert _fn_calls_name(
        bundle_manifest_mod, "validate_manifest", "_validate_manifest_deep"
    )
    assert _fn_calls_name(
        bundle_manifest_mod, "deep_validation_failure", "_validate_manifest_deep"
    )
    assert _fn_calls_name(
        verifier_mod.BundleVerifier._step_deep_manifest_validation,
        "_step_deep_manifest_validation",
        "deep_validation_failure",
    )


# ---------------------------------------------------------------------------
# Layer 2 — differential corpus: each shallow check rejects through BOTH paths
# ---------------------------------------------------------------------------


def _build_bundle(tmp_path: Path, mutate) -> Path:
    """Minimal otherwise-green bundle, then one corpus mutation."""
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    data = b"hello world\n"
    (bundle_dir / "data.txt").write_bytes(data)
    manifest: dict = {
        "schema_version": "vcp-v1.1-canary4",
        "bundle_id": "parity-ratchet",
        "files": {"data.txt": hashlib.sha256(data).hexdigest()},
        "spec_files": {},
        "cross_refs": {},
        "typed_checks": [],
    }
    mutate(manifest, bundle_dir)
    (bundle_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return bundle_dir


# check_id -> (mutation, exception class name the validate side must raise).
# Every class in EXPECTED_SHALLOW_RAISES plus every helper's raise class must
# be witnessed here (closure test below).
_CORPUS: dict[str, tuple] = {
    "step0_field_shape": (
        lambda m, d: m.update({"files": ["not", "a", "dict"]}),
        "MalformedManifest",
    ),
    "step1_schema_version": (
        lambda m, d: m.update({"schema_version": "evil-future-schema"}),
        "SchemaVersionError",
    ),
    "step2_missing_file": (
        lambda m, d: m["files"].update({"ghost.txt": "0" * 64}),
        "FileSHAMismatch",
    ),
    "step2_sha_mismatch": (
        lambda m, d: m["files"].update({"data.txt": "0" * 64}),
        "FileSHAMismatch",
    ),
    "step2_path_escape": (
        lambda m, d: m["files"].update({"../escapee": "0" * 64}),
        "UnsafeBundlePath",
    ),
    "step3_empty_spec_sha": (
        lambda m, d: m["spec_files"].update({"spec/x.json": ""}),
        "SpecSHAMissing",
    ),
    "step4_cross_ref_broken": (
        lambda m, d: m["cross_refs"].update({"x": "no-such-target.txt"}),
        "CrossRefBroken",
    ),
    "step5_typed_check_unregistered": (
        lambda m, d: m["typed_checks"].append("totally_unregistered_check"),
        "TypedCheckUnregistered",
    ),
}


def _validate_side_raise(bundle_dir: Path) -> str:
    """Exception class name from the validate_manifest entry path (parse via
    _load_manifest included — a parse-boundary raise IS that path rejecting)."""
    try:
        validate_manifest(_load_manifest(bundle_dir), bundle_dir)
    except ManifestError as exc:
        return type(exc).__name__
    pytest.fail("validate_manifest path ACCEPTED a corpus bundle built to fail")


@pytest.mark.parametrize("check_id", sorted(_CORPUS))
def test_shallow_check_rejects_through_both_paths(
    tmp_path: Path, check_id: str
) -> None:
    mutate, expected_exc = _CORPUS[check_id]
    bundle_dir = _build_bundle(tmp_path, mutate)

    raised = _validate_side_raise(bundle_dir)
    assert raised == expected_exc, (
        f"{check_id}: validate side raised {raised}, corpus expects "
        f"{expected_exc} — the mutation no longer trips the intended check"
    )

    verdict = BundleVerifier().verify(bundle_dir)
    assert not verdict.ok, (
        f"{check_id}: validate_manifest raises {raised} but "
        f"BundleVerifier.verify() returned OK — a shallow check is orphaned "
        f"from the verdict path (the BLOCK-03 class, live again)"
    )


def test_baseline_bundle_is_green_through_both_paths(tmp_path: Path) -> None:
    """The corpus signal is the MUTATION, not a broken baseline."""
    bundle_dir = _build_bundle(tmp_path, lambda m, d: None)
    validate_manifest(_load_manifest(bundle_dir), bundle_dir)  # must not raise
    assert BundleVerifier().verify(bundle_dir).ok


# ---------------------------------------------------------------------------
# Layer 3 — closure: the AST inventory is fully witnessed by the corpus
# ---------------------------------------------------------------------------

# Exception classes raised by the inventoried HELPERS (not visible to the
# direct-raise AST scan). Maintained alongside EXPECTED_SHALLOW_HELPERS.
_HELPER_RAISE_CLASSES = frozenset(
    {
        "MalformedManifest",  # _validate_field_shapes
        "SchemaVersionError",  # validate_schema_version
        "UnsafeBundlePath",  # _safe_bundle_path
        # _sha256_file raises nothing of its own
    }
)


def test_corpus_witnesses_every_inventoried_check() -> None:
    """Every exception class the shallow slice can raise — directly or via an
    inventoried helper — must be tripped by at least one corpus entry. A new
    shallow check cannot pass the inventory pin AND this closure without a
    corpus entry proving verify() rejects it."""
    witnessed = {expected_exc for _, expected_exc in _CORPUS.values()}
    required = EXPECTED_SHALLOW_RAISES | _HELPER_RAISE_CLASSES
    missing = required - witnessed
    assert not missing, (
        f"shallow checks with NO differential corpus entry: {sorted(missing)} "
        "— add a _CORPUS mutation tripping each, so its reachability through "
        "verify() is proven, not assumed"
    )
