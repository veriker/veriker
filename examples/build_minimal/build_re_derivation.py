#!/usr/bin/env python3
"""build_re_derivation.py — stdlib re-derivation pack for the build/recipe domain.

Re-executes a deterministic build recipe against the committed source tree and
asserts that the produced artifact bytes equal the bundled artifact bytes.

the audit-bundle contract §C6 (re-derivation pack — domain-agnostic substrate).
AB4: stdlib only, no imports from audit_bundle.

Reads:
  recipe/build_recipe.json              — pinned recipe (steps, inputs, options)
  sources/<name>                        — input source files
  payload/artifacts/<final_artifact>    — bundled artifact bytes to match against

Re-derivation procedure:
  1. Parse recipe/build_recipe.json.
  2. Execute each step in declared order:
       - rule=concat: join input file bytes with declared separator (default "\\n")
       - rule=gzip:   gzip the single input with declared mtime + compresslevel
  3. Locate the recipe's `final_artifact` path among the step outputs.
  4. Read the bundled artifact bytes from <bundle_dir>/<final_artifact>.
  5. Compare. Equality is required; any byte difference is a mismatch.

Exits 0 on full match; 1 on first mismatch with a [BUILD_REDER_FAIL] line on stderr.

Usage:
    python build_re_derivation.py --bundle-dir /path/to/bundle
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Recipe execution
# ---------------------------------------------------------------------------


def _execute_recipe(recipe: dict, sources_dir: Path) -> tuple[bytes | None, str | None]:
    """Re-execute the recipe; return (final_artifact_bytes, error).

    On success: error is None and the artifact bytes are returned.
    On failure: artifact is None and error is a human-readable description.
    """
    steps = recipe.get("steps")
    if not isinstance(steps, list) or not steps:
        return None, "recipe.steps missing or empty"

    final_path = recipe.get("final_artifact")
    if not isinstance(final_path, str) or not final_path:
        return None, "recipe.final_artifact missing or empty"

    # In-memory map of step-output path → produced bytes.  Source files are
    # read on demand (sources/<name>) and never go through this dict.
    intermediates: dict[str, bytes] = {}

    def _read_input(inp: str) -> bytes:
        if inp.startswith("sources/"):
            p = sources_dir / inp[len("sources/"):]
            if not p.exists():
                raise FileNotFoundError(f"input {inp!r}: missing source {p}")
            return p.read_bytes()
        if inp in intermediates:
            return intermediates[inp]
        raise KeyError(f"input {inp!r} not found in sources/ or intermediates")

    for step in steps:
        rule = step.get("rule")
        opts = step.get("options", {}) or {}
        out_path = step.get("output")
        inputs = step.get("inputs") or []

        if not isinstance(out_path, str) or not out_path:
            return None, f"step {step.get('id')!r}: missing output path"

        try:
            if rule == "concat":
                sep = opts.get("separator", "\n").encode(opts.get("encoding", "utf-8"))
                parts = [_read_input(i) for i in inputs]
                intermediates[out_path] = sep.join(parts)

            elif rule == "gzip":
                if len(inputs) != 1:
                    return None, (
                        f"step {step.get('id')!r}: gzip rule expects exactly 1 input, "
                        f"got {len(inputs)}"
                    )
                raw = _read_input(inputs[0])
                buf = io.BytesIO()
                with gzip.GzipFile(
                    fileobj=buf,
                    mode="wb",
                    mtime=int(opts.get("mtime", 0)),
                    compresslevel=int(opts.get("compresslevel", 6)),
                ) as gz:
                    gz.write(raw)
                intermediates[out_path] = buf.getvalue()

            else:
                return None, f"step {step.get('id')!r}: unsupported rule {rule!r}"

        except (FileNotFoundError, KeyError) as exc:
            return None, f"step {step.get('id')!r}: {exc}"

    if final_path not in intermediates:
        return None, (
            f"final_artifact {final_path!r} not produced by any recipe step"
        )

    return intermediates[final_path], None


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _verify(bundle_dir: Path) -> str | None:
    """Return an error description on mismatch, or None on success."""
    recipe_path = bundle_dir / "recipe" / "build_recipe.json"
    sources_dir = bundle_dir / "sources"

    if not recipe_path.exists():
        return f"recipe/build_recipe.json absent from bundle_dir {bundle_dir}"
    if not sources_dir.is_dir():
        return f"sources/ directory absent from bundle_dir {bundle_dir}"

    try:
        recipe: dict = json.loads(recipe_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return f"failed to read recipe/build_recipe.json: {exc}"

    schema = recipe.get("schema")
    if schema != "build-recipe-v1":
        return f"unsupported recipe.schema={schema!r}; expected 'build-recipe-v1'"

    rederived, err = _execute_recipe(recipe, sources_dir)
    if err is not None:
        return f"recipe re-execution failed: {err}"
    assert rederived is not None  # narrowing for type-checkers

    final_path = recipe["final_artifact"]
    bundled_artifact = bundle_dir / final_path
    if not bundled_artifact.exists():
        return f"bundled final_artifact {final_path!r} absent from bundle_dir"

    bundled_bytes = bundled_artifact.read_bytes()
    if bundled_bytes != rederived:
        return (
            f"final_artifact byte mismatch — "
            f"re-derived={len(rederived)} bytes, bundled={len(bundled_bytes)} bytes; "
            f"first-difference offset="
            f"{_first_diff_offset(rederived, bundled_bytes)}"
        )

    return None


def _first_diff_offset(a: bytes, b: bytes) -> int:
    """Return the index of the first differing byte, or len(min) if one is a prefix."""
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i
    return n


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build re-derivation check for build/recipe audit bundles"
    )
    parser.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="Root directory of the unpacked audit bundle",
    )
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    error = _verify(bundle_dir)
    if error is None:
        return 0

    print(f"[BUILD_REDER_FAIL] {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
