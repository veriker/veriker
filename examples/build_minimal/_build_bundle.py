"""_build_bundle.py — build a deterministic build_minimal audit bundle.

Synthesizes three source text files plus a two-step deterministic build recipe
(concat → canonical gzip), executes the recipe in-process to produce the final
artifact, and emits a standards-compliant manifest binding sources, recipe, and
artifact bytes via per-file SHA-256.

The substrate claim this pilot establishes: V-Kernel re-derivation generalizes
to **deterministic build/recipe execution** — the Nix / Bazel / reproducible-
builds shape — where the re-derivation primitive is "re-execute the recipe
against the committed inputs and assert the produced artifact bytes match the
bundled artifact bytes."

Usage (from v-kernel-audit-bundle root):
    python examples/build_minimal/_build_bundle.py --out-dir /tmp/build_bundle

Outputs:
  <out-dir>/sources/a.txt
  <out-dir>/sources/b.txt
  <out-dir>/sources/c.txt
  <out-dir>/recipe/build_recipe.json
  <out-dir>/payload/artifacts/combined.txt.gz
  <out-dir>/manifest.json

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.emitter import BundleContent, write_bundle  # noqa: E402

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "build-minimal-rc"
_CREATED_AT = "2026-05-09T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
    "build_re_derivation",
]

# ---------------------------------------------------------------------------
# Synthetic source tree — three deterministic text files
#
# Stand-ins for a real source tree. Content is fixed and ASCII-only so the
# pilot is byte-stable across platforms (no CRLF/LF surprises — we always
# write LF).  In a real integration these would be the project's actual
# source files, addressed by repo-relative path.
# ---------------------------------------------------------------------------

_SOURCES: dict[str, str] = {
    "a.txt": "alpha source\nfirst module\n",
    "b.txt": "beta source\nsecond module\nwith two lines of content\n",
    "c.txt": "gamma source\nthird module\nfinal segment\n",
}

# ---------------------------------------------------------------------------
# Build recipe — two deterministic steps
#
#   step_1 (concat): join sources/{a,b,c}.txt in declared order, separator="\n"
#   step_2 (gzip):   gzip step_1 output with mtime=0 + compresslevel=6
#
# Determinism knobs: input order is declared (not filesystem-walk), separator
# is explicit, gzip mtime is pinned to 0, and the compress level is pinned.
# Stdlib gzip with compresslevel=6 + mtime=0 is byte-stable across CPython
# versions ≥3.10 on every supported platform.
# ---------------------------------------------------------------------------

_RECIPE: dict = {
    "schema": "build-recipe-v1",
    "tools": {
        "interpreter": "cpython",
        "interpreter_minimum": "3.10",
        "modules": ["gzip (stdlib)"],
    },
    "steps": [
        {
            "id": "step_1_concat",
            "rule": "concat",
            "inputs": ["sources/a.txt", "sources/b.txt", "sources/c.txt"],
            "output": "_intermediate/combined.txt",
            "options": {
                "separator": "\n",
                "encoding": "utf-8",
            },
        },
        {
            "id": "step_2_gzip",
            "rule": "gzip",
            "inputs": ["_intermediate/combined.txt"],
            "output": "payload/artifacts/combined.txt.gz",
            "options": {
                "mtime": 0,
                "compresslevel": 6,
            },
        },
    ],
    "final_artifact": "payload/artifacts/combined.txt.gz",
}


def _execute_recipe(recipe: dict, source_bytes: dict[str, bytes]) -> bytes:
    """Execute the recipe in-process; return the final artifact bytes.

    Mirror image of build_re_derivation.py — kept duplicated (AB4: don't import
    across pilot boundaries; substrate is the only shared layer).
    """
    intermediates: dict[str, bytes] = {}

    for step in recipe["steps"]:
        rule = step["rule"]
        opts = step.get("options", {})

        if rule == "concat":
            sep = opts.get("separator", "\n").encode(opts.get("encoding", "utf-8"))
            parts: list[bytes] = []
            for inp in step["inputs"]:
                if inp.startswith("sources/"):
                    parts.append(source_bytes[inp[len("sources/"):]])
                elif inp.startswith("_intermediate/"):
                    parts.append(intermediates[inp])
                else:
                    raise AssertionError(f"unknown input prefix: {inp!r}")
            output = sep.join(parts)
            intermediates[step["output"]] = output

        elif rule == "gzip":
            assert len(step["inputs"]) == 1, "gzip rule expects a single input"
            inp = step["inputs"][0]
            if inp.startswith("_intermediate/"):
                raw = intermediates[inp]
            elif inp.startswith("sources/"):
                raw = source_bytes[inp[len("sources/"):]]
            else:
                raise AssertionError(f"unknown input prefix: {inp!r}")
            buf = io.BytesIO()
            with gzip.GzipFile(
                fileobj=buf,
                mode="wb",
                mtime=int(opts.get("mtime", 0)),
                compresslevel=int(opts.get("compresslevel", 6)),
            ) as gz:
                gz.write(raw)
            output = buf.getvalue()
            intermediates[step["output"]] = output

        else:
            raise AssertionError(f"unsupported rule: {rule!r}")

    final_path = recipe["final_artifact"]
    assert final_path in intermediates, (
        f"final_artifact {final_path!r} not produced by any step"
    )
    return intermediates[final_path]


def build(out_dir: Path) -> None:
    # Generate source bytes (LF-normalized, UTF-8)
    source_bytes: dict[str, bytes] = {}
    for name, content in _SOURCES.items():
        # Defensive: enforce LF on write so platform line-ending defaults
        # cannot drift the bundled bytes.
        source_bytes[name] = content.encode("utf-8")

    # Recipe bytes
    recipe_bytes = json.dumps(_RECIPE, indent=2, sort_keys=True).encode("utf-8")

    # Execute recipe → final artifact
    artifact_bytes = _execute_recipe(_RECIPE, source_bytes)

    # Emit via the reference-emitter SDK
    content = BundleContent(
        bundle_id=_BUNDLE_ID,
        created_at=_CREATED_AT,
        schema_version=_SCHEMA_VERSION,
        files={
            "sources/a.txt": source_bytes["a.txt"],
            "sources/b.txt": source_bytes["b.txt"],
            "sources/c.txt": source_bytes["c.txt"],
            "recipe/build_recipe.json": recipe_bytes,
            "payload/artifacts/combined.txt.gz": artifact_bytes,
        },
        typed_checks=_TYPED_CHECKS,
    )
    manifest = write_bundle(out_dir, content)
    files = manifest["files"]

    print(f"Bundle written to {out_dir}")
    print(f"  source files       : {len(_SOURCES)}")
    print(f"  recipe steps       : {len(_RECIPE['steps'])}")
    print(f"  final artifact     : combined.txt.gz ({len(artifact_bytes)} bytes)")
    print(f"  manifest files     : {len(files)}")
    print(f"  manifest           : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic build_minimal audit bundle"
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
    except AssertionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
