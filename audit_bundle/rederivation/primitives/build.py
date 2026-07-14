"""build_recompute — verifier-side deterministic build/recipe re-derivation.

Axis-2 value-return form of the build re-derivation, PROMOTED into the
shippable core registry (RECIPE_BOOK.md, shape `build artifact digest`). The
generic verifier recomputes the representative output on the SAFE spec-pinned
path: no subprocess, no bundle-supplied code — the recompute rule lives HERE in
verifier-distribution code and the comparator + tolerance come from the
auditor-anchored spec.

Re-derivation primitive (one sentence):
    artifact_sha = sha256( gzip(mtime=0, level=6, concat(sources, sep="\\n")) ).hex()

The representative re-derived output is the SHA-256 hex digest of the build
artifact bytes produced by RE-EXECUTING the committed recipe
(recipe/build_recipe.json) against the committed sources/ tree — exactly the
recipe semantics: each `concat` step joins its inputs with the declared
separator (default "\\n", utf-8), each `gzip` step gzips its single input with
the declared mtime (default 0) and compresslevel (default 6) via stdlib
gzip.GzipFile. The recipe's `final_artifact` step output is the produced
artifact; we then take sha256 over those produced bytes.

The recipe-execution rule is FIXED in this primitive — the primitive_id
("build_recompute") IS the rule. The auditor's SHA-pinned spec binds the output
type "artifact_sha" to this primitive_id and to an `exact` comparator
(byte-exact hex string equality); a producer cannot weaken the recipe
interpretation or the comparison without changing the primitive_id / spec SHA,
which the anchor rejects.

artifact_sha is the representative value because it is a deterministic, key-free
recompute: re-execute recipe + plain SHA-256 over the produced bytes. No producer
key is needed (only the committed recipe + sources).

Faithfulness (verifier-side reimplementation — Gate B):
  - `concat` joins input bytes with the declared separator; no implicit newline
    is appended beyond what the separator provides.
  - `gzip` uses stdlib gzip.GzipFile with the declared mtime (pinned 0) and
    compresslevel (pinned 6).
  - The two-step recipe (concat → gzip → sha256) is a faithful verifier-side
    reimplementation of `_build_bundle.py`'s `_execute_recipe`: same separator
    encoding, same gzip parameters, same final sha256.  An honest PASS
    demonstrates the verifier recomputes the producer's digest within one zlib
    build and catches edit-drift between the two recipe-execution copies.
    Cross-zlib-build stability is not guaranteed by construction; it is
    backstopped by a pinned golden digest in the test suite.
  - Unsupported rules raise ValueError so the primitive fails closed rather than
    returning a bogus value.

Stdlib-only (§C5 core verify() path).
"""

from __future__ import annotations

import gzip
import hashlib
import io
from pathlib import Path

from ...admission import admit_json_file
from ...plugin import ParsedInputs, RecomputedValue
from ..registry import register_primitive
from ._safepath import resolve_within


# ---------------------------------------------------------------------------
# Recipe execution engine — byte-identical to the producer pack
# (examples/build_minimal/_build_bundle.py :: _execute_recipe)
# ---------------------------------------------------------------------------


def recompute_artifact_bytes(recipe: dict, sources_dir: Path) -> bytes:
    """Re-execute the committed recipe against the committed sources/ tree and
    return the produced final-artifact bytes.

    Faithful verifier-side reimplementation of the builder's _execute_recipe
    semantics:
      - rule=concat: join input bytes with declared separator (default "\\n",
        encoded with declared encoding, default utf-8).
      - rule=gzip:   gzip the single input with declared mtime (default 0) and
        compresslevel (default 6) via stdlib gzip.GzipFile.
    Source inputs (sources/<name>) are read from sources_dir; intermediate
    inputs are produced by earlier steps. Returns the bytes of the step whose
    output path equals recipe["final_artifact"].
    """
    steps = recipe.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ValueError("recipe.steps missing or empty")
    final_path = recipe.get("final_artifact")
    if not isinstance(final_path, str) or not final_path:
        raise ValueError("recipe.final_artifact missing or empty")

    intermediates: dict[str, bytes] = {}

    def _read_input(inp: str) -> bytes:
        if inp.startswith("sources/"):
            # inp is recipe-controlled (bundle data): contain the read inside
            # sources/ so a hostile recipe cannot steer it to an out-of-tree
            # file via '..' / an absolute path. Fails closed (ValueError).
            p = resolve_within(sources_dir, inp[len("sources/") :])
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
            raise ValueError(f"step {step.get('id')!r}: missing output path")

        if rule == "concat":
            sep = opts.get("separator", "\n").encode(opts.get("encoding", "utf-8"))
            parts = [_read_input(i) for i in inputs]
            intermediates[out_path] = sep.join(parts)
        elif rule == "gzip":
            if len(inputs) != 1:
                raise ValueError(
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
            raise ValueError(f"step {step.get('id')!r}: unsupported rule {rule!r}")

    if final_path not in intermediates:
        raise ValueError(
            f"final_artifact {final_path!r} not produced by any recipe step"
        )
    return intermediates[final_path]


# ---------------------------------------------------------------------------
# Canonical computation (the verifier's authoritative re-derivation rule)
# ---------------------------------------------------------------------------


def compute_artifact_sha(recipe: dict, sources_dir: Path) -> str:
    """Canonical artifact SHA-256 hex digest = sha256 over the bytes produced by
    re-executing the committed recipe against the committed sources. Builder and
    verifier share this ONE definition so the honest claimed sha and the
    re-derivation cannot drift.
    """
    return hashlib.sha256(recompute_artifact_bytes(recipe, sources_dir)).hexdigest()


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered at import for the core registry)
# ---------------------------------------------------------------------------


class BuildRecompute:
    """Verifier-side primitive for re-deriving the build artifact SHA-256."""

    primitive_id: str = "build_recompute"

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        """Recompute the build artifact SHA-256 hex digest by re-executing the
        committed recipe against the committed sources/ tree.

        Returns the recomputed VALUE only — it reads no acceptance epsilon and
        does not compare; the auditor-anchored `exact` comparator decides
        agreement against outputs/<id>.json.
        """
        bundle_dir: Path = inputs.bundle_dir
        recipe_path = bundle_dir / "recipe" / "build_recipe.json"
        sources_dir = bundle_dir / "sources"
        if not recipe_path.is_file():
            raise FileNotFoundError(
                f"recipe/build_recipe.json not found in bundle at {bundle_dir}"
            )
        if not sources_dir.is_dir():
            raise FileNotFoundError(
                f"sources/ directory not found in bundle at {bundle_dir}"
            )
        recipe = admit_json_file(recipe_path)
        value = compute_artifact_sha(recipe, sources_dir)
        return RecomputedValue(
            value=value,
            detail=(
                f"re-derived build artifact sha256 by re-executing "
                f"{len(recipe.get('steps', []))} recipe step(s) over sources/"
            ),
        )


register_primitive(BuildRecompute())
