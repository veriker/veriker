"""tests/test_recipe_build_promoted.py — the `build artifact digest` shape is
PROMOTED into the shippable core registry (RECIPE_BOOK.md).

Two things are proven, deliberately without a tautology:

  GENERIC SAFE PATH. The bundle is verified by a BARE BundleVerifier under an
  auditor SpecAnchor with NO demo-local register_primitive and WITHOUT importing
  the primitive module at all. The only thing that resolves the recompute is the
  core registry auto-registration (run_spec_pinned_dispatch ->
  _ensure_primitives_loaded -> import primitives -> build self-registers). If
  build were not promoted, the dispatch would fail UNKNOWN_PRIMITIVE.

  PRODUCER-FAITHFULNESS (not f(x)==f(x)). The producer's claimed artifact_sha is
  the SHA-256 of the producer's OWN payload/artifacts/combined.txt.gz — emitted
  by _build_bundle.py's _execute_recipe function, a verifier-side reimplementation
  kept separate from primitives/build.py. The verifier recomputes the artifact sha
  by re-executing the committed recipe over the committed sources and compares.
  An honest PASS demonstrates the verifier recomputes the producer's digest within
  one zlib build and catches edit-drift between the two recipe-execution copies.
  The claim is never routed through the verifier's own compute_artifact_sha.

  CROSS-VERSION STABILITY (golden digest). A pinned golden digest
  (_GOLDEN_ARTIFACT_SHA, derived offline from the fixed source content and
  recipe) is asserted against the verifier's recomputed value in the honest-pass
  test. This makes the byte-stability claim testable: if a zlib/CPython version
  change shifts the output, the golden assertion fails explicitly rather than
  passing silently because producer and verifier share the same build.  Derivation:
  sha256(gzip(mtime=0, level=6, concat(a.txt, b.txt, c.txt, sep=\\n))) over the
  fixed _SOURCES in _build_bundle.py — confirmed by independent in-process
  computation and by running the producer script.

Run SOLO — shared bundle basenames collide in one pytest process.

Surfaces:
  1. Honest bundle -> PASS (generic safe path AND producer-faithfulness AND
     golden digest).
  2. Tampered claimed value (flip one hex char) -> REDERIVATION_MISMATCH only.
  3. Tampered committed input (append bytes to sources/a.txt) ->
     REDERIVATION_MISMATCH only.
For (2)/(3) the manifest file SHA is re-aligned so FileIntegrity does not fire
first — isolating the re-derivation mismatch from a plain integrity failure.
(Only the value-tamper is a failure FileIntegrity could NEVER catch: the
claimed-value file is producer-controlled and self-pinned; the re-derivation
dispatch is what catches it.)
The neg-control assertions check the EXACT reason-code set (==) so a future
change that lets FileIntegrity or another check co-fire is caught rather than
silently passing.

Stdlib-only orchestration; the build runs the pilot's real producer _build_bundle.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# NOTE: the verifier's recompute primitive (primitives/build.py) is deliberately
# NOT imported here. The claim is derived from the producer artifact, and the
# primitive must resolve ONLY via dispatch's core auto-registration.
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from examples._spec_pinned_overlay import apply_overlay, compute_anchor  # noqa: E402

_PILOT_DIR = _PKG_ROOT / "examples" / "build_minimal"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "build.spec.json"
_OUTPUT_ID = "artifact_sha"
_TYPE_KEY = "artifact_sha"
_ARTIFACT_REL = "payload/artifacts/combined.txt.gz"

# ---------------------------------------------------------------------------
# Golden digest — pinned for cross-version stability testing
#
# Derived from the fixed source content in _build_bundle.py._SOURCES and the
# two-step recipe (concat sep="\n" → gzip mtime=0 compresslevel=6):
#   sha256( gzip(mtime=0, level=6, b"alpha...\n\nbeta...\n\ngamma...") )
#
# Confirmed by two independent paths:
#   (a) in-process Python computation using the same gzip.GzipFile parameters
#   (b) running _build_bundle.py and hashing the emitted artifact file
#
# If a CPython or zlib version change shifts gzip output, the honest-pass
# assertion below will fail explicitly with a clear diff rather than silently
# passing because producer and verifier share the same process.
# ---------------------------------------------------------------------------
_GOLDEN_ARTIFACT_SHA = (
    "7d0ac1271b00a9af7c1cba87d35776cf6cc48351b9c5ac70f839d13dbbf268cf"
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _build(out_dir: Path, *, claimed_override=None):
    """Build a spec-pinned build_minimal bundle producer-side. Returns (bundle, anchor).

    The base bundle is produced by the pilot's real _build_bundle.py (sources/,
    recipe/build_recipe.json, payload/artifacts/combined.txt.gz, manifest). The
    HONEST claimed artifact_sha is sha256(payload/artifacts/combined.txt.gz) —
    the producer's OWN emitted artifact bytes, computed by an _execute_recipe code
    copy independent of the verifier primitive. The generic β overlay then adds the
    auditor spec, the producer claimed-value file, and manifest.outputs.
    """
    subprocess.run(
        [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(out_dir)],
        check=True,
        capture_output=True,
    )
    # Producer-side claim: hash the producer's independently-emitted artifact.
    # This is NOT routed through the verifier's compute_artifact_sha — it reads
    # the bytes already written by _build_bundle.py's _execute_recipe, which is
    # an independent code copy. The verifier's recompute uses its own
    # recompute_artifact_bytes; if the two ever drift, this test will FAIL on
    # the honest case, surfacing the faithfulness bug.
    claimed = _sha256((out_dir / _ARTIFACT_REL).read_bytes())
    if claimed_override is not None:
        claimed = claimed_override
    apply_overlay(
        out_dir,
        spec_src_path=_SPEC_SRC,
        output_id=_OUTPUT_ID,
        type_key=_TYPE_KEY,
        claimed_value=claimed,
    )
    # Match manifest.typed_checks to the minimal plugin set we run (the verifier
    # rejects a typed_checks name with no matching plugin instance).
    mp = out_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["typed_checks"] = ["file_integrity_many_small"]
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))
    return out_dir, compute_anchor(_SPEC_SRC)


def _realign_file_sha(bundle_dir: Path, rel: str) -> None:
    """Recompute and store the manifest SHA for one file so FileIntegrity does not
    fire before the re-derivation dispatch can be observed."""
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][rel] = _sha256((bundle_dir / rel).read_bytes())
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))


def _verify(bundle_dir: Path, anchor):
    # BARE verifier: FileIntegrity + spec-pinned dispatch under the auditor anchor.
    # NO register_primitive — the recompute resolves only via the CORE registry.
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()], spec_anchor=anchor
    ).verify(bundle_dir)


def test_promoted_generic_safe_path_and_faithfulness_pass(tmp_path):
    # Honest PASS proves three things:
    #   (1) The generic verifier resolves build via core auto-registration (no
    #       import, no demo registration).
    #   (2) The verifier's recompute agrees with the producer's independent
    #       artifact bytes (producer-faithfulness, not f(x)==f(x)).
    #   (3) The recomputed digest equals the pinned golden value, making the
    #       byte-stability claim testable: a zlib/CPython version shift that
    #       changes gzip output will fail here explicitly.
    bundle_dir, anchor = _build(tmp_path / "bundle")
    result = _verify(bundle_dir, anchor)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]
    # Golden digest: independently derived from the fixed _SOURCES + recipe.
    # Verifier recomputed value == this constant proves cross-build stability
    # within the current zlib (producer ran in this process; golden pins the
    # expected output for future zlib changes).
    claimed_doc = json.loads(
        (bundle_dir / "outputs" / f"{_OUTPUT_ID}.json").read_bytes()
    )
    assert claimed_doc["value"] == _GOLDEN_ARTIFACT_SHA, (
        f"recomputed digest drifted from golden: got {claimed_doc['value']!r}, "
        f"expected {_GOLDEN_ARTIFACT_SHA!r}"
    )


def test_promoted_tampered_value_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Flip one hex char of the producer's claimed artifact_sha.
    claim_path = bundle_dir / "outputs" / f"{_OUTPUT_ID}.json"
    doc = json.loads(claim_path.read_bytes())
    honest = doc["value"]
    doc["value"] = ("0" if honest[0] != "0" else "1") + honest[1:]
    assert doc["value"] != honest
    claim_path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    _realign_file_sha(bundle_dir, f"outputs/{_OUTPUT_ID}.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    # Exact set: re-aligned SHA means FileIntegrity must NOT also fire.
    # If a future change lets another check co-fire, this assertion catches it.
    assert _reason_codes(result) == {"REDERIVATION_MISMATCH"}, _reason_codes(result)


def test_promoted_tampered_input_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Append bytes to sources/a.txt — re-executing the recipe over the mutated
    # source produces a different gzip artifact, so the recomputed sha diverges
    # from the (honest) claimed sha.
    src_path = bundle_dir / "sources" / "a.txt"
    src_path.write_bytes(src_path.read_bytes() + b"TAMPERED EXTRA SOURCE LINE\n")
    _realign_file_sha(bundle_dir, "sources/a.txt")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    # Exact set: re-aligned SHA means FileIntegrity must NOT also fire.
    # If a future change lets another check co-fire, this assertion catches it.
    assert _reason_codes(result) == {"REDERIVATION_MISMATCH"}, _reason_codes(result)
