"""tests/test_recipe_build_real_compiler_promoted.py — the `real-compiler build
digest` shape is PROMOTED into the shippable core registry (RECIPE_BOOK.md).

Two things are proven, deliberately without a tautology:

  GENERIC SAFE PATH. The bundle is verified by a BARE BundleVerifier under an
  auditor SpecAnchor with NO demo-local register_primitive and WITHOUT importing
  the primitive module at all. The only thing that resolves the recompute is the
  core registry auto-registration (run_spec_pinned_dispatch ->
  _ensure_primitives_loaded -> import primitives -> build_real_compiler
  self-registers). If it were not promoted, dispatch would fail UNKNOWN_PRIMITIVE.

  PRODUCER-FAITHFULNESS (not f(x)==f(x)). The producer's claimed pyc_sha is
  sha256 of the producer's OWN emitted payload/artifacts/mod_a.pyc — the .pyc the
  producer compiled and bundled, NOT the verifier's recompile. The verifier
  recompiles the committed sources/mod_a.py (CHECKED_HASH, SOURCE_DATE_EPOCH=0,
  cache_tag-guarded) and SHA-256s the produced bytes, then compares. An honest
  PASS proves the producer's bundled .pyc and the verifier's recompiled .pyc agree
  within one CPython/cache_tag — if the two compile copies ever drift, this test
  FAILS. The claim is never routed through the verifier's compute_pyc_sha.

Run SOLO — shared bundle basenames collide in one pytest process.

Surfaces:
  1. Honest bundle -> PASS (generic safe path AND producer-faithfulness).
  2. Tampered claimed value (flip one hex char) -> REDERIVATION_MISMATCH.
  3. Tampered committed input (append a comment to sources/mod_a.py so the
     CHECKED_HASH header — a function of the source bytes — changes, re-deriving a
     DIFFERENT .pyc sha) -> REDERIVATION_MISMATCH. manifest.files for the source
     is re-aligned so FileIntegrity does not fire first.

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

# NOTE: the verifier's recompute primitive (primitives/build_real_compiler.py) is
# deliberately NOT imported here. The claim is derived from the producer artifact,
# and the primitive must resolve ONLY via dispatch's core auto-registration.
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from examples._spec_pinned_overlay import apply_overlay, compute_anchor  # noqa: E402

_PILOT_DIR = _PKG_ROOT / "examples" / "build_real_compiler_minimal"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "build_real_compiler.spec.json"
_OUTPUT_ID = "pyc_sha"
_TYPE_KEY = "pyc_sha"
_ARTIFACT_REL = "payload/artifacts/mod_a.pyc"
_SOURCE_REL = "sources/mod_a.py"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _build(out_dir: Path, *, claimed_override=None):
    """Build a spec-pinned build_real_compiler bundle producer-side.

    The base bundle is produced by the pilot's real _build_bundle.py (sources/,
    recipe/build_recipe.json, payload/artifacts/*.pyc, manifest). The HONEST
    claimed pyc_sha is sha256(payload/artifacts/mod_a.pyc) — the producer's OWN
    compiled-and-bundled .pyc bytes, independent of the verifier's recompile.
    """
    subprocess.run(
        [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(out_dir)],
        check=True,
        capture_output=True,
    )
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
    mp = out_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["typed_checks"] = ["file_integrity_many_small"]
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))
    return out_dir, compute_anchor(_SPEC_SRC)


def _realign_file_sha(bundle_dir: Path, rel: str) -> None:
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][rel] = _sha256((bundle_dir / rel).read_bytes())
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))


def _verify(bundle_dir: Path, anchor):
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()], spec_anchor=anchor
    ).verify(bundle_dir)


def test_promoted_generic_safe_path_and_faithfulness_pass(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    result = _verify(bundle_dir, anchor)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_promoted_tampered_value_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    claim_path = bundle_dir / "outputs" / f"{_OUTPUT_ID}.json"
    doc = json.loads(claim_path.read_bytes())
    honest = doc["value"]
    doc["value"] = ("0" if honest[0] != "0" else "1") + honest[1:]
    assert doc["value"] != honest
    claim_path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    _realign_file_sha(bundle_dir, f"outputs/{_OUTPUT_ID}.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert _reason_codes(result) == {"REDERIVATION_MISMATCH"}, _reason_codes(result)


def test_promoted_tampered_input_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Append a comment to sources/mod_a.py. Under CHECKED_HASH the .pyc header
    # embeds a hash of the source bytes, so a comment-only edit still changes the
    # recompiled .pyc sha — diverging from the (honest) producer-bundled claim.
    src_path = bundle_dir / _SOURCE_REL
    src_path.write_bytes(src_path.read_bytes() + b"\n# TAMPERED SOURCE COMMENT\n")
    _realign_file_sha(bundle_dir, _SOURCE_REL)

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert _reason_codes(result) == {"REDERIVATION_MISMATCH"}, _reason_codes(result)
