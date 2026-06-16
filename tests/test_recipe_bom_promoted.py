"""tests/test_recipe_bom_promoted.py — the `bom` shape is PROMOTED into
the shippable core registry (RECIPE_BOOK.md).

Two things are proven, deliberately without a tautology:

  GENERIC SAFE PATH. The bundle is verified by a BARE BundleVerifier under an
  auditor SpecAnchor with NO demo-local register_primitive and WITHOUT importing
  the primitive module at all. The only thing that resolves the recompute is the
  core registry auto-registration (run_spec_pinned_dispatch ->
  _ensure_primitives_loaded -> import primitives -> bom self-registers). If
  bom were not promoted, the dispatch would fail UNKNOWN_PRIMITIVE.

  PRODUCER-FAITHFULNESS (not f(x)==f(x)). The producer's claimed resolved_tree
  is read from the producer's OWN payload/resolved_tree.json — emitted by
  _build_bundle.py's _bfs_resolve() + tree construction. The verifier recomputes
  the full resolved_tree dict from the committed lockfile and compares. An honest
  PASS proves the verifier's reimplementation agrees element-for-element with the
  producer's emitted artifact. If the two implementations ever drift (edit-drift),
  this test FAILS. The claim is never routed through the verifier's own
  compute_resolved_tree — it is read from the producer artifact.

  Note: the test catches producer↔verifier OUTPUT divergence (edit-drift).
  It does not claim to detect bugs that are identical in both implementations
  (shared-logic bugs); the verifier's recompute is a faithful verifier-side
  reimplementation, not a separate codebase.

Run SOLO — shared bundle basenames collide in one pytest process.

Surfaces:
  1. Honest bundle -> PASS (generic safe path AND producer-faithfulness).
  2. Tampered claimed value (swap two package ids in resolution_order within the
     full tree dict) -> REDERIVATION_MISMATCH.
  3. Tampered committed input (mutate a lockfile dep) -> REDERIVATION_MISMATCH.
For (2)/(3) the manifest file SHA is re-aligned so FileIntegrity does not fire
first — isolating the re-derivation mismatch from a plain integrity failure.
(Only the value-tamper is a failure FileIntegrity could NEVER catch: the
claimed-value file is producer-controlled and self-pinned; the re-derivation
dispatch is what catches it.)

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

# NOTE: the verifier's recompute primitive (primitives/bom.py) is deliberately
# NOT imported here. The claim is derived from the producer artifact, and the
# primitive must resolve ONLY via dispatch's core auto-registration.
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from examples._spec_pinned_overlay import apply_overlay, compute_anchor  # noqa: E402

_PILOT_DIR = _PKG_ROOT / "examples" / "bom_minimal"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "bom.spec.json"
_OUTPUT_ID = "bom_resolved_tree"
_TYPE_KEY = "bom_resolved_tree"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _build(out_dir: Path, *, claimed_override=None):
    """Build a spec-pinned bom bundle producer-side. Returns (bundle_dir, anchor).

    The base bundle is produced by the pilot's real _build_bundle.py
    (lockfile/lockfile.json, payload/resolved_tree.json, manifest). The HONEST
    claimed resolved_tree is read from the producer's OWN independently-emitted
    artifact (payload/resolved_tree.json) — a dict {root, nodes, resolution_order}
    produced by _build_bundle._bfs_resolve(). The generic β overlay then adds
    the auditor spec, the producer claimed-value file, and manifest.outputs.
    """
    subprocess.run(
        [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(out_dir)],
        check=True,
        capture_output=True,
    )
    # Producer-side claim: read the full resolved_tree dict from the producer's
    # independently-emitted payload/resolved_tree.json (NOT from the verifier).
    tree = json.loads((out_dir / "payload" / "resolved_tree.json").read_bytes())
    claimed = tree  # full {root, nodes, resolution_order} dict
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
    # Honest PASS proves BOTH: the generic verifier resolves bom via core
    # auto-registration (no import, no demo registration), AND the verifier's
    # recompute agrees element-for-element with the producer's independently-emitted
    # resolved_tree.json (full tree dict: root, nodes, resolution_order).
    bundle_dir, anchor = _build(tmp_path / "bundle")
    result = _verify(bundle_dir, anchor)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_promoted_tampered_value_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Swap the first two package ids in resolution_order within the claimed full tree.
    claim_path = bundle_dir / "outputs" / f"{_OUTPUT_ID}.json"
    doc = json.loads(claim_path.read_bytes())
    honest_tree = doc["value"]
    honest_order = list(honest_tree["resolution_order"])
    assert len(honest_order) >= 2, "expected at least 2 packages in resolution_order"
    # Swap first two entries — changes resolution_order without altering the set.
    tampered_order = [honest_order[1], honest_order[0]] + honest_order[2:]
    assert tampered_order != honest_order
    tampered_tree = dict(honest_tree)
    tampered_tree["resolution_order"] = tampered_order
    doc["value"] = tampered_tree
    claim_path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    _realign_file_sha(bundle_dir, f"outputs/{_OUTPUT_ID}.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_promoted_tampered_input_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Remove a dep from the lockfile so the BFS walk yields a different resolved tree.
    lockfile_path = bundle_dir / "lockfile" / "lockfile.json"
    lockfile = json.loads(lockfile_path.read_bytes())
    # Drop the first dep of the root package — changes the BFS frontier, which
    # changes the node set, depths, and resolution_order in the recomputed tree.
    root_id = lockfile["root"]
    orig_deps = list(lockfile["packages"][root_id]["deps"])
    assert len(orig_deps) >= 1, "root must have at least one dep"
    lockfile["packages"][root_id]["deps"] = orig_deps[1:]
    lockfile_path.write_bytes(
        json.dumps(lockfile, indent=2, sort_keys=True).encode("utf-8")
    )
    _realign_file_sha(bundle_dir, "lockfile/lockfile.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)
