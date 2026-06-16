"""tests/test_recipe_kg_promoted.py — the `knowledge-graph derivation` shape is
PROMOTED into the shippable core registry (RECIPE_BOOK.md).

Two things are proven, deliberately without a tautology:

  GENERIC SAFE PATH. The bundle is verified by a BARE BundleVerifier under an
  auditor SpecAnchor with NO demo-local register_primitive and WITHOUT importing
  the primitive module at all. The only thing that resolves the recompute is the
  core registry auto-registration (run_spec_pinned_dispatch ->
  _ensure_primitives_loaded -> import primitives -> kg self-registers). If kg
  were not promoted, the dispatch would fail UNKNOWN_PRIMITIVE.

  PRODUCER-FAITHFULNESS (not f(x)==f(x)). The producer's claimed answer_nodes
  is read directly from the producer's OWN emitted payload/query_result.json
  (the "answer_nodes" list the _build_bundle.py producer computed with its OWN
  independent BFS — _producer_bfs, a deliberately separate hand-copy that imports
  neither primitives/kg.py nor compute_answer_nodes — and wrote to disk). That
  list is an INDEPENDENT source from the verifier's primitives/kg.py BFS
  recompute. The verifier re-executes BFS over the committed triple set and
  compares via the `set` comparator. An honest PASS therefore proves the
  verifier's BFS recompute agrees with the producer's independently-COMPUTED
  answer_nodes — two separate BFS implementations over the same committed triples;
  if either ever drifts, this test FAILS. The claim is never routed through the
  verifier's own compute_answer_nodes.

Run SOLO — shared bundle basenames collide in one pytest process.

Surfaces:
  1. Honest bundle -> PASS (generic safe path AND producer-faithfulness).
  2. Tampered claimed value (swap one reachable node for an unreachable one)
     -> REDERIVATION_MISMATCH.
  3. Tampered committed input (append a new triple so BFS expands to a new node
     not in the honest claimed set) -> REDERIVATION_MISMATCH.
For (2)/(3) the manifest file SHA is re-aligned so FileIntegrity does not fire
first — isolating the re-derivation mismatch from a plain integrity failure.

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

# NOTE: the verifier's recompute primitive (primitives/kg.py) is deliberately
# NOT imported here. The claimed answer_nodes are read from the producer artifact,
# and the primitive must resolve ONLY via dispatch's core auto-registration.
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.plugins.dispatch_record_wellformed import (  # noqa: E402
    DispatchRecordWellformedCheck,
)
from audit_bundle.plugins.stamp_lattice import StampLatticeCheck  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from examples._spec_pinned_overlay import apply_overlay, compute_anchor  # noqa: E402

_PILOT_DIR = _PKG_ROOT / "examples" / "kg_minimal"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "kg.spec.json"
_OUTPUT_ID = "kg_answer_nodes"
_TYPE_KEY = "kg_answer_nodes"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _build(out_dir: Path, *, claimed_override=None):
    """Build a spec-pinned kg bundle producer-side. Returns (bundle_dir, anchor).

    The base bundle is produced by the pilot's real _build_bundle.py (kg/triples.jsonl,
    payload/query_result.json, manifest). The HONEST claimed answer_nodes is read
    from the producer's independently-emitted payload/query_result.json["answer_nodes"]
    — the list the producer computed at build time with its OWN independent BFS
    (_producer_bfs in _build_bundle.py), an INDEPENDENT implementation from the
    verifier primitive's BFS recompute. The generic β overlay then adds the auditor
    spec, the producer claimed-value file, and manifest.outputs.
    """
    subprocess.run(
        [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(out_dir)],
        check=True,
        capture_output=True,
    )
    # Producer-side claim: read answer_nodes from the producer's own emitted artifact.
    # This is NOT computed by the verifier's compute_answer_nodes — it is the list
    # the producer computed with its OWN independent BFS (_producer_bfs) and wrote
    # to payload/query_result.json at build time.
    qr = json.loads((out_dir / "payload" / "query_result.json").read_bytes())
    claimed = qr["answer_nodes"]  # producer artifact, independent of verifier recompute
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
        plugins=[
            FileIntegrityManySmall(),
            # The bundle carries dispatch_records; verify()'s stamp-claims
            # coverage guard fails closed unless C15 well-formedness and the
            # C14 lattice claim are both evaluated (2026-06-12). Orthogonal
            # to what this test proves (core-registry recompute path).
            DispatchRecordWellformedCheck(op_kinds_admitted=frozenset({"GRAPH_QUERY", "COMPUTE"})),
            StampLatticeCheck(),
        ],
        spec_anchor=anchor,
    ).verify(bundle_dir)


def test_promoted_generic_safe_path_and_faithfulness_pass(tmp_path):
    # Honest PASS proves BOTH: the generic verifier resolves kg via core
    # auto-registration (no import, no demo registration), AND the verifier's BFS
    # recompute agrees with the producer's independently-emitted answer_nodes.
    bundle_dir, anchor = _build(tmp_path / "bundle")
    result = _verify(bundle_dir, anchor)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_promoted_tampered_value_fails(tmp_path):
    # Swap one reachable node (ex:Dave) for an unreachable one (ex:Eve) in the
    # claimed answer_nodes — BFS recompute finds {ex:Bob, ex:Carol, ex:Dave},
    # claimed is {ex:Bob, ex:Carol, ex:Eve} -> REDERIVATION_MISMATCH.
    bundle_dir, anchor = _build(
        tmp_path / "bundle",
        claimed_override=["ex:Bob", "ex:Carol", "ex:Eve"],
    )
    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_promoted_tampered_input_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Append a new triple so the BFS expands to a new node (ex:Zoe) not in the
    # honest claimed set: ex:Bob ex:knows ex:Zoe. Bob is reached at depth 1 and
    # expanded (1 < max_depth=3), so ex:Zoe becomes reachable at depth 2.
    triples_path = bundle_dir / "kg" / "triples.jsonl"
    text = triples_path.read_text(encoding="utf-8")
    extra = json.dumps(
        {"object": "ex:Zoe", "predicate": "ex:knows", "subject": "ex:Bob"},
        sort_keys=True,
    )
    new_bytes = (text + extra + "\n").encode("utf-8")
    triples_path.write_bytes(new_bytes)
    # Re-align manifest SHA so FileIntegrityManySmall does not preempt the dispatch.
    _realign_file_sha(bundle_dir, "kg/triples.jsonl")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)
