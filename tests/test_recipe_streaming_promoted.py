"""tests/test_recipe_streaming_promoted.py — the `streaming aggregation` shape is
PROMOTED into the shippable core registry (RECIPE_BOOK.md).

Two things are proven, deliberately without a tautology:

  GENERIC SAFE PATH. The bundle is verified by a BARE BundleVerifier under an
  auditor SpecAnchor with NO demo-local register_primitive and WITHOUT importing
  the primitive module at all. The only thing that resolves the recompute is the
  core registry auto-registration (run_spec_pinned_dispatch ->
  _ensure_primitives_loaded -> import primitives -> streaming self-registers). If
  streaming were not promoted, the dispatch would fail UNKNOWN_PRIMITIVE.

  PRODUCER-FAITHFULNESS (not f(x)==f(x)). The producer's claimed value is the
  per-window aggregate list written by _build_bundle.py's _run_windowing into
  payload/checkpoint.json — NOT routed through the verifier's own
  compute_window_aggregates. The verifier recomputes its own window-aggregate
  list from the committed event stream + windowing spec and compares element-wise.

  Honesty note: the producer's _run_windowing and the verifier's
  primitives/streaming.py.compute_window_aggregates are a VERBATIM copy of the
  same aggregation logic held in sync by the re-export shim — they are NOT two
  independently-authored implementations, so an honest PASS is not a cross-check
  between two independent algorithms. What this test DOES guarantee is drift
  detection: it derives the claim from the PRODUCER artifact (checkpoint.json) and
  the recompute from the verifier copy, so if anyone ever edits one copy without
  the other, the two paths disagree and this test FAILS.

Run SOLO — shared bundle basenames collide in one pytest process.

Surfaces:
  1. Honest bundle -> PASS (generic safe path AND producer-faithfulness).
  2. Tampered claimed value (perturb one window's aggregate by +1) ->
     REDERIVATION_MISMATCH.
  3. Tampered committed input (mutate one event's value so its window aggregate
     differs) -> REDERIVATION_MISMATCH (manifest SHA re-aligned so FileIntegrity
     does not fire first).

Stdlib-only orchestration; the build runs the pilot's real producer _build_bundle.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

# NOTE: the verifier's recompute primitive (primitives/streaming.py) is
# deliberately NOT imported here. The claim is derived from the producer artifact,
# and the primitive must resolve ONLY via dispatch's core auto-registration.
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from examples._spec_pinned_overlay import apply_overlay, compute_anchor  # noqa: E402

_PILOT_DIR = _PKG_ROOT / "examples" / "streaming_minimal"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "streaming.spec.json"
_OUTPUT_ID = "streaming_window_aggregates"
_TYPE_KEY = "streaming_window_aggregates"


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _sha256(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def _realign_file_sha(bundle_dir: Path, rel: str) -> None:
    """Recompute and store the manifest SHA for one file so FileIntegrity does not
    fire before the re-derivation dispatch can be observed."""
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][rel] = _sha256((bundle_dir / rel).read_bytes())
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))


def _build(out_dir: Path, *, claimed_override=None):
    """Build a spec-pinned streaming bundle producer-side. Returns (bundle_dir, anchor).

    The base bundle is produced by the pilot's real _build_bundle.py
    (events/stream.jsonl, spec/segmentation.json, payload/checkpoint.json,
    manifest). The HONEST claimed value is the per-window aggregate list read from
    payload/checkpoint.json — the producer's OWN emitted artifact, computed by the
    producer's aggregation copy (a verbatim copy of the verifier primitive held in
    sync by the re-export shim, not an independently-authored implementation). The
    generic beta overlay then adds the auditor spec, the producer claimed-value
    file, and manifest.outputs.
    """
    subprocess.run(
        [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(out_dir)],
        check=True,
        capture_output=True,
    )
    # Producer-side claim: read the producer's emitted checkpoint. This is NOT
    # routed through the verifier's compute_window_aggregates — it is the list
    # produced by _build_bundle._run_windowing (a verbatim sync-held copy) and
    # written to checkpoint.json.
    claimed = json.loads((out_dir / "payload" / "checkpoint.json").read_bytes())
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


def _verify(bundle_dir: Path, anchor):
    # BARE verifier: FileIntegrity + spec-pinned dispatch under the auditor anchor.
    # NO register_primitive — the recompute resolves only via the CORE registry.
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()], spec_anchor=anchor
    ).verify(bundle_dir)


def test_promoted_generic_safe_path_and_faithfulness_pass(tmp_path):
    # Honest PASS proves BOTH: the generic verifier resolves streaming via core
    # auto-registration (no import, no demo registration), AND the verifier's
    # recompute agrees element-wise with the producer's checkpoint.json (the
    # producer copy being a verbatim sync-held copy, so this is a drift check, not
    # an independent-implementation cross-check).
    bundle_dir, anchor = _build(tmp_path / "bundle")
    result = _verify(bundle_dir, anchor)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_promoted_tampered_value_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Perturb the first window's aggregate by +1.
    claim_path = bundle_dir / "outputs" / f"{_OUTPUT_ID}.json"
    doc = json.loads(claim_path.read_bytes())
    honest = doc["value"]
    assert len(honest) >= 1, "expected at least one window"
    tampered = [dict(w) for w in honest]
    tampered[0]["aggregate"] = tampered[0]["aggregate"] + 1
    assert tampered != honest
    doc["value"] = tampered
    claim_path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    _realign_file_sha(bundle_dir, f"outputs/{_OUTPUT_ID}.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_promoted_tampered_input_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Mutate the first event's value in events/stream.jsonl so its window's
    # aggregate re-derives differently than the (honest) claimed value.
    stream_path = bundle_dir / "events" / "stream.jsonl"
    raw = stream_path.read_bytes()
    lines = raw.splitlines()
    first = json.loads(lines[0])
    first["value"] = first["value"] + 1000
    lines[0] = json.dumps(first, separators=(",", ":")).encode("utf-8")
    new_bytes = b"\n".join(lines) + b"\n"
    stream_path.write_bytes(new_bytes)
    _realign_file_sha(bundle_dir, "events/stream.jsonl")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)
