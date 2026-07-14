"""tests/test_recipe_tabular_promoted.py — the `tabular` shape is PROMOTED into
the shippable core registry (RECIPE_BOOK.md).

Two things are proven, deliberately without a tautology:

  GENERIC SAFE PATH. The bundle is verified by a BARE BundleVerifier under an
  auditor SpecAnchor with NO demo-local register_primitive and WITHOUT importing
  the primitive module at all. The only thing that resolves the recompute is the
  core registry auto-registration (run_spec_pinned_dispatch ->
  _ensure_primitives_loaded -> import primitives -> tabular self-registers). If
  tabular were not promoted, the dispatch would fail UNKNOWN_PRIMITIVE.

  PRODUCER-FAITHFULNESS (not f(x)==f(x)). The producer's claimed result_sha is
  the SHA-256 of the producer's OWN payload/result.csv — emitted by
  _build_bundle.py's aggregation+serialization, an INDEPENDENT code copy from the
  verifier's primitives/tabular.py. The verifier recomputes its own result-CSV
  sha from the committed query + input and compares. An honest PASS therefore
  proves the two independent aggregation/serialization paths agree byte-for-byte
  — if they ever drift, this test FAILS. The claim is never routed through the
  verifier's own compute_result_sha.

Run SOLO — shared bundle basenames collide in one pytest process.

Surfaces:
  1. Honest bundle -> PASS (generic safe path AND producer-faithfulness).
  2. Tampered claimed value (flip one hex char) -> REDERIVATION_MISMATCH.
  3. Tampered committed input (mutate a data/sales.csv row) -> REDERIVATION_MISMATCH.
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

# NOTE: the verifier's recompute primitive (primitives/tabular.py) is deliberately
# NOT imported here. The claim is derived from the producer artifact, and the
# primitive must resolve ONLY via dispatch's core auto-registration.
from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
from examples._spec_pinned_overlay import apply_overlay, compute_anchor  # noqa: E402

_PILOT_DIR = _PKG_ROOT / "examples" / "tabular_minimal"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "tabular.spec.json"
_OUTPUT_ID = "result_sha"
_TYPE_KEY = "result_sha"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


def _build(out_dir: Path, *, claimed_override=None):
    """Build a spec-pinned tabular bundle producer-side. Returns (bundle, anchor).

    The base bundle is produced by the pilot's real _build_bundle.py (data/sales.csv,
    spec/query.json, payload/result.csv, manifest). The HONEST claimed result_sha is
    sha256(payload/result.csv) — the producer's OWN emitted artifact, computed by an
    aggregation code copy independent of the verifier primitive. The generic β overlay
    then adds the auditor spec, the producer claimed-value file, and manifest.outputs.
    """
    subprocess.run(
        [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(out_dir)],
        check=True,
        capture_output=True,
    )
    # Producer-side claim: hash the producer's independently-emitted result.csv.
    claimed = _sha256((out_dir / "payload" / "result.csv").read_bytes())
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
    # Honest PASS proves BOTH: the generic verifier resolves tabular via core
    # auto-registration (no import, no demo registration), AND the verifier's
    # recompute agrees byte-for-byte with the producer's independent result.csv.
    bundle_dir, anchor = _build(tmp_path / "bundle")
    result = _verify(bundle_dir, anchor)
    assert result.ok, [(f.check_name, f.reason_code, f.detail) for f in result.failures]


def test_promoted_tampered_value_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Flip one hex char of the producer's claimed result_sha.
    claim_path = bundle_dir / "outputs" / f"{_OUTPUT_ID}.json"
    doc = json.loads(claim_path.read_bytes())
    honest = doc["value"]
    doc["value"] = ("0" if honest[0] != "0" else "1") + honest[1:]
    assert doc["value"] != honest
    claim_path.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    _realign_file_sha(bundle_dir, f"outputs/{_OUTPUT_ID}.json")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)


def test_promoted_tampered_input_fails(tmp_path):
    bundle_dir, anchor = _build(tmp_path / "bundle")
    # Mutate the first data row in data/sales.csv (header is line 0).
    sales_path = bundle_dir / "data" / "sales.csv"
    lines = sales_path.read_bytes().decode("utf-8").split("\n")
    cols = lines[1].split(",")  # region,product,units,revenue
    cols[3] = str(int(cols[3]) + 1000)
    lines[1] = ",".join(cols)
    sales_path.write_bytes("\n".join(lines).encode("utf-8"))
    _realign_file_sha(bundle_dir, "data/sales.csv")

    result = _verify(bundle_dir, anchor)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result), _reason_codes(result)
