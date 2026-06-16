"""examples/_spec_pinned_overlay.py — apply the β spec-pinned conformance shape
to an already-built audit bundle (shared by the 3 step-7 exemplars).

Given a base bundle (built by a pilot's existing _build_bundle.py) this:
  1. copies the AUDITOR's binding spec verbatim into bundle spec/<basename>;
  2. writes the producer's claimed value to outputs/<output_id>.json;
  3. writes any extra producer inputs (e.g. inputs/span_claim.json);
  4. rewrites manifest.json to carry the β shape:
       - manifest.outputs += {output_id, type, conforms_to: "spec/<basename>"}
       - manifest.spec_files[<basename>] = sha256(spec bytes)   (step-2 SHA pin)
       - manifest.files[<rel>] = sha256 for every new producer file (step-1 integ.)

The auditor's anchor is computed from the auditor's OWN committed copy of the
spec (compute_anchor) — NOT from the bundle — so a producer who ships a weaker
spec (different SHA) is not authoritative and fails closed.

Stdlib-only. This is build/example tooling, NOT verifier substrate.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_spec(spec_src_path: Path) -> tuple[str, str, bytes]:
    """Return (spec_id, basename, raw_bytes) for an auditor binding spec."""
    raw = spec_src_path.read_bytes()
    doc = json.loads(raw)
    spec_id = doc["spec_id"]
    return spec_id, spec_src_path.name, raw


def compute_anchor(spec_src_path: Path):
    """Build a SpecAnchor from the AUDITOR's committed spec copy: {spec_id: sha}."""
    from audit_bundle.rederivation.spec_binding import SpecAnchor

    spec_id, _basename, raw = read_spec(spec_src_path)
    return SpecAnchor(allowed={spec_id: _sha256(raw)})


def apply_overlay(
    bundle_dir: Path,
    *,
    spec_src_path: Path,
    output_id: str,
    type_key: str,
    claimed_value,
    input_files: dict[str, bytes] | None = None,
    spec_bytes_override: bytes | None = None,
) -> str:
    """Mutate a built bundle in place into the β spec-pinned shape.

    `spec_bytes_override` lets a test ship a DIFFERENT spec in the bundle than
    the auditor's anchored copy (the weak-spec-substitution attack). Returns the
    SHA written into manifest.spec_files for the spec.
    """
    bundle_dir = Path(bundle_dir)
    _spec_id, basename, raw = read_spec(spec_src_path)
    spec_in_bundle = spec_bytes_override if spec_bytes_override is not None else raw

    # 1. spec/<basename>
    spec_dir = bundle_dir / "spec"
    spec_dir.mkdir(parents=True, exist_ok=True)
    (spec_dir / basename).write_bytes(spec_in_bundle)
    spec_sha = _sha256(spec_in_bundle)

    # 2. extra producer inputs
    written: dict[str, str] = {}
    for rel, data in (input_files or {}).items():
        dst = bundle_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(data)
        written[rel] = _sha256(data)

    # 3. outputs/<output_id>.json
    out_dir = bundle_dir / "outputs"
    out_dir.mkdir(parents=True, exist_ok=True)
    claim_bytes = json.dumps({"value": claimed_value}, indent=2).encode("utf-8")
    (out_dir / f"{output_id}.json").write_bytes(claim_bytes)
    written[f"outputs/{output_id}.json"] = _sha256(claim_bytes)

    # 4. rewrite manifest.json
    manifest_path = bundle_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    manifest.setdefault("files", {})
    manifest.setdefault("spec_files", {})
    manifest["files"].update(written)
    manifest["spec_files"][basename] = spec_sha
    outputs = list(manifest.get("outputs", []))
    outputs.append(
        {"output_id": output_id, "type": type_key, "conforms_to": f"spec/{basename}"}
    )
    manifest["outputs"] = outputs
    manifest_path.write_bytes(json.dumps(manifest, indent=2).encode("utf-8"))
    return spec_sha
