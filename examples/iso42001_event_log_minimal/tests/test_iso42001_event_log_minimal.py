"""tests/test_iso42001_event_log_minimal.py — tamper + §4a attack tests.

ISO/IEC 42001 A.6 event-log integrity re-derivation (hash-chain head, exact).
Surfaces:

  0. Unit: head is deterministic; reorder changes it; field edit changes it.
  1. Happy path -> PASS.
  2. Digest mutation (exact): doctor the claimed head -> REDERIVATION_MISMATCH.
  3. Event field tamper: edit an event 'action' without updating manifest.files
     -> BAD_FILE_SHA + REDERIVATION_MISMATCH (head changes).
  4. Event reorder: swap two events -> head changes (order-sensitive) ->
     BAD_FILE_SHA + REDERIVATION_MISMATCH.
  5. Substitute-spec -> AnchorViolation (Axis-1 anchor).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

_TEST_DIR = Path(__file__).resolve().parent
_PILOT_DIR = _TEST_DIR.parent
_PKG_ROOT = _PILOT_DIR.parents[1]

if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))
if str(_PILOT_DIR) not in sys.path:
    sys.path.insert(0, str(_PILOT_DIR))

from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall  # noqa: E402
from audit_bundle.rederivation.registry import register_primitive  # noqa: E402
from audit_bundle.rederivation.spec_binding import SpecAnchor  # noqa: E402
from audit_bundle.verifier import BundleVerifier  # noqa: E402
import iso42001_event_log_recompute as _prim_mod  # noqa: E402

register_primitive(_prim_mod.Iso42001LogChainHeadRecompute())

_SPEC_SRC = _PILOT_DIR / "spec_pinned" / "iso42001_event_log.spec.json"
_BUILD_SCRIPT = _PILOT_DIR / "_build_bundle.py"
_CLAIM_REL = "outputs/log_chain_head_digest.json"


def _build(out_dir: Path) -> None:
    subprocess.run(
        [sys.executable, str(_BUILD_SCRIPT), "--out-dir", str(out_dir)],
        capture_output=True,
        check=True,
    )


def _anchor() -> SpecAnchor:
    raw = _SPEC_SRC.read_bytes()
    doc = json.loads(raw)
    return SpecAnchor(allowed={doc["spec_id"]: hashlib.sha256(raw).hexdigest()})


def _verifier(anchor: SpecAnchor | None = None) -> BundleVerifier:
    return BundleVerifier(
        plugins=[FileIntegrityManySmall()],
        spec_anchor=anchor if anchor is not None else _anchor(),
    )


def _reason_codes(result) -> set[str]:
    return {f.reason_code for f in result.failures}


# ---------------------------------------------------------------------------
# 0. Unit — determinism + order/edit sensitivity
# ---------------------------------------------------------------------------


def test_chain_properties():
    evs = [
        {"seq": 1, "action": "a"},
        {"seq": 2, "action": "b"},
        {"seq": 3, "action": "c"},
    ]
    head = _prim_mod.compute_log_head_digest(evs)
    assert len(head) == 64
    # Deterministic
    assert _prim_mod.compute_log_head_digest(evs) == head
    # Reorder changes the head
    reordered = [evs[0], evs[2], evs[1]]
    assert _prim_mod.compute_log_head_digest(reordered) != head
    # Field edit changes the head
    edited = [dict(evs[0], action="A"), evs[1], evs[2]]
    assert _prim_mod.compute_log_head_digest(edited) != head


# ---------------------------------------------------------------------------
# 1. Happy path
# ---------------------------------------------------------------------------


def test_honest_pass(tmp_path):
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)
    result = _verifier().verify(bundle_dir)
    assert result.ok, [
        (f.check_name, f.reason_code, f.detail) for f in result.failures
    ]


# ---------------------------------------------------------------------------
# 2. Digest mutation (exact)
# ---------------------------------------------------------------------------


def test_digest_mutation_fails(tmp_path):
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)
    p = bundle_dir / _CLAIM_REL
    head = json.loads(p.read_bytes())["value"]
    # flip the last hex nibble
    doctored = head[:-1] + ("0" if head[-1] != "0" else "1")
    nb = json.dumps({"value": doctored}, indent=2).encode("utf-8")
    p.write_bytes(nb)
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["files"][_CLAIM_REL] = hashlib.sha256(nb).hexdigest()
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))

    result = _verifier().verify(bundle_dir)
    assert not result.ok
    assert "REDERIVATION_MISMATCH" in _reason_codes(result)


# ---------------------------------------------------------------------------
# 3. Event field tamper
# ---------------------------------------------------------------------------


def test_event_field_tamper_fails(tmp_path):
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)
    lp = bundle_dir / "inputs" / "event_log.json"
    doc = json.loads(lp.read_bytes())
    doc["events"][3]["action"] = "policy_threshold_SILENTLY_CHANGED"
    lp.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    # Do NOT update manifest.files -> BAD_FILE_SHA.
    result = _verifier().verify(bundle_dir)
    assert not result.ok
    rc = _reason_codes(result)
    assert "bad_file_sha" in rc or "plugin_failed" in rc, rc
    assert "REDERIVATION_MISMATCH" in rc, rc


# ---------------------------------------------------------------------------
# 4. Event reorder (order-sensitive chain)
# ---------------------------------------------------------------------------


def test_event_reorder_fails(tmp_path):
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)
    lp = bundle_dir / "inputs" / "event_log.json"
    doc = json.loads(lp.read_bytes())
    ev = doc["events"]
    ev[1], ev[2] = ev[2], ev[1]  # swap two events; head must change
    lp.write_bytes(json.dumps(doc, indent=2).encode("utf-8"))
    result = _verifier().verify(bundle_dir)
    assert not result.ok
    rc = _reason_codes(result)
    assert "bad_file_sha" in rc or "plugin_failed" in rc, rc
    assert "REDERIVATION_MISMATCH" in rc, rc


# ---------------------------------------------------------------------------
# 5. Substitute-spec -> AnchorViolation
# ---------------------------------------------------------------------------


def test_substitute_spec_fails(tmp_path):
    bundle_dir = tmp_path / "bundle"
    _build(bundle_dir)
    # A substitute spec (same spec_id) binding the type to some other primitive.
    # Its SHA is not anchored -> not authoritative -> AnchorViolation.
    subst = json.dumps(
        {
            "spec_id": "iso42001.eventlog.v1",
            "types": {
                "log_chain_head_digest": {
                    "primitive_id": "some_weaker_digest_rule",
                    "comparator": {"kind": "exact", "params": {}},
                }
            },
        }
    ).encode("utf-8")
    sp = bundle_dir / "spec" / "iso42001_event_log.spec.json"
    sp.write_bytes(subst)
    mp = bundle_dir / "manifest.json"
    m = json.loads(mp.read_bytes())
    m["spec_files"]["iso42001_event_log.spec.json"] = hashlib.sha256(subst).hexdigest()
    mp.write_bytes(json.dumps(m, indent=2).encode("utf-8"))

    result = _verifier(_anchor()).verify(bundle_dir)
    assert not result.ok
    assert "AnchorViolation" in _reason_codes(result)
