"""tests/test_dispatch_output_id_safety.py — output_id path-traversal hardening.

Redteam regression: run_spec_pinned_dispatch interpolates output_id straight
into outputs/<output_id>.json. Without a grammar a hostile manifest could set
output_id to a traversal string and steer the verifier's claimed-value read
outside outputs/ — undermining the "safe re-derivation" story, whose threat
model explicitly includes a MALICIOUS producer who signs the manifest.

Self-contained: we mint a minimal auditor-anchored spec set inline (one type
bound to a no-op primitive via the param-less 'exact' comparator) so
build_anchored_spec_set succeeds and the per-output loop is reached, then inject
hostile output_ids. No dependency on any examples/ pilot — this test ships and
runs inside the open-tier export.

Asserts:
  * a traversal output_id records an OUTPUT_ID_UNSAFE failure (fail-closed,
    never a crash) and is refused BEFORE any claimed-value read outside outputs/;
  * a legitimate dotted output_id passes the grammar (it proceeds far enough to
    fail later on primitive resolution, proving the grammar did not reject it);
  * the grammar accepts every real output_id shape and rejects traversal.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from audit_bundle.rederivation.dispatch import (
    _OUTPUT_ID_RE,
    run_spec_pinned_dispatch,
)
from audit_bundle.rederivation.spec_binding import SpecAnchor

_SPEC_BASENAME = "redteam.spec.json"
_SPEC_ID = "redteam-output-id-safety"
_TYPE_KEY = "t1"


class _Manifest:
    """Duck-typed manifest the dispatch loop reads (.spec_files, .outputs)."""

    def __init__(self, spec_files, outputs):
        self.spec_files = spec_files
        self.outputs = outputs


def _anchored_bundle(tmp_path: Path, outputs):
    """A minimal bundle + manifest + auditor anchor that resolves cleanly, so the
    per-output loop (where the output_id grammar lives) is exercised. The bound
    primitive_id is intentionally unregistered — resolution happens AFTER the
    grammar check, so a legit id surfaces UNKNOWN_PRIMITIVE while a hostile id is
    stopped earlier at OUTPUT_ID_UNSAFE."""
    bundle = tmp_path / "bundle"
    (bundle / "spec").mkdir(parents=True, exist_ok=True)
    spec = {
        "spec_id": _SPEC_ID,
        "types": {
            _TYPE_KEY: {
                "primitive_id": "noop-unregistered",
                "comparator": {"kind": "exact", "params": {}},
            }
        },
    }
    raw = json.dumps(spec).encode("utf-8")
    (bundle / "spec" / _SPEC_BASENAME).write_bytes(raw)
    anchor = SpecAnchor(allowed={_SPEC_ID: hashlib.sha256(raw).hexdigest()})
    manifest = _Manifest(spec_files=[_SPEC_BASENAME], outputs=outputs)
    return bundle, manifest, anchor


def _run(tmp_path, outputs):
    bundle, manifest, anchor = _anchored_bundle(tmp_path, outputs)
    failures = run_spec_pinned_dispatch(bundle, manifest, anchor)
    return bundle, {f.reason_code for f in failures}


# ---------------------------------------------------------------------------
# Integration: traversal output_id is hard-rejected, no escape read
# ---------------------------------------------------------------------------


def test_traversal_output_id_is_rejected_and_no_escape_read(tmp_path):
    bundle, _, _ = _anchored_bundle(tmp_path, [])
    # '../secret' from outputs/ resolves to bundle/secret.json. Plant a decoy
    # there: if the read were not refused, its 'value' would be substituted as
    # the producer's claimed value from OUTSIDE outputs/.
    (bundle / "secret.json").write_text(json.dumps({"value": "LEAKED"}))

    failures = run_spec_pinned_dispatch(
        bundle,
        _Manifest([_SPEC_BASENAME], [{"output_id": "../secret", "type": _TYPE_KEY}]),
        SpecAnchor(
            allowed={
                _SPEC_ID: hashlib.sha256(
                    (bundle / "spec" / _SPEC_BASENAME).read_bytes()
                ).hexdigest()
            }
        ),
    )
    codes = {f.reason_code for f in failures}
    assert "OUTPUT_ID_UNSAFE" in codes, codes
    # Refused BEFORE touching the file — no claimed-value read outside outputs/.
    assert "CLAIMED_VALUE_MALFORMED" not in codes
    assert "CLAIMED_VALUE_MISSING" not in codes
    assert "REDERIVATION_MISMATCH" not in codes


def test_assorted_traversal_shapes_all_rejected(tmp_path):
    for i, hostile in enumerate(
        (
            "../secret",
            "../../etc/passwd",
            "/etc/passwd",
            "..",
            ".",
            "sub/dir",
            "back\\slash",
            "trail/",
            ".hidden",
        )
    ):
        sub = tmp_path / f"c{i}"
        sub.mkdir()
        _, codes = _run(sub, [{"output_id": hostile, "type": _TYPE_KEY}])
        assert "OUTPUT_ID_UNSAFE" in codes, f"{hostile!r} not rejected: {codes}"


def test_legit_dotted_output_id_passes_grammar(tmp_path):
    # A genuine dotted id (real bundles use e.g. 'P6.1_trust_in_ai__DE__2026Q3')
    # must NOT be rejected by the grammar. With its claimed-value file present it
    # safely traverses the whole read path (grammar -> containment -> claimed
    # read) and only fails later at primitive resolution — proving the id was
    # admitted and read from INSIDE outputs/.
    legit_id = "P6.1_trust_in_ai__DE"
    bundle, manifest, anchor = _anchored_bundle(
        tmp_path, [{"output_id": legit_id, "type": _TYPE_KEY}]
    )
    out_dir = bundle / "outputs"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{legit_id}.json").write_text(json.dumps({"value": 1}))

    failures = run_spec_pinned_dispatch(bundle, manifest, anchor)
    codes = {f.reason_code for f in failures}
    assert "OUTPUT_ID_UNSAFE" not in codes, codes
    assert "UNKNOWN_PRIMITIVE" in codes, codes


# ---------------------------------------------------------------------------
# Grammar unit checks
# ---------------------------------------------------------------------------


def test_grammar_accepts_real_shapes():
    for ok in (
        "P6.1_trust_in_ai__DE__2026Q3",
        "energy-score-2026-04-28T23:00:00Z",
        "E0008-2026-05",
        "alerted_sources",
        "climate-total-scope3-001",
        "result_sha",
    ):
        assert _OUTPUT_ID_RE.match(ok), ok


def test_grammar_rejects_traversal_and_separators():
    for bad in ("../x", "..", ".", "/abs", "a/b", "a\\b", ".hidden", "", "x/../y"):
        assert not _OUTPUT_ID_RE.match(bad), bad
