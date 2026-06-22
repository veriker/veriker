"""tests/test_path_containment_sweep.py — path-containment sibling sweep regressions.

Follow-up to the H1 fix (fragment_attestation snapshot traversal): the same
"a bundle-controlled path joined and read WITHOUT the fail-closed containment
helper" pattern recurred at sibling sites. Each must fail closed (refuse the
read) on a `..`-traversal / absolute path rather than reading an out-of-bundle
host file.

Sites covered:
  * rederivation/primitives/spectra_span.py      — source_cid -> corpus/<cid>.txt
  * plugins/file_integrity_many_small.py         — manifest.files key -> read
  * plugins/reference/span_re_derivation.py       — source_cid -> corpus/<cid>.txt
  * plugins/reference/control_rederivation.py     — evidence_ref -> bundle read
  * plugins/reference/aigov_rederivation.py       — evidence_ref -> bundle read
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# Raw-join sites (evidence_ref used verbatim): a bare ".." is a traversal.
HOSTILE = ["../../etc/passwd", "/etc/passwd", "..", "../secret"]
# Suffixed sites (f"{source_cid}.txt"): a bare ".." becomes the literal
# filename "...txt" (contained, not an escape), so it's excluded here — these
# must still escape even with the .txt suffix appended.
HOSTILE_SUFFIXED = ["../../etc/passwd", "/etc/passwd", "../secret"]


# ---------------------------------------------------------------------------
# spectra_span core primitive (the live-core H1 twin)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("source_cid", HOSTILE_SUFFIXED)
def test_spectra_span_source_cid_traversal_fails_closed(tmp_path: Path, source_cid):
    from audit_bundle.plugin import ParsedInputs
    from audit_bundle.rederivation.primitives.spectra_span import SpectraSpanRecompute

    (tmp_path / "inputs").mkdir()
    (tmp_path / "inputs" / "span_claim.json").write_text(
        json.dumps({"source_cid": source_cid, "fragment_id": 0}), encoding="utf-8"
    )
    (tmp_path / "corpus").mkdir()
    # Containment rejects BEFORE any read -> ValueError -> RECOMPUTE_ERROR.
    with pytest.raises(ValueError):
        SpectraSpanRecompute().recompute(ParsedInputs(bundle_dir=tmp_path), {})


def test_spectra_span_genuine_source_cid_still_recomputes(tmp_path: Path):
    from audit_bundle.plugin import ParsedInputs
    from audit_bundle.rederivation.primitives.spectra_span import SpectraSpanRecompute

    (tmp_path / "inputs").mkdir()
    (tmp_path / "inputs" / "span_claim.json").write_text(
        json.dumps({"source_cid": "doc1", "fragment_id": 0}), encoding="utf-8"
    )
    (tmp_path / "corpus").mkdir()
    (tmp_path / "corpus" / "doc1.txt").write_text("First sentence. Second.", "utf-8")
    out = SpectraSpanRecompute().recompute(ParsedInputs(bundle_dir=tmp_path), {})
    assert out.value == "First sentence"


# ---------------------------------------------------------------------------
# file_integrity_many_small plugin (parallel to the hardened core step)
# ---------------------------------------------------------------------------


class _Manifest:
    def __init__(self, files):
        self.files = files


@pytest.mark.parametrize("rel", ["../../etc/passwd", "/etc/passwd", "/", "."])
def test_file_integrity_many_small_unsafe_path_rejected(tmp_path: Path, rel):
    from audit_bundle.plugins.file_integrity_many_small import FileIntegrityManySmall

    res = FileIntegrityManySmall().check(tmp_path, _Manifest({rel: "00" * 32}))
    assert not res.ok
    assert res.reason_code == "UNSAFE_FILE_PATH", res.reason_code


# ---------------------------------------------------------------------------
# reference subprocess packs — shared _resolve_within containment helper
# ---------------------------------------------------------------------------


def test_reference_pack_resolve_within_helpers(tmp_path: Path):
    from audit_bundle.plugins.reference.aigov_rederivation import (
        _resolve_within as arw,
    )
    from audit_bundle.plugins.reference.control_rederivation import (
        _resolve_within as crw,
    )

    (tmp_path / "ok.json").write_text("{}", encoding="utf-8")
    for fn in (crw, arw):
        for hostile in HOSTILE:
            assert fn(tmp_path, hostile) is None, hostile
        assert fn(tmp_path, "ok.json") is not None


@pytest.mark.parametrize("source_cid", HOSTILE_SUFFIXED)
def test_span_re_derivation_source_cid_traversal_fails_closed(tmp_path, source_cid):
    from audit_bundle.plugins.reference.span_re_derivation import _check_span

    rec = {
        "output_text": "hello world",
        "span": {"start": 0, "end": 5},
        "source_cid": source_cid,
        "fragment_id": 0,
    }
    err = _check_span(tmp_path, rec, 0)
    assert err is not None
    assert "outside corpus" in err, err
