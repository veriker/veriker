"""Red-team B-4 regression — reserved C17/C20 fields disclosed as unverified.

attested_serving (C17) and semantic_fidelity (C20) are parsed into the manifest
but NOT verified at v0.3 (M0 stubs). An adversarial bundle can embed a
fabricated TEE measurement / semantic_fidelity=ENTAILMENT inside an otherwise-
green bundle. We do not fail closed (legit pilots carry these benignly) but the
CLI MUST emit a parsed-but-UNVERIFIED note so the PASS verdict cannot be read as
covering them.

Stdlib-only: json + the veriker.cli.verify helper.
"""

from __future__ import annotations

import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from veriker.cli.verify import _print_reserved_unverified_note  # noqa: E402


def _write(tmp_path: Path, manifest: dict) -> Path:
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return tmp_path


def _capture(bundle_dir: Path) -> str:
    buf = io.StringIO()
    with redirect_stdout(buf):
        _print_reserved_unverified_note(bundle_dir)
    return buf.getvalue()


def test_no_note_when_reserved_fields_absent(tmp_path: Path):
    _write(tmp_path, {"schema_version": "v0.3"})
    assert _capture(tmp_path) == ""


def test_note_emitted_for_attested_serving(tmp_path: Path):
    _write(
        tmp_path,
        {
            "schema_version": "v0.3",
            "attested_serving": {"tee_measurement": "ff" * 32, "at": "2099-01-01"},
        },
    )
    out = _capture(tmp_path)
    assert "NOT VERIFIED" in out
    assert "attested_serving" in out


def test_note_emitted_for_semantic_fidelity(tmp_path: Path):
    _write(tmp_path, {"semantic_fidelity": "ENTAILMENT"})
    out = _capture(tmp_path)
    assert "NOT VERIFIED" in out
    assert "semantic_fidelity" in out


def test_note_lists_both_when_both_present(tmp_path: Path):
    _write(
        tmp_path,
        {"attested_serving": {"x": 1}, "semantic_fidelity": "ENTAILMENT"},
    )
    out = _capture(tmp_path)
    assert "attested_serving" in out and "semantic_fidelity" in out
