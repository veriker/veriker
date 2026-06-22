"""L8 citation-integrity fault-injection matrix — the proof.

Widens the single-citation proof to a realistic
multi-citation bundle and exercises BOTH locked resolver kinds (byte-offset +
sentence-ID) plus the fail-closed edges the single-citation test doesn't cover.

Every reason code asserted below is a real code emitted by the default-ON
``FragmentAttestationCheck`` plugin (audit_bundle/plugins/fragment_attestation.py)
on the standard ``veriker/cli/verify.py`` path — none invented. The source snapshot IS the
ground truth; there is no answer key.

Matrix (see the audit-bundle contract §6):
  0 all ~4 citations verbatim (byte-offset + sentence-ID)  -> PASS
  1 one quote fabricated                                   -> FRAGMENT_MISQUOTE
  2 one offset pushed past the snapshot                    -> FRAGMENT_OFFSET_OUT_OF_BOUNDS
  3 sentence anchor under a drifted segmenter              -> SEGMENTER_MISMATCH
  4 a citation whose source isn't bundled                  -> FRAGMENT_SOURCE_UNRESOLVABLE
  5 the genuine sentence-ID citation alone                 -> PASS
"""

from __future__ import annotations

import sys

# Per the internal design notes — set FIRST.
sys.dont_write_bytecode = True

import subprocess  # noqa: E402
from pathlib import Path  # noqa: E402

_HERE = Path(__file__).resolve().parent
_PILOT_DIR = _HERE.parent
_PKG_ROOT = _PILOT_DIR.parents[1]  # .../v-kernel-audit-bundle
_VERIFY_PY = _PKG_ROOT / "veriker" / "cli" / "verify.py"

sys.path.insert(0, str(_PILOT_DIR))
from build_bundle import build_citation_bundle  # noqa: E402


def _run_verify(bundle_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(_VERIFY_PY), "--bundle-dir", str(bundle_dir)],
        capture_output=True,
        text=True,
        cwd=str(_PKG_ROOT),
        check=False,
    )


# --- Row 0: the full all-verbatim citation set verifies clean ---------------


def test_genuine_citation_set_attests_and_passes(tmp_path: Path) -> None:
    bundle = build_citation_bundle(tmp_path / "genuine")
    proc = _run_verify(bundle)
    assert proc.returncode == 0, (
        f"expected PASS, got rc={proc.returncode}\n{proc.stdout}\n{proc.stderr}"
    )
    assert "PASS  plugin:fragment_attestation" in proc.stdout, proc.stdout


# --- Row 1: a single fabricated quote fails the WHOLE bundle closed ----------


def test_one_fabricated_quote_fails_misquote(tmp_path: Path) -> None:
    bundle = build_citation_bundle(tmp_path / "fabricate", fault="fabricate")
    proc = _run_verify(bundle)
    assert proc.returncode == 1, (
        f"expected FAIL, got rc={proc.returncode}\n{proc.stdout}"
    )
    combined = proc.stdout + proc.stderr
    assert "FRAGMENT_MISQUOTE" in combined, combined
    assert "fragment_attestation" in combined, combined


# --- Row 2: an out-of-bounds offset fails closed ----------------------------


def test_offset_out_of_bounds_fails_closed(tmp_path: Path) -> None:
    bundle = build_citation_bundle(tmp_path / "oob", fault="offset_oob")
    proc = _run_verify(bundle)
    assert proc.returncode == 1, (
        f"expected FAIL, got rc={proc.returncode}\n{proc.stdout}"
    )
    combined = proc.stdout + proc.stderr
    assert "FRAGMENT_OFFSET_OUT_OF_BOUNDS" in combined, combined


# --- Row 3: a sentence anchor under a drifted segmenter fails closed --------


def test_segmenter_drift_fails_closed(tmp_path: Path) -> None:
    bundle = build_citation_bundle(tmp_path / "drift", fault="segmenter_drift")
    proc = _run_verify(bundle)
    assert proc.returncode == 1, (
        f"expected FAIL, got rc={proc.returncode}\n{proc.stdout}"
    )
    combined = proc.stdout + proc.stderr
    assert "SEGMENTER_MISMATCH" in combined, combined


# --- Row 4: a citation whose source isn't bundled fails closed --------------


def test_unresolvable_source_fails_closed(tmp_path: Path) -> None:
    bundle = build_citation_bundle(tmp_path / "nosrc", fault="source_unresolvable")
    proc = _run_verify(bundle)
    assert proc.returncode == 1, (
        f"expected FAIL, got rc={proc.returncode}\n{proc.stdout}"
    )
    combined = proc.stdout + proc.stderr
    assert "FRAGMENT_SOURCE_UNRESOLVABLE" in combined, combined


# --- Row 5: the genuine sentence-ID citation attests on its own --------------


def test_sentence_id_citation_alone_passes(tmp_path: Path) -> None:
    """Exercises the second locked resolver (resolve_sentence_id) in isolation."""
    bundle = build_citation_bundle(tmp_path / "sentence", only=["cit-4"])
    proc = _run_verify(bundle)
    assert proc.returncode == 0, (
        f"expected PASS, got rc={proc.returncode}\n{proc.stdout}\n{proc.stderr}"
    )
    assert "PASS  plugin:fragment_attestation" in proc.stdout, proc.stdout


# --- The headline property: the verdict flips on quote faithfulness alone ----
#     (normalized equality, D7.d — case/punctuation/whitespace-insensitive,
#     NOT byte-exact; see citation_integrity_minimal/README.md).


def test_verdict_flips_only_on_quote_faithfulness(tmp_path: Path) -> None:
    """Genuine and fabricated bundles cite the SAME sources at the SAME spans;
    only one claimed quote differs. No answer key — the snapshot is ground truth."""
    genuine = _run_verify(build_citation_bundle(tmp_path / "g"))
    fabricated = _run_verify(build_citation_bundle(tmp_path / "f", fault="fabricate"))
    assert genuine.returncode == 0 and fabricated.returncode == 1
