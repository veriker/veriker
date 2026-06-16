"""tests/test_primitive_path_containment.py — bundle-controlled file paths in
the PROMOTED re-derivation primitives must not steer reads outside the bundle.

The promoted primitives run on the SAFE spec-pinned path ("bundle data, not
code"). But two of them read files NAMED by bundle data:
  - build.recompute_artifact_bytes reads recipe-named inputs (`step["inputs"]`);
  - scrabble.compute_ruling reads the timeline-named `wordlist_file`.
Those names are producer-controlled. Without containment a hostile bundle could
request `../../etc/passwd` or an absolute path and turn a verifier-side read into
an arbitrary-file oracle on the AUDITOR's machine. resolve_within contains both,
failing CLOSED (ValueError -> RECOMPUTE_ERROR) rather than reading out of tree.

Each negative test plants a real secret OUTSIDE the bundle and asserts (a) the
primitive raises and (b) the secret bytes never reach the returned value.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_PKG_ROOT = Path(__file__).resolve().parents[1]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.rederivation.primitives._safepath import resolve_within  # noqa: E402
from audit_bundle.rederivation.primitives.build import recompute_artifact_bytes  # noqa: E402
from audit_bundle.rederivation.primitives.scrabble import compute_ruling  # noqa: E402


# --------------------------------------------------------------------------- #
# resolve_within — the shared containment rule
# --------------------------------------------------------------------------- #


def test_resolve_within_allows_in_tree(tmp_path):
    (tmp_path / "a.txt").write_text("ok")
    assert resolve_within(tmp_path, "a.txt") == (tmp_path / "a.txt").resolve()
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.txt").write_text("ok")
    assert (
        resolve_within(tmp_path, "sub/b.txt") == (tmp_path / "sub" / "b.txt").resolve()
    )


def test_resolve_within_rejects_dotdot(tmp_path):
    root = tmp_path / "bundle"
    root.mkdir()
    (tmp_path / "secret.txt").write_text("SECRET")
    with pytest.raises(ValueError):
        resolve_within(root, "../secret.txt")


def test_resolve_within_rejects_absolute(tmp_path):
    root = tmp_path / "bundle"
    root.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("SECRET")
    with pytest.raises(ValueError):
        resolve_within(root, str(secret))


def test_resolve_within_rejects_symlink_escape(tmp_path):
    root = tmp_path / "bundle"
    root.mkdir()
    (tmp_path / "secret.txt").write_text("SECRET")
    link = root / "link.txt"
    try:
        link.symlink_to(tmp_path / "secret.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unsupported on this platform")
    with pytest.raises(ValueError):
        resolve_within(root, "link.txt")


# --------------------------------------------------------------------------- #
# build — recipe-named inputs must stay under sources/
# --------------------------------------------------------------------------- #


def _hostile_build_recipe(rel_input: str) -> dict:
    return {
        "steps": [
            {"id": "s1", "rule": "concat", "inputs": [rel_input], "output": "out"}
        ],
        "final_artifact": "out",
    }


def test_build_rejects_dotdot_input(tmp_path):
    sources = tmp_path / "bundle" / "sources"
    sources.mkdir(parents=True)
    (tmp_path / "bundle" / "secret.txt").write_bytes(b"TOPSECRET")
    recipe = _hostile_build_recipe("sources/../secret.txt")
    with pytest.raises(ValueError):
        recompute_artifact_bytes(recipe, sources)


def test_build_rejects_absolute_input(tmp_path):
    sources = tmp_path / "bundle" / "sources"
    sources.mkdir(parents=True)
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"TOPSECRET")
    # "sources/" + an absolute path -> stripped component is absolute.
    recipe = _hostile_build_recipe("sources/" + str(secret))
    with pytest.raises(ValueError):
        recompute_artifact_bytes(recipe, sources)


def test_build_honest_input_still_reads(tmp_path):
    sources = tmp_path / "bundle" / "sources"
    sources.mkdir(parents=True)
    (sources / "a.txt").write_bytes(b"hello")
    recipe = _hostile_build_recipe("sources/a.txt")
    assert recompute_artifact_bytes(recipe, sources) == b"hello"


# --------------------------------------------------------------------------- #
# scrabble — timeline-named wordlist_file must stay under the bundle
# --------------------------------------------------------------------------- #


def _timeline(wordlist_file: str) -> dict:
    return {
        "authorities": {
            "INTL": [
                {
                    "start": "2020-01-01T00:00:00Z",
                    "end": None,
                    "edition": "ED1",
                    "wordlist_file": wordlist_file,
                }
            ]
        }
    }


_DISPUTE = {
    "word": "SECRET",
    "jurisdiction": "INTL",
    "timestamp": "2024-01-01T00:00:00Z",
}


def test_scrabble_rejects_dotdot_wordlist(tmp_path):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    # Plant a wordlist OUTSIDE the bundle that WOULD make is_legal True.
    (tmp_path / "secret_wordlist.txt").write_text("SECRET\n")
    with pytest.raises(ValueError):
        compute_ruling(bundle, _timeline("../secret_wordlist.txt"), _DISPUTE)


def test_scrabble_rejects_absolute_wordlist(tmp_path):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    secret = tmp_path / "secret_wordlist.txt"
    secret.write_text("SECRET\n")
    with pytest.raises(ValueError):
        compute_ruling(bundle, _timeline(str(secret)), _DISPUTE)


def test_scrabble_honest_wordlist_still_reads(tmp_path):
    bundle = tmp_path / "bundle"
    (bundle / "dictionaries").mkdir(parents=True)
    (bundle / "dictionaries" / "ED1.txt").write_text("SECRET\nHELLO\n")
    ruling = compute_ruling(bundle, _timeline("dictionaries/ED1.txt"), _DISPUTE)
    assert ruling == {"edition_cited": "ED1", "word": "SECRET", "is_legal": True}
