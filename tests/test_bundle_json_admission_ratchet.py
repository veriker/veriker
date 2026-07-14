"""tests/test_bundle_json_admission_ratchet.py — locks the bundle-JSON admission
convention across the WHOLE audit_bundle package.

Redteam (ChatGPT, redteam mirror): admission bounds were applied to manifest.json
only; primitives/plugins read other bundle JSON via raw json.loads(path.read_bytes())
with no size/depth/cardinality bound. The fix was a shared loader
(admission.admit_json_file for single-value JSON, admit_jsonl_file for line-delimited
.jsonl, iter_admitted_jsonl_tolerant for skip-malformed scans). This ratchet stops
the asymmetry from re-growing: it FAILS if any package file parses a freshly-read
bundle file without going through the admission loaders.

SCOPE HISTORY (RES-02, 2026-06-11): the first version of this ratchet scanned only
rederivation/primitives/ + plugins/, NON-recursively — and the very next redteam
round found a raw read one directory above the scan root (dispatch.py's
producer-claimed value, the most bundle-controlled read on the dispatch path)
while plugins/reference/ escaped via the non-recursive glob. The scan is now the
ENTIRE package, recursive, with a path-keyed allowlist whose every entry carries
its justification. A scope carve-out is an allowlist entry with a reason, never
a narrower scan root.

KNOWN AST BLIND SPOTS (reviewed by hand when touching these shapes — the ratchet
cannot see them, so do not treat a green run as covering them):
  - variable indirection: text = path.read_text(); json.loads(text)
  - file-handle iteration: for line in fh: json.loads(line)
  - bytes-fed parses: json.loads(blob) where blob crossed a function boundary
The RES-02 sweep migrated every such site found by grep (event_log_replay,
energy_score_pack, streaming, tabular, c9_1 line scans, bundle_manifest
policy-stamp scan); new code should use the admission loaders from the start.

Two AST-detectable anti-patterns are forbidden (empty allowlist — burn it down, don't
grow it):
  (A) json.loads(<expr containing .read_bytes()/.read_text()>) — an unbounded parse of
      a file's bytes; a deeply-nested file drives the parser to RecursionError before
      any bound applies. Use admit_json_file(path).
  (B) <.read_text()/.read_bytes()>.splitlines() — an unbounded JSONL read; use
      admit_jsonl_file(path).

NOT flagged (legitimately raw): a bare ``path.read_bytes()`` whose result is hashed or
parsed by a non-JSON codec (audio/raster/CSV payloads, SHA integrity reads). Those are
not JSON-parse recursion vectors, and pure size is the operator's concern per
SECURITY.md ("DoS via legitimate-shaped but expensive bundles" — out of scope) and is
already read by the integrity walk regardless.
"""

from __future__ import annotations

import ast
from pathlib import Path

_PKG = Path(__file__).resolve().parents[1] / "audit_bundle"

# Files permitted to retain a flagged pattern, keyed by path RELATIVE to
# audit_bundle/, each with a stated reason. Burn it down, don't grow it — a
# genuine exception is added here with justification, never silently.
_ALLOWLIST: dict[str, str] = {
    "extensions/c18_tuf_client.py": (
        "reads operator-side TUF trust-store metadata, not bundle-controlled "
        "files; the supply-chain fetch path mints no Verdict and python-tuf "
        "performs the authoritative validation (C18 triage 2026-06-10)"
    ),
}
# verifier.py left the allowlist 2026-06-11 (RES-04 single-snapshot): verify()
# now reads manifest.json exactly once, admits those bytes, and threads them
# through _parse_manifest — no read-into-parse pattern remains to flag.


def _is_file_read(node: ast.AST) -> bool:
    """True if `node` is (or transitively contains) a `.read_bytes()` / `.read_text()`
    call — i.e. it evaluates freshly-read file bytes/text."""
    for sub in ast.walk(node):
        if (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and sub.func.attr in ("read_bytes", "read_text")
        ):
            return True
    return False


def _is_splitlines_of_file_read(node: ast.AST) -> bool:
    """True if `node` is a `<file read>.splitlines()` call."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "splitlines"
        and _is_file_read(node.func.value)
    )


def _contains_json_loads(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Attribute)
            and sub.func.attr == "loads"
            and isinstance(sub.func.value, ast.Name)
            and sub.func.value.id == "json"
        ):
            return True
    return False


def _violations_in(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    hits: list[str] = []
    for node in ast.walk(tree):
        # (A) json.loads(<file read>) — unbounded single-value parse.
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "loads"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "json"
            and node.args
            and _is_file_read(node.args[0])
        ):
            hits.append(
                f"{path.name}:{node.lineno}: json.loads(<file read>) — use admit_json_file"
            )
        # (B) a for-loop / comprehension iterating <file read>.splitlines() whose
        # body parses JSON — an unbounded JSONL read. A plain-text line read (e.g.
        # a wordlist) has no json.loads in its body and is correctly NOT flagged.
        if isinstance(node, ast.For) and _is_splitlines_of_file_read(node.iter):
            if any(_contains_json_loads(b) for b in node.body):
                hits.append(
                    f"{path.name}:{node.lineno}: for-loop over <file read>.splitlines() "
                    "parsing JSON — use admit_jsonl_file"
                )
        if isinstance(
            node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
        ):
            iter_is_jsonl = any(
                _is_splitlines_of_file_read(g.iter) for g in node.generators
            )
            if iter_is_jsonl and _contains_json_loads(node):
                hits.append(
                    f"{path.name}:{node.lineno}: comprehension over <file read>.splitlines() "
                    "parsing JSON — use admit_jsonl_file"
                )
    return hits


def test_no_unbounded_bundle_json_reads():
    violations: list[str] = []
    for py in sorted(_PKG.rglob("*.py")):
        rel = py.relative_to(_PKG).as_posix()
        if rel in _ALLOWLIST:
            continue
        violations.extend(f"{rel} :: {hit}" for hit in _violations_in(py))
    assert not violations, (
        "Unbounded bundle-JSON read(s) — route through admission.admit_json_file "
        "(single value) / admit_jsonl_file (.jsonl) / iter_admitted_jsonl_tolerant "
        "(skip-malformed scans), or add a justified _ALLOWLIST entry:\n  "
        + "\n  ".join(violations)
    )


def test_allowlist_entries_still_exist():
    """An allowlist entry for a deleted file is stale — fail so it gets cleaned."""
    for rel in _ALLOWLIST:
        assert (_PKG / rel).is_file(), (
            f"allowlist names {rel!r} but no such file exists under audit_bundle/"
        )


def test_allowlisted_files_still_have_a_flagged_pattern():
    """An allowlist entry whose file no longer trips the scanner is stale —
    remove it so the file rejoins the enforced set (burn-down direction)."""
    for rel in _ALLOWLIST:
        assert _violations_in(_PKG / rel), (
            f"allowlist entry {rel!r} is stale: the file has no flagged pattern "
            "left — delete the entry"
        )
