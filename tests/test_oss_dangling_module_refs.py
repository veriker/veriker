"""Ratchet: no UNSCOPED references to export-excluded modules in shipped code.

Why this exists
---------------
The OSS export drops whole modules (``gate/chokepoint*``, ``gate/nonce_store``,
``orchestrator_turn/``, ``emitter_premium/``) while the files that REFERENCE
them ship. A shipped docstring that says "the production path is
``gate.chokepoint.AgentActionChokepoint``" reads, to an open-drop consumer, as
guidance pointing at a module that does not exist in their tree (found via the
2026-06-10 Codex mirror-review pass: the gate clock-injection notes named the
chokepoint with no hint it is closed-tier). The mirror reviewer is a proxy for
every real OSS auditor — if shipped text needs internal context to make sense,
the open surface has a doc gap even when the code is fine.

The rule this test pins: a shipped reference to an excluded module is FINE, but
it must be SCOPED — within a few lines of language telling the open-drop reader
the module is closed-tier / not in this drop / merely not-imported (the
``gate/__init__.py`` optional-import block is the model). New unscoped
references fail here with instructions.

Companion guards: ``test_dsse_seal_oss_boundary.py`` (ships alongside this
file; no premium IMPORTS at runtime), plus two producer-side guards that run
only in the internal tree and are NOT in the open drop (the export's
internal-trailer strip test and its premium-path enumeration test — they
enforce the boundary from the publishing side). This one covers prose, which
none of those see.

Stdlib only.
"""

from __future__ import annotations

import re
from pathlib import Path

import audit_bundle

PACKAGE_ROOT = Path(audit_bundle.__file__).resolve().parent
PRODUCT_ROOT = PACKAGE_ROOT.parent

# Module-shaped tokens for export-excluded modules. Deliberately dotted/path
# forms — the bare word "chokepoint" as a concept ("a chokepoint cannot be
# tricked...") is legitimate shipped prose and must not match.
_EXCLUDED_MODULE_TOKENS = (
    "gate.chokepoint",
    "gate/chokepoint",
    ".chokepoint import",
    "gate.nonce_store",
    "gate/nonce_store",
    ".nonce_store import",
    "nonce_store",
    "orchestrator_turn",
    "emitter_premium",
)

# A reference is SCOPED when one of these appears within _WINDOW lines of it.
# Covers the boundary-disclosure spellings already in the tree: the
# gate/__init__.py optional-import block, the "does NOT import" negative
# contracts, and the OSS_RELEASE_BOUNDARY.md pointers added 2026-06-10.
_SCOPING_MARKER = re.compile(
    r"EXCLUDED from the open\s+drop"
    r"|excluded from the open\s+drop"
    r"|CLOSED tier|closed tier|closed-tier"
    r"|does NOT import|must (?:never|not) import|no premium import"
    r"|OSS_RELEASE_BOUNDARY|OSS boundary"
    r"|hosted[- ]enforcement tier|hosted[- ]availability SKU",
)
_WINDOW = 20

# Files that ARE the excluded modules (or their dedicated tests, themselves
# export-excluded) — they may of course name themselves.
_EXCLUDED_FILE_PARTS = (
    "gate/chokepoint",
    "gate/nonce_store",
    "gate/dispatch_ledger",  # chartered-fleet keystone (enforcement, excluded from open drop)
    "orchestrator_turn/",
    "emitter_premium/",
)

# Reviewed (relpath, token) pairs allowed WITHOUT a nearby scoping marker.
# Keep EMPTY if possible — prefer adding the one-clause disclosure inline.
ALLOWED_UNSCOPED: frozenset[tuple[str, str]] = frozenset()


def _shipped_sources() -> list[Path]:
    files: list[Path] = []
    for top in ("audit_bundle", "veriker"):
        root = PRODUCT_ROOT / top
        if not root.is_dir():
            continue
        for py in sorted(root.rglob("*.py")):
            rel = py.relative_to(PRODUCT_ROOT).as_posix()
            if any(part in rel for part in _EXCLUDED_FILE_PARTS):
                continue
            files.append(py)
    return files


def test_excluded_module_references_are_scoped():
    violations: list[str] = []
    for py in _shipped_sources():
        rel = py.relative_to(PRODUCT_ROOT).as_posix()
        lines = py.read_text(encoding="utf-8").splitlines()
        marker_lines = [
            i for i, line in enumerate(lines) if _SCOPING_MARKER.search(line)
        ]
        for i, line in enumerate(lines):
            for token in _EXCLUDED_MODULE_TOKENS:
                if token not in line:
                    continue
                if (rel, token) in ALLOWED_UNSCOPED:
                    continue
                if any(abs(i - m) <= _WINDOW for m in marker_lines):
                    continue
                violations.append(f"{rel}:{i + 1}  [{token}]  {line.strip()[:90]}")
                break  # one violation per line is enough
    assert not violations, (
        "shipped open-tier source references an export-EXCLUDED module with no "
        "scoping disclosure nearby:\n  "
        + "\n  ".join(violations)
        + "\nAn open-drop reader has no such module — tell them. Add a short "
        "clause within a few lines (the gate/__init__.py optional-import block "
        'is the model), e.g.: "closed tier, EXCLUDED from the open drop per '
        'OSS_RELEASE_BOUNDARY.md" — or, for a deliberate exception, add the '
        "(file, token) pair to ALLOWED_UNSCOPED with a comment saying why."
    )


def test_scoping_marker_matches_the_canonical_spellings():
    # Regression-pin the marker regex against the real disclosures in the tree,
    # so a rewording of one of them doesn't silently turn its references into
    # false violations (or worse, a marker regex typo pass everything).
    for sample in (
        "These are the CLOSED tier and are EXCLUDED from the open\n drop",
        "the seal path does NOT import ``audit_bundle.emitter_premium``",
        "closed tier, EXCLUDED from the open drop per ``OSS_RELEASE_BOUNDARY.md``",
        "(OSS boundary preserved)",
        "hosted-availability SKU",
    ):
        assert _SCOPING_MARKER.search(sample.replace("\n", " ")), sample
