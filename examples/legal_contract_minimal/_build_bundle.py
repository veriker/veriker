"""_build_bundle.py — build a deterministic legal_contract_minimal audit bundle.

Legal contract clause precedent retrieval domain pilot: given a set of contract
clauses each tagged with keyword terms, retrieve matching precedent cases by
keyword overlap and produce a per-clause ranked list of case citations.  The
audit bundle captures the clause corpus, the precedent database, and the bundled
retrieval result — enough for an independent verifier to re-run the deterministic
keyword-based retrieval and assert every clause's case_cite list (order + content)
matches the bundled result exactly.

Re-derivation primitive (one sentence):
  For each clause (in clause_id order), rank all precedent cases by the count of
  keyword overlaps with the clause's query_keywords (desc), breaking ties by
  case_cite alphanumeric ascending, and assert the resulting per-clause
  case_cite list matches the bundled retrieval_result.json exactly.

Why this matters for legal / contract review:
  Counterparty-risk review tools must demonstrate that their AI-retrieved
  precedent citations are deterministically reproducible from committed
  inputs: the auditor must re-run the retrieval against the exact clause corpus
  and precedent database the model saw, using only committed artifacts. The
  audit bundle is that receipt. This pilot demonstrates the substrate claim on a
  synthetic but structurally realistic keyword-based retrieval; production
  integrators replace the keyword ranker with a determinism-mode embedding
  nearest-neighbour pass; the bundle shape and verification protocol are identical.

The fragment kind exercised is OpaqueFragment(kind_tag="legal_precedent_anchor"):
one anchor per (clause_id, case_cite) hit. Substrate validates shape only;
semantic validation is the responsibility of LegalContractReDerivationCheck.

Usage (from v-kernel-audit-bundle root, or anywhere):
    python examples/legal_contract_minimal/_build_bundle.py
        # writes manifest + bundle artifacts into the pilot directory itself

    python examples/legal_contract_minimal/_build_bundle.py --out-dir /tmp/legal_bundle
        # writes into a fresh out-dir (does NOT copy source files)

Caveat:
  When --out-dir is specified, only the generated artifacts (inputs/, payload/,
  re_derive/pack copy, manifest.json) are written. The pilot's own source files
  (_build_bundle.py, verify.py, README.md, LegalContractReDerivationCheck.py,
  tests/) are not copied. The in-place build (default) is the canonical mode
  used by cli/verify.py: every file in the pilot directory is SHA-hashed into
  manifest.files so file_integrity_many_small Pass 3 (EXTRA_FILE_NOT_IN_MANIFEST)
  passes cleanly.

Outputs (in-place):
  examples/legal_contract_minimal/inputs/clauses.json
  examples/legal_contract_minimal/inputs/precedents.json
  examples/legal_contract_minimal/payload/retrieval_result.json
  examples/legal_contract_minimal/re_derive/legal_contract_pack.py
  examples/legal_contract_minimal/manifest.json

Exit codes:
  0  success
  1  assertion failure
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_PKG_ROOT = Path(__file__).resolve().parents[2]
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from audit_bundle.fragments.fragment_id import (
    OpaqueFragment,
    fragment_to_canonical_dict,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SCHEMA_VERSION = "vcp-v1.1-canary4"
_BUNDLE_ID = "legal-contract-minimal-rc"
_CREATED_AT = "2026-05-18T00:00:00Z"
_TYPED_CHECKS = [
    "file_integrity_many_small",
    "re_derivation_invocation",
]

# ---------------------------------------------------------------------------
# Synthetic fixtures — 8 contract clauses + 12 precedent cases
# ---------------------------------------------------------------------------

# Each clause has a clause_id and a list of query_keywords that characterise
# the clause's legal subject matter.
_CLAUSES = [
    {
        "clause_id": "cl-001",
        "title": "Limitation of Liability",
        "query_keywords": ["liability", "damages", "indemnification", "cap"],
    },
    {
        "clause_id": "cl-002",
        "title": "Confidentiality",
        "query_keywords": ["confidential", "disclosure", "trade_secret", "nda"],
    },
    {
        "clause_id": "cl-003",
        "title": "Intellectual Property Assignment",
        "query_keywords": [
            "intellectual_property",
            "assignment",
            "ownership",
            "patent",
        ],
    },
    {
        "clause_id": "cl-004",
        "title": "Force Majeure",
        "query_keywords": ["force_majeure", "unforeseeable", "event", "excused"],
    },
    {
        "clause_id": "cl-005",
        "title": "Dispute Resolution",
        "query_keywords": ["arbitration", "dispute", "jurisdiction", "governing_law"],
    },
    {
        "clause_id": "cl-006",
        "title": "Termination for Cause",
        "query_keywords": ["termination", "breach", "cure", "notice"],
    },
    {
        "clause_id": "cl-007",
        "title": "Payment Terms",
        "query_keywords": ["payment", "invoice", "net30", "late_fee"],
    },
    {
        "clause_id": "cl-008",
        "title": "Warranty Disclaimer",
        "query_keywords": ["warranty", "disclaimer", "as_is", "merchantability"],
    },
]

# Each precedent case carries a case_cite (the citation) and a set of keywords
# that describe the legal principles covered by that case.
_PRECEDENTS = [
    {
        "case_cite": "Adams v. Baker, 112 F.3d 200 (1st Cir. 1997)",
        "keywords": ["liability", "damages", "cap", "indemnification"],
    },
    {
        "case_cite": "Baker v. Carter, 88 F.2d 301 (2d Cir. 1988)",
        "keywords": ["confidential", "trade_secret", "nda", "disclosure"],
    },
    {
        "case_cite": "Carter v. Davis, 201 F.3d 450 (3d Cir. 2000)",
        "keywords": ["intellectual_property", "patent", "assignment", "ownership"],
    },
    {
        "case_cite": "Davis v. Evans, 55 F.3d 100 (4th Cir. 1995)",
        "keywords": ["force_majeure", "unforeseeable", "excused", "event"],
    },
    {
        "case_cite": "Evans v. Foster, 330 F.3d 700 (5th Cir. 2003)",
        "keywords": ["arbitration", "dispute", "jurisdiction", "governing_law"],
    },
    {
        "case_cite": "Foster v. Grant, 145 F.3d 800 (6th Cir. 1998)",
        "keywords": ["termination", "breach", "cure", "notice"],
    },
    {
        "case_cite": "Grant v. Hughes, 77 F.3d 150 (7th Cir. 1996)",
        "keywords": ["payment", "invoice", "net30", "late_fee"],
    },
    {
        "case_cite": "Hughes v. Ingram, 260 F.3d 520 (8th Cir. 2001)",
        "keywords": ["warranty", "disclaimer", "as_is", "merchantability"],
    },
    {
        "case_cite": "Ingram v. Jones, 390 F.3d 610 (9th Cir. 2004)",
        "keywords": ["liability", "indemnification", "warranty", "disclaimer"],
    },
    {
        "case_cite": "Jones v. Kelly, 180 F.3d 310 (10th Cir. 1999)",
        "keywords": ["confidential", "disclosure", "breach", "termination"],
    },
    {
        "case_cite": "Kelly v. Lewis, 95 F.3d 220 (11th Cir. 1996)",
        "keywords": ["intellectual_property", "ownership", "dispute", "arbitration"],
    },
    {
        "case_cite": "Lewis v. Morgan, 415 F.3d 900 (Fed. Cir. 2005)",
        "keywords": ["patent", "assignment", "payment", "damages"],
    },
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(obj) -> bytes:
    """Deterministic JSON: sort_keys + compact separators + trailing newline."""
    return (
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _keyword_overlap(clause_keywords: list[str], case_keywords: list[str]) -> int:
    """Count of keyword tokens that appear in both clause and case keyword lists."""
    clause_set = set(clause_keywords)
    case_set = set(case_keywords)
    return len(clause_set & case_set)


def _retrieve_cases(clause: dict, precedents: list[dict]) -> list[str]:
    """Return the case_cite list for a clause, sorted by keyword overlap (desc)
    then case_cite alphanumeric (asc) for deterministic tiebreak.

    Only precedents with overlap >= 1 are included.
    """
    hits: list[tuple[int, str]] = []
    for case in precedents:
        overlap = _keyword_overlap(clause["query_keywords"], case["keywords"])
        if overlap >= 1:
            hits.append((overlap, case["case_cite"]))
    # Sort: overlap DESC, then case_cite ASC (stable, deterministic).
    hits.sort(key=lambda t: (-t[0], t[1]))
    return [cite for _, cite in hits]


def _derive_retrieval_result(clauses: list[dict], precedents: list[dict]) -> list[dict]:
    """Deterministic keyword retrieval → per-clause case_cite lists.

    Each entry: clause_id, clause_title, case_cites (ordered list).
    Sorted by clause_id for a stable byte layout.
    """
    result: list[dict] = []
    for clause in sorted(clauses, key=lambda c: c["clause_id"]):
        cites = _retrieve_cases(clause, precedents)
        result.append(
            {
                "clause_id": clause["clause_id"],
                "clause_title": clause["title"],
                "case_cites": cites,
            }
        )
    return result


def _build_fragment_anchors(
    retrieval_result: list[dict],
    clauses_cid: str,
    precedents_cid: str,
) -> dict:
    """One OpaqueFragment per (clause_id, case_cite) hit.

    source_cid = precedents_cid (the precedent database is the source of the
    citation). kind_tag = "legal_precedent_anchor".
    """
    anchors: dict = {}
    for entry in retrieval_result:
        clause_id = entry["clause_id"]
        for case_cite in entry["case_cites"]:
            # Deterministic key: clause_id + case_cite (trimmed for safety)
            key = f"{clause_id}::{case_cite[:60]}"
            anchors[key] = fragment_to_canonical_dict(
                OpaqueFragment(
                    source_cid=precedents_cid,
                    kind_tag="legal_precedent_anchor",
                    locator={
                        "clause_id": clause_id,
                        "case_cite": case_cite,
                    },
                )
            )
    return anchors


# ---------------------------------------------------------------------------
# Re-derivation pack — written into re_derive/ inside the bundle
# ---------------------------------------------------------------------------

_RE_DERIVE_PACK_SOURCE: str = '''#!/usr/bin/env python3
"""legal_contract_pack.py — stdlib re-derivation pack for legal contract domain.

the audit-bundle contract §C5 (auditor independence) + AB4 (duplicate-don't-import):
no audit_bundle imports inside this script. Stdlib only.

Re-derivation steps:
  1. Load inputs/clauses.json      — list of {clause_id, title, query_keywords[]}
  2. Load inputs/precedents.json   — list of {case_cite, keywords[]}
  3. Load payload/retrieval_result.json — list of {clause_id, clause_title, case_cites[]}
  4. Re-run deterministic keyword-based retrieval:
       For each clause (sorted by clause_id):
         For each precedent: overlap = |clause_keywords ∩ case_keywords|
         Keep precedents with overlap >= 1
         Sort by overlap DESC, then case_cite ASC (tiebreak)
         Collect case_cite list
  5. Assert per-clause equality with bundled retrieval_result.json:
       - same number of clause entries
       - per-entry: clause_id and clause_title match
       - per-entry: case_cites list matches (order + content)
  6. Exit 0 on full match; exit 1 with [LC_REDER_FAIL] <description> on stderr.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _fail(msg: str) -> int:
    print(f"[LC_REDER_FAIL] {msg}", file=sys.stderr)
    return 1


def _keyword_overlap(clause_kws: list, case_kws: list) -> int:
    return len(set(clause_kws) & set(case_kws))


def _retrieve_cases(clause: dict, precedents: list) -> list:
    hits = []
    for case in precedents:
        overlap = _keyword_overlap(clause["query_keywords"], case["keywords"])
        if overlap >= 1:
            hits.append((overlap, case["case_cite"]))
    hits.sort(key=lambda t: (-t[0], t[1]))
    return [cite for _, cite in hits]


def _derive_retrieval_result(clauses: list, precedents: list) -> list:
    result = []
    for clause in sorted(clauses, key=lambda c: c["clause_id"]):
        cites = _retrieve_cases(clause, precedents)
        result.append(
            {
                "clause_id": clause["clause_id"],
                "clause_title": clause["title"],
                "case_cites": cites,
            }
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Legal contract clause precedent re-derivation check"
    )
    parser.add_argument("--bundle-dir", required=True, type=Path)
    args = parser.parse_args()
    bundle_dir: Path = args.bundle_dir.resolve()

    clauses_path = bundle_dir / "inputs" / "clauses.json"
    precedents_path = bundle_dir / "inputs" / "precedents.json"
    result_path = bundle_dir / "payload" / "retrieval_result.json"
    for p in (clauses_path, precedents_path, result_path):
        if not p.exists():
            return _fail(f"required file missing: {p}")

    try:
        clauses = json.loads(clauses_path.read_text(encoding="utf-8"))
        precedents = json.loads(precedents_path.read_text(encoding="utf-8"))
        bundled = json.loads(result_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return _fail(f"failed to load bundle inputs/payload: {exc}")

    if not isinstance(clauses, list) or not isinstance(precedents, list) or not isinstance(bundled, list):
        return _fail("clauses.json, precedents.json, retrieval_result.json must each be JSON arrays")

    recomputed = _derive_retrieval_result(clauses, precedents)

    if len(recomputed) != len(bundled):
        return _fail(
            f"clause entry count mismatch: recomputed={len(recomputed)} bundled={len(bundled)}"
        )

    for i, (rec, exp) in enumerate(zip(recomputed, bundled)):
        if rec["clause_id"] != exp.get("clause_id"):
            return _fail(
                f"entry[{i}] clause_id mismatch: "
                f"recomputed={rec['clause_id']!r} bundled={exp.get('clause_id')!r}"
            )
        if rec["clause_title"] != exp.get("clause_title"):
            return _fail(
                f"entry[{i}] clause_title mismatch for clause_id={rec['clause_id']!r}: "
                f"recomputed={rec['clause_title']!r} bundled={exp.get('clause_title')!r}"
            )
        rec_cites = rec["case_cites"]
        exp_cites = exp.get("case_cites", [])
        if rec_cites != exp_cites:
            return _fail(
                f"entry[{i}] case_cites mismatch for clause_id={rec['clause_id']!r}: "
                f"recomputed={rec_cites!r} bundled={exp_cites!r}"
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def _enumerate_pilot_files_for_manifest(pilot_dir: Path) -> dict:
    """Walk the pilot dir and return {rel_path: sha256} for every file.

    Excludes manifest.json itself, __pycache__ trees, .pyc artifacts, and
    any spec/ or snapshots/ trees. Used only for in-place builds.
    """
    files: dict[str, str] = {}
    _SKIP_TOP = frozenset({"spec", "snapshots", "__pycache__"})
    for fpath in sorted(pilot_dir.rglob("*")):
        if fpath.is_dir():
            continue
        rel = fpath.relative_to(pilot_dir).as_posix()
        if rel == "manifest.json":
            continue
        parts = rel.split("/")
        if parts[0] in _SKIP_TOP:
            continue
        if any(p == "__pycache__" for p in parts):
            continue
        if rel.endswith(".pyc"):
            continue
        files[rel] = _sha256(fpath.read_bytes())
    return files


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    inputs_dir = out_dir / "inputs"
    payload_dir = out_dir / "payload"
    re_derive_dir = out_dir / "re_derive"
    for d in (inputs_dir, payload_dir, re_derive_dir):
        d.mkdir(parents=True, exist_ok=True)

    # --- Write the re-derivation pack first so its bytes are deterministic ---
    pack_path = re_derive_dir / "legal_contract_pack.py"
    pack_path.write_bytes(_RE_DERIVE_PACK_SOURCE.encode("utf-8"))

    # --- Write clauses.json ---
    clauses_bytes = _canonical_json_bytes(_CLAUSES)
    (inputs_dir / "clauses.json").write_bytes(clauses_bytes)
    clauses_cid = f"sha256:{_sha256(clauses_bytes)}"

    # --- Write precedents.json ---
    precedents_bytes = _canonical_json_bytes(_PRECEDENTS)
    (inputs_dir / "precedents.json").write_bytes(precedents_bytes)
    precedents_cid = f"sha256:{_sha256(precedents_bytes)}"

    # --- Re-derive the retrieval result and write retrieval_result.json ---
    retrieval_result = _derive_retrieval_result(_CLAUSES, _PRECEDENTS)
    assert len(retrieval_result) == 8, (
        f"Expected exactly 8 clause entries (one per clause); got {len(retrieval_result)}."
    )

    result_bytes = _canonical_json_bytes(retrieval_result)
    (payload_dir / "retrieval_result.json").write_bytes(result_bytes)

    # --- Fragment anchors (OpaqueFragment per (clause_id, case_cite) hit) ---
    fragment_anchors = _build_fragment_anchors(
        retrieval_result, clauses_cid, precedents_cid
    )
    total_hits = sum(len(e["case_cites"]) for e in retrieval_result)
    assert 5 <= len(fragment_anchors) <= 30, (
        f"Expected 5..30 evidence anchors; got {len(fragment_anchors)}."
    )

    # --- Build manifest.files ---
    if out_dir.resolve() == _HERE.resolve():
        files = _enumerate_pilot_files_for_manifest(out_dir)
    else:
        files = {
            "inputs/clauses.json": _sha256(clauses_bytes),
            "inputs/precedents.json": _sha256(precedents_bytes),
            "payload/retrieval_result.json": _sha256(result_bytes),
            "re_derive/legal_contract_pack.py": _sha256(
                _RE_DERIVE_PACK_SOURCE.encode("utf-8")
            ),
        }

    manifest = {
        "schema_version": _SCHEMA_VERSION,
        "bundle_id": _BUNDLE_ID,
        "created_at": _CREATED_AT,
        "files": files,
        "spec_files": {},
        "cross_refs": {},
        "payload": {},
        "typed_checks": _TYPED_CHECKS,
        "fragment_anchors": fragment_anchors,
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"Bundle written to {out_dir}")
    print(f"  clauses          : {len(_CLAUSES)}")
    print(f"  precedents       : {len(_PRECEDENTS)}")
    print(f"  clause entries   : {len(retrieval_result)} (with case_cite lists)")
    print(f"  total hits       : {total_hits}")
    print(f"  evidence anchors : {len(fragment_anchors)} OpaqueFragment")
    print(f"  manifest files   : {len(files)}")
    print(f"  manifest         : {out_dir / 'manifest.json'}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a deterministic legal_contract_minimal audit bundle"
    )
    parser.add_argument(
        "--out-dir",
        required=False,
        type=Path,
        default=_HERE,
        help=(
            "Destination directory. Defaults to the pilot's own directory "
            "(in-place build) so cli/verify.py --bundle-dir <pilot-dir> Just Works. "
            "Pass an explicit --out-dir to write a standalone bundle."
        ),
    )
    args = parser.parse_args()
    try:
        build(args.out_dir.resolve())
    except AssertionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
