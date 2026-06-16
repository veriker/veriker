#!/usr/bin/env python3
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
