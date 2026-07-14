"""legal_contract_recompute.py — verifier-side clause-precedent retrieval re-derivation primitive.

Axis-2 value-return form (SPEC_PINNED_DISPATCH_ARCHITECTURE §3.3). Self-contained
per-dir migration of the legal_contract_minimal pilot onto spec-pinned dispatch:
the recompute primitive lives HERE (verifier-distribution code, registered by the
spec-pinned builder), NOT in audit_bundle/rederivation/primitives/.

Re-derivation primitive (one sentence):
    per-clause case_cites = for each clause (in clause_id order), rank every
    precedent by its keyword-overlap count with the clause's query_keywords
    (descending), break ties by case_cite ascending, retain only precedents with
    overlap >= 1.

over the committed clause corpus (inputs/clauses.json) and precedent database
(inputs/precedents.json) in the bundle. The ranking rule (overlap DESC, case_cite
ASC tie-break, overlap >= 1 retained, fail-closed reads) is FIXED in this
primitive — the primitive_id ("legal_contract_recompute") IS the rule. This
mirrors the legacy _build_bundle pack's _retrieve_cases/_derive_retrieval_result
EXACTLY. The auditor's SHA-pinned spec binds the output type
"legal_contract_case_cites" to this primitive_id and to an `exact` comparator (no
params; the per-clause ordered structure compared element-wise); a producer cannot
weaken the ranking without changing the primitive_id, which the anchor rejects.

Stdlib-only (§C5 contract). This module is importable WITHOUT audit_bundle on
sys.path (the RecomputedValue import is deferred into recompute()), so the
spec-pinned builder can import compute_case_cites() standalone.
"""

from __future__ import annotations

import json
from pathlib import Path


# ---------------------------------------------------------------------------
# Canonical computation (shared by the builder and the verifier — ONE source)
# ---------------------------------------------------------------------------


def _keyword_overlap(clause_keywords: list, case_keywords: list) -> int:
    """Count of keyword tokens that appear in both clause and case keyword lists."""
    return len(set(clause_keywords) & set(case_keywords))


def _retrieve_cases(clause: dict, precedents: list) -> list:
    """Return the case_cite list for a clause, sorted by keyword overlap (desc)
    then case_cite alphanumeric (asc) for deterministic tiebreak. Only precedents
    with overlap >= 1 are included. Mirrors the legacy pack EXACTLY."""
    hits: list[tuple[int, str]] = []
    for case in precedents:
        overlap = _keyword_overlap(clause["query_keywords"], case["keywords"])
        if overlap >= 1:
            hits.append((overlap, case["case_cite"]))
    hits.sort(key=lambda t: (-t[0], t[1]))
    return [cite for _, cite in hits]


def compute_case_cites(clauses: list, precedents: list) -> list:
    """Canonical per-clause case_cites re-derivation. Mirrors the legacy pack's
    _derive_retrieval_result EXACTLY: for each clause (sorted by clause_id),
    re-run the deterministic keyword retrieval and emit
    {clause_id, clause_title, case_cites}.

    Builder and verifier share this ONE definition so the honest claimed value
    and the re-derivation cannot drift.

    Fail-closed: raises KeyError/TypeError if a clause or precedent is missing
    required fields, or the corpus is malformed (the verifier must not invent a
    ranking).
    """
    if not isinstance(clauses, list) or not isinstance(precedents, list):
        raise TypeError("clauses and precedents must each be JSON arrays")
    result: list = []
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


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered before BundleVerifier)
# ---------------------------------------------------------------------------


class LegalContractRecompute:
    """Verifier-side primitive for re-deriving the per-clause case_cites structure."""

    primitive_id: str = "legal_contract_recompute"

    def recompute(self, inputs, pack_section: dict):
        """Recompute the per-clause case_cites structure from the committed clause
        corpus + precedent database.

        inputs.bundle_dir is a read-only Path. pack_section carries
        {output_id, type, params} from the auditor's spec binding. Returns a
        RecomputedValue carrying the per-clause ordered structure; the verifier's
        `exact` comparator compares it element-wise to the claimed value.
        """
        # Deferred import keeps this module importable standalone (builder use).
        from audit_bundle.plugin import RecomputedValue  # noqa: PLC0415

        bundle_dir: Path = inputs.bundle_dir

        clauses_path = bundle_dir / "inputs" / "clauses.json"
        precedents_path = bundle_dir / "inputs" / "precedents.json"
        for p in (clauses_path, precedents_path):
            if not p.is_file():
                raise FileNotFoundError(f"{p} not found in bundle at {bundle_dir}")

        clauses = json.loads(clauses_path.read_bytes())
        precedents = json.loads(precedents_path.read_bytes())

        value = compute_case_cites(clauses, precedents)
        total_hits = sum(len(e["case_cites"]) for e in value)
        return RecomputedValue(
            value=value,
            detail=(
                f"re-derived per-clause case_cites ({len(value)} clauses, "
                f"{total_hits} total hits) from committed clause + precedent corpus"
            ),
        )
