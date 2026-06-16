"""C20 — Semantic fidelity (schema reservation only at v0.3).

v0.3 scope: SCHEMA RESERVATION ONLY. NO plugin code. Substantive NLI / entailment
/ contradiction-detector plugin work is its own dedicated future sprint scheduled
against the EU AI Act August 2026 high-risk obligations calendar.

Lead plugin candidates (ruled in at C20 sprint scoping, NOT here):
  - MiniCheck (retrieval-grounded entailment, modest compute)
  - AlignScore (retrieval-grounded entailment, modest compute)
Ruled out:
  - FActScore (too expensive — multiple LLM calls per claim)
  - Custom contradiction-detector (too expensive to build at current scale)
  - DeBERTa-v3 NLI (cheap baseline only)

When implemented, this module supplies the `semantic_fidelity` TypedDict /
dataclass shape for the schema namespace (NO plugin logic), backing the
`semantic_fidelity` field declaration in audit_bundle/bundle_manifest.py.


"""

from __future__ import annotations

from typing import Literal, TypedDict


SEMANTIC_FIDELITY_SCHEMA_VERSION = "0.3-reservation"


FidelityCheckKind = Literal["nli", "entailment", "contradiction-detector", "none"]


class SemanticFidelityEvidence(TypedDict, total=False):
    """v0.3 schema reservation only. No verifier-side enforcement. No plugin code.

    Emitters MAY default to empty `{}` or omit the field entirely. Future plugin
    (MiniCheck / AlignScore lead candidates per S5) lands in a dedicated
    post-2026-08-02 sprint aligned with EU AI Act Article 26 high-risk-AI-system
    obligations. Substrate-shape decision among (a) model-stamped plugin /
    (b) attested-score separate surface / (c) stdlib-fit heuristics is TBD per
    future-sprint S5 ratification.
    """

    fidelity_check_kind: FidelityCheckKind
    fidelity_check_artifact: dict | None
    fidelity_check_signature: str | None
    citation_halo_probe_run: bool
    citation_halo_score: float | None
