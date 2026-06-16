"""healthcare_diagnosis_recompute — verifier-side fire-and-collect ICD-10 re-derivation.

Axis-2 value-return form, PROMOTED into the shippable core registry (RECIPE_BOOK.md,
shape `deterministic rule/predicate evaluation → ordered categorical decision list`,
control-structure sub-family **C. fire-and-collect** — emits a value only for the
rules that FIRE, collected in order). The generic verifier recomputes the
representative output on the SAFE spec-pinned path: no subprocess, no bundle-supplied
code — the rule-traversal lives HERE in verifier-distribution code and the comparator
comes from the auditor-anchored spec.

Re-derivation primitive (one sentence):
    icd10_codes = for each rule in inputs/rules.json (sorted by rule_id), the rule
        FIRES iff every condition's symptom is present in inputs/symptoms.json AND
        its severity >= the condition's min_severity; each fired rule appends its
        icd10_code to an ordered list (rules that do not fire emit nothing).

Fire-and-collect vs first-match (the family distinction). prior_auth / anticheat
(first-match) emit ONE decision per record and stop at the first matching rule;
healthcare_diagnosis emits a value per FIRING rule and collects ALL of them — there
is no "default" and no early stop. The condition vocabulary here is a single fixed
predicate (symptom-present AND severity >= min_severity) — there is NO per-condition
operator field (unlike anticheat's {signal, comparator, threshold}), so there is no
unknown-comparator branch to mirror. The representative output is the ordered list of
categorical icd10_code STRINGS only; the producer's per-candidate confidence float
(sum(matched severities) * confidence_weight, rounded), description, matched_symptom_
ids, and rule_path are OUT OF SCOPE — projected out so the `exact` comparator stays
float-free (an ordered list of code strings compared element-wise). Dropping the
float is sound because the firing decision (which codes appear, and in what order)
does not depend on the confidence value; only the codes are re-derived.

SCOPE / COVERAGE HONESTY. This promoted safe-path check re-derives STRICTLY LESS
than the pilot's own (unsafe, subprocess) re_derive pack, which additionally asserts
each candidate's description, confidence (to 6 places), matched_symptom_ids, and
rule_path. On this path a tampered confidence / description / rule_path inside
payload/diagnosis.json would NOT be caught — only a change to the ordered set of
fired icd10_code strings is. That is the deliberate trade for running on the safe
spec-pinned path (no bundle-supplied code execution); it is the re-derived firing
DECISION, not a byte-for-byte attestation of the producer's full candidate record.
The ORDER of the codes IS in scope and load-bearing: the list is built in sorted
rule_id order and compared element-wise, so a reorder is a mismatch (the promoted
test discriminates this with a fixture whose rule_id order differs from code order).

The traversal rule (rule_id sort, AND-of-conditions, severity threshold, fire-and-
collect) is FIXED here — the primitive_id ("healthcare_diagnosis_recompute") IS the
rule. The auditor's SHA-pinned spec binds the output type "healthcare_diagnosis_codes"
to this primitive_id and to an `exact` comparator; a producer cannot weaken the
traversal without changing the primitive_id, which the anchor rejects.

Faithfulness (Gate B). The promoted test derives the honest claim from the pilot's
OWN producer (examples/healthcare_diagnosis_minimal/_build_bundle.py emits
payload/diagnosis.json from an independent inline copy of _eval_condition /
_derive_candidates — enforced disjoint by tests/test_recipe_producer_verifier_
disjoint.py), projected to the ordered icd10_code list, never from this module. This
recompute MIRRORS that producer's _eval_condition / _derive_candidates (modulo the
projection to codes only) — asserted directly by a condition-agreement test over the
branches: symptom present/absent, severity at/above/below min_severity (boundary),
all-conditions-AND pass and fail, multi-rule fire-and-collect ORDERING (rule_id order
≠ code order, so the sort key is discriminated, not coincident), and no-fire.
Fail-closed parity on malformed input: a missing required key (rule_id / icd10_code /
conditions / severity / min_severity / symptom_id) raises KeyError and a non-list
rules/symptoms raises TypeError on BOTH copies. The parity is per-input-TYPE
incidental, not a shared contract: core raises TypeError from an explicit isinstance
guard while the producer raises the same TypeError because its `for s in <non-list>`
dict-comprehension is non-iterable (or indexes a non-dict) — they coincide on the
exercised inputs (int, missing-key) but the mechanisms differ. What matters for the
safe path is that core fails CLOSED (raise -> RECOMPUTE_ERROR), never inventing a
partial code list; the agreement test asserts the same-type raise on both directly.

Stdlib-only (§C5 core verify() path): json is stdlib.
"""

from __future__ import annotations

from pathlib import Path

from ...admission import admit_json_file
from ...plugin import ParsedInputs, RecomputedValue
from ..registry import register_primitive


# ---------------------------------------------------------------------------
# Rule traversal — MIRRORS _build_bundle.py (the producer "tool") EXACTLY.
# ---------------------------------------------------------------------------


def _eval_condition(symptom_map: dict, cond: dict) -> bool:
    """Return True iff the symptom is present and meets min_severity.

    Mirrors the producer's _eval_condition EXACTLY: an absent symptom fails the
    condition (fail-closed), and severity is compared as int >= int min_severity.
    """
    s = symptom_map.get(cond["symptom_id"])
    if s is None:
        return False
    return int(s["severity"]) >= int(cond["min_severity"])


def compute_icd10_codes(symptoms: list, rules: list) -> list[str]:
    """Canonical fire-and-collect ICD-10 code-list re-derivation.

    Mirrors the producer's _derive_candidates rule-traversal EXACTLY: for each rule
    (sorted by rule_id), every condition must match (symptom present AND severity >=
    min_severity); a rule that fires contributes its icd10_code to the ordered list,
    in sorted rule_id order. Only the categorical icd10_code strings are emitted
    (confidence floats are projected out — keeps the `exact` comparison float-free).

    Fail-closed: raises TypeError if symptoms/rules are not lists, and KeyError if a
    rule or symptom record is malformed (missing rule_id / icd10_code / conditions /
    severity / min_severity / symptom_id); the verifier must not invent a code list.
    """
    if not isinstance(symptoms, list):
        raise TypeError("symptoms must be a JSON array")
    if not isinstance(rules, list):
        raise TypeError("rules must be a JSON array")

    symptom_map = {s["symptom_id"]: s for s in symptoms}
    codes: list[str] = []
    for rule in sorted(rules, key=lambda r: r["rule_id"]):
        fired = True
        for cond in rule["conditions"]:
            if not _eval_condition(symptom_map, cond):
                fired = False
                break
        if not fired:
            continue
        codes.append(rule["icd10_code"])
    return codes


def _load_symptoms(bundle_dir: Path) -> list:
    """Read inputs/symptoms.json (list of {symptom_id, name, severity})."""
    p = bundle_dir / "inputs" / "symptoms.json"
    if not p.is_file():
        raise FileNotFoundError(
            f"inputs/symptoms.json not found in bundle at {bundle_dir}"
        )
    return admit_json_file(p)


def _load_rules(bundle_dir: Path) -> list:
    """Read inputs/rules.json (the committed decision rule set)."""
    p = bundle_dir / "inputs" / "rules.json"
    if not p.is_file():
        raise FileNotFoundError(
            f"inputs/rules.json not found in bundle at {bundle_dir}"
        )
    return admit_json_file(p)


# ---------------------------------------------------------------------------
# ReDerivationPrimitive (registered at import for the core registry)
# ---------------------------------------------------------------------------


class HealthcareDiagnosisRecompute:
    """Verifier-side primitive: re-derive the ordered fire-and-collect ICD-10 code
    list from the committed symptom set + decision rules."""

    primitive_id: str = "healthcare_diagnosis_recompute"

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        """Recompute the ordered icd10_code list from the committed inputs. Returns
        the recomputed VALUE only; the auditor-anchored `exact` comparator decides
        agreement (element-wise list equality) against the producer's claimed list.
        """
        bundle_dir: Path = inputs.bundle_dir
        symptoms = _load_symptoms(bundle_dir)
        rules = _load_rules(bundle_dir)
        value = compute_icd10_codes(symptoms, rules)
        return RecomputedValue(
            value=value,
            detail=(
                f"re-derived icd10_code list ({len(value)} codes) "
                f"from {len(rules)} rules x {len(symptoms)} symptoms"
            ),
        )


register_primitive(HealthcareDiagnosisRecompute())
